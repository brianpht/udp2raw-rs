//! Connection management: state machines, anti-replay, conversation multiplexer,
//! and wire protocol (send_bare, send_safer, recv_safer_multi).
//! Corresponds to connection.{h,cpp} in the C++ version.

use crate::common::*;
use crate::encrypt::Encryptor;
use crate::fd_manager::FdManager;
use crate::misc::Config;
use crate::network::{self, RawInfo, RawSocketState};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;

// ─── Constants ──────────────────────────────────────────────────────────────

pub const ANTI_REPLAY_WINDOW_SIZE: usize = 4000;

pub const CONV_TIMEOUT: u64 = 180_000;
pub const CONV_CLEAR_INTERVAL: u64 = 1000;
pub const CONV_CLEAR_RATIO: usize = 10;
pub const CONV_CLEAR_MIN: usize = 1;

pub const CONN_CLEAR_INTERVAL: u64 = 1000;
pub const CONN_CLEAR_RATIO: usize = 10;
pub const CONN_CLEAR_MIN: usize = 1;

pub const MAX_CONV_NUM: usize = 10_000;

// ─── Anti-Replay ────────────────────────────────────────────────────────────

pub struct AntiReplay {
    pub max_packet_received: u64,
    /// Bitset window: bit N of window[N/8] represents seq slot N.
    /// Uses 500 bytes instead of 4000 bytes (Vec<bool>), much more cache-friendly.
    window: Vec<u8>,
    pub seq: AntiReplaySeq,
}

impl AntiReplay {
    pub fn new() -> Self {
        Self {
            max_packet_received: 0,
            window: vec![0u8; (ANTI_REPLAY_WINDOW_SIZE + 7) / 8],
            seq: get_true_random_number_64() / 10,
        }
    }

    pub fn re_init(&mut self) {
        self.max_packet_received = 0;
        // window entries will be overwritten as needed
    }

    pub fn get_new_seq_for_send(&mut self) -> AntiReplaySeq {
        let s = self.seq;
        self.seq += 1;
        s
    }

    #[inline]
    fn bit_get(&self, idx: usize) -> bool {
        (self.window[idx >> 3] >> (idx & 7)) & 1 != 0
    }

    #[inline]
    fn bit_set(&mut self, idx: usize) {
        self.window[idx >> 3] |= 1 << (idx & 7);
    }

    #[inline]
    fn bit_clear(&mut self, idx: usize) {
        self.window[idx >> 3] &= !(1 << (idx & 7));
    }

    pub fn is_valid(&mut self, seq: u64, disable_anti_replay: bool) -> bool {
        if disable_anti_replay {
            return true;
        }
        if seq == self.max_packet_received {
            return false;
        }
        if seq > self.max_packet_received {
            let diff = seq - self.max_packet_received;
            if diff >= ANTI_REPLAY_WINDOW_SIZE as u64 {
                // Clear entire window
                for w in self.window.iter_mut() {
                    *w = 0;
                }
                self.bit_set((seq % ANTI_REPLAY_WINDOW_SIZE as u64) as usize);
            } else {
                for i in (self.max_packet_received + 1)..seq {
                    self.bit_clear((i % ANTI_REPLAY_WINDOW_SIZE as u64) as usize);
                }
                self.bit_set((seq % ANTI_REPLAY_WINDOW_SIZE as u64) as usize);
            }
            self.max_packet_received = seq;
            return true;
        }
        // seq < max_packet_received
        if self.max_packet_received - seq >= ANTI_REPLAY_WINDOW_SIZE as u64 {
            return false;
        }
        let idx = (seq % ANTI_REPLAY_WINDOW_SIZE as u64) as usize;
        if self.bit_get(idx) {
            return false;
        }
        self.bit_set(idx);
        true
    }
}

// ─── Conversation Manager ───────────────────────────────────────────────────

pub struct ConvManager<T: Hash + Eq + Clone> {
    data_to_conv: HashMap<T, u32>,
    conv_to_data: HashMap<u32, T>,
    lru: LruCollector<u32>,
    pub clear_fn: Option<Box<dyn Fn(T)>>,
    last_clear_time: MyTime,
}

impl<T: Hash + Eq + Clone> ConvManager<T> {
    pub fn new() -> Self {
        Self {
            data_to_conv: HashMap::with_capacity(64),
            conv_to_data: HashMap::with_capacity(64),
            lru: LruCollector::with_capacity(64),
            clear_fn: None,
            last_clear_time: 0,
        }
    }

    pub fn get_size(&self) -> usize {
        self.conv_to_data.len()
    }

    pub fn get_new_conv(&self) -> u32 {
        loop {
            let conv = get_true_random_number_nz();
            if !self.conv_to_data.contains_key(&conv) {
                return conv;
            }
        }
    }

    pub fn is_conv_used(&self, conv: u32) -> bool {
        self.conv_to_data.contains_key(&conv)
    }

    pub fn is_data_used(&self, data: &T) -> bool {
        self.data_to_conv.contains_key(data)
    }

    pub fn find_conv_by_data(&self, data: &T) -> Option<u32> {
        self.data_to_conv.get(data).copied()
    }

    pub fn find_data_by_conv(&self, conv: u32) -> Option<&T> {
        self.conv_to_data.get(&conv)
    }

    pub fn update_active_time(&mut self, conv: u32) {
        self.lru.update(&conv);
    }

    pub fn insert_conv(&mut self, conv: u32, data: T) {
        self.data_to_conv.insert(data.clone(), conv);
        self.conv_to_data.insert(conv, data);
        self.lru.new_key(conv);
    }

    pub fn erase_conv(&mut self, conv: u32) {
        if let Some(data) = self.conv_to_data.remove(&conv) {
            if let Some(ref f) = self.clear_fn {
                f(data.clone());
            }
            self.data_to_conv.remove(&data);
            self.lru.erase(&conv);
        }
    }

    pub fn clear_inactive(&mut self) {
        let now = get_current_time();
        if now - self.last_clear_time < CONV_CLEAR_INTERVAL {
            return;
        }
        self.last_clear_time = now;
        self.clear_inactive0();
    }

    fn clear_inactive0(&mut self) {
        let size = self.lru.size();
        let num_to_clean = (size / CONV_CLEAR_RATIO + CONV_CLEAR_MIN).min(size);
        let current_time = get_current_time();
        let mut cnt = 0;

        while cnt < num_to_clean {
            if let Some((conv, ts)) = self.lru.peek_back() {
                if current_time - ts < CONV_TIMEOUT {
                    break;
                }
                log::info!("conv {:x} cleared", conv);
                self.erase_conv(conv);
                cnt += 1;
            } else {
                break;
            }
        }
    }

    pub fn clear_all(&mut self) {
        let convs: Vec<u32> = self.conv_to_data.keys().cloned().collect();
        for conv in convs {
            self.erase_conv(conv);
        }
    }
}

// ─── Blob (conv_manager variant + anti_replay) ─────────────────────────────

pub enum ConvManagerVariant {
    Client(ConvManager<SocketAddr>),
    Server(ConvManager<Fd64>),
}

pub struct Blob {
    pub conv_manager: ConvManagerVariant,
    pub anti_replay: AntiReplay,
}

impl Blob {
    pub fn new_client() -> Self {
        Self {
            conv_manager: ConvManagerVariant::Client(ConvManager::new()),
            anti_replay: AntiReplay::new(),
        }
    }

    pub fn new_server(clear_fn: Box<dyn Fn(Fd64)>) -> Self {
        let mut cm = ConvManager::new();
        cm.clear_fn = Some(clear_fn);
        Self {
            conv_manager: ConvManagerVariant::Server(cm),
            anti_replay: AntiReplay::new(),
        }
    }
}

// ─── ConnInfo ───────────────────────────────────────────────────────────────

pub struct ConnInfo {
    pub state: ConnectionState,
    pub raw_info: RawInfo,
    pub last_state_time: MyTime,
    pub last_hb_sent_time: MyTime,
    pub last_hb_recv_time: MyTime,
    pub my_id: MyId,
    pub opposite_id: MyId,
    pub opposite_const_id: MyId,
    pub timer_fd64: Fd64,
    pub udp_fd64: Fd64,
    pub blob: Option<Box<Blob>>,
    pub my_roller: u8,
    pub opposite_roller: u8,
    pub last_opposite_roller_time: MyTime,
}

impl ConnInfo {
    pub fn new_client() -> Self {
        Self {
            state: ConnectionState::Client(ClientState::Idle),
            raw_info: RawInfo::default(),
            last_state_time: 0,
            last_hb_sent_time: 0,
            last_hb_recv_time: 0,
            my_id: 0,
            opposite_id: 0,
            opposite_const_id: 0,
            timer_fd64: 0,
            udp_fd64: 0,
            blob: None,
            my_roller: 0,
            opposite_roller: 0,
            last_opposite_roller_time: 0,
        }
    }

    pub fn new_server() -> Self {
        Self {
            state: ConnectionState::Server(ServerState::Idle),
            raw_info: RawInfo::default(),
            last_state_time: 0,
            last_hb_sent_time: 0,
            last_hb_recv_time: 0,
            my_id: 0,
            opposite_id: 0,
            opposite_const_id: 0,
            timer_fd64: 0,
            udp_fd64: 0,
            blob: None,
            my_roller: 0,
            opposite_roller: 0,
            last_opposite_roller_time: 0,
        }
    }

    pub fn prepare_client(&mut self) {
        self.blob = Some(Box::new(Blob::new_client()));
    }

    pub fn re_init_client(&mut self) {
        self.state = ConnectionState::Client(ClientState::Idle);
        self.last_state_time = 0;
        self.opposite_const_id = 0;
        self.my_roller = 0;
        self.opposite_roller = 0;
        self.last_opposite_roller_time = 0;
    }

    pub fn recover(&mut self, other: &ConnInfo) {
        self.raw_info = other.raw_info.clone();
        self.raw_info.rst_received = 0;
        self.raw_info.disabled = false;
        self.last_state_time = other.last_state_time;
        self.last_hb_recv_time = other.last_hb_recv_time;
        self.last_hb_sent_time = other.last_hb_sent_time;
        self.my_id = other.my_id;
        self.opposite_id = other.opposite_id;
        if let Some(ref mut blob) = self.blob {
            blob.anti_replay.re_init();
        }
        self.my_roller = 0;
        self.opposite_roller = 0;
        self.last_opposite_roller_time = 0;
    }
}

// ─── ConnManager (server only) ──────────────────────────────────────────────

pub struct ConnManager {
    pub ready_num: u32,
    pub mp: HashMap<SocketAddr, Box<ConnInfo>>,
    pub const_id_mp: HashMap<MyId, SocketAddr>,
    last_clear_time: MyTime,
}

impl ConnManager {
    pub fn new() -> Self {
        Self {
            ready_num: 0,
            mp: HashMap::with_capacity(64),
            const_id_mp: HashMap::with_capacity(64),
            last_clear_time: 0,
        }
    }

    pub fn exist(&self, addr: &SocketAddr) -> bool {
        self.mp.contains_key(addr)
    }

    pub fn find_or_insert(&mut self, addr: SocketAddr) -> &mut ConnInfo {
        self.mp
            .entry(addr)
            .or_insert_with(|| Box::new(ConnInfo::new_server()))
    }

    pub fn clear_inactive(&mut self, fd_manager: &mut FdManager) {
        let now = get_current_time();
        if now - self.last_clear_time < CONN_CLEAR_INTERVAL {
            return;
        }
        self.last_clear_time = now;
        self.clear_inactive0(fd_manager);
    }

    fn clear_inactive0(&mut self, fd_manager: &mut FdManager) {
        let size = self.mp.len();
        let num_to_clean = (size / CONN_CLEAR_RATIO + CONN_CLEAR_MIN).min(size);
        let current_time = get_current_time();

        let mut to_remove = Vec::new();
        let mut cnt = 0;

        for (addr, conn) in self.mp.iter() {
            if cnt >= num_to_clean {
                break;
            }
            let should_remove = match conn.state {
                ConnectionState::Server(ServerState::Ready) => {
                    current_time.saturating_sub(conn.last_hb_recv_time) > crate::misc::SERVER_CONN_TIMEOUT
                }
                _ => {
                    current_time.saturating_sub(conn.last_state_time) > crate::misc::SERVER_HANDSHAKE_TIMEOUT
                }
            };
            if should_remove {
                // Don't remove if it has active conversations
                if let Some(ref blob) = conn.blob {
                    if let ConvManagerVariant::Server(ref cm) = blob.conv_manager {
                        if cm.get_size() > 0 {
                            cnt += 1;
                            continue;
                        }
                    }
                }
                to_remove.push(*addr);
            }
            cnt += 1;
        }

        for addr in to_remove {
            self.erase(&addr, fd_manager);
        }
    }

    pub fn erase(&mut self, addr: &SocketAddr, fd_manager: &mut FdManager) {
        if let Some(mut conn) = self.mp.remove(addr) {
            if let ConnectionState::Server(ServerState::Ready) = conn.state {
                self.ready_num = self.ready_num.saturating_sub(1);
                if conn.opposite_const_id != 0 {
                    self.const_id_mp.remove(&conn.opposite_const_id);
                }
                if conn.timer_fd64 != 0 && fd_manager.exist(conn.timer_fd64) {
                    fd_manager.fd64_close(conn.timer_fd64);
                }
                conn.timer_fd64 = 0;
            }
            log::info!("connection to {} erased", addr);
        }
    }
}

// ─── Wire protocol functions ────────────────────────────────────────────────

/// Send a bare packet (encrypted, no anti-replay). Used during handshake.
pub fn send_bare(
    raw_state: &mut RawSocketState,
    raw_info: &mut RawInfo,
    data: &[u8],
    encryptor: &Encryptor,
    raw_mode: RawMode,
) -> Result<(), ()> {
    let mut buf = [0u8; BUF_LEN];
    let mut buf2 = [0u8; BUF_LEN];

    let iv = get_true_random_number_64();
    let padding = get_true_random_number_64();

    let mut offset = 0;
    buf[offset..offset + 8].copy_from_slice(&iv.to_ne_bytes());
    offset += 8;
    buf[offset..offset + 8].copy_from_slice(&padding.to_ne_bytes());
    offset += 8;
    buf[offset] = b'b';
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(data);
    let total = offset + data.len();

    let enc_len = encryptor.my_encrypt(&buf[..total], &mut buf2).map_err(|_| {
        log::debug!("send_bare: encrypt failed");
    })?;

    raw_state
        .send_raw0(raw_info, &buf2[..enc_len], raw_mode)
        .map_err(|e| {
            log::warn!("send_bare: send_raw0 failed: {}", e);
        })?;
    Ok(())
}

/// Receive a bare packet (encrypted, no anti-replay). Used during handshake.
pub fn recv_bare(
    raw_state: &mut RawSocketState,
    raw_info: &mut RawInfo,
    encryptor: &Encryptor,
    raw_mode: RawMode,
) -> Result<Vec<u8>, ()> {
    let encrypted = raw_state.recv_raw0(raw_info, raw_mode).map_err(|_| ())?;

    if encrypted.len() > MAX_DATA_LEN + 1 {
        log::debug!("recv_bare: data too long {}", encrypted.len());
        return Err(());
    }

    // For FakeTCP, check that it's an ACK (not SYN)
    if raw_mode == RawMode::FakeTcp && (raw_info.recv_info.syn || !raw_info.recv_info.ack) {
        log::debug!("recv_bare: unexpected packet type syn={} ack={}", raw_info.recv_info.syn, raw_info.recv_info.ack);
        return Err(());
    }

    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = encryptor.my_decrypt(&encrypted, &mut decrypted).map_err(|_| {
        log::debug!("recv_bare: decrypt failed");
    })?;

    // Verify marker
    if dec_len < 17 || decrypted[16] != b'b' {
        log::debug!("recv_bare: not a bare packet");
        return Err(());
    }

    let data_start = 17; // 8 (iv) + 8 (padding) + 1 (marker)
    if data_start > dec_len {
        return Err(());
    }
    Ok(decrypted[data_start..dec_len].to_vec())
}

/// Send handshake (wrapper around send_bare with 3 IDs).
pub fn send_handshake(
    raw_state: &mut RawSocketState,
    raw_info: &mut RawInfo,
    id1: MyId,
    id2: MyId,
    id3: MyId,
    encryptor: &Encryptor,
    raw_mode: RawMode,
) -> Result<(), ()> {
    let data = numbers_to_bytes(id1, id2, id3);
    send_bare(raw_state, raw_info, &data, encryptor, raw_mode)
}

/// Send a safer packet (encrypted + anti-replay). Used for data and heartbeats.
pub fn send_safer(
    raw_state: &mut RawSocketState,
    conn_info: &mut ConnInfo,
    pkt_type: u8, // b'h' or b'd'
    data: &[u8],
    encryptor: &Encryptor,
    config: &Config,
) -> Result<(), ()> {
    let blob = conn_info.blob.as_mut().ok_or(())?;
    let seq = blob.anti_replay.get_new_seq_for_send();

    let mut buf = [0u8; BUF_LEN];
    let mut buf2 = [0u8; BUF_LEN];

    let mut offset = 0;
    buf[offset..offset + 4].copy_from_slice(&conn_info.my_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&conn_info.opposite_id.to_be_bytes());
    offset += 4;
    buf[offset..offset + 8].copy_from_slice(&hton64(seq).to_ne_bytes());
    offset += 8;
    buf[offset] = pkt_type;
    offset += 1;
    buf[offset] = conn_info.my_roller;
    offset += 1;
    buf[offset..offset + data.len()].copy_from_slice(data);
    let total = offset + data.len();

    if !config.fix_gro {
        let enc_len = encryptor.my_encrypt(&buf[..total], &mut buf2).map_err(|_| ())?;
        raw_state
            .send_raw0(&mut conn_info.raw_info, &buf2[..enc_len], config.raw_mode)
            .map_err(|e| {
                log::warn!("send_safer: send failed: {}", e);
            })?;
    } else {
        // GRO fix: prepend 2-byte length, then XOR/AES-ECB first 16 bytes
        let enc_len = encryptor.my_encrypt(&buf[..total], &mut buf2[2..]).map_err(|_| ())?;
        write_u16(&mut buf2[..2], enc_len as u16);
        let final_len = enc_len + 2;

        if config.cipher_mode == CipherMode::Xor {
            buf2[0] ^= encryptor.keys.gro_xor[0];
            buf2[1] ^= encryptor.keys.gro_xor[1];
        } else if config.cipher_mode == CipherMode::Aes128Cbc || config.cipher_mode == CipherMode::Aes128Cfb {
            if final_len >= 16 {
                let mut block = [0u8; 16];
                block.copy_from_slice(&buf2[..16]);
                encryptor.aes_ecb_encrypt_block(&mut block);
                buf2[..16].copy_from_slice(&block);
            }
        }
        raw_state
            .send_raw0(&mut conn_info.raw_info, &buf2[..final_len], config.raw_mode)
            .map_err(|e| {
                log::warn!("send_safer: send failed: {}", e);
            })?;
    }

    network::after_send_raw0(&mut conn_info.raw_info, config.seq_mode);
    Ok(())
}

/// Send data via safer (wraps conv_id + payload).
pub fn send_data_safer(
    raw_state: &mut RawSocketState,
    conn_info: &mut ConnInfo,
    data: &[u8],
    conv_num: u32,
    encryptor: &Encryptor,
    config: &Config,
) -> Result<(), ()> {
    let mut buf = [0u8; BUF_LEN];
    buf[..4].copy_from_slice(&conv_num.to_be_bytes());
    buf[4..4 + data.len()].copy_from_slice(data);
    send_safer(raw_state, conn_info, b'd', &buf[..4 + data.len()], encryptor, config)
}

/// Parsed safer packet.
pub struct SaferPacket {
    pub pkt_type: u8,
    pub data: Vec<u8>,
}

/// Receive safer packet(s). Handles GRO (multiple packets in one recv).
pub fn recv_safer_multi(
    raw_state: &mut RawSocketState,
    conn_info: &mut ConnInfo,
    encryptor: &Encryptor,
    config: &Config,
) -> Result<Vec<SaferPacket>, ()> {
    let encrypted = raw_state.recv_raw0(&mut conn_info.raw_info, config.raw_mode).map_err(|_| ())?;
    let mut results = Vec::new();

    if !config.fix_gro {
        if let Some(pkt) = parse_safer_single(conn_info, &encrypted, encryptor, config)? {
            results.push(pkt);
        }
    } else {
        // GRO: multiple packets concatenated
        let mut offset = 0;
        while offset + 16 <= encrypted.len() {
            let mut header = [0u8; 16];
            header.copy_from_slice(&encrypted[offset..offset + 16]);

            // Decrypt length header
            if config.cipher_mode == CipherMode::Xor {
                header[0] ^= encryptor.keys.gro_xor[0];
                header[1] ^= encryptor.keys.gro_xor[1];
            } else if config.cipher_mode == CipherMode::Aes128Cbc || config.cipher_mode == CipherMode::Aes128Cfb {
                let mut block = [0u8; 16];
                block.copy_from_slice(&encrypted[offset..offset + 16]);
                encryptor.aes_ecb_decrypt_block(&mut block);
                header = block;
            }

            let single_len = read_u16(&header) as usize;
            offset += 2;

            if single_len > encrypted.len() - offset || single_len > MAX_DATA_LEN {
                break;
            }

            if let Ok(Some(pkt)) = parse_safer_single(conn_info, &encrypted[offset..offset + single_len], encryptor, config) {
                results.push(pkt);
            }
            offset += single_len;
        }
    }

    if results.is_empty() {
        return Err(());
    }
    Ok(results)
}

/// Parse a single safer packet.
fn parse_safer_single(
    conn_info: &mut ConnInfo,
    encrypted: &[u8],
    encryptor: &Encryptor,
    config: &Config,
) -> Result<Option<SaferPacket>, ()> {
    let mut decrypted = [0u8; BUF_LEN];
    let dec_len = encryptor.my_decrypt(encrypted, &mut decrypted).map_err(|_| ())?;

    if dec_len < 18 {
        // 4 + 4 + 8 + 1 + 1 = 18 minimum
        return Err(());
    }

    let h_opposite_id = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
    let h_my_id = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);

    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&decrypted[8..16]);
    let h_seq = ntoh64(u64::from_ne_bytes(seq_bytes));

    if h_opposite_id != conn_info.opposite_id || h_my_id != conn_info.my_id {
        log::debug!(
            "safer: ID mismatch got {:x}/{:x} expected {:x}/{:x}",
            h_opposite_id, h_my_id, conn_info.opposite_id, conn_info.my_id
        );
        return Err(());
    }

    let blob = conn_info.blob.as_mut().ok_or(())?;
    if !blob.anti_replay.is_valid(h_seq, config.disable_anti_replay) {
        log::debug!("safer: replay packet dropped");
        return Err(());
    }

    let pkt_type = decrypted[16];
    let roller = decrypted[17];

    if pkt_type != b'h' && pkt_type != b'd' {
        log::debug!("safer: invalid type {:x}", pkt_type);
        return Err(());
    }

    let data = decrypted[18..dec_len].to_vec();

    // Update roller
    if roller != conn_info.opposite_roller {
        conn_info.opposite_roller = roller;
        conn_info.last_opposite_roller_time = get_current_time();
    }
    if config.hb_mode == 0 {
        conn_info.my_roller = conn_info.my_roller.wrapping_add(1);
    } else if config.hb_mode == 1 && pkt_type == b'h' {
        conn_info.my_roller = conn_info.my_roller.wrapping_add(1);
    }

    network::after_recv_raw0(&mut conn_info.raw_info, config.seq_mode);

    Ok(Some(SaferPacket { pkt_type, data }))
}

