//! Server event loop and state machine.
//! Corresponds to server.cpp in the C++ version.

use crate::common::*;
use crate::connection::*;
use crate::encrypt::Encryptor;
use crate::fd_manager::{FdInfo, FdManager};
use crate::misc::{self, Config};
use crate::network::{self, RawSocketState};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;

use mio::{Events, Interest, Poll, Token};

const RAW_TOKEN: Token = Token(0);
const TIMER_TOKEN: Token = Token(1);
const FIFO_TOKEN: Token = Token(2);
const DYNAMIC_BASE: usize = 100;

struct MioFdSource {
    fd: RawFd,
}

impl mio::event::Source for MioFdSource {
    fn register(&mut self, registry: &mio::Registry, token: Token, interests: Interest) -> io::Result<()> {
        registry.register(&mut mio::unix::SourceFd(&self.fd), token, interests)
    }
    fn reregister(&mut self, registry: &mio::Registry, token: Token, interests: Interest) -> io::Result<()> {
        registry.reregister(&mut mio::unix::SourceFd(&self.fd), token, interests)
    }
    fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        registry.deregister(&mut mio::unix::SourceFd(&self.fd))
    }
}

pub fn server_event_loop(
    config: &Config,
    encryptor: &Encryptor,
    raw_state: &mut RawSocketState,
    const_id: MyId,
) -> io::Result<()> {
    let mut conn_manager = ConnManager::new();
    let mut fd_manager = FdManager::new();
    let mut next_token_id: usize = DYNAMIC_BASE;

    // Token <-> Fd64 mapping
    let mut token_to_fd64: std::collections::HashMap<usize, Fd64> = std::collections::HashMap::new();
    let mut fd64_to_token: std::collections::HashMap<Fd64, usize> = std::collections::HashMap::new();

    // Bind socket to prevent port conflicts
    let _bind_fd = create_bind_socket(config)?;

    // BPF filter
    raw_state.init_filter(config.local_addr.port(), config);

    // Setup mio poll
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(4096);

    let mut raw_source = MioFdSource { fd: raw_state.raw_recv_fd };
    poll.registry().register(&mut raw_source, RAW_TOKEN, Interest::READABLE)?;

    // Create timerfd
    let timer_fd = create_timerfd(misc::TIMER_INTERVAL)?;
    let mut timer_source = MioFdSource { fd: timer_fd };
    poll.registry().register(&mut timer_source, TIMER_TOKEN, Interest::READABLE)?;

    // Heartbeat buffer
    let hb_buf = vec![0u8; config.hb_len];

    // Reusable buffer for heartbeat iteration — avoids Vec allocation every 400ms
    let mut hb_addrs: Vec<SocketAddr> = Vec::new();

    log::info!("server listening at {}", config.local_addr);

    loop {
        poll.poll(&mut events, Some(Duration::from_secs(180)))?;

        for event in events.iter() {
            match event.token() {
                TIMER_TOKEN => {
                    // Drain timerfd
                    let mut dummy = [0u8; 8];
                    unsafe { libc::read(timer_fd, dummy.as_mut_ptr() as *mut libc::c_void, 8); }
                    conn_manager.clear_inactive(&mut fd_manager);

                    // Per-connection timers: send heartbeats for ready connections
                    // Reuse hb_addrs buffer — clear+extend retains Vec capacity
                    hb_addrs.clear();
                    hb_addrs.extend(conn_manager.mp.keys().cloned());
                    for addr in &hb_addrs {
                        if let Some(conn) = conn_manager.mp.get_mut(addr) {
                            if let ConnectionState::Server(ServerState::Ready) = conn.state {
                                let now = get_current_time();
                                if now - conn.last_hb_sent_time >= misc::HEARTBEAT_INTERVAL {
                                    let hb_data = if config.hb_mode == 0 { &[] as &[u8] } else { hb_buf.as_slice() };
                                    let _ = send_safer(raw_state, conn, b'h', hb_data, encryptor, config);
                                    conn.last_hb_sent_time = get_current_time();
                                }
                            }
                        }
                    }
                }

                RAW_TOKEN => {
                    server_on_raw_recv(
                        &mut conn_manager,
                        &mut fd_manager,
                        raw_state,
                        encryptor,
                        config,
                        const_id,
                        &mut poll,
                        &mut next_token_id,
                        &mut token_to_fd64,
                        &mut fd64_to_token,
                        &hb_buf,
                    );
                }

                token => {
                    let token_id = token.0;
                    if let Some(&fd64) = token_to_fd64.get(&token_id) {
                        if fd_manager.exist(fd64) {
                            // Find which conn this belongs to
                            if let Some(info) = fd_manager.get_info(fd64) {
                                if let Some(addr) = info.conn_info_key {
                                    if let Some(conn) = conn_manager.mp.get_mut(&addr) {
                                        server_on_udp_recv(conn, fd64, &fd_manager, raw_state, encryptor, config);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn server_on_raw_recv(
    conn_manager: &mut ConnManager,
    fd_manager: &mut FdManager,
    raw_state: &mut RawSocketState,
    encryptor: &Encryptor,
    config: &Config,
    const_id: MyId,
    poll: &mut Poll,
    next_token_id: &mut usize,
    token_to_fd64: &mut std::collections::HashMap<usize, Fd64>,
    fd64_to_token: &mut std::collections::HashMap<Fd64, usize>,
    hb_buf: &[u8],
) {
    // Peek to get source address
    let mut peek_info = network::RawInfo::default();
    peek_info.peek = true;
    let peek_result = raw_state.recv_raw0(&mut peek_info, config.raw_mode);
    if peek_result.is_err() {
        raw_state.discard_raw_packet();
        return;
    }

    let src_ip = peek_info.recv_info.src_ip;
    let src_port = peek_info.recv_info.src_port;
    let addr = SocketAddr::new(src_ip, src_port);

    // Handle TCP SYN
    if config.raw_mode == RawMode::FakeTcp && peek_info.recv_info.syn {
        if !conn_manager.exist(&addr)
            || !matches!(
                conn_manager.mp.get(&addr).map(|c| &c.state),
                Some(ConnectionState::Server(ServerState::Ready))
            )
        {
            let mut tmp_raw_info = network::RawInfo::default();
            let data = match raw_state.recv_raw0(&mut tmp_raw_info, config.raw_mode) {
                Ok(d) => d,
                Err(_) => return,
            };

            if config.use_tcp_dummy_socket {
                return;
            }

            if data.is_empty() && tmp_raw_info.recv_info.syn && !tmp_raw_info.recv_info.ack {
                // Reply with SYN+ACK
                tmp_raw_info.send_info.src_ip = tmp_raw_info.recv_info.dst_ip;
                tmp_raw_info.send_info.src_port = tmp_raw_info.recv_info.dst_port;
                tmp_raw_info.send_info.dst_ip = tmp_raw_info.recv_info.src_ip;
                tmp_raw_info.send_info.dst_port = tmp_raw_info.recv_info.src_port;
                tmp_raw_info.send_info.ack_seq = tmp_raw_info.recv_info.seq.wrapping_add(1);
                tmp_raw_info.send_info.seq = get_true_random_number();
                tmp_raw_info.send_info.syn = true;
                tmp_raw_info.send_info.ack = true;
                tmp_raw_info.send_info.psh = false;
                let _ = raw_state.send_raw0(&mut tmp_raw_info, &[], config.raw_mode);
                log::info!("[{}] sent SYN+ACK", addr);
            }
        } else {
            raw_state.discard_raw_packet();
        }
        return;
    }

    // New connection
    if !conn_manager.exist(&addr) {
        if conn_manager.mp.len() >= misc::MAX_HANDSHAKE_CONN_NUM {
            raw_state.discard_raw_packet();
            return;
        }

        let mut tmp_raw_info = network::RawInfo::default();
        let data = match recv_bare(raw_state, &mut tmp_raw_info, encryptor, config.raw_mode) {
            Ok(d) => d,
            Err(_) => return,
        };

        if data.len() < 12 {
            return;
        }

        let (_tmp_opposite_id, zero, _) = match bytes_to_numbers(&data) {
            Some(ids) => ids,
            None => return,
        };
        if zero != 0 {
            return;
        }

        let conn = conn_manager.find_or_insert(addr);
        conn.raw_info = tmp_raw_info;
        conn.raw_info.send_info.src_ip = conn.raw_info.recv_info.dst_ip;
        conn.raw_info.send_info.src_port = conn.raw_info.recv_info.dst_port;
        conn.raw_info.send_info.dst_ip = conn.raw_info.recv_info.src_ip;
        conn.raw_info.send_info.dst_port = conn.raw_info.recv_info.src_port;
        conn.my_id = get_true_random_number_nz();
        conn.state = ConnectionState::Server(ServerState::Handshake1);
        conn.last_state_time = get_current_time();

        log::info!("[{}] new connection, state -> Handshake1, my_id={:x}", addr, conn.my_id);

        // Process handshake1 inline (to avoid double borrow)
        server_process_handshake1_data(
            conn, &addr, &data, raw_state, encryptor, config, const_id, hb_buf,
        );
        conn_manager.ready_num = conn_manager.mp.values()
            .filter(|c| matches!(c.state, ConnectionState::Server(ServerState::Ready)))
            .count() as u32;
        return;
    }

    // Existing connection
    let conn_state = conn_manager.mp.get(&addr).map(|c| c.state);

    match conn_state {
        Some(ConnectionState::Server(ServerState::Handshake1)) => {
            let conn = conn_manager.mp.get_mut(&addr).unwrap();
            let data = match recv_bare(raw_state, &mut conn.raw_info, encryptor, config.raw_mode) {
                Ok(d) => d,
                Err(_) => return,
            };
            server_process_handshake1_data(
                conn, &addr, &data, raw_state, encryptor, config, const_id, hb_buf,
            );
            conn_manager.ready_num = conn_manager.mp.values()
                .filter(|c| matches!(c.state, ConnectionState::Server(ServerState::Ready)))
                .count() as u32;
        }

        Some(ConnectionState::Server(ServerState::Ready)) => {
            let conn = conn_manager.mp.get_mut(&addr).unwrap();
            let packets = match recv_safer_multi(raw_state, conn, encryptor, config) {
                Ok(p) => p,
                Err(_) => return,
            };

            for pkt in packets {
                server_on_data_packet(
                    conn, &addr, &pkt, raw_state, encryptor, config,
                    fd_manager, poll, next_token_id, token_to_fd64, fd64_to_token,
                );
            }
        }

        Some(ConnectionState::Server(ServerState::Idle)) | None => {
            raw_state.discard_raw_packet();
        }

        _ => {
            raw_state.discard_raw_packet();
        }
    }
}

fn server_process_handshake1_data(
    conn: &mut ConnInfo,
    addr: &SocketAddr,
    data: &[u8],
    raw_state: &mut RawSocketState,
    encryptor: &Encryptor,
    config: &Config,
    const_id: MyId,
    hb_buf: &[u8],
) {
    if data.len() < 12 {
        return;
    }

    let (tmp_opposite_id, tmp_my_id, tmp_const_id) = match bytes_to_numbers(data) {
        Some(ids) => ids,
        None => return,
    };

    if tmp_my_id == 0 {
        // Initial handshake — reply with our ID
        if config.raw_mode == RawMode::FakeTcp {
            conn.raw_info.send_info.seq = conn.raw_info.recv_info.ack_seq;
            conn.raw_info.send_info.ack_seq = conn.raw_info.recv_info.seq
                .wrapping_add(conn.raw_info.recv_info.data_len as u32);
            conn.raw_info.send_info.ts_ack = conn.raw_info.recv_info.ts;
        }
        let _ = send_handshake(
            raw_state, &mut conn.raw_info,
            conn.my_id, tmp_opposite_id, const_id,
            encryptor, config.raw_mode,
        );
        log::info!("[{}] sent handshake reply, my_id={:x}", addr, conn.my_id);
    } else if tmp_my_id == conn.my_id {
        // Handshake confirmation — transition to Ready
        conn.opposite_id = tmp_opposite_id;
        conn.opposite_const_id = tmp_const_id;

        if config.raw_mode == RawMode::FakeTcp {
            conn.raw_info.send_info.seq = conn.raw_info.recv_info.ack_seq;
            conn.raw_info.send_info.ack_seq = conn.raw_info.recv_info.seq
                .wrapping_add(conn.raw_info.recv_info.data_len as u32);
            conn.raw_info.send_info.ts_ack = conn.raw_info.recv_info.ts;
        }

        // Prepare blob with a no-op clear function (fd cleanup done externally)
        conn.blob = Some(Box::new(Blob::new_server(Box::new(|_fd64: Fd64| {
            // Conversation cleared — fd cleanup handled by conn_manager.erase()
        }))));
        conn.state = ConnectionState::Server(ServerState::Ready);
        conn.last_hb_recv_time = get_current_time();
        conn.last_hb_sent_time = conn.last_hb_recv_time;

        if let Some(ref mut blob) = conn.blob {
            blob.anti_replay.re_init();
        }

        // Send initial heartbeat
        let hb_data = if config.hb_mode == 0 { &[] as &[u8] } else { hb_buf };
        let _ = send_safer(raw_state, conn, b'h', hb_data, encryptor, config);

        log::info!("[{}] state -> Ready, opposite_id={:x}", addr, conn.opposite_id);
    }
}

fn server_on_data_packet(
    conn: &mut ConnInfo,
    addr: &SocketAddr,
    pkt: &SaferPacket,
    _raw_state: &mut RawSocketState,
    _encryptor: &Encryptor,
    config: &Config,
    fd_manager: &mut FdManager,
    poll: &mut Poll,
    next_token_id: &mut usize,
    token_to_fd64: &mut std::collections::HashMap<usize, Fd64>,
    fd64_to_token: &mut std::collections::HashMap<Fd64, usize>,
) {
    if pkt.pkt_type == b'h' {
        conn.last_hb_recv_time = get_current_time();
        return;
    }

    if pkt.pkt_type == b'd' && pkt.data.len() >= 4 {
        if config.hb_mode == 0 {
            conn.last_hb_recv_time = get_current_time();
        }

        let conv_id = u32::from_be_bytes([pkt.data[0], pkt.data[1], pkt.data[2], pkt.data[3]]);
        let payload = &pkt.data[4..];

        let blob = match conn.blob.as_mut() {
            Some(b) => b,
            None => return,
        };

        if let ConvManagerVariant::Server(ref mut cm) = blob.conv_manager {
            if !cm.is_conv_used(conv_id) {
                if cm.get_size() >= MAX_CONV_NUM {
                    log::warn!("[{}] max conv exceeded", addr);
                    return;
                }

                // Create new UDP fd connected to remote
                let new_udp_fd = match create_connected_udp_fd(&config.remote_addr) {
                    Ok(fd) => fd,
                    Err(e) => {
                        log::warn!("[{}] create udp fd failed: {}", addr, e);
                        return;
                    }
                };

                let fd64 = fd_manager.create(new_udp_fd);
                fd_manager.set_info(fd64, FdInfo { conn_info_key: Some(*addr) });

                // Register with mio
                let token_id = *next_token_id;
                *next_token_id += 1;
                token_to_fd64.insert(token_id, fd64);
                fd64_to_token.insert(fd64, token_id);

                let mut source = MioFdSource { fd: new_udp_fd };
                let _ = poll.registry().register(&mut source, Token(token_id), Interest::READABLE);

                cm.insert_conv(conv_id, fd64);
                log::info!("[{}] new conv {:x}, fd={}", addr, conv_id, new_udp_fd);
            }

            cm.update_active_time(conv_id);

            if let Some(&fd64) = cm.find_data_by_conv(conv_id) {
                let fd = fd_manager.to_fd(fd64);
                unsafe {
                    libc::send(
                        fd,
                        payload.as_ptr() as *const libc::c_void,
                        payload.len(),
                        0,
                    );
                }
            }

            cm.clear_inactive();
        }
    }
}

fn server_on_udp_recv(
    conn: &mut ConnInfo,
    fd64: Fd64,
    fd_manager: &FdManager,
    raw_state: &mut RawSocketState,
    encryptor: &Encryptor,
    config: &Config,
) {
    if !matches!(conn.state, ConnectionState::Server(ServerState::Ready)) {
        return;
    }

    let blob = match conn.blob.as_ref() {
        Some(b) => b,
        None => return,
    };

    let conv_id = if let ConvManagerVariant::Server(ref cm) = blob.conv_manager {
        if !cm.is_data_used(&fd64) {
            return;
        }
        cm.find_conv_by_data(&fd64).unwrap()
    } else {
        return;
    };

    let fd = fd_manager.to_fd(fd64);
    let mut buf = [0u8; MAX_DATA_LEN + 1];
    let recv_len = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

    if recv_len <= 0 {
        return;
    }
    let recv_len = recv_len as usize;
    if recv_len > MAX_DATA_LEN {
        log::warn!("huge packet from remote ({}), dropped", recv_len);
        return;
    }

    let _ = send_data_safer(raw_state, conn, &buf[..recv_len], conv_id, encryptor, config);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn create_bind_socket(config: &Config) -> io::Result<RawFd> {
    let family = if config.local_addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let sock_type = match config.raw_mode {
        RawMode::FakeTcp => libc::SOCK_STREAM,
        _ => libc::SOCK_DGRAM,
    };
    let fd = unsafe { libc::socket(family, sock_type, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    match config.local_addr {
        SocketAddr::V4(ref a) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = a.port().to_be();
            sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            if unsafe {
                libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32)
            } != 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
        }
        SocketAddr::V6(ref a) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = a.port().to_be();
            sa.sin6_addr = unsafe { std::mem::transmute(*a.ip()) };
            if unsafe {
                libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32)
            } != 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
        }
    }

    if config.raw_mode == RawMode::FakeTcp {
        if unsafe { libc::listen(fd, libc::SOMAXCONN) } != 0 {
            unsafe { libc::close(fd); }
            return Err(io::Error::last_os_error());
        }
    }

    Ok(fd)
}

fn create_timerfd(interval_ms: u64) -> io::Result<RawFd> {
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let its = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: (interval_ms / 1000) as i64,
            tv_nsec: ((interval_ms % 1000) * 1_000_000) as i64,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1, // Fire immediately
        },
    };
    unsafe {
        libc::timerfd_settime(fd, 0, &its, std::ptr::null_mut());
    }
    Ok(fd)
}

fn create_connected_udp_fd(remote: &SocketAddr) -> io::Result<RawFd> {
    let family = if remote.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    setnonblocking(fd)?;
    set_buf_size(fd, 1024 * 1024, false)?;

    match remote {
        SocketAddr::V4(ref a) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = a.port().to_be();
            sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            if unsafe {
                libc::connect(fd, &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32)
            } != 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
        }
        SocketAddr::V6(ref a) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = a.port().to_be();
            sa.sin6_addr = unsafe { std::mem::transmute(*a.ip()) };
            if unsafe {
                libc::connect(fd, &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32)
            } != 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(fd)
}

