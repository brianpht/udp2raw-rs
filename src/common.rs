//! Common types, constants, and utility functions.
//! Corresponds to common.{h,cpp} in the C++ version.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Type aliases ───────────────────────────────────────────────────────────

pub type MyId = u32;
pub type Fd64 = u64;
pub type AntiReplaySeq = u64;
pub type MyTime = u64; // milliseconds

// ─── Constants ──────────────────────────────────────────────────────────────

pub const MAX_DATA_LEN: usize = 1800;
pub const BUF_LEN: usize = MAX_DATA_LEN + 400;
pub const HUGE_DATA_LEN: usize = 65535 + 100;
pub const HUGE_BUF_LEN: usize = HUGE_DATA_LEN + 100;
pub const MAX_ADDR_LEN: usize = 100;

// ─── Time ───────────────────────────────────────────────────────────────────

/// Get current time in milliseconds (monotonic-ish, matching C++ ev_time() behavior).
#[inline]
pub fn get_current_time() -> MyTime {
    get_current_time_us() / 1000
}

pub fn get_current_time_us() -> u64 {
    // Use CLOCK_MONOTONIC via libc for consistency with libev's ev_time behavior
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
}

// ─── Random ─────────────────────────────────────────────────────────────────

use rand::RngCore;

pub fn get_true_random_number_64() -> u64 {
    rand::rngs::OsRng.next_u64()
}

pub fn get_true_random_number() -> u32 {
    rand::rngs::OsRng.next_u32()
}

/// Non-zero random u32.
pub fn get_true_random_number_nz() -> u32 {
    loop {
        let r = get_true_random_number();
        if r != 0 {
            return r;
        }
    }
}

// ─── Network byte order helpers ─────────────────────────────────────────────

#[inline]
pub fn write_u16(buf: &mut [u8], val: u16) {
    buf[..2].copy_from_slice(&val.to_be_bytes());
}

#[inline]
pub fn read_u16(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

#[inline]
pub fn write_u32(buf: &mut [u8], val: u32) {
    buf[..4].copy_from_slice(&val.to_be_bytes());
}

#[inline]
pub fn read_u32(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

#[inline]
pub fn ntoh64(val: u64) -> u64 {
    u64::from_be(val)
}

#[inline]
pub fn hton64(val: u64) -> u64 {
    val.to_be()
}

// ─── Checksum (RFC 1071) ────────────────────────────────────────────────────

#[inline]
pub fn csum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    let len = data.len();

    while i + 1 < len {
        sum += u16::from_ne_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < len {
        let mut odd = [0u8; 2];
        odd[0] = data[i];
        sum += u16::from_ne_bytes(odd) as u32;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    !(sum as u16)
}

#[inline]
pub fn csum_with_header(header: &[u8], data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum header (must be even length)
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_ne_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }

    // Sum data
    i = 0;
    let len = data.len();
    while i + 1 < len {
        sum += u16::from_ne_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < len {
        let mut odd = [0u8; 2];
        odd[0] = data[i];
        sum += u16::from_ne_bytes(odd) as u32;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    !(sum as u16)
}

// ─── Handshake ID serialization ─────────────────────────────────────────────

pub fn numbers_to_bytes(id1: MyId, id2: MyId, id3: MyId) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&id1.to_be_bytes());
    buf[4..8].copy_from_slice(&id2.to_be_bytes());
    buf[8..12].copy_from_slice(&id3.to_be_bytes());
    buf
}

pub fn bytes_to_numbers(data: &[u8]) -> Option<(MyId, MyId, MyId)> {
    if data.len() < 12 {
        return None;
    }
    let id1 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let id2 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let id3 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    Some((id1, id2, id3))
}

// ─── Socket utilities ───────────────────────────────────────────────────────

pub fn setnonblocking(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn set_buf_size(fd: RawFd, size: usize, force: bool) -> std::io::Result<()> {
    let size_i = size as libc::c_int;
    let optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    if force {
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUFFORCE,
                &size_i as *const _ as *const libc::c_void,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &size_i as *const _ as *const libc::c_void,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    } else {
        unsafe {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size_i as *const _ as *const libc::c_void,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size_i as *const _ as *const libc::c_void,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

// ─── Command execution ──────────────────────────────────────────────────────

pub fn run_command(command: &str) -> std::io::Result<(i32, String)> {
    log::debug!("run_command: {}", command);
    let output = Command::new("sh").arg("-c").arg(command).output()?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if code != 0 {
        log::warn!(
            "command '{}' returned {}: {}",
            command,
            code,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok((code, stdout))
}

// ─── Config file parsing ────────────────────────────────────────────────────

/// Parse a single config line into option tokens.
/// Lines starting with '#' are comments. Each line is "-option" or "-option value".
pub fn parse_conf_line(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Vec::new();
    }
    if !trimmed.starts_with('-') {
        log::error!("config line does not start with '-': {}", line);
        return Vec::new();
    }
    // Split into at most 2 parts: option and value
    let mut parts = trimmed.splitn(2, |c: char| c == ' ' || c == '\t');
    let mut result = Vec::new();
    if let Some(opt) = parts.next() {
        result.push(opt.to_string());
    }
    if let Some(val) = parts.next() {
        let val = val.trim();
        if !val.is_empty() {
            result.push(val.to_string());
        }
    }
    result
}

// ─── Hash functions (for address hashing, matching C++ djb2/sdbm) ───────────

pub fn sdbm_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &c in data {
        hash = (c as u32)
            .wrapping_add(hash.wrapping_shl(6))
            .wrapping_add(hash.wrapping_shl(16))
            .wrapping_sub(hash);
    }
    hash
}

// ─── LRU collector ──────────────────────────────────────────────────────────

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

pub struct LruCollector<K: Hash + Eq + Clone> {
    map: HashMap<K, MyTime>,
    queue: VecDeque<(K, MyTime)>,
}

impl<K: Hash + Eq + Clone> LruCollector<K> {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: HashMap::with_capacity(cap),
            queue: VecDeque::with_capacity(cap),
        }
    }

    pub fn new_key(&mut self, key: K) {
        let ts = get_current_time();
        self.map.insert(key.clone(), ts);
        self.queue.push_front((key, ts));
    }

    pub fn update(&mut self, key: &K) {
        let ts = get_current_time();
        self.map.insert(key.clone(), ts);
        // Lazy cleanup: don't remove old entry from queue, just update map.
        // Stale entries in queue will be skipped during peek_back.
        self.queue.push_front((key.clone(), ts));
        // Compact when queue grows too large relative to actual entries.
        // Without this, a conversation updated 1000 times creates 1000 queue entries.
        // Amortized cost is O(1) per update due to the 3× threshold.
        if self.queue.len() > self.map.len() * 3 + 16 {
            self.queue.retain(|(k, t)| {
                self.map.get(k).map_or(false, |&mt| mt == *t)
            });
        }
    }

    pub fn size(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.queue.clear();
    }

    /// Peek the oldest entry. Returns (key, timestamp).
    /// Skips stale entries whose timestamp doesn't match the map.
    pub fn peek_back(&mut self) -> Option<(K, MyTime)> {
        while let Some((key, ts)) = self.queue.back() {
            if let Some(&map_ts) = self.map.get(key) {
                if map_ts == *ts {
                    return Some((key.clone(), *ts));
                }
            }
            // Stale entry, remove it
            self.queue.pop_back();
        }
        None
    }

    pub fn erase(&mut self, key: &K) {
        self.map.remove(key);
        // Lazy: stale entries in queue will be cleaned by peek_back
    }
}

// ─── Wrapping comparison (matching C++ larger_than_u32) ─────────────────────

#[inline]
pub fn larger_than_u32(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
pub fn larger_than_u16(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}

// ─── Enums ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramMode {
    Unset,
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMode {
    FakeTcp,
    Udp,
    Icmp,
}

impl fmt::Display for RawMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawMode::FakeTcp => write!(f, "faketcp"),
            RawMode::Udp => write!(f, "udp"),
            RawMode::Icmp => write!(f, "icmp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    None,
    Aes128Cbc,
    Xor,
    Aes128Cfb,
}

impl fmt::Display for CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherMode::None => write!(f, "none"),
            CipherMode::Aes128Cbc => write!(f, "aes128cbc"),
            CipherMode::Xor => write!(f, "xor"),
            CipherMode::Aes128Cfb => write!(f, "aes128cfb"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    None,
    Md5,
    Crc32,
    Simple,
    HmacSha1,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMode::None => write!(f, "none"),
            AuthMode::Md5 => write!(f, "md5"),
            AuthMode::Crc32 => write!(f, "crc32"),
            AuthMode::Simple => write!(f, "simple"),
            AuthMode::HmacSha1 => write!(f, "hmac_sha1"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Idle,
    TcpHandshake,
    TcpHandshakeDummy,
    Handshake1,
    Handshake2,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    Idle,
    Handshake1,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Client(ClientState),
    Server(ServerState),
}

// ─── MyExit ─────────────────────────────────────────────────────────────────

pub fn myexit(code: i32) -> ! {
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numbers_roundtrip() {
        let (a, b, c) = (0x12345678, 0xDEADBEEF, 0x0A0B0C0D);
        let bytes = numbers_to_bytes(a, b, c);
        let (a2, b2, c2) = bytes_to_numbers(&bytes).unwrap();
        assert_eq!((a, b, c), (a2, b2, c2));
    }

    #[test]
    fn test_read_write_u16() {
        let mut buf = [0u8; 2];
        write_u16(&mut buf, 0x1234);
        assert_eq!(read_u16(&buf), 0x1234);
    }

    #[test]
    fn test_read_write_u32() {
        let mut buf = [0u8; 4];
        write_u32(&mut buf, 0xDEADBEEF);
        assert_eq!(read_u32(&buf), 0xDEADBEEF);
    }

    #[test]
    fn test_parse_conf_line() {
        assert!(parse_conf_line("# comment").is_empty());
        assert!(parse_conf_line("").is_empty());
        assert_eq!(parse_conf_line("-k passwd"), vec!["-k", "passwd"]);
        assert_eq!(parse_conf_line("--raw-mode faketcp"), vec!["--raw-mode", "faketcp"]);
        assert_eq!(parse_conf_line("-c"), vec!["-c"]);
    }

    #[test]
    fn test_larger_than_u32() {
        assert!(larger_than_u32(10, 5));
        assert!(!larger_than_u32(5, 10));
        // Wrapping case
        assert!(larger_than_u32(0, u32::MAX));
    }

    #[test]
    fn test_lru_collector() {
        let mut lru = LruCollector::<u32>::new();
        lru.new_key(1);
        lru.new_key(2);
        lru.new_key(3);
        assert_eq!(lru.size(), 3);
        // Oldest should be 1
        let (key, _) = lru.peek_back().unwrap();
        assert_eq!(key, 1);
        lru.erase(&1);
        assert_eq!(lru.size(), 2);
    }
}

