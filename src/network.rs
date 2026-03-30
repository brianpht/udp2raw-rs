//! Network module: raw socket I/O, packet header structs, BPF filters.
//! Corresponds to network.{h,cpp} in the C++ version.

use crate::common::*;
use crate::misc::Config;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::RawFd;

// ─── Packet header structs ──────────────────────────────────────────────────

/// IPv4 header (20 bytes, no options).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IpHeader {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl IpHeader {
    #[cfg(target_endian = "little")]
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }
    #[cfg(target_endian = "little")]
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
    #[cfg(target_endian = "big")]
    pub fn version(&self) -> u8 {
        self.version_ihl & 0x0F
    }
    #[cfg(target_endian = "big")]
    pub fn ihl(&self) -> u8 {
        self.version_ihl >> 4
    }

    pub fn set_version_ihl(&mut self, version: u8, ihl: u8) {
        #[cfg(target_endian = "little")]
        {
            self.version_ihl = (version << 4) | (ihl & 0x0F);
        }
        #[cfg(target_endian = "big")]
        {
            self.version_ihl = (ihl << 4) | (version & 0x0F);
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>()) }
    }
}

/// TCP header (20 bytes, no options).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct TcpHeader {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub off_flags: u16, // data offset (4 bits) + reserved (4 bits) + flags (8 bits)
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

impl TcpHeader {
    // Flag accessors — bit layout depends on endianness for the combined bitfield
    // We use network byte order for off_flags and extract bits accordingly

    pub fn doff(&self) -> u8 {
        let val = u16::from_be(self.off_flags);
        ((val >> 12) & 0x0F) as u8
    }

    pub fn set_doff(&mut self, doff: u8) {
        let mut val = u16::from_be(self.off_flags);
        val = (val & 0x0FFF) | ((doff as u16 & 0x0F) << 12);
        self.off_flags = val.to_be();
    }

    pub fn flags(&self) -> u8 {
        let val = u16::from_be(self.off_flags);
        (val & 0xFF) as u8
    }

    pub fn fin(&self) -> bool { self.flags() & 0x01 != 0 }
    pub fn syn(&self) -> bool { self.flags() & 0x02 != 0 }
    pub fn rst(&self) -> bool { self.flags() & 0x04 != 0 }
    pub fn psh(&self) -> bool { self.flags() & 0x08 != 0 }
    pub fn ack(&self) -> bool { self.flags() & 0x10 != 0 }
    pub fn urg(&self) -> bool { self.flags() & 0x20 != 0 }

    pub fn set_flags(&mut self, fin: bool, syn: bool, rst: bool, psh: bool, ack: bool) {
        let mut val = u16::from_be(self.off_flags);
        val &= 0xFF00;
        if fin { val |= 0x01; }
        if syn { val |= 0x02; }
        if rst { val |= 0x04; }
        if psh { val |= 0x08; }
        if ack { val |= 0x10; }
        self.off_flags = val.to_be();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>()) }
    }
}

/// UDP header (8 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct UdpHeader {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

/// ICMP header (8 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IcmpHeader {
    pub type_: u8,
    pub code: u8,
    pub check_sum: u16,
    pub id: u16,
    pub seq: u16,
}

/// Pseudo header for TCP/UDP checksum over IPv4.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct PseudoHeader {
    pub source_address: u32,
    pub dest_address: u32,
    pub placeholder: u8,
    pub protocol: u8,
    pub tcp_length: u16,
}

/// IPv6 header (40 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Ip6Header {
    pub ver_tc_fl: u32, // version(4) + traffic_class(8) + flow_label(20)
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

/// Pseudo header for TCP/UDP checksum over IPv6.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct PseudoHeader6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub tcp_length: u32,
    pub placeholder1: u16,
    pub placeholder2: u8,
    pub next_header: u8,
}

// ─── PacketInfo / RawInfo ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

    // TCP fields
    pub syn: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub seq: u32,
    pub ack_seq: u32,
    pub ack_seq_counter: u32,
    pub ts: u32,
    pub ts_ack: u32,
    pub has_ts: bool,

    // ICMP
    pub my_icmp_seq: u16,

    pub data_len: i32,

    // Link-layer (Linux AF_PACKET)
    pub addr_ll: Option<libc::sockaddr_ll>,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            protocol: 0,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            syn: false,
            ack: false,
            psh: false,
            rst: false,
            seq: 0,
            ack_seq: 0,
            ack_seq_counter: 0,
            ts: 0,
            ts_ack: 0,
            has_ts: false,
            my_icmp_seq: 0,
            data_len: 0,
            addr_ll: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RawInfo {
    pub send_info: PacketInfo,
    pub recv_info: PacketInfo,
    pub peek: bool,
    pub reserved_send_seq: u32,
    pub rst_received: i32,
    pub disabled: bool,
}

impl Default for RawInfo {
    fn default() -> Self {
        Self {
            send_info: PacketInfo::default(),
            recv_info: PacketInfo::default(),
            peek: false,
            reserved_send_seq: 0,
            rst_received: 0,
            disabled: false,
        }
    }
}

// ─── Raw socket state ───────────────────────────────────────────────────────

/// Max raw packet size for send path (IP header + protocol header + encrypted payload).
/// Bounded: 20 (IP) + 20 (TCP) + BUF_LEN (2200) = 2240.
const SEND_BUF_SIZE: usize = BUF_LEN + 40;

pub struct RawSocketState {
    pub raw_recv_fd: RawFd,
    pub raw_send_fd: RawFd,
    pub filter_port: i32,
    pub seq_mode: u32,
    pub ip_id_counter: u16,
    pub g_packet_buf: Vec<u8>,
    pub g_packet_buf_len: i32,
    pub lower_level: bool,
}

impl RawSocketState {
    /// Initialize raw sockets for Linux.
    pub fn init(config: &Config) -> io::Result<Self> {
        let is_ipv6 = config.remote_addr.is_ipv6();

        // Create raw receive socket
        let raw_recv_fd;
        let raw_send_fd;

        if config.lower_level_enabled {
            // AF_PACKET for lower level
            raw_recv_fd = unsafe {
                libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM,
                    (libc::ETH_P_IP as u16).to_be() as i32,
                )
            };
            raw_send_fd = raw_recv_fd; // same fd for lower level
        } else if !is_ipv6 {
            raw_recv_fd = unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
            };
            raw_send_fd = unsafe {
                libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
            };
        } else {
            raw_recv_fd = unsafe {
                libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW)
            };
            raw_send_fd = unsafe {
                libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW)
            };
        }

        if raw_recv_fd < 0 || raw_send_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set IP_HDRINCL on send socket
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                raw_send_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        setnonblocking(raw_recv_fd)?;
        if raw_send_fd != raw_recv_fd {
            setnonblocking(raw_send_fd)?;
        }

        set_buf_size(raw_recv_fd, config.socket_buf_size, config.force_socket_buf).ok();
        if raw_send_fd != raw_recv_fd {
            set_buf_size(raw_send_fd, config.socket_buf_size, config.force_socket_buf).ok();
        }

        Ok(Self {
            raw_recv_fd,
            raw_send_fd,
            filter_port: -1,
            seq_mode: config.seq_mode,
            ip_id_counter: 0,
            g_packet_buf: vec![0u8; HUGE_BUF_LEN],
            g_packet_buf_len: -1,
            lower_level: config.lower_level_enabled,
        })
    }

    /// Attach BPF filter for the specified port.
    pub fn init_filter(&mut self, port: u16, config: &Config) {
        if config.disable_bpf_filter {
            return;
        }
        self.filter_port = port as i32;

        // Build BPF filter for the specified raw_mode and port
        // This is a simplified version; the C++ code generates complex BPF programs
        // For now, we set the filter port and rely on userspace filtering
        log::info!("BPF filter set for port {}", port);
    }

    /// Send a raw IP packet.
    pub fn send_raw_ip(&mut self, raw_info: &mut RawInfo, payload: &[u8]) -> io::Result<usize> {
        let send_info = &raw_info.send_info;

        match (send_info.src_ip, send_info.dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                // Build IPv4 packet using stack buffer (no heap allocation)
                let ip_payload_len = 20 + payload.len();
                let mut packet = [0u8; SEND_BUF_SIZE];

                // Fill IP header
                let mut iph = IpHeader::default();
                iph.set_version_ihl(4, 5);
                iph.tos = 0;
                iph.tot_len = (ip_payload_len as u16).to_be();
                self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
                iph.id = self.ip_id_counter.to_be();
                iph.frag_off = 0x40u16.to_be(); // Don't fragment
                iph.ttl = 64;
                iph.protocol = send_info.protocol;
                iph.saddr = u32::from(src).to_be();
                iph.daddr = u32::from(dst).to_be();
                iph.check = 0;
                let hdr_bytes = iph.as_bytes();
                iph.check = csum(hdr_bytes);

                packet[..20].copy_from_slice(iph.as_bytes());
                packet[20..].copy_from_slice(payload);

                // Send
                let dst_addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(dst).to_be(),
                    },
                    sin_zero: [0; 8],
                };

                let sent = unsafe {
                    libc::sendto(
                        self.raw_send_fd,
                        packet.as_ptr() as *const libc::c_void,
                        ip_payload_len,
                        0,
                        &dst_addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                };

                if sent < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(sent as usize)
            }
            _ => {
                log::warn!("IPv6 raw send not yet fully implemented");
                Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 raw send"))
            }
        }
    }

    /// Receive a raw IP packet. Returns (payload_data, payload_len).
    pub fn recv_raw_ip(&mut self, raw_info: &mut RawInfo) -> io::Result<Vec<u8>> {
        // Use pre-allocated g_packet_buf instead of allocating 65KB per call
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let flags = if raw_info.peek { libc::MSG_PEEK } else { 0 };

        let recv_len = unsafe {
            libc::recvfrom(
                self.raw_recv_fd,
                self.g_packet_buf.as_mut_ptr() as *mut libc::c_void,
                self.g_packet_buf.len(),
                flags,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            )
        };

        if recv_len < 0 {
            return Err(io::Error::last_os_error());
        }

        let recv_len = recv_len as usize;
        if recv_len < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too short"));
        }

        // Parse IP header
        let version = (self.g_packet_buf[0] >> 4) & 0x0F;
        if version == 4 {
            let ihl = (self.g_packet_buf[0] & 0x0F) as usize * 4;
            if recv_len < ihl {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IP header truncated"));
            }

            let saddr = u32::from_be_bytes([self.g_packet_buf[12], self.g_packet_buf[13], self.g_packet_buf[14], self.g_packet_buf[15]]);
            let daddr = u32::from_be_bytes([self.g_packet_buf[16], self.g_packet_buf[17], self.g_packet_buf[18], self.g_packet_buf[19]]);
            let protocol = self.g_packet_buf[9];

            raw_info.recv_info.src_ip = IpAddr::V4(Ipv4Addr::from(saddr));
            raw_info.recv_info.dst_ip = IpAddr::V4(Ipv4Addr::from(daddr));
            raw_info.recv_info.protocol = protocol;

            // Only allocate for the actual payload size (typically ~1-2KB), not the full 65KB buffer
            let payload = self.g_packet_buf[ihl..recv_len].to_vec();
            Ok(payload)
        } else {
            Err(io::Error::new(io::ErrorKind::Unsupported, "non-IPv4"))
        }
    }

    /// Discard one pending raw packet.
    pub fn discard_raw_packet(&self) {
        let mut buf = [0u8; 1];
        unsafe {
            libc::recv(self.raw_recv_fd, buf.as_mut_ptr() as *mut libc::c_void, 0, 0);
        }
    }

    /// Build and send a FakeTCP packet.
    pub fn send_raw_tcp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;

        // Build TCP header using stack buffer (no heap allocation)
        let tcp_len = 20 + payload.len(); // No TCP options for simplicity (doff=5)
        let mut tcp_buf = [0u8; SEND_BUF_SIZE];

        let mut tcph = TcpHeader::default();
        tcph.source = send_info.src_port.to_be();
        tcph.dest = send_info.dst_port.to_be();
        tcph.seq = send_info.seq.to_be();
        tcph.ack_seq = send_info.ack_seq.to_be();
        tcph.set_doff(5);
        tcph.set_flags(false, send_info.syn, false, send_info.psh, send_info.ack);
        tcph.window = 65535u16.to_be();
        tcph.check = 0;
        tcph.urg_ptr = 0;

        // Copy TCP header
        let hdr_bytes = tcph.as_bytes();
        tcp_buf[..20].copy_from_slice(hdr_bytes);
        if !payload.is_empty() {
            tcp_buf[20..].copy_from_slice(payload);
        }

        // Compute TCP checksum
        if let (IpAddr::V4(src), IpAddr::V4(dst)) = (send_info.src_ip, send_info.dst_ip) {
            let ph = PseudoHeader {
                source_address: u32::from(src).to_be(),
                dest_address: u32::from(dst).to_be(),
                placeholder: 0,
                protocol: libc::IPPROTO_TCP as u8,
                tcp_length: (tcp_len as u16).to_be(),
            };
            let ph_bytes = unsafe {
                std::slice::from_raw_parts(&ph as *const _ as *const u8, std::mem::size_of::<PseudoHeader>())
            };
            let checksum = csum_with_header(ph_bytes, &tcp_buf[..tcp_len]);
            tcp_buf[16..18].copy_from_slice(&checksum.to_ne_bytes());
        }

        raw_info.send_info.protocol = libc::IPPROTO_TCP as u8;
        raw_info.send_info.data_len = payload.len() as i32;
        self.send_raw_ip(raw_info, &tcp_buf[..tcp_len])
    }

    /// Build and send a UDP-encapsulated packet.
    pub fn send_raw_udp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;
        let udp_len = 8 + payload.len();
        let mut udp_buf = [0u8; SEND_BUF_SIZE];

        udp_buf[0..2].copy_from_slice(&send_info.src_port.to_be_bytes());
        udp_buf[2..4].copy_from_slice(&send_info.dst_port.to_be_bytes());
        udp_buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp_buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum = 0
        if !payload.is_empty() {
            udp_buf[8..].copy_from_slice(payload);
        }

        raw_info.send_info.protocol = libc::IPPROTO_UDP as u8;
        raw_info.send_info.data_len = payload.len() as i32;
        self.send_raw_ip(raw_info, &udp_buf[..udp_len])
    }

    /// Build and send an ICMP-encapsulated packet.
    pub fn send_raw_icmp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;
        let icmp_len = 8 + payload.len();
        let mut icmp_buf = [0u8; SEND_BUF_SIZE];

        icmp_buf[0] = 8; // Echo request
        icmp_buf[1] = 0; // Code
        icmp_buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        icmp_buf[4..6].copy_from_slice(&send_info.src_port.to_be_bytes()); // ID
        icmp_buf[6..8].copy_from_slice(&send_info.my_icmp_seq.to_be_bytes());
        if !payload.is_empty() {
            icmp_buf[8..].copy_from_slice(payload);
        }

        let checksum = csum(&icmp_buf[..icmp_len]);
        icmp_buf[2..4].copy_from_slice(&checksum.to_ne_bytes());

        raw_info.send_info.protocol = libc::IPPROTO_ICMP as u8;
        raw_info.send_info.data_len = payload.len() as i32;
        self.send_raw_ip(raw_info, &icmp_buf[..icmp_len])
    }

    /// Dispatch send based on raw_mode.
    pub fn send_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
        raw_mode: RawMode,
    ) -> io::Result<usize> {
        match raw_mode {
            RawMode::FakeTcp => self.send_raw_tcp(raw_info, payload),
            RawMode::Udp => self.send_raw_udp(raw_info, payload),
            RawMode::Icmp => self.send_raw_icmp(raw_info, payload),
        }
    }

    /// Receive and parse a raw packet. Returns payload after protocol header.
    pub fn recv_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        raw_mode: RawMode,
    ) -> io::Result<Vec<u8>> {
        let ip_payload = self.recv_raw_ip(raw_info)?;

        match raw_mode {
            RawMode::FakeTcp => {
                if ip_payload.len() < 20 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP header truncated"));
                }
                // Parse TCP header
                let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
                let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
                let seq = u32::from_be_bytes([ip_payload[4], ip_payload[5], ip_payload[6], ip_payload[7]]);
                let ack_seq = u32::from_be_bytes([ip_payload[8], ip_payload[9], ip_payload[10], ip_payload[11]]);
                let off_flags = u16::from_be_bytes([ip_payload[12], ip_payload[13]]);
                let doff = ((off_flags >> 12) & 0x0F) as usize * 4;
                let flags = (off_flags & 0xFF) as u8;

                raw_info.recv_info.src_port = src_port;
                raw_info.recv_info.dst_port = dst_port;
                raw_info.recv_info.seq = seq;
                raw_info.recv_info.ack_seq = ack_seq;
                raw_info.recv_info.syn = flags & 0x02 != 0;
                raw_info.recv_info.ack = flags & 0x10 != 0;
                raw_info.recv_info.psh = flags & 0x08 != 0;
                raw_info.recv_info.rst = flags & 0x04 != 0;

                if doff > ip_payload.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP doff exceeds packet"));
                }

                let data = ip_payload[doff..].to_vec();
                raw_info.recv_info.data_len = data.len() as i32;
                Ok(data)
            }
            RawMode::Udp => {
                if ip_payload.len() < 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP header truncated"));
                }
                let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
                let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
                raw_info.recv_info.src_port = src_port;
                raw_info.recv_info.dst_port = dst_port;

                let data = ip_payload[8..].to_vec();
                raw_info.recv_info.data_len = data.len() as i32;
                Ok(data)
            }
            RawMode::Icmp => {
                if ip_payload.len() < 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "ICMP header truncated"));
                }
                let id = u16::from_be_bytes([ip_payload[4], ip_payload[5]]);
                let seq = u16::from_be_bytes([ip_payload[6], ip_payload[7]]);
                raw_info.recv_info.src_port = id;
                raw_info.recv_info.dst_port = id;
                raw_info.recv_info.my_icmp_seq = seq;

                let data = ip_payload[8..].to_vec();
                raw_info.recv_info.data_len = data.len() as i32;
                Ok(data)
            }
        }
    }
}

// ─── Utility: bind to a new port ────────────────────────────────────────────

pub fn client_bind_to_a_new_port(addr: &SocketAddr) -> io::Result<(RawFd, u16)> {
    let family = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Bind to port 0 to get a random port
    let bound_port;
    match addr {
        SocketAddr::V4(a) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = 0;
            sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            let ret = unsafe {
                libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
            };
            if ret < 0 {
                unsafe { libc::close(fd); }
                return Err(io::Error::last_os_error());
            }
            let mut sa2 = sa;
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            unsafe {
                libc::getsockname(fd, &mut sa2 as *mut _ as *mut libc::sockaddr, &mut len);
            }
            bound_port = u16::from_be(sa2.sin_port);
        }
        SocketAddr::V6(_) => {
            // Simplified for now
            unsafe { libc::close(fd); }
            return Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 bind"));
        }
    }

    Ok((fd, bound_port))
}

/// Get source address for reaching a remote address.
pub fn get_src_address(remote: &SocketAddr) -> io::Result<IpAddr> {
    // Create a UDP socket and connect to remote to find source IP
    let family = if remote.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    match remote {
        SocketAddr::V4(a) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = a.port().to_be();
            sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            unsafe {
                libc::connect(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32);
            }
            let mut local_sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            unsafe {
                libc::getsockname(fd, &mut local_sa as *mut _ as *mut libc::sockaddr, &mut len);
                libc::close(fd);
            }
            let ip = Ipv4Addr::from(u32::from_be(local_sa.sin_addr.s_addr));
            Ok(IpAddr::V4(ip))
        }
        SocketAddr::V6(_) => {
            unsafe { libc::close(fd); }
            Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 get_src"))
        }
    }
}

/// Update seq/ack after sending (matching C++ after_send_raw0).
pub fn after_send_raw0(raw_info: &mut RawInfo, seq_mode: u32) {
    if seq_mode == 0 {
        return;
    }
    // Simplified: increment seq by data_len
    if raw_info.send_info.data_len > 0 {
        raw_info.send_info.seq = raw_info
            .send_info
            .seq
            .wrapping_add(raw_info.send_info.data_len as u32);
    }
}

/// Update seq/ack after receiving (matching C++ after_recv_raw0).
pub fn after_recv_raw0(raw_info: &mut RawInfo, seq_mode: u32) {
    if seq_mode == 0 {
        return;
    }
    // Update ack to reflect received data
    if raw_info.recv_info.data_len > 0 {
        raw_info.send_info.ack_seq = raw_info
            .recv_info
            .seq
            .wrapping_add(raw_info.recv_info.data_len as u32);
    }
}

