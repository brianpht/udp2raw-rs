//! Network module: raw socket I/O, packet header structs, BPF filters.
//! Corresponds to network.{h,cpp} in the C++ version.

use crate::common::*;
use crate::misc::Config;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

#[derive(Clone, Debug, Default)]
pub struct RawInfo {
    pub send_info: PacketInfo,
    pub recv_info: PacketInfo,
    pub peek: bool,
    pub reserved_send_seq: u32,
    pub rst_received: i32,
    pub disabled: bool,
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
    pub is_client: bool,
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
            is_client: config.program_mode == ProgramMode::Client,
        })
    }


    /// Attach BPF filter for the specified port.
    /// Generates and attaches a BPF program to the raw recv socket to filter
    /// only the protocol and port we're interested in, matching C++ gen_bpf_filter.
    pub fn init_filter(&mut self, port: u16, config: &Config) {

        if config.disable_bpf_filter {
            return;
        }
        self.filter_port = port as i32;

        // Build BPF filter instructions based on raw_mode.
        //
        // For raw sockets (not AF_PACKET), the BPF program sees the full IP packet
        // starting at the IP header. Offsets:
        //   byte 0: version_ihl
        //   byte 9: protocol
        //   IP header length: (byte[0] & 0x0f) * 4
        //
        // FakeTCP: ip[9] == 6 (TCP), dst_port at IP_hdr_len + 2 matches port
        // UDP:     ip[9] == 17 (UDP), dst_port at IP_hdr_len + 2 matches port
        // ICMP:    ip[9] == 1 (ICMP), icmp type at IP_hdr_len + 0 matches expected type

        let filter = match config.raw_mode {
            RawMode::FakeTcp => build_bpf_filter_tcp(port, config.program_mode),
            RawMode::Udp => build_bpf_filter_udp(port, config.program_mode),
            RawMode::Icmp => build_bpf_filter_icmp(config.program_mode),
        };

        if filter.is_empty() {
            log::warn!("BPF filter generation failed, running without filter");
            return;
        }

        let fprog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };

        let ret = unsafe {
            libc::setsockopt(
                self.raw_recv_fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            log::warn!("BPF filter attach failed: {}", std::io::Error::last_os_error());
        } else {
            log::info!("BPF filter attached for port {} ({})", port, config.raw_mode);
        }
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
                packet[20..20 + payload.len()].copy_from_slice(payload);


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

    /// Receive a raw IP packet. Returns `(ihl, recv_len)` — the IP payload is
    /// at `self.g_packet_buf[ihl..recv_len]`. Zero-copy: no heap allocation.
    fn recv_raw_ip_offsets(&mut self, raw_info: &mut RawInfo) -> io::Result<(usize, usize)> {

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

            Ok((ihl, recv_len))
        } else {
            Err(io::Error::new(io::ErrorKind::Unsupported, "non-IPv4"))
        }
    }

    /// Discard one pending raw packet.
    pub fn discard_raw_packet(&mut self) {

        let mut buf = [0u8; 1];
        unsafe {
            libc::recv(self.raw_recv_fd, buf.as_mut_ptr() as *mut libc::c_void, 0, 0);
        }
    }

    /// Build and send a FakeTCP packet.
    /// Includes TCP timestamp option (12 bytes) when `has_ts` is set, matching C++ behavior.
    pub fn send_raw_tcp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;

        // TCP header: 20 bytes base + optional 12-byte timestamp (NOP, NOP, TS val, TS ecr)
        let has_ts = send_info.has_ts;
        let tcp_hdr_len: usize = if has_ts { 32 } else { 20 };
        let tcp_len = tcp_hdr_len + payload.len();
        let mut tcp_buf = [0u8; SEND_BUF_SIZE];

        let mut tcph = TcpHeader::default();
        tcph.source = send_info.src_port.to_be();
        tcph.dest = send_info.dst_port.to_be();
        tcph.seq = send_info.seq.to_be();
        tcph.ack_seq = send_info.ack_seq.to_be();
        tcph.set_doff(if has_ts { 8 } else { 5 });
        tcph.set_flags(false, send_info.syn, false, send_info.psh, send_info.ack);
        tcph.window = 65535u16.to_be();
        tcph.check = 0;
        tcph.urg_ptr = 0;

        // Copy TCP header
        let hdr_bytes = tcph.as_bytes();
        tcp_buf[..20].copy_from_slice(hdr_bytes);

        if has_ts {
            // TCP timestamp option: NOP(1), NOP(1), Timestamp(10)
            // Kind=8, Length=10, TSval(4), TSecr(4)
            tcp_buf[20] = 0x01; // NOP
            tcp_buf[21] = 0x01; // NOP
            tcp_buf[22] = 0x08; // Timestamp kind
            tcp_buf[23] = 0x0A; // Timestamp length (10)
            tcp_buf[24..28].copy_from_slice(&send_info.ts.to_be_bytes());
            tcp_buf[28..32].copy_from_slice(&send_info.ts_ack.to_be_bytes());
        }

        if !payload.is_empty() {
            tcp_buf[tcp_hdr_len..tcp_hdr_len + payload.len()].copy_from_slice(payload);
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
    /// `icmp_type`: 8 for echo request (client), 0 for echo reply (server).
    pub fn send_raw_icmp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
        icmp_type: u8,
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;
        let icmp_len = 8 + payload.len();
        let mut icmp_buf = [0u8; SEND_BUF_SIZE];

        icmp_buf[0] = icmp_type;
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
            RawMode::Icmp => {
                // Client sends echo request (type 8), server sends echo reply (type 0)
                let icmp_type = if self.is_client { 8 } else { 0 };
                self.send_raw_icmp(raw_info, payload, icmp_type)
            }
        }
    }

    /// Receive a raw IP packet. Writes IP payload (after IP header) into `output`.
    /// Returns the number of bytes written to `output`.
    pub fn recv_raw_ip(&mut self, raw_info: &mut RawInfo, output: &mut [u8]) -> io::Result<usize> {

        let (ihl, recv_len) = self.recv_raw_ip_offsets(raw_info)?;

        // Zero-copy: write directly into caller's output buffer
        let payload_len = recv_len - ihl;
        output[..payload_len].copy_from_slice(&self.g_packet_buf[ihl..recv_len]);
        Ok(payload_len)
    }

    /// Receive and parse a raw packet. Writes payload after protocol header into `output`.
    /// Returns the number of bytes written. Zero heap allocations.
    pub fn recv_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        raw_mode: RawMode,
        output: &mut [u8],
    ) -> io::Result<usize> {
        let (ihl, recv_len) = self.recv_raw_ip_offsets(raw_info)?;
        // g_packet_buf[ihl..recv_len] is the IP payload — mutable borrow released
        parse_protocol_payload(&self.g_packet_buf[ihl..recv_len], raw_info, raw_mode, output)
    }
}

/// Parse protocol headers from an IP payload and extract the application data.
/// Shared by RawSocketState::recv_raw0 and XdpSocketState::recv_raw0.
/// Writes the extracted data into `output` and returns the number of bytes written.
pub fn parse_protocol_payload(
    ip_payload: &[u8],
    raw_info: &mut RawInfo,
    raw_mode: RawMode,
    output: &mut [u8],
) -> io::Result<usize> {
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

            // Parse TCP timestamp option (NOP, NOP, Kind=8, Len=10, TSval, TSecr)
            raw_info.recv_info.has_ts = false;
            if doff > 20 && ip_payload.len() >= doff {
                let mut opt_offset = 20;
                while opt_offset < doff {
                    let kind = ip_payload[opt_offset];
                    if kind == 0 {
                        break; // End of options
                    }
                    if kind == 1 {
                        opt_offset += 1; // NOP
                        continue;
                    }
                    if opt_offset + 1 >= doff {
                        break;
                    }
                    let opt_len = ip_payload[opt_offset + 1] as usize;
                    if opt_len < 2 || opt_offset + opt_len > doff {
                        break;
                    }
                    if kind == 8 && opt_len == 10 && opt_offset + 10 <= doff {
                        // Timestamp option
                        raw_info.recv_info.ts = u32::from_be_bytes([
                            ip_payload[opt_offset + 2],
                            ip_payload[opt_offset + 3],
                            ip_payload[opt_offset + 4],
                            ip_payload[opt_offset + 5],
                        ]);
                        raw_info.recv_info.ts_ack = u32::from_be_bytes([
                            ip_payload[opt_offset + 6],
                            ip_payload[opt_offset + 7],
                            ip_payload[opt_offset + 8],
                            ip_payload[opt_offset + 9],
                        ]);
                        raw_info.recv_info.has_ts = true;
                    }
                    opt_offset += opt_len;
                }
            }

            if doff > ip_payload.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "TCP doff exceeds packet"));
            }

            let data_len = ip_payload.len() - doff;
            output[..data_len].copy_from_slice(&ip_payload[doff..]);
            raw_info.recv_info.data_len = data_len as i32;
            Ok(data_len)
        }
        RawMode::Udp => {
            if ip_payload.len() < 8 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP header truncated"));
            }
            let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
            let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
            raw_info.recv_info.src_port = src_port;
            raw_info.recv_info.dst_port = dst_port;

            let data_len = ip_payload.len() - 8;
            output[..data_len].copy_from_slice(&ip_payload[8..]);
            raw_info.recv_info.data_len = data_len as i32;
            Ok(data_len)
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

            let data_len = ip_payload.len() - 8;
            output[..data_len].copy_from_slice(&ip_payload[8..]);
            raw_info.recv_info.data_len = data_len as i32;
            Ok(data_len)
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
/// seq_mode: 0=noop, 1=increase by data_len, 2=increase by random, 3=real-seq, 4=noop (handled by timer)
pub fn after_send_raw0(raw_info: &mut RawInfo, seq_mode: u32) {
    match seq_mode {
        0 | 4 => {
            // mode 0: don't increase seq at all
            // mode 4: seq is updated by periodic timer, not per-packet
        }
        1 => {
            // mode 1: increase seq by data_len
            if raw_info.send_info.data_len > 0 {
                raw_info.send_info.seq = raw_info
                    .send_info
                    .seq
                    .wrapping_add(raw_info.send_info.data_len as u32);
            }
        }
        2 => {
            // mode 2: increase seq by a random amount (1..=100)
            let r = (get_true_random_number() % 100).wrapping_add(1);
            raw_info.send_info.seq = raw_info.send_info.seq.wrapping_add(r);
        }
        3 => {
            // mode 3 (real seq mode): increase seq by data_len, ack follows recv
            if raw_info.send_info.data_len > 0 {
                raw_info.send_info.seq = raw_info
                    .send_info
                    .seq
                    .wrapping_add(raw_info.send_info.data_len as u32);
            }
        }
        _ => {
            // Unknown mode — treat like mode 0
        }
    }
}

/// Update seq/ack after receiving (matching C++ after_recv_raw0).
/// seq_mode: 0=noop, 1=update ack, 2=noop, 3=real-seq (update ack), 4=noop
pub fn after_recv_raw0(raw_info: &mut RawInfo, seq_mode: u32) {
    match seq_mode {
        0 | 2 | 4 => {
            // No ack update for these modes
        }
        1 => {
            // mode 1: ack = recv_seq + data_len
            if raw_info.recv_info.data_len > 0 {
                raw_info.send_info.ack_seq = raw_info
                    .recv_info
                    .seq
                    .wrapping_add(raw_info.recv_info.data_len as u32);
            }
        }
        3 => {
            // mode 3 (real seq mode): ack = recv_seq + data_len, track ts
            if raw_info.recv_info.data_len > 0 {
                raw_info.send_info.ack_seq = raw_info
                    .recv_info
                    .seq
                    .wrapping_add(raw_info.recv_info.data_len as u32);
            }
            if raw_info.recv_info.has_ts {
                raw_info.send_info.ts_ack = raw_info.recv_info.ts;
            }
        }
        _ => {
            // Unknown mode — treat like mode 0
        }
    }
}

// ─── BPF filter builders ────────────────────────────────────────────────────

/// BPF instruction helper: creates a libc::sock_filter
#[inline]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

#[inline]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

// BPF opcodes
const BPF_LD: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_B: u16 = 0x10;
const BPF_H: u16 = 0x08;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;
const BPF_MSH: u16 = 0xa0;
const BPF_LDX: u16 = 0x01;
const BPF_IND: u16 = 0x40;

/// Build BPF filter for FakeTCP mode.
/// Matches: ip[9] == 6 (TCP) && tcp.dport/sport == port
fn build_bpf_filter_tcp(port: u16, mode: ProgramMode) -> Vec<libc::sock_filter> {
    let port32 = port as u32;
    // For client: filter on source port (server sends from its port)
    // For server: filter on destination port (client sends to our port)
    let port_offset: u32 = match mode {
        ProgramMode::Client => 0, // tcp.sport (offset 0 from TCP header start)
        _ => 2,                    // tcp.dport (offset 2 from TCP header start)
    };

    vec![
        // Load ip protocol byte at offset 9
        bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 9),
        // If protocol != TCP (6), reject
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 4),
        // Load IHL (IP header length) for index register
        bpf_stmt(BPF_LDX | BPF_B | BPF_MSH, 0),
        // Load tcp port at IHL + port_offset as u16
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, port_offset),
        // If port matches, accept
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, port32, 0, 1),
        // Accept (return max length)
        bpf_stmt(BPF_RET | BPF_K, 0xFFFFFFFF),
        // Reject
        bpf_stmt(BPF_RET | BPF_K, 0),
    ]
}

/// Build BPF filter for UDP raw mode.
/// Matches: ip[9] == 17 (UDP) && udp.dport/sport == port
fn build_bpf_filter_udp(port: u16, mode: ProgramMode) -> Vec<libc::sock_filter> {
    let port32 = port as u32;
    let port_offset: u32 = match mode {
        ProgramMode::Client => 0, // udp.sport
        _ => 2,                    // udp.dport
    };

    vec![
        bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 9),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 4),
        bpf_stmt(BPF_LDX | BPF_B | BPF_MSH, 0),
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, port_offset),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, port32, 0, 1),
        bpf_stmt(BPF_RET | BPF_K, 0xFFFFFFFF),
        bpf_stmt(BPF_RET | BPF_K, 0),
    ]
}

/// Build BPF filter for ICMP raw mode.
/// Matches: ip[9] == 1 (ICMP) && icmp.type matches expected direction.
/// Server expects echo request (type 8), client expects echo reply (type 0).
fn build_bpf_filter_icmp(mode: ProgramMode) -> Vec<libc::sock_filter> {
    let expected_type: u32 = match mode {
        ProgramMode::Client => 0, // echo reply
        _ => 8,                    // echo request
    };

    vec![
        bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 9),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 4),
        bpf_stmt(BPF_LDX | BPF_B | BPF_MSH, 0),
        // ICMP type is first byte of ICMP header (offset 0 from IP header end)
        bpf_stmt(BPF_LD | BPF_B | BPF_IND, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, expected_type, 0, 1),
        bpf_stmt(BPF_RET | BPF_K, 0xFFFFFFFF),
        bpf_stmt(BPF_RET | BPF_K, 0),
    ]
}



