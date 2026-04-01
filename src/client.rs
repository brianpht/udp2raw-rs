//! Client event loop and state machine.
//! Corresponds to client.cpp in the C++ version.

use crate::common::*;
use crate::connection::*;
use crate::encrypt::Encryptor;
use crate::mio_fd::MioFdSource;
use crate::misc::{self, Config};
use crate::network;
use crate::transport::RawTransport;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::Duration;

use mio::{Events, Interest, Poll, Token};

const UDP_TOKEN: Token = Token(0);
const RAW_TOKEN: Token = Token(1);
const FIFO_TOKEN: Token = Token(2);


pub fn client_event_loop(
    config: &Config,
    encryptor: &Encryptor,
    raw_state: &mut RawTransport,
    const_id: MyId,
) -> io::Result<()> {
    let mut conn_info = ConnInfo::new_client();
    conn_info.my_id = get_true_random_number_nz();
    conn_info.prepare_client();

    let mut fail_time_counter: i32 = 0;
    let mut bind_fd: RawFd = -1;

    // Create UDP listen socket
    let udp_fd = unsafe {
        let family = if config.local_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP)
    };
    if udp_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    set_buf_size(udp_fd, config.socket_buf_size, config.force_socket_buf)?;

    // Bind UDP socket
    match config.local_addr {
        SocketAddr::V4(ref a) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = a.port().to_be();
            sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            if unsafe {
                libc::bind(
                    udp_fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        SocketAddr::V6(ref a) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = a.port().to_be();
            sa.sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
            if unsafe {
                libc::bind(
                    udp_fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    setnonblocking(udp_fd)?;

    // Set up send_info destination
    conn_info.raw_info.send_info.dst_ip = config.remote_addr.ip();
    conn_info.raw_info.send_info.dst_port = config.remote_addr.port();

    // Heartbeat buffer
    let hb_buf = vec![0u8; config.hb_len];

    // Setup mio poll
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);

    let mut udp_source = MioFdSource { fd: udp_fd };
    let mut raw_source = MioFdSource {
        fd: raw_state.recv_fd(),
    };

    poll.registry()
        .register(&mut udp_source, UDP_TOKEN, Interest::READABLE)?;
    poll.registry()
        .register(&mut raw_source, RAW_TOKEN, Interest::READABLE)?;

    // Optional FIFO
    let mut fifo_fd: Option<RawFd> = None;
    if let Some(ref path) = config.fifo_file {
        let fd = create_fifo(path)?;
        let mut fifo_source = MioFdSource { fd };
        poll.registry()
            .register(&mut fifo_source, FIFO_TOKEN, Interest::READABLE)?;
        fifo_fd = Some(fd);
    }

    log::info!(
        "client event loop started, local={}, remote={}",
        config.local_addr,
        config.remote_addr
    );

    let timer_duration = Duration::from_millis(misc::TIMER_INTERVAL);

    loop {
        poll.poll(&mut events, Some(timer_duration))?;

        // Timer tick (always, even if events exist)
        client_on_timer(
            &mut conn_info,
            raw_state,
            encryptor,
            config,
            const_id,
            &mut bind_fd,
            &mut fail_time_counter,
            &hb_buf,
        );

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    client_on_udp_recv(
                        &mut conn_info,
                        raw_state,
                        encryptor,
                        config,
                        udp_fd,
                    );
                }
                RAW_TOKEN => {
                    client_on_raw_recv(
                        &mut conn_info,
                        raw_state,
                        encryptor,
                        config,
                        udp_fd,
                    );
                }
                FIFO_TOKEN => {
                    if let Some(fd) = fifo_fd {
                        let mut buf = [0u8; 1024];
                        let len = unsafe {
                            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                        };
                        if len > 0 {
                            let cmd = String::from_utf8_lossy(&buf[..len as usize]);
                            let cmd = cmd.trim();
                            log::info!("fifo command: {}", cmd);
                            if cmd == "reconnect" {
                                conn_info.state = ConnectionState::Client(ClientState::Idle);
                                conn_info.my_id = get_true_random_number_nz();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn client_on_timer(
    conn_info: &mut ConnInfo,
    raw_state: &mut RawTransport,
    encryptor: &Encryptor,
    config: &Config,
    const_id: MyId,
    bind_fd: &mut RawFd,
    fail_time_counter: &mut i32,
    hb_buf: &[u8],
) {
    let state = match conn_info.state {
        ConnectionState::Client(s) => s,
        _ => return,
    };

    let now = get_current_time();

    match state {
        ClientState::Idle => {
            // Clean up old bind_fd
            if *bind_fd >= 0 {
                unsafe { libc::close(*bind_fd); }
                *bind_fd = -1;
            }

            conn_info.raw_info.disabled = false;
            *fail_time_counter += 1;
            if misc::MAX_FAIL_TIME > 0 && *fail_time_counter > misc::MAX_FAIL_TIME {
                log::error!("max fail time exceeded");
                myexit(-1);
            }

            if let Some(ref mut blob) = conn_info.blob {
                blob.anti_replay.re_init();
            }
            conn_info.my_id = get_true_random_number_nz();

            // Determine source IP
            let src_ip = if let Some(ip) = config.source_ip {
                ip
            } else {
                network::get_src_address(&config.remote_addr).unwrap_or_else(|e| {
                    log::warn!("get_src_address failed: {}", e);
                    config.local_addr.ip()
                })
            };
            conn_info.raw_info.send_info.src_ip = src_ip;

            // Bind to a new port
            if config.source_port.is_none() {
                let bind_addr = SocketAddr::new(src_ip, 0);
                match network::client_bind_to_a_new_port(&bind_addr) {
                    Ok((fd, port)) => {
                        *bind_fd = fd;
                        conn_info.raw_info.send_info.src_port = port;
                    }
                    Err(e) => {
                        log::warn!("bind_to_new_port failed: {}", e);
                        return;
                    }
                }
            } else {
                conn_info.raw_info.send_info.src_port = config.source_port.unwrap();
            }

            raw_state.init_filter(conn_info.raw_info.send_info.src_port, config);

            // Transition state
            if config.raw_mode == RawMode::FakeTcp {
                if config.use_tcp_dummy_socket {
                    conn_info.state = ConnectionState::Client(ClientState::TcpHandshakeDummy);
                } else {
                    conn_info.state = ConnectionState::Client(ClientState::TcpHandshake);
                }
            } else {
                conn_info.state = ConnectionState::Client(ClientState::Handshake1);
            }

            conn_info.last_state_time = now;
            conn_info.last_hb_sent_time = 0;
            log::info!("state -> {:?}, src_port={}", conn_info.state, conn_info.raw_info.send_info.src_port);
        }

        ClientState::TcpHandshake | ClientState::TcpHandshakeDummy => {
            if now - conn_info.last_state_time > misc::CLIENT_HANDSHAKE_TIMEOUT {
                conn_info.state = ConnectionState::Client(ClientState::Idle);
                log::info!("tcp handshake timeout, back to idle");
                return;
            }
            if now - conn_info.last_hb_sent_time > misc::CLIENT_RETRY_INTERVAL {
                if conn_info.last_hb_sent_time == 0 {
                    conn_info.raw_info.send_info.psh = false;
                    conn_info.raw_info.send_info.syn = true;
                    conn_info.raw_info.send_info.ack = false;
                    conn_info.raw_info.send_info.seq = get_true_random_number();
                    conn_info.raw_info.send_info.ack_seq = get_true_random_number();
                    conn_info.raw_info.send_info.has_ts = true;
                    conn_info.raw_info.send_info.ts = (now & 0xFFFFFFFF) as u32;
                }
                let _ = raw_state.send_raw0(&mut conn_info.raw_info, &[], config.raw_mode);
                conn_info.last_hb_sent_time = now;
                log::info!("(re)sent TCP SYN");
            }
        }

        ClientState::Handshake1 => {
            if now - conn_info.last_state_time > misc::CLIENT_HANDSHAKE_TIMEOUT {
                conn_info.state = ConnectionState::Client(ClientState::Idle);
                log::info!("handshake1 timeout, back to idle");
                return;
            }
            if now - conn_info.last_hb_sent_time > misc::CLIENT_RETRY_INTERVAL {
                if config.raw_mode == RawMode::FakeTcp {
                    if conn_info.last_hb_sent_time == 0 {
                        conn_info.raw_info.send_info.seq = conn_info.raw_info.send_info.seq.wrapping_add(1);
                        conn_info.raw_info.send_info.ack_seq = conn_info.raw_info.recv_info.seq.wrapping_add(1);
                        conn_info.raw_info.send_info.ts_ack = conn_info.raw_info.recv_info.ts;
                        conn_info.raw_info.reserved_send_seq = conn_info.raw_info.send_info.seq;
                    }
                    conn_info.raw_info.send_info.seq = conn_info.raw_info.reserved_send_seq;
                    conn_info.raw_info.send_info.psh = false;
                    conn_info.raw_info.send_info.syn = false;
                    conn_info.raw_info.send_info.ack = true;
                    let _ = raw_state.send_raw0(&mut conn_info.raw_info, &[], config.raw_mode);
                }

                let _ = send_handshake(
                    raw_state, &mut conn_info.raw_info,
                    conn_info.my_id, 0, const_id,
                    encryptor, config.raw_mode,
                );

                if config.raw_mode == RawMode::FakeTcp {
                    conn_info.raw_info.send_info.seq = conn_info.raw_info.send_info.seq
                        .wrapping_add(conn_info.raw_info.send_info.data_len as u32);
                }

                conn_info.last_hb_sent_time = now;
                log::info!("(re)sent handshake1");
            }
        }

        ClientState::Handshake2 => {
            if now - conn_info.last_state_time > misc::CLIENT_HANDSHAKE_TIMEOUT {
                conn_info.state = ConnectionState::Client(ClientState::Idle);
                log::info!("handshake2 timeout, back to idle");
                return;
            }
            if now - conn_info.last_hb_sent_time > misc::CLIENT_RETRY_INTERVAL {
                if config.raw_mode == RawMode::FakeTcp {
                    if conn_info.last_hb_sent_time == 0 {
                        conn_info.raw_info.send_info.ack_seq = conn_info.raw_info.recv_info.seq
                            .wrapping_add(conn_info.raw_info.recv_info.data_len as u32);
                        conn_info.raw_info.send_info.ts_ack = conn_info.raw_info.recv_info.ts;
                        conn_info.raw_info.reserved_send_seq = conn_info.raw_info.send_info.seq;
                    }
                    conn_info.raw_info.send_info.seq = conn_info.raw_info.reserved_send_seq;
                }

                let _ = send_handshake(
                    raw_state, &mut conn_info.raw_info,
                    conn_info.my_id, conn_info.opposite_id, const_id,
                    encryptor, config.raw_mode,
                );

                if config.raw_mode == RawMode::FakeTcp {
                    conn_info.raw_info.send_info.seq = conn_info.raw_info.send_info.seq
                        .wrapping_add(conn_info.raw_info.send_info.data_len as u32);
                }

                conn_info.last_hb_sent_time = now;
                log::info!("(re)sent handshake2");
            }
        }

        ClientState::Ready => {
            *fail_time_counter = 0;

            if now - conn_info.last_hb_recv_time > misc::CLIENT_CONN_TIMEOUT {
                conn_info.state = ConnectionState::Client(ClientState::Idle);
                log::info!("server->client timeout, back to idle");
                return;
            }

            if now - conn_info.last_opposite_roller_time > misc::CLIENT_CONN_UPLINK_TIMEOUT {
                conn_info.state = ConnectionState::Client(ClientState::Idle);
                log::info!("client->server uplink timeout, back to idle");
                return;
            }

            if now - conn_info.last_hb_sent_time < misc::HEARTBEAT_INTERVAL {
                return;
            }

            log::debug!("heartbeat sent <{:x},{:x}>", conn_info.opposite_id, conn_info.my_id);
            let hb_data = if config.hb_mode == 0 { &[] as &[u8] } else { hb_buf };
            let _ = send_safer(raw_state, conn_info, b'h', hb_data, encryptor, config);
            conn_info.last_hb_sent_time = now;
        }
    }
}

fn client_on_raw_recv(
    conn_info: &mut ConnInfo,
    raw_state: &mut RawTransport,
    encryptor: &Encryptor,
    config: &Config,
    udp_fd: RawFd,
) {
    let state = match conn_info.state {
        ConnectionState::Client(s) => s,
        _ => return,
    };

    match state {
        ClientState::Idle => {
            raw_state.discard_raw_packet();
        }

        ClientState::TcpHandshake | ClientState::TcpHandshakeDummy => {
            let mut recv_buf = [0u8; BUF_LEN];
            let data_len = match raw_state.recv_raw0(&mut conn_info.raw_info, config.raw_mode, &mut recv_buf) {
                Ok(n) => n,
                Err(_) => return,
            };
            let ri = &conn_info.raw_info.recv_info;
            if ri.src_ip != conn_info.raw_info.send_info.dst_ip
                || ri.src_port != conn_info.raw_info.send_info.dst_port
            {
                return;
            }
            if data_len == 0 && ri.syn && ri.ack {
                conn_info.state = ConnectionState::Client(ClientState::Handshake1);
                conn_info.last_state_time = get_current_time();
                conn_info.last_hb_sent_time = 0;
                log::info!("received SYN+ACK, state -> Handshake1");
            }
        }

        ClientState::Handshake1 => {
            let mut data = [0u8; BUF_LEN];
            let data_len = match recv_bare(raw_state, &mut conn_info.raw_info, encryptor, config.raw_mode, &mut data) {
                Ok(n) => n,
                Err(_) => return,
            };
            if data_len < 12 {
                return;
            }
            let (tmp_opposite_id, tmp_my_id, _tmp_const_id) =
                match bytes_to_numbers(&data[..data_len]) {
                    Some(ids) => ids,
                    None => return,
                };
            if tmp_my_id != conn_info.my_id {
                log::debug!("handshake1 reply: my_id mismatch");
                return;
            }
            conn_info.opposite_id = tmp_opposite_id;
            conn_info.state = ConnectionState::Client(ClientState::Handshake2);
            conn_info.last_state_time = get_current_time();
            conn_info.last_hb_sent_time = 0;
            log::info!(
                "state -> Handshake2, my_id={:x} opposite_id={:x}",
                conn_info.my_id,
                conn_info.opposite_id
            );
        }

        ClientState::Handshake2 | ClientState::Ready => {
            // Check for RST before processing
            if config.raw_mode == RawMode::FakeTcp {
                // Peek to check for RST flag without consuming
                if conn_info.raw_info.recv_info.rst {
                    conn_info.raw_info.rst_received += 1;
                    if conn_info.raw_info.rst_received > 5 {
                        log::warn!("too many RST received, reconnecting");
                        conn_info.state = ConnectionState::Client(ClientState::Idle);
                        return;
                    }
                }
            }

            let packets = match recv_safer_multi(raw_state, conn_info, encryptor, config) {
                Ok(p) => p,
                Err(_) => return,
            };

            for pkt in packets {
                client_on_data_packet(conn_info, &pkt, config, udp_fd);
            }
        }
    }
}

fn client_on_data_packet(
    conn_info: &mut ConnInfo,
    pkt: &SaferPacket,
    config: &Config,
    udp_fd: RawFd,
) {
    let now = get_current_time();

    // Transition from Handshake2 to Ready on first valid packet
    if let ConnectionState::Client(ClientState::Handshake2) = conn_info.state {
        conn_info.state = ConnectionState::Client(ClientState::Ready);
        conn_info.last_hb_sent_time = 0;
        conn_info.last_hb_recv_time = now;
        conn_info.last_opposite_roller_time = now;
        log::info!("state -> Ready");
    }

    if pkt.pkt_type == b'h' {
        conn_info.last_hb_recv_time = now;
        log::debug!("heartbeat received");
        return;
    }

    if pkt.pkt_type == b'd' && pkt.data.len() >= 4 {
        if config.hb_mode == 0 {
            conn_info.last_hb_recv_time = now;
        }

        let conv_id = u32::from_be_bytes([pkt.data[0], pkt.data[1], pkt.data[2], pkt.data[3]]);
        let payload = &pkt.data[4..];

        let blob = match conn_info.blob.as_ref() {
            Some(b) => b,
            None => return,
        };
        if let ConvManagerVariant::Client(ref cm) = blob.conv_manager {
            let addr = match cm.find_data_by_conv(conv_id) {
                Some(a) => *a,
                None => {
                    log::info!("unknown conv {:x}, ignored", conv_id);
                    return;
                }
            };

            // Send payload back to the local UDP client
            match addr {
                SocketAddr::V4(ref a) => {
                    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                    sa.sin_family = libc::AF_INET as u16;
                    sa.sin_port = a.port().to_be();
                    sa.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                    unsafe {
                        libc::sendto(
                            udp_fd,
                            payload.as_ptr() as *const libc::c_void,
                            payload.len(),
                            0,
                            &sa as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<libc::sockaddr_in>() as u32,
                        );
                    }
                }
                SocketAddr::V6(ref a) => {
                    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                    sa.sin6_family = libc::AF_INET6 as u16;
                    sa.sin6_port = a.port().to_be();
                    sa.sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
                    unsafe {
                        libc::sendto(
                            udp_fd,
                            payload.as_ptr() as *const libc::c_void,
                            payload.len(),
                            0,
                            &sa as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<libc::sockaddr_in6>() as u32,
                        );
                    }
                }
            }
        }

        // Update conv activity
        if let Some(ref mut blob) = conn_info.blob {
            if let ConvManagerVariant::Client(ref mut cm) = blob.conv_manager {
                cm.update_active_time(conv_id);
            }
        }
    }
}

fn client_on_udp_recv(
    conn_info: &mut ConnInfo,
    raw_state: &mut RawTransport,
    encryptor: &Encryptor,
    config: &Config,
    udp_fd: RawFd,
) {
    let mut buf = [0u8; MAX_DATA_LEN + 1];
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let recv_len = unsafe {
        libc::recvfrom(
            udp_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut addr_len,
        )
    };

    if recv_len <= 0 {
        return;
    }
    let recv_len = recv_len as usize;

    if recv_len > MAX_DATA_LEN {
        log::warn!("huge UDP packet ({}), dropped", recv_len);
        return;
    }

    // Convert sockaddr to SocketAddr
    let src_addr = sockaddr_to_socketaddr(&addr, addr_len);
    let src_addr = match src_addr {
        Some(a) => a,
        None => return,
    };

    let blob = match conn_info.blob.as_mut() {
        Some(b) => b,
        None => return,
    };

    let conv = if let ConvManagerVariant::Client(ref mut cm) = blob.conv_manager {
        let conv = match cm.find_conv_by_data(&src_addr) {
            Some(c) => c,
            None => {
                if cm.get_size() >= MAX_CONV_NUM {
                    log::warn!("max conv num exceeded");
                    return;
                }
                let conv = cm.get_new_conv();
                cm.insert_conv(conv, src_addr);
                log::info!("new UDP session from {}, conv={:x}", src_addr, conv);
                conv
            }
        };
        cm.update_active_time(conv);
        cm.clear_inactive();
        conv
    } else {
        return;
    };

    if let ConnectionState::Client(ClientState::Ready) = conn_info.state {
        let _ = send_data_safer(raw_state, conn_info, &buf[..recv_len], conv, encryptor, config);
    }
}


fn create_fifo(path: &str) -> io::Result<RawFd> {
    use std::ffi::CString;
    let c_path = CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?;

    let ret = unsafe { libc::mkfifo(c_path.as_ptr(), 0o666) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

