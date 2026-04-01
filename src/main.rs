//! udp2raw-tunnel — UDP tunnel over encrypted raw sockets.
//!
//! Encapsulates UDP traffic into FakeTCP/UDP/ICMP packets using raw sockets.
//! Wire-compatible with the original C++ udp2raw implementation.


use udp2raw::common::*;
use udp2raw::encrypt::{EncryptionKeys, Encryptor};
use udp2raw::misc;
use udp2raw::network::RawSocketState;
use udp2raw::transport::RawTransport;
use udp2raw::{client, logging, server};

fn main() {
    // Parse CLI arguments and config
    let config = misc::parse_args();

    // Initialize logger
    logging::init_logger(config.log_level, config.log_color, config.log_position);

    log::info!("udp2raw Rust version starting");
    log::info!(
        "mode={:?} raw_mode={} cipher={} auth={} local={} remote={}",
        config.program_mode,
        config.raw_mode,
        config.cipher_mode,
        config.auth_mode,
        config.local_addr,
        config.remote_addr
    );

    // Root check
    if unsafe { libc::geteuid() } != 0 {
        log::warn!("running as non-root, raw sockets may fail");
    }

    // Generate const_id (random, persistent within session for connection recovery)
    let const_id = get_true_random_number_nz();
    log::info!("const_id = {:x}", const_id);

    // Derive encryption keys
    let is_client = config.program_mode == ProgramMode::Client;
    let keys = EncryptionKeys::derive(&config.key_string, is_client);
    let encryptor = Encryptor::new(keys, config.auth_mode, config.cipher_mode);

    // Handle --gen-rule
    if config.generate_iptables_rule {
        let ipt = misc::IptablesManager::new(&config, const_id);
        ipt.print_rule();
        std::process::exit(0);
    }

    // Handle --clear
    if config.clear_iptables {
        let mut ipt = misc::IptablesManager::new(&config, const_id);
        ipt.added = true; // pretend we added so clear works
        let _ = ipt.clear_rules();
        std::process::exit(0);
    }

    // Initialize transport (raw sockets or AF_XDP)
    let mut transport = init_transport(&config);

    // Setup iptables rules (auto-add)
    let mut _iptables: Option<misc::IptablesManager> = None;
    if config.auto_add_iptables_rule {
        let mut ipt = misc::IptablesManager::new(&config, const_id);
        if let Err(e) = ipt.add_rules() {
            log::error!("failed to add iptables rules: {}", e);
            std::process::exit(-1);
        }
        _iptables = Some(ipt);
    } else if config.raw_mode == RawMode::FakeTcp && !config.use_tcp_dummy_socket {
        log::warn!("-a has not been set, make sure you have added the needed iptables rules manually");
    }

    // Install signal handlers
    install_signal_handlers();

    // Run event loop
    let result = match config.program_mode {
        ProgramMode::Client => {
            client::client_event_loop(&config, &encryptor, &mut transport, const_id)
        }
        ProgramMode::Server => {
            server::server_event_loop(&config, &encryptor, &mut transport, const_id)
        }
        ProgramMode::Unset => {
            log::error!("program mode not set");
            std::process::exit(-1);
        }
    };

    if let Err(e) = result {
        log::error!("event loop error: {}", e);
        std::process::exit(-1);
    }
}

fn install_signal_handlers() {
    // Handle SIGINT/SIGTERM for graceful shutdown
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as usize);
        libc::signal(libc::SIGTERM, signal_handler as usize);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    // Graceful exit — iptables cleanup happens via Drop
    std::process::exit(0);
}

fn init_transport(config: &misc::Config) -> RawTransport {
    #[cfg(feature = "xdp")]
    if config.xdp_enabled {
        log::info!("using AF_XDP transport");
        let xdp_state = udp2raw::xdp::XdpSocketState::init(config).unwrap_or_else(|e| {
            log::error!("AF_XDP init failed: {}", e);
            log::error!("hint: requires Linux >= 5.7, CAP_NET_ADMIN + CAP_NET_RAW, and --dev <interface>");
            std::process::exit(-1);
        });
        return RawTransport::Xdp(xdp_state);
    }

    #[cfg(not(feature = "xdp"))]
    if config.xdp_enabled {
        log::error!("AF_XDP not available: recompile with --features xdp");
        std::process::exit(-1);
    }

    log::info!("using raw socket transport");
    let raw_state = RawSocketState::init(config).unwrap_or_else(|e| {
        log::error!("raw socket init failed: {}", e);
        log::error!("hint: run as root or with CAP_NET_RAW capability");
        std::process::exit(-1);
    });
    RawTransport::Socket(raw_state)
}

