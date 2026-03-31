//! CLI argument parsing, configuration, iptables rule management.
//! Corresponds to misc.{h,cpp} in the C++ version.

use crate::common::*;
use clap::Parser;
use std::fs;
use std::net::SocketAddr;

// ─── Timing constants (matching C++ misc.h) ─────────────────────────────────

pub const HEARTBEAT_INTERVAL: u64 = 600;
pub const TIMER_INTERVAL: u64 = 400;
pub const CLIENT_CONN_TIMEOUT: u64 = 10_000;
pub const CLIENT_CONN_UPLINK_TIMEOUT: u64 = 5_000;
pub const CLIENT_HANDSHAKE_TIMEOUT: u64 = 5_000;
pub const CLIENT_RETRY_INTERVAL: u64 = 1_000;
pub const SERVER_CONN_TIMEOUT: u64 = 240_000;
pub const SERVER_HANDSHAKE_TIMEOUT: u64 = 10_000;
pub const MAX_FAIL_TIME: i32 = 3;
pub const MAX_READY_CONN_NUM: u32 = 1000;
pub const MAX_HANDSHAKE_CONN_NUM: usize = 10_000;
pub const IPTABLES_RULE_KEEP_INTERVAL: u64 = 20;
pub const RETRY_ON_ERROR_INTERVAL: u64 = 3;

// ─── CLI definition ─────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "udp2raw", about = "UDP tunnel over encrypted raw sockets (FakeTCP/UDP/ICMP)")]
pub struct Cli {
    /// Run as client
    #[arg(short = 'c', long = "client", group = "mode")]
    pub client: bool,

    /// Run as server
    #[arg(short = 's', long = "server", group = "mode")]
    pub server: bool,

    /// Local listen address (ip:port)
    #[arg(short = 'l')]
    pub local: String,

    /// Remote address (ip:port)
    #[arg(short = 'r')]
    pub remote: String,

    /// Password for symmetric key
    #[arg(short = 'k', long = "key", default_value = "secret key")]
    pub key: String,

    /// Raw mode: faketcp, udp, icmp
    #[arg(long = "raw-mode", default_value = "faketcp")]
    pub raw_mode: String,

    /// Cipher mode: aes128cbc, aes128cfb, xor, none
    #[arg(long = "cipher-mode", default_value = "aes128cbc")]
    pub cipher_mode: String,

    /// Auth mode: hmac_sha1, md5, crc32, simple, none
    #[arg(long = "auth-mode", default_value = "md5")]
    pub auth_mode: String,

    /// Auto add/delete iptables rule
    #[arg(short = 'a', long = "auto-rule")]
    pub auto_rule: bool,

    /// Generate iptables rule then exit
    #[arg(short = 'g', long = "gen-rule")]
    pub gen_rule: bool,

    /// Disable anti-replay
    #[arg(long = "disable-anti-replay")]
    pub disable_anti_replay: bool,

    /// Fix GRO huge packets
    #[arg(long = "fix-gro")]
    pub fix_gro: bool,

    /// Force source IP
    #[arg(long = "source-ip")]
    pub source_ip: Option<String>,

    /// Force source port
    #[arg(long = "source-port")]
    pub source_port: Option<u16>,

    /// Log level (0=never, 1=fatal, 2=error, 3=warn, 4=info, 5=debug, 6=trace)
    #[arg(long = "log-level", default_value = "4")]
    pub log_level: u8,

    /// Enable log position info
    #[arg(long = "log-position")]
    pub log_position: bool,

    /// Disable log color
    #[arg(long = "disable-color")]
    pub disable_color: bool,

    /// Disable BPF filter
    #[arg(long = "disable-bpf")]
    pub disable_bpf: bool,

    /// Socket buffer size in kbytes
    #[arg(long = "sock-buf", default_value = "1024")]
    pub sock_buf: usize,

    /// Force socket buffer size
    #[arg(long = "force-sock-buf")]
    pub force_sock_buf: bool,

    /// Seq increase mode for faketcp (0-4)
    #[arg(long = "seq-mode", default_value = "3")]
    pub seq_mode: u32,

    /// Send at OSI level 2 (format: if_name#dest_mac)
    #[arg(long = "lower-level")]
    pub lower_level: Option<String>,

    /// FIFO file for runtime commands
    #[arg(long = "fifo")]
    pub fifo: Option<String>,

    /// Config file
    #[arg(long = "conf-file")]
    pub conf_file: Option<String>,

    /// Heartbeat mode (0 or 1)
    #[arg(long = "hb-mode", default_value = "1")]
    pub hb_mode: u32,

    /// Heartbeat packet length
    #[arg(long = "hb-len", default_value = "1200")]
    pub hb_len: usize,

    /// MTU warning threshold
    #[arg(long = "mtu-warn", default_value = "1375")]
    pub mtu_warn: usize,

    /// TTL value
    #[arg(long = "set-ttl", default_value = "64")]
    pub ttl: u8,

    /// Use easy-faketcp mode (dummy TCP socket for handshake)
    #[arg(long = "easy-tcp")]
    pub easy_tcp: bool,

    /// Clear iptables rules added by this program
    #[arg(long = "clear")]
    pub clear: bool,

    /// Monitor and re-add iptables rules
    #[arg(long = "keep-rule")]
    pub keep_rule: bool,

    /// Generate iptables rule and add permanently
    #[arg(long = "gen-add")]
    pub gen_add: bool,

    /// Wait for xtables lock
    #[arg(long = "wait-lock")]
    pub wait_lock: bool,

    /// Retry on error
    #[arg(long = "retry-on-error")]
    pub retry_on_error: bool,

    /// Bind raw socket to device
    #[arg(long = "dev")]
    pub dev: Option<String>,

    /// AF_XDP mode: "if_name#dest_mac" (e.g. "eth0#aa:bb:cc:dd:ee:ff")
    #[cfg(feature = "xdp")]
    #[arg(long = "xdp")]
    pub xdp: Option<String>,

    /// AF_XDP RX queue ID (default 0)
    #[cfg(feature = "xdp")]
    #[arg(long = "xdp-queue", default_value = "0")]
    pub xdp_queue: u32,

    /// AF_XDP zero-copy mode (requires driver support)
    #[cfg(feature = "xdp")]
    #[arg(long = "xdp-zerocopy")]
    pub xdp_zerocopy: bool,
}

// ─── Config struct ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub program_mode: ProgramMode,
    pub raw_mode: RawMode,
    pub cipher_mode: CipherMode,
    pub auth_mode: AuthMode,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub source_ip: Option<std::net::IpAddr>,
    pub source_port: Option<u16>,
    pub key_string: String,
    pub socket_buf_size: usize,
    pub force_socket_buf: bool,
    pub seq_mode: u32,
    pub hb_mode: u32,
    pub hb_len: usize,
    pub mtu_warn: usize,
    pub ttl_value: u8,
    pub lower_level_enabled: bool,
    pub lower_level_manual: bool,
    pub lower_level_if_name: String,
    pub lower_level_dest_mac: [u8; 6],
    pub auto_add_iptables_rule: bool,
    pub generate_iptables_rule: bool,
    pub generate_iptables_rule_add: bool,
    pub keep_rule: bool,
    pub disable_anti_replay: bool,
    pub disable_bpf_filter: bool,
    pub fix_gro: bool,
    pub use_tcp_dummy_socket: bool,
    pub fifo_file: Option<String>,
    pub log_level: u8,
    pub log_color: bool,
    pub log_position: bool,
    pub retry_on_error: bool,
    pub clear_iptables: bool,
    pub wait_xtables_lock: bool,
    pub dev: String,
    #[cfg(feature = "xdp")]
    pub xdp_enabled: bool,
    #[cfg(feature = "xdp")]
    pub xdp_ifname: String,
    #[cfg(feature = "xdp")]
    pub xdp_dst_mac: [u8; 6],
    #[cfg(feature = "xdp")]
    pub xdp_queue_id: u32,
    #[cfg(feature = "xdp")]
    pub xdp_zerocopy: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let program_mode = if cli.client {
            ProgramMode::Client
        } else if cli.server {
            ProgramMode::Server
        } else {
            log::error!("-c or -s must be specified");
            myexit(-1);
        };

        let raw_mode = match cli.raw_mode.as_str() {
            "faketcp" => RawMode::FakeTcp,
            "udp" => RawMode::Udp,
            "icmp" => RawMode::Icmp,
            "easyfaketcp" | "easy-faketcp" | "easy_faketcp" => RawMode::FakeTcp,
            other => {
                log::error!("unknown raw-mode: {}", other);
                myexit(-1);
            }
        };

        let use_tcp_dummy = cli.easy_tcp
            || matches!(cli.raw_mode.as_str(), "easyfaketcp" | "easy-faketcp" | "easy_faketcp");

        let cipher_mode = match cli.cipher_mode.as_str() {
            "aes128cbc" => CipherMode::Aes128Cbc,
            "aes128cfb" => CipherMode::Aes128Cfb,
            "xor" => CipherMode::Xor,
            "none" => CipherMode::None,
            other => {
                log::error!("unknown cipher-mode: {}", other);
                myexit(-1);
            }
        };

        let auth_mode = match cli.auth_mode.as_str() {
            "hmac_sha1" => AuthMode::HmacSha1,
            "md5" => AuthMode::Md5,
            "crc32" => AuthMode::Crc32,
            "simple" => AuthMode::Simple,
            "none" => AuthMode::None,
            other => {
                log::error!("unknown auth-mode: {}", other);
                myexit(-1);
            }
        };

        let local_addr: SocketAddr = cli.local.parse().unwrap_or_else(|e| {
            log::error!("invalid local address '{}': {}", cli.local, e);
            myexit(-1);
        });

        let remote_addr: SocketAddr = cli.remote.parse().unwrap_or_else(|e| {
            log::error!("invalid remote address '{}': {}", cli.remote, e);
            myexit(-1);
        });

        let source_ip = cli.source_ip.as_ref().map(|s| {
            s.parse().unwrap_or_else(|e| {
                log::error!("invalid source-ip '{}': {}", s, e);
                myexit(-1);
            })
        });

        let (lower_level_enabled, lower_level_manual, lower_level_if_name, lower_level_dest_mac) =
            parse_lower_level(&cli.lower_level);

        let disable_anti_replay = cli.disable_anti_replay || auth_mode == AuthMode::None;

        #[cfg(feature = "xdp")]
        let (xdp_enabled, xdp_ifname, xdp_dst_mac) = parse_xdp_opt(&cli.xdp);

        Config {
            program_mode,
            raw_mode,
            cipher_mode,
            auth_mode,
            local_addr,
            remote_addr,
            source_ip,
            source_port: cli.source_port,
            key_string: cli.key.clone(),
            socket_buf_size: cli.sock_buf * 1024,
            force_socket_buf: cli.force_sock_buf,
            seq_mode: cli.seq_mode,
            hb_mode: cli.hb_mode,
            hb_len: cli.hb_len.min(1500),
            mtu_warn: cli.mtu_warn,
            ttl_value: cli.ttl,
            lower_level_enabled,
            lower_level_manual,
            lower_level_if_name,
            lower_level_dest_mac,
            auto_add_iptables_rule: cli.auto_rule,
            generate_iptables_rule: cli.gen_rule,
            generate_iptables_rule_add: cli.gen_add,
            keep_rule: cli.keep_rule,
            disable_anti_replay,
            disable_bpf_filter: cli.disable_bpf,
            fix_gro: cli.fix_gro,
            use_tcp_dummy_socket: use_tcp_dummy,
            fifo_file: cli.fifo.clone(),
            log_level: cli.log_level,
            log_color: !cli.disable_color,
            log_position: cli.log_position,
            retry_on_error: cli.retry_on_error,
            clear_iptables: cli.clear,
            wait_xtables_lock: cli.wait_lock,
            dev: cli.dev.clone().unwrap_or_default(),
            #[cfg(feature = "xdp")]
            xdp_enabled,
            #[cfg(feature = "xdp")]
            xdp_ifname,
            #[cfg(feature = "xdp")]
            xdp_dst_mac,
            #[cfg(feature = "xdp")]
            xdp_queue_id: cli.xdp_queue,
            #[cfg(feature = "xdp")]
            xdp_zerocopy: cli.xdp_zerocopy,
        }
    }
}

fn parse_lower_level(opt: &Option<String>) -> (bool, bool, String, [u8; 6]) {
    match opt {
        None => (false, false, String::new(), [0; 6]),
        Some(s) if s == "auto" => (true, false, String::new(), [0xff; 6]),
        Some(s) => {
            // Format: if_name#aa:bb:cc:dd:ee:ff
            if let Some(idx) = s.find('#') {
                let if_name = s[..idx].to_string();
                let mac_str = &s[idx + 1..];
                let parts: Vec<u8> = mac_str
                    .split(':')
                    .filter_map(|p| u8::from_str_radix(p, 16).ok())
                    .collect();
                let mut mac = [0u8; 6];
                for (i, &b) in parts.iter().enumerate().take(6) {
                    mac[i] = b;
                }
                (true, true, if_name, mac)
            } else {
                log::error!("--lower-level format: if_name#dest_mac");
                myexit(-1);
            }
        }
    }
}

/// Parse `--xdp` option: `"if_name#dest_mac"` (same format as `--lower-level`).
/// Returns `(enabled, ifname, dst_mac)`.
#[cfg(feature = "xdp")]
fn parse_xdp_opt(opt: &Option<String>) -> (bool, String, [u8; 6]) {
    match opt {
        None => (false, String::new(), [0; 6]),
        Some(s) => {
            // Format: if_name#aa:bb:cc:dd:ee:ff
            if let Some(idx) = s.find('#') {
                let if_name = s[..idx].to_string();
                let mac_str = &s[idx + 1..];
                let parts: Vec<u8> = mac_str
                    .split(':')
                    .filter_map(|p| u8::from_str_radix(p, 16).ok())
                    .collect();
                if parts.len() != 6 {
                    log::error!("--xdp: invalid MAC address '{}', expected 6 hex octets", mac_str);
                    myexit(-1);
                }
                let mut mac = [0u8; 6];
                for (i, &b) in parts.iter().enumerate().take(6) {
                    mac[i] = b;
                }
                (true, if_name, mac)
            } else {
                log::error!("--xdp format: if_name#dest_mac (e.g. eth0#aa:bb:cc:dd:ee:ff)");
                myexit(-1);
            }
        }
    }
}

/// Parse arguments, handling --conf-file.
pub fn parse_args() -> Config {
    // First pass: check for --conf-file and merge
    let args: Vec<String> = std::env::args().collect();

    let mut final_args = Vec::new();
    let mut conf_file = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--conf-file" {
            if i + 1 < args.len() {
                conf_file = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
        }
        final_args.push(args[i].clone());
        i += 1;
    }

    // Load config file if specified
    if let Some(path) = conf_file {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("Failed to read config file '{}': {}", path, e);
            std::process::exit(-1);
        });
        for line in content.lines() {
            let tokens = parse_conf_line(line);
            for tok in tokens {
                final_args.push(tok);
            }
        }
    }

    let cli = Cli::parse_from(&final_args);
    Config::from_cli(&cli)
}

// ─── iptables management ────────────────────────────────────────────────────

pub struct IptablesManager {
    command: String,
    pattern: String,
    chains: [String; 2],
    pub added: bool,
    pub keeped: bool,
}

impl IptablesManager {
    pub fn new(config: &Config, const_id: u32) -> Self {
        let is_ipv6 = config.remote_addr.is_ipv6();
        let base_cmd = if is_ipv6 { "ip6tables" } else { "iptables" };
        let command = if config.wait_xtables_lock {
            format!("{} -w", base_cmd)
        } else {
            base_cmd.to_string()
        };

        let pattern = build_iptables_pattern(config);

        let chains = [
            format!("udp2rawDwrW_{:x}_C0", const_id),
            format!("udp2rawDwrW_{:x}_C1", const_id),
        ];

        Self {
            command,
            pattern,
            chains,
            added: false,
            keeped: config.keep_rule,
        }
    }

    pub fn add_rules(&mut self) -> std::io::Result<()> {
        let limit = if self.keeped { 2 } else { 1 };
        for i in 0..limit {
            let _ = run_command(&format!("{} -N {}", self.command, self.chains[i]));
            let _ = run_command(&format!("{} -F {}", self.command, self.chains[i]));
            let _ = run_command(&format!("{} -I {} -j DROP", self.command, self.chains[i]));

            let rule_add = format!("{} -I INPUT {} -j {}", self.command, self.pattern, self.chains[i]);
            let (code, _) = run_command(&rule_add)?;
            if code != 0 {
                log::error!("failed to add iptables rule: {}", rule_add);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "iptables failed"));
            }
        }
        self.added = true;
        log::warn!("auto added iptables rules");
        Ok(())
    }

    pub fn clear_rules(&mut self) -> std::io::Result<()> {
        if !self.added {
            return Ok(());
        }
        let limit = if self.keeped { 2 } else { 1 };
        for i in 0..limit {
            let _ = run_command(&format!(
                "{} -D INPUT {} -j {}",
                self.command, self.pattern, self.chains[i]
            ));
            let _ = run_command(&format!("{} -F {}", self.command, self.chains[i]));
            let _ = run_command(&format!("{} -X {}", self.command, self.chains[i]));
        }
        Ok(())
    }

    pub fn keep_rules(&mut self) -> std::io::Result<()> {
        // Simplified keep logic: just re-add the rules
        if !self.keeped {
            return Ok(());
        }
        for i in 0..2 {
            let _ = run_command(&format!("{} -N {}", self.command, self.chains[i]));
            let _ = run_command(&format!("{} -F {}", self.command, self.chains[i]));
            let _ = run_command(&format!("{} -I {} -j DROP", self.command, self.chains[i]));
            let rule_del = format!("{} -D INPUT {} -j {}", self.command, self.pattern, self.chains[i]);
            let _ = run_command(&rule_del);
            let rule_add = format!("{} -I INPUT {} -j {}", self.command, self.pattern, self.chains[i]);
            let _ = run_command(&rule_add);
        }
        Ok(())
    }

    pub fn print_rule(&self) {
        println!(
            "{} -I INPUT {} -j DROP",
            self.command, self.pattern
        );
    }
}

impl Drop for IptablesManager {
    fn drop(&mut self) {
        let _ = self.clear_rules();
    }
}

fn build_iptables_pattern(config: &Config) -> String {
    match config.program_mode {
        ProgramMode::Client => {
            let ip = config.remote_addr.ip();
            let port = config.remote_addr.port();
            match config.raw_mode {
                RawMode::FakeTcp => format!("-s {} -p tcp -m tcp --sport {}", ip, port),
                RawMode::Udp => format!("-s {} -p udp -m udp --sport {}", ip, port),
                RawMode::Icmp => {
                    if config.remote_addr.is_ipv4() {
                        format!("-s {} -p icmp --icmp-type 0", ip)
                    } else {
                        format!("-s {} -p icmpv6 --icmpv6-type 129", ip)
                    }
                }
            }
        }
        ProgramMode::Server => {
            let port = config.local_addr.port();
            let mut pattern = String::new();
            let ip = config.local_addr.ip();
            if !ip.is_unspecified() {
                pattern.push_str(&format!("-d {} ", ip));
            }
            match config.raw_mode {
                RawMode::FakeTcp => pattern.push_str(&format!("-p tcp -m tcp --dport {}", port)),
                RawMode::Udp => pattern.push_str(&format!("-p udp -m udp --dport {}", port)),
                RawMode::Icmp => {
                    if config.local_addr.is_ipv4() {
                        pattern.push_str("-p icmp --icmp-type 8");
                    } else {
                        pattern.push_str("-p icmpv6 --icmpv6-type 128");
                    }
                }
            }
            pattern
        }
        _ => String::new(),
    }
}

