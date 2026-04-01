//! udp2raw-tunnel library — UDP tunnel over encrypted raw sockets.
//!
//! Re-exports all modules for use by integration tests and examples.
//! The binary entry point is in `main.rs`.

#[cfg(not(target_os = "linux"))]
compile_error!("udp2raw only supports Linux (requires raw sockets, timerfd, iptables)");

pub mod client;
pub mod common;
pub mod connection;
pub mod encrypt;
pub mod fd_manager;
pub mod logging;
pub mod mio_fd;
pub mod misc;
pub mod network;
pub mod server;
pub mod transport;
#[cfg(feature = "xdp")]
#[allow(dead_code)]
pub mod xdp;

