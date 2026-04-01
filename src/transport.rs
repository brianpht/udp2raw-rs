//! Transport abstraction: dispatches to RawSocketState or XdpSocketState.
//!
//! The `RawTransport` enum provides a unified interface so client.rs, server.rs,
//! and connection.rs don't need to know which backend is in use.
//! This does NOT change any wire-format behavior.

use crate::common::*;
use crate::misc::Config;
use crate::network::{RawInfo, RawSocketState};
#[cfg(feature = "xdp")]
use crate::xdp::XdpSocketState;
use std::io;
use std::os::unix::io::RawFd;

/// Unified transport for raw packet I/O.
/// Dispatches to either the traditional raw socket path or AF_XDP.
pub enum RawTransport {
    Socket(RawSocketState),
    #[cfg(feature = "xdp")]
    Xdp(XdpSocketState),
}

impl RawTransport {
    /// Get the fd to register with mio for READABLE events.
    pub fn recv_fd(&self) -> RawFd {
        match self {
            RawTransport::Socket(s) => s.raw_recv_fd,
            #[cfg(feature = "xdp")]
            RawTransport::Xdp(x) => x.recv_fd(),
        }
    }

    pub fn init_filter(&mut self, port: u16, config: &Config) {
        match self {
            RawTransport::Socket(s) => s.init_filter(port, config),
            #[cfg(feature = "xdp")]
            RawTransport::Xdp(x) => x.init_filter(port, config),
        }
    }

    pub fn send_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
        raw_mode: RawMode,
    ) -> io::Result<usize> {
        match self {
            RawTransport::Socket(s) => s.send_raw0(raw_info, payload, raw_mode),
            #[cfg(feature = "xdp")]
            RawTransport::Xdp(x) => x.send_raw0(raw_info, payload, raw_mode),
        }
    }

    pub fn recv_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        raw_mode: RawMode,
        output: &mut [u8],
    ) -> io::Result<usize> {
        match self {
            RawTransport::Socket(s) => s.recv_raw0(raw_info, raw_mode, output),
            #[cfg(feature = "xdp")]
            RawTransport::Xdp(x) => x.recv_raw0(raw_info, raw_mode, output),
        }
    }

    pub fn discard_raw_packet(&mut self) {
        match self {
            RawTransport::Socket(s) => s.discard_raw_packet(),
            #[cfg(feature = "xdp")]
            RawTransport::Xdp(x) => x.discard_raw_packet(),
        }
    }
}

