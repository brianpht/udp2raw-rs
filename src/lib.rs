//! udp2raw-tunnel library — UDP tunnel over encrypted raw sockets.
//!
//! Re-exports all modules for use by integration tests and examples.
//! The binary entry point is in `main.rs`.

#![allow(dead_code)]
#![allow(unused_imports)]

pub mod client;
pub mod common;
pub mod connection;
pub mod encrypt;
pub mod fd_manager;
pub mod logging;
pub mod misc;
pub mod network;
pub mod server;

#[cfg(feature = "xdp")]
pub mod xdp;

