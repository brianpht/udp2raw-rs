//! XDP eBPF program for udp2raw AF_XDP backend.
//!
//! Minimal XDP program: look up the RX queue in XSKMAP and redirect.
//! Packets on queues without an XSK entry pass through normally (XDP_PASS).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};

/// XSKMAP shared with userspace — indexed by RX queue ID.
/// Max 64 queues should cover any NIC.
#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(64, 0);

/// XDP entry point: redirect all packets on bound queues to AF_XDP sockets.
/// Unbound queues fall through to XDP_PASS (normal kernel stack).
#[xdp]
pub fn udp2raw_xdp(ctx: XdpContext) -> u32 {
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    match XSKS_MAP.redirect(queue_id, 0) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

