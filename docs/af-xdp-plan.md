# Plan: AF_XDP Socket Backend

> Replace the `AF_INET/SOCK_RAW` and `AF_PACKET` transport in `RawSocketState`
> with an optional AF_XDP (XSK) backend for zero-copy, kernel-bypass packet I/O.
>
> **Wire-format bytes are untouched** — only the syscall path for
> sending/receiving frames changes.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Architecture Overview](#2-architecture-overview)
3. [Prerequisites](#3-prerequisites)
4. [New Files](#4-new-files)
5. [Modified Files](#5-modified-files)
6. [Step-by-step Implementation](#6-step-by-step-implementation)
7. [CLI Interface](#7-cli-interface)
8. [Build System](#8-build-system)
9. [Data Flow](#9-data-flow)
10. [Testing Strategy](#10-testing-strategy)
11. [Open Questions](#11-open-questions)

---

## 1. Motivation

| Path | Mechanism | Copies | Context switches |
|---|---|---|---|
| `AF_INET/SOCK_RAW` | kernel IP stack | 2+ per pkt | 1 per syscall |
| `AF_PACKET` (lower-level) | bypass IP stack, still kernel copy | 1 per pkt | 1 per syscall |
| **AF_XDP** | shared UMEM ring buffers | **0 (zero-copy)** or 1 (copy mode) | **0 (busy-poll)** or 1 |

AF_XDP gives the highest throughput for raw packet I/O on Linux (kernel ≥ 4.18)
while still being pollable with `mio` (the XSK fd supports `epoll`).

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      User Space                         │
│                                                         │
│  ┌──────────┐    ┌──────────────────────────────────┐   │
│  │ mio::Poll│───▶│ XSK fd (READABLE/WRITABLE)       │   │
│  └──────────┘    └──────┬──────────────────┬────────┘   │
│                         │                  │            │
│              ┌──────────▼──────┐  ┌────────▼─────────┐  │
│              │   RX Ring       │  │   TX Ring        │  │
│              │ (kernel→user)   │  │ (user→kernel)    │  │
│              └──────────┬──────┘  └────────┬─────────┘  │
│                         │                  │            │
│              ┌──────────▼──────────────────▼─────────┐  │
│              │         UMEM  (shared memory)         │  │
│              │    N frames × 4096 bytes each         │  │
│              └──────────┬──────────────────┬─────────┘  │
│                         │                  │            │
│              ┌──────────▼──────┐  ┌────────▼─────────┐  │
│              │  Fill Ring      │  │ Completion Ring  │  │
│              │ (user→kernel)   │  │ (kernel→user)    │  │
│              └─────────────────┘  └──────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │  bind(ifindex, queue_id)
┌──────────────────────────▼──────────────────────────────┐
│                     Kernel / NIC                        │
│                                                         │
│  ┌────────────────────────────────────────────────────┐ │
│  │  XDP eBPF program (aya-ebpf)                       │ │
│  │  ┌─────────────┐     ┌──────────┐                  │ │
│  │  │ pkt arrives │────▶│ XSKMAP   │──▶ redirect      │ │
│  │  │ on NIC queue│     │ lookup   │   to XSK socket  │ │
│  │  └─────────────┘     └──────────┘                  │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Crate | Role |
|---|---|---|
| XDP eBPF program | `aya-ebpf` | Runs on NIC; redirects packets to XSK via XSKMAP |
| eBPF loader | `aya` | Loads program, creates XSKMAP, attaches to NIC |
| XSK socket mgmt | `libc` (raw) | UMEM alloc, ring mmap, send/recv via ring buffers |
| Build glue | `aya-build` | Compiles eBPF crate at build time (bpfel target) |

---

## 3. Prerequisites

- Linux kernel ≥ 4.18 (AF_XDP support)
- `CAP_NET_ADMIN` + `CAP_BPF` (or root)
- NIC driver with XDP support (copy-mode works on all drivers; zero-copy requires driver support)
- `bpf-linker` installed: `cargo install bpf-linker`
- Nightly Rust toolchain (for eBPF target compilation only)

---

## 4. New Files

### 4.1 `udp2raw-ebpf/Cargo.toml` — eBPF crate manifest

```toml
[package]
name = "udp2raw-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1"

[[bin]]
name = "udp2raw-ebpf"
path = "src/main.rs"

[profile.dev]
opt-level = 2
panic = "abort"
debug = false
overflow-checks = false

[profile.release]
panic = "abort"
lto = true
```

### 4.2 `udp2raw-ebpf/src/main.rs` — XDP redirect program

Minimal XDP program: look up the RX queue in XSKMAP and redirect.
Packets on queues without an XSK entry pass through normally.

```rust
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
        Ok(()) => xdp_action::XDP_REDIRECT,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

### 4.3 `build.rs` — conditional eBPF compilation

```rust
fn main() {
    #[cfg(feature = "xdp")]
    {
        println!("cargo::rerun-if-changed=udp2raw-ebpf/src");
        println!("cargo::rerun-if-changed=udp2raw-ebpf/Cargo.toml");
        aya_build::build_ebpf(["udp2raw-ebpf"])
            .expect("eBPF build failed — install bpf-linker: cargo install bpf-linker");
    }
}
```

### 4.4 `src/xdp.rs` — AF_XDP socket management + aya loader

This is the bulk of new code (~500 lines). Broken into sections:

#### 4.4.1 AF_XDP kernel constants (`linux/if_xdp.h`)

```rust
pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;

// setsockopt options
pub const XDP_MMAP_OFFSETS: i32 = 1;
pub const XDP_RX_RING: i32 = 2;
pub const XDP_TX_RING: i32 = 3;
pub const XDP_UMEM_REG: i32 = 4;
pub const XDP_UMEM_FILL_RING: i32 = 5;
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;

// bind() flags
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// mmap page offsets
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x80000000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

// ring flags
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

// defaults
pub const DEFAULT_FRAME_SIZE: u32 = 4096;
pub const DEFAULT_NUM_FRAMES: u32 = 4096;
pub const DEFAULT_RING_SIZE: u32 = 2048;  // must be power-of-2
```

#### 4.4.2 Kernel structs (`#[repr(C)]`)

```rust
#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

#[repr(C)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,  // fill
    pub cr: XdpRingOffset,  // completion
}

#[repr(C, packed)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}
```

> **Note**: These are NOT wire-format structs — they are kernel ABI structs
> for AF_XDP socket setup. They do not affect packet bytes on the wire.

#### 4.4.3 `FrameAllocator` — free-list of UMEM frame addresses

```rust
struct FrameAllocator {
    free_list: Vec<u64>,  // stack of free frame addrs (LIFO for cache locality)
}

impl FrameAllocator {
    fn new(num_frames: u32, frame_size: u32) -> Self;
    fn alloc(&mut self) -> Option<u64>;
    fn free(&mut self, addr: u64);
}
```

#### 4.4.4 `Ring` — mmap'd producer/consumer ring buffer

Each ring is a shared-memory region with:
- `producer: *mut AtomicU32` (writer increments after filling entries)
- `consumer: *mut AtomicU32` (reader increments after draining entries)
- `ring: *mut u8` (descriptor array — `u64` for fill/comp, `XdpDesc` for rx/tx)
- `mask: u32` (ring_size − 1, for index wrapping)

```rust
struct Ring {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    flags:    *const AtomicU32,
    ring:     *mut u8,
    mask:     u32,
    size:     u32,
    map_addr: *mut u8,
    map_len:  usize,
    // Cached indices to reduce atomic reads
    cached_prod: u32,
    cached_cons: u32,
}
```

**Ring operations** (all single-threaded, matching mio event-loop pattern):

| Method | Role | Ordering |
|---|---|---|
| `prod_reserve(n)` → `Option<u32>` | Reserve n slots for writing | Acquire on consumer |
| `prod_submit(n)` | Publish n written slots | Release on producer |
| `cons_peek(n)` → `Option<u32>` | Check n readable slots | Acquire on producer |
| `cons_release(n)` | Release n consumed slots | Release on consumer |
| `needs_wakeup()` → `bool` | Check `XDP_RING_NEED_WAKEUP` flag | Relaxed |
| `addr_at(idx)` → `*mut u64` | Fill/completion ring descriptor | unsafe |
| `desc_at(idx)` → `*mut XdpDesc` | RX/TX ring descriptor | unsafe |

Cleanup via `Drop` → `munmap()`.

#### 4.4.5 `XskSocket` — AF_XDP socket with UMEM

```rust
pub struct XskSocket {
    fd:           RawFd,
    fill_ring:    Ring,
    comp_ring:    Ring,
    rx_ring:      Ring,
    tx_ring:      Ring,
    umem_buffer:  *mut u8,
    umem_size:    usize,
    frame_size:   u32,
    frame_alloc:  FrameAllocator,
    ifindex:      u32,
    queue_id:     u32,
    outstanding_tx: u32,
}
```

**Constructor `XskSocket::new(ifindex, queue_id, num_frames, frame_size, ring_size, zero_copy)`**:

1. `mmap(MAP_ANONYMOUS)` → allocate UMEM buffer
2. `socket(AF_XDP, SOCK_RAW, 0)` → create XSK fd
3. `setsockopt(SOL_XDP, XDP_UMEM_REG)` → register UMEM
4. `setsockopt(SOL_XDP, XDP_{FILL,COMP,RX,TX}_RING)` → set ring sizes
5. `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)` → get ring mmap offsets
6. `mmap(MAP_SHARED, fd, pgoff)` × 4 → map all rings
7. Populate fill ring with initial frames (half capacity)
8. `bind(fd, sockaddr_xdp{ifindex, queue_id, flags})` → bind to NIC queue
9. `setnonblocking(fd)` → for mio compatibility

**I/O methods**:

| Method | Description |
|---|---|
| `fd() → RawFd` | Return pollable fd for mio registration |
| `recv() → io::Result<Vec<u8>>` | Read one L2 frame from RX ring |
| `send(data: &[u8]) → io::Result<()>` | Write one L2 frame to TX ring |
| `kick_tx()` | `sendto(fd, NULL, 0, MSG_DONTWAIT)` to wake kernel TX |
| `reclaim_completion()` | Drain completion ring, free frames back to allocator |
| `recycle_frame(addr)` | Return consumed RX frame to fill ring |

**Frame lifecycle**:

```
           alloc
free_list ────────▶ TX ring ────▶ kernel sends ────▶ comp ring
    ▲                                                    │
    └────────────────────────────────────────────────────┘
                          free

           alloc
free_list ────────▶ fill ring ────▶ kernel fills ────▶ RX ring
    ▲                                                    │
    └────────────────────────────────────────────────────┘
                       recycle
```

Cleanup via `Drop` → `close(fd)` + `munmap(umem_buffer)` + ring drops.

#### 4.4.6 `XdpState` — top-level state (Aya + XSK + Ethernet)

```rust
pub struct XdpState {
    pub xsk:     XskSocket,
    _ebpf:       aya::Ebpf,       // kept alive to maintain XDP attachment
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}
```

**Constructor `XdpState::init(ebpf_bytes, ifname, queue_id, zero_copy, dst_mac)`**:

1. `if_nametoindex(ifname)` → resolve ifindex
2. `ioctl(SIOCGIFHWADDR)` → resolve source MAC
3. `XskSocket::new(...)` → create AF_XDP socket
4. `aya::Ebpf::load(ebpf_bytes)` → load eBPF object
5. Get `&mut Xdp` program → `load()` → `attach(ifname, XdpFlags::default())`
6. Get `XskMap` → `set(queue_id, xsk.fd(), 0)` → register socket in XSKMAP

**L3-level helpers** (called by `RawSocketState`):

```rust
/// Prepend 14-byte Ethernet header, write to TX ring.
pub fn send_ip_packet(&mut self, ip_packet: &[u8], ethertype: u16) -> io::Result<()>;

/// Strip 14-byte Ethernet header from RX frame.
pub fn recv_ip_packet(&mut self) -> io::Result<(u16, Vec<u8>)>;
```

#### 4.4.7 Helpers

```rust
fn ifname_to_index(name: &str) -> io::Result<u32>;        // libc::if_nametoindex
fn get_interface_mac(name: &str) -> io::Result<[u8; 6]>;  // ioctl(SIOCGIFHWADDR)
```

---

## 5. Modified Files

### 5.1 `Cargo.toml`

```diff
+[workspace]
+exclude = ["udp2raw-ebpf"]
+
 [package]
 name = "udp2raw"
 # ...existing...

+[features]
+default = []
+xdp = ["aya"]
+
 [dependencies]
 # ...existing...
+
+# AF_XDP (optional)
+aya = { version = "0.13", optional = true }
+
+[build-dependencies]
+aya-build = { version = "0.1", optional = true }
```

The `xdp` feature gates all AF_XDP code. Default builds are unaffected.

### 5.2 `src/lib.rs`

```diff
 pub mod server;
+
+#[cfg(feature = "xdp")]
+pub mod xdp;
```

### 5.3 `src/misc.rs` — CLI flags + Config fields

**Cli struct** — add (cfg-gated):

```rust
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
```

**Config struct** — add:

```rust
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
```

**Parsing**: reuse `parse_lower_level`-style `"if_name#mac"` parser for `--xdp` value.

### 5.4 `src/network.rs` — XDP transport integration

#### 5.4.a Add optional XDP field to `RawSocketState`

```rust
pub struct RawSocketState {
    pub raw_recv_fd: RawFd,
    pub raw_send_fd: RawFd,
    // ...existing fields...
    pub lower_level: bool,
    #[cfg(feature = "xdp")]
    pub xdp: Option<crate::xdp::XdpState>,
}
```

#### 5.4.b Add `init_xdp()` constructor

```rust
#[cfg(feature = "xdp")]
pub fn init_xdp(config: &Config, ebpf_bytes: &[u8]) -> io::Result<Self> {
    let xdp = crate::xdp::XdpState::init(
        ebpf_bytes,
        &config.xdp_ifname,
        config.xdp_queue_id,
        config.xdp_zerocopy,
        config.xdp_dst_mac,
    )?;
    let recv_fd = xdp.xsk.fd();  // pollable fd for mio

    Ok(Self {
        raw_recv_fd: recv_fd,
        raw_send_fd: recv_fd,
        filter_port: -1,
        seq_mode: config.seq_mode,
        ip_id_counter: 0,
        g_packet_buf: vec![0u8; HUGE_BUF_LEN],
        g_packet_buf_len: -1,
        lower_level: false,
        xdp: Some(xdp),
    })
}
```

#### 5.4.c Modify `send_raw_ip()` — XDP early-return after IP header build

```rust
pub fn send_raw_ip(&mut self, raw_info: &mut RawInfo, payload: &[u8]) -> io::Result<usize> {
    let send_info = &raw_info.send_info;
    match (send_info.src_ip, send_info.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // ...existing IP header construction (unchanged)...
            packet[..20].copy_from_slice(iph.as_bytes());
            packet[20..20 + payload.len()].copy_from_slice(payload);

            // ── XDP path: prepend Ethernet header, write to TX ring ──
            #[cfg(feature = "xdp")]
            if let Some(ref mut xdp) = self.xdp {
                xdp.send_ip_packet(&packet[..ip_payload_len], 0x0800)?;
                return Ok(ip_payload_len);
            }

            // ...existing sendto() path (unchanged)...
        }
        // ...
    }
}
```

#### 5.4.d Modify `recv_raw_ip()` — XDP early-return stripping Ethernet header

```rust
pub fn recv_raw_ip(&mut self, raw_info: &mut RawInfo) -> io::Result<Vec<u8>> {
    // ── XDP path: read L2 frame, strip Ethernet, parse IP ──
    #[cfg(feature = "xdp")]
    if let Some(ref mut xdp) = self.xdp {
        let (ethertype, ip_data) = xdp.recv_ip_packet()?;
        if ethertype != 0x0800 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "non-IPv4"));
        }
        if ip_data.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too short"));
        }
        let ihl = (ip_data[0] & 0x0F) as usize * 4;
        if ip_data.len() < ihl {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated"));
        }
        let saddr = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
        let daddr = u32::from_be_bytes([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);
        raw_info.recv_info.src_ip = IpAddr::V4(Ipv4Addr::from(saddr));
        raw_info.recv_info.dst_ip = IpAddr::V4(Ipv4Addr::from(daddr));
        raw_info.recv_info.protocol = ip_data[9];
        return Ok(ip_data[ihl..].to_vec());
    }

    // ...existing recvfrom() path (unchanged)...
}
```

#### 5.4.e Modify `discard_raw_packet()` — change `&self` → `&mut self`

```rust
// Before: pub fn discard_raw_packet(&self)
// After:
pub fn discard_raw_packet(&mut self) {
    #[cfg(feature = "xdp")]
    if self.xdp.is_some() {
        let _ = self.recv_raw_ip(&mut RawInfo::default());
        return;
    }

    // ...existing libc::recv path...
}
```

All callers already have `&mut RawSocketState` — no call-site changes needed.

#### 5.4.f Modify `init_filter()` — no-op for XDP mode

```rust
pub fn init_filter(&mut self, port: u16, config: &Config) {
    #[cfg(feature = "xdp")]
    if self.xdp.is_some() {
        log::info!("XDP mode: BPF filter handled by eBPF program");
        return;
    }
    // ...existing code...
}
```

### 5.5 `src/main.rs` — XDP initialization path

```rust
// Initialize raw sockets — dispatch based on XDP feature/config
#[cfg(feature = "xdp")]
let mut raw_state = if config.xdp_enabled {
    let ebpf_bytes = aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/udp2raw-ebpf")
    );
    RawSocketState::init_xdp(&config, ebpf_bytes).unwrap_or_else(|e| {
        log::error!("AF_XDP init failed: {}", e);
        log::error!("hint: requires CAP_NET_ADMIN+CAP_BPF, kernel ≥4.18, bpf-linker");
        std::process::exit(-1);
    })
} else {
    RawSocketState::init(&config).unwrap_or_else(|e| {
        log::error!("raw socket init failed: {}", e);
        std::process::exit(-1);
    })
};

#[cfg(not(feature = "xdp"))]
let mut raw_state = RawSocketState::init(&config).unwrap_or_else(|e| {
    log::error!("raw socket init failed: {}", e);
    std::process::exit(-1);
});
```

---

## 6. Step-by-step Implementation

### Phase 1: Scaffold (no functional change)

| # | Task | Files |
|---|---|---|
| 1 | Add `[features] xdp` to `Cargo.toml`, add `aya`/`aya-build` deps | `Cargo.toml` |
| 2 | Add `[workspace] exclude = ["udp2raw-ebpf"]` | `Cargo.toml` |
| 3 | Create `udp2raw-ebpf/` with Cargo.toml + XDP program | new dir |
| 4 | Create `build.rs` (cfg-gated eBPF compilation) | `build.rs` |
| 5 | Add `#[cfg(feature = "xdp")] pub mod xdp;` | `src/lib.rs` |
| 6 | Create stub `src/xdp.rs` that compiles but does nothing | `src/xdp.rs` |
| 7 | Verify `cargo build` (default features) still works | — |
| 8 | Verify `cargo build --features xdp` compiles eBPF + loads aya | — |

### Phase 2: XSK socket core

| # | Task | Files |
|---|---|---|
| 9 | Define AF_XDP constants + kernel structs | `src/xdp.rs` |
| 10 | Implement `FrameAllocator` | `src/xdp.rs` |
| 11 | Implement `Ring` (mmap, prod/cons ops, Drop) | `src/xdp.rs` |
| 12 | Implement `XskSocket::new()` (UMEM, rings, bind) | `src/xdp.rs` |
| 13 | Implement `XskSocket::recv()` / `send()` / reclaim | `src/xdp.rs` |
| 14 | Unit test: create XSK in netns, send/recv raw frame | `tests/xdp_smoke.rs` |

### Phase 3: Aya integration

| # | Task | Files |
|---|---|---|
| 15 | Implement `XdpState::init()` — load, attach, register XSK in map | `src/xdp.rs` |
| 16 | Implement `send_ip_packet()` / `recv_ip_packet()` (Ethernet wrap/unwrap) | `src/xdp.rs` |
| 17 | Add helper `ifname_to_index()`, `get_interface_mac()` | `src/xdp.rs` |

### Phase 4: RawSocketState integration

| # | Task | Files |
|---|---|---|
| 18 | Add `xdp: Option<XdpState>` field to `RawSocketState` | `src/network.rs` |
| 19 | Add `init_xdp()` constructor | `src/network.rs` |
| 20 | Add XDP early-return in `send_raw_ip()` | `src/network.rs` |
| 21 | Add XDP early-return in `recv_raw_ip()` | `src/network.rs` |
| 22 | Change `discard_raw_packet(&self)` → `(&mut self)` | `src/network.rs` |
| 23 | Add XDP no-op in `init_filter()` | `src/network.rs` |

### Phase 5: CLI + main wiring

| # | Task | Files |
|---|---|---|
| 24 | Add `--xdp`, `--xdp-queue`, `--xdp-zerocopy` CLI flags | `src/misc.rs` |
| 25 | Add Config fields, parsing | `src/misc.rs` |
| 26 | Add XDP init path in `main()` | `src/main.rs` |

### Phase 6: Testing + validation

| # | Task | Files |
|---|---|---|
| 27 | `cargo test` — all existing tests still pass (no feature) | — |
| 28 | `cargo test --features xdp` — compilation succeeds | — |
| 29 | Integration test in network namespace (veth pair) | `tests/xdp_integration.rs` |
| 30 | Manual test: udp2raw client ↔ server with `--xdp` | — |
| 31 | Wire protocol test: capture packets, verify byte-identical to non-XDP | — |

---

## 7. CLI Interface

```bash
# Default (no change):
udp2raw -c -l 0.0.0.0:3333 -r 1.2.3.4:4096 -k secret --raw-mode faketcp -a

# With AF_XDP (compile with --features xdp):
udp2raw -c -l 0.0.0.0:3333 -r 1.2.3.4:4096 -k secret --raw-mode faketcp \
    --xdp "eth0#aa:bb:cc:dd:ee:ff" \
    --xdp-queue 0

# With zero-copy:
udp2raw -c ... --xdp "eth0#aa:bb:cc:dd:ee:ff" --xdp-zerocopy
```

The `--xdp` argument format `"if_name#dest_mac"` mirrors the existing
`--lower-level` format for consistency.

---

## 8. Build System

```bash
# Default build (no AF_XDP, no extra deps):
cargo build --release

# AF_XDP build (needs bpf-linker + nightly for eBPF target):
cargo install bpf-linker
cargo build --release --features xdp

# Test (no root needed for unit tests):
cargo test
cargo test --features xdp

# XDP integration test (root / CAP_NET_ADMIN required):
sudo cargo test --features xdp --test xdp_integration
```

The `xdp` feature is **opt-in** and **additive**:
- Without `xdp`: no aya deps, no eBPF compilation, no AF_XDP code paths
- With `xdp`: aya + aya-build pulled in, eBPF compiled, `--xdp` flag available

---

## 9. Data Flow

### 9.1 Send path (XDP mode)

```
client_on_udp_recv()
  └─▶ send_data_safer()            # connection.rs — build safer packet
        └─▶ encryptor.my_encrypt()  # encrypt.rs   — encrypt payload
              └─▶ send_raw0()       # network.rs   — dispatch by raw_mode
                    └─▶ send_raw_tcp() / send_raw_udp() / send_raw_icmp()
                          └─▶ send_raw_ip()   # network.rs
                                │
                                │  Build IP header + checksum (UNCHANGED)
                                │  Build packet[..ip_payload_len]
                                │
                                ├── [XDP path] xdp.send_ip_packet()
                                │     ├── Prepend 14-byte Ethernet header
                                │     │   [dst_mac:6][src_mac:6][0x0800:2]
                                │     ├── Copy into UMEM frame
                                │     ├── Write XdpDesc to TX ring
                                │     ├── prod_submit()
                                │     └── kick_tx() → sendto(fd,NULL,0)
                                │
                                └── [Legacy path] libc::sendto()  (unchanged)
```

### 9.2 Receive path (XDP mode)

```
NIC hardware queue
  └─▶ XDP eBPF program (udp2raw_xdp)
        └─▶ XSKMAP.redirect(queue_id) → XDP_REDIRECT
              └─▶ kernel fills RX ring with L2 frame

mio::Poll wakes on XSK fd READABLE
  └─▶ client_on_raw_recv() / server_on_raw_recv()
        └─▶ recv_raw0()                 # network.rs
              └─▶ recv_raw_ip()
                    │
                    ├── [XDP path] xdp.recv_ip_packet()
                    │     ├── cons_peek(1) on RX ring
                    │     ├── Read L2 frame from UMEM
                    │     ├── Strip 14-byte Ethernet header
                    │     ├── cons_release(1)
                    │     ├── Recycle frame → fill ring
                    │     └── Return (ethertype, ip_payload)
                    │
                    └── [Legacy path] libc::recvfrom()  (unchanged)
              │
              └─▶ Parse protocol header (TCP/UDP/ICMP) — UNCHANGED
        └─▶ recv_bare() / recv_safer_multi() — UNCHANGED
              └─▶ encryptor.my_decrypt() — UNCHANGED
```

### 9.3 Wire format verification

The IP packet bytes built in `send_raw_ip()` are **identical** regardless of
transport (legacy sendto vs XDP TX ring). The only difference is the L2 framing
that AF_XDP requires, which is added/stripped at the boundary and never reaches
the encryption or wire-protocol layers.

```
                 ┌─── AF_XDP adds/strips this ───┐
                 │                                │
    L2:  [dst_mac:6][src_mac:6][ethertype:2]  [IP header][TCP/UDP/ICMP][encrypted payload]
                                               └──────── identical bytes ────────────────┘
```

---

## 10. Testing Strategy

### 10.1 Existing tests (MUST still pass)

```bash
cargo test                          # no feature — zero XDP code compiled
cargo test --features xdp           # XDP code compiled, but not activated at runtime
cargo test --test wire_protocol     # byte-layout verification
cargo test --test encrypt_cross     # cipher×auth roundtrips
cargo test --test packet_headers    # struct size/offset assertions
cargo test --test anti_replay       # sliding window correctness
```

### 10.2 New XDP unit tests (`src/xdp.rs` #[cfg(test)])

| Test | What it verifies |
|---|---|
| `frame_allocator_roundtrip` | alloc→free→alloc returns valid addrs |
| `ring_prod_cons_basic` | reserve/submit/peek/release cycle |
| `xdp_constants_match_kernel` | AF_XDP=44, SOL_XDP=283, struct sizes |
| `ethernet_header_build` | 14-byte header with correct MAC + ethertype |

### 10.3 New XDP integration test (`tests/xdp_integration.rs`)

Requires root or `CAP_NET_ADMIN` + `CAP_BPF`. Uses a veth pair in a network
namespace for isolation.

```rust
#[test]
#[ignore]  // needs root
fn xdp_veth_roundtrip() {
    // 1. Create netns + veth pair
    // 2. Start udp2raw server with --xdp on veth1
    // 3. Start udp2raw client with --xdp on veth0
    // 4. Send UDP payload through tunnel
    // 5. Verify payload arrives intact
    // 6. Capture raw packets on veth — verify byte-identical to non-XDP
}
```

### 10.4 Wire-compatibility verification

```bash
# Run non-XDP server, XDP client (or vice versa) — must interop:
# Server (legacy):
sudo ./udp2raw -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 -k test -a
# Client (XDP):
sudo ./udp2raw -c -l 0.0.0.0:3333 -r server:4096 -k test \
    --xdp "eth0#<server_mac>" -a
```

If any packet differs → **AF_XDP implementation is broken**.

---

## 11. Open Questions

| # | Question | Options | Recommendation |
|---|---|---|---|
| 1 | **Default bind flag** | `XDP_COPY` vs `XDP_ZEROCOPY` | Default `XDP_COPY` (all drivers); opt-in `--xdp-zerocopy` |
| 2 | **XDP attach mode** | `SKB_MODE` vs `DRV_MODE` vs `HW_MODE` | Default `SKB_MODE` (compat); add `--xdp-mode` flag later |
| 3 | **Multi-queue** | Single queue (queue 0) vs all queues | Start with single queue (`--xdp-queue 0`); multi-queue later |
| 4 | **Busy-poll** | `SO_BUSY_POLL` / `SO_PREFER_BUSY_POLL` | Add later as `--xdp-busy-poll` for lowest latency |
| 5 | **IPv6 support** | AF_XDP is L2-agnostic | Check `ethertype == 0x86DD` in recv path; phase 2 |
| 6 | **UMEM sizing** | Fixed 4096×4096 = 16MB | Add `--xdp-umem-frames` / `--xdp-frame-size` later |
| 7 | **Graceful fallback** | If XDP attach fails, fall back to legacy? | No — fail loudly; user can remove `--xdp` flag |

---

## Appendix A: File Change Summary

| File | Action | Lines (est.) |
|---|---|---|
| `udp2raw-ebpf/Cargo.toml` | **CREATE** | ~25 |
| `udp2raw-ebpf/src/main.rs` | **CREATE** | ~30 |
| `build.rs` | **CREATE** | ~10 |
| `src/xdp.rs` | **CREATE** | ~500 |
| `Cargo.toml` | MODIFY | +10 |
| `src/lib.rs` | MODIFY | +2 |
| `src/misc.rs` | MODIFY | +40 |
| `src/network.rs` | MODIFY | +60 |
| `src/main.rs` | MODIFY | +15 |
| `tests/xdp_integration.rs` | **CREATE** | ~80 |
| **Total** | | **~770** |

## Appendix B: Dependency Tree (xdp feature only)

```
udp2raw (bin)
├── aya 0.13             # eBPF loader, XskMap management
│   ├── libc
│   ├── thiserror
│   └── ...
└── (build) aya-build 0.1  # compiles udp2raw-ebpf → BPF bytecode
    └── (invokes cargo with bpfel-unknown-none target)

udp2raw-ebpf (eBPF binary, NOT a workspace member)
└── aya-ebpf 0.1         # #![no_std] eBPF helpers
```

No new runtime dependencies are added to the default (non-xdp) build.

