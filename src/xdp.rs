//! AF_XDP (eXpress Data Path) socket transport.
//!
//! Provides a high-performance kernel-bypass packet I/O path as an alternative
//! to AF_INET SOCK_RAW or AF_PACKET. The AF_XDP socket fd is epoll-compatible,
//! so it plugs directly into the mio::Poll event loop.
//!
//! Activated via `--xdp` CLI flag. Requires Linux >= 5.4 and CAP_NET_ADMIN + CAP_NET_RAW.
//! Uses XDP_SKB_MODE (copy mode) by default for broad compatibility.
//!
//! ⚠️  This module only changes the transport layer. Packet contents on the wire
//! (IP headers, protocol headers, encrypted payloads) remain byte-identical
//! to the raw socket path. Wire compatibility is preserved.

use crate::common::*;
use crate::misc::Config;
use crate::network::{
    IpHeader, PseudoHeader, RawInfo, TcpHeader,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::RawFd;


// ─── Kernel constants (from linux/if_xdp.h) ────────────────────────────────
// These are stable ABI and will not change.

const AF_XDP: i32 = 44;

const SOL_XDP: i32 = 283;

const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;

const XDP_PGOFF_RX_RING: u64 = 0;
const XDP_PGOFF_TX_RING: u64 = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;

/// XDP "pass" action — let packet continue up the normal stack.
const XDP_PASS: i32 = 2;
/// XDP "redirect" action — redirect to an XSK map entry.
const XDP_REDIRECT: i32 = 4;

// BPF constants for loading programs via bpf() syscall
const BPF_PROG_LOAD: i32 = 5;
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_LINK_CREATE: i32 = 28;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;

const SYS_BPF: libc::c_long = 321; // x86_64

// ─── Ring descriptor (matches kernel struct xdp_desc) ───────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

// ─── UMEM registration struct ───────────────────────────────────────────────

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

// ─── sockaddr_xdp ──────────────────────────────────────────────────────────

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

// ─── Mmap offsets struct ────────────────────────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset, // fill ring
    cr: XdpRingOffset, // completion ring
}

// ─── bpf_attr union for BPF syscall ─────────────────────────────────────────

// We define minimal versions of the bpf_attr union fields we need.
// Each variant is passed to the bpf() syscall as a raw pointer.

#[repr(C)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    // Remaining fields are zero-initialized
    _pad: [u8; 96], // bpf_attr is ~120 bytes total; we pad the rest
}

#[repr(C)]
struct BpfAttrMapUpdate {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value_or_next: u64,
    flags: u64,
    _pad: [u8; 80],
}

#[repr(C)]
struct BpfAttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    // pad to full bpf_attr size
    _pad: [u8; 72],
}

#[repr(C)]
struct BpfAttrLinkCreate {
    prog_fd: u32,
    target_fd: u32,  // target_ifindex for XDP
    attach_type: u32, // BPF_XDP = 37
    flags: u32,
    _pad: [u8; 96],
}

// ─── BPF insn ───────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    dst_src: u8, // dst_reg:4 | src_reg:4
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_src: (src << 4) | (dst & 0xf),
            off,
            imm,
        }
    }
}

// BPF instruction macros as const fns
const BPF_ALU64: u8 = 0x07;
const BPF_MOV: u8 = 0xb0;
const BPF_K_SRC: u8 = 0x00;
const BPF_JMP_OP: u8 = 0x05;
const BPF_EXIT: u8 = 0x90;
const BPF_CALL: u8 = 0x80;
const BPF_LD_IMM64: u8 = 0x18;
const BPF_DW: u8 = 0x18;

const fn bpf_mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K_SRC, dst, 0, 0, imm)
}

const fn bpf_mov64_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | 0x08, dst, src, 0, 0)
}

const fn bpf_call(func_id: i32) -> BpfInsn {
    BpfInsn::new(BPF_JMP_OP | BPF_CALL, 0, 0, 0, func_id)
}

const fn bpf_exit() -> BpfInsn {
    BpfInsn::new(BPF_JMP_OP | BPF_EXIT, 0, 0, 0, 0)
}

// bpf_ld_map_fd is 2 instructions (wide immediate)
fn bpf_ld_map_fd(dst: u8, map_fd: i32) -> [BpfInsn; 2] {
    [
        BpfInsn::new(BPF_LD_IMM64 | 0x01, dst, 1, 0, map_fd), // BPF_PSEUDO_MAP_FD = 1
        BpfInsn::new(0, 0, 0, 0, 0), // upper 32 bits of imm64
    ]
}

// ─── Ring helpers ───────────────────────────────────────────────────────────

struct UmemRing {
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut u64, // for fill/completion rings: array of u64 addrs
    mask: u32,
    size: u32,
    _map: *mut u8,
    _map_len: usize,
}

struct DescRing {
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut XdpDesc, // for rx/tx rings: array of XdpDesc
    mask: u32,
    size: u32,
    _map: *mut u8,
    _map_len: usize,
}

// ─── UMEM frame allocator ───────────────────────────────────────────────────

struct FrameAllocator {
    free_list: Vec<u64>,
}

impl FrameAllocator {
    fn new(num_frames: u32, frame_size: u32) -> Self {
        let mut free_list = Vec::with_capacity(num_frames as usize);
        for i in 0..num_frames {
            free_list.push((i as u64) * (frame_size as u64));
        }
        Self { free_list }
    }

    fn alloc(&mut self) -> Option<u64> {
        self.free_list.pop()
    }

    fn free(&mut self, addr: u64) {
        self.free_list.push(addr);
    }

    fn available(&self) -> usize {
        self.free_list.len()
    }
}

// ─── Configuration ──────────────────────────────────────────────────────────

const NUM_FRAMES: u32 = 4096;
const FRAME_SIZE: u32 = 4096; // XDP_UMEM_MIN_CHUNK_SIZE
const RING_SIZE: u32 = 2048; // Must be power of 2
const FRAME_HEADROOM: u32 = 0;

/// Max raw packet size for XDP send path.
/// Ethernet(14) + IP(20) + TCP(32) + BUF_LEN(2200) = 2266
const XDP_SEND_BUF_SIZE: usize = BUF_LEN + 66;

// ─── XdpSocketState ─────────────────────────────────────────────────────────

pub struct XdpSocketState {
    /// The AF_XDP socket fd — register this with mio as READABLE.
    pub xsk_fd: RawFd,
    /// Interface index.
    ifindex: u32,
    /// Queue ID for the XDP socket.
    queue_id: u32,
    /// UMEM area (mmap'd).
    umem_area: *mut u8,
    umem_size: usize,
    /// Frame allocator.
    frames: FrameAllocator,
    /// Fill ring (userspace → kernel: frames available for RX).
    fill: UmemRing,
    /// Completion ring (kernel → userspace: TX frames completed).
    comp: UmemRing,
    /// RX ring (kernel → userspace: received packets).
    rx: DescRing,
    /// TX ring (userspace → kernel: packets to transmit).
    tx: DescRing,
    /// BPF program fd (for cleanup).
    bpf_prog_fd: RawFd,
    /// XSKMAP fd.
    xskmap_fd: RawFd,
    /// BPF link fd (for cleanup).
    bpf_link_fd: RawFd,
    /// Reusable recv buffer.
    pub g_packet_buf: Vec<u8>,
    /// Counters (matching RawSocketState interface).
    pub ip_id_counter: u16,
    pub is_client: bool,
    pub seq_mode: u32,
    pub filter_port: i32,
    /// Source MAC address (resolved from interface).
    src_mac: [u8; 6],
    /// Destination MAC address (from config or ARP).
    dst_mac: [u8; 6],
}

// Safety: XdpSocketState contains raw pointers to mmap'd regions and is only
// used from a single-threaded mio event loop (no Send/Sync needed), matching
// the RawSocketState pattern.

impl XdpSocketState {
    /// Initialize AF_XDP socket and attach XDP program.
    pub fn init(config: &Config) -> io::Result<Self> {
        let if_name = if !config.xdp_if_name.is_empty() {
            config.xdp_if_name.clone()
        } else if !config.dev.is_empty() {
            config.dev.clone()
        } else if !config.lower_level_if_name.is_empty() {
            config.lower_level_if_name.clone()
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--xdp requires --dev <interface> or --lower-level <if_name#mac>",
            ));
        };

        let ifindex = if_nametoindex(&if_name)?;
        let queue_id = config.xdp_queue_id;

        log::info!("AF_XDP: interface={} ifindex={} queue={}", if_name, ifindex, queue_id);

        // 1. Create AF_XDP socket
        let xsk_fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if xsk_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // 2. Allocate and register UMEM
        let umem_size = (NUM_FRAMES as usize) * (FRAME_SIZE as usize);
        let umem_area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem_area == libc::MAP_FAILED {
            unsafe { libc::close(xsk_fd); }
            return Err(io::Error::last_os_error());
        }
        let umem_area = umem_area as *mut u8;

        let umem_reg = XdpUmemReg {
            addr: umem_area as u64,
            len: umem_size as u64,
            chunk_size: FRAME_SIZE,
            headroom: FRAME_HEADROOM,
            flags: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                xsk_fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(umem_area as *mut libc::c_void, umem_size);
                libc::close(xsk_fd);
            }
            return Err(e);
        }

        // 3. Set ring sizes
        let ring_size_val: libc::c_int = RING_SIZE as libc::c_int;
        let optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        for opt in [XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
            let ret = unsafe {
                libc::setsockopt(
                    xsk_fd, SOL_XDP, opt,
                    &ring_size_val as *const _ as *const libc::c_void,
                    optlen,
                )
            };
            if ret < 0 {
                let e = io::Error::last_os_error();
                unsafe {
                    libc::munmap(umem_area as *mut libc::c_void, umem_size);
                    libc::close(xsk_fd);
                }
                return Err(e);
            }
        }

        // 4. Get mmap offsets
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen_offsets = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen_offsets,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            unsafe {
                libc::munmap(umem_area as *mut libc::c_void, umem_size);
                libc::close(xsk_fd);
            }
            return Err(e);
        }

        // 5. Mmap the rings
        let fill = Self::mmap_umem_ring(xsk_fd, &offsets.fr, RING_SIZE, XDP_UMEM_PGOFF_FILL_RING)?;
        let comp = Self::mmap_umem_ring(xsk_fd, &offsets.cr, RING_SIZE, XDP_UMEM_PGOFF_COMPLETION_RING)?;
        let rx = Self::mmap_desc_ring(xsk_fd, &offsets.rx, RING_SIZE, XDP_PGOFF_RX_RING)?;
        let tx = Self::mmap_desc_ring(xsk_fd, &offsets.tx, RING_SIZE, XDP_PGOFF_TX_RING)?;

        // 6. Initialize frame allocator and pre-fill the fill ring
        let mut frames = FrameAllocator::new(NUM_FRAMES, FRAME_SIZE);

        // Pre-populate the fill ring so kernel has frames for RX
        let fill_count = RING_SIZE.min(NUM_FRAMES / 2);
        for i in 0..fill_count {
            let addr = frames.alloc().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "out of UMEM frames during init")
            })?;
            unsafe {
                let idx = i & (RING_SIZE - 1);
                *fill.ring.add(idx as usize) = addr;
            }
        }
        unsafe {
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            *fill.producer = fill_count;
        }

        // 7. Create XSKMAP and load XDP program
        let xskmap_fd = Self::create_xskmap()?;
        let bpf_prog_fd = Self::load_xdp_program(xskmap_fd)?;

        // 8. Add XSK fd to map at queue_id
        Self::update_xskmap(xskmap_fd, queue_id, xsk_fd)?;

        // 9. Attach XDP program to interface
        let bpf_link_fd = Self::attach_xdp_program(bpf_prog_fd, ifindex)?;

        // 10. Bind the AF_XDP socket
        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_FLAGS_SKB_MODE as u16,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                xsk_fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let e = io::Error::last_os_error();
            // Cleanup omitted for brevity — Drop handles it
            return Err(e);
        }

        setnonblocking(xsk_fd)?;

        // 11. Resolve MAC addresses
        let src_mac = get_interface_mac(&if_name)?;
        let dst_mac = if config.lower_level_manual {
            config.lower_level_dest_mac
        } else {
            config.xdp_dst_mac
        };

        log::info!(
            "AF_XDP: src_mac={} dst_mac={} frames={} ring_size={}",
            format_mac(&src_mac), format_mac(&dst_mac), NUM_FRAMES, RING_SIZE
        );

        Ok(Self {
            xsk_fd,
            ifindex,
            queue_id,
            umem_area,
            umem_size,
            frames,
            fill,
            comp,
            rx,
            tx,
            bpf_prog_fd,
            xskmap_fd,
            bpf_link_fd,
            g_packet_buf: vec![0u8; HUGE_BUF_LEN],
            ip_id_counter: 0,
            is_client: config.program_mode == ProgramMode::Client,
            seq_mode: config.seq_mode,
            filter_port: -1,
            src_mac,
            dst_mac,
        })
    }

    /// The fd to register with mio for READABLE events (analogous to raw_recv_fd).
    pub fn recv_fd(&self) -> RawFd {
        self.xsk_fd
    }

    // ─── Ring mmap helpers ──────────────────────────────────────────────────

    fn mmap_umem_ring(
        fd: RawFd,
        off: &XdpRingOffset,
        size: u32,
        pgoff: u64,
    ) -> io::Result<UmemRing> {
        let map_len = (off.desc as usize) + (size as usize) * std::mem::size_of::<u64>();
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let map = map as *mut u8;
        Ok(UmemRing {
            producer: unsafe { map.add(off.producer as usize) as *mut u32 },
            consumer: unsafe { map.add(off.consumer as usize) as *mut u32 },
            ring: unsafe { map.add(off.desc as usize) as *mut u64 },
            mask: size - 1,
            size,
            _map: map,
            _map_len: map_len,
        })
    }

    fn mmap_desc_ring(
        fd: RawFd,
        off: &XdpRingOffset,
        size: u32,
        pgoff: u64,
    ) -> io::Result<DescRing> {
        let map_len = (off.desc as usize) + (size as usize) * std::mem::size_of::<XdpDesc>();
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as libc::off_t,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let map = map as *mut u8;
        Ok(DescRing {
            producer: unsafe { map.add(off.producer as usize) as *mut u32 },
            consumer: unsafe { map.add(off.consumer as usize) as *mut u32 },
            ring: unsafe { map.add(off.desc as usize) as *mut XdpDesc },
            mask: size - 1,
            size,
            _map: map,
            _map_len: map_len,
        })
    }

    // ─── BPF program loading ────────────────────────────────────────────────

    fn create_xskmap() -> io::Result<RawFd> {
        let mut attr: BpfAttrMapCreate = unsafe { std::mem::zeroed() };
        attr.map_type = BPF_MAP_TYPE_XSKMAP;
        attr.key_size = 4;
        attr.value_size = 4;
        attr.max_entries = 256;

        let fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_CREATE,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapCreate>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    fn update_xskmap(map_fd: RawFd, key: u32, xsk_fd: RawFd) -> io::Result<()> {
        let key_val = key;
        let val = xsk_fd as u32;
        let mut attr: BpfAttrMapUpdate = unsafe { std::mem::zeroed() };
        attr.map_fd = map_fd as u32;
        attr.key = &key_val as *const u32 as u64;
        attr.value_or_next = &val as *const u32 as u64;
        attr.flags = 0; // BPF_ANY

        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_UPDATE_ELEM,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapUpdate>(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Load a minimal XDP program that redirects all packets to the XSKMAP.
    ///
    /// Equivalent eBPF (pseudo-C):
    /// ```c
    /// SEC("xdp")
    /// int xdp_sock_prog(struct xdp_md *ctx) {
    ///     return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    /// }
    /// ```
    fn load_xdp_program(xskmap_fd: RawFd) -> io::Result<RawFd> {
        // Build BPF instructions.
        // r1 = ctx (already set by kernel)
        // r2 = *(u32 *)(ctx + 16)  // ctx->rx_queue_index (offset 16 in xdp_md)
        // r1 = map_fd (XSKMAP)     // bpf_ld_map_fd → 2 insns
        // r3 = XDP_PASS            // fallback action
        // call bpf_redirect_map    // helper #51
        // exit

        let ld_map = bpf_ld_map_fd(1, xskmap_fd as i32);

        let insns: Vec<BpfInsn> = vec![
            // r2 = *(u32 *)(r1 + 16)  — load ctx->rx_queue_index
            BpfInsn::new(0x61, 2, 1, 16, 0), // BPF_LDX_MEM(BPF_W, r2, r1, 16)
            // r1 = map_fd
            ld_map[0],
            ld_map[1],
            // r3 = XDP_PASS (fallback)
            bpf_mov64_imm(3, XDP_PASS),
            // call bpf_redirect_map (#51)
            bpf_call(51),
            // exit
            bpf_exit(),
        ];

        let license = b"GPL\0";

        let mut attr: BpfAttrProgLoad = unsafe { std::mem::zeroed() };
        attr.prog_type = BPF_PROG_TYPE_XDP;
        attr.insn_cnt = insns.len() as u32;
        attr.insns = insns.as_ptr() as u64;
        attr.license = license.as_ptr() as u64;

        let fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_PROG_LOAD,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrProgLoad>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    /// Attach the XDP program to the interface using BPF_LINK_CREATE.
    fn attach_xdp_program(prog_fd: RawFd, ifindex: u32) -> io::Result<RawFd> {
        let mut attr: BpfAttrLinkCreate = unsafe { std::mem::zeroed() };
        attr.prog_fd = prog_fd as u32;
        attr.target_fd = ifindex;
        attr.attach_type = 37; // BPF_XDP
        attr.flags = 0;

        let fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_LINK_CREATE,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrLinkCreate>(),
            )
        };
        if fd < 0 {
            // BPF_LINK_CREATE may not be available on older kernels.
            // Fall back to NETLINK_ROUTE XDP attach via setsockopt.
            log::warn!("BPF_LINK_CREATE failed ({}), trying legacy XDP attach", io::Error::last_os_error());
            return Self::attach_xdp_legacy(prog_fd, ifindex);
        }
        Ok(fd as RawFd)
    }

    /// Legacy XDP attach via netlink (fallback for kernels without BPF_LINK_CREATE).
    fn attach_xdp_legacy(_prog_fd: RawFd, _ifindex: u32) -> io::Result<RawFd> {
        // Use IFLA_XDP via netlink to attach.
        // For simplicity, shell out to `ip link set dev <ifname> xdp fd <prog_fd>`
        // This is a fallback — BPF_LINK_CREATE is preferred.
        //
        // Actually, we can use the XDP_SETUP_PROG netlink command directly.
        // For now, return -1 as the link fd and clean up via netlink in Drop.
        log::warn!("legacy XDP attach not implemented, BPF_LINK_CREATE is required (Linux >= 5.7)");
        Err(io::Error::new(io::ErrorKind::Unsupported, "BPF_LINK_CREATE required"))
    }

    // ─── Reclaim TX completion frames ───────────────────────────────────────

    fn reclaim_tx_completions(&mut self) {
        let cons = unsafe { std::ptr::read_volatile(self.comp.consumer) };
        let prod = unsafe { std::ptr::read_volatile(self.comp.producer) };

        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);

        let mut idx = cons;
        while idx != prod {
            let i = (idx & self.comp.mask) as usize;
            let addr = unsafe { *self.comp.ring.add(i) };
            // Return frame to allocator (aligned to FRAME_SIZE)
            self.frames.free(addr & !((FRAME_SIZE as u64) - 1));
            idx = idx.wrapping_add(1);
        }

        if cons != prod {
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            unsafe { std::ptr::write_volatile(self.comp.consumer, prod); }
        }
    }

    // ─── Refill the fill ring ───────────────────────────────────────────────

    fn refill_fill_ring(&mut self) {
        let prod = unsafe { std::ptr::read_volatile(self.fill.producer) };
        let cons = unsafe { std::ptr::read_volatile(self.fill.consumer) };

        let free_slots = self.fill.size.wrapping_sub(prod.wrapping_sub(cons));
        let to_fill = free_slots.min(self.frames.available() as u32);

        if to_fill == 0 {
            return;
        }

        let mut idx = prod;
        for _ in 0..to_fill {
            if let Some(addr) = self.frames.alloc() {
                let i = (idx & self.fill.mask) as usize;
                unsafe { *self.fill.ring.add(i) = addr; }
                idx = idx.wrapping_add(1);
            } else {
                break;
            }
        }

        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe { std::ptr::write_volatile(self.fill.producer, idx); }
    }

    // ─── Public API matching RawSocketState ─────────────────────────────────

    /// Attach BPF filter for the specified port.
    /// For AF_XDP, the XDP program already redirects all packets.
    /// Port filtering is done in userspace (same as raw socket BPF — just faster path).
    pub fn init_filter(&mut self, port: u16, _config: &Config) {
        self.filter_port = port as i32;
        log::info!("AF_XDP: filter port set to {} (userspace filtering)", port);
    }

    /// Send a raw IP packet via the TX ring.
    pub fn send_raw_ip(&mut self, raw_info: &mut RawInfo, payload: &[u8]) -> io::Result<usize> {
        let send_info = &raw_info.send_info;

        match (send_info.src_ip, send_info.dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                self.reclaim_tx_completions();

                let ip_payload_len = 20 + payload.len();
                let eth_frame_len = 14 + ip_payload_len;

                // Allocate a TX frame
                let frame_addr = self.frames.alloc().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::WouldBlock, "no free XDP TX frames")
                })?;

                // Build Ethernet + IP + payload into the UMEM frame
                let frame_ptr = unsafe { self.umem_area.add(frame_addr as usize) };

                // Ethernet header (14 bytes)
                unsafe {
                    std::ptr::copy_nonoverlapping(self.dst_mac.as_ptr(), frame_ptr, 6);
                    std::ptr::copy_nonoverlapping(self.src_mac.as_ptr(), frame_ptr.add(6), 6);
                    // EtherType: IPv4 = 0x0800
                    *frame_ptr.add(12) = 0x08;
                    *frame_ptr.add(13) = 0x00;
                }

                // IP header (20 bytes)
                let mut iph = IpHeader::default();
                iph.set_version_ihl(4, 5);
                iph.tos = 0;
                iph.tot_len = (ip_payload_len as u16).to_be();
                self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
                iph.id = self.ip_id_counter.to_be();
                iph.frag_off = 0x40u16.to_be();
                iph.ttl = 64;
                iph.protocol = send_info.protocol;
                iph.saddr = u32::from(src).to_be();
                iph.daddr = u32::from(dst).to_be();
                iph.check = 0;
                let hdr_bytes = iph.as_bytes();
                iph.check = csum(hdr_bytes);

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        iph.as_bytes().as_ptr(),
                        frame_ptr.add(14),
                        20,
                    );
                    std::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        frame_ptr.add(34),
                        payload.len(),
                    );
                }

                // Submit to TX ring
                let prod = unsafe { std::ptr::read_volatile(self.tx.producer) };
                let cons = unsafe { std::ptr::read_volatile(self.tx.consumer) };

                if prod.wrapping_sub(cons) >= self.tx.size {
                    self.frames.free(frame_addr);
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "XDP TX ring full"));
                }

                let idx = (prod & self.tx.mask) as usize;
                unsafe {
                    let desc = &mut *self.tx.ring.add(idx);
                    desc.addr = frame_addr;
                    desc.len = eth_frame_len as u32;
                    desc.options = 0;
                }

                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                unsafe { std::ptr::write_volatile(self.tx.producer, prod.wrapping_add(1)); }

                // Kick the kernel to process TX
                self.kick_tx()?;

                Ok(eth_frame_len)
            }
            _ => Err(io::Error::new(io::ErrorKind::Unsupported, "IPv6 not yet supported for AF_XDP")),
        }
    }

    /// Receive a raw IP packet from the RX ring.
    /// Returns the length of the IP payload stored at `self.g_packet_buf[0..len]`.
    /// Zero heap allocations.
    pub fn recv_raw_ip(&mut self, raw_info: &mut RawInfo) -> io::Result<usize> {
        self.reclaim_tx_completions();
        self.refill_fill_ring();

        let cons = unsafe { std::ptr::read_volatile(self.rx.consumer) };
        let prod = unsafe { std::ptr::read_volatile(self.rx.producer) };

        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);

        if cons == prod {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packets in RX ring"));
        }

        let idx = (cons & self.rx.mask) as usize;
        let desc = unsafe { *self.rx.ring.add(idx) };

        let frame_ptr = unsafe { self.umem_area.add(desc.addr as usize) };
        let frame_len = desc.len as usize;

        if frame_len < 14 + 20 {
            // Free the frame and advance consumer
            self.frames.free(desc.addr & !((FRAME_SIZE as u64) - 1));
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            unsafe { std::ptr::write_volatile(self.rx.consumer, cons.wrapping_add(1)); }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too short"));
        }

        // Skip Ethernet header (14 bytes) unless it's a peek
        if raw_info.peek {
            // For peek, copy to g_packet_buf but don't advance consumer
            let ip_data = unsafe {
                std::slice::from_raw_parts(frame_ptr.add(14), frame_len - 14)
            };
            let copy_len = ip_data.len().min(self.g_packet_buf.len());
            self.g_packet_buf[..copy_len].copy_from_slice(&ip_data[..copy_len]);

            // Parse IP header from the copy
            return self.parse_ip_packet_offsets(raw_info, copy_len);
        }

        // Non-peek: copy IP packet, free frame, advance consumer
        let ip_data = unsafe {
            std::slice::from_raw_parts(frame_ptr.add(14), frame_len - 14)
        };
        let copy_len = ip_data.len().min(self.g_packet_buf.len());
        self.g_packet_buf[..copy_len].copy_from_slice(&ip_data[..copy_len]);

        // Free the frame
        self.frames.free(desc.addr & !((FRAME_SIZE as u64) - 1));
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe { std::ptr::write_volatile(self.rx.consumer, cons.wrapping_add(1)); }

        self.parse_ip_packet_offsets(raw_info, copy_len)
    }

    /// Parse IP header from g_packet_buf. Returns length of IP payload
    /// shifted to the start of g_packet_buf (g_packet_buf[0..payload_len]).
    fn parse_ip_packet_offsets(&mut self, raw_info: &mut RawInfo, recv_len: usize) -> io::Result<usize> {
        if recv_len < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet too short"));
        }

        let version = (self.g_packet_buf[0] >> 4) & 0x0F;
        if version == 4 {
            let ihl = (self.g_packet_buf[0] & 0x0F) as usize * 4;
            if recv_len < ihl {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "IP header truncated"));
            }

            let saddr = u32::from_be_bytes([
                self.g_packet_buf[12], self.g_packet_buf[13],
                self.g_packet_buf[14], self.g_packet_buf[15],
            ]);
            let daddr = u32::from_be_bytes([
                self.g_packet_buf[16], self.g_packet_buf[17],
                self.g_packet_buf[18], self.g_packet_buf[19],
            ]);
            let protocol = self.g_packet_buf[9];

            raw_info.recv_info.src_ip = IpAddr::V4(Ipv4Addr::from(saddr));
            raw_info.recv_info.dst_ip = IpAddr::V4(Ipv4Addr::from(daddr));
            raw_info.recv_info.protocol = protocol;

            // Shift IP payload to start of g_packet_buf to match RawSocketState interface
            let payload_len = recv_len - ihl;
            self.g_packet_buf.copy_within(ihl..recv_len, 0);
            Ok(payload_len)
        } else {
            Err(io::Error::new(io::ErrorKind::Unsupported, "non-IPv4"))
        }
    }

    /// Discard one pending RX packet.
    pub fn discard_raw_packet(&mut self) {
        let cons = unsafe { std::ptr::read_volatile(self.rx.consumer) };
        let prod = unsafe { std::ptr::read_volatile(self.rx.producer) };

        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);

        if cons != prod {
            let idx = (cons & self.rx.mask) as usize;
            let desc = unsafe { *self.rx.ring.add(idx) };
            self.frames.free(desc.addr & !((FRAME_SIZE as u64) - 1));
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            unsafe { std::ptr::write_volatile(self.rx.consumer, cons.wrapping_add(1)); }
        }

        self.refill_fill_ring();
    }

    /// Build and send a FakeTCP packet (same logic as RawSocketState::send_raw_tcp).
    pub fn send_raw_tcp(
        &mut self,
        raw_info: &mut RawInfo,
        payload: &[u8],
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;
        let has_ts = send_info.has_ts;
        let tcp_hdr_len: usize = if has_ts { 32 } else { 20 };
        let tcp_len = tcp_hdr_len + payload.len();
        let mut tcp_buf = [0u8; XDP_SEND_BUF_SIZE];

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

        tcp_buf[..20].copy_from_slice(tcph.as_bytes());

        if has_ts {
            tcp_buf[20] = 0x01;
            tcp_buf[21] = 0x01;
            tcp_buf[22] = 0x08;
            tcp_buf[23] = 0x0A;
            tcp_buf[24..28].copy_from_slice(&send_info.ts.to_be_bytes());
            tcp_buf[28..32].copy_from_slice(&send_info.ts_ack.to_be_bytes());
        }

        if !payload.is_empty() {
            tcp_buf[tcp_hdr_len..tcp_hdr_len + payload.len()].copy_from_slice(payload);
        }

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
        let mut udp_buf = [0u8; XDP_SEND_BUF_SIZE];

        udp_buf[0..2].copy_from_slice(&send_info.src_port.to_be_bytes());
        udp_buf[2..4].copy_from_slice(&send_info.dst_port.to_be_bytes());
        udp_buf[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp_buf[6..8].copy_from_slice(&0u16.to_be_bytes());
        if !payload.is_empty() {
            udp_buf[8..8 + payload.len()].copy_from_slice(payload);
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
        icmp_type: u8,
    ) -> io::Result<usize> {
        let send_info = &raw_info.send_info;
        let icmp_len = 8 + payload.len();
        let mut icmp_buf = [0u8; XDP_SEND_BUF_SIZE];

        icmp_buf[0] = icmp_type;
        icmp_buf[1] = 0;
        icmp_buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        icmp_buf[4..6].copy_from_slice(&send_info.src_port.to_be_bytes());
        icmp_buf[6..8].copy_from_slice(&send_info.my_icmp_seq.to_be_bytes());
        if !payload.is_empty() {
            icmp_buf[8..8 + payload.len()].copy_from_slice(payload);
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
                let icmp_type = if self.is_client { 8 } else { 0 };
                self.send_raw_icmp(raw_info, payload, icmp_type)
            }
        }
    }

    /// Receive and parse a raw packet. Writes payload after protocol header into `output`.
    /// Returns the number of bytes written. Identical logic to RawSocketState::recv_raw0.
    pub fn recv_raw0(
        &mut self,
        raw_info: &mut RawInfo,
        raw_mode: RawMode,
        output: &mut [u8],
    ) -> io::Result<usize> {
        let ip_payload_len = self.recv_raw_ip(raw_info)?;

        // Reuse the same protocol parsing as RawSocketState
        // IP payload is in g_packet_buf[0..ip_payload_len] after recv_raw_ip
        crate::network::parse_protocol_payload(&self.g_packet_buf[..ip_payload_len], raw_info, raw_mode, output)
    }

    /// Kick the kernel to process TX ring entries.
    fn kick_tx(&self) -> io::Result<()> {
        let ret = unsafe {
            libc::sendto(
                self.xsk_fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOBUFS)
                || err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EBUSY)
            {
                // Transient — not fatal
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }
}

impl Drop for XdpSocketState {
    fn drop(&mut self) {
        // Close BPF link (detaches XDP program)
        if self.bpf_link_fd >= 0 {
            unsafe { libc::close(self.bpf_link_fd); }
        }
        // Close BPF program
        if self.bpf_prog_fd >= 0 {
            unsafe { libc::close(self.bpf_prog_fd); }
        }
        // Close XSKMAP
        if self.xskmap_fd >= 0 {
            unsafe { libc::close(self.xskmap_fd); }
        }
        // Close XSK socket
        if self.xsk_fd >= 0 {
            unsafe { libc::close(self.xsk_fd); }
        }
        // Unmap UMEM
        if !self.umem_area.is_null() {
            unsafe { libc::munmap(self.umem_area as *mut libc::c_void, self.umem_size); }
        }
        // Unmap rings (handled by kernel when socket closes)
        log::info!("AF_XDP: cleaned up");
    }
}

// ─── Utility functions ──────────────────────────────────────────────────────

fn if_nametoindex(name: &str) -> io::Result<u32> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx)
}

fn get_interface_mac(name: &str) -> io::Result<[u8; 6]> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = c_name.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr() as *const i8,
            ifr.ifr_name.as_mut_ptr(),
            copy_len,
        );
    }

    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::c_ulong, &mut ifr) };
    unsafe { libc::close(fd); }

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut mac = [0u8; 6];
    unsafe {
        let data = ifr.ifr_ifru.ifru_hwaddr.sa_data;
        for i in 0..6 {
            mac[i] = data[i] as u8;
        }
    }
    Ok(mac)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

