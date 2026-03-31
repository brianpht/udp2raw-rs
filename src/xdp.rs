//! AF_XDP (XSK) socket backend for zero-copy packet I/O.
//!
//! This module provides an optional high-performance transport that replaces
//! the `AF_INET/SOCK_RAW` and `AF_PACKET` syscall paths with AF_XDP ring
//! buffers. Wire-format bytes are untouched — only the kernel I/O path changes.
//!
//! Requires Linux ≥ 4.18, `CAP_NET_ADMIN` + `CAP_BPF` (or root), and a NIC
//! with XDP support (copy-mode works on all drivers).

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

// ─── AF_XDP kernel constants (linux/if_xdp.h) ──────────────────────────────

pub const AF_XDP: i32 = 44;
pub const SOL_XDP: i32 = 283;

// setsockopt / getsockopt options
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

// mmap page offsets for each ring
pub const XDP_PGOFF_RX_RING: u64 = 0;
pub const XDP_PGOFF_TX_RING: u64 = 0x80000000;
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

// ring flags
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

// defaults
pub const DEFAULT_FRAME_SIZE: u32 = 4096;
pub const DEFAULT_NUM_FRAMES: u32 = 4096;
pub const DEFAULT_RING_SIZE: u32 = 2048; // must be power-of-2

// Ethernet
const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;

// ─── Kernel ABI structs ─────────────────────────────────────────────────────
//
// These are NOT wire-format structs. They match linux/if_xdp.h for socket
// setup and do not affect packet bytes on the wire.

/// UMEM registration parameters for `setsockopt(SOL_XDP, XDP_UMEM_REG)`.
#[repr(C)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

/// Address structure for `bind()` on an AF_XDP socket.
#[repr(C)]
pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

/// Offsets for a single ring within the mmap'd region.
#[repr(C)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

/// Offsets for all four rings, returned by `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)`.
#[repr(C)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset, // fill ring
    pub cr: XdpRingOffset, // completion ring
}

/// Descriptor for RX/TX ring entries (packed to match kernel layout exactly).
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

// ─── Frame Allocator ────────────────────────────────────────────────────────

/// LIFO free-list of UMEM frame addresses.
///
/// LIFO order gives better cache locality — recently freed frames are
/// reused first, keeping the hot working set small.
struct FrameAllocator {
    free_list: Vec<u64>,
}

impl FrameAllocator {
    /// Create an allocator with `num_frames` frames of `frame_size` bytes each.
    /// Frame addresses are `0, frame_size, 2*frame_size, ...`.
    fn new(num_frames: u32, frame_size: u32) -> Self {
        let mut free_list = Vec::with_capacity(num_frames as usize);
        for i in 0..num_frames {
            free_list.push((i as u64) * (frame_size as u64));
        }
        Self { free_list }
    }

    /// Allocate one frame, returning its UMEM byte offset.
    fn alloc(&mut self) -> Option<u64> {
        self.free_list.pop()
    }

    /// Return a frame to the free-list.
    fn free(&mut self, addr: u64) {
        self.free_list.push(addr);
    }

    /// Number of frames currently available.
    #[allow(dead_code)]
    fn available(&self) -> usize {
        self.free_list.len()
    }
}

// ─── Ring Buffer ────────────────────────────────────────────────────────────

/// Mmap'd producer/consumer ring buffer shared between user space and kernel.
///
/// Each ring has atomic producer and consumer pointers. The index into the
/// descriptor array is `idx & mask` (power-of-2 wrapping).
///
/// Single-threaded use only (matching mio event-loop pattern). Cached indices
/// reduce atomic reads on the hot path.
///
/// **Invariant**: every `prod_reserve(n)` must be followed by exactly one
/// `prod_submit(n)` with the same `n` before calling `prod_reserve` again.
struct Ring {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    flags: *const AtomicU32,
    ring: *mut u8,
    mask: u32,
    #[allow(dead_code)]
    size: u32,
    map_addr: *mut u8,
    map_len: usize,
    /// Local write cursor (producer rings) or snapshot of kernel write cursor (consumer rings).
    cached_prod: u32,
    /// Snapshot of kernel read cursor (producer rings) or local read cursor (consumer rings).
    cached_cons: u32,
}

// Ring is Send: it is used from a single-threaded event loop.
// The raw pointers reference mmap'd memory owned by this struct.
unsafe impl Send for Ring {}

impl Ring {
    /// Map a ring from the XSK file descriptor.
    ///
    /// # Safety
    ///
    /// * `fd` must be a valid AF_XDP socket with rings configured via `setsockopt`.
    /// * `pgoff` must be one of the `XDP_PGOFF_*` / `XDP_UMEM_PGOFF_*` constants.
    /// * `ring_offset` must come from `getsockopt(XDP_MMAP_OFFSETS)`.
    /// * `entry_size` must match the ring type (8 for fill/comp, 16 for RX/TX).
    unsafe fn mmap(
        fd: RawFd,
        ring_size: u32,
        pgoff: u64,
        ring_offset: &XdpRingOffset,
        entry_size: usize,
    ) -> io::Result<Self> {
        let map_len = (ring_offset.desc as usize) + (ring_size as usize) * entry_size;

        let map_addr = libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff as libc::off_t,
        );
        if map_addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let base = map_addr as *mut u8;
        Ok(Ring {
            producer: base.add(ring_offset.producer as usize) as *mut AtomicU32,
            consumer: base.add(ring_offset.consumer as usize) as *mut AtomicU32,
            flags: base.add(ring_offset.flags as usize) as *const AtomicU32,
            ring: base.add(ring_offset.desc as usize),
            mask: ring_size - 1,
            size: ring_size,
            map_addr: base,
            map_len,
            cached_prod: 0,
            cached_cons: 0,
        })
    }

    // ── Producer operations (fill ring, TX ring) ────────────────────────────

    /// Reserve `n` slots in the producer ring for writing.
    /// Returns the starting index if enough space is available.
    fn prod_reserve(&mut self, n: u32) -> Option<u32> {
        self.cached_cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        let free = self
            .cached_cons
            .wrapping_add(self.size)
            .wrapping_sub(self.cached_prod);
        if free < n {
            return None;
        }
        let idx = self.cached_prod;
        self.cached_prod = self.cached_prod.wrapping_add(n);
        Some(idx)
    }

    /// Publish `n` written slots to the producer ring.
    /// The kernel can see these entries after this call.
    fn prod_submit(&self, n: u32) {
        unsafe {
            (*self.producer).fetch_add(n, Ordering::Release);
        }
    }

    // ── Consumer operations (completion ring, RX ring) ──────────────────────

    /// Check if there are `n` readable slots in the consumer ring.
    /// Returns the starting index if enough entries are available.
    fn cons_peek(&mut self, n: u32) -> Option<u32> {
        self.cached_prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let avail = self.cached_prod.wrapping_sub(self.cached_cons);
        if avail < n {
            return None;
        }
        Some(self.cached_cons)
    }

    /// Release `n` consumed slots from the consumer ring.
    /// The kernel can reuse these slots after this call.
    fn cons_release(&mut self, n: u32) {
        self.cached_cons = self.cached_cons.wrapping_add(n);
        unsafe {
            (*self.consumer).store(self.cached_cons, Ordering::Release);
        }
    }

    // ── Shared helpers ──────────────────────────────────────────────────────

    /// Check if the kernel has set the `XDP_RING_NEED_WAKEUP` flag.
    fn needs_wakeup(&self) -> bool {
        unsafe { (*self.flags).load(Ordering::Relaxed) & XDP_RING_NEED_WAKEUP != 0 }
    }

    /// Pointer to a `u64` entry at `idx` (fill/completion ring descriptor).
    ///
    /// # Safety
    /// `idx` must come from a successful `prod_reserve` or `cons_peek`.
    unsafe fn addr_at(&self, idx: u32) -> *mut u64 {
        let offset = ((idx & self.mask) as usize) * std::mem::size_of::<u64>();
        self.ring.add(offset) as *mut u64
    }

    /// Pointer to an `XdpDesc` entry at `idx` (RX/TX ring descriptor).
    ///
    /// # Safety
    /// `idx` must come from a successful `prod_reserve` or `cons_peek`.
    unsafe fn desc_at(&self, idx: u32) -> *mut XdpDesc {
        let offset = ((idx & self.mask) as usize) * std::mem::size_of::<XdpDesc>();
        self.ring.add(offset) as *mut XdpDesc
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        if !self.map_addr.is_null() && self.map_len > 0 {
            unsafe {
                libc::munmap(self.map_addr as *mut libc::c_void, self.map_len);
            }
        }
    }
}

// ─── XSK Socket ─────────────────────────────────────────────────────────────

/// AF_XDP socket with UMEM, 4 ring buffers, and frame allocator.
///
/// Provides zero-copy (or copy-mode) packet I/O through shared-memory ring
/// buffers. The socket fd is epoll-compatible for use with `mio::Poll`.
pub struct XskSocket {
    fd: RawFd,
    fill_ring: Ring,
    comp_ring: Ring,
    rx_ring: Ring,
    tx_ring: Ring,
    umem_buffer: *mut u8,
    umem_size: usize,
    frame_size: u32,
    frame_alloc: FrameAllocator,
    outstanding_tx: u32,
}

// XskSocket is Send: single-threaded event loop owns it exclusively.
unsafe impl Send for XskSocket {}

impl XskSocket {
    /// Create a new AF_XDP socket bound to the given NIC queue.
    ///
    /// Nine-step construction:
    /// 1. `mmap(MAP_ANONYMOUS)` → allocate UMEM buffer
    /// 2. `socket(AF_XDP, SOCK_RAW, 0)` → create XSK fd
    /// 3. `setsockopt(XDP_UMEM_REG)` → register UMEM
    /// 4. `setsockopt(XDP_{FILL,COMP,RX,TX}_RING)` → set ring sizes
    /// 5. `getsockopt(XDP_MMAP_OFFSETS)` → get ring mmap offsets
    /// 6. `mmap(MAP_SHARED, fd, pgoff)` × 4 → map all rings
    /// 7. Populate fill ring with initial frames (half capacity)
    /// 8. `bind(fd, sockaddr_xdp)` → bind to NIC queue
    /// 9. `setnonblocking(fd)` → for mio compatibility
    pub fn new(
        ifindex: u32,
        queue_id: u32,
        num_frames: u32,
        frame_size: u32,
        ring_size: u32,
        zero_copy: bool,
    ) -> io::Result<Self> {
        // Validate ring_size is power of 2
        if ring_size == 0 || (ring_size & (ring_size - 1)) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ring_size must be a power of 2",
            ));
        }

        let umem_size = (num_frames as usize) * (frame_size as usize);

        // ── Step 1: Allocate UMEM buffer (page-aligned anonymous mmap) ──
        let umem_buffer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem_buffer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let umem_buffer = umem_buffer as *mut u8;

        // ── Step 2: Create AF_XDP socket ──
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            unsafe {
                libc::munmap(umem_buffer as *mut libc::c_void, umem_size);
            }
            return Err(io::Error::last_os_error());
        }

        // From this point, use `cleanup_on_err` on failure paths.
        // Once we construct XskSocket, its Drop handles cleanup.
        let cleanup_on_err = |fd: RawFd, buf: *mut u8, sz: usize| {
            unsafe {
                libc::close(fd);
                libc::munmap(buf as *mut libc::c_void, sz);
            }
        };

        // ── Step 3: Register UMEM ──
        let umem_reg = XdpUmemReg {
            addr: umem_buffer as u64,
            len: umem_size as u64,
            chunk_size: frame_size,
            headroom: 0,
            flags: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            cleanup_on_err(fd, umem_buffer, umem_size);
            return Err(io::Error::last_os_error());
        }

        // ── Step 4: Set ring sizes ──
        for opt in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_XDP,
                    opt,
                    &ring_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                cleanup_on_err(fd, umem_buffer, umem_size);
                return Err(io::Error::last_os_error());
            }
        }

        // ── Step 5: Query ring mmap offsets ──
        let mut offsets: XdpMmapOffsets = unsafe { std::mem::zeroed() };
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            cleanup_on_err(fd, umem_buffer, umem_size);
            return Err(io::Error::last_os_error());
        }

        // ── Step 6: mmap all 4 rings ──
        //
        // Fill/Completion rings use u64 entries (8 bytes).
        // RX/TX rings use XdpDesc entries (16 bytes).
        let fill_ring = unsafe {
            Ring::mmap(
                fd,
                ring_size,
                XDP_UMEM_PGOFF_FILL_RING,
                &offsets.fr,
                std::mem::size_of::<u64>(),
            )
        }
        .map_err(|e| {
            cleanup_on_err(fd, umem_buffer, umem_size);
            e
        })?;

        let comp_ring = unsafe {
            Ring::mmap(
                fd,
                ring_size,
                XDP_UMEM_PGOFF_COMPLETION_RING,
                &offsets.cr,
                std::mem::size_of::<u64>(),
            )
        }
        .map_err(|e| {
            cleanup_on_err(fd, umem_buffer, umem_size);
            e
        })?;

        let rx_ring = unsafe {
            Ring::mmap(
                fd,
                ring_size,
                XDP_PGOFF_RX_RING,
                &offsets.rx,
                std::mem::size_of::<XdpDesc>(),
            )
        }
        .map_err(|e| {
            cleanup_on_err(fd, umem_buffer, umem_size);
            e
        })?;

        let tx_ring = unsafe {
            Ring::mmap(
                fd,
                ring_size,
                XDP_PGOFF_TX_RING,
                &offsets.tx,
                std::mem::size_of::<XdpDesc>(),
            )
        }
        .map_err(|e| {
            cleanup_on_err(fd, umem_buffer, umem_size);
            e
        })?;

        let frame_alloc = FrameAllocator::new(num_frames, frame_size);

        let mut socket = XskSocket {
            fd,
            fill_ring,
            comp_ring,
            rx_ring,
            tx_ring,
            umem_buffer,
            umem_size,
            frame_size,
            frame_alloc,
            outstanding_tx: 0,
        };

        // ── Step 7: Populate fill ring with initial frames (half capacity) ──
        let fill_count = ring_size / 2;
        socket.populate_fill_ring(fill_count)?;

        // ── Step 8: Bind to NIC queue ──
        let bind_flags = if zero_copy {
            XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP
        } else {
            XDP_COPY | XDP_USE_NEED_WAKEUP
        };
        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: bind_flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            // Drop handles cleanup of rings + UMEM
            return Err(io::Error::last_os_error());
        }

        // ── Step 9: Set non-blocking for mio compatibility ──
        crate::common::setnonblocking(fd)?;

        log::info!(
            "AF_XDP socket created: ifindex={}, queue={}, frames={}, frame_size={}, ring_size={}, zero_copy={}",
            ifindex, queue_id, num_frames, frame_size, ring_size, zero_copy,
        );

        Ok(socket)
    }

    /// Populate the fill ring with frames from the allocator.
    fn populate_fill_ring(&mut self, count: u32) -> io::Result<()> {
        let idx = self.fill_ring.prod_reserve(count).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "fill ring full during populate")
        })?;

        for i in 0..count {
            let addr = self.frame_alloc.alloc().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "no free frames for fill ring")
            })?;
            unsafe {
                *self.fill_ring.addr_at(idx.wrapping_add(i)) = addr;
            }
        }

        self.fill_ring.prod_submit(count);
        Ok(())
    }

    /// Return the pollable fd for mio registration.
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Read one L2 frame from the RX ring.
    ///
    /// Returns the full frame data including the Ethernet header.
    /// Returns `WouldBlock` if no frames are available.
    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        // Reclaim any completed TX frames first
        self.reclaim_completion();

        // Check RX ring for available frames
        let idx = self.rx_ring.cons_peek(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "no RX frames available")
        })?;

        // Read descriptor
        let desc = unsafe { *self.rx_ring.desc_at(idx) };
        let addr = desc.addr;
        let len = desc.len as usize;

        // Copy data from UMEM frame
        let data = unsafe {
            let ptr = self.umem_buffer.add(addr as usize);
            std::slice::from_raw_parts(ptr, len).to_vec()
        };

        // Release the RX slot
        self.rx_ring.cons_release(1);

        // Recycle the frame back to the fill ring
        self.recycle_frame(addr);

        Ok(data)
    }

    /// Write one L2 frame to the TX ring.
    ///
    /// `data` must include the Ethernet header (14 bytes).
    /// Returns `WouldBlock` if the TX ring is full.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        // Reclaim completed TX frames first
        self.reclaim_completion();

        // Allocate a UMEM frame
        let addr = self.frame_alloc.alloc().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no free TX frames")
        })?;

        if data.len() > self.frame_size as usize {
            self.frame_alloc.free(addr);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame too large for UMEM",
            ));
        }

        // Copy data into UMEM frame
        unsafe {
            let ptr = self.umem_buffer.add(addr as usize);
            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        }

        // Reserve TX ring slot
        let idx = match self.tx_ring.prod_reserve(1) {
            Some(idx) => idx,
            None => {
                self.frame_alloc.free(addr);
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "TX ring full"));
            }
        };

        // Write descriptor
        unsafe {
            let desc = self.tx_ring.desc_at(idx);
            (*desc).addr = addr;
            (*desc).len = data.len() as u32;
            (*desc).options = 0;
        }

        // Submit and kick kernel
        self.tx_ring.prod_submit(1);
        self.outstanding_tx += 1;
        self.kick_tx();

        Ok(())
    }

    /// Wake the kernel to process TX ring entries.
    ///
    /// Only issues a syscall if the kernel has set `XDP_RING_NEED_WAKEUP`.
    fn kick_tx(&self) {
        if self.tx_ring.needs_wakeup() {
            unsafe {
                libc::sendto(
                    self.fd,
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
            }
        }
    }

    /// Drain the completion ring, returning TX frames to the allocator.
    ///
    /// Called automatically before send/recv. Frames in the completion ring
    /// have been transmitted by the kernel and can be reused.
    fn reclaim_completion(&mut self) {
        if self.outstanding_tx == 0 {
            return;
        }
        while let Some(idx) = self.comp_ring.cons_peek(1) {
            let addr = unsafe { *self.comp_ring.addr_at(idx) };
            self.comp_ring.cons_release(1);
            self.frame_alloc.free(addr);
            self.outstanding_tx = self.outstanding_tx.saturating_sub(1);
        }
    }

    /// Return a consumed RX frame address to the fill ring.
    ///
    /// If the fill ring is full, the frame is returned to the free-list instead.
    fn recycle_frame(&mut self, addr: u64) {
        if let Some(idx) = self.fill_ring.prod_reserve(1) {
            unsafe {
                *self.fill_ring.addr_at(idx) = addr;
            }
            self.fill_ring.prod_submit(1);

            // Kick fill ring if kernel needs wakeup (so it can refill)
            if self.fill_ring.needs_wakeup() {
                unsafe {
                    libc::recvfrom(
                        self.fd,
                        std::ptr::null_mut(),
                        0,
                        libc::MSG_DONTWAIT,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }
            }
        } else {
            // Fill ring full — return frame to allocator as fallback
            self.frame_alloc.free(addr);
        }
    }
}

impl Drop for XskSocket {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
        if !self.umem_buffer.is_null() && self.umem_size > 0 {
            unsafe {
                libc::munmap(self.umem_buffer as *mut libc::c_void, self.umem_size);
            }
        }
        // Ring Drop impls handle their own munmap
    }
}

// ─── XDP State (Aya + XSK + Ethernet) ──────────────────────────────────────

/// Top-level AF_XDP state: eBPF program + XSK socket + Ethernet info.
///
/// Kept alive for the duration of the event loop. Dropping this struct
/// detaches the XDP program from the NIC and closes the XSK socket.
pub struct XdpState {
    pub xsk: XskSocket,
    /// Held to maintain the XDP program attachment to the NIC.
    _ebpf: aya::Ebpf,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

impl XdpState {
    /// Initialize AF_XDP: load eBPF program, attach to NIC, create XSK socket.
    ///
    /// # Arguments
    /// * `ebpf_bytes` — compiled eBPF bytecode (from `include_bytes!` in build)
    /// * `ifname` — network interface name (e.g. `"eth0"`)
    /// * `queue_id` — NIC RX queue to bind
    /// * `zero_copy` — use `XDP_ZEROCOPY` (requires driver support)
    /// * `dst_mac` — destination MAC address for outgoing Ethernet frames
    pub fn init(
        ebpf_bytes: &[u8],
        ifname: &str,
        queue_id: u32,
        zero_copy: bool,
        dst_mac: [u8; 6],
    ) -> io::Result<Self> {
        use aya::maps::XskMap;
        use aya::programs::{Xdp, XdpFlags};

        // Resolve interface
        let ifindex = ifname_to_index(ifname)?;
        let src_mac = get_interface_mac(ifname)?;

        log::info!(
            "AF_XDP init: ifname={}, ifindex={}, queue={}, \
             src_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, \
             dst_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ifname,
            ifindex,
            queue_id,
            src_mac[0],
            src_mac[1],
            src_mac[2],
            src_mac[3],
            src_mac[4],
            src_mac[5],
            dst_mac[0],
            dst_mac[1],
            dst_mac[2],
            dst_mac[3],
            dst_mac[4],
            dst_mac[5],
        );

        // Create XSK socket
        let xsk = XskSocket::new(
            ifindex,
            queue_id,
            DEFAULT_NUM_FRAMES,
            DEFAULT_FRAME_SIZE,
            DEFAULT_RING_SIZE,
            zero_copy,
        )?;

        // Load eBPF program
        let mut ebpf = aya::Ebpf::load(ebpf_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("eBPF load failed: {}", e),
            )
        })?;

        // Attach XDP program to interface
        let program: &mut Xdp = ebpf
            .program_mut("udp2raw_xdp")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "XDP program 'udp2raw_xdp' not found in eBPF object",
                )
            })?
            .try_into()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("not an XDP program: {}", e),
                )
            })?;

        program.load().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("XDP program load failed: {}", e),
            )
        })?;

        program
            .attach(ifname, XdpFlags::default())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("XDP attach to {} failed: {}", ifname, e),
                )
            })?;

        log::info!("XDP program attached to {}", ifname);

        // Register XSK socket in XSKMAP
        {
            let xsk_map_ref = ebpf.map_mut("XSKS_MAP").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "XSKS_MAP not found in eBPF object",
                )
            })?;

            let mut xsk_map: XskMap<_> =
                XskMap::try_from(xsk_map_ref).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("XSKS_MAP type error: {}", e),
                    )
                })?;

            let borrowed_fd =
                unsafe { std::os::unix::io::BorrowedFd::borrow_raw(xsk.fd()) };

            xsk_map.set(queue_id, borrowed_fd, 0).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("XSKMAP set failed: {}", e),
                )
            })?;
        }

        log::info!("XSK socket registered in XSKMAP at queue {}", queue_id);

        Ok(XdpState {
            xsk,
            _ebpf: ebpf,
            src_mac,
            dst_mac,
        })
    }

    /// Send an IP packet by prepending a 14-byte Ethernet header.
    ///
    /// The IP packet bytes (header + payload) are identical to what
    /// `send_raw_ip()` builds — only the L2 framing is added here.
    ///
    /// ```text
    /// [dst_mac:6][src_mac:6][ethertype:2][ip_packet...]
    /// ```
    pub fn send_ip_packet(&mut self, ip_packet: &[u8], ethertype: u16) -> io::Result<()> {
        let frame_len = ETH_HLEN + ip_packet.len();
        if frame_len > self.xsk.frame_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IP packet + Ethernet header exceeds frame size",
            ));
        }

        // Build L2 frame: [dst_mac:6][src_mac:6][ethertype:2][ip_packet]
        let mut frame = vec![0u8; frame_len];
        frame[0..6].copy_from_slice(&self.dst_mac);
        frame[6..12].copy_from_slice(&self.src_mac);
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[ETH_HLEN..].copy_from_slice(ip_packet);

        self.xsk.send(&frame)
    }

    /// Receive an IP packet by reading an L2 frame and stripping the Ethernet header.
    ///
    /// Returns `(ethertype, ip_data)` where `ip_data` starts at the IP header.
    pub fn recv_ip_packet(&mut self) -> io::Result<(u16, Vec<u8>)> {
        let frame = self.xsk.recv()?;

        if frame.len() < ETH_HLEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short for Ethernet header",
            ));
        }

        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let ip_data = frame[ETH_HLEN..].to_vec();

        Ok((ethertype, ip_data))
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Resolve network interface name to ifindex via `libc::if_nametoindex`.
pub fn ifname_to_index(name: &str) -> io::Result<u32> {
    let c_name = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
    })?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface '{}' not found", name),
        ))
    } else {
        Ok(idx)
    }
}

/// Get the MAC address of a network interface via `ioctl(SIOCGIFHWADDR)`.
pub fn get_interface_mac(name: &str) -> io::Result<[u8; 6]> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }

    // Copy interface name into ifreq (NUL-terminated by zeroed init)
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );
    }

    let ret = unsafe {
        libc::ioctl(fd, libc::SIOCGIFHWADDR as libc::c_ulong, &mut ifr)
    };
    unsafe {
        libc::close(fd);
    }

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // Extract MAC from ifr_ifru.ifru_hwaddr.sa_data[0..6]
    let mut mac = [0u8; 6];
    unsafe {
        let sa_data = ifr.ifr_ifru.ifru_hwaddr.sa_data;
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = sa_data[i] as u8;
        }
    }

    Ok(mac)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_allocator_roundtrip() {
        let mut alloc = FrameAllocator::new(8, 4096);
        assert_eq!(alloc.available(), 8);

        // Allocate all frames
        let mut addrs = Vec::new();
        for _ in 0..8 {
            addrs.push(alloc.alloc().unwrap());
        }
        assert_eq!(alloc.available(), 0);
        assert!(alloc.alloc().is_none());

        // Verify addresses are distinct and frame-aligned
        let mut sorted = addrs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 8);
        for addr in &sorted {
            assert_eq!(addr % 4096, 0, "frame addr {} not aligned", addr);
        }

        // Free all and re-allocate (LIFO order)
        for addr in &addrs {
            alloc.free(*addr);
        }
        assert_eq!(alloc.available(), 8);

        let a1 = alloc.alloc().unwrap();
        let a2 = alloc.alloc().unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn frame_allocator_different_sizes() {
        let mut alloc = FrameAllocator::new(4, 2048);
        assert_eq!(alloc.alloc(), Some(3 * 2048));
        assert_eq!(alloc.alloc(), Some(2 * 2048));
        assert_eq!(alloc.alloc(), Some(1 * 2048));
        assert_eq!(alloc.alloc(), Some(0));
        assert_eq!(alloc.alloc(), None);
    }

    #[test]
    fn xdp_constants_match_kernel() {
        assert_eq!(AF_XDP, 44);
        assert_eq!(SOL_XDP, 283);

        // XdpDesc is packed: u64 + u32 + u32 = 16 bytes exactly
        assert_eq!(std::mem::size_of::<XdpDesc>(), 16);

        // SockaddrXdp: u16+u16+u32+u32+u32 = 16 bytes, align 4
        assert_eq!(std::mem::size_of::<SockaddrXdp>(), 16);

        // XdpRingOffset: 4 × u64 = 32 bytes
        assert_eq!(std::mem::size_of::<XdpRingOffset>(), 32);

        // XdpMmapOffsets: 4 × XdpRingOffset = 128 bytes
        assert_eq!(std::mem::size_of::<XdpMmapOffsets>(), 128);
    }

    #[test]
    fn ethernet_header_build() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ethertype: u16 = ETH_P_IP;
        let ip_data = [0x45, 0x00, 0x00, 0x28]; // minimal IP header start

        let mut frame = vec![0u8; ETH_HLEN + ip_data.len()];
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&src_mac);
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame[ETH_HLEN..].copy_from_slice(&ip_data);

        // Verify Ethernet header layout: [dst:6][src:6][type:2]
        assert_eq!(&frame[0..6], &dst_mac);
        assert_eq!(&frame[6..12], &src_mac);
        assert_eq!(&frame[12..14], &[0x08, 0x00]);
        assert_eq!(&frame[ETH_HLEN..], &ip_data);
        assert_eq!(frame.len(), 18);
    }

    #[test]
    fn ethernet_header_strip() {
        let frame = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // ethertype (IPv4)
            0x45, 0x00, 0x00, 0x14, // IP header start
        ];

        assert!(frame.len() >= ETH_HLEN);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let ip_data = &frame[ETH_HLEN..];

        assert_eq!(ethertype, ETH_P_IP);
        assert_eq!(ip_data, &[0x45, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn xdp_desc_packed_layout() {
        // Verify XdpDesc is truly packed (no internal padding)
        let desc = XdpDesc {
            addr: 0x1234_5678_9ABC_DEF0,
            len: 0xDEAD_BEEF,
            options: 0,
        };
        let ptr = &desc as *const _ as *const u8;
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<XdpDesc>()) };

        // addr at offset 0 (little-endian on x86)
        let addr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(addr, 0x1234_5678_9ABC_DEF0);

        // len at offset 8
        let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(len, 0xDEAD_BEEF);

        // options at offset 12
        let options = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        assert_eq!(options, 0);
    }
}

