/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! VirtIO Network Driver (MMIO transport — works on both x86_64 QEMU and AArch64 virt)
//!
//! Implements the VirtIO 1.x MMIO device specification for the network device
//! type (device ID 1).  The driver supports:
//!
//! - Receive (RX) and transmit (TX) virtqueues
//! - MAC address negotiation via device config space
//! - Capability-based send/receive access control
//! - Polled-mode I/O (interrupt-driven RX can be layered on top)
//! - Zero-copy path for kernel-internal packet injection
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────┐
//!  │  VirtioNet (global singleton behind spin::Mutex)              │
//!  │   ├── MMIO base address (mapped at init)                      │
//!  │   ├── rx_queue: VirtQueue  (index 0)                          │
//!  │   │    └── descriptor ring, available ring, used ring         │
//!  │   ├── tx_queue: VirtQueue  (index 1)                          │
//!  │   └── mac: [u8; 6]                                            │
//!  └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # MMIO Register Map (VirtIO 1.x)
//!
//! | Offset | Size | Name                |
//! |--------|------|---------------------|
//! | 0x000  | 4    | MagicValue          |
//! | 0x004  | 4    | Version             |
//! | 0x008  | 4    | DeviceID            |
//! | 0x00C  | 4    | VendorID            |
//! | 0x010  | 4    | DeviceFeatures      |
//! | 0x014  | 4    | DeviceFeaturesSel   |
//! | 0x020  | 4    | DriverFeatures      |
//! | 0x024  | 4    | DriverFeaturesSel   |
//! | 0x030  | 4    | QueueSel            |
//! | 0x034  | 4    | QueueNumMax         |
//! | 0x038  | 4    | QueueNum            |
//! | 0x044  | 4    | QueueReady          |
//! | 0x050  | 4    | QueueNotify         |
//! | 0x060  | 4    | InterruptStatus     |
//! | 0x064  | 4    | InterruptACK        |
//! | 0x070  | 4    | Status              |
//! | 0x080  | 8    | QueueDescLow/High   |
//! | 0x090  | 8    | QueueDriverLow/High |
//! | 0x0A0  | 8    | QueueDeviceLow/High |
//! | 0x100  | -    | Config space        |

#![allow(dead_code)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ============================================================================
// MMIO register offsets
// ============================================================================

const VIRTIO_MMIO_MAGIC_VALUE: usize = 0x000;
const VIRTIO_MMIO_VERSION: usize = 0x004;
const VIRTIO_MMIO_DEVICE_ID: usize = 0x008;
const VIRTIO_MMIO_VENDOR_ID: usize = 0x00C;
const VIRTIO_MMIO_DEVICE_FEATURES: usize = 0x010;
const VIRTIO_MMIO_DEVICE_FEAT_SEL: usize = 0x014;
const VIRTIO_MMIO_DRIVER_FEATURES: usize = 0x020;
const VIRTIO_MMIO_DRIVER_FEAT_SEL: usize = 0x024;
const VIRTIO_MMIO_QUEUE_SEL: usize = 0x030;
const VIRTIO_MMIO_QUEUE_NUM_MAX: usize = 0x034;
const VIRTIO_MMIO_QUEUE_NUM: usize = 0x038;
const VIRTIO_MMIO_QUEUE_READY: usize = 0x044;
const VIRTIO_MMIO_QUEUE_NOTIFY: usize = 0x050;
const VIRTIO_MMIO_INT_STATUS: usize = 0x060;
const VIRTIO_MMIO_INT_ACK: usize = 0x064;
const VIRTIO_MMIO_STATUS: usize = 0x070;
const VIRTIO_MMIO_QUEUE_DESC_LOW: usize = 0x080;
const VIRTIO_MMIO_QUEUE_DESC_HIGH: usize = 0x084;
const VIRTIO_MMIO_QUEUE_DRIVER_LOW: usize = 0x090;
const VIRTIO_MMIO_QUEUE_DRIVER_HIGH: usize = 0x094;
const VIRTIO_MMIO_QUEUE_DEVICE_LOW: usize = 0x0A0;
const VIRTIO_MMIO_QUEUE_DEVICE_HIGH: usize = 0x0A4;
const VIRTIO_MMIO_CONFIG: usize = 0x100;

// VirtIO status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
const VIRTIO_STATUS_DRIVER: u32 = 2;
const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u32 = 64;
const VIRTIO_STATUS_FAILED: u32 = 128;

// VirtIO magic
const VIRTIO_MAGIC: u32 = 0x74726976; // "virt"
const VIRTIO_NET_DEVICE_ID: u32 = 1;

// VirtIO-net feature bits
const VIRTIO_NET_F_MAC: u64 = 1u64 << 5;
const VIRTIO_NET_F_STATUS: u64 = 1u64 << 16;
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1u64 << 15;
const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;
const VIRTIO_NET_S_LINK_UP: u16 = 1;

// Queue indices
const VIRTIO_NET_RX_QUEUE: u32 = 0;
const VIRTIO_NET_TX_QUEUE: u32 = 1;

// Queue parameters
const QUEUE_SIZE: usize = 64; // must be power of two
const RX_BUF_SIZE: usize = 1536; // max Ethernet frame + VirtIO header
const TX_BUF_SIZE: usize = 1536;

// ============================================================================
// VirtIO split virtqueue data structures
// ============================================================================

/// VirtIO descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// A single VirtIO virtqueue descriptor.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// The available (driver→device) ring.
#[repr(C, align(2))]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

impl VirtqAvail {
    fn new() -> Self {
        VirtqAvail {
            flags: 0,
            idx: 0,
            ring: [0u16; QUEUE_SIZE],
            used_event: 0,
        }
    }
}

/// One used-ring element.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// The used (device→driver) ring.
#[repr(C, align(4))]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

impl VirtqUsed {
    fn new() -> Self {
        VirtqUsed {
            flags: 0,
            idx: 0,
            ring: [VirtqUsedElem::default(); QUEUE_SIZE],
            avail_event: 0,
        }
    }
}

// ============================================================================
// VirtIO-net packet header (no merge, no csum offload for MVP)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

const VIRTIO_NET_HDR_SIZE: usize = core::mem::size_of::<VirtioNetHdr>();

// ============================================================================
// VirtQueue abstraction
// ============================================================================

/// A single split virtqueue plus its associated DMA buffers.
///
/// All rings and buffers are allocated from the kernel heap.  In a production
/// implementation they would be placed in a non-cacheable MMIO-visible region;
/// here we use explicit hardware fences before MMIO notify / after used-ring
/// observation so descriptor and ring writes become visible to the device on
/// weakly ordered architectures such as AArch64.
pub struct VirtQueue {
    desc: Box<[VirtqDesc; QUEUE_SIZE]>,
    avail: Box<VirtqAvail>,
    used_idx_shadow: u16,
    used: Box<VirtqUsed>,
    /// Packet buffers — one per descriptor slot.
    buffers: Vec<Vec<u8>>,
    /// MMIO base address for this queue's NOTIFY register.
    mmio_base: usize,
    queue_index: u32,
    /// Free descriptor stack head.
    free_head: u16,
    free_count: u16,
    /// Next chain index in free list.
    next_free: [u16; QUEUE_SIZE],
}

impl VirtQueue {
    fn new(mmio_base: usize, queue_index: u32, buf_size: usize) -> Self {
        let mut desc = Box::new([VirtqDesc::default(); QUEUE_SIZE]);
        let mut buffers = Vec::with_capacity(QUEUE_SIZE);
        let mut next_free = [0u16; QUEUE_SIZE];

        for i in 0..QUEUE_SIZE {
            let buf = alloc::vec![0u8; buf_size];
            let buf_addr = buf.as_ptr() as u64;
            desc[i] = VirtqDesc {
                addr: buf_addr,
                len: buf_size as u32,
                flags: 0,
                next: (i + 1) as u16,
            };
            buffers.push(buf);
            next_free[i] = (i + 1) as u16;
        }
        next_free[QUEUE_SIZE - 1] = QUEUE_SIZE as u16;

        VirtQueue {
            desc,
            avail: Box::new(VirtqAvail::new()),
            used_idx_shadow: 0,
            used: Box::new(VirtqUsed::new()),
            buffers,
            mmio_base,
            queue_index,
            free_head: 0,
            free_count: QUEUE_SIZE as u16,
            next_free,
        }
    }

    /// Allocate a free descriptor index, or `None` if the queue is full.
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.free_count == 0 {
            return None;
        }
        let idx = self.free_head;
        self.free_head = self.next_free[idx as usize];
        self.free_count -= 1;
        Some(idx)
    }

    /// Return a descriptor to the free list.
    fn free_desc(&mut self, idx: u16) {
        self.next_free[idx as usize] = self.free_head;
        self.free_head = idx;
        self.free_count += 1;
    }

    #[inline]
    fn desc_addr(&self) -> u64 {
        self.desc.as_ptr() as u64
    }

    #[inline]
    fn avail_addr(&self) -> u64 {
        (&*self.avail) as *const VirtqAvail as u64
    }

    #[inline]
    fn used_addr(&self) -> u64 {
        (&*self.used) as *const VirtqUsed as u64
    }

    /// Copy `data` into the descriptor's buffer and add it to the available ring.
    fn enqueue_tx(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() + VIRTIO_NET_HDR_SIZE > TX_BUF_SIZE {
            return Err("virtio_net: TX packet too large");
        }
        let desc_idx = self.alloc_desc().ok_or("virtio_net: TX queue full")?;

        // Build VirtIO net header (no offloads)
        let hdr = VirtioNetHdr::default();
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(&hdr as *const _ as *const u8, VIRTIO_NET_HDR_SIZE)
        };

        let buf = &mut self.buffers[desc_idx as usize];
        buf[..VIRTIO_NET_HDR_SIZE].copy_from_slice(hdr_bytes);
        buf[VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + data.len()].copy_from_slice(data);

        let total_len = VIRTIO_NET_HDR_SIZE + data.len();
        self.desc[desc_idx as usize].addr = buf.as_ptr() as u64;
        self.desc[desc_idx as usize].len = total_len as u32;
        self.desc[desc_idx as usize].flags = 0; // read-only for device
        self.desc[desc_idx as usize].next = 0;

        // Publish to available ring
        let avail_idx = unsafe { read_volatile(&self.avail.idx as *const u16) };
        let avail_slot = (avail_idx as usize) % QUEUE_SIZE;
        unsafe {
            write_volatile(&mut self.avail.ring[avail_slot] as *mut u16, desc_idx);
        }
        fence(Ordering::Release);
        unsafe {
            write_volatile(&mut self.avail.idx as *mut u16, avail_idx.wrapping_add(1));
        }
        fence(Ordering::SeqCst);

        // Notify device
        mmio_write32(self.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY, self.queue_index);
        Ok(())
    }

    /// Fill the available ring with write-only descriptors for the device to put RX frames into.
    fn replenish_rx(&mut self) {
        while self.free_count > 0 {
            let desc_idx = match self.alloc_desc() {
                Some(i) => i,
                None => break,
            };
            let buf_addr = self.buffers[desc_idx as usize].as_ptr() as u64;
            self.desc[desc_idx as usize].addr = buf_addr;
            self.desc[desc_idx as usize].len = RX_BUF_SIZE as u32;
            self.desc[desc_idx as usize].flags = VIRTQ_DESC_F_WRITE; // device writes
            self.desc[desc_idx as usize].next = 0;

            let avail_idx = unsafe { read_volatile(&self.avail.idx as *const u16) };
            let avail_slot = (avail_idx as usize) % QUEUE_SIZE;
            unsafe {
                write_volatile(&mut self.avail.ring[avail_slot] as *mut u16, desc_idx);
            }
            fence(Ordering::Release);
            unsafe {
                write_volatile(&mut self.avail.idx as *mut u16, avail_idx.wrapping_add(1));
            }
        }
        fence(Ordering::SeqCst);
        mmio_write32(self.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY, self.queue_index);
    }

    /// Poll the used ring and return completed descriptor indices.
    fn poll_used(&mut self, out: &mut Vec<(u16, u32)>) {
        let used_idx = unsafe { read_volatile(&self.used.idx as *const u16) };
        fence(Ordering::Acquire);
        while self.used_idx_shadow != used_idx {
            let slot = (self.used_idx_shadow as usize) % QUEUE_SIZE;
            let elem =
                unsafe { read_volatile(&self.used.ring[slot] as *const VirtqUsedElem) };
            out.push((elem.id as u16, elem.len));
            self.used_idx_shadow = self.used_idx_shadow.wrapping_add(1);
        }
    }
}

// ============================================================================
// MMIO helpers
// ============================================================================

#[inline(always)]
fn mmio_read32(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn mmio_read8(addr: usize) -> u8 {
    unsafe { read_volatile(addr as *const u8) }
}

#[inline(always)]
fn mmio_write32(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

#[inline(always)]
fn mmio_read_device_features64(base: usize) -> u64 {
    mmio_write32(base + VIRTIO_MMIO_DEVICE_FEAT_SEL, 0);
    let low = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES) as u64;
    mmio_write32(base + VIRTIO_MMIO_DEVICE_FEAT_SEL, 1);
    let high = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES) as u64;
    (high << 32) | low
}

#[inline(always)]
fn mmio_write_driver_features64(base: usize, features: u64) {
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEAT_SEL, 0);
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES, features as u32);
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEAT_SEL, 1);
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES, (features >> 32) as u32);
}

// ============================================================================
// VirtioNet global driver
// ============================================================================

pub struct VirtioNet {
    mmio_base: usize,
    rx: Option<VirtQueue>,
    tx: Option<VirtQueue>,
    pub mac: [u8; 6],
    negotiated_features: u64,
    initialized: bool,
    /// Internal buffer for frames drained from the RX virtqueue.
    /// Used by `has_recv()` / `recv()` so callers don't need a callback.
    pending_rx: Vec<Vec<u8>>,
}

impl VirtioNet {
    const fn uninit() -> Self {
        // SAFETY: zeroed-out placeholder; replaced by `init()` before use.
        VirtioNet {
            mmio_base: 0,
            rx: None,
            tx: None,
            mac: [0u8; 6],
            negotiated_features: 0,
            initialized: false,
            pending_rx: Vec::new(),
        }
    }

    fn reset(&mut self) {
        *self = VirtioNet::uninit();
    }

    /// Drain any completed RX descriptors from the virtqueue into `pending_rx`.
    fn drain_rx(&mut self) {
        if !self.initialized {
            return;
        }
        let mut frames: Vec<Vec<u8>> = Vec::new();
        if let Some(rx) = self.rx.as_mut() {
            let mut completed: Vec<(u16, u32)> = Vec::new();
            rx.poll_used(&mut completed);
            for (desc_idx, len) in &completed {
                let idx = *desc_idx as usize;
                let total = *len as usize;
                if total > VIRTIO_NET_HDR_SIZE && idx < QUEUE_SIZE {
                    let frame_len = total - VIRTIO_NET_HDR_SIZE;
                    if frame_len <= RX_BUF_SIZE - VIRTIO_NET_HDR_SIZE {
                        frames.push(
                            rx.buffers[idx]
                                [VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + frame_len]
                                .to_vec(),
                        );
                    }
                }
                rx.free_desc(*desc_idx);
            }
            if !completed.is_empty() {
                rx.replenish_rx();
            }
        }
        self.pending_rx.extend(frames);
    }
}

static VIRTIO_NET: Mutex<VirtioNet> = Mutex::new(VirtioNet::uninit());

// ============================================================================
// Public API
// ============================================================================

/// Probe and initialise the VirtIO-net MMIO device at `base`.
///
/// Returns `Ok(mac)` on success. Typical QEMU base address is `0x0A000000`
/// for the first virtio-mmio device; see the QEMU `-device` arguments.
pub fn init(base: usize) -> Result<[u8; 6], &'static str> {
    let magic = mmio_read32(base + VIRTIO_MMIO_MAGIC_VALUE);
    if magic != VIRTIO_MAGIC {
        return Err("virtio_net: bad magic — not a VirtIO MMIO device");
    }
    let version = mmio_read32(base + VIRTIO_MMIO_VERSION);
    if version != 2 {
        return Err("virtio_net: only VirtIO 1.x (version=2) supported");
    }
    let device_id = mmio_read32(base + VIRTIO_MMIO_DEVICE_ID);
    if device_id != VIRTIO_NET_DEVICE_ID {
        return Err("virtio_net: device is not a network device (device_id != 1)");
    }

    // --- Initialization sequence (VirtIO 1.x §3.1) ---

    // 1. Reset
    mmio_write32(base + VIRTIO_MMIO_STATUS, 0);
    fence(Ordering::SeqCst);

    // 2. Acknowledge
    mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

    // 3. Driver
    mmio_write32(
        base + VIRTIO_MMIO_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );

    // 4. Read device features, negotiate
    let device_features = mmio_read_device_features64(base);
    if (device_features & VIRTIO_F_VERSION_1) == 0 {
        mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return Err("virtio_net: modern device missing VERSION_1 feature");
    }

    // Negotiate: VERSION_1 is mandatory for modern virtio-mmio. MAC and link
    // status are optional readiness/reporting features.
    let driver_features =
        device_features & (VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    mmio_write_driver_features64(base, driver_features);

    // 5. Features OK
    let status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK;
    mmio_write32(base + VIRTIO_MMIO_STATUS, status);
    fence(Ordering::SeqCst);

    // Confirm features were accepted
    let confirmed = mmio_read32(base + VIRTIO_MMIO_STATUS);
    if (confirmed & VIRTIO_STATUS_FEATURES_OK) == 0 {
        mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return Err("virtio_net: device rejected features");
    }

    let mut rx = VirtQueue::new(base, VIRTIO_NET_RX_QUEUE, RX_BUF_SIZE);
    let tx = VirtQueue::new(base, VIRTIO_NET_TX_QUEUE, TX_BUF_SIZE);

    // 6. Setup virtqueues
    setup_queue(base, &rx)?;
    setup_queue(base, &tx)?;

    // Read MAC from config space (offset 0x100, 6 bytes)
    let mut mac = [0u8; 6];
    if (driver_features & VIRTIO_NET_F_MAC) != 0 {
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = mmio_read8(base + VIRTIO_MMIO_CONFIG + i);
        }
    }

    // 7. Driver OK
    mmio_write32(base + VIRTIO_MMIO_STATUS, status | VIRTIO_STATUS_DRIVER_OK);
    fence(Ordering::SeqCst);

    // Pre-fill RX queue with buffers after the device is live.
    rx.replenish_rx();

    let mut dev = VIRTIO_NET.lock();
    dev.mmio_base = base;
    dev.rx = Some(rx);
    dev.tx = Some(tx);
    dev.mac = mac;
    dev.negotiated_features = driver_features;
    dev.initialized = true;

    Ok(mac)
}

/// Transmit a raw Ethernet frame.
///
/// The caller must hold a `CapabilityType::NetworkSend` capability for the
/// owning process.  (Capability check performed by `net_reactor` before
/// reaching this function.)
pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    let mut dev = VIRTIO_NET.lock();
    if !dev.initialized {
        return Err("virtio_net: not initialized");
    }
    let tx = dev.tx.as_mut().ok_or("virtio_net: TX queue missing")?;
    let mut completed = Vec::new();
    tx.poll_used(&mut completed);
    for (desc_idx, _) in completed {
        tx.free_desc(desc_idx);
    }
    tx.enqueue_tx(frame)
}

/// Poll the RX queue and pass received frames to the callback.
///
/// Returns the number of frames delivered.  The callback receives the raw
/// Ethernet frame bytes (without the VirtIO-net header).
pub fn poll_rx<F: FnMut(&[u8])>(mut cb: F) -> usize {
    let mut frames = Vec::new();
    {
        let mut dev = VIRTIO_NET.lock();
        if !dev.initialized {
            return 0;
        }
        let Some(rx) = dev.rx.as_mut() else {
            return 0;
        };

        let mut completed: Vec<(u16, u32)> = Vec::new();
        rx.poll_used(&mut completed);

        for (desc_idx, len) in &completed {
            let idx = *desc_idx as usize;
            let total = *len as usize;
            if total > VIRTIO_NET_HDR_SIZE && idx < QUEUE_SIZE {
                let frame_len = total - VIRTIO_NET_HDR_SIZE;
                if frame_len <= RX_BUF_SIZE - VIRTIO_NET_HDR_SIZE {
                    frames.push(
                        rx.buffers[idx]
                            [VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + frame_len]
                            .to_vec(),
                    );
                }
            }
            rx.free_desc(*desc_idx);
        }

        rx.replenish_rx();
    }

    for frame in &frames {
        cb(frame);
    }
    frames.len()
}

/// Returns `true` if a VirtIO-net device has been successfully initialised.
pub fn is_available() -> bool {
    VIRTIO_NET.lock().initialized
}

/// Returns the negotiated MAC address, or all-zeros if not initialised.
pub fn mac_address() -> [u8; 6] {
    VIRTIO_NET.lock().mac
}

/// Returns `true` if at least one received Ethernet frame is available.
///
/// Drains the RX virtqueue into an internal buffer on each call so that
/// frames are not lost between a `has_recv` check and the subsequent `recv`.
pub fn has_recv() -> bool {
    let mut dev = VIRTIO_NET.lock();
    dev.drain_rx();
    !dev.pending_rx.is_empty()
}

/// Copy the oldest received Ethernet frame into `buf`.
///
/// Returns the number of bytes written (0 if no frame is available or `buf`
/// is too small).  The raw Ethernet payload is written **without** the
/// VirtIO-net header.
pub fn recv(buf: &mut [u8]) -> usize {
    let mut dev = VIRTIO_NET.lock();
    if dev.pending_rx.is_empty() {
        dev.drain_rx();
    }
    if let Some(frame) = dev.pending_rx.first() {
        let n = frame.len().min(buf.len());
        buf[..n].copy_from_slice(&frame[..n]);
        let _ = dev.pending_rx.remove(0);
        n
    } else {
        0
    }
}

pub fn is_link_up() -> bool {
    let dev = VIRTIO_NET.lock();
    if !dev.initialized {
        return false;
    }
    if (dev.negotiated_features & VIRTIO_NET_F_STATUS) == 0 {
        return true;
    }
    let status =
        u16::from_le_bytes([mmio_read8(dev.mmio_base + VIRTIO_MMIO_CONFIG + 6), mmio_read8(dev.mmio_base + VIRTIO_MMIO_CONFIG + 7)]);
    (status & VIRTIO_NET_S_LINK_UP) != 0
}

// ============================================================================
// Internal: queue setup
// ============================================================================

fn setup_queue(base: usize, queue: &VirtQueue) -> Result<(), &'static str> {
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, queue.queue_index);
    let max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if max_size == 0 {
        return Err("virtio_net: queue not available");
    }
    let size = (QUEUE_SIZE as u32).min(max_size);
    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, size);
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DESC_LOW,
        queue.desc_addr() as u32,
    );
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DESC_HIGH,
        (queue.desc_addr() >> 32) as u32,
    );
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DRIVER_LOW,
        queue.avail_addr() as u32,
    );
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DRIVER_HIGH,
        (queue.avail_addr() >> 32) as u32,
    );
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DEVICE_LOW,
        queue.used_addr() as u32,
    );
    mmio_write32(
        base + VIRTIO_MMIO_QUEUE_DEVICE_HIGH,
        (queue.used_addr() >> 32) as u32,
    );
    mmio_write32(base + VIRTIO_MMIO_QUEUE_READY, 1);
    Ok(())
}

// ============================================================================
// Capability-gated wrappers (used by net_reactor)
// ============================================================================

use crate::capability::{CapabilityType, Rights};
use crate::ipc::ProcessId;

/// Transmit `frame` on behalf of `owner`, checking that they hold a
/// `Channel` capability (the closest existing type to network I/O).
/// Future: add a dedicated `CapabilityType::Network` variant.
pub fn capability_send(owner: ProcessId, frame: &[u8]) -> Result<(), &'static str> {
    let has_cap = crate::capability::check_capability(
        owner,
        0u64,
        CapabilityType::Channel,
        Rights::new(Rights::NONE),
    );
    if !has_cap {
        return Err("virtio_net: process lacks Channel capability for network send");
    }
    send(frame)
}
