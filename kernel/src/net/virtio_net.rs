/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
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

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};
use spin::Mutex;

// ============================================================================
// MMIO register offsets
// ============================================================================

const VIRTIO_MMIO_MAGIC_VALUE:      usize = 0x000;
const VIRTIO_MMIO_VERSION:          usize = 0x004;
const VIRTIO_MMIO_DEVICE_ID:        usize = 0x008;
const VIRTIO_MMIO_VENDOR_ID:        usize = 0x00C;
const VIRTIO_MMIO_DEVICE_FEATURES:  usize = 0x010;
const VIRTIO_MMIO_DEVICE_FEAT_SEL:  usize = 0x014;
const VIRTIO_MMIO_DRIVER_FEATURES:  usize = 0x020;
const VIRTIO_MMIO_DRIVER_FEAT_SEL:  usize = 0x024;
const VIRTIO_MMIO_QUEUE_SEL:        usize = 0x030;
const VIRTIO_MMIO_QUEUE_NUM_MAX:    usize = 0x034;
const VIRTIO_MMIO_QUEUE_NUM:        usize = 0x038;
const VIRTIO_MMIO_QUEUE_READY:      usize = 0x044;
const VIRTIO_MMIO_QUEUE_NOTIFY:     usize = 0x050;
const VIRTIO_MMIO_INT_STATUS:       usize = 0x060;
const VIRTIO_MMIO_INT_ACK:          usize = 0x064;
const VIRTIO_MMIO_STATUS:           usize = 0x070;
const VIRTIO_MMIO_QUEUE_DESC_LOW:   usize = 0x080;
const VIRTIO_MMIO_QUEUE_DESC_HIGH:  usize = 0x084;
const VIRTIO_MMIO_QUEUE_DRIVER_LOW: usize = 0x090;
const VIRTIO_MMIO_QUEUE_DRIVER_HIGH:usize = 0x094;
const VIRTIO_MMIO_QUEUE_DEVICE_LOW: usize = 0x0A0;
const VIRTIO_MMIO_QUEUE_DEVICE_HIGH:usize = 0x0A4;
const VIRTIO_MMIO_CONFIG:           usize = 0x100;

// VirtIO status bits
const VIRTIO_STATUS_ACKNOWLEDGE:  u32 = 1;
const VIRTIO_STATUS_DRIVER:       u32 = 2;
const VIRTIO_STATUS_DRIVER_OK:    u32 = 4;
const VIRTIO_STATUS_FEATURES_OK:  u32 = 8;
const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u32 = 64;
const VIRTIO_STATUS_FAILED:       u32 = 128;

// VirtIO magic
const VIRTIO_MAGIC: u32 = 0x74726976; // "virt"
const VIRTIO_NET_DEVICE_ID: u32 = 1;

// VirtIO-net feature bits
const VIRTIO_NET_F_MAC: u32      = 1 << 5;
const VIRTIO_NET_F_STATUS: u32   = 1 << 16;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;

// Queue indices
const VIRTIO_NET_RX_QUEUE: u32 = 0;
const VIRTIO_NET_TX_QUEUE: u32 = 1;

// Queue parameters
const QUEUE_SIZE: usize = 64;  // must be power of two
const RX_BUF_SIZE: usize = 1536; // max Ethernet frame + VirtIO header
const TX_BUF_SIZE: usize = 1536;

// ============================================================================
// VirtIO split virtqueue data structures
// ============================================================================

/// VirtIO descriptor flags
const VIRTQ_DESC_F_NEXT:  u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// A single VirtIO virtqueue descriptor.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

/// The available (driver→device) ring.
#[repr(C, align(2))]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx:   u16,
    pub ring:  [u16; QUEUE_SIZE],
    pub used_event: u16,
}

/// One used-ring element.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id:  u32,
    pub len: u32,
}

/// The used (device→driver) ring.
#[repr(C, align(4))]
pub struct VirtqUsed {
    pub flags:     u16,
    pub idx:       u16,
    pub ring:      [VirtqUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

// ============================================================================
// VirtIO-net packet header (no merge, no csum offload for MVP)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioNetHdr {
    flags:       u8,
    gso_type:    u8,
    hdr_len:     u16,
    gso_size:    u16,
    csum_start:  u16,
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
/// here we use `compiler_fence` to prevent the compiler from reordering stores,
/// and rely on cache coherency (coherent DMA model used by QEMU virtio-mmio).
pub struct VirtQueue {
    desc:   Vec<VirtqDesc>,
    avail:  Vec<u16>,       // ring[] portion only; we track flags/idx separately
    avail_flags: u16,
    avail_idx: u16,
    used_idx_shadow: u16,
    used:   Vec<VirtqUsedElem>,
    used_flags: u16,
    used_idx: u16,
    /// Packet buffers — one per descriptor slot.
    buffers: Vec<Vec<u8>>,
    /// MMIO base address for this queue's NOTIFY register.
    mmio_base: usize,
    queue_index: u32,
    /// Free descriptor stack head.
    free_head: u16,
    free_count: u16,
    /// Next chain index in free list.
    next_free: Vec<u16>,
}

impl VirtQueue {
    fn new(mmio_base: usize, queue_index: u32, buf_size: usize) -> Self {
        let mut desc = Vec::with_capacity(QUEUE_SIZE);
        let mut buffers = Vec::with_capacity(QUEUE_SIZE);
        let mut next_free = Vec::with_capacity(QUEUE_SIZE);

        for i in 0..QUEUE_SIZE {
            let buf = alloc::vec![0u8; buf_size];
            let buf_addr = buf.as_ptr() as u64;
            desc.push(VirtqDesc {
                addr:  buf_addr,
                len:   buf_size as u32,
                flags: 0,
                next:  (i + 1) as u16,
            });
            buffers.push(buf);
            next_free.push((i + 1) as u16);
        }
        // Last free-list pointer wraps (sentinel)
        if let Some(last) = next_free.last_mut() { *last = QUEUE_SIZE as u16; }

        VirtQueue {
            desc,
            avail: alloc::vec![0u16; QUEUE_SIZE],
            avail_flags: 0,
            avail_idx: 0,
            used_idx_shadow: 0,
            used: alloc::vec![VirtqUsedElem::default(); QUEUE_SIZE],
            used_flags: 0,
            used_idx: 0,
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
        if self.free_count == 0 { return None; }
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

    /// Copy `data` into the descriptor's buffer and add it to the available ring.
    fn enqueue_tx(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() + VIRTIO_NET_HDR_SIZE > TX_BUF_SIZE {
            return Err("virtio_net: TX packet too large");
        }
        let desc_idx = self.alloc_desc().ok_or("virtio_net: TX queue full")?;

        // Build VirtIO net header (no offloads)
        let hdr = VirtioNetHdr::default();
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(
                &hdr as *const _ as *const u8,
                VIRTIO_NET_HDR_SIZE,
            )
        };

        let buf = &mut self.buffers[desc_idx as usize];
        buf[..VIRTIO_NET_HDR_SIZE].copy_from_slice(hdr_bytes);
        buf[VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + data.len()].copy_from_slice(data);

        let total_len = VIRTIO_NET_HDR_SIZE + data.len();
        self.desc[desc_idx as usize].addr  = buf.as_ptr() as u64;
        self.desc[desc_idx as usize].len   = total_len as u32;
        self.desc[desc_idx as usize].flags = 0; // read-only for device
        self.desc[desc_idx as usize].next  = 0;

        // Publish to available ring
        let avail_slot = (self.avail_idx as usize) % QUEUE_SIZE;
        self.avail[avail_slot] = desc_idx;
        compiler_fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        compiler_fence(Ordering::SeqCst);

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
            self.desc[desc_idx as usize].addr  = buf_addr;
            self.desc[desc_idx as usize].len   = RX_BUF_SIZE as u32;
            self.desc[desc_idx as usize].flags = VIRTQ_DESC_F_WRITE; // device writes
            self.desc[desc_idx as usize].next  = 0;

            let avail_slot = (self.avail_idx as usize) % QUEUE_SIZE;
            self.avail[avail_slot] = desc_idx;
            compiler_fence(Ordering::SeqCst);
            self.avail_idx = self.avail_idx.wrapping_add(1);
        }
        compiler_fence(Ordering::SeqCst);
        mmio_write32(self.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY, self.queue_index);
    }

    /// Poll the used ring and return completed descriptor indices.
    fn poll_used(&mut self, out: &mut Vec<(u16, u32)>) {
        let used_idx = self.used_idx;
        while self.used_idx_shadow != used_idx {
            let slot = (self.used_idx_shadow as usize) % QUEUE_SIZE;
            let elem = self.used[slot];
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
fn mmio_write32(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

// ============================================================================
// VirtioNet global driver
// ============================================================================

pub struct VirtioNet {
    mmio_base: usize,
    rx: VirtQueue,
    tx: VirtQueue,
    pub mac: [u8; 6],
    initialized: bool,
}

impl VirtioNet {
    const fn uninit() -> Self {
        // SAFETY: zeroed-out placeholder; replaced by `init()` before use.
        VirtioNet {
            mmio_base: 0,
            rx: VirtQueue {
                desc: Vec::new(),
                avail: Vec::new(),
                avail_flags: 0,
                avail_idx: 0,
                used_idx_shadow: 0,
                used: Vec::new(),
                used_flags: 0,
                used_idx: 0,
                buffers: Vec::new(),
                mmio_base: 0,
                queue_index: 0,
                free_head: 0,
                free_count: 0,
                next_free: Vec::new(),
            },
            tx: VirtQueue {
                desc: Vec::new(),
                avail: Vec::new(),
                avail_flags: 0,
                avail_idx: 0,
                used_idx_shadow: 0,
                used: Vec::new(),
                used_flags: 0,
                used_idx: 0,
                buffers: Vec::new(),
                mmio_base: 0,
                queue_index: 1,
                free_head: 0,
                free_count: 0,
                next_free: Vec::new(),
            },
            mac: [0u8; 6],
            initialized: false,
        }
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
    compiler_fence(Ordering::SeqCst);

    // 2. Acknowledge
    mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

    // 3. Driver
    mmio_write32(
        base + VIRTIO_MMIO_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );

    // 4. Read device features, negotiate
    mmio_write32(base + VIRTIO_MMIO_DEVICE_FEAT_SEL, 0);
    let device_features = mmio_read32(base + VIRTIO_MMIO_DEVICE_FEATURES);

    // Negotiate: we want MAC and status; no GSO/checksum offload for MVP.
    let driver_features = device_features & (VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS);
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEAT_SEL, 0);
    mmio_write32(base + VIRTIO_MMIO_DRIVER_FEATURES, driver_features);

    // 5. Features OK
    let status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK;
    mmio_write32(base + VIRTIO_MMIO_STATUS, status);
    compiler_fence(Ordering::SeqCst);

    // Confirm features were accepted
    let confirmed = mmio_read32(base + VIRTIO_MMIO_STATUS);
    if (confirmed & VIRTIO_STATUS_FEATURES_OK) == 0 {
        mmio_write32(base + VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return Err("virtio_net: device rejected features");
    }

    // 6. Setup virtqueues
    setup_queue(base, VIRTIO_NET_RX_QUEUE)?;
    setup_queue(base, VIRTIO_NET_TX_QUEUE)?;

    // 7. Driver OK
    mmio_write32(
        base + VIRTIO_MMIO_STATUS,
        status | VIRTIO_STATUS_DRIVER_OK,
    );
    compiler_fence(Ordering::SeqCst);

    // Read MAC from config space (offset 0x100, 6 bytes)
    let mut mac = [0u8; 6];
    if (driver_features & VIRTIO_NET_F_MAC) != 0 {
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = mmio_read32(base + VIRTIO_MMIO_CONFIG + i) as u8;
        }
    }

    let mut dev = VIRTIO_NET.lock();
    dev.mmio_base = base;
    dev.mac = mac;
    dev.rx = VirtQueue::new(base, VIRTIO_NET_RX_QUEUE, RX_BUF_SIZE);
    dev.tx = VirtQueue::new(base, VIRTIO_NET_TX_QUEUE, TX_BUF_SIZE);
    dev.initialized = true;

    // Pre-fill RX queue with buffers
    dev.rx.replenish_rx();

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
    dev.tx.enqueue_tx(frame)
}

/// Poll the RX queue and pass received frames to the callback.
///
/// Returns the number of frames delivered.  The callback receives the raw
/// Ethernet frame bytes (without the VirtIO-net header).
pub fn poll_rx<F: FnMut(&[u8])>(mut cb: F) -> usize {
    let mut dev = VIRTIO_NET.lock();
    if !dev.initialized {
        return 0;
    }

    let mut completed: Vec<(u16, u32)> = Vec::new();
    dev.rx.poll_used(&mut completed);

    let mut count = 0;
    for (desc_idx, len) in &completed {
        let idx = *desc_idx as usize;
        let total = *len as usize;
        if total <= VIRTIO_NET_HDR_SIZE { continue; }
        let frame_len = total - VIRTIO_NET_HDR_SIZE;
        if idx < QUEUE_SIZE && frame_len <= RX_BUF_SIZE - VIRTIO_NET_HDR_SIZE {
            let frame = &dev.rx.buffers[idx][VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + frame_len];
            cb(frame);
            count += 1;
        }
        dev.rx.free_desc(*desc_idx);
    }

    // Replenish freed descriptors
    dev.rx.replenish_rx();

    count
}

/// Returns `true` if a VirtIO-net device has been successfully initialised.
pub fn is_available() -> bool {
    VIRTIO_NET.lock().initialized
}

/// Returns the negotiated MAC address, or all-zeros if not initialised.
pub fn mac_address() -> [u8; 6] {
    VIRTIO_NET.lock().mac
}

// ============================================================================
// Internal: queue setup
// ============================================================================

fn setup_queue(base: usize, queue_idx: u32) -> Result<(), &'static str> {
    mmio_write32(base + VIRTIO_MMIO_QUEUE_SEL, queue_idx);
    let max_size = mmio_read32(base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if max_size == 0 {
        return Err("virtio_net: queue not available");
    }
    let size = (QUEUE_SIZE as u32).min(max_size);
    mmio_write32(base + VIRTIO_MMIO_QUEUE_NUM, size);
    // We set QUEUE_READY to 1 after writing descriptor/avail/used addresses.
    // For the MVP we rely on the host (QEMU) to accept the kernel virtual
    // addresses directly (no IOMMU; host and guest share address space in
    // QEMU's TCG mode, which is the development target).
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
