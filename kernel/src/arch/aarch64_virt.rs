/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 */

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{
    AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

use super::{ArchPlatform, BootInfo};
use super::aarch64_vectors::VectorSlot;

const QEMU_VIRT_GICD_BASE_FALLBACK: usize = 0x0800_0000;
const QEMU_VIRT_GICC_BASE_FALLBACK: usize = 0x0801_0000;
const QEMU_VIRT_MEM_BASE_FALLBACK: usize = 0x4000_0000;
const QEMU_VIRT_MEM_SIZE_FALLBACK: usize = 512 * 1024 * 1024;
const TIMER_HZ: u64 = 100;
const HEARTBEAT_TICKS: u64 = TIMER_HZ;
const MAX_TRACKED_VIRTIO_MMIO: usize = 16;

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER0: usize = 0x100;
const GICD_ICENABLER0: usize = 0x180;
const GICD_ISPENDR0: usize = 0x200;
const GICD_ICPENDR0: usize = 0x280;
const GICD_ISACTIVER0: usize = 0x300;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xC00;

const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_BPR: usize = 0x008;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;
const GICC_RPR: usize = 0x014;
const GICC_HPPIR: usize = 0x018;

const GIC_SPURIOUS_INTID_MIN: u32 = 1020;
const VIRTIO_MMIO_INTERRUPT_STATUS: usize = 0x060;
const VIRTIO_MMIO_INTERRUPT_ACK: usize = 0x064;
const VIRTIO_MMIO_MAGIC_VALUE: usize = 0x000;
const VIRTIO_MMIO_VERSION: usize = 0x004;
const VIRTIO_MMIO_DEVICE_ID: usize = 0x008;
const VIRTIO_MMIO_VENDOR_ID: usize = 0x00c;
const VIRTIO_MMIO_HOST_FEATURES: usize = 0x010;
const VIRTIO_MMIO_HOST_FEATURES_SEL: usize = 0x014;
const VIRTIO_MMIO_GUEST_FEATURES: usize = 0x020;
const VIRTIO_MMIO_GUEST_FEATURES_SEL: usize = 0x024;
const VIRTIO_MMIO_GUEST_PAGE_SIZE: usize = 0x028;
const VIRTIO_MMIO_QUEUE_SEL: usize = 0x030;
const VIRTIO_MMIO_QUEUE_NUM_MAX: usize = 0x034;
const VIRTIO_MMIO_QUEUE_NUM: usize = 0x038;
const VIRTIO_MMIO_QUEUE_ALIGN: usize = 0x03c;
const VIRTIO_MMIO_QUEUE_PFN: usize = 0x040;
const VIRTIO_MMIO_QUEUE_NOTIFY: usize = 0x050;
const VIRTIO_MMIO_STATUS: usize = 0x070;
const VIRTIO_MMIO_MAGIC_EXPECTED: u32 = 0x7472_6976; // 'virt'
const VIRTIO_MMIO_VERSION_LEGACY: u32 = 1;
const VIRTIO_MMIO_DEVICE_ID_NET: u32 = 1;
const VIRTIO_MMIO_DEVICE_ID_BLOCK: u32 = 2;
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
const VIRTIO_STATUS_DRIVER: u32 = 2;
const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_STATUS_FAILED: u32 = 0x80;
const VIRTIO_QUEUE_ALIGN_BYTES: usize = 4096;
const VIRTIO_QUEUE_SIZE_TARGET: u16 = 8;
const VIRTIO_BLK_CONFIG_CAPACITY_LO: usize = 0x100;
const VIRTIO_BLK_CONFIG_CAPACITY_HI: usize = 0x104;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

static BOOT_DTB_PTR: AtomicUsize = AtomicUsize::new(0);
static BOOT_CMDLINE_PTR: AtomicUsize = AtomicUsize::new(0);
static BOOT_CMDLINE_LEN: AtomicUsize = AtomicUsize::new(0);

static DISCOVERED_UART_BASE: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_GICD_BASE: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_GICC_BASE: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_MEM_BASE: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_MEM_SIZE: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_TIMER_INTID: AtomicU32 = AtomicU32::new(30);
static DISCOVERED_UART_IRQ_INTID: AtomicU32 = AtomicU32::new(u32::MAX);
static DISCOVERED_VIRTIO_MMIO_COUNT: AtomicUsize = AtomicUsize::new(0);
static DISCOVERED_VIRTIO_MMIO_BASES: [AtomicUsize; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];
static DISCOVERED_VIRTIO_MMIO_SIZES: [AtomicUsize; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];
static DISCOVERED_VIRTIO_MMIO_IRQS: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX),
];

static EARLY_UART_READY: AtomicBool = AtomicBool::new(false);
static GIC_READY: AtomicBool = AtomicBool::new(false);
static TIMER_READY: AtomicBool = AtomicBool::new(false);
static DTB_DISCOVERY_DONE: AtomicBool = AtomicBool::new(false);
static STRICT_UART_IRQ_MODE: AtomicBool = AtomicBool::new(false);

static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_INTERVAL_TICKS: AtomicU64 = AtomicU64::new(0);
static TIMER_FREQ_HZ: AtomicU64 = AtomicU64::new(0);
static LAST_IRQ_ID: AtomicU32 = AtomicU32::new(u32::MAX);
static LAST_GICC_IAR_RAW: AtomicU32 = AtomicU32::new(0);
static LAST_GICC_HPPIR: AtomicU32 = AtomicU32::new(0);
static UNKNOWN_IRQ_LOGGED: AtomicU32 = AtomicU32::new(u32::MAX);
static UART_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static VIRTIO_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static VIRTIO_IRQ_ACK_COUNT: AtomicU64 = AtomicU64::new(0);
static SCHED_TICK_HOOK_COUNT: AtomicU64 = AtomicU64::new(0);
static HEARTBEAT_COUNT: AtomicU64 = AtomicU64::new(0);
static AARCH64_SCHED_TICK_TOTAL: AtomicU64 = AtomicU64::new(0);
static AARCH64_SCHED_RESCHED_PENDING: AtomicBool = AtomicBool::new(false);
static AARCH64_SCHED_RESCHED_REQUESTS: AtomicU64 = AtomicU64::new(0);
static AARCH64_SCHED_TIMESLICE_TICKS: AtomicU64 = AtomicU64::new(10);
static AARCH64_SCHED_TIMESLICE_POS: AtomicU64 = AtomicU64::new(0);
static VIRTIO_MMIO_LAST_IRQ_STATUS: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static VIRTIO_MMIO_IRQ_COUNTS: [AtomicU64; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static VIRTIO_MMIO_MAGIC: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static VIRTIO_MMIO_VERSION_REG: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static VIRTIO_MMIO_DEVICE_ID_REG: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static VIRTIO_MMIO_VENDOR_ID_REG: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];
static VIRTIO_MMIO_HOST_FEATURES0: [AtomicU32; MAX_TRACKED_VIRTIO_MMIO] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

#[repr(C, align(4096))]
struct AlignedVirtQueueMem {
    bytes: [u8; 8192],
}

struct VirtioQueueStorage {
    mem: UnsafeCell<AlignedVirtQueueMem>,
}

unsafe impl Sync for VirtioQueueStorage {}

impl VirtioQueueStorage {
    const fn new() -> Self {
        Self {
            mem: UnsafeCell::new(AlignedVirtQueueMem { bytes: [0; 8192] }),
        }
    }

    fn base_ptr(&self) -> *mut u8 {
        unsafe { (&mut (*self.mem.get()).bytes) as *mut [u8; 8192] as *mut u8 }
    }
}

static VIRTIO_Q0_STORAGE: VirtioQueueStorage = VirtioQueueStorage::new();
static VIRTIO_ACTIVE_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static VIRTIO_ACTIVE_DEVICE_ID: AtomicU32 = AtomicU32::new(0);
static VIRTIO_ACTIVE_QUEUE_SIZE: AtomicU32 = AtomicU32::new(0);
static VIRTIO_ACTIVE_QUEUE_BASE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_ACTIVE_DESC_OFF: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_ACTIVE_AVAIL_OFF: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_ACTIVE_USED_RING_OFF: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_ACTIVE_USED_IDX_LAST: AtomicU32 = AtomicU32::new(0);
static VIRTIO_ACTIVE_USED_ADVANCES: AtomicU64 = AtomicU64::new(0);
static VIRTIO_ACTIVE_NOTIFY_COUNT: AtomicU64 = AtomicU64::new(0);
static VIRTIO_ACTIVE_INIT_OK: AtomicBool = AtomicBool::new(false);
static VIRTIO_ACTIVE_INIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static VIRTIO_ACTIVE_INIT_FAILS: AtomicU64 = AtomicU64::new(0);
static VIRTIO_BLK_CAPACITY_SECTORS: AtomicU64 = AtomicU64::new(0);
static VIRTIO_BLK_REQ_POSTED: AtomicU64 = AtomicU64::new(0);
static VIRTIO_BLK_REQ_COMPLETED: AtomicU64 = AtomicU64::new(0);
static VIRTIO_BLK_REQ_POST_FAILS: AtomicU64 = AtomicU64::new(0);
static VIRTIO_BLK_REQ_LAST_STATUS: AtomicU32 = AtomicU32::new(0xFF);
static VIRTIO_BLK_REQ_LAST_USED_LEN: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    ioprio: u32,
    sector: u64,
}

#[repr(C, align(16))]
struct VirtioBlkReqState {
    hdr: UnsafeCell<VirtioBlkReqHeader>,
    data: UnsafeCell<[u8; 512]>,
    status: UnsafeCell<u8>,
}

unsafe impl Sync for VirtioBlkReqState {}

impl VirtioBlkReqState {
    const fn new() -> Self {
        Self {
            hdr: UnsafeCell::new(VirtioBlkReqHeader {
                req_type: 0,
                ioprio: 0,
                sector: 0,
            }),
            data: UnsafeCell::new([0; 512]),
            status: UnsafeCell::new(0xFF),
        }
    }
}

static VIRTIO_BLK_REQ: VirtioBlkReqState = VirtioBlkReqState::new();

#[inline]
fn nonzero_ptr(ptr: usize) -> Option<usize> {
    if ptr == 0 { None } else { Some(ptr) }
}

#[inline]
pub(crate) fn uart() -> &'static super::aarch64_pl011::Pl011 {
    super::aarch64_pl011::early_uart()
}

fn ensure_uart() {
    if !EARLY_UART_READY.load(Ordering::Relaxed) {
        uart().init_early();
        EARLY_UART_READY.store(true, Ordering::Relaxed);
    }
}

fn seed_platform_fallbacks() {
    DISCOVERED_UART_BASE.store(super::aarch64_pl011::QEMU_VIRT_PL011_BASE, Ordering::Relaxed);
    DISCOVERED_GICD_BASE.store(QEMU_VIRT_GICD_BASE_FALLBACK, Ordering::Relaxed);
    DISCOVERED_GICC_BASE.store(QEMU_VIRT_GICC_BASE_FALLBACK, Ordering::Relaxed);
    DISCOVERED_MEM_BASE.store(QEMU_VIRT_MEM_BASE_FALLBACK, Ordering::Relaxed);
    DISCOVERED_MEM_SIZE.store(QEMU_VIRT_MEM_SIZE_FALLBACK, Ordering::Relaxed);
    DISCOVERED_TIMER_INTID.store(30, Ordering::Relaxed);
    DISCOVERED_UART_IRQ_INTID.store(u32::MAX, Ordering::Relaxed);
    DISCOVERED_VIRTIO_MMIO_COUNT.store(0, Ordering::Relaxed);
    for slot in &DISCOVERED_VIRTIO_MMIO_BASES {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &DISCOVERED_VIRTIO_MMIO_SIZES {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &DISCOVERED_VIRTIO_MMIO_IRQS {
        slot.store(u32::MAX, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_LAST_IRQ_STATUS {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_IRQ_COUNTS {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_MAGIC {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_VERSION_REG {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_DEVICE_ID_REG {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_VENDOR_ID_REG {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &VIRTIO_MMIO_HOST_FEATURES0 {
        slot.store(0, Ordering::Relaxed);
    }
    VIRTIO_IRQ_ACK_COUNT.store(0, Ordering::Relaxed);
    UART_IRQ_COUNT.store(0, Ordering::Relaxed);
    VIRTIO_IRQ_COUNT.store(0, Ordering::Relaxed);
    TIMER_IRQ_COUNT.store(0, Ordering::Relaxed);
    TIMER_TICKS.store(0, Ordering::Relaxed);
    SCHED_TICK_HOOK_COUNT.store(0, Ordering::Relaxed);
    HEARTBEAT_COUNT.store(0, Ordering::Relaxed);
    AARCH64_SCHED_TICK_TOTAL.store(0, Ordering::Relaxed);
    AARCH64_SCHED_RESCHED_PENDING.store(false, Ordering::Relaxed);
    AARCH64_SCHED_RESCHED_REQUESTS.store(0, Ordering::Relaxed);
    AARCH64_SCHED_TIMESLICE_POS.store(0, Ordering::Relaxed);
    STRICT_UART_IRQ_MODE.store(false, Ordering::Relaxed);
    VIRTIO_ACTIVE_SLOT.store(usize::MAX, Ordering::Relaxed);
    VIRTIO_ACTIVE_DEVICE_ID.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_SIZE.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_BASE.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_DESC_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_AVAIL_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_RING_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_IDX_LAST.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_ADVANCES.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_NOTIFY_COUNT.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_INIT_OK.store(false, Ordering::Relaxed);
    VIRTIO_ACTIVE_INIT_ATTEMPTS.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_INIT_FAILS.store(0, Ordering::Relaxed);
    VIRTIO_BLK_CAPACITY_SECTORS.store(0, Ordering::Relaxed);
    VIRTIO_BLK_REQ_POSTED.store(0, Ordering::Relaxed);
    VIRTIO_BLK_REQ_COMPLETED.store(0, Ordering::Relaxed);
    VIRTIO_BLK_REQ_POST_FAILS.store(0, Ordering::Relaxed);
    VIRTIO_BLK_REQ_LAST_STATUS.store(0xFF, Ordering::Relaxed);
    VIRTIO_BLK_REQ_LAST_USED_LEN.store(0, Ordering::Relaxed);
}

fn discover_from_dtb_if_needed() {
    if DTB_DISCOVERY_DONE.load(Ordering::Acquire) {
        return;
    }
    seed_platform_fallbacks();
    let dtb_ptr = BOOT_DTB_PTR.load(Ordering::Relaxed);
    if let Some(platform) = super::aarch64_dtb::parse_platform_info(dtb_ptr) {
        if let Some(base) = platform.uart_pl011_base {
            DISCOVERED_UART_BASE.store(base, Ordering::Relaxed);
            super::aarch64_pl011::early_uart().set_base(base);
        }
        if let Some(base) = platform.gic_dist_base {
            DISCOVERED_GICD_BASE.store(base, Ordering::Relaxed);
        }
        if let Some(base) = platform.gic_cpu_base {
            DISCOVERED_GICC_BASE.store(base, Ordering::Relaxed);
        }
        if let Some(mem) = platform.memory {
            DISCOVERED_MEM_BASE.store(mem.base, Ordering::Relaxed);
            DISCOVERED_MEM_SIZE.store(mem.size, Ordering::Relaxed);
        }
        if let Some(intid) = platform.timer_irq_intid {
            DISCOVERED_TIMER_INTID.store(intid, Ordering::Relaxed);
        }
        if let Some(intid) = platform.uart_pl011_irq_intid {
            DISCOVERED_UART_IRQ_INTID.store(intid, Ordering::Relaxed);
        }
        let mut count = 0usize;
        for dev in platform.virtio_mmio.iter() {
            if count >= MAX_TRACKED_VIRTIO_MMIO || dev.base == 0 {
                break;
            }
            DISCOVERED_VIRTIO_MMIO_BASES[count].store(dev.base, Ordering::Relaxed);
            DISCOVERED_VIRTIO_MMIO_SIZES[count].store(dev.size, Ordering::Relaxed);
            DISCOVERED_VIRTIO_MMIO_IRQS[count].store(dev.irq_intid.unwrap_or(u32::MAX), Ordering::Relaxed);
            count += 1;
        }
        DISCOVERED_VIRTIO_MMIO_COUNT.store(count, Ordering::Relaxed);
        BOOT_CMDLINE_PTR.store(platform.chosen_bootargs_ptr.unwrap_or(0), Ordering::Relaxed);
        BOOT_CMDLINE_LEN.store(platform.chosen_bootargs_len, Ordering::Relaxed);
    }
    DTB_DISCOVERY_DONE.store(true, Ordering::Release);
}

pub(crate) fn early_log(msg: &str) {
    ensure_uart();
    uart().write_str(msg);
}

#[inline]
fn mmio_read32(base: usize, off: usize) -> u32 {
    unsafe { read_volatile((base + off) as *const u32) }
}

#[inline]
fn mmio_write32(base: usize, off: usize, val: u32) {
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

#[inline]
fn mmio_write8(base: usize, off: usize, val: u8) {
    unsafe { write_volatile((base + off) as *mut u8, val) }
}

#[inline]
fn gicd_base() -> usize {
    let b = DISCOVERED_GICD_BASE.load(Ordering::Relaxed);
    if b != 0 { b } else { QEMU_VIRT_GICD_BASE_FALLBACK }
}

#[inline]
fn gicc_base() -> usize {
    let b = DISCOVERED_GICC_BASE.load(Ordering::Relaxed);
    if b != 0 { b } else { QEMU_VIRT_GICC_BASE_FALLBACK }
}

#[inline]
fn discovered_uart_irq_intid() -> Option<u32> {
    let v = DISCOVERED_UART_IRQ_INTID.load(Ordering::Relaxed);
    if v == u32::MAX { None } else { Some(v) }
}

fn for_each_discovered_virtio_irq(mut f: impl FnMut(usize, u32)) {
    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    for idx in 0..count {
        let intid = DISCOVERED_VIRTIO_MMIO_IRQS[idx].load(Ordering::Relaxed);
        if intid != u32::MAX {
            f(idx, intid);
        }
    }
}

#[derive(Clone, Copy)]
struct GicIntidSnapshot {
    enabled: bool,
    pending: bool,
    active: bool,
    priority: u8,
    target: u8,
    cfg_bits: u8,
}

#[derive(Clone, Copy)]
struct GicCpuIfSnapshot {
    ctlr: u32,
    pmr: u32,
    bpr: u32,
    rpr: u32,
    hppir: u32,
    last_iar_raw: u32,
}

fn gicd_intid_bit(intid: u32) -> (usize, u32) {
    ((intid as usize / 32) * 4, 1u32 << (intid & 31))
}

fn gicv2_snapshot_intid(gicd: usize, intid: u32) -> GicIntidSnapshot {
    let (word_off, bit) = gicd_intid_bit(intid);
    let enabled = (mmio_read32(gicd, GICD_ISENABLER0 + word_off) & bit) != 0;
    let pending = (mmio_read32(gicd, GICD_ISPENDR0 + word_off) & bit) != 0;
    let active = (mmio_read32(gicd, GICD_ISACTIVER0 + word_off) & bit) != 0;
    let priority = unsafe { read_volatile((gicd + GICD_IPRIORITYR + intid as usize) as *const u8) };
    let target = if intid >= 32 {
        unsafe { read_volatile((gicd + GICD_ITARGETSR + intid as usize) as *const u8) }
    } else {
        0
    };
    let cfg_reg = GICD_ICFGR + (((intid as usize) / 16) * 4);
    let cfg_shift = ((intid as usize) % 16) * 2;
    let cfg_bits = ((mmio_read32(gicd, cfg_reg) >> cfg_shift) & 0b11) as u8;
    GicIntidSnapshot {
        enabled,
        pending,
        active,
        priority,
        target,
        cfg_bits,
    }
}

fn gicv2_snapshot_cpu_if(gicc: usize) -> GicCpuIfSnapshot {
    let hppir = mmio_read32(gicc, GICC_HPPIR);
    LAST_GICC_HPPIR.store(hppir, Ordering::Relaxed);
    GicCpuIfSnapshot {
        ctlr: mmio_read32(gicc, GICC_CTLR),
        pmr: mmio_read32(gicc, GICC_PMR),
        bpr: mmio_read32(gicc, GICC_BPR),
        rpr: mmio_read32(gicc, GICC_RPR),
        hppir,
        last_iar_raw: LAST_GICC_IAR_RAW.load(Ordering::Relaxed),
    }
}

fn gicv2_configure_spi(gicd: usize, intid: u32, target_mask: u8, priority: u8, edge_triggered: bool) {
    if intid < 32 {
        return;
    }
    let cfg_reg = GICD_ICFGR + (((intid as usize) / 16) * 4);
    let cfg_shift = ((intid as usize) % 16) * 2;
    let mut cfg = mmio_read32(gicd, cfg_reg);
    // GICD_ICFGRn[2*x+1]: 0=level, 1=edge. Leave [2*x] as 0.
    cfg &= !(0b11 << cfg_shift);
    if edge_triggered {
        cfg |= 0b10 << cfg_shift;
    }
    mmio_write32(gicd, cfg_reg, cfg);

    mmio_write8(gicd, GICD_ITARGETSR + intid as usize, target_mask);
    mmio_write8(gicd, GICD_IPRIORITYR + intid as usize, priority);

    let (word_off, bit) = gicd_intid_bit(intid);
    // Clear stale pending before enabling.
    mmio_write32(gicd, GICD_ICPENDR0 + word_off, bit);
    mmio_write32(gicd, GICD_ICENABLER0 + word_off, bit);
    mmio_write32(gicd, GICD_ISENABLER0 + word_off, bit);
}

pub(crate) fn for_each_discovered_virtio_mmio(mut f: impl FnMut(usize, usize, u32)) {
    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    for idx in 0..count {
        let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
        let size = DISCOVERED_VIRTIO_MMIO_SIZES[idx].load(Ordering::Relaxed);
        let irq = DISCOVERED_VIRTIO_MMIO_IRQS[idx].load(Ordering::Relaxed);
        if base != 0 && size != 0 {
            f(base, size, irq);
        }
    }
}

#[inline]
pub(crate) fn scheduler_timer_tick_hook() {
    let total = AARCH64_SCHED_TICK_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    let quantum = AARCH64_SCHED_TIMESLICE_TICKS.load(Ordering::Relaxed).max(1);
    let pos = (total % quantum) as u64;
    AARCH64_SCHED_TIMESLICE_POS.store(pos, Ordering::Relaxed);
    if pos == 0 {
        AARCH64_SCHED_RESCHED_PENDING.store(true, Ordering::Release);
        AARCH64_SCHED_RESCHED_REQUESTS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
fn scheduler_tick_backend_snapshot() -> (u64, bool, u64, u64, u64) {
    (
        AARCH64_SCHED_TICK_TOTAL.load(Ordering::Relaxed),
        AARCH64_SCHED_RESCHED_PENDING.load(Ordering::Acquire),
        AARCH64_SCHED_RESCHED_REQUESTS.load(Ordering::Relaxed),
        AARCH64_SCHED_TIMESLICE_TICKS.load(Ordering::Relaxed),
        AARCH64_SCHED_TIMESLICE_POS.load(Ordering::Relaxed),
    )
}

fn scheduler_tick_backend_clear_pending() {
    AARCH64_SCHED_RESCHED_PENDING.store(false, Ordering::Release);
}

fn scheduler_tick_backend_set_quantum(ticks: u64) -> Result<(), &'static str> {
    if ticks == 0 || ticks > 10_000 {
        return Err("quantum out of range");
    }
    AARCH64_SCHED_TIMESLICE_TICKS.store(ticks, Ordering::Relaxed);
    Ok(())
}

#[inline]
pub(crate) fn discovered_dtb_ptr() -> Option<usize> {
    nonzero_ptr(BOOT_DTB_PTR.load(Ordering::Relaxed))
}

#[inline]
pub(crate) fn discovered_memory_range() -> Option<(usize, usize)> {
    let base = DISCOVERED_MEM_BASE.load(Ordering::Relaxed);
    let size = DISCOVERED_MEM_SIZE.load(Ordering::Relaxed);
    if base == 0 || size == 0 {
        None
    } else {
        Some((base, size))
    }
}

#[inline]
pub(crate) fn discovered_gicv2_bases() -> Option<(usize, usize)> {
    let d = DISCOVERED_GICD_BASE.load(Ordering::Relaxed);
    let c = DISCOVERED_GICC_BASE.load(Ordering::Relaxed);
    if d == 0 || c == 0 {
        None
    } else {
        Some((d, c))
    }
}

#[inline]
pub(crate) fn discovered_timer_intid() -> u32 {
    DISCOVERED_TIMER_INTID.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn timer_irq_count() -> u64 {
    TIMER_IRQ_COUNT.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn last_irq_id() -> u32 {
    LAST_IRQ_ID.load(Ordering::Relaxed)
}

pub(crate) fn enable_fp_simd_access() {
    let mut cpacr: u64;
    unsafe {
        core::arch::asm!("mrs {out}, CPACR_EL1", out = out(reg) cpacr, options(nomem, nostack));
        cpacr |= 0b11 << 20; // FPEN[21:20] = 0b11 (EL0/EL1 access enabled)
        core::arch::asm!(
            "msr CPACR_EL1, {val}",
            "isb",
            val = in(reg) cpacr,
            options(nostack),
        );
    }
}

fn uart_write_hex_usize(value: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 2 + (core::mem::size_of::<usize>() * 2)];
    buf[0] = b'0';
    buf[1] = b'x';
    let digits = core::mem::size_of::<usize>() * 2;
    for i in 0..digits {
        let shift = (digits - 1 - i) * 4;
        buf[2 + i] = HEX[((value >> shift) & 0xF) as usize];
    }
    for &b in &buf {
        uart().write_byte(b);
    }
}

fn uart_write_hex_u64(value: u64) {
    uart_write_hex_usize(value as usize);
}

#[inline]
fn uart_newline() {
    uart().write_str("\n");
}

fn shell_prompt() {
    uart().write_str("\r\na64> ");
}

#[inline]
fn shell_try_read_input_byte() -> Option<u8> {
    if discovered_uart_irq_intid().is_some() {
        if let Some(b) = uart().try_read_buffered_byte() {
            return Some(b);
        }
        if STRICT_UART_IRQ_MODE.load(Ordering::Relaxed) {
            return None;
        }
        // QEMU/firmware combinations may not deliver PL011 RX IRQs reliably yet.
        // Keep an interrupt-first fallback so the shell stays usable while bring-up
        // continues.
        if UART_IRQ_COUNT.load(Ordering::Relaxed) == 0 {
            return uart().try_read_byte();
        }
        None
    } else {
        uart().try_read_byte()
    }
}

#[inline]
pub(crate) fn read_currentel() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, CurrentEL", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
pub(crate) fn read_daif() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, DAIF", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
pub(crate) fn read_sctlr_el1() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, SCTLR_EL1", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
pub(crate) fn read_vbar_el1() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, VBAR_EL1", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
fn read_cntfrq_el0() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, CNTFRQ_EL0", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
fn read_cntpct_el0() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mrs {out}, CNTPCT_EL0", out = out(reg) value, options(nomem, nostack));
    }
    value
}

fn generic_timer_rearm() {
    let interval = TIMER_INTERVAL_TICKS.load(Ordering::Relaxed).max(1);
    unsafe {
        core::arch::asm!(
            "msr CNTP_TVAL_EL0, {tval}",
            "msr CNTP_CTL_EL0, {ctl}",
            "isb",
            tval = in(reg) interval,
            ctl = in(reg) 1u64, // ENABLE=1, IMASK=0
            options(nostack),
        );
    }
}

fn generic_timer_init() {
    let freq = read_cntfrq_el0();
    let interval = (freq / TIMER_HZ).max(1);
    TIMER_FREQ_HZ.store(freq, Ordering::Relaxed);
    TIMER_INTERVAL_TICKS.store(interval, Ordering::Relaxed);
    generic_timer_rearm();
    TIMER_READY.store(true, Ordering::Relaxed);
}

fn gicv2_set_priority(gicd: usize, intid: u32, priority: u8) {
    mmio_write8(gicd, GICD_IPRIORITYR + intid as usize, priority);
}

fn gicv2_route_spi_to_cpu0(gicd: usize, intid: u32) {
    if intid < 32 {
        return;
    }
    mmio_write8(gicd, GICD_ITARGETSR + intid as usize, 0x01);
}

fn gicv2_enable_intid(gicd: usize, intid: u32) {
    let bit = 1u32 << (intid & 31);
    let icen = GICD_ICENABLER0 + ((intid as usize / 32) * 4);
    let isen = GICD_ISENABLER0 + ((intid as usize / 32) * 4);
    mmio_write32(gicd, icen, bit);
    mmio_write32(gicd, isen, bit);
}

fn virtio_mmio_handle_irq(intid: u32) -> bool {
    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    for idx in 0..count {
        let irq = DISCOVERED_VIRTIO_MMIO_IRQS[idx].load(Ordering::Relaxed);
        if irq != intid {
            continue;
        }
        let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
        if base == 0 {
            continue;
        }
        let status = mmio_read32(base, VIRTIO_MMIO_INTERRUPT_STATUS);
        VIRTIO_MMIO_LAST_IRQ_STATUS[idx].store(status, Ordering::Relaxed);
        VIRTIO_MMIO_IRQ_COUNTS[idx].fetch_add(1, Ordering::Relaxed);
        if status != 0 {
            mmio_write32(base, VIRTIO_MMIO_INTERRUPT_ACK, status);
            VIRTIO_IRQ_ACK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if VIRTIO_ACTIVE_INIT_OK.load(Ordering::Acquire)
            && VIRTIO_ACTIVE_SLOT.load(Ordering::Relaxed) == idx
        {
            if let Some(cur_used_idx) = virtio_active_used_idx() {
                let prev = VIRTIO_ACTIVE_USED_IDX_LAST.load(Ordering::Relaxed) as u16;
                let delta = cur_used_idx.wrapping_sub(prev) as u64;
                if delta != 0 {
                    VIRTIO_ACTIVE_USED_ADVANCES.fetch_add(delta, Ordering::Relaxed);
                    if VIRTIO_ACTIVE_DEVICE_ID.load(Ordering::Relaxed) == VIRTIO_MMIO_DEVICE_ID_BLOCK {
                        let status = unsafe { read_volatile(VIRTIO_BLK_REQ.status.get() as *const u8) };
                        VIRTIO_BLK_REQ_LAST_STATUS.store(status as u32, Ordering::Relaxed);
                        if let Some(used_len) = virtio_active_used_len() {
                            VIRTIO_BLK_REQ_LAST_USED_LEN.store(used_len, Ordering::Relaxed);
                        }
                        VIRTIO_BLK_REQ_COMPLETED.fetch_add(delta, Ordering::Relaxed);
                    }
                }
                VIRTIO_ACTIVE_USED_IDX_LAST.store(cur_used_idx as u32, Ordering::Relaxed);
            }
        }
        return true;
    }
    false
}

fn virtio_mmio_probe_all() {
    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    for idx in 0..count {
        let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
        if base == 0 {
            continue;
        }
        let magic = mmio_read32(base, VIRTIO_MMIO_MAGIC_VALUE);
        let version = mmio_read32(base, VIRTIO_MMIO_VERSION);
        let device = mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);
        let vendor = mmio_read32(base, VIRTIO_MMIO_VENDOR_ID);
        mmio_write32(base, VIRTIO_MMIO_HOST_FEATURES_SEL, 0);
        let host_features0 = mmio_read32(base, VIRTIO_MMIO_HOST_FEATURES);
        VIRTIO_MMIO_MAGIC[idx].store(magic, Ordering::Relaxed);
        VIRTIO_MMIO_VERSION_REG[idx].store(version, Ordering::Relaxed);
        VIRTIO_MMIO_DEVICE_ID_REG[idx].store(device, Ordering::Relaxed);
        VIRTIO_MMIO_VENDOR_ID_REG[idx].store(vendor, Ordering::Relaxed);
        VIRTIO_MMIO_HOST_FEATURES0[idx].store(host_features0, Ordering::Relaxed);
    }
}

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    (value + (align - 1)) & !(align - 1)
}

#[derive(Clone, Copy)]
struct VirtQueueLayout {
    desc_off: usize,
    avail_off: usize,
    used_off: usize,
    total_bytes: usize,
}

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

fn virtqueue_layout_legacy(qsize: u16) -> Option<VirtQueueLayout> {
    let q = qsize as usize;
    if q == 0 {
        return None;
    }
    let desc_bytes = 16usize.checked_mul(q)?;
    let avail_bytes = 6usize.checked_add(2usize.checked_mul(q)?)?;
    let used_bytes = 6usize.checked_add(8usize.checked_mul(q)?)?;
    let desc_off = 0usize;
    let avail_off = desc_off.checked_add(desc_bytes)?;
    let used_off = align_up(avail_off.checked_add(avail_bytes)?, VIRTIO_QUEUE_ALIGN_BYTES);
    let total = used_off.checked_add(used_bytes)?;
    if total > 8192 {
        return None;
    }
    Some(VirtQueueLayout {
        desc_off,
        avail_off,
        used_off,
        total_bytes: total,
    })
}

fn virtio_active_used_idx() -> Option<u16> {
    if !VIRTIO_ACTIVE_INIT_OK.load(Ordering::Acquire) {
        return None;
    }
    let base = VIRTIO_ACTIVE_QUEUE_BASE.load(Ordering::Relaxed);
    let used_off = VIRTIO_ACTIVE_USED_RING_OFF.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    let ptr = (base + used_off + 2) as *const u16;
    Some(unsafe { read_volatile(ptr) })
}

fn virtio_active_used_len() -> Option<u32> {
    if !VIRTIO_ACTIVE_INIT_OK.load(Ordering::Acquire) {
        return None;
    }
    let qsize = VIRTIO_ACTIVE_QUEUE_SIZE.load(Ordering::Relaxed) as usize;
    let used_off = VIRTIO_ACTIVE_USED_RING_OFF.load(Ordering::Relaxed);
    let base = VIRTIO_ACTIVE_QUEUE_BASE.load(Ordering::Relaxed);
    if base == 0 || qsize == 0 {
        return None;
    }
    let cur = VIRTIO_ACTIVE_USED_IDX_LAST.load(Ordering::Relaxed) as usize;
    let elem_idx = cur.wrapping_sub(1) % qsize;
    let elem_ptr = (base + used_off + 4 + elem_idx * 8) as *const u32;
    let len = unsafe { read_volatile(elem_ptr.add(1)) };
    Some(len)
}

fn virtio_queue_write_desc(
    queue_base: usize,
    layout: VirtQueueLayout,
    idx: usize,
    addr: usize,
    len: u32,
    flags: u16,
    next: u16,
) {
    let ptr = (queue_base + layout.desc_off + idx * core::mem::size_of::<VirtqDesc>()) as *mut VirtqDesc;
    unsafe {
        write_volatile(
            ptr,
            VirtqDesc {
                addr: addr as u64,
                len,
                flags,
                next,
            },
        );
    }
}

fn virtio_queue_submit_head(base: usize, queue_base: usize, layout: VirtQueueLayout, qsize: u16, head: u16) {
    let qsz = qsize as usize;
    let avail_flags_ptr = (queue_base + layout.avail_off) as *mut u16;
    let avail_idx_ptr = (queue_base + layout.avail_off + 2) as *mut u16;
    let ring_ptr = (queue_base + layout.avail_off + 4) as *mut u16;
    unsafe {
        let idx = read_volatile(avail_idx_ptr);
        write_volatile(avail_flags_ptr, 0);
        write_volatile(ring_ptr.add((idx as usize) % qsz), head);
        core::sync::atomic::fence(Ordering::Release);
        write_volatile(avail_idx_ptr, idx.wrapping_add(1));
    }
    mmio_write32(base, VIRTIO_MMIO_QUEUE_NOTIFY, 0);
    VIRTIO_ACTIVE_NOTIFY_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn virtio_blk_read_capacity(base: usize) -> u64 {
    let lo = mmio_read32(base, VIRTIO_BLK_CONFIG_CAPACITY_LO) as u64;
    let hi = mmio_read32(base, VIRTIO_BLK_CONFIG_CAPACITY_HI) as u64;
    (hi << 32) | lo
}

fn virtio_blk_post_capacity_probe_read(base: usize, queue_base: usize, layout: VirtQueueLayout, qsize: u16) -> bool {
    if qsize < 3 {
        VIRTIO_BLK_REQ_POST_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    unsafe {
        (*VIRTIO_BLK_REQ.hdr.get()).req_type = VIRTIO_BLK_T_IN;
        (*VIRTIO_BLK_REQ.hdr.get()).ioprio = 0;
        (*VIRTIO_BLK_REQ.hdr.get()).sector = 0;
        core::ptr::write_bytes((*VIRTIO_BLK_REQ.data.get()).as_mut_ptr(), 0, 512);
        *VIRTIO_BLK_REQ.status.get() = 0xFF;
    }

    let hdr_addr = VIRTIO_BLK_REQ.hdr.get() as usize;
    let data_addr = VIRTIO_BLK_REQ.data.get() as usize;
    let status_addr = VIRTIO_BLK_REQ.status.get() as usize;

    virtio_queue_write_desc(queue_base, layout, 0, hdr_addr, core::mem::size_of::<VirtioBlkReqHeader>() as u32, VIRTQ_DESC_F_NEXT, 1);
    virtio_queue_write_desc(queue_base, layout, 1, data_addr, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
    virtio_queue_write_desc(queue_base, layout, 2, status_addr, 1, VIRTQ_DESC_F_WRITE, 0);

    virtio_queue_submit_head(base, queue_base, layout, qsize, 0);
    VIRTIO_BLK_REQ_POSTED.fetch_add(1, Ordering::Relaxed);
    true
}

fn virtio_mmio_mark_failed(base: usize, status: u32) {
    mmio_write32(base, VIRTIO_MMIO_STATUS, status | VIRTIO_STATUS_FAILED);
}

fn virtio_mmio_bringup_one() {
    VIRTIO_ACTIVE_INIT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    VIRTIO_ACTIVE_INIT_OK.store(false, Ordering::Relaxed);
    VIRTIO_ACTIVE_SLOT.store(usize::MAX, Ordering::Relaxed);
    VIRTIO_ACTIVE_DEVICE_ID.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_SIZE.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_BASE.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_DESC_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_AVAIL_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_RING_OFF.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_IDX_LAST.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_ADVANCES.store(0, Ordering::Relaxed);
    VIRTIO_ACTIVE_NOTIFY_COUNT.store(0, Ordering::Relaxed);

    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    let mut chosen: Option<usize> = None;
    let mut fallback: Option<usize> = None;
    for idx in 0..count {
        let dev = VIRTIO_MMIO_DEVICE_ID_REG[idx].load(Ordering::Relaxed);
        if dev == 0 {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(idx);
        }
        if dev == VIRTIO_MMIO_DEVICE_ID_BLOCK {
            chosen = Some(idx);
            break;
        }
    }
    let Some(idx) = chosen.or(fallback) else {
        return;
    };

    let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
    let version = VIRTIO_MMIO_VERSION_REG[idx].load(Ordering::Relaxed);
    let device_id = VIRTIO_MMIO_DEVICE_ID_REG[idx].load(Ordering::Relaxed);
    let magic = VIRTIO_MMIO_MAGIC[idx].load(Ordering::Relaxed);
    if base == 0 || magic != VIRTIO_MMIO_MAGIC_EXPECTED || version != VIRTIO_MMIO_VERSION_LEGACY {
        VIRTIO_ACTIVE_INIT_FAILS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let queue_base = VIRTIO_Q0_STORAGE.base_ptr() as usize;
    unsafe {
        core::ptr::write_bytes(VIRTIO_Q0_STORAGE.base_ptr(), 0, 8192);
    }

    mmio_write32(base, VIRTIO_MMIO_STATUS, 0);
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    mmio_write32(base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    mmio_write32(base, VIRTIO_MMIO_HOST_FEATURES_SEL, 0);
    let host_features0 = mmio_read32(base, VIRTIO_MMIO_HOST_FEATURES);
    VIRTIO_MMIO_HOST_FEATURES0[idx].store(host_features0, Ordering::Relaxed);
    mmio_write32(base, VIRTIO_MMIO_GUEST_FEATURES_SEL, 0);
    mmio_write32(base, VIRTIO_MMIO_GUEST_FEATURES, 0);
    mmio_write32(base, VIRTIO_MMIO_GUEST_PAGE_SIZE, VIRTIO_QUEUE_ALIGN_BYTES as u32);

    mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, 0);
    let qmax = mmio_read32(base, VIRTIO_MMIO_QUEUE_NUM_MAX) as u16;
    if qmax == 0 {
        virtio_mmio_mark_failed(base, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        VIRTIO_ACTIVE_INIT_FAILS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let qsize = core::cmp::min(qmax, VIRTIO_QUEUE_SIZE_TARGET);
    let Some(layout) = virtqueue_layout_legacy(qsize) else {
        virtio_mmio_mark_failed(base, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        VIRTIO_ACTIVE_INIT_FAILS.fetch_add(1, Ordering::Relaxed);
        return;
    };

    // Touch layout total for bounds/diagnostics.
    let _ = layout.total_bytes;

    mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, qsize as u32);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_ALIGN, VIRTIO_QUEUE_ALIGN_BYTES as u32);
    mmio_write32(base, VIRTIO_MMIO_QUEUE_PFN, (queue_base >> 12) as u32);
    mmio_write32(
        base,
        VIRTIO_MMIO_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
    );

    let used_idx = unsafe { read_volatile((queue_base + layout.used_off + 2) as *const u16) };
    VIRTIO_ACTIVE_SLOT.store(idx, Ordering::Relaxed);
    VIRTIO_ACTIVE_DEVICE_ID.store(device_id, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_SIZE.store(qsize as u32, Ordering::Relaxed);
    VIRTIO_ACTIVE_QUEUE_BASE.store(queue_base, Ordering::Relaxed);
    VIRTIO_ACTIVE_DESC_OFF.store(layout.desc_off, Ordering::Relaxed);
    VIRTIO_ACTIVE_AVAIL_OFF.store(layout.avail_off, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_RING_OFF.store(layout.used_off, Ordering::Relaxed);
    VIRTIO_ACTIVE_USED_IDX_LAST.store(used_idx as u32, Ordering::Relaxed);

    if device_id == VIRTIO_MMIO_DEVICE_ID_BLOCK {
        let capacity = virtio_blk_read_capacity(base);
        VIRTIO_BLK_CAPACITY_SECTORS.store(capacity, Ordering::Relaxed);
        let _ = virtio_blk_post_capacity_probe_read(base, queue_base, layout, qsize);
    }

    VIRTIO_ACTIVE_INIT_OK.store(true, Ordering::Release);
}

fn gicv2_init() {
    let gicd = gicd_base();
    let gicc = gicc_base();
    let timer_intid = DISCOVERED_TIMER_INTID.load(Ordering::Relaxed);

    mmio_write32(gicd, GICD_CTLR, 0);
    mmio_write32(gicc, GICC_CTLR, 0);

    // Set CPU interface priority mask to allow all priorities.
    mmio_write32(gicc, GICC_PMR, 0xFF);
    mmio_write32(gicc, GICC_BPR, 0);

    // Timer PPI.
    gicv2_enable_intid(gicd, timer_intid);
    gicv2_set_priority(gicd, timer_intid, 0x20);

    // Optional PL011 UART SPI (kept simple: enable routing + IRQ mask in UART later).
    if let Some(uart_intid) = discovered_uart_irq_intid() {
        gicv2_configure_spi(gicd, uart_intid, 0x01, 0x30, false);
    }

    // Optional virtio-mmio SPIs discovered from DTB.
    for_each_discovered_virtio_irq(|_, intid| {
        gicv2_configure_spi(gicd, intid, 0x01, 0x40, false);
    });

    mmio_write32(gicd, GICD_CTLR, 1);
    mmio_write32(gicc, GICC_CTLR, 1);

    let _ = mmio_read32(gicd, GICD_TYPER); // probe/access sanity (best effort)
    GIC_READY.store(true, Ordering::Relaxed);
}

#[inline]
fn daif_clear_irq() {
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
}

#[no_mangle]
pub extern "C" fn arch_aarch64_record_boot_handoff(dtb_ptr: usize) {
    BOOT_DTB_PTR.store(dtb_ptr, Ordering::Relaxed);
    BOOT_CMDLINE_PTR.store(0, Ordering::Relaxed);
    BOOT_CMDLINE_LEN.store(0, Ordering::Relaxed);
    DTB_DISCOVERY_DONE.store(false, Ordering::Relaxed);
    seed_platform_fallbacks();
}

pub(super) struct AArch64QemuVirtPlatform;

pub(super) static PLATFORM: AArch64QemuVirtPlatform = AArch64QemuVirtPlatform;

impl ArchPlatform for AArch64QemuVirtPlatform {
    fn name(&self) -> &'static str {
        "aarch64-qemu-virt"
    }

    fn boot_info(&self) -> BootInfo {
        discover_from_dtb_if_needed();
        let dtb_ptr = BOOT_DTB_PTR.load(Ordering::Relaxed);
        let mut boot = BootInfo {
            raw_info_ptr: nonzero_ptr(dtb_ptr),
            dtb_ptr: nonzero_ptr(dtb_ptr),
            cmdline_ptr: nonzero_ptr(BOOT_CMDLINE_PTR.load(Ordering::Relaxed)),
            ..BootInfo::default()
        };
        if let Some(ptr) = boot.dtb_ptr {
            if !super::aarch64_dtb::is_valid_dtb(ptr) {
                boot.dtb_ptr = None;
            }
        }
        boot
    }

    fn init_cpu_tables(&self) {
        enable_fp_simd_access();
        discover_from_dtb_if_needed();
        if let Some(base) = nonzero_ptr(DISCOVERED_UART_BASE.load(Ordering::Relaxed)) {
            super::aarch64_pl011::early_uart().set_base(base);
        }
        ensure_uart();
        early_log("[A64] qemu-virt early console online (PL011)\n");
        early_log("[A64] FP/SIMD access enabled (CPACR_EL1.FPEN=0b11)\n");
    }

    fn init_trap_table(&self) {
        super::aarch64_vectors::install_stub_vectors();
        if super::aarch64_vectors::vectors_installed() {
            early_log("[A64] exception vectors installed (real VBAR_EL1 table)\n");
        }
    }

    fn init_interrupt_controller(&self) {
        gicv2_init();
        virtio_mmio_probe_all();
        virtio_mmio_bringup_one();
        let u = uart();
        u.write_str("[A64] GICv2 init dist=");
        uart_write_hex_usize(gicd_base());
        u.write_str(" cpu=");
        uart_write_hex_usize(gicc_base());
        u.write_str(" timer-intid=");
        uart_write_hex_u64(DISCOVERED_TIMER_INTID.load(Ordering::Relaxed) as u64);
        u.write_str(" uart-intid=");
        uart_write_hex_u64(discovered_uart_irq_intid().unwrap_or(u32::MAX) as u64);
        u.write_str(" virtio=");
        uart_write_hex_u64(DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed) as u64);
        uart_newline();

        let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
        for idx in 0..count {
            let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
            if base == 0 {
                continue;
            }
            u.write_str("[A64] virtio-mmio probe[");
            uart_write_hex_u64(idx as u64);
            u.write_str("] base=");
            uart_write_hex_usize(base);
            u.write_str(" magic=");
            uart_write_hex_u64(VIRTIO_MMIO_MAGIC[idx].load(Ordering::Relaxed) as u64);
            u.write_str(" ver=");
            uart_write_hex_u64(VIRTIO_MMIO_VERSION_REG[idx].load(Ordering::Relaxed) as u64);
            u.write_str(" dev=");
            uart_write_hex_u64(VIRTIO_MMIO_DEVICE_ID_REG[idx].load(Ordering::Relaxed) as u64);
            u.write_str(" vendor=");
            uart_write_hex_u64(VIRTIO_MMIO_VENDOR_ID_REG[idx].load(Ordering::Relaxed) as u64);
            if VIRTIO_MMIO_MAGIC[idx].load(Ordering::Relaxed) != VIRTIO_MMIO_MAGIC_EXPECTED {
                u.write_str(" bad-magic");
            }
            uart_newline();
        }
    }

    fn init_timer(&self) {
        generic_timer_init();
        let u = uart();
        u.write_str("[A64] generic timer init freq=");
        uart_write_hex_u64(TIMER_FREQ_HZ.load(Ordering::Relaxed));
        u.write_str(" interval=");
        uart_write_hex_u64(TIMER_INTERVAL_TICKS.load(Ordering::Relaxed));
        u.write_str(" cntpct=");
        uart_write_hex_u64(read_cntpct_el0());
        uart_newline();
    }

    fn enable_interrupts(&self) {
        if discovered_uart_irq_intid().is_some() {
            uart().enable_rx_interrupts();
        } else {
            uart().disable_interrupts();
        }
        daif_clear_irq();
        early_log("[A64] IRQs unmasked (DAIF.I cleared)\n");
    }

    fn halt_loop(&self) -> ! {
        loop {
            unsafe {
                core::arch::asm!("wfe", options(nomem, nostack));
            }
        }
    }
}

pub(crate) fn handle_irq_exception(_slot: u8) {
    if !GIC_READY.load(Ordering::Relaxed) {
        return;
    }

    let gicc = gicc_base();
    let iar = mmio_read32(gicc, GICC_IAR);
    LAST_GICC_IAR_RAW.store(iar, Ordering::Relaxed);
    let intid = iar & 0x3FF;
    if intid >= GIC_SPURIOUS_INTID_MIN {
        return;
    }

    LAST_IRQ_ID.store(intid, Ordering::Relaxed);
    if intid == DISCOVERED_TIMER_INTID.load(Ordering::Relaxed) {
        TIMER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        let ticks = TIMER_TICKS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        crate::kernel_timer_tick_hook();
        SCHED_TICK_HOOK_COUNT.fetch_add(1, Ordering::Relaxed);
        if HEARTBEAT_TICKS != 0 && (ticks % HEARTBEAT_TICKS) == 0 {
            HEARTBEAT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if TIMER_READY.load(Ordering::Relaxed) {
            generic_timer_rearm();
        }
    } else if discovered_uart_irq_intid() == Some(intid) {
        UART_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        let _ = uart().masked_interrupt_status();
        let _ = uart().irq_drain_rx_to_buffer();
        uart().ack_interrupts();
    } else {
        if virtio_mmio_handle_irq(intid) {
            VIRTIO_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
        } else {
            let prev = UNKNOWN_IRQ_LOGGED.load(Ordering::Relaxed);
            if prev != intid {
                UNKNOWN_IRQ_LOGGED.store(intid, Ordering::Relaxed);
                let u = uart();
                u.write_str("[A64-IRQ] unhandled intid=");
                uart_write_hex_u64(intid as u64);
                uart_newline();
            }
        }
    }

    mmio_write32(gicc, GICC_EOIR, iar);
}

pub(crate) fn self_test_sync_exception() {
    let before = super::aarch64_vectors::sync_exception_count();
    early_log("[A64] running synchronous exception self-test (BRK)\n");
    super::aarch64_vectors::trigger_breakpoint();
    let after = super::aarch64_vectors::sync_exception_count();
    let u = uart();
    u.write_str("[A64] sync self-test count ");
    uart_write_hex_u64(before);
    u.write_str(" -> ");
    uart_write_hex_u64(after);
    u.write_str(" ok=");
    u.write_str(if after == before + 1 { "1" } else { "0" });
    uart_newline();
}

fn shell_print_boot_info() {
    let boot = crate::arch::boot_info();
    let u = uart();
    u.write_str("[A64] platform=");
    u.write_str(crate::arch::platform_name());
    u.write_str(" raw_info_ptr=");
    uart_write_hex_usize(boot.raw_info_ptr.unwrap_or(0));
    u.write_str(" dtb_ptr=");
    uart_write_hex_usize(boot.dtb_ptr.unwrap_or(0));
    u.write_str(" uart=");
    uart_write_hex_usize(uart().base());
    uart_newline();

    if let Some(cmd) = super::aarch64_dtb::bootargs_str(
        nonzero_ptr(BOOT_CMDLINE_PTR.load(Ordering::Relaxed)),
        BOOT_CMDLINE_LEN.load(Ordering::Relaxed),
    ) {
        u.write_str("[A64] bootargs=");
        u.write_str(cmd);
        uart_newline();
    }
}

fn shell_print_dtb_info() {
    let boot = crate::arch::boot_info();
    match boot.dtb_ptr.and_then(super::aarch64_dtb::parse_platform_info) {
        Some(info) => {
            let h = info.header;
            let u = uart();
            u.write_str("[A64] dtb total=");
            uart_write_hex_usize(h.total_size);
            u.write_str(" struct_off=");
            uart_write_hex_usize(h.off_dt_struct);
            u.write_str(" strings_off=");
            uart_write_hex_usize(h.off_dt_strings);
            u.write_str(" rsvmap_off=");
            uart_write_hex_usize(h.off_mem_rsvmap);
            uart_newline();

            u.write_str("[A64] dtb version=");
            uart_write_hex_u64(h.version as u64);
            u.write_str(" last_comp=");
            uart_write_hex_u64(h.last_comp_version as u64);
            uart_newline();

            if let Some(mem) = info.memory {
                u.write_str("[A64] dtb memory base=");
                uart_write_hex_usize(mem.base);
                u.write_str(" size=");
                uart_write_hex_usize(mem.size);
                uart_newline();
            }
            if let Some(base) = info.uart_pl011_base {
                u.write_str("[A64] dtb pl011=");
                uart_write_hex_usize(base);
                if let Some(intid) = info.uart_pl011_irq_intid {
                    u.write_str(" irq=");
                    uart_write_hex_u64(intid as u64);
                }
                uart_newline();
            }
            if let (Some(gd), Some(gc)) = (info.gic_dist_base, info.gic_cpu_base) {
                u.write_str("[A64] dtb gic dist=");
                uart_write_hex_usize(gd);
                u.write_str(" cpu=");
                uart_write_hex_usize(gc);
                uart_newline();
            }
            if let Some(intid) = info.timer_irq_intid {
                u.write_str("[A64] dtb timer-intid=");
                uart_write_hex_u64(intid as u64);
                uart_newline();
            }
            for dev in info.virtio_mmio.iter().take(info.virtio_mmio_count) {
                u.write_str("[A64] dtb virtio-mmio base=");
                uart_write_hex_usize(dev.base);
                u.write_str(" size=");
                uart_write_hex_usize(dev.size);
                u.write_str(" irq=");
                uart_write_hex_u64(dev.irq_intid.unwrap_or(u32::MAX) as u64);
                uart_newline();
            }
            if let Some(cmd) = info.chosen_bootargs_str() {
                u.write_str("[A64] dtb chosen.bootargs=");
                u.write_str(cmd);
                uart_newline();
            }
        }
        None => early_log("[A64] dtb: unavailable/invalid\n"),
    }
}

fn shell_print_regs() {
    let u = uart();
    u.write_str("[A64] CurrentEL=");
    uart_write_hex_u64(read_currentel());
    u.write_str(" DAIF=");
    uart_write_hex_u64(read_daif());
    u.write_str(" SCTLR_EL1=");
    uart_write_hex_u64(read_sctlr_el1());
    uart_newline();

    u.write_str("[A64] VBAR_EL1=");
    uart_write_hex_u64(read_vbar_el1());
    u.write_str(" TTBR0_EL1=");
    uart_write_hex_usize(crate::arch::mmu::current_page_table_root_addr());
    u.write_str(" TTBR1_EL1=");
    uart_write_hex_usize(crate::arch::mmu::kernel_page_table_root_addr().unwrap_or(0));
    uart_newline();

    u.write_str("[A64] CNTFRQ_EL0=");
    uart_write_hex_u64(TIMER_FREQ_HZ.load(Ordering::Relaxed));
    u.write_str(" CNTPCT_EL0=");
    uart_write_hex_u64(read_cntpct_el0());
    uart_newline();
}

fn shell_print_traps() {
    let u = uart();
    let sync = super::aarch64_vectors::sync_exception_count();
    let spx_sync = super::aarch64_vectors::vector_count(VectorSlot::CurrentElSpxSync as u8);
    let spx_irq = super::aarch64_vectors::vector_count(VectorSlot::CurrentElSpxIrq as u8);
    let lower_sync = super::aarch64_vectors::vector_count(VectorSlot::LowerElA64Sync as u8);
    let lower_irq = super::aarch64_vectors::vector_count(VectorSlot::LowerElA64Irq as u8);
    u.write_str("[A64] trap-counts sync=");
    uart_write_hex_u64(sync);
    u.write_str(" cur-spx-sync=");
    uart_write_hex_u64(spx_sync);
    u.write_str(" cur-spx-irq=");
    uart_write_hex_u64(spx_irq);
    u.write_str(" lower-a64-sync=");
    uart_write_hex_u64(lower_sync);
    u.write_str(" lower-a64-irq=");
    uart_write_hex_u64(lower_irq);
    uart_newline();
    super::aarch64_vectors::dump_last_exception();
}

fn shell_print_irqs() {
    let u = uart();
    u.write_str("[A64] irq gic_ready=");
    u.write_str(if GIC_READY.load(Ordering::Relaxed) { "1" } else { "0" });
    u.write_str(" timer_ready=");
    u.write_str(if TIMER_READY.load(Ordering::Relaxed) { "1" } else { "0" });
    u.write_str(" timer_intid=");
    uart_write_hex_u64(DISCOVERED_TIMER_INTID.load(Ordering::Relaxed) as u64);
    u.write_str(" uart_intid=");
    uart_write_hex_u64(discovered_uart_irq_intid().unwrap_or(u32::MAX) as u64);
    u.write_str(" last_irq=");
    uart_write_hex_u64(LAST_IRQ_ID.load(Ordering::Relaxed) as u64);
    uart_newline();

    u.write_str("[A64] irq-counts timer=");
    uart_write_hex_u64(TIMER_IRQ_COUNT.load(Ordering::Relaxed));
    u.write_str(" uart=");
    uart_write_hex_u64(UART_IRQ_COUNT.load(Ordering::Relaxed));
    u.write_str(" virtio=");
    uart_write_hex_u64(VIRTIO_IRQ_COUNT.load(Ordering::Relaxed));
    u.write_str(" virtio-ack=");
    uart_write_hex_u64(VIRTIO_IRQ_ACK_COUNT.load(Ordering::Relaxed));
    uart_newline();

    u.write_str("[A64] uart-rx-buffer len=");
    uart_write_hex_u64(uart().rx_buffer_len() as u64);
    u.write_str(" dropped=");
    uart_write_hex_u64(uart().rx_buffer_dropped());
    uart_newline();

    let count = DISCOVERED_VIRTIO_MMIO_COUNT.load(Ordering::Relaxed).min(MAX_TRACKED_VIRTIO_MMIO);
    for idx in 0..count {
        let base = DISCOVERED_VIRTIO_MMIO_BASES[idx].load(Ordering::Relaxed);
        let size = DISCOVERED_VIRTIO_MMIO_SIZES[idx].load(Ordering::Relaxed);
        let intid = DISCOVERED_VIRTIO_MMIO_IRQS[idx].load(Ordering::Relaxed);
        let irq_count = VIRTIO_MMIO_IRQ_COUNTS[idx].load(Ordering::Relaxed);
        let last_status = VIRTIO_MMIO_LAST_IRQ_STATUS[idx].load(Ordering::Relaxed);
        let magic = VIRTIO_MMIO_MAGIC[idx].load(Ordering::Relaxed);
        let ver = VIRTIO_MMIO_VERSION_REG[idx].load(Ordering::Relaxed);
        let dev = VIRTIO_MMIO_DEVICE_ID_REG[idx].load(Ordering::Relaxed);
        if base == 0 {
            continue;
        }
        u.write_str("[A64] virtio[");
        uart_write_hex_u64(idx as u64);
        u.write_str("] base=");
        uart_write_hex_usize(base);
        u.write_str(" size=");
        uart_write_hex_usize(size);
        u.write_str(" irq=");
        uart_write_hex_u64(intid as u64);
        u.write_str(" irq-count=");
        uart_write_hex_u64(irq_count);
        u.write_str(" last-status=");
        uart_write_hex_u64(last_status as u64);
        u.write_str(" probe=");
        uart_write_hex_u64(magic as u64);
        u.write_str("/");
        uart_write_hex_u64(ver as u64);
        u.write_str("/");
        uart_write_hex_u64(dev as u64);
        uart_newline();
    }
}

fn shell_print_ticks() {
    let u = uart();
    u.write_str("[A64] ticks=");
    uart_write_hex_u64(TIMER_TICKS.load(Ordering::Relaxed));
    u.write_str(" timer-irqs=");
    uart_write_hex_u64(TIMER_IRQ_COUNT.load(Ordering::Relaxed));
    u.write_str(" interval=");
    uart_write_hex_u64(TIMER_INTERVAL_TICKS.load(Ordering::Relaxed));
    u.write_str(" heartbeat=");
    uart_write_hex_u64(HEARTBEAT_COUNT.load(Ordering::Relaxed));
    u.write_str(" schedhook=");
    uart_write_hex_u64(SCHED_TICK_HOOK_COUNT.load(Ordering::Relaxed));
    uart_newline();
}

fn shell_print_scheduler_backend() {
    let (ticks, pending, requests, quantum, pos) = scheduler_tick_backend_snapshot();
    let u = uart();
    u.write_str("[A64] sched-backend ticks=");
    uart_write_hex_u64(ticks);
    u.write_str(" pending=");
    u.write_str(if pending { "1" } else { "0" });
    u.write_str(" requests=");
    uart_write_hex_u64(requests);
    u.write_str(" quantum=");
    uart_write_hex_u64(quantum);
    u.write_str(" pos=");
    uart_write_hex_u64(pos);
    uart_newline();
}

fn shell_print_uart_irq_diag() {
    let u = uart();
    u.write_str("[A64] uartirq strict=");
    u.write_str(if STRICT_UART_IRQ_MODE.load(Ordering::Relaxed) { "1" } else { "0" });
    u.write_str(" irq-count=");
    uart_write_hex_u64(UART_IRQ_COUNT.load(Ordering::Relaxed));
    uart_newline();

    u.write_str("[A64] pl011 FR=");
    uart_write_hex_u64(uart().flags() as u64);
    u.write_str(" RIS=");
    uart_write_hex_u64(uart().raw_interrupt_status() as u64);
    u.write_str(" MIS=");
    uart_write_hex_u64(uart().masked_interrupt_status() as u64);
    u.write_str(" IMSC=");
    uart_write_hex_u64(uart().interrupt_mask() as u64);
    uart_newline();

    if let Some(intid) = discovered_uart_irq_intid() {
        let snap = gicv2_snapshot_intid(gicd_base(), intid);
        let cpu = gicv2_snapshot_cpu_if(gicc_base());
        u.write_str("[A64] gic uart-intid=");
        uart_write_hex_u64(intid as u64);
        u.write_str(" en=");
        u.write_str(if snap.enabled { "1" } else { "0" });
        u.write_str(" pend=");
        u.write_str(if snap.pending { "1" } else { "0" });
        u.write_str(" act=");
        u.write_str(if snap.active { "1" } else { "0" });
        u.write_str(" prio=");
        uart_write_hex_u64(snap.priority as u64);
        u.write_str(" target=");
        uart_write_hex_u64(snap.target as u64);
        u.write_str(" icfgr=");
        uart_write_hex_u64(snap.cfg_bits as u64);
        uart_newline();

        u.write_str("[A64] gicc ctlr=");
        uart_write_hex_u64(cpu.ctlr as u64);
        u.write_str(" pmr=");
        uart_write_hex_u64(cpu.pmr as u64);
        u.write_str(" bpr=");
        uart_write_hex_u64(cpu.bpr as u64);
        u.write_str(" rpr=");
        uart_write_hex_u64(cpu.rpr as u64);
        u.write_str(" hppir=");
        uart_write_hex_u64(cpu.hppir as u64);
        u.write_str(" last-iar=");
        uart_write_hex_u64(cpu.last_iar_raw as u64);
        uart_newline();
    } else {
        u.write_str("[A64] gic uart-intid=<none>\n");
    }
}

fn shell_uartirq_reconfigure() {
    let Some(intid) = discovered_uart_irq_intid() else {
        early_log("[A64] uartirq fix: no UART SPI in DTB\n");
        return;
    };
    let gicd = gicd_base();
    gicv2_configure_spi(gicd, intid, 0x01, 0x30, false);
    uart().enable_rx_interrupts();
    early_log("[A64] uartirq fix: reapplied GIC SPI + PL011 RX IRQ mask\n");
    shell_print_uart_irq_diag();
}

fn shell_print_virtio_runtime() {
    let u = uart();
    let slot = VIRTIO_ACTIVE_SLOT.load(Ordering::Relaxed);
    u.write_str("[A64] virtio-active slot=");
    uart_write_hex_u64(if slot == usize::MAX { u64::MAX } else { slot as u64 });
    u.write_str(" init-ok=");
    u.write_str(if VIRTIO_ACTIVE_INIT_OK.load(Ordering::Relaxed) { "1" } else { "0" });
    u.write_str(" attempts=");
    uart_write_hex_u64(VIRTIO_ACTIVE_INIT_ATTEMPTS.load(Ordering::Relaxed));
    u.write_str(" fails=");
    uart_write_hex_u64(VIRTIO_ACTIVE_INIT_FAILS.load(Ordering::Relaxed));
    uart_newline();

    if slot != usize::MAX {
        u.write_str("[A64] virtio-active dev=");
        uart_write_hex_u64(VIRTIO_ACTIVE_DEVICE_ID.load(Ordering::Relaxed) as u64);
        u.write_str(" qsz=");
        uart_write_hex_u64(VIRTIO_ACTIVE_QUEUE_SIZE.load(Ordering::Relaxed) as u64);
        u.write_str(" qbase=");
        uart_write_hex_usize(VIRTIO_ACTIVE_QUEUE_BASE.load(Ordering::Relaxed));
        u.write_str(" desc_off=");
        uart_write_hex_usize(VIRTIO_ACTIVE_DESC_OFF.load(Ordering::Relaxed));
        u.write_str(" avail_off=");
        uart_write_hex_usize(VIRTIO_ACTIVE_AVAIL_OFF.load(Ordering::Relaxed));
        u.write_str(" used_off=");
        uart_write_hex_usize(VIRTIO_ACTIVE_USED_RING_OFF.load(Ordering::Relaxed));
        u.write_str(" used_idx=");
        uart_write_hex_u64(VIRTIO_ACTIVE_USED_IDX_LAST.load(Ordering::Relaxed) as u64);
        u.write_str(" used_adv=");
        uart_write_hex_u64(VIRTIO_ACTIVE_USED_ADVANCES.load(Ordering::Relaxed));
        u.write_str(" notify=");
        uart_write_hex_u64(VIRTIO_ACTIVE_NOTIFY_COUNT.load(Ordering::Relaxed));
        u.write_str(" hostfeat0=");
        if slot < MAX_TRACKED_VIRTIO_MMIO {
            uart_write_hex_u64(VIRTIO_MMIO_HOST_FEATURES0[slot].load(Ordering::Relaxed) as u64);
        } else {
            uart_write_hex_u64(0);
        }
        uart_newline();

        if VIRTIO_ACTIVE_DEVICE_ID.load(Ordering::Relaxed) == VIRTIO_MMIO_DEVICE_ID_BLOCK {
            u.write_str("[A64] virtio-blk cap-sectors=");
            uart_write_hex_u64(VIRTIO_BLK_CAPACITY_SECTORS.load(Ordering::Relaxed));
            u.write_str(" post=");
            uart_write_hex_u64(VIRTIO_BLK_REQ_POSTED.load(Ordering::Relaxed));
            u.write_str(" done=");
            uart_write_hex_u64(VIRTIO_BLK_REQ_COMPLETED.load(Ordering::Relaxed));
            u.write_str(" post-fails=");
            uart_write_hex_u64(VIRTIO_BLK_REQ_POST_FAILS.load(Ordering::Relaxed));
            u.write_str(" status=");
            uart_write_hex_u64(VIRTIO_BLK_REQ_LAST_STATUS.load(Ordering::Relaxed) as u64);
            u.write_str(" used-len=");
            uart_write_hex_u64(VIRTIO_BLK_REQ_LAST_USED_LEN.load(Ordering::Relaxed) as u64);
            uart_newline();
        }
    }
}

fn vm_map_self_test() -> Result<(), &'static str> {
    let mut space = crate::arch::mmu::AddressSpace::new()?;

    let code_va = 0x0040_0000usize;
    let stack_va = 0x0080_0000usize;
    let phys_map_va = 0x00C0_0000usize;

    crate::arch::mmu::alloc_user_pages(&mut space, code_va, 1, true)?;
    crate::arch::mmu::alloc_user_pages(&mut space, stack_va, 1, true)?;

    let phys_page = crate::arch::mmu::aarch64_alloc_debug_page()?;
    crate::arch::mmu::map_user_range_phys(&mut space, phys_map_va, phys_page, 4096, true)?;

    let old_root = crate::arch::mmu::current_page_table_root_addr();
    unsafe { space.activate(); }

    unsafe {
        (code_va as *mut u8).write(0xC3);
        (stack_va as *mut u8).write(0x5A);
        (phys_map_va as *mut u8).write(0xA5);
    }

    let code_byte = unsafe { (code_va as *const u8).read() };
    let stack_byte = unsafe { (stack_va as *const u8).read() };
    let phys_byte = unsafe { (phys_map_va as *const u8).read() };

    crate::arch::mmu::set_page_table_root(old_root)?;
    crate::arch::mmu::unmap_page(&mut space, code_va)?;
    crate::arch::mmu::unmap_page(&mut space, stack_va)?;
    crate::arch::mmu::unmap_page(&mut space, phys_map_va)?;

    let u = uart();
    u.write_str("[A64] vmtest old-root=");
    uart_write_hex_usize(old_root);
    u.write_str(" new-root=");
    uart_write_hex_usize(space.page_table_root_addr());
    u.write_str(" bytes=");
    uart_write_hex_u64(code_byte as u64);
    u.write_str("/");
    uart_write_hex_u64(stack_byte as u64);
    u.write_str("/");
    uart_write_hex_u64(phys_byte as u64);
    uart_newline();

    if code_byte != 0xC3 || stack_byte != 0x5A || phys_byte != 0xA5 {
        return Err("write/read verification failed");
    }
    if space.page_table_root_addr() == old_root {
        return Err("AddressSpace::new reused active TTBR0 root");
    }
    Ok(())
}

fn parse_u64_decimal(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?;
        value = value.checked_add((b - b'0') as u64)?;
    }
    Some(value)
}

fn shell_exec_command(cmd: &str) -> bool {
    if cmd == "uartirq" {
        shell_print_uart_irq_diag();
        return true;
    }
    if cmd == "uartirq fix" || cmd == "uartirq reconfig" {
        shell_uartirq_reconfigure();
        return true;
    }
    if let Some(arg) = cmd.strip_prefix("strict-uart-irq ") {
        match arg.trim() {
            "on" | "1" | "enable" => {
                STRICT_UART_IRQ_MODE.store(true, Ordering::Relaxed);
                early_log("[A64] strict-uart-irq=on\n");
            }
            "off" | "0" | "disable" => {
                STRICT_UART_IRQ_MODE.store(false, Ordering::Relaxed);
                early_log("[A64] strict-uart-irq=off\n");
            }
            _ => early_log("[A64] usage: strict-uart-irq on|off\n"),
        }
        shell_print_uart_irq_diag();
        return true;
    }
    if cmd == "strict-uart-irq" {
        shell_print_uart_irq_diag();
        return true;
    }
    if cmd == "sched" {
        shell_print_scheduler_backend();
        return true;
    }
    if cmd == "sched clear" {
        scheduler_tick_backend_clear_pending();
        shell_print_scheduler_backend();
        return true;
    }
    if let Some(arg) = cmd.strip_prefix("sched quantum ") {
        match parse_u64_decimal(arg.trim()).and_then(|v| scheduler_tick_backend_set_quantum(v).ok().map(|_| v)) {
            Some(v) => {
                let u = uart();
                u.write_str("[A64] sched quantum set=");
                uart_write_hex_u64(v);
                uart_newline();
            }
            None => early_log("[A64] usage: sched quantum <ticks>\n"),
        }
        shell_print_scheduler_backend();
        return true;
    }
    if cmd == "virtio" {
        shell_print_virtio_runtime();
        return true;
    }
    if cmd == "virtio init" || cmd == "virtio reinit" {
        virtio_mmio_probe_all();
        virtio_mmio_bringup_one();
        shell_print_virtio_runtime();
        return true;
    }

    match cmd {
        "" => {}
        "help" => {
            early_log("[A64] commands: help boot dtb mmu regs traps irqs uartirq strict-uart-irq ticks sched virtio brk vectors vmtest halt\n");
        }
        "boot" => shell_print_boot_info(),
        "dtb" => shell_print_dtb_info(),
        "mmu" => {
            let u = uart();
            u.write_str("[A64] mmu backend=");
            u.write_str(crate::arch::mmu::backend_name());
            u.write_str(" ttbr0=");
            uart_write_hex_usize(crate::arch::mmu::current_page_table_root_addr());
            u.write_str(" ttbr1=");
            uart_write_hex_usize(crate::arch::mmu::kernel_page_table_root_addr().unwrap_or(0));
            uart_newline();
        }
        "regs" => shell_print_regs(),
        "traps" => shell_print_traps(),
        "irqs" => shell_print_irqs(),
        "ticks" => shell_print_ticks(),
        "vectors" => {
            let u = uart();
            u.write_str("[A64] vectors installed=");
            u.write_str(if super::aarch64_vectors::vectors_installed() { "1" } else { "0" });
            u.write_str(" base=");
            uart_write_hex_usize(super::aarch64_vectors::vector_base());
            u.write_str(" vbar=");
            uart_write_hex_u64(read_vbar_el1());
            uart_newline();
        }
        "brk" | "sync" => {
            early_log("[A64] triggering BRK\n");
            super::aarch64_vectors::trigger_breakpoint();
            shell_print_traps();
        }
        "vmtest" => match vm_map_self_test() {
            Ok(()) => early_log("[A64] vmtest ok\n"),
            Err(e) => {
                let u = uart();
                u.write_str("[A64] vmtest failed: ");
                u.write_str(e);
                uart_newline();
            }
        },
        "halt" | "exit" => {
            early_log("[A64] halting\n");
            return false;
        }
        _ => {
            let u = uart();
            u.write_str("[A64] unknown command: ");
            u.write_str(cmd);
            uart_newline();
        }
    }
    true
}

pub(crate) fn run_serial_shell() -> ! {
    ensure_uart();
    early_log("[A64] minimal serial shell ready (type 'help')\n");
    shell_prompt();

    let mut buf = [0u8; 128];
    let mut len = 0usize;

    loop {
        if let Some(byte) = shell_try_read_input_byte() {
            match byte {
                b'\r' | b'\n' => {
                    uart_newline();
                    let cmd = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    let keep_running = shell_exec_command(cmd.trim());
                    len = 0;
                    if !keep_running {
                        crate::arch::halt_loop();
                    }
                    shell_prompt();
                }
                8 | 127 => {
                    if len > 0 {
                        len -= 1;
                        uart().write_str("\x08 \x08");
                    }
                }
                b if (0x20..=0x7E).contains(&b) => {
                    if len < buf.len() - 1 {
                        buf[len] = b;
                        len += 1;
                        uart().write_byte(b);
                    }
                }
                _ => {}
            }
        } else {
            unsafe {
                core::arch::asm!("wfi", options(nomem, nostack));
            }
        }
    }
}
