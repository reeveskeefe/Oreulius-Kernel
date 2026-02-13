//! VirtIO Block Driver (legacy PCI)
//!
//! Provides basic sector read/write, simple partition parsing, and a small cache.

#![allow(dead_code)]

use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};
use spin::Mutex;

use crate::pci::PciDevice;

// VirtIO PCI legacy IDs
const VIRTIO_PCI_VENDOR: u16 = 0x1AF4;
const VIRTIO_BLK_LEGACY_ID: u16 = 0x1001;
const VIRTIO_BLK_MODERN_ID: u16 = 0x1042;

// VirtIO PCI I/O register offsets (legacy)
const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_SIZE: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SELECT: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_ISR: u16 = 0x13;
const VIRTIO_PCI_CONFIG: u16 = 0x14;

// VirtIO status bits
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 0x80;

// Virtqueue descriptor flags
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// Block request types
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

const SECTOR_SIZE: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlkReq {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

struct VirtQueue {
    size: u16,
    mem: *mut u8,
    mem_size: usize,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    last_used: u16,
}

impl VirtQueue {
    fn new(size: u16) -> Result<Self, &'static str> {
        let qsize = size as usize;
        if qsize == 0 || qsize > 256 {
            return Err("Invalid queue size");
        }

        let desc_size = 16 * qsize;
        let avail_size = 4 + 2 * qsize + 2; // flags+idx + ring + used_event
        let used_size = 4 + 8 * qsize + 2;  // flags+idx + ring + avail_event
        let used_off = align_up(desc_size + avail_size, 4);
        let total_size = align_up(used_off + used_size, 4096);

        let layout = alloc::alloc::Layout::from_size_align(total_size, 4096).map_err(|_| "bad layout")?;
        let mem = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if mem.is_null() {
            return Err("Failed to allocate virtqueue");
        }

        let desc = mem as *mut VirtqDesc;
        let avail = unsafe { mem.add(desc_size) } as *mut VirtqAvail;
        let used = unsafe { mem.add(used_off) } as *mut VirtqUsed;

        Ok(VirtQueue {
            size,
            mem,
            mem_size: total_size,
            desc,
            avail,
            used,
            last_used: 0,
        })
    }

    fn pfn(&self) -> u32 {
        (self.mem as usize >> 12) as u32
    }

    #[inline]
    unsafe fn avail_idx_ptr(&self) -> *mut u16 {
        (self.avail as *mut u8).add(2) as *mut u16
    }

    #[inline]
    unsafe fn avail_ring_ptr(&self) -> *mut u16 {
        (self.avail as *mut u8).add(4) as *mut u16
    }

    #[inline]
    unsafe fn used_idx_ptr(&self) -> *mut u16 {
        (self.used as *mut u8).add(2) as *mut u16
    }

    #[inline]
    unsafe fn used_ring_ptr(&self) -> *mut VirtqUsedElem {
        (self.used as *mut u8).add(4) as *mut VirtqUsedElem
    }

    unsafe fn push(&mut self, desc_idx: u16) {
        let idx = read_volatile(self.avail_idx_ptr());
        let ring_idx = (idx % self.size) as usize;
        write_volatile(self.avail_ring_ptr().add(ring_idx), desc_idx);
        compiler_fence(Ordering::SeqCst);
        write_volatile(self.avail_idx_ptr(), idx.wrapping_add(1));
    }

    unsafe fn pop_used(&mut self) -> Option<VirtqUsedElem> {
        let idx = read_volatile(self.used_idx_ptr());
        if idx == self.last_used {
            return None;
        }
        let ring_idx = (self.last_used % self.size) as usize;
        let elem = read_volatile(self.used_ring_ptr().add(ring_idx));
        self.last_used = self.last_used.wrapping_add(1);
        Some(elem)
    }
}

struct BlockCacheEntry {
    valid: bool,
    sector: u64,
    data: [u8; SECTOR_SIZE],
    last_used: u64,
}

struct BlockCache {
    entries: [BlockCacheEntry; 16],
    tick: u64,
}

impl BlockCache {
    const fn new() -> Self {
        const EMPTY: BlockCacheEntry = BlockCacheEntry {
            valid: false,
            sector: 0,
            data: [0; SECTOR_SIZE],
            last_used: 0,
        };
        BlockCache {
            entries: [EMPTY; 16],
            tick: 0,
        }
    }

    fn get(&mut self, sector: u64, out: &mut [u8]) -> bool {
        self.tick = self.tick.wrapping_add(1);
        for entry in &mut self.entries {
            if entry.valid && entry.sector == sector {
                out[..SECTOR_SIZE].copy_from_slice(&entry.data);
                entry.last_used = self.tick;
                return true;
            }
        }
        false
    }

    fn put(&mut self, sector: u64, data: &[u8]) {
        self.tick = self.tick.wrapping_add(1);
        let mut victim = 0;
        let mut oldest_time = u64::MAX;
        
        // LRU eviction: find oldest entry or first invalid slot
        for (i, entry) in self.entries.iter().enumerate() {
            if !entry.valid {
                // Empty slot found - use it immediately
                victim = i;
                break;
            }
            if entry.last_used < oldest_time {
                oldest_time = entry.last_used;
                victim = i;
            }
        }

        let entry = &mut self.entries[victim];
        entry.valid = true;
        entry.sector = sector;
        entry.data.copy_from_slice(&data[..SECTOR_SIZE]);
        entry.last_used = self.tick;
    }
}

pub struct VirtioBlk {
    pci: PciDevice,
    io_base: u16,
    queue: VirtQueue,
    capacity_sectors: u64,
    cache: BlockCache,
    req: VirtioBlkReq,
    status: u8,
}

// Safe because access is serialized through the global spin::Mutex.
unsafe impl Send for VirtioBlk {}

impl VirtioBlk {
    fn io_read_u32(&self, offset: u16) -> u32 {
        unsafe { inl(self.io_base + offset) }
    }

    fn io_write_u32(&self, offset: u16, val: u32) {
        unsafe { outl(self.io_base + offset, val) }
    }

    fn io_read_u16(&self, offset: u16) -> u16 {
        unsafe { inw(self.io_base + offset) }
    }

    fn io_write_u16(&self, offset: u16, val: u16) {
        unsafe { outw(self.io_base + offset, val) }
    }

    fn io_read_u8(&self, offset: u16) -> u8 {
        unsafe { inb(self.io_base + offset) }
    }

    fn io_write_u8(&self, offset: u16, val: u8) {
        unsafe { outb(self.io_base + offset, val) }
    }

    fn read_config_u64(&self, offset: u16) -> u64 {
        let lo = self.io_read_u32(offset) as u64;
        let hi = self.io_read_u32(offset + 4) as u64;
        lo | (hi << 32)
    }

    fn submit(&mut self, req_type: u32, sector: u64, buffer: *mut u8, write: bool) -> Result<(), &'static str> {
        let size = self.queue.size as usize;
        if size < 3 {
            return Err("Queue too small");
        }

        self.req.req_type = req_type;
        self.req.reserved = 0;
        self.req.sector = sector;
        self.status = 0xFF;

        unsafe {
            // descriptor 0: header
            (*self.queue.desc.add(0)) = VirtqDesc {
                addr: (&self.req as *const VirtioBlkReq as u64),
                len: size_of::<VirtioBlkReq>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            };
            // descriptor 1: data
            (*self.queue.desc.add(1)) = VirtqDesc {
                addr: buffer as u64,
                len: SECTOR_SIZE as u32,
                flags: if write { VIRTQ_DESC_F_NEXT } else { VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE },
                next: 2,
            };
            // descriptor 2: status
            (*self.queue.desc.add(2)) = VirtqDesc {
                addr: (&self.status as *const u8 as u64),
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            };

            compiler_fence(Ordering::SeqCst);
            self.queue.push(0);
            compiler_fence(Ordering::SeqCst);
            self.io_write_u16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
        }

        loop {
            if let Some(_elem) = unsafe { self.queue.pop_used() } {
                break;
            }
        }

        if self.status != 0 {
            return Err("I/O error");
        }
        Ok(())
    }

    fn read_sector_raw(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        if buf.len() < SECTOR_SIZE {
            return Err("buffer too small");
        }
        self.submit(VIRTIO_BLK_T_IN, lba, buf.as_mut_ptr(), false)
    }

    fn write_sector_raw(&mut self, lba: u64, buf: &[u8]) -> Result<(), &'static str> {
        if buf.len() < SECTOR_SIZE {
            return Err("buffer too small");
        }
        let ptr = buf.as_ptr() as *mut u8;
        self.submit(VIRTIO_BLK_T_OUT, lba, ptr, true)
    }

    fn read_sector_cached(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        if self.cache.get(lba, buf) {
            return Ok(());
        }
        self.read_sector_raw(lba, buf)?;
        self.cache.put(lba, buf);
        Ok(())
    }

    fn write_sector_cached(&mut self, lba: u64, buf: &[u8]) -> Result<(), &'static str> {
        self.write_sector_raw(lba, buf)?;
        self.cache.put(lba, buf);
        Ok(())
    }
}

static VIRTIO_BLK: Mutex<Option<VirtioBlk>> = Mutex::new(None);

pub fn init(device: PciDevice) -> Result<(), &'static str> {
    if device.vendor_id != VIRTIO_PCI_VENDOR {
        return Err("Not virtio");
    }
    if device.device_id != VIRTIO_BLK_LEGACY_ID && device.device_id != VIRTIO_BLK_MODERN_ID {
        return Err("Not virtio block");
    }

    unsafe {
        device.enable_bus_mastering();
        device.enable_io_space();
    }

    let bar0 = unsafe { device.read_bar(0) };
    if (bar0 & 0x1) == 0 {
        return Err("VirtIO block expects I/O BAR");
    }
    let io_base = (bar0 & 0xFFFC) as u16;

    unsafe {
        // Reset and announce driver
        outb(io_base + VIRTIO_PCI_STATUS, 0);
        outb(io_base + VIRTIO_PCI_STATUS, STATUS_ACKNOWLEDGE);
        outb(io_base + VIRTIO_PCI_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Negotiate features (none for now)
        let _features = inl(io_base + VIRTIO_PCI_HOST_FEATURES);
        outl(io_base + VIRTIO_PCI_GUEST_FEATURES, 0);

        // Select queue 0
        outw(io_base + VIRTIO_PCI_QUEUE_SELECT, 0);
    }

    let qsize = unsafe { inw(io_base + VIRTIO_PCI_QUEUE_SIZE) };
    if qsize == 0 {
        unsafe { outb(io_base + VIRTIO_PCI_STATUS, STATUS_FAILED) };
        return Err("Queue size 0");
    }

    let queue = VirtQueue::new(qsize)?;
    unsafe {
        outl(io_base + VIRTIO_PCI_QUEUE_PFN, queue.pfn());
    }

    let capacity = {
        let lo = unsafe { inl(io_base + VIRTIO_PCI_CONFIG) } as u64;
        let hi = unsafe { inl(io_base + VIRTIO_PCI_CONFIG + 4) } as u64;
        lo | (hi << 32)
    };

    let driver = VirtioBlk {
        pci: device,
        io_base,
        queue,
        capacity_sectors: capacity,
        cache: BlockCache::new(),
        req: VirtioBlkReq { req_type: 0, reserved: 0, sector: 0 },
        status: 0,
    };

    unsafe {
        outb(io_base + VIRTIO_PCI_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK);
        inb(io_base + VIRTIO_PCI_ISR); // clear
    }

    *VIRTIO_BLK.lock() = Some(driver);
    Ok(())
}

pub fn is_present() -> bool {
    VIRTIO_BLK.lock().is_some()
}

pub fn capacity_sectors() -> Option<u64> {
    VIRTIO_BLK.lock().as_ref().map(|d| d.capacity_sectors)
}

pub fn read_sector(lba: u64, buf: &mut [u8]) -> Result<(), &'static str> {
    let mut guard = VIRTIO_BLK.lock();
    let dev = guard.as_mut().ok_or("No virtio block device")?;
    dev.read_sector_cached(lba, buf)
}

pub fn write_sector(lba: u64, buf: &[u8]) -> Result<(), &'static str> {
    let mut guard = VIRTIO_BLK.lock();
    let dev = guard.as_mut().ok_or("No virtio block device")?;
    dev.write_sector_cached(lba, buf)
}

// --------------------------------------------------------------------------
// Partition parsing (MBR + basic GPT)
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct MbrPartition {
    pub bootable: bool,
    pub part_type: u8,
    pub lba_start: u32,
    pub sectors: u32,
}

#[derive(Clone, Copy)]
pub struct GptPartition {
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: [u8; 36],
}

pub fn read_partitions(mbr_out: &mut [Option<MbrPartition>; 4], gpt_out: &mut [Option<GptPartition>; 4]) -> Result<(), &'static str> {
    for entry in mbr_out.iter_mut() {
        *entry = None;
    }
    for entry in gpt_out.iter_mut() {
        *entry = None;
    }

    let mut sector0 = [0u8; SECTOR_SIZE];
    read_sector(0, &mut sector0)?;
    
    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return Err("Invalid MBR signature");
    }
    
    for i in 0..4 {
        let off = 446 + i * 16;
        let boot = sector0[off] == 0x80;
        let part_type = sector0[off + 4];
        let lba_start = u32::from_le_bytes([sector0[off + 8], sector0[off + 9], sector0[off + 10], sector0[off + 11]]);
        let sectors = u32::from_le_bytes([sector0[off + 12], sector0[off + 13], sector0[off + 14], sector0[off + 15]]);
        if part_type != 0 {
            mbr_out[i] = Some(MbrPartition { bootable: boot, part_type, lba_start, sectors });
        }
    }
    
    // Detect GPT protective MBR (type 0xEE)
    let has_gpt = mbr_out.iter().any(|p| p.map(|pp| pp.part_type == 0xEE).unwrap_or(false));
    if !has_gpt {
        return Ok(());
    }
    
    let mut gpt_header = [0u8; SECTOR_SIZE];
    read_sector(1, &mut gpt_header)?;
    if &gpt_header[0..8] != b"EFI PART" {
        return Err("GPT signature not found");
    }
    
    let entries_lba = u64::from_le_bytes([
        gpt_header[72], gpt_header[73], gpt_header[74], gpt_header[75],
        gpt_header[76], gpt_header[77], gpt_header[78], gpt_header[79],
    ]);
    let entry_size = u32::from_le_bytes([gpt_header[84], gpt_header[85], gpt_header[86], gpt_header[87]]) as usize;
    if entry_size < 128 {
        return Err("GPT entry size too small");
    }
    
    let mut entries_sector = [0u8; SECTOR_SIZE];
    read_sector(entries_lba, &mut entries_sector)?;
    
    for i in 0..4 {
        let off = i * entry_size;
        if off + 128 > SECTOR_SIZE {
            break;
        }
        let first_lba = u64::from_le_bytes([
            entries_sector[off + 32], entries_sector[off + 33], entries_sector[off + 34], entries_sector[off + 35],
            entries_sector[off + 36], entries_sector[off + 37], entries_sector[off + 38], entries_sector[off + 39],
        ]);
        let last_lba = u64::from_le_bytes([
            entries_sector[off + 40], entries_sector[off + 41], entries_sector[off + 42], entries_sector[off + 43],
            entries_sector[off + 44], entries_sector[off + 45], entries_sector[off + 46], entries_sector[off + 47],
        ]);
        if first_lba == 0 && last_lba == 0 {
            continue;
        }
        
        let mut name = [0u8; 36];
        let name_off = off + 56;
        for j in 0..36 {
            name[j] = entries_sector[name_off + j * 2];
        }
        
        gpt_out[i] = Some(GptPartition { first_lba, last_lba, name });
    }
    
    Ok(())
}

// --------------------------------------------------------------------------
// Low-level I/O
// --------------------------------------------------------------------------

#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn outw(port: u16, value: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    value
}

#[inline]
unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    core::arch::asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack, preserves_flags));
    value
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags));
    value
}

#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
