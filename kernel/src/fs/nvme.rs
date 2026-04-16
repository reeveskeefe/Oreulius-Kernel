// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

//! NVMe (Non-Volatile Memory Express) storage driver
//!
//! # Architecture
//!
//! ```text
//!  PCI scan → class 0x01 / subclass 0x08 → NvmeController::init()
//!       ├─ BAR0 MMIO (64-bit)
//!       ├─ Controller reset (CC.EN=0 → CSTS.RDY=0)
//!       ├─ Admin SQ/CQ setup (64 entries each)
//!       ├─ Set IO SQ/CQ sizes in AQA
//!       ├─ Controller start (CC.EN=1 → CSTS.RDY=1)
//!       ├─ IDENTIFY CNS=1 → controller capabilities (MDTS)
//!       ├─ IDENTIFY CNS=0 → namespace 1 FLBAS → block size
//!       ├─ CREATE IO CQ  (Admin command 0x05)
//!       └─ CREATE IO SQ  (Admin command 0x01)
//!
//!  READ / WRITE NVM submitted on IO SQ via:
//!       NvmeController::read_sectors(lba, count, buf)
//!       NvmeController::write_sectors(lba, count, buf)
//!
//!  Completion via polling CQ phase bit (no MSI/IRQ in early boot).
//! ```
//!
//! # Memory model
//!
//! All queues and data buffers are static (identity-mapped physaddr==virtaddr).
//! Maximum transfer: MDTS pages (we cap at 128 KiB = 32 × 4K pages).
#![allow(dead_code)] // hardware register table — constants reserved for full NVMe implementation
#![allow(non_upper_case_globals)] // NVMe spec uses mixed-case doorbell names (SQnTDBL, CQnHDBL)

use crate::drivers::x86::pci::PciDevice;
use spin::Mutex;

// ============================================================================
// PCI class constants
// ============================================================================

const PCI_CLASS_STORAGE: u8 = 0x01;
const PCI_SUBCLASS_NVME: u8 = 0x08;

// ============================================================================
// NVMe MMIO register offsets (CAP through SQNDBS)
// ============================================================================

const NVME_CAP: usize = 0x00; // u64 Controller Capabilities
const NVME_VS: usize = 0x08; // u32 Version
const NVME_INTMS: usize = 0x0C; // u32 Interrupt Mask Set
const NVME_INTMC: usize = 0x10; // u32 Interrupt Mask Clear
const NVME_CC: usize = 0x14; // u32 Controller Configuration
const NVME_CSTS: usize = 0x1C; // u32 Controller Status
const NVME_AQA: usize = 0x24; // u32 Admin Queue Attributes
const NVME_ASQ: usize = 0x28; // u64 Admin Submission Queue Base Address
const NVME_ACQ: usize = 0x30; // u64 Admin Completion Queue Base Address
const NVME_SQnTDBL: usize = 0x1000; // Submission Queue n Tail Doorbell
const NVME_CQnHDBL: usize = 0x1004; // Completion Queue n Head Doorbell

// CC register fields
const NVME_CC_EN: u32 = 1 << 0;
const NVME_CC_CSS_NVM: u32 = 0 << 4; // NVM Command Set
const NVME_CC_MPS_4K: u32 = 0 << 7; // Memory Page Size = 4096 (MPS=0)
const NVME_CC_AMS_RR: u32 = 0 << 11; // Arbitration = Round Robin
const NVME_CC_IOSQES: u32 = 6 << 16; // IO SQ Entry Size = 2^6 = 64
const NVME_CC_IOCQES: u32 = 4 << 20; // IO CQ Entry Size = 2^4 = 16

// CSTS register fields
const NVME_CSTS_RDY: u32 = 1 << 0;
const NVME_CSTS_CFS: u32 = 1 << 1;

// Admin command opcodes
const NVME_ADMIN_DELETE_IO_SQ: u8 = 0x00;
const NVME_ADMIN_CREATE_IO_SQ: u8 = 0x01;
const NVME_ADMIN_DELETE_IO_CQ: u8 = 0x04;
const NVME_ADMIN_CREATE_IO_CQ: u8 = 0x05;
const NVME_ADMIN_IDENTIFY: u8 = 0x06;
const NVME_ADMIN_ABORT: u8 = 0x08;
const NVME_ADMIN_SET_FEATURES: u8 = 0x09;
const NVME_ADMIN_GET_FEATURES: u8 = 0x0A;

// NVM command opcodes
const NVME_CMD_FLUSH: u8 = 0x00;
const NVME_CMD_WRITE: u8 = 0x01;
const NVME_CMD_READ: u8 = 0x02;

// ============================================================================
// NVMe queue entry sizes
// ============================================================================

const NVME_ADMIN_QUEUE_DEPTH: usize = 64; // entries per Admin SQ/CQ
const NVME_IO_QUEUE_DEPTH: usize = 256; // entries per IO SQ/CQ
const NVME_SQE_SIZE: usize = 64; // Submission Queue Entry: 64 bytes
const NVME_CQE_SIZE: usize = 16; // Completion Queue Entry: 16 bytes

/// Maximum data transfer = 128 KiB (32 × 4K pages via PRP list)
const NVME_MAX_TRANSFER: usize = 128 * 1024;
const NVME_PAGE_SIZE: usize = 4096;
const NVME_MAX_PRP_ENTRIES: usize = NVME_MAX_TRANSFER / NVME_PAGE_SIZE;

// ============================================================================
// Submission Queue Entry (SQE) — 64 bytes
// ============================================================================

#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
pub struct NvmeSqe {
    pub cdw0: u32, // [3:0]=OPC [15:14]=FUSE [21:16]=PSDT [31:16]=CID
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64, // Metadata Pointer
    pub prp1: u64, // PRP1 (first data buffer page)
    pub prp2: u64, // PRP2 (second page or PRP list pointer)
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

// ============================================================================
// Completion Queue Entry (CQE) — 16 bytes
// ============================================================================

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct NvmeCqe {
    pub dw0: u32,          // command-specific result
    pub dw1: u32,          // reserved
    pub sq_hd: u16,        // SQ Head Pointer
    pub sq_id: u16,        // SQ Identifier
    pub cid: u16,          // Command Identifier
    pub phase_status: u16, // bit 0 = Phase Tag; bits 15:1 = Status Field
}

impl NvmeCqe {
    pub fn phase(&self) -> bool {
        self.phase_status & 1 != 0
    }
    pub fn status(&self) -> u16 {
        (self.phase_status >> 1) & 0x7FFF
    }
}

// ============================================================================
// Static queue storage (identity-mapped)
// ============================================================================

#[repr(C, align(4096))]
struct AdminSqBuf {
    data: [NvmeSqe; NVME_ADMIN_QUEUE_DEPTH],
}
#[repr(C, align(4096))]
struct AdminCqBuf {
    data: [NvmeCqe; NVME_ADMIN_QUEUE_DEPTH],
}
#[repr(C, align(4096))]
struct IoSqBuf {
    data: [NvmeSqe; NVME_IO_QUEUE_DEPTH],
}
#[repr(C, align(4096))]
struct IoCqBuf {
    data: [NvmeCqe; NVME_IO_QUEUE_DEPTH],
}

static mut NVME_ADMIN_SQ: AdminSqBuf = AdminSqBuf {
    data: [NvmeSqe {
        cdw0: 0,
        nsid: 0,
        cdw2: 0,
        cdw3: 0,
        mptr: 0,
        prp1: 0,
        prp2: 0,
        cdw10: 0,
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    }; NVME_ADMIN_QUEUE_DEPTH],
};
static mut NVME_ADMIN_CQ: AdminCqBuf = AdminCqBuf {
    data: [NvmeCqe {
        dw0: 0,
        dw1: 0,
        sq_hd: 0,
        sq_id: 0,
        cid: 0,
        phase_status: 0,
    }; NVME_ADMIN_QUEUE_DEPTH],
};
static mut NVME_IO_SQ: IoSqBuf = IoSqBuf {
    data: [NvmeSqe {
        cdw0: 0,
        nsid: 0,
        cdw2: 0,
        cdw3: 0,
        mptr: 0,
        prp1: 0,
        prp2: 0,
        cdw10: 0,
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    }; NVME_IO_QUEUE_DEPTH],
};
static mut NVME_IO_CQ: IoCqBuf = IoCqBuf {
    data: [NvmeCqe {
        dw0: 0,
        dw1: 0,
        sq_hd: 0,
        sq_id: 0,
        cid: 0,
        phase_status: 0,
    }; NVME_IO_QUEUE_DEPTH],
};

/// PRP list for multi-page transfers (up to 128 KiB = 32 pages).
#[repr(C, align(4096))]
struct PrpList {
    entries: [u64; NVME_MAX_PRP_ENTRIES],
}
static mut NVME_PRP_LIST: PrpList = PrpList {
    entries: [0u64; NVME_MAX_PRP_ENTRIES],
};

/// Identify buffer (4 KiB).
#[repr(C, align(4096))]
struct IdentifyBuf {
    data: [u8; 4096],
}
static mut NVME_IDENTIFY_BUF: IdentifyBuf = IdentifyBuf { data: [0u8; 4096] };

// ============================================================================
// NVMe Controller
// ============================================================================

pub struct NvmeController {
    pub mmio_base: usize,
    pub pci: PciDevice,
    pub initialised: bool,
    pub block_size: u64,
    pub num_blocks: u64,
    pub ns1_id: u32,
    /// Doorbell stride in bytes (2^(2 + DSTRD))
    dstrd: usize,
    /// Admin SQ tail (shadow)
    admin_sq_tail: usize,
    /// Admin CQ head (shadow) + expected phase
    admin_cq_head: usize,
    admin_cq_phase: bool,
    /// IO SQ tail / CQ head
    io_sq_tail: usize,
    io_cq_head: usize,
    io_cq_phase: bool,
    /// Next Command Identifier
    next_cid: u16,
}

impl NvmeController {
    pub fn new(mmio_base: usize, pci: PciDevice) -> Self {
        NvmeController {
            mmio_base,
            pci,
            initialised: false,
            block_size: 512,
            num_blocks: 0,
            ns1_id: 1,
            dstrd: 4,
            admin_sq_tail: 0,
            admin_cq_head: 0,
            admin_cq_phase: true,
            io_sq_tail: 0,
            io_cq_head: 0,
            io_cq_phase: true,
            next_cid: 1,
        }
    }

    // ----------------------------------------------------------------
    // MMIO helpers
    // ----------------------------------------------------------------

    unsafe fn read32(&self, off: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u32)
    }
    unsafe fn read64(&self, off: usize) -> u64 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u64)
    }
    unsafe fn write32(&self, off: usize, v: u32) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u32, v);
    }
    unsafe fn write64(&self, off: usize, v: u64) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u64, v);
    }

    fn delay(&self) {
        for _ in 0..50_000u32 {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    // ----------------------------------------------------------------
    // Doorbell helpers
    // ----------------------------------------------------------------

    /// Write Admin SQ tail doorbell.
    unsafe fn ring_admin_sq(&self) {
        let off = NVME_SQnTDBL; // Admin SQ = queue 0
        self.write32(off, self.admin_sq_tail as u32);
    }
    /// Write Admin CQ head doorbell.
    unsafe fn ring_admin_cq(&self) {
        let off = NVME_CQnHDBL; // Admin CQ = queue 0
        self.write32(off, self.admin_cq_head as u32);
    }
    /// Write IO SQ tail doorbell (queue 1, dstrd-offset).
    unsafe fn ring_io_sq(&self) {
        let off = NVME_SQnTDBL + 2 * self.dstrd;
        self.write32(off, self.io_sq_tail as u32);
    }
    /// Write IO CQ head doorbell.
    unsafe fn ring_io_cq(&self) {
        let off = NVME_CQnHDBL + 2 * self.dstrd;
        self.write32(off, self.io_cq_head as u32);
    }

    // ----------------------------------------------------------------
    // Command submission helpers
    // ----------------------------------------------------------------

    fn alloc_cid(&mut self) -> u16 {
        let id = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        id
    }

    unsafe fn submit_admin_cmd(&mut self, sqe: NvmeSqe) -> u16 {
        let cid = (sqe.cdw0 >> 16) as u16;
        NVME_ADMIN_SQ.data[self.admin_sq_tail] = sqe;
        self.admin_sq_tail = (self.admin_sq_tail + 1) % NVME_ADMIN_QUEUE_DEPTH;
        self.ring_admin_sq();
        cid
    }

    unsafe fn submit_io_cmd(&mut self, sqe: NvmeSqe) -> u16 {
        let cid = (sqe.cdw0 >> 16) as u16;
        NVME_IO_SQ.data[self.io_sq_tail] = sqe;
        self.io_sq_tail = (self.io_sq_tail + 1) % NVME_IO_QUEUE_DEPTH;
        self.ring_io_sq();
        cid
    }

    /// Poll Admin CQ for completion of `cid`.  Returns status field (0 = success).
    unsafe fn poll_admin_cq(&mut self, cid: u16) -> u16 {
        for _ in 0..2_000_000u32 {
            let cqe = &NVME_ADMIN_CQ.data[self.admin_cq_head];
            if cqe.phase() == self.admin_cq_phase {
                let found_cid = cqe.cid;
                let status = cqe.status();
                self.admin_cq_head = (self.admin_cq_head + 1) % NVME_ADMIN_QUEUE_DEPTH;
                if self.admin_cq_head == 0 {
                    self.admin_cq_phase = !self.admin_cq_phase;
                }
                self.ring_admin_cq();
                if found_cid == cid {
                    return status;
                }
            }
        }
        0xFFFF // timeout
    }

    /// Poll IO CQ for completion of `cid`.  Returns status field.
    unsafe fn poll_io_cq(&mut self, cid: u16) -> u16 {
        for _ in 0..2_000_000u32 {
            let cqe = &NVME_IO_CQ.data[self.io_cq_head];
            if cqe.phase() == self.io_cq_phase {
                let found_cid = cqe.cid;
                let status = cqe.status();
                self.io_cq_head = (self.io_cq_head + 1) % NVME_IO_QUEUE_DEPTH;
                if self.io_cq_head == 0 {
                    self.io_cq_phase = !self.io_cq_phase;
                }
                self.ring_io_cq();
                if found_cid == cid {
                    return status;
                }
            }
        }
        0xFFFF
    }

    // ----------------------------------------------------------------
    // Initialisation
    // ----------------------------------------------------------------

    pub fn init(&mut self) -> bool {
        unsafe {
            self.pci.enable_bus_mastering();

            // Read CAP for dstrd and MPSMIN
            let cap = self.read64(NVME_CAP);
            let dstrd = ((cap >> 32) & 0xF) as usize; // bits 35:32 = DSTRD
            self.dstrd = 4 << dstrd; // doorbell stride in bytes
            crate::serial_println!("[NVMe] CAP=0x{:016X} dstrd={}B", cap, self.dstrd);

            // Disable controller
            let cc = self.read32(NVME_CC);
            if cc & NVME_CC_EN != 0 {
                self.write32(NVME_CC, cc & !NVME_CC_EN);
                for _ in 0..1_000_000u32 {
                    if self.read32(NVME_CSTS) & NVME_CSTS_RDY == 0 {
                        break;
                    }
                    self.delay();
                }
            }

            // Set Admin Queue Attributes: 63 entries each (0-indexed = 64)
            self.write32(
                NVME_AQA,
                ((NVME_ADMIN_QUEUE_DEPTH as u32 - 1) << 16) | (NVME_ADMIN_QUEUE_DEPTH as u32 - 1),
            );

            // Set Admin SQ/CQ base addresses
            let asq_phys = NVME_ADMIN_SQ.data.as_ptr() as u64;
            let acq_phys = NVME_ADMIN_CQ.data.as_ptr() as u64;
            self.write64(NVME_ASQ, asq_phys);
            self.write64(NVME_ACQ, acq_phys);

            // Configure and enable controller
            let new_cc = NVME_CC_EN
                | NVME_CC_CSS_NVM
                | NVME_CC_MPS_4K
                | NVME_CC_AMS_RR
                | NVME_CC_IOSQES
                | NVME_CC_IOCQES;
            self.write32(NVME_CC, new_cc);

            // Wait for RDY
            for _ in 0..5_000_000u32 {
                let csts = self.read32(NVME_CSTS);
                if csts & NVME_CSTS_RDY != 0 {
                    break;
                }
                if csts & NVME_CSTS_CFS != 0 {
                    crate::serial_println!("[NVMe] Controller Fatal Status");
                    return false;
                }
                self.delay();
            }
            if self.read32(NVME_CSTS) & NVME_CSTS_RDY == 0 {
                crate::serial_println!("[NVMe] Controller RDY timeout");
                return false;
            }

            crate::serial_println!("[NVMe] Controller ready, VS=0x{:08X}", self.read32(NVME_VS));

            // IDENTIFY controller (CNS=1)
            {
                let cid = self.alloc_cid();
                let ident_phys = NVME_IDENTIFY_BUF.data.as_ptr() as u64;
                let sqe = NvmeSqe {
                    cdw0: (NVME_ADMIN_IDENTIFY as u32) | ((cid as u32) << 16),
                    nsid: 0,
                    prp1: ident_phys,
                    prp2: 0,
                    cdw10: 1, // CNS=1 = Identify Controller
                    ..NvmeSqe::default()
                };
                let cid_ret = self.submit_admin_cmd(sqe);
                let st = self.poll_admin_cq(cid_ret);
                if st != 0 {
                    crate::serial_println!("[NVMe] IDENTIFY controller failed, status=0x{:X}", st);
                }
                // MDTS at offset 77
                let _mdts = NVME_IDENTIFY_BUF.data[77];
            }

            // IDENTIFY namespace 1 (CNS=0)
            {
                let cid = self.alloc_cid();
                let ident_phys = NVME_IDENTIFY_BUF.data.as_ptr() as u64;
                let sqe = NvmeSqe {
                    cdw0: (NVME_ADMIN_IDENTIFY as u32) | ((cid as u32) << 16),
                    nsid: 1,
                    prp1: ident_phys,
                    prp2: 0,
                    cdw10: 0, // CNS=0 = Identify Namespace
                    ..NvmeSqe::default()
                };
                let cid_ret = self.submit_admin_cmd(sqe);
                let st = self.poll_admin_cq(cid_ret);
                if st == 0 {
                    // NSZE at offset 0 (u64 LE)
                    let mut nsze = 0u64;
                    for i in 0..8 {
                        nsze |= (NVME_IDENTIFY_BUF.data[i] as u64) << (i * 8);
                    }
                    self.num_blocks = nsze;
                    // FLBAS at offset 26: bits 3:0 = current LBA format index
                    let flbas = NVME_IDENTIFY_BUF.data[26] & 0x0F;
                    // LBA Format Descriptor at offset 128 + flbas*4
                    let lbaf_off = 128 + flbas as usize * 4;
                    // LBADS (LBA Data Size) at byte 3 of each LBAF (bytes/sector = 2^LBADS)
                    let lbads = NVME_IDENTIFY_BUF.data[lbaf_off + 3];
                    self.block_size = if lbads >= 9 { 1u64 << lbads } else { 512 };
                    crate::serial_println!(
                        "[NVMe] NS1: {} blocks × {} B/block",
                        self.num_blocks,
                        self.block_size
                    );
                }
            }

            // CREATE IO CQ (queue 1, 256 entries)
            {
                let cid = self.alloc_cid();
                let iocq_phys = NVME_IO_CQ.data.as_ptr() as u64;
                let sqe = NvmeSqe {
                    cdw0: (NVME_ADMIN_CREATE_IO_CQ as u32) | ((cid as u32) << 16),
                    nsid: 0,
                    prp1: iocq_phys,
                    // CDW10: QSIZE=255 (0-indexed), QID=1
                    cdw10: ((NVME_IO_QUEUE_DEPTH as u32 - 1) << 16) | 1,
                    // CDW11: PC=1 (physically contiguous), IEN=0 (polled)
                    cdw11: 1,
                    ..NvmeSqe::default()
                };
                let cid_ret = self.submit_admin_cmd(sqe);
                let st = self.poll_admin_cq(cid_ret);
                if st != 0 {
                    crate::serial_println!("[NVMe] CREATE IO CQ failed, status=0x{:X}", st);
                    return false;
                }
            }

            // CREATE IO SQ (queue 1, 256 entries, paired with IO CQ 1)
            {
                let cid = self.alloc_cid();
                let iosq_phys = NVME_IO_SQ.data.as_ptr() as u64;
                let sqe = NvmeSqe {
                    cdw0: (NVME_ADMIN_CREATE_IO_SQ as u32) | ((cid as u32) << 16),
                    nsid: 0,
                    prp1: iosq_phys,
                    // CDW10: QSIZE=255, QID=1
                    cdw10: ((NVME_IO_QUEUE_DEPTH as u32 - 1) << 16) | 1,
                    // CDW11: PC=1, QPRIO=0 (urgent), CQID=1
                    cdw11: (1 << 16) | 1,
                    ..NvmeSqe::default()
                };
                let cid_ret = self.submit_admin_cmd(sqe);
                let st = self.poll_admin_cq(cid_ret);
                if st != 0 {
                    crate::serial_println!("[NVMe] CREATE IO SQ failed, status=0x{:X}", st);
                    return false;
                }
            }

            self.initialised = true;
            crate::serial_println!("[NVMe] Initialisation complete");
        }
        true
    }

    // ----------------------------------------------------------------
    // PRP list setup
    // ----------------------------------------------------------------

    /// Build PRP1/PRP2 for a transfer of `byte_count` bytes at `buf_phys`.
    ///
    /// Returns (prp1, prp2) where prp2 is either the second page address (for
    /// exactly 2 pages) or a pointer to the PRP list (for > 2 pages).
    unsafe fn build_prp(&mut self, buf_phys: u64, byte_count: usize) -> (u64, u64) {
        let pages = (byte_count + NVME_PAGE_SIZE - 1) / NVME_PAGE_SIZE;
        let prp1 = buf_phys;
        if pages <= 1 {
            (prp1, 0)
        } else if pages == 2 {
            let prp2 = (buf_phys & !(NVME_PAGE_SIZE as u64 - 1)) + NVME_PAGE_SIZE as u64;
            (prp1, prp2)
        } else {
            // Build a PRP list (pages - 1 entries starting from page 1)
            let base = buf_phys & !(NVME_PAGE_SIZE as u64 - 1);
            let n = core::cmp::min(pages - 1, NVME_MAX_PRP_ENTRIES);
            for i in 0..n {
                NVME_PRP_LIST.entries[i] = base + (i as u64 + 1) * NVME_PAGE_SIZE as u64;
            }
            let list_phys = NVME_PRP_LIST.entries.as_ptr() as u64;
            (prp1, list_phys)
        }
    }

    // ----------------------------------------------------------------
    // Block I/O
    // ----------------------------------------------------------------

    /// Read `sector_count` sectors (each `block_size` bytes) starting at `lba`
    /// into `buf`.  Returns `true` on success.
    pub fn read_sectors(&mut self, lba: u64, sector_count: u32, buf: &mut [u8]) -> bool {
        if !self.initialised {
            return false;
        }
        let byte_count = sector_count as usize * self.block_size as usize;
        if buf.len() < byte_count {
            return false;
        }

        unsafe {
            let buf_phys = buf.as_ptr() as u64;
            let (prp1, prp2) = self.build_prp(buf_phys, byte_count);
            let cid = self.alloc_cid();
            let sqe = NvmeSqe {
                cdw0: (NVME_CMD_READ as u32) | ((cid as u32) << 16),
                nsid: self.ns1_id,
                prp1,
                prp2,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: sector_count - 1, // NLB (0-based)
                ..NvmeSqe::default()
            };
            let cid_ret = self.submit_io_cmd(sqe);
            let st = self.poll_io_cq(cid_ret);
            if st != 0 {
                crate::serial_println!(
                    "[NVMe] READ LBA={} count={} status=0x{:X}",
                    lba,
                    sector_count,
                    st
                );
                return false;
            }
        }
        true
    }

    /// Write `sector_count` sectors from `buf` starting at `lba`.
    pub fn write_sectors(&mut self, lba: u64, sector_count: u32, buf: &[u8]) -> bool {
        if !self.initialised {
            return false;
        }
        let byte_count = sector_count as usize * self.block_size as usize;
        if buf.len() < byte_count {
            return false;
        }

        unsafe {
            let buf_phys = buf.as_ptr() as u64;
            let (prp1, prp2) = self.build_prp(buf_phys, byte_count);
            let cid = self.alloc_cid();
            let sqe = NvmeSqe {
                cdw0: (NVME_CMD_WRITE as u32) | ((cid as u32) << 16),
                nsid: self.ns1_id,
                prp1,
                prp2,
                cdw10: (lba & 0xFFFF_FFFF) as u32,
                cdw11: ((lba >> 32) & 0xFFFF_FFFF) as u32,
                cdw12: sector_count - 1,
                ..NvmeSqe::default()
            };
            let cid_ret = self.submit_io_cmd(sqe);
            let st = self.poll_io_cq(cid_ret);
            if st != 0 {
                crate::serial_println!(
                    "[NVMe] WRITE LBA={} count={} status=0x{:X}",
                    lba,
                    sector_count,
                    st
                );
                return false;
            }
        }
        true
    }

    pub fn flush(&mut self) -> bool {
        if !self.initialised {
            return false;
        }
        unsafe {
            let cid = self.alloc_cid();
            let sqe = NvmeSqe {
                cdw0: (NVME_CMD_FLUSH as u32) | ((cid as u32) << 16),
                nsid: self.ns1_id,
                ..NvmeSqe::default()
            };
            let cid_ret = self.submit_io_cmd(sqe);
            self.poll_io_cq(cid_ret) == 0
        }
    }

    pub fn block_size(&self) -> u64 {
        self.block_size
    }
    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }
}

// ============================================================================
// Global NVMe controller
// ============================================================================

pub static NVME: Mutex<Option<NvmeController>> = Mutex::new(None);

/// Probe PCI bus for an NVMe controller and initialise it.
pub fn init(pci_devices: &[PciDevice]) {
    for &dev in pci_devices {
        if dev.class_code != PCI_CLASS_STORAGE || dev.subclass != PCI_SUBCLASS_NVME {
            continue;
        }
        let bar0_lo = unsafe { dev.read_bar(0) };
        let _bar0_hi = unsafe { dev.read_bar(1) }; // 64-bit BAR high word; unused on 32-bit targets
        if bar0_lo == 0 {
            continue;
        }
        // BAR0 is a 64-bit MMIO BAR (bit 2:1 = 0b10)
        // On 32-bit targets the high BAR word is inaccessible; use low bits.
        let mmio_base = (bar0_lo & !0xF) as usize;

        let mut ctrl = NvmeController::new(mmio_base, dev);
        if ctrl.init() {
            *NVME.lock() = Some(ctrl);
            return;
        }
    }
    crate::serial_println!("[NVMe] No NVMe device found");
}

/// Read sectors via the global NVMe controller.
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> bool {
    match NVME.lock().as_mut() {
        Some(c) => c.read_sectors(lba, count, buf),
        None => false,
    }
}

/// Write sectors via the global NVMe controller.
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> bool {
    match NVME.lock().as_mut() {
        Some(c) => c.write_sectors(lba, count, buf),
        None => false,
    }
}
