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

//! ATA/IDE Storage Driver (PIO and DMA modes)
//!
//! Implements programmed I/O (PIO-28 and PIO-48 LBA) access to ATA hard disks
//! and ATAPI optical drives attached to the legacy IDE bus, plus detection of
//! ATA controllers via PCI (class 0x01 / subclass 0x01).
//!
//! # Architecture
//!
//! ```text
//! AtaController  (per IDE channel, owns the two I/O port ranges)
//!   └─ AtaDrive  (master / slave, detected via IDENTIFY)
//!        ├─ read_sectors_lba28  (≤ 128 MiB range, max 256 sectors/cmd)
//!        ├─ read_sectors_lba48  (> 128 GiB range, max 65536 sectors/cmd)
//!        └─ write_sectors_lba28 / write_sectors_lba48
//! ```
//!
//! Two global singletons cover the two standard IDE channels:
//! - `PRIMARY`:   I/O base 0x1F0, control 0x3F6, IRQ 14
//! - `SECONDARY`: I/O base 0x170, control 0x376, IRQ 15
//!
//! Higher-level code should call `init()` once at boot, then use
//! `primary()` / `secondary()` to obtain a lock guard and issue commands.
//!
//! # Limitations
//! - DMA support (Bus Master IDE) is wired for controllers with BAR4.  Set the
//!   bus master base via `AtaController::set_bus_master_base()` after PCI init.
//! - ATAPI (CD-ROM) identification is detected but read commands are not
//!   implemented.
//! - No interrupt-driven completion; all waits are busy-poll on the status
//!   register, which is acceptable for early-boot use.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

// ============================================================================
// ATA I/O Register Offsets (relative to channel base)
// ============================================================================

/// Read/write: Data register (16-bit)
const REG_DATA: u16 = 0;
/// Read: Error register
const REG_ERROR: u16 = 1;
/// Write: Features register
const REG_FEATURES: u16 = 1;
/// Read/write: Sector count
const REG_SECTOR_COUNT: u16 = 2;
/// Read/write: LBA low (bits 0–7)
const REG_LBA_LO: u16 = 3;
/// Read/write: LBA mid (bits 8–15)
const REG_LBA_MID: u16 = 4;
/// Read/write: LBA high (bits 16–23)
const REG_LBA_HI: u16 = 5;
/// Read/write: Drive / head select
const REG_DRIVE_HEAD: u16 = 6;
/// Read: Status register
const REG_STATUS: u16 = 7;
/// Write: Command register
const REG_COMMAND: u16 = 7;

// Control register (separate port range, offset 0 from control_base)
const REG_ALT_STATUS: u16 = 0; // read
const REG_DEV_CONTROL: u16 = 0; // write

// ============================================================================
// ATA Status Register Bits
// ============================================================================

const STATUS_ERR: u8 = 1 << 0; // Error
const STATUS_DRQ: u8 = 1 << 3; // Data request ready
const STATUS_SRV: u8 = 1 << 4; // Service request
const STATUS_DF: u8 = 1 << 5; // Drive fault
const STATUS_RDY: u8 = 1 << 6; // Drive ready
const STATUS_BSY: u8 = 1 << 7; // Drive busy

// ============================================================================
// ATA Command Bytes
// ============================================================================

const CMD_READ_PIO28: u8 = 0x20;
const CMD_READ_PIO48: u8 = 0x24;
const CMD_WRITE_PIO28: u8 = 0x30;
const CMD_WRITE_PIO48: u8 = 0x34;
const CMD_CACHE_FLUSH: u8 = 0xE7;
const CMD_IDENTIFY: u8 = 0xEC;
const CMD_IDENTIFY_PACKET: u8 = 0xA1; // ATAPI

// Bus Master DMA commands (LBA28 and LBA48 variants)
const CMD_READ_DMA: u8 = 0xC8;
const CMD_READ_DMA_EXT: u8 = 0x25;
const CMD_WRITE_DMA: u8 = 0xCA;
const CMD_WRITE_DMA_EXT: u8 = 0x35;

// ============================================================================
// Bus Master IDE (BMDMA) register offsets (from channel bus_master_base)
// ============================================================================

/// BMDMA command register offset.
const BMDMA_CMD: u16 = 0;
/// BMDMA status register offset.
const BMDMA_STATUS: u16 = 2;
/// BMDMA physical region descriptor table address register offset (32-bit).
const BMDMA_PRDT: u16 = 4;

const BMDMA_CMD_START: u8 = 1 << 0; // Start/Stop bus master
const BMDMA_CMD_WRITE: u8 = 1 << 3; // Direction: 1=write, 0=read
const BMDMA_STS_ERR:   u8 = 1 << 1; // DMA error (set by hardware)
const BMDMA_STS_INTR:  u8 = 1 << 2; // Interrupt received (set by hardware)

/// Maximum sectors per single DMA command: one PRD entry can hold at most
/// 65535 bytes (fields of 0 mean 64 KiB), so 127 × 512 = 65024 bytes is safe.
const DMA_MAX_SECTORS: usize = 127;

// ============================================================================
// Physical Region Descriptor (PRD) table
// ============================================================================

/// A single Physical Region Descriptor entry (ATA BMDMA spec §4.1).
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct PrdEntry {
    /// Physical byte address of the DMA buffer region.
    base: u32,
    /// Byte count for this region (0 = 64 KiB).
    count: u16,
    /// Bit 15 must be set on the last (or only) entry.
    flags: u16,
}

// SAFETY: Only accessed under the per-channel `Mutex<AtaController>` lock;
// single-entry table re-initialised at the start of every DMA command.
static mut ATA_PRDT: PrdEntry = PrdEntry { base: 0, count: 0, flags: 0 };

// ============================================================================
// Drive select masks
// ============================================================================

const DRIVE_MASTER: u8 = 0xA0; // 1010_0000
const DRIVE_SLAVE: u8 = 0xB0; // 1011_0000
const DRIVE_LBA: u8 = 0x40; // bit 6: LBA mode

// ============================================================================
// Sector geometry
// ============================================================================

pub const SECTOR_SIZE: usize = 512;

// ============================================================================
// IRQ counters (populated from the interrupt handler in disk.rs)
// ============================================================================

static ATA_PRIMARY_IRQS: AtomicU32 = AtomicU32::new(0);
static ATA_SECONDARY_IRQS: AtomicU32 = AtomicU32::new(0);

/// Called from the IRQ 14 handler.
pub fn on_primary_irq() {
    ATA_PRIMARY_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// Called from the IRQ 15 handler.
pub fn on_secondary_irq() {
    ATA_SECONDARY_IRQS.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Low-level port I/O
// ============================================================================

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port,
                     options(nomem, nostack, preserves_flags));
    v
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val,
                     options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port,
                     options(nomem, nostack, preserves_flags));
    v
}

#[inline]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val,
                     options(nomem, nostack, preserves_flags));
}

// ============================================================================
// AtaDrive — a single disk or optical drive
// ============================================================================

/// Geometry and identity information returned by the IDENTIFY command.
#[derive(Debug, Clone, Copy)]
pub struct AtaIdentity {
    /// True if this is an ATAPI device (CD/DVD).
    pub is_atapi: bool,
    /// Model string (40 bytes, null-padded, byte-swapped per ATA spec).
    pub model: [u8; 40],
    /// LBA28 sector count (non-zero if LBA28 is supported).
    pub lba28_sectors: u32,
    /// LBA48 sector count (non-zero if LBA48 is supported).
    pub lba48_sectors: u64,
    /// True if LBA mode is supported.
    pub lba_supported: bool,
    /// True if DMA mode is supported.
    pub dma_supported: bool,
    /// Logical sector size (usually 512, can be 4096 for 4Kn drives).
    pub logical_sector_size: u32,
}

impl AtaIdentity {
    const fn zeroed() -> Self {
        AtaIdentity {
            is_atapi: false,
            model: [0u8; 40],
            lba28_sectors: 0,
            lba48_sectors: 0,
            lba_supported: false,
            dma_supported: false,
            logical_sector_size: 512,
        }
    }

    /// Extract the model string, trimming trailing spaces.
    pub fn model_str(&self) -> &str {
        let s = core::str::from_utf8(&self.model).unwrap_or("?");
        s.trim_end_matches(' ')
    }

    /// Total addressable sectors (prefers LBA48 over LBA28).
    pub fn total_sectors(&self) -> u64 {
        if self.lba48_sectors > 0 {
            self.lba48_sectors
        } else {
            self.lba28_sectors as u64
        }
    }

    /// Disk capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors() * self.logical_sector_size as u64
    }
}

/// One physical drive (master or slave) on an IDE channel.
pub struct AtaDrive {
    pub present: bool,
    pub slave: bool,
    pub identity: AtaIdentity,
    /// IO base port of the owning channel.
    io_base: u16,
    /// Control base port of the owning channel.
    ctrl_base: u16,
    /// Bus Master IDE base port (0 = DMA unavailable on this channel).
    bus_master_base: u16,
}

impl AtaDrive {
    const fn absent(io_base: u16, ctrl_base: u16, slave: bool) -> Self {
        AtaDrive {
            present: false,
            slave,
            identity: AtaIdentity::zeroed(),
            io_base,
            ctrl_base,
            bus_master_base: 0,
        }
    }

    // ----------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------

    /// Read the alternate status register (does not clear interrupts).
    unsafe fn alt_status(&self) -> u8 {
        inb(self.ctrl_base + REG_ALT_STATUS)
    }

    /// Select this drive and wait for BSY to clear.
    unsafe fn select(&self) {
        let sel = if self.slave {
            DRIVE_SLAVE
        } else {
            DRIVE_MASTER
        };
        outb(self.io_base + REG_DRIVE_HEAD, sel);
        // 400 ns delay: read alt-status 4×
        for _ in 0..4 {
            let _ = self.alt_status();
        }
        self.wait_not_busy();
    }

    /// Busy-poll until BSY clears.  Returns the final status byte.
    unsafe fn wait_not_busy(&self) -> u8 {
        loop {
            let s = inb(self.io_base + REG_STATUS);
            if s & STATUS_BSY == 0 {
                return s;
            }
        }
    }

    /// Busy-poll until DRQ or ERR is set (after issuing a data command).
    unsafe fn wait_drq(&self) -> Result<(), AtaError> {
        loop {
            let s = inb(self.io_base + REG_STATUS);
            if s & STATUS_BSY == 0 {
                if s & STATUS_ERR != 0 || s & STATUS_DF != 0 {
                    return Err(AtaError::DeviceError(inb(self.io_base + REG_ERROR)));
                }
                if s & STATUS_DRQ != 0 {
                    return Ok(());
                }
            }
        }
    }

    /// Send a software reset on this channel.
    unsafe fn soft_reset(&self) {
        outb(self.ctrl_base + REG_DEV_CONTROL, 0x04); // SRST
                                                      // hold at least 5 µs
        for _ in 0..4 {
            let _ = self.alt_status();
        }
        outb(self.ctrl_base + REG_DEV_CONTROL, 0x00); // clear SRST
        self.wait_not_busy();
    }

    // ----------------------------------------------------------------
    // IDENTIFY
    // ----------------------------------------------------------------

    /// Run the IDENTIFY (or IDENTIFY PACKET) command and fill `identity`.
    ///
    /// Returns `true` on success.
    pub unsafe fn identify(&mut self) -> bool {
        self.select();

        // Clear the high LBA / sector count registers
        outb(self.io_base + REG_SECTOR_COUNT, 0);
        outb(self.io_base + REG_LBA_LO, 0);
        outb(self.io_base + REG_LBA_MID, 0);
        outb(self.io_base + REG_LBA_HI, 0);
        outb(self.io_base + REG_COMMAND, CMD_IDENTIFY);

        let status = inb(self.io_base + REG_STATUS);
        if status == 0 {
            return false; // No drive
        }
        self.wait_not_busy();

        // Check for ATAPI signature
        let lba_mid = inb(self.io_base + REG_LBA_MID);
        let lba_hi = inb(self.io_base + REG_LBA_HI);
        let is_atapi = lba_mid == 0x14 && lba_hi == 0xEB;

        if is_atapi {
            outb(self.io_base + REG_COMMAND, CMD_IDENTIFY_PACKET);
            self.wait_not_busy();
        }

        if self.wait_drq().is_err() {
            return false;
        }

        // Read 256 words from the data register
        let mut buf = [0u16; 256];
        for w in buf.iter_mut() {
            *w = inw(self.io_base + REG_DATA);
        }

        let mut id = AtaIdentity::zeroed();
        id.is_atapi = is_atapi;

        // Words 27–46: model string (byte-swapped)
        for i in 0..20usize {
            let w = buf[27 + i];
            id.model[i * 2] = (w >> 8) as u8;
            id.model[i * 2 + 1] = (w & 0xFF) as u8;
        }

        // Word 49 bit 9: LBA supported; bit 8: DMA supported
        id.lba_supported = buf[49] & (1 << 9) != 0;
        id.dma_supported = buf[49] & (1 << 8) != 0;

        // Words 60–61: LBA28 sector count
        id.lba28_sectors = (buf[61] as u32) << 16 | buf[60] as u32;

        // Word 83 bit 10: LBA48 supported
        if buf[83] & (1 << 10) != 0 {
            id.lba48_sectors = (buf[103] as u64) << 48
                | (buf[102] as u64) << 32
                | (buf[101] as u64) << 16
                | buf[100] as u64;
        }

        // Word 117–118: logical sector size (if word 106 bit 12 set)
        if buf[106] & (1 << 12) != 0 {
            let lss = (buf[118] as u32) << 16 | buf[117] as u32;
            if lss > 0 {
                id.logical_sector_size = lss * 2; // value is in 16-bit words
            }
        }

        self.identity = id;
        self.present = true;
        true
    }

    // ----------------------------------------------------------------
    // PIO read
    // ----------------------------------------------------------------

    /// Read `count` sectors starting at `lba` into `buf`.
    ///
    /// Uses LBA28 for drives ≤ 128 GiB and LBA48 otherwise.
    /// `buf` must be at least `count * SECTOR_SIZE` bytes.
    pub fn read_sectors(&self, lba: u64, count: usize, buf: &mut [u8]) -> Result<(), AtaError> {
        if !self.present {
            return Err(AtaError::NoDrive);
        }
        if !self.identity.lba_supported {
            return Err(AtaError::NoLbaSupport);
        }
        if buf.len() < count * SECTOR_SIZE {
            return Err(AtaError::BufferTooSmall);
        }
        if lba + count as u64 > self.identity.total_sectors() {
            return Err(AtaError::OutOfRange);
        }

        let use_dma = self.bus_master_base != 0 && self.identity.dma_supported;
        if self.identity.lba48_sectors > 0 && lba >= (1 << 28) {
            if use_dma {
                unsafe { self.read_lba48_dma(lba, count, buf) }
            } else {
                unsafe { self.read_lba48(lba, count, buf) }
            }
        } else if use_dma {
            unsafe { self.read_lba28_dma(lba as u32, count, buf) }
        } else {
            unsafe { self.read_lba28(lba as u32, count, buf) }
        }
    }

    /// Write `count` sectors starting at `lba` from `buf`.
    pub fn write_sectors(&self, lba: u64, count: usize, buf: &[u8]) -> Result<(), AtaError> {
        if !self.present {
            return Err(AtaError::NoDrive);
        }
        if !self.identity.lba_supported {
            return Err(AtaError::NoLbaSupport);
        }
        if buf.len() < count * SECTOR_SIZE {
            return Err(AtaError::BufferTooSmall);
        }
        if lba + count as u64 > self.identity.total_sectors() {
            return Err(AtaError::OutOfRange);
        }

        let use_dma = self.bus_master_base != 0 && self.identity.dma_supported;
        if self.identity.lba48_sectors > 0 && lba >= (1 << 28) {
            if use_dma {
                unsafe { self.write_lba48_dma(lba, count, buf) }
            } else {
                unsafe { self.write_lba48(lba, count, buf) }
            }
        } else if use_dma {
            unsafe { self.write_lba28_dma(lba as u32, count, buf) }
        } else {
            unsafe { self.write_lba28(lba as u32, count, buf) }
        }
    }

    // ----------------------------------------------------------------
    // LBA28 implementation
    // ----------------------------------------------------------------

    unsafe fn read_lba28(&self, lba: u32, count: usize, buf: &mut [u8]) -> Result<(), AtaError> {
        // max 256 sectors per command (count=0 means 256)
        let sectors_per_cmd: usize = 256;
        let mut done = 0usize;
        let mut remaining = count;

        while remaining > 0 {
            let n = remaining.min(sectors_per_cmd);
            let this_lba = lba + done as u32;

            let sel = (if self.slave {
                DRIVE_SLAVE
            } else {
                DRIVE_MASTER
            }) | DRIVE_LBA
                | ((this_lba >> 24) & 0x0F) as u8;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            outb(self.io_base + REG_SECTOR_COUNT, (n & 0xFF) as u8);
            outb(self.io_base + REG_LBA_LO, (this_lba & 0xFF) as u8);
            outb(self.io_base + REG_LBA_MID, ((this_lba >> 8) & 0xFF) as u8);
            outb(self.io_base + REG_LBA_HI, ((this_lba >> 16) & 0xFF) as u8);
            outb(self.io_base + REG_COMMAND, CMD_READ_PIO28);

            for s in 0..n {
                self.wait_drq()?;
                let off = (done + s) * SECTOR_SIZE;
                for i in (0..SECTOR_SIZE).step_by(2) {
                    let w = inw(self.io_base + REG_DATA);
                    buf[off + i] = (w & 0xFF) as u8;
                    buf[off + i + 1] = (w >> 8) as u8;
                }
            }

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    unsafe fn write_lba28(&self, lba: u32, count: usize, buf: &[u8]) -> Result<(), AtaError> {
        let sectors_per_cmd: usize = 256;
        let mut done = 0usize;
        let mut remaining = count;

        while remaining > 0 {
            let n = remaining.min(sectors_per_cmd);
            let this_lba = lba + done as u32;

            let sel = (if self.slave {
                DRIVE_SLAVE
            } else {
                DRIVE_MASTER
            }) | DRIVE_LBA
                | ((this_lba >> 24) & 0x0F) as u8;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            outb(self.io_base + REG_SECTOR_COUNT, (n & 0xFF) as u8);
            outb(self.io_base + REG_LBA_LO, (this_lba & 0xFF) as u8);
            outb(self.io_base + REG_LBA_MID, ((this_lba >> 8) & 0xFF) as u8);
            outb(self.io_base + REG_LBA_HI, ((this_lba >> 16) & 0xFF) as u8);
            outb(self.io_base + REG_COMMAND, CMD_WRITE_PIO28);

            for s in 0..n {
                self.wait_drq()?;
                let off = (done + s) * SECTOR_SIZE;
                for i in (0..SECTOR_SIZE).step_by(2) {
                    let lo = buf[off + i] as u16;
                    let hi = buf[off + i + 1] as u16;
                    outw(self.io_base + REG_DATA, lo | (hi << 8));
                }
            }

            // Flush cache
            outb(self.io_base + REG_COMMAND, CMD_CACHE_FLUSH);
            self.wait_not_busy();

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // LBA48 implementation
    // ----------------------------------------------------------------

    unsafe fn setup_lba48(&self, lba: u64, count: u16) {
        // Send high bytes first (HOB bit must be set in DEV_CONTROL for reads,
        // but it is cleaner to write the register pairs in the documented order)
        outb(self.io_base + REG_SECTOR_COUNT, (count >> 8) as u8);
        outb(self.io_base + REG_LBA_LO, ((lba >> 24) & 0xFF) as u8);
        outb(self.io_base + REG_LBA_MID, ((lba >> 32) & 0xFF) as u8);
        outb(self.io_base + REG_LBA_HI, ((lba >> 40) & 0xFF) as u8);
        // Send low bytes
        outb(self.io_base + REG_SECTOR_COUNT, (count & 0xFF) as u8);
        outb(self.io_base + REG_LBA_LO, (lba & 0xFF) as u8);
        outb(self.io_base + REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        outb(self.io_base + REG_LBA_HI, ((lba >> 16) & 0xFF) as u8);
    }

    unsafe fn read_lba48(&self, lba: u64, count: usize, buf: &mut [u8]) -> Result<(), AtaError> {
        let max_per_cmd: usize = 65536;
        let mut done = 0usize;
        let mut remaining = count;

        while remaining > 0 {
            let n = remaining.min(max_per_cmd);
            let this_lba = lba + done as u64;

            let sel = (if self.slave {
                DRIVE_SLAVE
            } else {
                DRIVE_MASTER
            }) | DRIVE_LBA;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            self.setup_lba48(this_lba, n as u16);
            outb(self.io_base + REG_COMMAND, CMD_READ_PIO48);

            for s in 0..n {
                self.wait_drq()?;
                let off = (done + s) * SECTOR_SIZE;
                for i in (0..SECTOR_SIZE).step_by(2) {
                    let w = inw(self.io_base + REG_DATA);
                    buf[off + i] = (w & 0xFF) as u8;
                    buf[off + i + 1] = (w >> 8) as u8;
                }
            }

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    unsafe fn write_lba48(&self, lba: u64, count: usize, buf: &[u8]) -> Result<(), AtaError> {
        let max_per_cmd: usize = 65536;
        let mut done = 0usize;
        let mut remaining = count;

        while remaining > 0 {
            let n = remaining.min(max_per_cmd);
            let this_lba = lba + done as u64;

            let sel = (if self.slave {
                DRIVE_SLAVE
            } else {
                DRIVE_MASTER
            }) | DRIVE_LBA;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            self.setup_lba48(this_lba, n as u16);
            outb(self.io_base + REG_COMMAND, CMD_WRITE_PIO48);

            for s in 0..n {
                self.wait_drq()?;
                let off = (done + s) * SECTOR_SIZE;
                for i in (0..SECTOR_SIZE).step_by(2) {
                    let lo = buf[off + i] as u16;
                    let hi = buf[off + i + 1] as u16;
                    outw(self.io_base + REG_DATA, lo | (hi << 8));
                }
            }

            outb(self.io_base + REG_COMMAND, CMD_CACHE_FLUSH);
            self.wait_not_busy();

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // BMDMA helpers (used by DMA read/write methods below)
    // ----------------------------------------------------------------

    /// Initialise the single-entry PRDT and program the BMDMA registers.
    ///
    /// `write_dir`: `true` = write to disk, `false` = read from disk.
    ///
    /// # Safety
    /// Caller must hold the channel lock and must not call concurrently.
    unsafe fn bmdma_setup(&self, buf_virt: *const u8, byte_count: usize, write_dir: bool) {
        ATA_PRDT = PrdEntry {
            base: buf_virt as u32,
            count: byte_count as u16, // 0 is magic for 64 KiB; callers ensure ≤ 65024
            flags: 0x8000,            // End-of-Table bit
        };
        let prdt_phys = &ATA_PRDT as *const PrdEntry as u32;

        // Stop DMA and clear sticky error/interrupt status bits.
        outb(self.bus_master_base + BMDMA_CMD, 0);
        outb(
            self.bus_master_base + BMDMA_STATUS,
            BMDMA_STS_ERR | BMDMA_STS_INTR,
        );

        // Program PRDT base address (32-bit, little-endian).
        let p = self.bus_master_base + BMDMA_PRDT;
        outb(p,     (prdt_phys & 0xFF) as u8);
        outb(p + 1, ((prdt_phys >>  8) & 0xFF) as u8);
        outb(p + 2, ((prdt_phys >> 16) & 0xFF) as u8);
        outb(p + 3, ((prdt_phys >> 24) & 0xFF) as u8);

        // Latch direction bit (write=1, read=0) without starting the engine.
        let dir_bit = if write_dir { BMDMA_CMD_WRITE } else { 0 };
        outb(self.bus_master_base + BMDMA_CMD, dir_bit);
    }

    /// Start the bus master DMA engine (call after issuing the ATA command).
    unsafe fn bmdma_start(&self) {
        let cmd = inb(self.bus_master_base + BMDMA_CMD);
        outb(self.bus_master_base + BMDMA_CMD, cmd | BMDMA_CMD_START);
    }

    /// Poll until the DMA transfer completes, stop the engine, and return
    /// an error if the hardware reported a fault.
    unsafe fn bmdma_wait(&self) -> Result<(), AtaError> {
        loop {
            let st = inb(self.bus_master_base + BMDMA_STATUS);
            if st & BMDMA_STS_ERR != 0 {
                outb(self.bus_master_base + BMDMA_CMD, 0);
                return Err(AtaError::DeviceError(inb(self.io_base + REG_ERROR)));
            }
            if st & BMDMA_STS_INTR != 0 {
                break;
            }
        }
        outb(self.bus_master_base + BMDMA_CMD, 0);
        let drv = inb(self.io_base + REG_STATUS);
        if drv & (STATUS_ERR | STATUS_DF) != 0 {
            return Err(AtaError::DeviceError(inb(self.io_base + REG_ERROR)));
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // DMA read/write — LBA28
    // ----------------------------------------------------------------

    unsafe fn read_lba28_dma(
        &self,
        lba: u32,
        count: usize,
        buf: &mut [u8],
    ) -> Result<(), AtaError> {
        let mut done = 0;
        let mut remaining = count;
        while remaining > 0 {
            let n = remaining.min(DMA_MAX_SECTORS);
            let off = done * SECTOR_SIZE;
            let this_lba = lba + done as u32;

            let sel = (if self.slave { DRIVE_SLAVE } else { DRIVE_MASTER })
                | DRIVE_LBA
                | ((this_lba >> 24) & 0x0F) as u8;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            outb(self.io_base + REG_SECTOR_COUNT, (n & 0xFF) as u8);
            outb(self.io_base + REG_LBA_LO,  (this_lba & 0xFF) as u8);
            outb(self.io_base + REG_LBA_MID, ((this_lba >>  8) & 0xFF) as u8);
            outb(self.io_base + REG_LBA_HI,  ((this_lba >> 16) & 0xFF) as u8);

            self.bmdma_setup(buf[off..].as_ptr(), n * SECTOR_SIZE, false);
            outb(self.io_base + REG_COMMAND, CMD_READ_DMA);
            self.bmdma_start();
            self.bmdma_wait()?;

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    unsafe fn write_lba28_dma(
        &self,
        lba: u32,
        count: usize,
        buf: &[u8],
    ) -> Result<(), AtaError> {
        let mut done = 0;
        let mut remaining = count;
        while remaining > 0 {
            let n = remaining.min(DMA_MAX_SECTORS);
            let off = done * SECTOR_SIZE;
            let this_lba = lba + done as u32;

            let sel = (if self.slave { DRIVE_SLAVE } else { DRIVE_MASTER })
                | DRIVE_LBA
                | ((this_lba >> 24) & 0x0F) as u8;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            outb(self.io_base + REG_SECTOR_COUNT, (n & 0xFF) as u8);
            outb(self.io_base + REG_LBA_LO,  (this_lba & 0xFF) as u8);
            outb(self.io_base + REG_LBA_MID, ((this_lba >>  8) & 0xFF) as u8);
            outb(self.io_base + REG_LBA_HI,  ((this_lba >> 16) & 0xFF) as u8);

            self.bmdma_setup(buf[off..].as_ptr(), n * SECTOR_SIZE, true);
            outb(self.io_base + REG_COMMAND, CMD_WRITE_DMA);
            self.bmdma_start();
            self.bmdma_wait()?;

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    // ----------------------------------------------------------------
    // DMA read/write — LBA48
    // ----------------------------------------------------------------

    unsafe fn read_lba48_dma(
        &self,
        lba: u64,
        count: usize,
        buf: &mut [u8],
    ) -> Result<(), AtaError> {
        let mut done = 0;
        let mut remaining = count;
        while remaining > 0 {
            let n = remaining.min(DMA_MAX_SECTORS);
            let off = done * SECTOR_SIZE;
            let this_lba = lba + done as u64;

            let sel = (if self.slave { DRIVE_SLAVE } else { DRIVE_MASTER }) | DRIVE_LBA;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            self.setup_lba48(this_lba, n as u16);
            self.bmdma_setup(buf[off..].as_ptr(), n * SECTOR_SIZE, false);
            outb(self.io_base + REG_COMMAND, CMD_READ_DMA_EXT);
            self.bmdma_start();
            self.bmdma_wait()?;

            done += n;
            remaining -= n;
        }
        Ok(())
    }

    unsafe fn write_lba48_dma(
        &self,
        lba: u64,
        count: usize,
        buf: &[u8],
    ) -> Result<(), AtaError> {
        let mut done = 0;
        let mut remaining = count;
        while remaining > 0 {
            let n = remaining.min(DMA_MAX_SECTORS);
            let off = done * SECTOR_SIZE;
            let this_lba = lba + done as u64;

            let sel = (if self.slave { DRIVE_SLAVE } else { DRIVE_MASTER }) | DRIVE_LBA;
            outb(self.io_base + REG_DRIVE_HEAD, sel);
            for _ in 0..4 {
                let _ = self.alt_status();
            }
            self.wait_not_busy();

            self.setup_lba48(this_lba, n as u16);
            self.bmdma_setup(buf[off..].as_ptr(), n * SECTOR_SIZE, true);
            outb(self.io_base + REG_COMMAND, CMD_WRITE_DMA_EXT);
            self.bmdma_start();
            self.bmdma_wait()?;

            done += n;
            remaining -= n;
        }
        Ok(())
    }
}

// ============================================================================
// AtaError
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaError {
    /// No drive present at the selected position.
    NoDrive,
    /// Drive does not support LBA addressing.
    NoLbaSupport,
    /// Supplied buffer is smaller than the requested transfer.
    BufferTooSmall,
    /// LBA + count exceeds the drive's capacity.
    OutOfRange,
    /// Device reported an error (error register value embedded).
    DeviceError(u8),
    /// Channel is not initialised.
    NotInitialised,
}

impl AtaError {
    pub fn as_str(self) -> &'static str {
        match self {
            AtaError::NoDrive => "no drive",
            AtaError::NoLbaSupport => "drive does not support LBA",
            AtaError::BufferTooSmall => "buffer too small",
            AtaError::OutOfRange => "LBA out of range",
            AtaError::DeviceError(_) => "device error",
            AtaError::NotInitialised => "channel not initialised",
        }
    }
}

// ============================================================================
// AtaController — one IDE channel (primary or secondary)
// ============================================================================

/// Standard port addresses for the two legacy IDE channels.
pub const PRIMARY_IO_BASE: u16 = 0x1F0;
pub const PRIMARY_CTRL_BASE: u16 = 0x3F6;
pub const PRIMARY_IRQ: u8 = 14;

pub const SECONDARY_IO_BASE: u16 = 0x170;
pub const SECONDARY_CTRL_BASE: u16 = 0x376;
pub const SECONDARY_IRQ: u8 = 15;

/// An IDE controller with a master and a slave drive.
pub struct AtaController {
    pub io_base: u16,
    pub ctrl_base: u16,
    pub irq: u8,
    pub initialised: bool,
    pub master: AtaDrive,
    pub slave: AtaDrive,
}

impl AtaController {
    pub const fn new(io_base: u16, ctrl_base: u16, irq: u8) -> Self {
        AtaController {
            io_base,
            ctrl_base,
            irq,
            initialised: false,
            master: AtaDrive::absent(io_base, ctrl_base, false),
            slave: AtaDrive::absent(io_base, ctrl_base, true),
        }
    }

    /// Probe the channel, run IDENTIFY on both positions, populate drive info.
    pub fn init(&mut self) {
        unsafe {
            // Software reset
            outb(self.ctrl_base + REG_DEV_CONTROL, 0x04);
            for _ in 0..4 {
                let _ = inb(self.ctrl_base + REG_ALT_STATUS);
            }
            outb(self.ctrl_base + REG_DEV_CONTROL, 0x00);
            // Wait for BSY to clear after reset
            let mut spin = 0u32;
            loop {
                let s = inb(self.io_base + REG_STATUS);
                if s & STATUS_BSY == 0 {
                    break;
                }
                spin += 1;
                if spin > 100_000 {
                    break;
                } // bail out rather than hang
            }

            self.master.identify();
            self.slave.identify();
        }
        self.initialised = true;
    }

    /// Configure the Bus Master IDE base port for both drives on this channel.
    ///
    /// Call this immediately after `init()` once PCI BAR4 has been read.
    /// For the primary channel pass `bar4 & !3`; for the secondary channel
    /// pass `(bar4 & !3) + 8`.
    pub fn set_bus_master_base(&mut self, bm_base: u16) {
        self.master.bus_master_base = bm_base;
        self.slave.bus_master_base = bm_base;
    }

    /// Return the first present drive (master first, then slave).
    pub fn first_drive(&self) -> Option<&AtaDrive> {
        if self.master.present {
            return Some(&self.master);
        }
        if self.slave.present {
            return Some(&self.slave);
        }
        None
    }

    /// Returns `true` if at least one drive is present.
    pub fn has_drive(&self) -> bool {
        self.master.present || self.slave.present
    }
}

// ============================================================================
// Global singletons
// ============================================================================

static PRIMARY: Mutex<AtaController> = Mutex::new(AtaController::new(
    PRIMARY_IO_BASE,
    PRIMARY_CTRL_BASE,
    PRIMARY_IRQ,
));
static SECONDARY: Mutex<AtaController> = Mutex::new(AtaController::new(
    SECONDARY_IO_BASE,
    SECONDARY_CTRL_BASE,
    SECONDARY_IRQ,
));

/// Initialise both IDE channels.  Safe to call from any context.
pub fn init() {
    PRIMARY.lock().init();
    SECONDARY.lock().init();
}

/// Obtain a lock guard to the primary (0x1F0) IDE channel.
pub fn primary() -> spin::MutexGuard<'static, AtaController> {
    PRIMARY.lock()
}

/// Obtain a lock guard to the secondary (0x170) IDE channel.
pub fn secondary() -> spin::MutexGuard<'static, AtaController> {
    SECONDARY.lock()
}

// ============================================================================
// PCI ATA controller detection
// ============================================================================

/// PCI class / subclass codes for ATA / IDE storage controllers.
pub mod pci_class {
    /// PCI class 0x01 — Mass Storage Controller
    pub const CLASS_STORAGE: u8 = 0x01;
    /// Subclass 0x01: IDE controller
    pub const SUBCLASS_IDE: u8 = 0x01;
    /// Subclass 0x05: ATA controller (with single DMA)
    pub const SUBCLASS_ATA: u8 = 0x05;
    /// Subclass 0x06: SATA / AHCI controller
    pub const SUBCLASS_SATA: u8 = 0x06;
    /// Subclass 0x07: Serial Attached SCSI controller
    pub const SUBCLASS_SAS: u8 = 0x07;
    /// Subclass 0x08: NVM Express (NVMe)
    pub const SUBCLASS_NVME: u8 = 0x08;
}

/// A detected PCI storage device.
#[derive(Debug, Clone, Copy)]
pub struct StorageDevice {
    pub pci: crate::drivers::x86::pci::PciDevice,
    pub kind: StorageKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    Ide,
    Ata,
    Sata,
    Sas,
    Nvme,
    Other,
}

impl StorageDevice {
    pub fn description(&self) -> &'static str {
        match self.kind {
            StorageKind::Ide => "IDE controller",
            StorageKind::Ata => "ATA controller",
            StorageKind::Sata => "SATA / AHCI controller",
            StorageKind::Sas => "Serial Attached SCSI",
            StorageKind::Nvme => "NVM Express (NVMe)",
            StorageKind::Other => "Unknown storage controller",
        }
    }
}

/// Scan `pci_devices` and return all storage controllers.
pub fn detect_storage_devices(
    pci_devices: &[Option<crate::drivers::x86::pci::PciDevice>],
) -> alloc::vec::Vec<StorageDevice> {
    extern crate alloc;
    use alloc::vec::Vec;

    let mut out = Vec::new();
    for dev_opt in pci_devices {
        let Some(dev) = dev_opt else { continue };
        if dev.class_code != pci_class::CLASS_STORAGE {
            continue;
        }
        let kind = match dev.subclass {
            pci_class::SUBCLASS_IDE => StorageKind::Ide,
            pci_class::SUBCLASS_ATA => StorageKind::Ata,
            pci_class::SUBCLASS_SATA => StorageKind::Sata,
            pci_class::SUBCLASS_SAS => StorageKind::Sas,
            pci_class::SUBCLASS_NVME => StorageKind::Nvme,
            _ => StorageKind::Other,
        };
        out.push(StorageDevice { pci: *dev, kind });
    }
    out
}

// ============================================================================
// Health / diagnostics
// ============================================================================

/// Snapshot of ATA driver statistics.
#[derive(Debug, Clone, Copy)]
pub struct AtaHealth {
    pub primary_irqs: u32,
    pub secondary_irqs: u32,
    pub primary_master_present: bool,
    pub primary_slave_present: bool,
    pub secondary_master_present: bool,
    pub secondary_slave_present: bool,
}

pub fn health() -> AtaHealth {
    let pri = PRIMARY.lock();
    let sec = SECONDARY.lock();
    AtaHealth {
        primary_irqs: ATA_PRIMARY_IRQS.load(Ordering::Relaxed),
        secondary_irqs: ATA_SECONDARY_IRQS.load(Ordering::Relaxed),
        primary_master_present: pri.master.present,
        primary_slave_present: pri.slave.present,
        secondary_master_present: sec.master.present,
        secondary_slave_present: sec.slave.present,
    }
}
