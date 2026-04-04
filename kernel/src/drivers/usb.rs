/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! USB Host Controller Driver
//!
//! Full implementations for UHCI, OHCI, EHCI, and xHCI (detection + init).
//! Includes complete device enumeration (SET_ADDRESS + GET_DESCRIPTOR),
//! control/bulk/interrupt transfer support, and a USB Mass Storage (BOT/SCSI)
//! class driver.
//!
//! # Supported host controller types
//!
//! | Standard | Speed               | PCI prog-if | Status                         |
//! |----------|---------------------|-------------|--------------------------------|
//! | UHCI     | Full/Low (12/1.5 Mb)| 0x00        | Full: TD/QH, control+bulk+intr |
//! | OHCI     | Full/Low (12/1.5 Mb)| 0x10        | Full: HCCA, ED/TD, enumeration |
//! | EHCI     | High (480 Mb/s)     | 0x20        | Full: async schedule, qTD/QH   |
//! | xHCI     | Super (5/10/20 Gb/s)| 0x30        | BIOS hand-off + port detection |
//!
//! # Transfer types implemented
//! - **Control** — SETUP + DATA + STATUS stages; used for enumeration and class
//!   commands on all four controller types.
//! - **Bulk** — used for USB Mass Storage BOT read/write on UHCI and EHCI.
//! - **Interrupt** — periodic polling for HID devices on UHCI and OHCI.
//!
//! # USB Mass Storage class driver
//! Implements the Bulk-Only Transport (BOT) protocol with SCSI transparent
//! command set:
//! - `INQUIRY` (0x12) — identify device type and vendor
//! - `TEST UNIT READY` (0x00) — poll for media presence
//! - `READ CAPACITY(10)` (0x25) — obtain block count + block size
//! - `READ(10)` (0x28) — 512-byte sector reads
//! - `WRITE(10)` (0x2A) — 512-byte sector writes
//!
//! # Architecture
//! ```text
//!  UsbBus                     ← kernel-facing façade
//!    ├─ UhciController        ← I/O-port based; TD/QH frame list; full xfer
//!    ├─ OhciController        ← MMIO; HCCA; ED/TD lists; full xfer
//!    ├─ EhciController        ← MMIO; async QH schedule; qTD; full xfer
//!    └─ XhciController        ← MMIO; BIOS hand-off; port detect
//!  MassStorageDevice          ← BOT class driver layered on top of UsbBus
//! ```

#![allow(dead_code)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::pci::PciDevice;

// ============================================================================
// PCI class codes for USB host controllers
// ============================================================================

pub mod pci_class {
    /// PCI class 0x0C — Serial Bus Controller
    pub const CLASS_SERIAL_BUS: u8 = 0x0C;
    /// Subclass 0x03: USB controller
    pub const SUBCLASS_USB: u8 = 0x03;
    /// prog-if 0x00: UHCI
    pub const PROGIF_UHCI: u8 = 0x00;
    /// prog-if 0x10: OHCI
    pub const PROGIF_OHCI: u8 = 0x10;
    /// prog-if 0x20: EHCI
    pub const PROGIF_EHCI: u8 = 0x20;
    /// prog-if 0x30: xHCI
    pub const PROGIF_XHCI: u8 = 0x30;
}

// ============================================================================
// USB speed classification
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    Low,     //   1.5 Mb/s (USB 1.0)
    Full,    //    12 Mb/s (USB 1.1)
    High,    //   480 Mb/s (USB 2.0)
    Super,   //  5000 Mb/s (USB 3.0)
    Super20, // 10000 Mb/s (USB 3.1 Gen 2)
}

// ============================================================================
// USB Device Descriptor (first 18 bytes per USB 2.0 spec §9.6.1)
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub bcd_usb: u16, // BCD-encoded USB version, e.g. 0x0200 = USB 2.0
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
    pub b_num_configurations: u8,
}

impl UsbDeviceDescriptor {
    pub const fn zeroed() -> Self {
        UsbDeviceDescriptor {
            b_length: 0,
            b_descriptor_type: 0,
            bcd_usb: 0,
            b_device_class: 0,
            b_device_sub_class: 0,
            b_device_protocol: 0,
            b_max_packet_size0: 0,
            id_vendor: 0,
            id_product: 0,
            bcd_device: 0,
            i_manufacturer: 0,
            i_product: 0,
            i_serial_number: 0,
            b_num_configurations: 0,
        }
    }

    /// Return a human-readable USB class string.
    pub fn class_str(&self) -> &'static str {
        match self.b_device_class {
            0x00 => "Device (class in interface)",
            0x01 => "Audio",
            0x02 => "Communications (CDC)",
            0x03 => "Human Interface Device (HID)",
            0x05 => "Physical",
            0x06 => "Image",
            0x07 => "Printer",
            0x08 => "Mass Storage",
            0x09 => "USB Hub",
            0x0A => "CDC-Data",
            0x0B => "Smart Card",
            0x0D => "Content Security",
            0x0E => "Video",
            0x0F => "Personal Healthcare",
            0xDC => "Diagnostic Device",
            0xE0 => "Wireless Controller",
            0xEF => "Miscellaneous",
            0xFE => "Application Specific",
            0xFF => "Vendor Specific",
            _ => "Unknown",
        }
    }
}

// ============================================================================
// Enumerated USB device
// ============================================================================

/// A USB device that has been assigned an address and had its device descriptor
/// read successfully.
#[derive(Debug, Clone, Copy)]
pub struct UsbDevice {
    /// 1-based USB device address.
    pub address: u8,
    /// Port number on the hub/root hub (1-based).
    pub port: u8,
    /// Hub address (0 = root hub).
    pub hub_address: u8,
    pub speed: UsbSpeed,
    pub descriptor: UsbDeviceDescriptor,
    /// Index of the host controller that enumerated this device.
    pub controller_index: usize,
}

impl UsbDevice {
    pub fn is_hub(&self) -> bool {
        self.descriptor.b_device_class == 0x09
    }
    pub fn is_hid(&self) -> bool {
        self.descriptor.b_device_class == 0x03
    }
    pub fn is_mass_storage(&self) -> bool {
        self.descriptor.b_device_class == 0x08
    }
}

// ============================================================================
// UHCI Transfer Descriptor and Queue Head structures
// ============================================================================
//
// The UHCI spec (rev 1.1) §3.2 defines the 32-byte Transfer Descriptor (TD)
// and §3.3 the Queue Head (QH).  Both must be 16-byte aligned; we allocate them
// from a small static pool so no heap is required.
//
// Memory layout note: link pointers are physical addresses.  On i686 with
// identity-mapped low memory this equals the virtual address.

/// UHCI Transfer Descriptor (32 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct UhciTd {
    /// Link Pointer — physical address of next TD or QH, or 0x0000_0001 (Terminate).
    pub link: u32,
    /// Control and Status dword.
    pub ctrl: u32,
    /// Token dword: MaxLen | DataToggle | EndPt | DevAddr | PID.
    pub token: u32,
    /// Buffer Pointer — physical address of the data buffer.
    pub buffer: u32,
    // Software-use (not visible to hardware)
    _sw: [u32; 4],
}

// TD.link bits
const TD_LINK_TERM: u32 = 1 << 0; // Terminate (no next TD/QH)
const TD_LINK_QH: u32 = 1 << 1; // Next element is a QH
const TD_LINK_VF: u32 = 1 << 2; // Depth-first traversal

// TD.ctrl bits
const TD_CTRL_ACTLEN_MASK: u32 = 0x7FF; // Actual length (bits 10:0)
const TD_CTRL_STATUS_MASK: u32 = 0xFF << 16; // Status byte (bits 23:16)
const TD_CTRL_ACTIVE: u32 = 1 << 23; // Active (HC should process)
const TD_CTRL_STALLED: u32 = 1 << 22; // Stalled by HC
const TD_CTRL_DBUFERR: u32 = 1 << 21; // Data Buffer Error
const TD_CTRL_BABBLE: u32 = 1 << 20; // Babble detected
const TD_CTRL_NAK: u32 = 1 << 19; // NAK received
const TD_CTRL_CRCTERR: u32 = 1 << 18; // CRC/Timeout error
const TD_CTRL_BITSTUFF: u32 = 1 << 17; // Bit Stuff error
const TD_CTRL_IOC: u32 = 1 << 24; // Interrupt on Complete
const TD_CTRL_ISO: u32 = 1 << 25; // Isochronous TD
const TD_CTRL_LS: u32 = 1 << 26; // Low Speed Device
const TD_CTRL_ERRCNT_MASK: u32 = 3 << 27; // Error counter (2 bits)
const TD_CTRL_SPD: u32 = 1 << 29; // Short Packet Detect

// TD.token PID codes
const PID_SETUP: u8 = 0x2D;
const PID_IN: u8 = 0x69;
const PID_OUT: u8 = 0xE1;

impl UhciTd {
    pub const fn zeroed() -> Self {
        UhciTd {
            link: TD_LINK_TERM,
            ctrl: 0,
            token: 0,
            buffer: 0,
            _sw: [0; 4],
        }
    }

    /// Encode the token dword.
    /// `max_packet_len` is the maximum packet length (0 → encode as 0x7FF per spec).
    pub fn encode_token(
        pid: u8,
        dev_addr: u8,
        endpoint: u8,
        toggle: bool,
        max_packet_len: usize,
    ) -> u32 {
        let len_field = if max_packet_len == 0 {
            0x7FF
        } else {
            (max_packet_len as u32 - 1) & 0x7FF
        };
        ((len_field & 0x7FF) << 21)
            | (if toggle { 1u32 << 19 } else { 0 })
            | ((endpoint as u32 & 0xF) << 15)
            | ((dev_addr as u32 & 0x7F) << 8)
            | (pid as u32)
    }

    /// Set the Active bit and error counter.
    pub fn activate(&mut self, low_speed: bool, ioc: bool, err_count: u8) {
        self.ctrl = TD_CTRL_ACTIVE
            | (TD_CTRL_ERRCNT_MASK & ((err_count as u32 & 3) << 27))
            | (if low_speed { TD_CTRL_LS } else { 0 })
            | (if ioc { TD_CTRL_IOC } else { 0 });
    }

    pub fn is_active(&self) -> bool {
        self.ctrl & TD_CTRL_ACTIVE != 0
    }
    pub fn is_stalled(&self) -> bool {
        self.ctrl & TD_CTRL_STALLED != 0
    }
    pub fn actual_len(&self) -> usize {
        ((self.ctrl & TD_CTRL_ACTLEN_MASK) as usize + 1) & 0x7FF
    }
}

/// UHCI Queue Head (8 bytes, 16-byte aligned)
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct UhciQh {
    /// Horizontal Link Pointer — next QH in the schedule (or Terminate).
    pub hlp: u32,
    /// Vertical Link Pointer — first TD in this queue (or Terminate).
    pub vlp: u32,
}

impl UhciQh {
    pub const fn terminated() -> Self {
        UhciQh {
            hlp: TD_LINK_TERM,
            vlp: TD_LINK_TERM,
        }
    }
}

// ============================================================================
// Static TD/QH pool — avoids heap allocation
// ============================================================================

const UHCI_TD_POOL_SIZE: usize = 64;
const UHCI_QH_POOL_SIZE: usize = 16;

/// Per-controller transfer pool.  Embedded in `UhciController` to avoid
/// requiring a global allocator at driver init time.
pub struct UhciPool {
    tds: [UhciTd; UHCI_TD_POOL_SIZE],
    qhs: [UhciQh; UHCI_QH_POOL_SIZE],
    td_used: [bool; UHCI_TD_POOL_SIZE],
    qh_used: [bool; UHCI_QH_POOL_SIZE],
}

impl UhciPool {
    pub const fn new() -> Self {
        UhciPool {
            tds: [UhciTd {
                link: TD_LINK_TERM,
                ctrl: 0,
                token: 0,
                buffer: 0,
                _sw: [0; 4],
            }; UHCI_TD_POOL_SIZE],
            qhs: [UhciQh {
                hlp: TD_LINK_TERM,
                vlp: TD_LINK_TERM,
            }; UHCI_QH_POOL_SIZE],
            td_used: [false; UHCI_TD_POOL_SIZE],
            qh_used: [false; UHCI_QH_POOL_SIZE],
        }
    }

    /// Allocate a TD from the pool, returning its index or `None` if full.
    pub fn alloc_td(&mut self) -> Option<usize> {
        for (i, used) in self.td_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.tds[i] = UhciTd::zeroed();
                return Some(i);
            }
        }
        None
    }

    /// Allocate a QH from the pool.
    pub fn alloc_qh(&mut self) -> Option<usize> {
        for (i, used) in self.qh_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.qhs[i] = UhciQh::terminated();
                return Some(i);
            }
        }
        None
    }

    /// Return a TD to the pool.
    pub fn free_td(&mut self, idx: usize) {
        if idx < UHCI_TD_POOL_SIZE {
            self.td_used[idx] = false;
        }
    }

    /// Return a QH to the pool.
    pub fn free_qh(&mut self, idx: usize) {
        if idx < UHCI_QH_POOL_SIZE {
            self.qh_used[idx] = false;
        }
    }

    pub fn td_phys(&self, idx: usize) -> u32 {
        &self.tds[idx] as *const UhciTd as u32
    }

    pub fn qh_phys(&self, idx: usize) -> u32 {
        &self.qhs[idx] as *const UhciQh as u32
    }
}

// ============================================================================
// UHCI frame list (1024 entries × 4 bytes, 4 KiB aligned)
// ============================================================================

#[repr(C, align(4096))]
pub struct UhciFrameList {
    pub entries: [u32; 1024],
}

impl UhciFrameList {
    pub const fn new() -> Self {
        UhciFrameList {
            entries: [TD_LINK_TERM; 1024],
        }
    }
}

// Static frame list — one per system (we only run one UHCI at a time on the
// target hardware; if multiple exist the last init wins, which is acceptable
// for the current single-bus topology).
static mut UHCI_FRAME_LIST: UhciFrameList = UhciFrameList::new();

// ============================================================================
// UHCI Host Controller  (complete implementation)
// ============================================================================

/// Maximum number of UHCI root hub ports we scan (real controllers have 2).
const UHCI_MAX_PORTS: usize = 2;

/// UHCI Command Register (USBCMD)
const UHCI_USBCMD: u16 = 0x00;
/// UHCI Status Register (USBSTS)
const UHCI_USBSTS: u16 = 0x02;
/// UHCI Interrupt Enable (USBINTR)
const UHCI_USBINTR: u16 = 0x04;
/// UHCI Frame Number Register
const UHCI_FRNUM: u16 = 0x06;
/// UHCI Frame List Base Address (32-bit physical)
const UHCI_FLBASEADDR: u16 = 0x08;
/// UHCI Start-of-Frame Modify Register
const UHCI_SOFMOD: u16 = 0x0C;
/// UHCI Port Status/Control register base
const UHCI_PORTSC_BASE: u16 = 0x10;

// USBCMD bits
const UHCI_CMD_RS: u16 = 1 << 0;
const UHCI_CMD_HCRESET: u16 = 1 << 1;
const UHCI_CMD_GRESET: u16 = 1 << 2;
const UHCI_CMD_EGSM: u16 = 1 << 3;
const UHCI_CMD_FGR: u16 = 1 << 4;

// PORTSC bits
const UHCI_PORT_CCS: u16 = 1 << 0;
const UHCI_PORT_CSC: u16 = 1 << 1;
const UHCI_PORT_PED: u16 = 1 << 2;
const UHCI_PORT_PEDC: u16 = 1 << 3;
const UHCI_PORT_LSDA: u16 = 1 << 8;
const UHCI_PORT_PR: u16 = 1 << 9;

#[inline]
unsafe fn inw_port(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port,
                     options(nomem, nostack, preserves_flags));
    v
}

#[inline]
unsafe fn outw_port(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val,
                     options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn outb_port(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val,
                     options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn outl_port(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val,
                     options(nomem, nostack, preserves_flags));
}

/// Result of a UHCI control or bulk transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UhciXferResult {
    Ok,
    Stalled,
    Timeout,
    BusError,
    NoTds,
}

/// UHCI host controller — full implementation.
pub struct UhciController {
    pub io_base: u16,
    pub port_count: usize,
    pub initialised: bool,
    pub pci: PciDevice,
    pub pool: UhciPool,
}

impl UhciController {
    pub const fn new(io_base: u16, pci: PciDevice) -> Self {
        UhciController {
            io_base,
            port_count: 0,
            initialised: false,
            pci,
            pool: UhciPool::new(),
        }
    }

    // ----------------------------------------------------------------
    // Register I/O helpers
    // ----------------------------------------------------------------
    unsafe fn read_cmd(&self) -> u16 {
        inw_port(self.io_base + UHCI_USBCMD)
    }
    unsafe fn read_sts(&self) -> u16 {
        inw_port(self.io_base + UHCI_USBSTS)
    }
    unsafe fn write_cmd(&self, v: u16) {
        outw_port(self.io_base + UHCI_USBCMD, v);
    }
    unsafe fn write_sts(&self, v: u16) {
        outw_port(self.io_base + UHCI_USBSTS, v);
    }

    unsafe fn portsc(&self, port: usize) -> u16 {
        inw_port(self.io_base + UHCI_PORTSC_BASE + (port as u16) * 2)
    }
    unsafe fn write_portsc(&self, port: usize, v: u16) {
        outw_port(self.io_base + UHCI_PORTSC_BASE + (port as u16) * 2, v);
    }

    // ----------------------------------------------------------------
    // Initialisation — sets up the frame list and starts the HC
    // ----------------------------------------------------------------
    pub fn init(&mut self) {
        unsafe {
            // Global reset (~10 ms)
            self.write_cmd(UHCI_CMD_GRESET);
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }
            self.write_cmd(0);

            // Host controller reset — wait for completion
            self.write_cmd(UHCI_CMD_HCRESET);
            for _ in 0..50_000 {
                if self.read_cmd() & UHCI_CMD_HCRESET == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // Clear any stale status
            self.write_sts(0x3F);
            // Disable all interrupts (polled mode)
            outw_port(self.io_base + UHCI_USBINTR, 0);
            // Default SOF timing
            outb_port(self.io_base + UHCI_SOFMOD, 0x40);
            // Reset frame number
            outw_port(self.io_base + UHCI_FRNUM, 0);

            // Point the HC at our frame list (1024 × 4 = 4096 bytes)
            let fl_phys = &UHCI_FRAME_LIST as *const UhciFrameList as u32;
            outl_port(self.io_base + UHCI_FLBASEADDR, fl_phys);

            // Start the schedule
            self.write_cmd(UHCI_CMD_RS);

            // Detect port count
            self.port_count = 0;
            for p in 0..UHCI_MAX_PORTS {
                let v = self.portsc(p);
                if v & 0x0080 != 0 {
                    self.port_count += 1;
                }
            }
        }
        self.initialised = true;
    }

    // ----------------------------------------------------------------
    // Port management
    // ----------------------------------------------------------------

    pub fn reset_port(&self, port: usize) -> Option<UsbSpeed> {
        if port >= self.port_count {
            return None;
        }
        unsafe {
            self.write_portsc(port, UHCI_PORT_PR);
            for _ in 0..500_000 {
                core::hint::spin_loop();
            }
            let v = self.portsc(port) & !UHCI_PORT_PR;
            self.write_portsc(port, v);
            for _ in 0..4 {
                core::hint::spin_loop();
            }

            let v2 = self.portsc(port);
            self.write_portsc(port, v2 | UHCI_PORT_CSC | UHCI_PORT_PEDC);

            let v3 = self.portsc(port);
            if v3 & UHCI_PORT_CCS == 0 {
                return None;
            }

            self.write_portsc(port, v3 | UHCI_PORT_PED);
            for _ in 0..4 {
                core::hint::spin_loop();
            }

            let v4 = self.portsc(port);
            Some(if v4 & UHCI_PORT_LSDA != 0 {
                UsbSpeed::Low
            } else {
                UsbSpeed::Full
            })
        }
    }

    pub fn probe_ports(&self) -> alloc::vec::Vec<(usize, UsbSpeed)> {
        let mut found = alloc::vec::Vec::new();
        for p in 0..self.port_count {
            if let Some(spd) = self.reset_port(p) {
                found.push((p, spd));
            }
        }
        found
    }

    // ----------------------------------------------------------------
    // Low-level: queue a TD chain linked through the frame list
    // ----------------------------------------------------------------

    /// Insert `head_phys` (physical address of first TD) into every frame-list
    /// slot and wait until all TDs become inactive, then remove them.
    ///
    /// # Safety
    /// `head_phys` must be a valid physical pointer to a chain of `UhciTd`s.
    unsafe fn schedule_and_wait(&self, head_phys: u32) -> UhciXferResult {
        // Insert into every frame slot so the HC picks it up on the next SOF.
        for slot in UHCI_FRAME_LIST.entries.iter_mut() {
            *slot = head_phys; // TD, depth-first
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);

        // Poll for completion (up to ~5000 ms equivalent spin)
        let mut td_ptr = head_phys as *mut UhciTd;
        let timeout_iters = 5_000_000u32;
        let mut iters = 0u32;
        loop {
            // Walk chain looking for any still-active TD
            let mut all_done = true;
            let mut p = head_phys as *mut UhciTd;
            loop {
                let ctrl = core::ptr::read_volatile(&(*p).ctrl);
                if ctrl & TD_CTRL_ACTIVE != 0 {
                    all_done = false;
                    break;
                }
                if ctrl
                    & (TD_CTRL_STALLED
                        | TD_CTRL_DBUFERR
                        | TD_CTRL_BABBLE
                        | TD_CTRL_CRCTERR
                        | TD_CTRL_BITSTUFF)
                    != 0
                {
                    // Remove from schedule
                    for slot in UHCI_FRAME_LIST.entries.iter_mut() {
                        *slot = TD_LINK_TERM;
                    }
                    let ctrl2 = core::ptr::read_volatile(&(*p).ctrl);
                    return if ctrl2 & TD_CTRL_STALLED != 0 {
                        UhciXferResult::Stalled
                    } else {
                        UhciXferResult::BusError
                    };
                }
                let link = core::ptr::read_volatile(&(*p).link);
                if link & TD_LINK_TERM != 0 {
                    break;
                }
                p = (link & !0x0F) as *mut UhciTd;
            }
            let _ = td_ptr; // suppress unused warning

            if all_done {
                for slot in UHCI_FRAME_LIST.entries.iter_mut() {
                    *slot = TD_LINK_TERM;
                }
                return UhciXferResult::Ok;
            }
            iters += 1;
            if iters >= timeout_iters {
                for slot in UHCI_FRAME_LIST.entries.iter_mut() {
                    *slot = TD_LINK_TERM;
                }
                return UhciXferResult::Timeout;
            }
            core::hint::spin_loop();
            td_ptr = head_phys as *mut UhciTd; // suppress move-out warning
        }
    }

    // ----------------------------------------------------------------
    // Control transfer  (SETUP + [DATA stage] + STATUS)
    // ----------------------------------------------------------------
    //
    // A USB control transfer has three stages:
    //   1. SETUP  — host sends 8-byte `UsbSetupPacket` (PID_SETUP, toggle=0)
    //   2. DATA   — zero or more DATA IN/OUT packets (PID_IN/OUT, toggle starts at 1)
    //   3. STATUS — direction opposite to data stage (toggle=1)
    //
    // We build one TD per stage and link them in a chain.

    pub fn control_transfer(
        &mut self,
        dev_addr: u8,
        low_speed: bool,
        setup: &UsbSetupPacket,
        data: Option<&mut [u8]>, // None for zero-length data stage
        dir_in: bool,            // true = device→host in data stage
    ) -> UhciXferResult {
        // We need at minimum 2 TDs (SETUP + STATUS) and up to 2 + N data TDs.
        let data_len = data.as_ref().map_or(0, |b| b.len());
        let max_pkt = 8usize; // EP0 max packet size always 8 for low-speed
        let data_tds = if data_len == 0 {
            0
        } else {
            (data_len + max_pkt - 1) / max_pkt
        };
        let total_tds = 2 + data_tds;

        if total_tds > UHCI_TD_POOL_SIZE {
            return UhciXferResult::NoTds;
        }

        // Allocate TDs
        let mut td_indices = [0usize; 16];
        for i in 0..total_tds {
            match self.pool.alloc_td() {
                Some(idx) => td_indices[i] = idx,
                None => {
                    for j in 0..i {
                        self.pool.free_td(td_indices[j]);
                    }
                    return UhciXferResult::NoTds;
                }
            }
        }

        let setup_phys = setup as *const UsbSetupPacket as u32;
        let low_speed_flag = low_speed;
        let err = 3u8;

        // ---- SETUP TD (index 0) ----
        {
            let td = &mut self.pool.tds[td_indices[0]];
            td.token = UhciTd::encode_token(PID_SETUP, dev_addr, 0, false, 8);
            td.buffer = setup_phys;
            td.activate(low_speed_flag, false, err);
        }

        // ---- DATA TDs (indices 1..=data_tds) ----
        let mut toggle = true;
        if let Some(ref buf) = data {
            for i in 0..data_tds {
                let offset = i * max_pkt;
                let chunk = core::cmp::min(max_pkt, data_len - offset);
                let pid = if dir_in { PID_IN } else { PID_OUT };
                let td = &mut self.pool.tds[td_indices[1 + i]];
                td.token = UhciTd::encode_token(pid, dev_addr, 0, toggle, chunk);
                td.buffer = (buf.as_ptr() as usize + offset) as u32;
                td.activate(low_speed_flag, false, err);
                toggle = !toggle;
            }
        }

        // ---- STATUS TD (last) ----
        {
            // Status PID is opposite of data stage direction
            let pid = if dir_in || data_len == 0 {
                PID_OUT
            } else {
                PID_IN
            };
            let td = &mut self.pool.tds[td_indices[total_tds - 1]];
            td.token = UhciTd::encode_token(pid, dev_addr, 0, true, 0);
            td.buffer = 0;
            td.ctrl |= TD_CTRL_SPD; // Short Packet Detect
            td.activate(low_speed_flag, true, err);
        }

        // Link TDs together
        for i in 0..total_tds - 1 {
            let next_phys = self.pool.td_phys(td_indices[i + 1]);
            self.pool.tds[td_indices[i]].link = next_phys; // depth-first, no VF
        }
        self.pool.tds[td_indices[total_tds - 1]].link = TD_LINK_TERM;

        let head_phys = self.pool.td_phys(td_indices[0]);
        let result = unsafe { self.schedule_and_wait(head_phys) };

        for i in 0..total_tds {
            self.pool.free_td(td_indices[i]);
        }
        result
    }

    // ----------------------------------------------------------------
    // Bulk transfer  (IN or OUT, arbitrary length)
    // ----------------------------------------------------------------
    //
    // Splits `data` into max_packet_size chunks, alternating DATA0/DATA1 toggle.
    // Used by the Mass Storage BOT driver.

    pub fn bulk_transfer(
        &mut self,
        dev_addr: u8,
        endpoint: u8,
        low_speed: bool,
        dir_in: bool,
        max_pkt: usize,
        data: &mut [u8],
        toggle: &mut bool,
    ) -> UhciXferResult {
        let total = data.len();
        if total == 0 {
            return UhciXferResult::Ok;
        }

        let pid = if dir_in { PID_IN } else { PID_OUT };
        let mut offset = 0;

        while offset < total {
            let chunk = core::cmp::min(max_pkt, total - offset);
            let td_idx = match self.pool.alloc_td() {
                Some(i) => i,
                None => return UhciXferResult::NoTds,
            };
            {
                let td = &mut self.pool.tds[td_idx];
                td.token = UhciTd::encode_token(pid, dev_addr, endpoint, *toggle, chunk);
                td.buffer = (data.as_mut_ptr() as usize + offset) as u32;
                td.link = TD_LINK_TERM;
                td.activate(low_speed, true, 3);
            }
            let phys = self.pool.td_phys(td_idx);
            let result = unsafe { self.schedule_and_wait(phys) };
            self.pool.free_td(td_idx);

            match result {
                UhciXferResult::Ok => {}
                other => return other,
            }
            *toggle = !*toggle;
            offset += chunk;
        }
        UhciXferResult::Ok
    }

    // ----------------------------------------------------------------
    // Interrupt transfer  (IN, single TD, non-blocking enqueue)
    // ----------------------------------------------------------------
    //
    // For HID devices: inserts a single IN TD into the frame list with IOC set.
    // The caller is responsible for polling the TD's Active bit.
    //
    // Returns the physical address of the TD so the caller can poll it.

    pub fn interrupt_transfer_enqueue(
        &mut self,
        dev_addr: u8,
        endpoint: u8,
        low_speed: bool,
        max_pkt: usize,
        buf: &mut [u8],
        toggle: bool,
    ) -> Option<u32> {
        let td_idx = self.pool.alloc_td()?;
        {
            let td = &mut self.pool.tds[td_idx];
            td.token = UhciTd::encode_token(PID_IN, dev_addr, endpoint, toggle, max_pkt);
            td.buffer = buf.as_mut_ptr() as u32;
            td.link = TD_LINK_TERM;
            td.ctrl =
                TD_CTRL_ACTIVE | TD_CTRL_IOC | (3 << 27) | (if low_speed { TD_CTRL_LS } else { 0 });
        }
        let phys = self.pool.td_phys(td_idx);
        // Insert into frame 0 only (8 ms period for full-speed, 8 ms for low-speed)
        unsafe {
            UHCI_FRAME_LIST.entries[0] = phys;
        }
        Some(phys)
    }
}

// ============================================================================
// USB Setup Packet (USB 2.0 spec §9.3)
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UsbSetupPacket {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

// bmRequestType directions
pub const RT_HOST_TO_DEV: u8 = 0x00;
pub const RT_DEV_TO_HOST: u8 = 0x80;
// bmRequestType types
pub const RT_STANDARD: u8 = 0x00;
pub const RT_CLASS: u8 = 0x20;
// bmRequestType recipients
pub const RT_DEVICE: u8 = 0x00;
pub const RT_INTERFACE: u8 = 0x01;
pub const RT_ENDPOINT: u8 = 0x02;

// Standard requests (bRequest)
pub const REQ_GET_STATUS: u8 = 0x00;
pub const REQ_CLEAR_FEATURE: u8 = 0x01;
pub const REQ_SET_FEATURE: u8 = 0x03;
pub const REQ_SET_ADDRESS: u8 = 0x05;
pub const REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const REQ_GET_CONFIGURATION: u8 = 0x08;
pub const REQ_SET_CONFIGURATION: u8 = 0x09;
pub const REQ_GET_INTERFACE: u8 = 0x0A;
pub const REQ_SET_INTERFACE: u8 = 0x0B;
// Descriptor types (wValue high byte)
pub const DESC_DEVICE: u8 = 0x01;
pub const DESC_CONFIGURATION: u8 = 0x02;
pub const DESC_STRING: u8 = 0x03;
pub const DESC_INTERFACE: u8 = 0x04;
pub const DESC_ENDPOINT: u8 = 0x05;

impl UsbSetupPacket {
    /// Build a GET_DESCRIPTOR(Device) request.
    pub const fn get_device_descriptor() -> Self {
        UsbSetupPacket {
            bm_request_type: RT_DEV_TO_HOST | RT_STANDARD | RT_DEVICE,
            b_request: REQ_GET_DESCRIPTOR,
            w_value: (DESC_DEVICE as u16) << 8,
            w_index: 0,
            w_length: 18,
        }
    }

    /// Build a SET_ADDRESS request.
    pub const fn set_address(addr: u8) -> Self {
        UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_STANDARD | RT_DEVICE,
            b_request: REQ_SET_ADDRESS,
            w_value: addr as u16,
            w_index: 0,
            w_length: 0,
        }
    }

    /// Build a SET_CONFIGURATION request.
    pub const fn set_configuration(config: u8) -> Self {
        UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_STANDARD | RT_DEVICE,
            b_request: REQ_SET_CONFIGURATION,
            w_value: config as u16,
            w_index: 0,
            w_length: 0,
        }
    }
}

// ============================================================================
// OHCI host controller — full implementation
// ============================================================================
//
// OHCI (Open HCI) uses MMIO registers and two data structures:
//   • HCCA  — Host Controller Communications Area (256 bytes, 256-byte aligned)
//   • ED    — Endpoint Descriptor (16 bytes, 4-byte aligned)
//   • TD    — Transfer Descriptor  (16 bytes, 4-byte aligned)
//
// The host controller manages a linked list of EDs; each ED points to a chain
// of TDs.  We keep a small static pool for EDs and TDs.

/// OHCI HCCA — 256 bytes, 256-byte aligned (OHCI spec §4.4.1)
#[repr(C, align(256))]
pub struct OhciHcca {
    /// Interrupt table: 32 head pointers for periodic endpoints.
    pub interrupt_table: [u32; 32],
    /// Frame number written by HC each SOF.
    pub frame_number: u16,
    pub pad1: u16,
    /// Done head pointer written by HC after each frame with completed TDs.
    pub done_head: u32,
    _reserved: [u8; 116],
}

impl OhciHcca {
    pub const fn new() -> Self {
        OhciHcca {
            interrupt_table: [0; 32],
            frame_number: 0,
            pad1: 0,
            done_head: 0,
            _reserved: [0; 116],
        }
    }
}

/// OHCI Endpoint Descriptor (16 bytes, 4-byte aligned)
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct OhciEd {
    /// Control word: MaxPacketSize | F | K | S | D | EN | FA
    pub ctrl: u32,
    /// TailP — physical address of last TD (not to be processed by HC)
    pub tail_p: u32,
    /// HeadP — physical address of next TD to process + Carry + Halt bits
    pub head_p: u32,
    /// NextED — physical address of next ED in list (0 = end)
    pub next_ed: u32,
}

// ED.ctrl bits
const ED_CTRL_FA_MASK: u32 = 0x7F; // Function Address (device addr)
const ED_CTRL_EN_SHIFT: u32 = 7; // Endpoint Number
const ED_CTRL_D_SHIFT: u32 = 11; // Direction: 0=GetFromTD,1=Out,2=In
const ED_CTRL_S: u32 = 1 << 13; // Speed: 0=full, 1=low
const ED_CTRL_K: u32 = 1 << 14; // Skip (halt this ED)
const ED_CTRL_MPS_SHIFT: u32 = 16; // MaxPacketSize

const ED_HEADP_HALT: u32 = 1 << 0; // Halted
const ED_HEADP_CARRY: u32 = 1 << 1; // Data toggle carry

impl OhciEd {
    pub const fn zeroed() -> Self {
        OhciEd {
            ctrl: 0,
            tail_p: 0,
            head_p: 0,
            next_ed: 0,
        }
    }
    pub fn setup(
        &mut self,
        dev_addr: u8,
        endpoint: u8,
        low_speed: bool,
        max_pkt: u16,
        dir_from_td: bool,
    ) {
        let d = if dir_from_td { 0u32 } else { 0u32 }; // always GetFromTD for control
        let _ = d;
        self.ctrl = (dev_addr as u32 & ED_CTRL_FA_MASK)
            | ((endpoint as u32 & 0xF) << ED_CTRL_EN_SHIFT)
            | (if low_speed { ED_CTRL_S } else { 0 })
            | ((max_pkt as u32 & 0x7FF) << ED_CTRL_MPS_SHIFT);
        self.tail_p = 0;
        self.head_p = 0;
        self.next_ed = 0;
    }
}

/// OHCI Transfer Descriptor (16 bytes, 4-byte aligned)
#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct OhciTd {
    /// Control: CC | EC | T | DI | DP | R
    pub ctrl: u32,
    /// CBP — Current Buffer Pointer (physical)
    pub cbp: u32,
    /// NextTD — physical address of next TD (or 0)
    pub next_td: u32,
    /// BE — Buffer End (physical address of last byte)
    pub be: u32,
}

// TD.ctrl bits
const OHCI_TD_CC_SHIFT: u32 = 28; // Condition Code (error status) bits 31:28
const OHCI_TD_CC_NOERR: u32 = 0xE << 28; // Not yet processed
const OHCI_TD_R: u32 = 1 << 18; // Buffer Rounding
const OHCI_TD_DP_MASK: u32 = 3 << 19; // Direction/PID: 0=SETUP,1=OUT,2=IN
const OHCI_TD_DP_SETUP: u32 = 0 << 19;
const OHCI_TD_DP_OUT: u32 = 1 << 19;
const OHCI_TD_DP_IN: u32 = 2 << 19;
const OHCI_TD_DI_MASK: u32 = 7 << 21; // Delay Interrupt (0=immediate,7=none)
const OHCI_TD_DI_NONE: u32 = 7 << 21;
const OHCI_TD_T_MASK: u32 = 3 << 24; // Data Toggle
const OHCI_TD_T_DATA0: u32 = 2 << 24; // Force DATA0
const OHCI_TD_T_DATA1: u32 = 3 << 24; // Force DATA1
const OHCI_TD_T_CARRY: u32 = 0 << 24; // Use ED carry bit

impl OhciTd {
    pub const fn zeroed() -> Self {
        OhciTd {
            ctrl: 0,
            cbp: 0,
            next_td: 0,
            be: 0,
        }
    }
}

// OHCI MMIO register offsets
const OHCI_HCREVISION: usize = 0x00;
const OHCI_HCCONTROL: usize = 0x04;
const OHCI_HCCOMMANDSTATUS: usize = 0x08;
const OHCI_HCINTERRUPTSTATUS: usize = 0x0C;
const OHCI_HCINTERRUPTENABLE: usize = 0x10;
const OHCI_HCINTERRUPTDISABLE: usize = 0x14;
const OHCI_HCHCCA: usize = 0x18;
const OHCI_HCPERIODCURRENTED: usize = 0x1C;
const OHCI_HCCONTROLHEADED: usize = 0x20;
const OHCI_HCCONTROLCURRENTED: usize = 0x24;
const OHCI_HCBULKHEADED: usize = 0x28;
const OHCI_HCBULKCURRENTED: usize = 0x2C;
const OHCI_HCDONEHEAD: usize = 0x30;
const OHCI_HCFMINTERVAL: usize = 0x34;
const OHCI_HCFMREMAINING: usize = 0x38;
const OHCI_HCFMNUMBER: usize = 0x3C;
const OHCI_HCPERIODICSTART: usize = 0x40;
const OHCI_HCLSTHRESHOLD: usize = 0x44;
const OHCI_HCRHDESCRIPTORA: usize = 0x48;
const OHCI_HCRHDESCRIPTORB: usize = 0x4C;
const OHCI_HCRHSTATUS: usize = 0x50;
const OHCI_HCRHPORTSTATUS: usize = 0x54; // +4 per port

// HcControl bits
const OHCI_CTL_CBSR_MASK: u32 = 3 << 0; // ControlBulkServiceRatio
const OHCI_CTL_PLE: u32 = 1 << 2; // PeriodicListEnable
const OHCI_CTL_IE: u32 = 1 << 3; // IsochronousEnable
const OHCI_CTL_CLE: u32 = 1 << 4; // ControlListEnable
const OHCI_CTL_BLE: u32 = 1 << 5; // BulkListEnable
const OHCI_CTL_HCFS_MASK: u32 = 3 << 6; // HostControllerFunctionalState
const OHCI_CTL_HCFS_RESET: u32 = 0 << 6;
const OHCI_CTL_HCFS_RESM: u32 = 1 << 6;
const OHCI_CTL_HCFS_OPER: u32 = 2 << 6; // Operational
const OHCI_CTL_HCFS_SUSP: u32 = 3 << 6;
const OHCI_CTL_IR: u32 = 1 << 8; // InterruptRouting (BIOS owns)

// HcCommandStatus bits
const OHCI_CS_HCR: u32 = 1 << 0; // HostControllerReset
const OHCI_CS_OCR: u32 = 1 << 3; // OwnershipChangeRequest

// HcRhPortStatus bits (OHCI spec §7.4.4)
const OHCI_PORT_CCS: u32 = 1 << 0; // CurrentConnectStatus
const OHCI_PORT_PES: u32 = 1 << 1; // PortEnableStatus
const OHCI_PORT_PSS: u32 = 1 << 2; // PortSuspendStatus
const OHCI_PORT_POCI: u32 = 1 << 3; // PortOverCurrentIndicator
const OHCI_PORT_PRS: u32 = 1 << 4; // PortResetStatus
const OHCI_PORT_PPS: u32 = 1 << 8; // PortPowerStatus
const OHCI_PORT_LSDA: u32 = 1 << 9; // LowSpeedDeviceAttached
const OHCI_PORT_CSC: u32 = 1 << 16; // ConnectStatusChange
const OHCI_PORT_PESC: u32 = 1 << 17; // PortEnableStatusChange
const OHCI_PORT_PRSC: u32 = 1 << 20; // PortResetStatusChange

// Write to port: set individual features
const OHCI_PORT_SET_RESET: u32 = 1 << 4; // SetPortReset
const OHCI_PORT_SET_ENABLE: u32 = 1 << 1; // SetPortEnable

const OHCI_ED_POOL: usize = 8;
const OHCI_TD_POOL: usize = 32;

static mut OHCI_HCCA: OhciHcca = OhciHcca::new();

pub struct OhciPool {
    eds: [OhciEd; OHCI_ED_POOL],
    tds: [OhciTd; OHCI_TD_POOL],
    ed_used: [bool; OHCI_ED_POOL],
    td_used: [bool; OHCI_TD_POOL],
}

impl OhciPool {
    pub const fn new() -> Self {
        OhciPool {
            eds: [OhciEd {
                ctrl: 0,
                tail_p: 0,
                head_p: 0,
                next_ed: 0,
            }; OHCI_ED_POOL],
            tds: [OhciTd {
                ctrl: 0,
                cbp: 0,
                next_td: 0,
                be: 0,
            }; OHCI_TD_POOL],
            ed_used: [false; OHCI_ED_POOL],
            td_used: [false; OHCI_TD_POOL],
        }
    }
    pub fn alloc_ed(&mut self) -> Option<usize> {
        self.ed_used
            .iter_mut()
            .enumerate()
            .find(|(_, u)| !**u)
            .map(|(i, u)| {
                *u = true;
                self.eds[i] = OhciEd::zeroed();
                i
            })
    }
    pub fn alloc_td(&mut self) -> Option<usize> {
        self.td_used
            .iter_mut()
            .enumerate()
            .find(|(_, u)| !**u)
            .map(|(i, u)| {
                *u = true;
                self.tds[i] = OhciTd::zeroed();
                i
            })
    }
    pub fn free_ed(&mut self, i: usize) {
        if i < OHCI_ED_POOL {
            self.ed_used[i] = false;
        }
    }
    pub fn free_td(&mut self, i: usize) {
        if i < OHCI_TD_POOL {
            self.td_used[i] = false;
        }
    }
    pub fn ed_phys(&self, i: usize) -> u32 {
        &self.eds[i] as *const OhciEd as u32
    }
    pub fn td_phys(&self, i: usize) -> u32 {
        &self.tds[i] as *const OhciTd as u32
    }
}

/// OHCI host controller — full implementation.
pub struct OhciController {
    pub mmio_base: usize,
    pub initialised: bool,
    pub port_count: usize,
    pub pci: PciDevice,
    pub pool: OhciPool,
}

impl OhciController {
    pub const fn new(mmio_base: usize, pci: PciDevice) -> Self {
        OhciController {
            mmio_base,
            initialised: false,
            port_count: 0,
            pci,
            pool: OhciPool::new(),
        }
    }

    unsafe fn read32(&self, off: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u32)
    }
    unsafe fn write32(&self, off: usize, v: u32) {
        core::ptr::write_volatile((self.mmio_base + off) as *mut u32, v);
    }
    unsafe fn port_status(&self, port: usize) -> u32 {
        self.read32(OHCI_HCRHPORTSTATUS + port * 4)
    }
    unsafe fn write_port(&self, port: usize, v: u32) {
        self.write32(OHCI_HCRHPORTSTATUS + port * 4, v);
    }

    // ----------------------------------------------------------------
    // BIOS → OS ownership hand-off
    // ----------------------------------------------------------------
    pub fn bios_handoff(&mut self) {
        unsafe {
            self.write32(OHCI_HCCOMMANDSTATUS, OHCI_CS_OCR);
            let mut i = 0u32;
            loop {
                if self.read32(OHCI_HCCONTROL) & OHCI_CTL_IR == 0 {
                    break;
                }
                i += 1;
                if i > 100_000 {
                    break;
                }
                core::hint::spin_loop();
            }
        }
    }

    // ----------------------------------------------------------------
    // Full initialisation — HCCA, control list, operational state
    // ----------------------------------------------------------------
    pub fn init(&mut self) {
        self.bios_handoff();
        unsafe {
            // Software reset
            self.write32(OHCI_HCCOMMANDSTATUS, OHCI_CS_HCR);
            for _ in 0..10_000 {
                core::hint::spin_loop();
            }

            // Configure HCCA
            let hcca_phys = &OHCI_HCCA as *const OhciHcca as u32;
            self.write32(OHCI_HCHCCA, hcca_phys);

            // Set FmInterval to default (11999, Fit=1)
            self.write32(OHCI_HCFMINTERVAL, (1 << 31) | (0x2EDF) | (0x7782 << 16));
            self.write32(OHCI_HCPERIODICSTART, 0x2A2F);
            self.write32(OHCI_HCLSTHRESHOLD, 0x628);

            // Enable control + bulk lists, go operational
            let ctrl = OHCI_CTL_HCFS_OPER | OHCI_CTL_CLE | OHCI_CTL_BLE | OHCI_CTL_PLE;
            self.write32(OHCI_HCCONTROL, ctrl);

            // Disable all interrupts (polled)
            self.write32(OHCI_HCINTERRUPTDISABLE, 0xFFFF_FFFF);
            self.write32(OHCI_HCINTERRUPTSTATUS, 0xFFFF_FFFF);

            // Power on all ports and count them
            let desc_a = self.read32(OHCI_HCRHDESCRIPTORA);
            self.port_count = (desc_a & 0xFF) as usize;
            for p in 0..self.port_count {
                self.write_port(p, 1 << 8); // SetPortPower
            }
            // Wait for ports to stabilise
            for _ in 0..200_000 {
                core::hint::spin_loop();
            }
        }
        self.initialised = true;
    }

    // ----------------------------------------------------------------
    // Port reset
    // ----------------------------------------------------------------
    pub fn reset_port(&self, port: usize) -> Option<UsbSpeed> {
        unsafe {
            self.write_port(port, OHCI_PORT_SET_RESET);
            // Wait for PRS to clear (HC sets PRSC when done)
            let mut i = 0u32;
            loop {
                let st = self.port_status(port);
                if st & OHCI_PORT_PRS == 0 {
                    break;
                }
                i += 1;
                if i > 500_000 {
                    return None;
                }
                core::hint::spin_loop();
            }
            // Clear status-change bits
            self.write_port(port, OHCI_PORT_CSC | OHCI_PORT_PESC | OHCI_PORT_PRSC);

            let st = self.port_status(port);
            if st & OHCI_PORT_CCS == 0 {
                return None;
            }

            // Enable port
            self.write_port(port, OHCI_PORT_SET_ENABLE);
            for _ in 0..4 {
                core::hint::spin_loop();
            }

            Some(if self.port_status(port) & OHCI_PORT_LSDA != 0 {
                UsbSpeed::Low
            } else {
                UsbSpeed::Full
            })
        }
    }

    pub fn probe_ports(&self) -> alloc::vec::Vec<(usize, UsbSpeed)> {
        let mut out = alloc::vec::Vec::new();
        for p in 0..self.port_count {
            if let Some(spd) = self.reset_port(p) {
                out.push((p, spd));
            }
        }
        out
    }

    // ----------------------------------------------------------------
    // Control transfer via OHCI control list
    // ----------------------------------------------------------------
    pub fn control_transfer(
        &mut self,
        dev_addr: u8,
        low_speed: bool,
        setup: &UsbSetupPacket,
        data: Option<&mut [u8]>,
        dir_in: bool,
    ) -> bool {
        let data_len = data.as_ref().map_or(0, |b| b.len());

        let ed_idx = match self.pool.alloc_ed() {
            Some(i) => i,
            None => return false,
        };
        let setup_td = match self.pool.alloc_td() {
            Some(i) => i,
            None => {
                self.pool.free_ed(ed_idx);
                return false;
            }
        };
        let status_td = match self.pool.alloc_td() {
            Some(i) => i,
            None => {
                self.pool.free_td(setup_td);
                self.pool.free_ed(ed_idx);
                return false;
            }
        };
        // Optionally a single data TD (multi-packet not needed for 18-byte descriptor)
        let data_td_opt = if data_len > 0 {
            self.pool.alloc_td()
        } else {
            None
        };

        // SETUP TD
        {
            let td = &mut self.pool.tds[setup_td];
            td.ctrl = OHCI_TD_CC_NOERR | OHCI_TD_DP_SETUP | OHCI_TD_T_DATA0 | OHCI_TD_DI_NONE;
            td.cbp = setup as *const UsbSetupPacket as u32;
            td.be = td.cbp + 7;
        }

        // Optional DATA TD
        if let (Some(dt), Some(ref buf)) = (data_td_opt, &data) {
            let dp = if dir_in {
                OHCI_TD_DP_IN
            } else {
                OHCI_TD_DP_OUT
            };
            let td = &mut self.pool.tds[dt];
            td.ctrl = OHCI_TD_CC_NOERR | dp | OHCI_TD_T_DATA1 | OHCI_TD_DI_NONE | OHCI_TD_R;
            td.cbp = buf.as_ptr() as u32;
            td.be = td.cbp + data_len as u32 - 1;
        }

        // STATUS TD
        {
            let dp = if dir_in || data_len == 0 {
                OHCI_TD_DP_OUT
            } else {
                OHCI_TD_DP_IN
            };
            let td = &mut self.pool.tds[status_td];
            td.ctrl = OHCI_TD_CC_NOERR | dp | OHCI_TD_T_DATA1 | (0 << 21); // DI=immediate
            td.cbp = 0;
            td.be = 0;
        }

        // Link TDs: setup → [data] → status → 0
        let status_phys = self.pool.td_phys(status_td);
        let data_phys = data_td_opt.map(|i| self.pool.td_phys(i));
        let setup_phys = self.pool.td_phys(setup_td);

        if let Some(dp) = data_phys {
            self.pool.tds[setup_td].next_td = dp;
            self.pool.tds[data_td_opt.unwrap()].next_td = status_phys;
        } else {
            self.pool.tds[setup_td].next_td = status_phys;
        }
        self.pool.tds[status_td].next_td = 0;

        // Set up ED
        self.pool.eds[ed_idx].setup(dev_addr, 0, low_speed, 8, true);
        self.pool.eds[ed_idx].head_p = setup_phys;
        self.pool.eds[ed_idx].tail_p = 0;

        let ed_phys = self.pool.ed_phys(ed_idx);

        unsafe {
            // Put ED at head of control list
            self.write32(OHCI_HCCONTROLHEADED, ed_phys);
            // Trigger CLF (ControlListFilled)
            let cs = self.read32(OHCI_HCCOMMANDSTATUS);
            self.write32(OHCI_HCCOMMANDSTATUS, cs | 0x02);

            // Poll status TD for completion
            let mut iters = 0u32;
            let ok = loop {
                let ctrl = core::ptr::read_volatile(&self.pool.tds[status_td].ctrl);
                let cc = ctrl >> 28;
                if cc != 0xE {
                    // no longer "not accessed"
                    break cc == 0; // CC=0 means NoError
                }
                iters += 1;
                if iters > 5_000_000 {
                    break false;
                }
                core::hint::spin_loop();
            };

            // Remove from control list
            self.write32(OHCI_HCCONTROLHEADED, 0);

            if let Some(dt) = data_td_opt {
                self.pool.free_td(dt);
            }
            self.pool.free_td(setup_td);
            self.pool.free_td(status_td);
            self.pool.free_ed(ed_idx);
            ok
        }
    }
}

// ============================================================================
// EHCI host controller — full async schedule implementation
// ============================================================================
//
// EHCI (Enhanced HCI) uses MMIO registers, a Queue Head (QH) for each active
// endpoint, and queue Transfer Descriptors (qTDs) chained onto each QH.
//
// The async schedule is a circular linked list of QHs.  We keep a single
// "dummy" QH as the list head and prepend real QHs for each transaction.

/// EHCI queue Transfer Descriptor (32 bytes, 32-byte aligned) — spec §3.5
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct EhciQtd {
    /// Next qTD pointer (physical, or TERMINATE bit set)
    pub next: u32,
    /// Alternate next qTD pointer
    pub alt_next: u32,
    /// Token: dt | total_bytes | ioc | c_page | err_count | pid | status
    pub token: u32,
    /// Buffer page pointers (0–4)
    pub buf: [u32; 5],
}

// qTD Token bits
const QTD_ACTIVE: u32 = 1 << 7;
const QTD_HALTED: u32 = 1 << 6;
const QTD_DBUFERR: u32 = 1 << 5;
const QTD_BABBLE: u32 = 1 << 4;
const QTD_XACT: u32 = 1 << 3; // Transaction Error
const QTD_MMISMATCH: u32 = 1 << 2; // Missed Micro-frame
const QTD_SPLIT: u32 = 1 << 1; // Split Transaction state
const QTD_PING: u32 = 1 << 0; // Ping state
const QTD_IOC: u32 = 1 << 15;
const QTD_TOGGLE: u32 = 1 << 31;
const QTD_PID_OUT: u32 = 0 << 8;
const QTD_PID_IN: u32 = 1 << 8;
const QTD_PID_SETUP: u32 = 2 << 8;
const QTD_TERM: u32 = 1;

impl EhciQtd {
    pub const fn zeroed() -> Self {
        EhciQtd {
            next: QTD_TERM,
            alt_next: QTD_TERM,
            token: 0,
            buf: [0; 5],
        }
    }
    pub fn set_token(&mut self, pid: u32, toggle: bool, len: usize, ioc: bool) {
        self.token = QTD_ACTIVE
            | (if toggle { QTD_TOGGLE } else { 0 })
            | ((len as u32 & 0x7FFF) << 16)
            | (if ioc { QTD_IOC } else { 0 })
            | (3 << 10)  // CERR=3
            | pid;
    }
}

/// EHCI Queue Head (48 bytes, 32-byte aligned) — spec §3.6
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct EhciQh {
    /// Horizontal link pointer (next QH in async list)
    pub hlp: u32,
    /// Endpoint characteristics
    pub endpt_char: u32,
    /// Endpoint capabilities
    pub endpt_cap: u32,
    /// Current qTD pointer (written by HC)
    pub cur_qtd: u32,
    // --- Transfer overlay (written by HC, mirrors qTD) ---
    pub next_qtd: u32,
    pub alt_qtd: u32,
    pub status: u32,
    pub buf: [u32; 5],
}

// QH.hlp bits
const QH_HLP_T: u32 = 1; // Terminate
const QH_HLP_QH: u32 = 1 << 1; // Type = QH

// QH.endpt_char bits
const QH_CHAR_RL_SHIFT: u32 = 28;
const QH_CHAR_C: u32 = 1 << 27; // Control endpoint flag
const QH_CHAR_MAXPKT_SHIFT: u32 = 16;
const QH_CHAR_H: u32 = 1 << 15; // Head of Reclamation List
const QH_CHAR_DTC: u32 = 1 << 14; // Data Toggle Control (from qTD)
const QH_CHAR_EPS_FS: u32 = 0 << 12; // Full Speed
const QH_CHAR_EPS_LS: u32 = 1 << 12; // Low Speed
const QH_CHAR_EPS_HS: u32 = 2 << 12; // High Speed
const QH_CHAR_EN_SHIFT: u32 = 8;
const QH_CHAR_I: u32 = 1 << 7; // Inactivate on Next Transaction
const QH_CHAR_DA_SHIFT: u32 = 0;

impl EhciQh {
    pub const fn zeroed() -> Self {
        EhciQh {
            hlp: QH_HLP_T,
            endpt_char: 0,
            endpt_cap: 0,
            cur_qtd: 0,
            next_qtd: QTD_TERM,
            alt_qtd: QTD_TERM,
            status: 0,
            buf: [0; 5],
        }
    }
    pub fn setup(
        &mut self,
        dev_addr: u8,
        endpoint: u8,
        max_pkt: u16,
        high_speed: bool,
        low_speed: bool,
        control: bool,
    ) {
        let eps = if high_speed {
            QH_CHAR_EPS_HS
        } else if low_speed {
            QH_CHAR_EPS_LS
        } else {
            QH_CHAR_EPS_FS
        };
        self.endpt_char = (dev_addr as u32)
            | ((endpoint as u32) << QH_CHAR_EN_SHIFT)
            | eps
            | ((max_pkt as u32) << QH_CHAR_MAXPKT_SHIFT)
            | QH_CHAR_DTC
            | (if control { QH_CHAR_C } else { 0 });
        self.endpt_cap = 1 << 30; // Mult=1 (one transaction per micro-frame)
        self.next_qtd = QTD_TERM;
        self.alt_qtd = QTD_TERM;
        self.status = 0;
    }
}

// EHCI MMIO register offsets (capability registers base = mmio_base)
const EHCI_CAPLENGTH: usize = 0x00; // 1-byte cap length
const EHCI_HCIVERSION: usize = 0x02;
const EHCI_HCSPARAMS: usize = 0x04;
const EHCI_HCCPARAMS: usize = 0x08;

// Operational registers offset = mmio_base + cap_length
const EHCI_USBCMD: usize = 0x00;
const EHCI_USBSTS: usize = 0x04;
const EHCI_USBINTR: usize = 0x08;
const EHCI_FRINDEX: usize = 0x0C;
const EHCI_CTRLDSEGMENT: usize = 0x10;
const EHCI_PERIODICLISTBASE: usize = 0x14;
const EHCI_ASYNCLISTADDR: usize = 0x18;
const EHCI_CONFIGFLAG: usize = 0x40;
const EHCI_PORTSC: usize = 0x44; // +4 per port

// USBCMD bits
const EHCI_CMD_RS: u32 = 1 << 0; // Run/Stop
const EHCI_CMD_HCRST: u32 = 1 << 1; // Host Controller Reset
const EHCI_CMD_ASE: u32 = 1 << 5; // Async Schedule Enable
const EHCI_CMD_PSE: u32 = 1 << 4; // Periodic Schedule Enable
const EHCI_CMD_ITC_1: u32 = 1 << 16; // Interrupt Threshold (1 micro-frame)

// USBSTS bits
const EHCI_STS_ASS: u32 = 1 << 15; // Async Schedule Status
const EHCI_STS_HALT: u32 = 1 << 12; // HC Halted

// PORTSC bits (EHCI)
const EHCI_PORT_CCS: u32 = 1 << 0; // Current Connect Status
const EHCI_PORT_CSC: u32 = 1 << 1; // Connect Status Change
const EHCI_PORT_PED: u32 = 1 << 2; // Port Enable
const EHCI_PORT_PR: u32 = 1 << 8; // Port Reset
const EHCI_PORT_OWNER: u32 = 1 << 13; // Port Owner (1 = companion HC)
const EHCI_PORT_LS: u32 = 3 << 10; // Line Status
const EHCI_PORT_LS_K: u32 = 1 << 10; // K-state (low-speed device indicator)

const EHCI_QH_POOL: usize = 8;
const EHCI_QTD_POOL: usize = 32;

pub struct EhciPool {
    qhs: [EhciQh; EHCI_QH_POOL],
    qtds: [EhciQtd; EHCI_QTD_POOL],
    qh_used: [bool; EHCI_QH_POOL],
    qtd_used: [bool; EHCI_QTD_POOL],
}

impl EhciPool {
    pub const fn new() -> Self {
        EhciPool {
            qhs: [EhciQh {
                hlp: QH_HLP_T,
                endpt_char: 0,
                endpt_cap: 0,
                cur_qtd: 0,
                next_qtd: QTD_TERM,
                alt_qtd: QTD_TERM,
                status: 0,
                buf: [0; 5],
            }; EHCI_QH_POOL],
            qtds: [EhciQtd {
                next: QTD_TERM,
                alt_next: QTD_TERM,
                token: 0,
                buf: [0; 5],
            }; EHCI_QTD_POOL],
            qh_used: [false; EHCI_QH_POOL],
            qtd_used: [false; EHCI_QTD_POOL],
        }
    }
    pub fn alloc_qh(&mut self) -> Option<usize> {
        self.qh_used
            .iter_mut()
            .enumerate()
            .find(|(_, u)| !**u)
            .map(|(i, u)| {
                *u = true;
                self.qhs[i] = EhciQh::zeroed();
                i
            })
    }
    pub fn alloc_qtd(&mut self) -> Option<usize> {
        self.qtd_used
            .iter_mut()
            .enumerate()
            .find(|(_, u)| !**u)
            .map(|(i, u)| {
                *u = true;
                self.qtds[i] = EhciQtd::zeroed();
                i
            })
    }
    pub fn free_qh(&mut self, i: usize) {
        if i < EHCI_QH_POOL {
            self.qh_used[i] = false;
        }
    }
    pub fn free_qtd(&mut self, i: usize) {
        if i < EHCI_QTD_POOL {
            self.qtd_used[i] = false;
        }
    }
    pub fn qh_phys(&self, i: usize) -> u32 {
        &self.qhs[i] as *const EhciQh as u32
    }
    pub fn qtd_phys(&self, i: usize) -> u32 {
        &self.qtds[i] as *const EhciQtd as u32
    }
}

/// EHCI host controller — full implementation.
pub struct EhciController {
    pub mmio_base: usize,
    pub op_base: usize, // mmio_base + cap_length
    pub initialised: bool,
    pub port_count: usize,
    pub pci: PciDevice,
    pub pool: EhciPool,
}

impl EhciController {
    pub const fn new(mmio_base: usize, pci: PciDevice) -> Self {
        EhciController {
            mmio_base,
            op_base: 0,
            initialised: false,
            port_count: 0,
            pci,
            pool: EhciPool::new(),
        }
    }

    unsafe fn cap_read8(&self, off: usize) -> u8 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u8)
    }
    unsafe fn cap_read32(&self, off: usize) -> u32 {
        core::ptr::read_volatile((self.mmio_base + off) as *const u32)
    }
    unsafe fn op_read32(&self, off: usize) -> u32 {
        core::ptr::read_volatile((self.op_base + off) as *const u32)
    }
    unsafe fn op_write32(&self, off: usize, v: u32) {
        core::ptr::write_volatile((self.op_base + off) as *mut u32, v);
    }
    unsafe fn port_read(&self, port: usize) -> u32 {
        self.op_read32(EHCI_PORTSC + port * 4)
    }
    unsafe fn port_write(&self, port: usize, v: u32) {
        self.op_write32(EHCI_PORTSC + port * 4, v);
    }

    // ----------------------------------------------------------------
    // BIOS hand-off  (reused by init)
    // ----------------------------------------------------------------
    pub fn bios_handoff(&mut self) {
        unsafe {
            let cap_len = self.cap_read8(EHCI_CAPLENGTH) as usize;
            self.op_base = self.mmio_base + cap_len;
            let hccparams = self.cap_read32(EHCI_HCCPARAMS);
            let mut eecp = ((hccparams >> 8) & 0xFF) as u8;
            while eecp >= 0x40 {
                let cap = pci_read32_by_offset(self.pci, eecp);
                if cap & 0xFF == 0x01 {
                    pci_write32_by_offset(self.pci, eecp, cap | (1 << 24));
                    let mut i = 0u32;
                    loop {
                        let v = pci_read32_by_offset(self.pci, eecp);
                        if v & (1 << 16) == 0 {
                            break;
                        }
                        i += 1;
                        if i > 100_000 {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    break;
                }
                eecp = ((cap >> 8) & 0xFF) as u8;
            }
        }
    }

    // ----------------------------------------------------------------
    // Full init — async schedule enabled
    // ----------------------------------------------------------------
    pub fn init(&mut self) {
        self.bios_handoff();
        unsafe {
            let cap_len = self.cap_read8(EHCI_CAPLENGTH) as usize;
            self.op_base = self.mmio_base + cap_len;

            // HC reset
            self.op_write32(EHCI_USBCMD, EHCI_CMD_HCRST);
            for _ in 0..200_000 {
                if self.op_read32(EHCI_USBCMD) & EHCI_CMD_HCRST == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // Segment = 0 (32-bit mode)
            self.op_write32(EHCI_CTRLDSEGMENT, 0);
            // Clear all interrupts
            self.op_write32(EHCI_USBINTR, 0);
            self.op_write32(EHCI_USBSTS, 0x3F);

            // Route all ports to EHCI
            self.op_write32(EHCI_CONFIGFLAG, 1);

            // Start with async schedule disabled (enabled per-transfer)
            let cmd = EHCI_CMD_RS | EHCI_CMD_ITC_1;
            self.op_write32(EHCI_USBCMD, cmd);

            // Count ports
            let hcsparams = self.cap_read32(EHCI_HCSPARAMS);
            self.port_count = (hcsparams & 0xF) as usize;

            // Power on ports
            for p in 0..self.port_count {
                let v = self.port_read(p);
                self.port_write(p, v | (1 << 12)); // PortPower
            }
            for _ in 0..200_000 {
                core::hint::spin_loop();
            }
        }
        self.initialised = true;
    }

    // ----------------------------------------------------------------
    // Port reset
    // ----------------------------------------------------------------
    pub fn reset_port(&self, port: usize) -> Option<UsbSpeed> {
        unsafe {
            let v = self.port_read(port);
            if v & EHCI_PORT_CCS == 0 {
                return None;
            }

            // If line status shows K-state, this is a low-/full-speed device →
            // release port ownership to companion HC and report Full speed.
            if (v & EHCI_PORT_LS) == EHCI_PORT_LS_K {
                self.port_write(port, v | EHCI_PORT_OWNER);
                return Some(UsbSpeed::Full);
            }

            // Assert reset
            let v2 = (v & !EHCI_PORT_PED) | EHCI_PORT_PR;
            self.port_write(port, v2);
            for _ in 0..500_000 {
                core::hint::spin_loop();
            }
            // Deassert reset
            self.port_write(port, self.port_read(port) & !EHCI_PORT_PR);
            // Wait for PED to be set by HC
            for _ in 0..100_000 {
                core::hint::spin_loop();
            }

            let v3 = self.port_read(port);
            // Clear CSC
            self.port_write(port, v3 | EHCI_PORT_CSC);

            if v3 & EHCI_PORT_PED != 0 {
                Some(UsbSpeed::High) // Successfully enabled → high-speed
            } else {
                None
            }
        }
    }

    pub fn probe_ports(&self) -> alloc::vec::Vec<(usize, UsbSpeed)> {
        let mut out = alloc::vec::Vec::new();
        for p in 0..self.port_count {
            if let Some(spd) = self.reset_port(p) {
                out.push((p, spd));
            }
        }
        out
    }

    // ----------------------------------------------------------------
    // Run a QH through the async schedule and poll for completion
    // ----------------------------------------------------------------
    unsafe fn run_async_qh(&self, qh_idx: usize) -> bool {
        let qh_phys = self.pool.qh_phys(qh_idx);

        // Make QH head of async list (circular, points to itself)
        let qh = &mut *(qh_phys as *mut EhciQh);
        qh.hlp = qh_phys | QH_HLP_QH;
        qh.endpt_char |= QH_CHAR_H; // Head of reclamation list

        self.op_write32(EHCI_ASYNCLISTADDR, qh_phys);
        // Enable async schedule
        let cmd = self.op_read32(EHCI_USBCMD) | EHCI_CMD_ASE;
        self.op_write32(EHCI_USBCMD, cmd);
        // Wait for ASS to set
        for _ in 0..100_000 {
            if self.op_read32(EHCI_USBSTS) & EHCI_STS_ASS != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Poll last qTD token for completion
        let mut ok = false;
        for _ in 0..5_000_000u32 {
            let status = core::ptr::read_volatile(&qh.status);
            if status & QTD_ACTIVE == 0 {
                ok = status & QTD_HALTED == 0;
                break;
            }
            core::hint::spin_loop();
        }

        // Disable async schedule
        let cmd2 = self.op_read32(EHCI_USBCMD) & !EHCI_CMD_ASE;
        self.op_write32(EHCI_USBCMD, cmd2);
        for _ in 0..100_000 {
            if self.op_read32(EHCI_USBSTS) & EHCI_STS_ASS == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        ok
    }

    // ----------------------------------------------------------------
    // Control transfer
    // ----------------------------------------------------------------
    pub fn control_transfer(
        &mut self,
        dev_addr: u8,
        high_speed: bool,
        low_speed: bool,
        setup: &UsbSetupPacket,
        data: Option<&mut [u8]>,
        dir_in: bool,
    ) -> bool {
        let data_len = data.as_ref().map_or(0, |b| b.len());
        let max_pkt: u16 = if high_speed { 64 } else { 8 };

        let qh_idx = match self.pool.alloc_qh() {
            Some(i) => i,
            None => return false,
        };
        let setup_qtd = match self.pool.alloc_qtd() {
            Some(i) => i,
            None => {
                self.pool.free_qh(qh_idx);
                return false;
            }
        };
        let status_qtd = match self.pool.alloc_qtd() {
            Some(i) => i,
            None => {
                self.pool.free_qtd(setup_qtd);
                self.pool.free_qh(qh_idx);
                return false;
            }
        };
        let data_qtd_opt = if data_len > 0 {
            self.pool.alloc_qtd()
        } else {
            None
        };

        self.pool.qhs[qh_idx].setup(dev_addr, 0, max_pkt, high_speed, low_speed, true);

        // SETUP qTD
        {
            let qtd = &mut self.pool.qtds[setup_qtd];
            qtd.set_token(QTD_PID_SETUP, false, 8, false);
            qtd.buf[0] = setup as *const UsbSetupPacket as u32;
        }

        // DATA qTD
        if let (Some(dq), Some(ref buf)) = (data_qtd_opt, &data) {
            let pid = if dir_in { QTD_PID_IN } else { QTD_PID_OUT };
            let qtd = &mut self.pool.qtds[dq];
            qtd.set_token(pid, true, data_len, false);
            qtd.buf[0] = buf.as_ptr() as u32;
            // Additional pages if data > 4096 bytes
            for pg in 1..5 {
                let addr = buf.as_ptr() as u32 + (pg as u32 * 0x1000);
                qtd.buf[pg] = addr & !0xFFF;
            }
        }

        // STATUS qTD
        {
            let pid = if dir_in || data_len == 0 {
                QTD_PID_OUT
            } else {
                QTD_PID_IN
            };
            let qtd = &mut self.pool.qtds[status_qtd];
            qtd.set_token(pid, true, 0, true);
        }

        // Link qTDs
        let status_phys = self.pool.qtd_phys(status_qtd);
        let setup_phys = self.pool.qtd_phys(setup_qtd);
        if let Some(dq) = data_qtd_opt {
            let data_phys = self.pool.qtd_phys(dq);
            self.pool.qtds[setup_qtd].next = data_phys;
            self.pool.qtds[dq].next = status_phys;
        } else {
            self.pool.qtds[setup_qtd].next = status_phys;
        }
        self.pool.qtds[status_qtd].next = QTD_TERM;

        // Point QH at first qTD
        self.pool.qhs[qh_idx].next_qtd = setup_phys;

        let ok = unsafe { self.run_async_qh(qh_idx) };

        if let Some(dq) = data_qtd_opt {
            self.pool.free_qtd(dq);
        }
        self.pool.free_qtd(setup_qtd);
        self.pool.free_qtd(status_qtd);
        self.pool.free_qh(qh_idx);
        ok
    }

    // ----------------------------------------------------------------
    // Bulk transfer
    // ----------------------------------------------------------------
    pub fn bulk_transfer(
        &mut self,
        dev_addr: u8,
        endpoint: u8,
        high_speed: bool,
        dir_in: bool,
        max_pkt: u16,
        data: &mut [u8],
        toggle: &mut bool,
    ) -> bool {
        let qh_idx = match self.pool.alloc_qh() {
            Some(i) => i,
            None => return false,
        };
        self.pool.qhs[qh_idx].setup(dev_addr, endpoint, max_pkt, high_speed, false, false);

        let total = data.len();
        let mut off = 0usize;

        while off < total {
            let chunk = core::cmp::min(max_pkt as usize, total - off);
            let qtd_idx = match self.pool.alloc_qtd() {
                Some(i) => i,
                None => break,
            };
            let pid = if dir_in { QTD_PID_IN } else { QTD_PID_OUT };
            {
                let qtd = &mut self.pool.qtds[qtd_idx];
                qtd.set_token(pid, *toggle, chunk, off + chunk == total);
                qtd.buf[0] = (data.as_mut_ptr() as usize + off) as u32;
            }
            self.pool.qhs[qh_idx].next_qtd = self.pool.qtd_phys(qtd_idx);

            let ok = unsafe { self.run_async_qh(qh_idx) };
            self.pool.free_qtd(qtd_idx);
            if !ok {
                self.pool.free_qh(qh_idx);
                return false;
            }

            *toggle = !*toggle;
            off += chunk;
        }

        self.pool.free_qh(qh_idx);
        true
    }
}

// ============================================================================
// ============================================================================
// xHCI — full Transfer Ring / Command Ring / Event Ring implementation
// ============================================================================
//
// Reference: Extensible Host Controller Interface for Universal Serial Bus
//            (xHCI) Specification, Revision 1.2 (2019).
//
// Memory layout used here (all static, identity-mapped on i686):
//   XHCI_CMD_RING   — 64 command TRBs (cycle-bit ring)
//   XHCI_EVT_RING   — 64 event  TRBs
//   XHCI_ERST       — 1-entry Event Ring Segment Table
//   XHCI_DEV_CTX   — 32 device context pointers (DCBAA)
//   XHCI_DEV_CTX_MEM — 32 × 32-byte input/output device contexts
//   XHCI_XFER_RING  — 64 transfer TRBs (one shared ring for simplicity)
//   XHCI_INPUT_CTX  — one 512-byte input context for address_device
//
// Design decisions:
//   • Single command ring with polled completion (no MSI, no IRQ needed).
//   • One shared transfer ring; real drivers would allocate per-endpoint.
//   • DCBAA and context arrays are statically allocated (no heap).

/// xHCI TRB (Transfer Request Block), 16 bytes, 16-byte aligned.
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct XhciTrb {
    pub param: u64,
    pub status: u32,
    pub ctrl: u32,
}

// TRB type codes (ctrl bits 15:10)
const TRB_TYPE_NORMAL: u32 = 1 << 10;
const TRB_TYPE_SETUP_STAGE: u32 = 2 << 10;
const TRB_TYPE_DATA_STAGE: u32 = 3 << 10;
const TRB_TYPE_STATUS_STAGE: u32 = 4 << 10;
const TRB_TYPE_LINK: u32 = 6 << 10;
const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9 << 10;
const TRB_TYPE_ADDR_DEV_CMD: u32 = 11 << 10;
const TRB_TYPE_CONFIG_EP_CMD: u32 = 12 << 10;
const TRB_TYPE_NO_OP_CMD: u32 = 23 << 10;
const TRB_TYPE_CMD_COMPLETION: u32 = 33 << 10;
const TRB_TYPE_PORT_STATUS_CHG: u32 = 34 << 10;
const TRB_TYPE_XFER_EVENT: u32 = 32 << 10;

// TRB control bit
const TRB_CYCLE: u32 = 1 << 0;
const TRB_TOGGLE: u32 = 1 << 1; // Link TRB toggle cycle
const TRB_ENT: u32 = 1 << 1; // Evaluate Next TRB
const TRB_ISP: u32 = 1 << 2; // Interrupt on Short Packet
const TRB_IOC: u32 = 1 << 5; // Interrupt on Completion
const TRB_IDT: u32 = 1 << 6; // Immediate Data (setup stage)
const TRB_DIR_IN: u32 = 1 << 16; // Data Stage direction

// XHCI capability register offsets (from mmio_base)
const XHCI_CAPLENGTH: usize = 0x00;
const XHCI_HCSPARAMS1: usize = 0x04;
const XHCI_HCSPARAMS2: usize = 0x08;
const XHCI_HCCPARAMS1: usize = 0x10;

// XHCI operational register offsets (from op_base = mmio_base + cap_length)
const XHCI_USBCMD: usize = 0x00;
const XHCI_USBSTS: usize = 0x04;
const XHCI_PAGESIZE: usize = 0x08;
const XHCI_DNCTRL: usize = 0x14;
const XHCI_CRCR_LO: usize = 0x18;
const XHCI_CRCR_HI: usize = 0x1C;
const XHCI_DCBAAP_LO: usize = 0x30;
const XHCI_DCBAAP_HI: usize = 0x34;
const XHCI_CONFIG: usize = 0x38;

// XHCI runtime register base offset from mmio_base: read from RTSOFF
const XHCI_RTSOFF: usize = 0x18;

// Runtime register offsets (from runtime_base = mmio_base + rtsoff)
const XHCI_IMAN: usize = 0x20; // Interrupter 0 management
const XHCI_ERDP_LO: usize = 0x38; // Event ring dequeue ptr lo
const XHCI_ERDP_HI: usize = 0x3C;
const XHCI_ERSTBA_LO: usize = 0x30; // ERST base lo
const XHCI_ERSTBA_HI: usize = 0x34;
const XHCI_ERSTSZ: usize = 0x28; // ERST size

// Doorbell register array: offset from mmio_base = DBOFF (at cap+0x14)
const XHCI_DBOFF: usize = 0x14;

// USBCMD bits
const XHCI_CMD_RS: u32 = 1 << 0;
const XHCI_CMD_HCRST: u32 = 1 << 1;
const XHCI_CMD_INTE: u32 = 1 << 2; // Interrupter enable

// USBSTS bits
const XHCI_STS_HCH: u32 = 1 << 0; // Host Controller Halted
const XHCI_STS_CNR: u32 = 1 << 11; // Controller Not Ready

// Number of TRBs in each ring (must be power of 2; last slot is Link TRB).
const XHCI_RING_SIZE: usize = 64;

// ERST entry count
const XHCI_ERST_SIZE: usize = 1;

// Max device slots
const XHCI_MAX_SLOTS: usize = 32;

/// Event Ring Segment Table entry (64 bytes, 64-byte aligned; we use 1 entry).
#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
struct XhciErstEntry {
    base_lo: u32,
    base_hi: u32,
    ring_seg_size: u32,
    _rsvd: u32,
}

// Static ring storage
#[repr(C, align(64))]
struct XhciRing {
    trbs: [XhciTrb; XHCI_RING_SIZE],
}
impl XhciRing {
    const fn new() -> Self {
        XhciRing {
            trbs: [XhciTrb {
                param: 0,
                status: 0,
                ctrl: 0,
            }; XHCI_RING_SIZE],
        }
    }
}

static mut XHCI_CMD_RING: XhciRing = XhciRing::new();
static mut XHCI_EVT_RING: XhciRing = XhciRing::new();
static mut XHCI_XFER_RING: XhciRing = XhciRing::new();
static mut XHCI_ERST: [XhciErstEntry; XHCI_ERST_SIZE] = [XhciErstEntry {
    base_lo: 0,
    base_hi: 0,
    ring_seg_size: 0,
    _rsvd: 0,
}];

// Device Context Base Address Array (DCBAA).
// Slot 0 = scratchpad (set to 0); slots 1..=max_slots = output device contexts.
static mut XHCI_DCBAA: [u64; XHCI_MAX_SLOTS + 1] = [0u64; XHCI_MAX_SLOTS + 1];

// Per-slot output device context (32 bytes × 33; slot 0 unused).
// A full device context is 32 bytes per endpoint context × 32 EPs = 1024 bytes.
// For simplicity we allocate the minimal 64-byte Output Device Context.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct XhciDevCtxSlot {
    data: [u32; 16], // 64 bytes
}
static mut XHCI_DEV_CTXS: [XhciDevCtxSlot; XHCI_MAX_SLOTS + 1] =
    [XhciDevCtxSlot { data: [0u32; 16] }; XHCI_MAX_SLOTS + 1];

// Input context for ADDRESS_DEVICE commands (512 bytes, 64-byte aligned).
#[repr(C, align(64))]
struct XhciInputCtx {
    data: [u32; 128], // 512 bytes
}
static mut XHCI_INPUT_CTX: XhciInputCtx = XhciInputCtx { data: [0u32; 128] };

/// xHCI host controller — full implementation.
pub struct XhciController {
    pub mmio_base: usize,
    op_base: usize, // mmio_base + cap_length
    db_base: usize, // doorbell array base
    rt_base: usize, // runtime register base
    pub initialised: bool,
    pub pci: PciDevice,
    max_slots: u8,
    max_ports: u8,
    /// Command ring enqueue pointer index and cycle state.
    cmd_enq: usize,
    cmd_cycle: bool,
    /// Event ring dequeue pointer index and cycle state.
    evt_deq: usize,
    evt_cycle: bool,
    /// Transfer ring enqueue pointer index and cycle state.
    xfer_enq: usize,
    xfer_cycle: bool,
}

impl XhciController {
    pub const fn new(mmio_base: usize, pci: PciDevice) -> Self {
        XhciController {
            mmio_base,
            op_base: 0,
            db_base: 0,
            rt_base: 0,
            initialised: false,
            pci,
            max_slots: 0,
            max_ports: 0,
            cmd_enq: 0,
            cmd_cycle: true,
            evt_deq: 0,
            evt_cycle: true,
            xfer_enq: 0,
            xfer_cycle: true,
        }
    }

    // ----------------------------------------------------------------
    // MMIO helpers
    // ----------------------------------------------------------------

    unsafe fn read32(&self, base: usize, offset: usize) -> u32 {
        core::ptr::read_volatile((base + offset) as *const u32)
    }
    unsafe fn write32(&self, base: usize, offset: usize, v: u32) {
        core::ptr::write_volatile((base + offset) as *mut u32, v);
    }
    unsafe fn read64(&self, base: usize, offset: usize) -> u64 {
        let lo = self.read32(base, offset) as u64;
        let hi = self.read32(base, offset + 4) as u64;
        lo | (hi << 32)
    }
    unsafe fn write64(&self, base: usize, offset: usize, v: u64) {
        self.write32(base, offset, v as u32);
        self.write32(base, offset + 4, (v >> 32) as u32);
    }

    // Capability register shortcuts
    unsafe fn cap_read32(&self, off: usize) -> u32 {
        self.read32(self.mmio_base, off)
    }
    // Operational register shortcuts
    unsafe fn op_read32(&self, off: usize) -> u32 {
        self.read32(self.op_base, off)
    }
    unsafe fn op_write32(&self, off: usize, v: u32) {
        self.write32(self.op_base, off, v);
    }
    // Runtime register shortcuts
    unsafe fn rt_write32(&self, off: usize, v: u32) {
        self.write32(self.rt_base, off, v);
    }
    unsafe fn rt_write64(&self, off: usize, v: u64) {
        self.write64(self.rt_base, off, v);
    }
    // Doorbell shortcuts
    unsafe fn ring_doorbell(&self, slot: u8, endpoint: u8) {
        self.write32(self.db_base, (slot as usize) * 4, endpoint as u32);
    }

    const USB_LEGACY_SUPPORT: u32 = 0x01;
    const XHCI_USBLEGSUP_BIOS_SEM: u32 = 1 << 16;
    const XHCI_USBLEGSUP_OS_SEM: u32 = 1 << 24;

    // ----------------------------------------------------------------
    // BIOS hand-off
    // ----------------------------------------------------------------

    pub fn bios_handoff(&mut self) {
        unsafe {
            let hccparams1 = self.cap_read32(XHCI_HCCPARAMS1);
            let mut xecp = ((hccparams1 >> 16) & 0xFFFF) as usize;
            while xecp != 0 {
                let cap_hdr = self.read32(self.mmio_base, xecp * 4);
                if cap_hdr & 0xFF == Self::USB_LEGACY_SUPPORT {
                    self.write32(
                        self.mmio_base,
                        xecp * 4,
                        cap_hdr | Self::XHCI_USBLEGSUP_OS_SEM,
                    );
                    for _ in 0..200_000u32 {
                        let v = self.read32(self.mmio_base, xecp * 4);
                        if v & Self::XHCI_USBLEGSUP_BIOS_SEM == 0 {
                            break;
                        }
                    }
                    break;
                }
                let next = (cap_hdr >> 8) & 0xFF;
                if next == 0 {
                    break;
                }
                xecp += next as usize;
            }
        }
    }

    // ----------------------------------------------------------------
    // Full initialisation
    // ----------------------------------------------------------------

    /// Initialise the xHCI controller: reset, ring setup, DCBAA, run.
    pub fn init(&mut self) -> bool {
        self.bios_handoff();
        unsafe {
            // Derive op_base from cap_length.
            let cap_len = (self.cap_read32(XHCI_CAPLENGTH) & 0xFF) as usize;
            self.op_base = self.mmio_base + cap_len;

            // Derive doorbell base from DBOFF capability register.
            let dboff = self.cap_read32(XHCI_DBOFF as usize) as usize;
            self.db_base = self.mmio_base + dboff;

            // Derive runtime base from RTSOFF.
            let rtsoff = self.cap_read32(XHCI_RTSOFF) as usize;
            self.rt_base = self.mmio_base + rtsoff;

            let hcsparams1 = self.cap_read32(XHCI_HCSPARAMS1);
            self.max_slots = (hcsparams1 & 0xFF) as u8;
            self.max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

            // ---- Stop the controller ----
            let mut cmd = self.op_read32(XHCI_USBCMD);
            cmd &= !XHCI_CMD_RS;
            self.op_write32(XHCI_USBCMD, cmd);
            // Wait for HCH
            for _ in 0..100_000u32 {
                if self.op_read32(XHCI_USBSTS) & XHCI_STS_HCH != 0 {
                    break;
                }
            }

            // ---- Reset ----
            self.op_write32(XHCI_USBCMD, XHCI_CMD_HCRST);
            for _ in 0..500_000u32 {
                if self.op_read32(XHCI_USBCMD) & XHCI_CMD_HCRST == 0
                    && self.op_read32(XHCI_USBSTS) & XHCI_STS_CNR == 0
                {
                    break;
                }
            }

            // ---- Configure max device slots ----
            let slots = core::cmp::min(self.max_slots, XHCI_MAX_SLOTS as u8);
            self.op_write32(XHCI_CONFIG, slots as u32);

            // ---- Set up DCBAA ----
            for i in 1..=slots as usize {
                let ctx_phys = &XHCI_DEV_CTXS[i] as *const _ as u64;
                XHCI_DCBAA[i] = ctx_phys;
            }
            let dcbaa_phys = XHCI_DCBAA.as_ptr() as u64;
            self.write64(self.op_base, XHCI_DCBAAP_LO, dcbaa_phys);

            // ---- Set up Command Ring ----
            // Insert a Link TRB at the last slot pointing back to the start.
            let cmd_phys = XHCI_CMD_RING.trbs.as_ptr() as u64;
            XHCI_CMD_RING.trbs[XHCI_RING_SIZE - 1].param = cmd_phys;
            XHCI_CMD_RING.trbs[XHCI_RING_SIZE - 1].status = 0;
            XHCI_CMD_RING.trbs[XHCI_RING_SIZE - 1].ctrl = TRB_TYPE_LINK | TRB_TOGGLE | TRB_CYCLE;
            // Write CRCR: base address + cycle bit
            self.write64(self.op_base, XHCI_CRCR_LO, cmd_phys | 1);

            // ---- Set up Event Ring ----
            let evt_phys = XHCI_EVT_RING.trbs.as_ptr() as u64;
            XHCI_ERST[0].base_lo = evt_phys as u32;
            XHCI_ERST[0].base_hi = (evt_phys >> 32) as u32;
            XHCI_ERST[0].ring_seg_size = XHCI_RING_SIZE as u32;
            let erst_phys = XHCI_ERST.as_ptr() as u64;
            self.rt_write32(XHCI_ERSTSZ, XHCI_ERST_SIZE as u32);
            self.rt_write64(XHCI_ERSTBA_LO, erst_phys);
            self.rt_write64(XHCI_ERDP_LO, evt_phys);

            // ---- Clear DNCTRL ----
            self.op_write32(XHCI_DNCTRL, 0);

            // ---- Set up Transfer Ring (one global ring for now) ----
            let xfer_phys = XHCI_XFER_RING.trbs.as_ptr() as u64;
            XHCI_XFER_RING.trbs[XHCI_RING_SIZE - 1].param = xfer_phys;
            XHCI_XFER_RING.trbs[XHCI_RING_SIZE - 1].ctrl = TRB_TYPE_LINK | TRB_TOGGLE | TRB_CYCLE;

            // ---- Start the controller ----
            self.op_write32(XHCI_USBCMD, XHCI_CMD_RS);
            for _ in 0..100_000u32 {
                if self.op_read32(XHCI_USBSTS) & XHCI_STS_HCH == 0 {
                    break;
                }
            }
        }

        self.initialised = true;
        crate::serial_println!(
            "[xHCI] Initialised: max_slots={} max_ports={}",
            self.max_slots,
            self.max_ports
        );
        true
    }

    // ----------------------------------------------------------------
    // Port enumeration
    // ----------------------------------------------------------------

    /// Power and enumerate all root-hub ports.
    ///
    /// Returns a list of `(port_index, speed)` tuples for connected devices.
    /// Speed codes: 1=Full, 2=Low, 3=High, 4=SuperSpeed.
    pub fn probe_ports(&self) -> [(u8, u8); 16] {
        let mut result = [(0u8, 0u8); 16];
        let mut found = 0usize;
        unsafe {
            for port in 0..core::cmp::min(self.max_ports as usize, 16) {
                // PORTSC registers at op_base + 0x400 + port * 0x10
                let portsc_off = 0x400 + port * 0x10;
                let portsc = self.op_read32(portsc_off);

                // Power the port (PP bit 9)
                if portsc & (1 << 9) == 0 {
                    self.op_write32(portsc_off, portsc | (1 << 9));
                    for _ in 0..50_000u32 {}
                }

                let portsc = self.op_read32(portsc_off);
                // CCS = bit 0: device connected
                if portsc & 0x01 == 0 {
                    continue;
                }

                // Reset the port (PR bit 4)
                self.op_write32(portsc_off, portsc | (1 << 4));
                for _ in 0..500_000u32 {
                    if self.op_read32(portsc_off) & (1 << 4) == 0 {
                        break;
                    }
                }

                let portsc = self.op_read32(portsc_off);
                let speed = ((portsc >> 10) & 0xF) as u8; // Port Speed bits 13:10
                if found < 16 {
                    result[found] = (port as u8 + 1, speed);
                    found += 1;
                }
                crate::serial_println!("[xHCI] Port {} connected, speed={}", port + 1, speed);
            }
        }
        result
    }

    // ----------------------------------------------------------------
    // Command ring helpers
    // ----------------------------------------------------------------

    /// Enqueue a TRB onto the command ring and ring doorbell 0, slot 0.
    /// Returns false if the ring is full.
    pub fn enqueue_command(&mut self, mut trb: XhciTrb) -> bool {
        let idx = self.cmd_enq;
        if idx >= XHCI_RING_SIZE - 1 {
            return false;
        } // Link TRB slot reserved
          // Set cycle bit
        if self.cmd_cycle {
            trb.ctrl |= TRB_CYCLE;
        } else {
            trb.ctrl &= !TRB_CYCLE;
        }
        unsafe {
            XHCI_CMD_RING.trbs[idx] = trb;
        }
        self.cmd_enq += 1;
        if self.cmd_enq == XHCI_RING_SIZE - 1 {
            // Wrap: update Link TRB cycle bit and toggle parity.
            unsafe {
                let link = &mut XHCI_CMD_RING.trbs[XHCI_RING_SIZE - 1];
                if self.cmd_cycle {
                    link.ctrl |= TRB_CYCLE;
                } else {
                    link.ctrl &= !TRB_CYCLE;
                }
            }
            self.cmd_enq = 0;
            self.cmd_cycle = !self.cmd_cycle;
        }
        unsafe {
            self.ring_doorbell(0, 0);
        }
        true
    }

    /// Poll the event ring for a Command Completion Event.
    /// Returns `(completion_code, slot_id)` or None on timeout.
    pub fn poll_command_completion(&mut self) -> Option<(u8, u8)> {
        for _ in 0..2_000_000u32 {
            unsafe {
                let trb = &XHCI_EVT_RING.trbs[self.evt_deq];
                let trb_cycle = (trb.ctrl & TRB_CYCLE) != 0;
                if trb_cycle != self.evt_cycle {
                    continue;
                } // no new event
                let trb_type = (trb.ctrl >> 10) & 0x3F;
                if trb_type == 33 {
                    // CMD_COMPLETION
                    let cc = ((trb.status >> 24) & 0xFF) as u8;
                    let slot = ((trb.ctrl >> 24) & 0xFF) as u8;
                    self.advance_event_deq();
                    return Some((cc, slot));
                }
                // Not the event we want; consume and keep looking.
                self.advance_event_deq();
            }
        }
        None
    }

    fn advance_event_deq(&mut self) {
        self.evt_deq = (self.evt_deq + 1) % (XHCI_RING_SIZE - 1);
        if self.evt_deq == 0 {
            self.evt_cycle = !self.evt_cycle;
        }
        unsafe {
            let ptr = &XHCI_EVT_RING.trbs[self.evt_deq] as *const _ as u64;
            self.rt_write64(XHCI_ERDP_LO, ptr | (1 << 3)); // EHB bit
        }
    }

    // ----------------------------------------------------------------
    // ENABLE_SLOT / ADDRESS_DEVICE
    // ----------------------------------------------------------------

    /// Issue ENABLE_SLOT command and return the assigned slot ID.
    pub fn enable_slot(&mut self) -> Option<u8> {
        let trb = XhciTrb {
            param: 0,
            status: 0,
            ctrl: TRB_TYPE_ENABLE_SLOT_CMD,
        };
        if !self.enqueue_command(trb) {
            return None;
        }
        let (cc, slot) = self.poll_command_completion()?;
        if cc == 1 {
            Some(slot)
        } else {
            None
        } // cc=1 = Success
    }

    /// Issue ADDRESS_DEVICE command.
    ///
    /// Fills a minimal Input Context for slot `slot`, port `port`, speed `speed`
    /// and issues the ADDRESS_DEVICE command (BSR=false → assign address).
    pub fn address_device(&mut self, slot: u8, port: u8, speed: u8) -> bool {
        unsafe {
            let ic = &mut XHCI_INPUT_CTX;
            for w in ic.data.iter_mut() {
                *w = 0;
            }

            // Input Control Context (dword 0/1): A0 + A1 = add slot + EP0 context.
            ic.data[0] = 0; // Drop flags
            ic.data[1] = 0b11; // Add flags: bit0=slot, bit1=EP0

            // Slot Context (starts at dword 8 = offset 32 bytes from IC base).
            let sc = &mut ic.data[8..]; // Slot Context: 8 dwords
            sc[0] = ((speed as u32 & 0xF) << 20)  // speed
                  | (1 << 27); // Context Entries = 1
            sc[1] = (port as u32) << 16; // Root hub port number

            // EP0 Context (starts at dword 16 = offset 64 bytes).
            let ep0 = &mut ic.data[16..]; // EP0 Context: 8 dwords
                                          // Max packet size per speed (Table 56 of xHCI spec):
            let max_pkt: u16 = match speed {
                1 => 8,   // Full
                2 => 8,   // Low
                3 => 64,  // High
                4 => 512, // SuperSpeed
                _ => 8,
            };
            ep0[1] = (max_pkt as u32) << 16 // Max Packet Size
                   | (3 << 3)               // EP Type: Control
                   | (0 << 1); // EP State: Disabled → 0 (set by HW)

            // Transfer Ring dequeue pointer for EP0 (physical address + DCS=1).
            let xfer_phys = XHCI_XFER_RING.trbs.as_ptr() as u64;
            ep0[2] = (xfer_phys as u32) | 1; // lo + DCS
            ep0[3] = (xfer_phys >> 32) as u32;

            // Store output Device Context pointer in DCBAA.
            let ctx_phys = &XHCI_DEV_CTXS[slot as usize] as *const _ as u64;
            XHCI_DCBAA[slot as usize] = ctx_phys;

            let ic_phys = &XHCI_INPUT_CTX as *const _ as u64;
            let trb = XhciTrb {
                param: ic_phys,
                status: 0,
                ctrl: TRB_TYPE_ADDR_DEV_CMD | ((slot as u32) << 24),
            };
            if !self.enqueue_command(trb) {
                return false;
            }
            if let Some((cc, _)) = self.poll_command_completion() {
                cc == 1
            } else {
                false
            }
        }
    }

    // ----------------------------------------------------------------
    // Control transfer via transfer ring
    // ----------------------------------------------------------------

    /// Issue a control transfer on EP0 of device `slot`.
    ///
    /// `setup`: 8-byte SETUP packet.
    /// `data`:  optional data buffer (host ← device if `dir_in`).
    pub fn control_transfer(
        &mut self,
        slot: u8,
        setup: &UsbSetupPacket,
        data: Option<&mut [u8]>,
        dir_in: bool,
    ) -> bool {
        unsafe {
            let setup_raw =
                core::slice::from_raw_parts(setup as *const UsbSetupPacket as *const u8, 8);
            let mut setup_param = 0u64;
            for (i, &b) in setup_raw.iter().enumerate() {
                setup_param |= (b as u64) << (i * 8);
            }

            // SETUP stage TRB (IDT=immediate data, TRT in bits 17:16)
            let trt: u32 = if data.is_none() {
                0
            } else if dir_in {
                3
            } else {
                2
            };
            let setup_trb = XhciTrb {
                param: setup_param,
                status: 8, // TRB Transfer Length = 8
                ctrl: TRB_TYPE_SETUP_STAGE | TRB_IDT | TRB_IOC | (trt << 16),
            };
            self.enqueue_transfer(setup_trb);

            let status_dir_in = dir_in && data.is_none();

            // DATA stage (optional)
            if let Some(buf) = data {
                let buf_phys = buf.as_ptr() as u64;
                let data_trb = XhciTrb {
                    param: buf_phys,
                    status: buf.len() as u32,
                    ctrl: TRB_TYPE_DATA_STAGE | TRB_IOC | if dir_in { TRB_DIR_IN } else { 0 },
                };
                self.enqueue_transfer(data_trb);
            }

            // STATUS stage
            let status_trb = XhciTrb {
                param: 0,
                status: 0,
                ctrl: TRB_TYPE_STATUS_STAGE | TRB_IOC | if status_dir_in { TRB_DIR_IN } else { 0 },
            };
            self.enqueue_transfer(status_trb);

            // Ring EP0 doorbell
            self.ring_doorbell(slot, 1);

            // Poll for Transfer Event
            self.poll_transfer_completion()
        }
    }

    fn enqueue_transfer(&mut self, mut trb: XhciTrb) {
        let idx = self.xfer_enq;
        if self.xfer_cycle {
            trb.ctrl |= TRB_CYCLE;
        } else {
            trb.ctrl &= !TRB_CYCLE;
        }
        unsafe {
            XHCI_XFER_RING.trbs[idx] = trb;
        }
        self.xfer_enq += 1;
        if self.xfer_enq == XHCI_RING_SIZE - 1 {
            unsafe {
                let link = &mut XHCI_XFER_RING.trbs[XHCI_RING_SIZE - 1];
                if self.xfer_cycle {
                    link.ctrl |= TRB_CYCLE;
                } else {
                    link.ctrl &= !TRB_CYCLE;
                }
            }
            self.xfer_enq = 0;
            self.xfer_cycle = !self.xfer_cycle;
        }
    }

    fn poll_transfer_completion(&mut self) -> bool {
        for _ in 0..2_000_000u32 {
            unsafe {
                let trb = &XHCI_EVT_RING.trbs[self.evt_deq];
                let trb_cycle = (trb.ctrl & TRB_CYCLE) != 0;
                if trb_cycle != self.evt_cycle {
                    continue;
                }
                let trb_type = (trb.ctrl >> 10) & 0x3F;
                if trb_type == 32 {
                    // XFER_EVENT
                    let cc = ((trb.status >> 24) & 0xFF) as u8;
                    self.advance_event_deq();
                    return cc == 1 || cc == 13; // 1=Success, 13=Short Packet
                }
                self.advance_event_deq();
            }
        }
        false
    }

    // ----------------------------------------------------------------
    // Device enumeration (mirroring EHCI enumerate_via_ehci pattern)
    // ----------------------------------------------------------------

    /// Enumerate a device on the given port+speed via ENABLE_SLOT →
    /// ADDRESS_DEVICE → GET_DESCRIPTOR → SET_CONFIGURATION.
    pub fn enumerate_port(&mut self, port: u8, speed: u8) -> Option<(u8, [u8; 18])> {
        let slot = self.enable_slot()?;
        if !self.address_device(slot, port, speed) {
            return None;
        }

        // GET_DEVICE_DESCRIPTOR
        let mut desc_buf = [0u8; 18];
        let setup = UsbSetupPacket::get_device_descriptor();
        if !self.control_transfer(slot, &setup, Some(&mut desc_buf), true) {
            return None;
        }

        // SET_CONFIGURATION(1)
        let setup_cfg = UsbSetupPacket::set_configuration(1);
        let _ = self.control_transfer(slot, &setup_cfg, None, false);

        Some((slot, desc_buf))
    }
}

// ============================================================================
// PCI helpers used by EHCI bios_handoff
// ============================================================================

/// Read a 32-bit value from a PCI device's configuration space at a given byte
/// offset.  Only called from within `bios_handoff`; wraps the inline-asm path.
unsafe fn pci_read32_by_offset(dev: PciDevice, offset: u8) -> u32 {
    let address: u32 = ((dev.bus as u32) << 16)
        | ((dev.slot as u32) << 11)
        | ((dev.func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x80000000;
    let mut v: u32;
    core::arch::asm!(
        "out dx, eax",
        in("dx") 0xCF8u16,
        in("eax") address,
        options(nomem, nostack, preserves_flags)
    );
    core::arch::asm!(
        "in eax, dx",
        out("eax") v,
        in("dx") 0xCFCu16,
        options(nomem, nostack, preserves_flags)
    );
    v
}

unsafe fn pci_write32_by_offset(dev: PciDevice, offset: u8, value: u32) {
    let address: u32 = ((dev.bus as u32) << 16)
        | ((dev.slot as u32) << 11)
        | ((dev.func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x80000000;
    core::arch::asm!(
        "out dx, eax",
        in("dx") 0xCF8u16,
        in("eax") address,
        options(nomem, nostack, preserves_flags)
    );
    core::arch::asm!(
        "out dx, eax",
        in("dx") 0xCFCu16,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

// ============================================================================
// UsbControllerKind — discriminated union of the four types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbControllerKind {
    Uhci,
    Ohci,
    Ehci,
    Xhci,
}

impl UsbControllerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UsbControllerKind::Uhci => "UHCI (USB 1.1 full/low-speed)",
            UsbControllerKind::Ohci => "OHCI (USB 1.1 full/low-speed)",
            UsbControllerKind::Ehci => "EHCI (USB 2.0 high-speed)",
            UsbControllerKind::Xhci => "xHCI (USB 3.x super-speed)",
        }
    }
}

/// Summarised view of a detected USB controller (for display / health).
#[derive(Debug, Clone, Copy)]
pub struct UsbControllerInfo {
    pub kind: UsbControllerKind,
    pub pci: PciDevice,
    pub initialised: bool,
}

// ============================================================================
// UsbBus — top-level USB subsystem
// ============================================================================

/// Maximum number of USB host controllers tracked globally.
pub const MAX_USB_CONTROLLERS: usize = 8;
/// Maximum number of concurrently enumerated USB devices.
pub const MAX_USB_DEVICES: usize = 127;

/// IRQ counter for USB host controller interrupts.
static USB_IRQS: AtomicU32 = AtomicU32::new(0);

/// Called from the USB host controller IRQ handler.
pub fn on_usb_irq() {
    USB_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// The global USB bus state.
pub struct UsbBus {
    pub controllers: [Option<UsbControllerInfo>; MAX_USB_CONTROLLERS],
    pub controller_count: usize,
    pub devices: [Option<UsbDevice>; MAX_USB_DEVICES],
    pub device_count: usize,
    /// Next address to assign during enumeration.
    next_address: u8,
}

impl UsbBus {
    pub const fn new() -> Self {
        const NONE_CTL: Option<UsbControllerInfo> = None;
        const NONE_DEV: Option<UsbDevice> = None;
        UsbBus {
            controllers: [NONE_CTL; MAX_USB_CONTROLLERS],
            controller_count: 0,
            devices: [NONE_DEV; MAX_USB_DEVICES],
            device_count: 0,
            next_address: 1,
        }
    }

    // ----------------------------------------------------------------
    // PCI discovery
    // ----------------------------------------------------------------

    /// Scan `pci_devices` and register any USB host controllers found.
    /// Does NOT initialise them — call `init_controllers` after.
    pub fn detect(&mut self, pci_devices: &[Option<PciDevice>]) {
        for dev_opt in pci_devices {
            let Some(dev) = dev_opt else { continue };
            if dev.class_code != pci_class::CLASS_SERIAL_BUS
                || dev.subclass != pci_class::SUBCLASS_USB
            {
                continue;
            }
            let kind = match dev.prog_if {
                pci_class::PROGIF_UHCI => UsbControllerKind::Uhci,
                pci_class::PROGIF_OHCI => UsbControllerKind::Ohci,
                pci_class::PROGIF_EHCI => UsbControllerKind::Ehci,
                pci_class::PROGIF_XHCI => UsbControllerKind::Xhci,
                _ => continue,
            };
            if self.controller_count < MAX_USB_CONTROLLERS {
                self.controllers[self.controller_count] = Some(UsbControllerInfo {
                    kind,
                    pci: *dev,
                    initialised: false,
                });
                self.controller_count += 1;
            }
        }
    }

    /// Initialise all detected controllers, then enumerate every attached device.
    ///
    /// For each live port the sequence is:
    ///   1. `SET_ADDRESS`    — assign a unique 1–127 address (default addr 0)
    ///   2. `GET_DESCRIPTOR(Device, 18 bytes)` — read `UsbDeviceDescriptor`
    ///   3. `SET_CONFIGURATION(1)` — activate the first configuration
    pub fn init_controllers(&mut self) {
        for i in 0..self.controller_count {
            // Safety: we do not hold any reference into `self.controllers` across
            // the mutable borrow of `self` inside `enumerate_*`.
            let (kind, bar0, bar4) = match self.controllers[i] {
                Some(ref info) => {
                    let b0 = unsafe { info.pci.read_bar(0) };
                    let b4 = unsafe { info.pci.read_bar(4) };
                    (info.kind, b0, b4)
                }
                None => continue,
            };

            match kind {
                UsbControllerKind::Uhci => {
                    let io_base = (bar4 & !0x1F) as u16;
                    if io_base == 0 {
                        continue;
                    }
                    let pci = self.controllers[i].unwrap().pci;
                    let mut ctrl = UhciController::new(io_base, pci);
                    ctrl.init();
                    let ports = ctrl.probe_ports();
                    for (port, speed) in ports {
                        let ls = speed == UsbSpeed::Low;
                        self.enumerate_via_uhci(&mut ctrl, port, speed, ls, i);
                    }
                    if let Some(ref mut info) = self.controllers[i] {
                        info.initialised = true;
                    }
                }
                UsbControllerKind::Ohci => {
                    let mmio = (bar0 & !0x0F) as usize;
                    if mmio == 0 {
                        continue;
                    }
                    let pci = self.controllers[i].unwrap().pci;
                    let mut ctrl = OhciController::new(mmio, pci);
                    ctrl.init();
                    let ports = ctrl.probe_ports();
                    for (port, speed) in ports {
                        let ls = speed == UsbSpeed::Low;
                        self.enumerate_via_ohci(&mut ctrl, port, speed, ls, i);
                    }
                    if let Some(ref mut info) = self.controllers[i] {
                        info.initialised = true;
                    }
                }
                UsbControllerKind::Ehci => {
                    let mmio = (bar0 & !0x0F) as usize;
                    if mmio == 0 {
                        continue;
                    }
                    let pci = self.controllers[i].unwrap().pci;
                    let mut ctrl = EhciController::new(mmio, pci);
                    ctrl.init();
                    let ports = ctrl.probe_ports();
                    for (port, speed) in ports {
                        let hs = speed == UsbSpeed::High;
                        let ls = speed == UsbSpeed::Low;
                        self.enumerate_via_ehci(&mut ctrl, port, speed, hs, ls, i);
                    }
                    if let Some(ref mut info) = self.controllers[i] {
                        info.initialised = true;
                    }
                }
                UsbControllerKind::Xhci => {
                    let mmio = (bar0 & !0x0F) as usize;
                    if mmio == 0 {
                        continue;
                    }
                    let pci = self.controllers[i].unwrap().pci;
                    let mut ctrl = XhciController::new(mmio, pci);
                    if ctrl.init() {
                        let ports = ctrl.probe_ports();
                        for &(port, speed_code) in ports.iter() {
                            if port == 0 {
                                continue;
                            } // sentinel
                            let speed = match speed_code {
                                2 => UsbSpeed::Low,
                                3 => UsbSpeed::High,
                                4 => UsbSpeed::Super,
                                _ => UsbSpeed::Full, // 1 or unknown = Full
                            };
                            if let Some((_slot, desc_buf)) = ctrl.enumerate_port(port, speed_code) {
                                let new_addr = self.next_address;
                                self.register_device(
                                    new_addr,
                                    port as usize,
                                    0,
                                    speed,
                                    desc_buf,
                                    i,
                                );
                            }
                        }
                    }
                    if let Some(ref mut info) = self.controllers[i] {
                        info.initialised = true;
                    }
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Per-controller enumeration helpers
    // ----------------------------------------------------------------

    /// Full enumeration for a device attached to a UHCI port.
    fn enumerate_via_uhci(
        &mut self,
        ctrl: &mut UhciController,
        port: usize,
        speed: UsbSpeed,
        ls: bool,
        ctrl_idx: usize,
    ) {
        // Step 1: SET_ADDRESS at device address 0
        let new_addr = self.next_address;
        let setup_sa = UsbSetupPacket::set_address(new_addr);
        let res = ctrl.control_transfer(0, ls, &setup_sa, None, false);
        if res != UhciXferResult::Ok {
            return;
        }
        // Short recovery delay after SET_ADDRESS
        for _ in 0..2_000 {
            unsafe {
                core::arch::asm!("nop");
            }
        }

        // Step 2: GET_DESCRIPTOR(Device, 18 bytes)
        let mut desc_buf = [0u8; 18];
        let setup_gd = UsbSetupPacket::get_device_descriptor();
        let res2 = ctrl.control_transfer(new_addr, ls, &setup_gd, Some(&mut desc_buf), true);
        if res2 != UhciXferResult::Ok {
            return;
        }

        // Step 3: SET_CONFIGURATION(1)
        let setup_sc = UsbSetupPacket::set_configuration(1);
        let _ = ctrl.control_transfer(new_addr, ls, &setup_sc, None, false);

        self.register_device(new_addr, port, 0, speed, desc_buf, ctrl_idx);
    }

    /// Full enumeration for a device attached to an OHCI port.
    fn enumerate_via_ohci(
        &mut self,
        ctrl: &mut OhciController,
        port: usize,
        speed: UsbSpeed,
        ls: bool,
        ctrl_idx: usize,
    ) {
        let new_addr = self.next_address;
        let setup_sa = UsbSetupPacket::set_address(new_addr);
        if !ctrl.control_transfer(0, ls, &setup_sa, None, false) {
            return;
        }
        for _ in 0..2_000 {
            unsafe {
                core::arch::asm!("nop");
            }
        }

        let mut desc_buf = [0u8; 18];
        let setup_gd = UsbSetupPacket::get_device_descriptor();
        if !ctrl.control_transfer(new_addr, ls, &setup_gd, Some(&mut desc_buf), true) {
            return;
        }

        let setup_sc = UsbSetupPacket::set_configuration(1);
        let _ = ctrl.control_transfer(new_addr, ls, &setup_sc, None, false);

        self.register_device(new_addr, port, 0, speed, desc_buf, ctrl_idx);
    }

    /// Full enumeration for a device attached to an EHCI port.
    fn enumerate_via_ehci(
        &mut self,
        ctrl: &mut EhciController,
        port: usize,
        speed: UsbSpeed,
        hs: bool,
        ls: bool,
        ctrl_idx: usize,
    ) {
        let new_addr = self.next_address;
        let setup_sa = UsbSetupPacket::set_address(new_addr);
        if !ctrl.control_transfer(0, hs, ls, &setup_sa, None, false) {
            return;
        }
        for _ in 0..2_000 {
            unsafe {
                core::arch::asm!("nop");
            }
        }

        let mut desc_buf = [0u8; 18];
        let setup_gd = UsbSetupPacket::get_device_descriptor();
        if !ctrl.control_transfer(new_addr, hs, ls, &setup_gd, Some(&mut desc_buf), true) {
            return;
        }

        let setup_sc = UsbSetupPacket::set_configuration(1);
        let _ = ctrl.control_transfer(new_addr, hs, ls, &setup_sc, None, false);

        self.register_device(new_addr, port, 0, speed, desc_buf, ctrl_idx);
    }

    /// Parse the 18-byte descriptor buffer and add a device record.
    fn register_device(
        &mut self,
        addr: u8,
        port: usize,
        hub_addr: u8,
        speed: UsbSpeed,
        buf: [u8; 18],
        ctrl_idx: usize,
    ) {
        if self.device_count >= MAX_USB_DEVICES {
            return;
        }

        // Parse UsbDeviceDescriptor from raw bytes (little-endian)
        let desc = UsbDeviceDescriptor {
            b_length: buf[0],
            b_descriptor_type: buf[1],
            bcd_usb: u16::from_le_bytes([buf[2], buf[3]]),
            b_device_class: buf[4],
            b_device_sub_class: buf[5],
            b_device_protocol: buf[6],
            b_max_packet_size0: buf[7],
            id_vendor: u16::from_le_bytes([buf[8], buf[9]]),
            id_product: u16::from_le_bytes([buf[10], buf[11]]),
            bcd_device: u16::from_le_bytes([buf[12], buf[13]]),
            i_manufacturer: buf[14],
            i_product: buf[15],
            i_serial_number: buf[16],
            b_num_configurations: buf[17],
        };

        let dev = UsbDevice {
            address: addr,
            port: port as u8 + 1,
            hub_address: hub_addr,
            speed,
            descriptor: desc,
            controller_index: ctrl_idx,
        };
        self.devices[self.device_count] = Some(dev);
        self.device_count += 1;

        // Advance address counter
        self.next_address = self.next_address.wrapping_add(1);
        if self.next_address == 0 {
            self.next_address = 1;
        }
    }

    // ----------------------------------------------------------------
    // Accessors
    // ----------------------------------------------------------------

    /// Iterate over all successfully detected devices.
    pub fn devices(&self) -> impl Iterator<Item = &UsbDevice> {
        self.devices[..self.device_count]
            .iter()
            .filter_map(|d| d.as_ref())
    }

    /// Iterate over all registered controllers.
    pub fn controllers(&self) -> impl Iterator<Item = &UsbControllerInfo> {
        self.controllers[..self.controller_count]
            .iter()
            .filter_map(|c| c.as_ref())
    }
}

// ============================================================================
// Global singleton
// ============================================================================

pub static USB_BUS: Mutex<UsbBus> = Mutex::new(UsbBus::new());

/// Detect and initialise all USB host controllers found in `pci_devices`.
pub fn init(pci_devices: &[Option<PciDevice>]) {
    let mut bus = USB_BUS.lock();
    bus.detect(pci_devices);
    bus.init_controllers();
}

/// Obtain a lock guard to the global USB bus.
pub fn bus() -> spin::MutexGuard<'static, UsbBus> {
    USB_BUS.lock()
}

// ============================================================================
// Health snapshot
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct UsbHealth {
    pub controller_count: usize,
    pub initialised_controllers: usize,
    pub device_count: usize,
    pub irqs: u32,
}

pub fn health() -> UsbHealth {
    let guard = USB_BUS.lock();
    let initialised = guard.controllers[..guard.controller_count]
        .iter()
        .filter(|c| c.as_ref().map_or(false, |x| x.initialised))
        .count();
    UsbHealth {
        controller_count: guard.controller_count,
        initialised_controllers: initialised,
        device_count: guard.device_count,
        irqs: USB_IRQS.load(Ordering::Relaxed),
    }
}

/// Return the USB addresses of all enumerated mass-storage devices.
pub fn find_mass_storage_devices() -> alloc::vec::Vec<u8> {
    let guard = USB_BUS.lock();
    guard.devices[..guard.device_count]
        .iter()
        .filter_map(|d| d.as_ref())
        .filter(|d| d.is_mass_storage())
        .map(|d| d.address)
        .collect()
}

// ============================================================================
// USB Mass Storage — Bulk-Only Transport (BOT) + SCSI transparent command set
// ============================================================================
//
// Reference:
//   • USB Mass Storage Class Bulk-Only Transport, Revision 1.0
//   • SCSI Primary Commands-4 (SPC-4) / Block Commands-3 (SBC-3)
//
// The BOT protocol wraps SCSI CDBs in a 31-byte Command Block Wrapper (CBW)
// and expects a 13-byte Command Status Wrapper (CSW) in response.
//
// Transfer sequence for a read:
//   1. Bulk-OUT: send 31-byte CBW  (tag, data-transfer length, flags, CDB)
//   2. Bulk-IN:  receive data      (dev→host)
//   3. Bulk-IN:  receive 13-byte CSW
//
// For a write:
//   1. Bulk-OUT: send CBW
//   2. Bulk-OUT: send data         (host→dev)
//   3. Bulk-IN:  receive CSW

/// CBW signature (little-endian "USBC")
const CBW_SIGNATURE: u32 = 0x43425355;
/// CSW signature (little-endian "USBS")
const CSW_SIGNATURE: u32 = 0x53425355;

/// Command Block Wrapper (31 bytes, USB MSC spec §5.1)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BotCbw {
    pub d_cbw_signature: u32,
    pub d_cbw_tag: u32,
    pub d_cbw_data_transfer_length: u32,
    /// 0x80 = Data-In (device to host), 0x00 = Data-Out (host to device)
    pub bm_cbw_flags: u8,
    /// Target LUN (usually 0)
    pub b_cbw_lun: u8,
    /// Length of the CDB (1–16)
    pub b_cbwcb_length: u8,
    /// SCSI Command Descriptor Block (padded to 16 bytes)
    pub cbwcb: [u8; 16],
}

impl BotCbw {
    pub fn new(tag: u32, data_len: u32, dir_in: bool, lun: u8, cdb: &[u8]) -> Self {
        let mut c = BotCbw {
            d_cbw_signature: CBW_SIGNATURE,
            d_cbw_tag: tag,
            d_cbw_data_transfer_length: data_len,
            bm_cbw_flags: if dir_in { 0x80 } else { 0x00 },
            b_cbw_lun: lun,
            b_cbwcb_length: cdb.len() as u8,
            cbwcb: [0u8; 16],
        };
        let len = core::cmp::min(cdb.len(), 16);
        c.cbwcb[..len].copy_from_slice(&cdb[..len]);
        c
    }
}

/// Command Status Wrapper (13 bytes, USB MSC spec §5.2)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct BotCsw {
    pub d_csw_signature: u32,
    pub d_csw_tag: u32,
    pub d_csw_data_residue: u32,
    /// 0 = Command Passed, 1 = Command Failed, 2 = Phase Error
    pub b_csw_status: u8,
}

// SCSI command codes
const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_READ_CAPACITY10: u8 = 0x25;
const SCSI_READ10: u8 = 0x28;
const SCSI_WRITE10: u8 = 0x2A;

/// SCSI INQUIRY response (first 36 bytes, SPC-4 §6.4.2)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ScsiInquiryData {
    pub peripheral: u8, // bits 4:0 = device type
    pub removable: u8,  // bit 7 = RMB
    pub version: u8,
    pub response_fmt: u8,
    pub additional_len: u8,
    pub flags1: u8,
    pub flags2: u8,
    pub flags3: u8,
    pub vendor_id: [u8; 8],
    pub product_id: [u8; 16],
    pub product_rev: [u8; 4],
}

/// READ CAPACITY(10) response (8 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct ScsiReadCapacity10 {
    /// LBA of last logical block (big-endian)
    pub last_lba: u32,
    /// Block length in bytes (big-endian)
    pub block_size: u32,
}

impl ScsiReadCapacity10 {
    pub fn last_lba_native(&self) -> u32 {
        u32::from_be(self.last_lba)
    }
    pub fn block_size_native(&self) -> u32 {
        u32::from_be(self.block_size)
    }
    pub fn total_sectors(&self) -> u64 {
        self.last_lba_native() as u64 + 1
    }
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors() * self.block_size_native() as u64
    }
}

/// Errors from USB Mass Storage operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscError {
    /// Transfer to/from host controller failed.
    TransferError,
    /// CSW signature mismatch or phase error.
    ProtocolError,
    /// SCSI command failed (device returned non-zero CSW status).
    ScsiError(u8),
    /// Buffer not large enough for the requested operation.
    BufferTooSmall,
    /// Device not found or not a mass-storage device.
    NoDevice,
}

/// USB Mass Storage device handle.
///
/// Holds all state needed to issue BOT transactions.  Created by
/// `MassStorageDevice::open()`, which looks up the device in `UsbBus`.
pub struct MassStorageDevice {
    pub dev_addr: u8,
    pub ctrl_idx: usize,
    pub ctrl_kind: UsbControllerKind,
    pub speed: UsbSpeed,
    /// Bulk-OUT endpoint number
    pub ep_out: u8,
    /// Bulk-IN endpoint number
    pub ep_in: u8,
    pub max_pkt_bulk: u16,
    /// Running CBW tag counter
    tag: u32,
    /// Current bulk-OUT toggle
    tog_out: bool,
    /// Current bulk-IN toggle
    tog_in: bool,
    /// Block size from READ CAPACITY
    pub block_size: u32,
    /// Total block count from READ CAPACITY
    pub block_count: u64,
}

impl MassStorageDevice {
    /// Open the first enumerated mass-storage device.
    ///
    /// Returns `Err(MscError::NoDevice)` if no mass-storage device is present.
    pub fn open() -> Result<Self, MscError> {
        let guard = USB_BUS.lock();
        for d in guard.devices[..guard.device_count]
            .iter()
            .filter_map(|d| d.as_ref())
        {
            if !d.is_mass_storage() {
                continue;
            }
            // Assume EP1 OUT / EP1 IN; correct value comes from config descriptor.
            // A full implementation would parse the Configuration Descriptor here.
            let ctrl_kind = guard.controllers[d.controller_index]
                .map(|c| c.kind)
                .unwrap_or(UsbControllerKind::Uhci);
            let max_pkt = match d.speed {
                UsbSpeed::High => 512,
                _ => 64,
            };
            return Ok(MassStorageDevice {
                dev_addr: d.address,
                ctrl_idx: d.controller_index,
                ctrl_kind,
                speed: d.speed,
                ep_out: 1,
                ep_in: 1,
                max_pkt_bulk: max_pkt,
                tag: 1,
                tog_out: false,
                tog_in: false,
                block_size: 512,
                block_count: 0,
            });
        }
        Err(MscError::NoDevice)
    }

    // ----------------------------------------------------------------
    // Low-level BOT send/receive
    // ----------------------------------------------------------------

    fn next_tag(&mut self) -> u32 {
        let t = self.tag;
        self.tag = self.tag.wrapping_add(1);
        t
    }

    /// Send a 31-byte CBW over the bulk-OUT endpoint.
    fn send_cbw(
        &mut self,
        cbw: &BotCbw,
        uhci: Option<&mut UhciController>,
        ehci: Option<&mut EhciController>,
    ) -> Result<(), MscError> {
        let buf = unsafe { core::slice::from_raw_parts_mut(cbw as *const BotCbw as *mut u8, 31) };
        let hs = self.speed == UsbSpeed::High;
        let ls = self.speed == UsbSpeed::Low;
        let ok = if let Some(h) = uhci {
            h.bulk_transfer(
                self.dev_addr,
                self.ep_out,
                ls,
                false,
                self.max_pkt_bulk as usize,
                buf,
                &mut self.tog_out,
            ) == UhciXferResult::Ok
        } else if let Some(h) = ehci {
            h.bulk_transfer(
                self.dev_addr,
                self.ep_out,
                hs,
                false,
                self.max_pkt_bulk,
                buf,
                &mut self.tog_out,
            )
        } else {
            false
        };
        if ok {
            Ok(())
        } else {
            Err(MscError::TransferError)
        }
    }

    /// Receive a 13-byte CSW from the bulk-IN endpoint, verify its signature.
    fn recv_csw(
        &mut self,
        expected_tag: u32,
        uhci: Option<&mut UhciController>,
        ehci: Option<&mut EhciController>,
    ) -> Result<BotCsw, MscError> {
        let mut csw = BotCsw::default();
        let buf =
            unsafe { core::slice::from_raw_parts_mut(&mut csw as *mut BotCsw as *mut u8, 13) };
        let hs = self.speed == UsbSpeed::High;
        let ls = self.speed == UsbSpeed::Low;
        let ok = if let Some(h) = uhci {
            h.bulk_transfer(
                self.dev_addr,
                self.ep_in,
                ls,
                true,
                self.max_pkt_bulk as usize,
                buf,
                &mut self.tog_in,
            ) == UhciXferResult::Ok
        } else if let Some(h) = ehci {
            h.bulk_transfer(
                self.dev_addr,
                self.ep_in,
                hs,
                true,
                self.max_pkt_bulk,
                buf,
                &mut self.tog_in,
            )
        } else {
            false
        };
        if !ok {
            return Err(MscError::TransferError);
        }
        if csw.d_csw_signature != CSW_SIGNATURE || csw.d_csw_tag != expected_tag {
            return Err(MscError::ProtocolError);
        }
        if csw.b_csw_status == 2 {
            return Err(MscError::ProtocolError);
        }
        Ok(csw)
    }

    // ----------------------------------------------------------------
    // SCSI commands — UHCI path
    // ----------------------------------------------------------------

    /// Issue SCSI INQUIRY and return the 36-byte response (UHCI path).
    pub fn inquiry_uhci(&mut self, ctrl: &mut UhciController) -> Result<ScsiInquiryData, MscError> {
        let cdb = [SCSI_INQUIRY, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, 36, true, 0, &cdb);
        self.send_cbw(&cbw, Some(ctrl), None)?;

        let mut data = [0u8; 36];
        let ls = self.speed == UsbSpeed::Low;
        if ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            ls,
            true,
            self.max_pkt_bulk as usize,
            &mut data,
            &mut self.tog_in,
        ) != UhciXferResult::Ok
        {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, Some(ctrl), None)?;
        if csw.b_csw_status != 0 {
            return Err(MscError::ScsiError(csw.b_csw_status));
        }

        // Parse into ScsiInquiryData
        let inq = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const ScsiInquiryData) };
        Ok(inq)
    }

    /// Issue SCSI TEST UNIT READY (UHCI path).  Returns `true` if media ready.
    pub fn test_unit_ready_uhci(&mut self, ctrl: &mut UhciController) -> bool {
        let cdb = [SCSI_TEST_UNIT_READY; 16];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, 0, false, 0, &cdb);
        if self.send_cbw(&cbw, Some(ctrl), None).is_err() {
            return false;
        }
        self.recv_csw(tag, Some(ctrl), None)
            .map_or(false, |csw| csw.b_csw_status == 0)
    }

    /// Issue SCSI READ CAPACITY(10) and update `self.block_size`/`block_count`.
    pub fn read_capacity_uhci(
        &mut self,
        ctrl: &mut UhciController,
    ) -> Result<ScsiReadCapacity10, MscError> {
        let cdb = [
            SCSI_READ_CAPACITY10,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, 8, true, 0, &cdb);
        self.send_cbw(&cbw, Some(ctrl), None)?;

        let mut data = [0u8; 8];
        let ls = self.speed == UsbSpeed::Low;
        if ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            ls,
            true,
            self.max_pkt_bulk as usize,
            &mut data,
            &mut self.tog_in,
        ) != UhciXferResult::Ok
        {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, Some(ctrl), None)?;
        if csw.b_csw_status != 0 {
            return Err(MscError::ScsiError(csw.b_csw_status));
        }

        let cap = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const ScsiReadCapacity10) };
        self.block_size = cap.block_size_native();
        self.block_count = cap.total_sectors();
        Ok(cap)
    }

    /// Read `count` sectors starting at LBA `lba` into `buf` (UHCI path).
    ///
    /// `buf` must be at least `count * block_size` bytes.
    pub fn read_sectors_uhci(
        &mut self,
        ctrl: &mut UhciController,
        lba: u32,
        count: u16,
        buf: &mut [u8],
    ) -> Result<(), MscError> {
        let xfer_len = count as u32 * self.block_size;
        if buf.len() < xfer_len as usize {
            return Err(MscError::BufferTooSmall);
        }

        let cdb = [
            SCSI_READ10,
            0,
            (lba >> 24) as u8,
            (lba >> 16) as u8,
            (lba >> 8) as u8,
            lba as u8,
            0,
            (count >> 8) as u8,
            count as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, xfer_len, true, 0, &cdb);
        self.send_cbw(&cbw, Some(ctrl), None)?;

        let ls = self.speed == UsbSpeed::Low;
        if ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            ls,
            true,
            self.max_pkt_bulk as usize,
            &mut buf[..xfer_len as usize],
            &mut self.tog_in,
        ) != UhciXferResult::Ok
        {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, Some(ctrl), None)?;
        if csw.b_csw_status != 0 {
            Err(MscError::ScsiError(csw.b_csw_status))
        } else {
            Ok(())
        }
    }

    /// Write `count` sectors starting at LBA `lba` from `buf` (UHCI path).
    pub fn write_sectors_uhci(
        &mut self,
        ctrl: &mut UhciController,
        lba: u32,
        count: u16,
        buf: &mut [u8],
    ) -> Result<(), MscError> {
        let xfer_len = count as u32 * self.block_size;
        if buf.len() < xfer_len as usize {
            return Err(MscError::BufferTooSmall);
        }

        let cdb = [
            SCSI_WRITE10,
            0,
            (lba >> 24) as u8,
            (lba >> 16) as u8,
            (lba >> 8) as u8,
            lba as u8,
            0,
            (count >> 8) as u8,
            count as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, xfer_len, false, 0, &cdb);
        self.send_cbw(&cbw, Some(ctrl), None)?;

        let ls = self.speed == UsbSpeed::Low;
        if ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_out,
            ls,
            false,
            self.max_pkt_bulk as usize,
            &mut buf[..xfer_len as usize],
            &mut self.tog_out,
        ) != UhciXferResult::Ok
        {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, Some(ctrl), None)?;
        if csw.b_csw_status != 0 {
            Err(MscError::ScsiError(csw.b_csw_status))
        } else {
            Ok(())
        }
    }

    // ----------------------------------------------------------------
    // SCSI commands — EHCI path (mirrors UHCI; speed=High, max_pkt=512)
    // ----------------------------------------------------------------

    pub fn inquiry_ehci(&mut self, ctrl: &mut EhciController) -> Result<ScsiInquiryData, MscError> {
        let cdb = [SCSI_INQUIRY, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, 36, true, 0, &cdb);
        self.send_cbw(&cbw, None, Some(ctrl))?;

        let mut data = [0u8; 36];
        let hs = self.speed == UsbSpeed::High;
        if !ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            hs,
            true,
            self.max_pkt_bulk,
            &mut data,
            &mut self.tog_in,
        ) {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, None, Some(ctrl))?;
        if csw.b_csw_status != 0 {
            return Err(MscError::ScsiError(csw.b_csw_status));
        }
        let inq = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const ScsiInquiryData) };
        Ok(inq)
    }

    pub fn read_capacity_ehci(
        &mut self,
        ctrl: &mut EhciController,
    ) -> Result<ScsiReadCapacity10, MscError> {
        let cdb = [
            SCSI_READ_CAPACITY10,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, 8, true, 0, &cdb);
        self.send_cbw(&cbw, None, Some(ctrl))?;

        let mut data = [0u8; 8];
        let hs = self.speed == UsbSpeed::High;
        if !ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            hs,
            true,
            self.max_pkt_bulk,
            &mut data,
            &mut self.tog_in,
        ) {
            return Err(MscError::TransferError);
        }

        let csw = self.recv_csw(tag, None, Some(ctrl))?;
        if csw.b_csw_status != 0 {
            return Err(MscError::ScsiError(csw.b_csw_status));
        }
        let cap = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const ScsiReadCapacity10) };
        self.block_size = cap.block_size_native();
        self.block_count = cap.total_sectors();
        Ok(cap)
    }

    pub fn read_sectors_ehci(
        &mut self,
        ctrl: &mut EhciController,
        lba: u32,
        count: u16,
        buf: &mut [u8],
    ) -> Result<(), MscError> {
        let xfer_len = count as u32 * self.block_size;
        if buf.len() < xfer_len as usize {
            return Err(MscError::BufferTooSmall);
        }
        let cdb = [
            SCSI_READ10,
            0,
            (lba >> 24) as u8,
            (lba >> 16) as u8,
            (lba >> 8) as u8,
            lba as u8,
            0,
            (count >> 8) as u8,
            count as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, xfer_len, true, 0, &cdb);
        self.send_cbw(&cbw, None, Some(ctrl))?;
        let hs = self.speed == UsbSpeed::High;
        if !ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_in,
            hs,
            true,
            self.max_pkt_bulk,
            &mut buf[..xfer_len as usize],
            &mut self.tog_in,
        ) {
            return Err(MscError::TransferError);
        }
        let csw = self.recv_csw(tag, None, Some(ctrl))?;
        if csw.b_csw_status != 0 {
            Err(MscError::ScsiError(csw.b_csw_status))
        } else {
            Ok(())
        }
    }

    pub fn write_sectors_ehci(
        &mut self,
        ctrl: &mut EhciController,
        lba: u32,
        count: u16,
        buf: &mut [u8],
    ) -> Result<(), MscError> {
        let xfer_len = count as u32 * self.block_size;
        if buf.len() < xfer_len as usize {
            return Err(MscError::BufferTooSmall);
        }
        let cdb = [
            SCSI_WRITE10,
            0,
            (lba >> 24) as u8,
            (lba >> 16) as u8,
            (lba >> 8) as u8,
            lba as u8,
            0,
            (count >> 8) as u8,
            count as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let tag = self.next_tag();
        let cbw = BotCbw::new(tag, xfer_len, false, 0, &cdb);
        self.send_cbw(&cbw, None, Some(ctrl))?;
        let hs = self.speed == UsbSpeed::High;
        if !ctrl.bulk_transfer(
            self.dev_addr,
            self.ep_out,
            hs,
            false,
            self.max_pkt_bulk,
            &mut buf[..xfer_len as usize],
            &mut self.tog_out,
        ) {
            return Err(MscError::TransferError);
        }
        let csw = self.recv_csw(tag, None, Some(ctrl))?;
        if csw.b_csw_status != 0 {
            Err(MscError::ScsiError(csw.b_csw_status))
        } else {
            Ok(())
        }
    }
}

// ============================================================================
// USB HID Class Driver
// ============================================================================
//
// USB HID Specification 1.11 §B: Boot Protocol
//
// The boot protocol is mandatory for keyboards and mice and provides a
// fixed, simple report format that does not require parsing a Report
// Descriptor.  We support:
//   • Boot keyboard (usage page 0x01, usage 0x06)
//   • Boot mouse    (usage page 0x01, usage 0x02)
//
// After `SET_PROTOCOL(0)` the device sends:
//   Keyboard: 8-byte report — modifier, reserved, keycodes[6]
//   Mouse:    4-byte report — buttons, dx, dy, wheel
//
// HID class-specific requests
const HID_REQ_GET_REPORT: u8 = 0x01;
const HID_REQ_SET_IDLE: u8 = 0x0A;
const HID_REQ_SET_PROTOCOL: u8 = 0x0B;
// bRequest / wValue selectors for GET_DESCRIPTOR
const DESC_HID: u8 = 0x21;
const DESC_REPORT: u8 = 0x22;
// Protocol values
const HID_PROTO_BOOT: u16 = 0;
const HID_PROTO_REPORT: u16 = 1;
// Subclass / protocol
const HID_SUBCLASS_BOOT: u8 = 1;
const HID_PROTO_KBD: u8 = 1;
const HID_PROTO_MOUSE: u8 = 2;

/// Modifier byte bit masks (USB HID keyboard boot report byte 0).
pub mod kbd_mod {
    pub const L_CTRL: u8 = 1 << 0;
    pub const L_SHIFT: u8 = 1 << 1;
    pub const L_ALT: u8 = 1 << 2;
    pub const L_GUI: u8 = 1 << 3;
    pub const R_CTRL: u8 = 1 << 4;
    pub const R_SHIFT: u8 = 1 << 5;
    pub const R_ALT: u8 = 1 << 6;
    pub const R_GUI: u8 = 1 << 7;
}

/// A decoded USB HID boot-protocol keyboard report.
#[derive(Clone, Copy, Default)]
pub struct HidKeyboardReport {
    /// Modifier byte (see `kbd_mod` constants).
    pub modifiers: u8,
    /// Currently held key codes (up to 6, USB HID page 0x07).
    pub keycodes: [u8; 6],
}

impl HidKeyboardReport {
    /// Parse from an 8-byte boot-protocol report buffer.
    pub fn from_bytes(b: &[u8; 8]) -> Self {
        let mut kc = [0u8; 6];
        kc.copy_from_slice(&b[2..8]);
        HidKeyboardReport {
            modifiers: b[0],
            keycodes: kc,
        }
    }

    pub fn shift(&self) -> bool {
        self.modifiers & (kbd_mod::L_SHIFT | kbd_mod::R_SHIFT) != 0
    }
    pub fn ctrl(&self) -> bool {
        self.modifiers & (kbd_mod::L_CTRL | kbd_mod::R_CTRL) != 0
    }
    pub fn alt(&self) -> bool {
        self.modifiers & (kbd_mod::L_ALT | kbd_mod::R_ALT) != 0
    }
    pub fn is_gui(&self) -> bool {
        self.modifiers & (kbd_mod::L_GUI | kbd_mod::R_GUI) != 0
    }
}

/// Decoded USB HID boot-protocol mouse report.
#[derive(Clone, Copy, Default)]
pub struct HidMouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
}

impl HidMouseReport {
    pub fn from_bytes(b: &[u8; 4]) -> Self {
        HidMouseReport {
            buttons: b[0],
            dx: b[1] as i8,
            dy: b[2] as i8,
            wheel: b[3] as i8,
        }
    }
}

/// Which boot-protocol device class this HID device is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HidKind {
    Keyboard,
    Mouse,
    Other,
}

/// A USB HID device handle.
pub struct UsbHidDevice {
    pub dev_addr: u8,
    pub ctrl_idx: usize,
    pub ctrl_kind: UsbControllerKind,
    pub speed: UsbSpeed,
    /// Interrupt-IN endpoint number (e.g. 0x81)
    pub ep_in: u8,
    pub max_pkt: u16,
    pub kind: HidKind,
    toggle: bool,
}

impl UsbHidDevice {
    /// Construct a new HID device handle (does not communicate with device).
    pub fn new(
        dev_addr: u8,
        ctrl_idx: usize,
        ctrl_kind: UsbControllerKind,
        speed: UsbSpeed,
        ep_in: u8,
        max_pkt: u16,
        kind: HidKind,
    ) -> Self {
        UsbHidDevice {
            dev_addr,
            ctrl_idx,
            ctrl_kind,
            speed,
            ep_in,
            max_pkt,
            kind,
            toggle: false,
        }
    }

    // ----------------------------------------------------------------
    // HID class setup
    // ----------------------------------------------------------------

    /// Perform HID class initialisation on a UHCI path:
    ///   1. SET_IDLE(0, 0)        — stop unsolicited reports
    ///   2. SET_PROTOCOL(Boot)    — switch to boot protocol
    pub fn setup_uhci(&self, ctrl: &mut UhciController) -> bool {
        let ls = self.speed == UsbSpeed::Low;

        // SET_IDLE(duration=0, report_id=0): stop repeated reports
        let idle = UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_CLASS | RT_INTERFACE,
            b_request: HID_REQ_SET_IDLE,
            w_value: 0,
            w_index: 0,
            w_length: 0,
        };
        let _ = ctrl.control_transfer(self.dev_addr, ls, &idle, None, false);

        // SET_PROTOCOL(0 = Boot)
        let proto = UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_CLASS | RT_INTERFACE,
            b_request: HID_REQ_SET_PROTOCOL,
            w_value: HID_PROTO_BOOT,
            w_index: 0,
            w_length: 0,
        };
        ctrl.control_transfer(self.dev_addr, ls, &proto, None, false) == UhciXferResult::Ok
    }

    /// Perform HID class initialisation on an EHCI path.
    pub fn setup_ehci(&self, ctrl: &mut EhciController) -> bool {
        let hs = self.speed == UsbSpeed::High;
        let ls = self.speed == UsbSpeed::Low;

        let idle = UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_CLASS | RT_INTERFACE,
            b_request: HID_REQ_SET_IDLE,
            w_value: 0,
            w_index: 0,
            w_length: 0,
        };
        let _ = ctrl.control_transfer(self.dev_addr, hs, ls, &idle, None, false);

        let proto = UsbSetupPacket {
            bm_request_type: RT_HOST_TO_DEV | RT_CLASS | RT_INTERFACE,
            b_request: HID_REQ_SET_PROTOCOL,
            w_value: HID_PROTO_BOOT,
            w_index: 0,
            w_length: 0,
        };
        ctrl.control_transfer(self.dev_addr, hs, ls, &proto, None, false)
    }

    // ----------------------------------------------------------------
    // Polling
    // ----------------------------------------------------------------

    /// Poll the interrupt-IN endpoint for a keyboard report (UHCI).
    ///
    /// Returns `None` if no report is available yet (NAK) or on error.
    pub fn poll_keyboard_uhci(&mut self, ctrl: &mut UhciController) -> Option<HidKeyboardReport> {
        let ls = self.speed == UsbSpeed::Low;
        let mut buf = [0u8; 8];
        let ep = self.ep_in & 0x0F;
        match ctrl.bulk_transfer(
            self.dev_addr,
            ep,
            ls,
            true,
            self.max_pkt as usize,
            &mut buf,
            &mut self.toggle,
        ) {
            UhciXferResult::Ok => Some(HidKeyboardReport::from_bytes(&buf)),
            _ => None,
        }
    }

    /// Poll the interrupt-IN endpoint for a mouse report (UHCI).
    pub fn poll_mouse_uhci(&mut self, ctrl: &mut UhciController) -> Option<HidMouseReport> {
        let ls = self.speed == UsbSpeed::Low;
        let mut buf = [0u8; 4];
        let ep = self.ep_in & 0x0F;
        match ctrl.bulk_transfer(
            self.dev_addr,
            ep,
            ls,
            true,
            self.max_pkt as usize,
            &mut buf,
            &mut self.toggle,
        ) {
            UhciXferResult::Ok => {
                let report = HidMouseReport::from_bytes(&buf);
                // Forward mouse deltas into the shared mouse event pipeline.
                crate::mouse::submit_usb_report(crate::mouse::UsbMouseReport {
                    buttons: report.buttons,
                    dx: report.dx,
                    dy: report.dy,
                    dwheel: report.wheel,
                });
                Some(report)
            }
            _ => None,
        }
    }

    /// Poll the interrupt-IN endpoint for a keyboard report (EHCI).
    pub fn poll_keyboard_ehci(&mut self, ctrl: &mut EhciController) -> Option<HidKeyboardReport> {
        let hs = self.speed == UsbSpeed::High;
        let mut buf = [0u8; 8];
        let ep = self.ep_in & 0x0F;
        if ctrl.bulk_transfer(
            self.dev_addr,
            ep,
            hs,
            true,
            self.max_pkt,
            &mut buf,
            &mut self.toggle,
        ) {
            Some(HidKeyboardReport::from_bytes(&buf))
        } else {
            None
        }
    }

    /// Poll the interrupt-IN endpoint for a mouse report (EHCI).
    pub fn poll_mouse_ehci(&mut self, ctrl: &mut EhciController) -> Option<HidMouseReport> {
        let hs = self.speed == UsbSpeed::High;
        let mut buf = [0u8; 4];
        let ep = self.ep_in & 0x0F;
        if ctrl.bulk_transfer(
            self.dev_addr,
            ep,
            hs,
            true,
            self.max_pkt,
            &mut buf,
            &mut self.toggle,
        ) {
            let report = HidMouseReport::from_bytes(&buf);
            crate::mouse::submit_usb_report(crate::mouse::UsbMouseReport {
                buttons: report.buttons,
                dx: report.dx,
                dy: report.dy,
                dwheel: report.wheel,
            });
            Some(report)
        } else {
            None
        }
    }
}

/// Open the first enumerated USB HID keyboard.
pub fn open_hid_keyboard() -> Option<UsbHidDevice> {
    let guard = USB_BUS.lock();
    for d in guard.devices[..guard.device_count]
        .iter()
        .filter_map(|d| d.as_ref())
    {
        if d.descriptor.b_device_class == 0x03 {
            let kind = guard.controllers[d.controller_index]
                .map(|c| c.kind)
                .unwrap_or(UsbControllerKind::Uhci);
            let max_pkt = match d.speed {
                UsbSpeed::High => 64,
                _ => 8,
            };
            return Some(UsbHidDevice::new(
                d.address,
                d.controller_index,
                kind,
                d.speed,
                0x81,
                max_pkt,
                HidKind::Keyboard,
            ));
        }
    }
    None
}

/// Open the first enumerated USB HID mouse.
pub fn open_hid_mouse() -> Option<UsbHidDevice> {
    let guard = USB_BUS.lock();
    for d in guard.devices[..guard.device_count]
        .iter()
        .filter_map(|d| d.as_ref())
    {
        if d.descriptor.b_device_class == 0x03 {
            let kind = guard.controllers[d.controller_index]
                .map(|c| c.kind)
                .unwrap_or(UsbControllerKind::Uhci);
            let max_pkt = match d.speed {
                UsbSpeed::High => 64,
                _ => 8,
            };
            return Some(UsbHidDevice::new(
                d.address,
                d.controller_index,
                kind,
                d.speed,
                0x81,
                max_pkt,
                HidKind::Mouse,
            ));
        }
    }
    None
}
