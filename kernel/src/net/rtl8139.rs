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

//! Realtek RTL8139 Fast Ethernet driver
//!
//! # Architecture
//!
//! ```text
//!  PCI: vendor 0x10EC / device 0x8139
//!       └─ I/O BAR0
//!
//!  TX: 4 fixed descriptors (TSAD0-3 / TSD0-3)
//!       ├─ rotating cursor `tx_cur` (0..3)
//!       ├─ each descriptor has its own static 1544-byte buffer
//!       └─ OWN bit in TSD clears when card finishes sending
//!
//!  RX: 8 KiB + 16 B + 1500 B ring buffer (RBSTART)
//!       ├─ read pointer maintained via CAPR
//!       └─ new packets signalled by ISR bit 0 (ROK) or polled
//!
//!  MAC address: 6 bytes at I/O base + 0x00
//! ```
//!
//! # Conformance
//!
//! Matches the `NetworkInterface` calling convention used by the existing
//! `e1000.rs` driver so the network stack can treat both devices uniformly.

#![allow(dead_code)] // hardware register table — constants reserved for full RTL8139 implementation

use crate::drivers::x86::pci::PciDevice;
use spin::Mutex;

// ============================================================================
// PCI identifiers
// ============================================================================

const PCI_VENDOR_REALTEK: u16 = 0x10EC;
const PCI_DEV_RTL8139: u16 = 0x8139;

// ============================================================================
// Register offsets (I/O port, relative to BAR0)
// ============================================================================

// MAC address (IDR0..5)
const RTL_IDR0: u16 = 0x00;
// Multicast filter registers
const RTL_MAR0: u16 = 0x08;
// TX descriptor base addresses (4 × 4-byte)
const RTL_TSAD0: u16 = 0x20;
const RTL_TSAD1: u16 = 0x24;
const RTL_TSAD2: u16 = 0x28;
const RTL_TSAD3: u16 = 0x2C;
// RX buffer start address
const RTL_RBSTART: u16 = 0x30;
// Early RX threshold count
const RTL_ERBCR: u16 = 0x34;
// Early RX status
const RTL_ERSR: u16 = 0x36;
// Command register
const RTL_CR: u16 = 0x37;
// Current Address of Packet Read (16-bit, subtracted from RBSTART)
const RTL_CAPR: u16 = 0x38;
// Current Buffer Address (hardware write pointer into RX ring)
const RTL_CBR: u16 = 0x3A;
// Interrupt mask / status registers
const RTL_IMR: u16 = 0x3C;
const RTL_ISR: u16 = 0x3E;
// TX config / RX config
const RTL_TCR: u16 = 0x40;
const RTL_RCR: u16 = 0x44;
// Timer count
const RTL_TCTR: u16 = 0x48;
// Missed packet counter
const RTL_MPC: u16 = 0x4C;
// 93C46 command register (EEPROM / config access)
const RTL_9346CR: u16 = 0x50;
// Config registers
const RTL_CONFIG0: u16 = 0x51;
const RTL_CONFIG1: u16 = 0x52;
// Media status
const RTL_MSR: u16 = 0x58;
// PHY parameter
const RTL_PHYPAR: u16 = 0x60;
// TX status descriptors (4 × 4-byte)
const RTL_TSD0: u16 = 0x10;
const RTL_TSD1: u16 = 0x14;
const RTL_TSD2: u16 = 0x18;
const RTL_TSD3: u16 = 0x1C;

// ============================================================================
// Register bit definitions
// ============================================================================

// Command register (CR)
const CR_RST: u8 = 1 << 4; // Software reset
const CR_RE: u8 = 1 << 3; // Receiver enable
const CR_TE: u8 = 1 << 2; // Transmitter enable
const CR_BUFE: u8 = 1 << 0; // Buffer empty (RX)

// Interrupt mask / status bits
const ISR_TOK: u16 = 1 << 2; // TX OK
const ISR_ROK: u16 = 1 << 0; // RX OK
const ISR_TER: u16 = 1 << 3; // TX Error
const ISR_RER: u16 = 1 << 1; // RX Error
const ISR_RXOVW: u16 = 1 << 4; // RX buffer overflow

// TX status bits (TSD)
const TSD_OWN: u32 = 1 << 13; // Card finished transmitting
const TSD_TOK: u32 = 1 << 15;
const TSD_TUN: u32 = 1 << 14; // TX underrun
const TSD_OWC: u32 = 1 << 29; // Out of window collision

// TX config (TCR) defaults:
// IFG = 3 (normal inter-frame gap), MXDMA = 2KB bursts
const TCR_DEFAULT: u32 = 0x0F00_0600;

// RX config (RCR): accept broadcast + multicast + unicast, no wrap, 8K+16 buf
// RBLEN=0 (8K+16), RX FIFO threshold=0 (No threshold), DMA burst=unlimited
const RCR_DEFAULT: u32 = 0x0000_F70F;
// Bit masks for RCR
const RCR_AAP: u32 = 1 << 0; // Accept all packets
const RCR_APM: u32 = 1 << 1; // Accept physical match
const RCR_AM: u32 = 1 << 2; // Accept multicast
const RCR_AB: u32 = 1 << 3; // Accept broadcast
const RCR_WRAP: u32 = 1 << 7; // No wrap — we handle wrap ourselves

// 93C46CR: EEM1/EEM0 bits to unlock config registers for write
const C46CR_CONFIG_WRITE: u8 = 0xC0;
const C46CR_NORMAL: u8 = 0x00;

// ============================================================================
// Packet sizes
// ============================================================================

const TX_BUF_SIZE: usize = 1544; // max Ethernet frame + some margin
const TX_DESC_COUNT: usize = 4;
const RX_BUF_SIZE: usize = 8192 + 16 + 1500; // ring + header + overshoot

// RX packet header fields
const RX_HDR_ROK: u16 = 1 << 0; // Receive OK
const RX_HDR_FAE: u16 = 1 << 1; // Frame Alignment Error
const RX_HDR_CRC: u16 = 1 << 2; // CRC Error

// ============================================================================
// Static DMA buffers
// ============================================================================

#[repr(C, align(4))]
struct TxBufArray {
    data: [[u8; TX_BUF_SIZE]; TX_DESC_COUNT],
}
static mut TX_BUFS: TxBufArray = TxBufArray {
    data: [[0u8; TX_BUF_SIZE]; TX_DESC_COUNT],
};

#[repr(C, align(4))]
struct RxBuf {
    data: [u8; RX_BUF_SIZE],
}
static mut RX_BUF: RxBuf = RxBuf {
    data: [0u8; RX_BUF_SIZE],
};

// ============================================================================
// RTL8139 driver
// ============================================================================

pub struct Rtl8139Driver {
    pub io_base: u16,
    pub pci: PciDevice,
    pub mac: [u8; 6],
    pub initialised: bool,
    /// Rotating TX descriptor index (0–3)
    tx_cur: usize,
    /// RX ring read offset (byte offset into RX_BUF)
    rx_offset: usize,
}

impl Rtl8139Driver {
    pub fn new(io_base: u16, pci: PciDevice) -> Self {
        Rtl8139Driver {
            io_base,
            pci,
            mac: [0u8; 6],
            initialised: false,
            tx_cur: 0,
            rx_offset: 0,
        }
    }

    // ----------------------------------------------------------------
    // I/O port helpers
    // ----------------------------------------------------------------

    #[inline(always)]
    unsafe fn inb(&self, reg: u16) -> u8 {
        let v: u8;
        core::arch::asm!("in al, dx", out("al") v, in("dx") self.io_base + reg);
        v
    }
    #[inline(always)]
    unsafe fn inw(&self, reg: u16) -> u16 {
        let v: u16;
        core::arch::asm!("in ax, dx", out("ax") v, in("dx") self.io_base + reg);
        v
    }
    #[inline(always)]
    unsafe fn ind(&self, reg: u16) -> u32 {
        let v: u32;
        core::arch::asm!("in eax, dx", out("eax") v, in("dx") self.io_base + reg);
        v
    }
    #[inline(always)]
    unsafe fn outb(&self, reg: u16, v: u8) {
        core::arch::asm!("out dx, al", in("dx") self.io_base + reg, in("al") v);
    }
    #[inline(always)]
    unsafe fn outw(&self, reg: u16, v: u16) {
        core::arch::asm!("out dx, ax", in("dx") self.io_base + reg, in("ax") v);
    }
    #[inline(always)]
    unsafe fn outd(&self, reg: u16, v: u32) {
        core::arch::asm!("out dx, eax", in("dx") self.io_base + reg, in("eax") v);
    }

    fn delay(&self) {
        for _ in 0..10_000u32 {
            unsafe {
                core::arch::asm!("nop");
            }
        }
    }

    // ----------------------------------------------------------------
    // TX descriptor register helpers
    // ----------------------------------------------------------------

    fn tsad_reg(&self, idx: usize) -> u16 {
        [RTL_TSAD0, RTL_TSAD1, RTL_TSAD2, RTL_TSAD3][idx & 3]
    }
    fn tsd_reg(&self, idx: usize) -> u16 {
        [RTL_TSD0, RTL_TSD1, RTL_TSD2, RTL_TSD3][idx & 3]
    }

    // ----------------------------------------------------------------
    // Initialisation
    // ----------------------------------------------------------------

    pub fn init(&mut self) -> bool {
        unsafe {
            self.pci.enable_bus_mastering();

            // Unlock config registers
            self.outb(RTL_9346CR, C46CR_CONFIG_WRITE);

            // Power on
            self.outb(RTL_CONFIG1, 0x00);

            // Software reset
            self.outb(RTL_CR, CR_RST);
            for _ in 0..100_000u32 {
                if self.inb(RTL_CR) & CR_RST == 0 {
                    break;
                }
            }

            // Re-lock config
            self.outb(RTL_9346CR, C46CR_NORMAL);

            // Read MAC address
            for i in 0..6 {
                self.mac[i] = self.inb(RTL_IDR0 + i as u16);
            }
            crate::serial_println!(
                "[RTL8139] MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                self.mac[0],
                self.mac[1],
                self.mac[2],
                self.mac[3],
                self.mac[4],
                self.mac[5]
            );

            // Set RX buffer start address
            let rx_phys = RX_BUF.data.as_ptr() as u32;
            self.outd(RTL_RBSTART, rx_phys);

            // Set TX buffer base addresses
            for i in 0..TX_DESC_COUNT {
                let tx_phys = TX_BUFS.data[i].as_ptr() as u32;
                self.outd(self.tsad_reg(i), tx_phys);
            }

            // Clear TX status registers
            for i in 0..TX_DESC_COUNT {
                self.outd(self.tsd_reg(i), 0);
            }

            // Configure RX: accept unicast + broadcast + multicast, 8K+16 ring, no WRAP
            // We handle wrap manually for simplicity; set WRAP=1 so hardware wraps
            // the ring automatically (simpler for 8K buffer).
            self.outd(RTL_RCR, RCR_DEFAULT | RCR_APM | RCR_AM | RCR_AB | RCR_WRAP);

            // Configure TX: normal IFG, 2KB DMA bursts
            self.outd(RTL_TCR, TCR_DEFAULT);

            // Unmask ROK, TOK, RER, TER interrupts
            self.outw(RTL_IMR, ISR_ROK | ISR_TOK | ISR_RER | ISR_TER);

            // Enable RX + TX
            self.outb(RTL_CR, CR_RE | CR_TE);

            // Clear CAPR / CBR
            self.outw(RTL_CAPR, 0);
            self.rx_offset = 0;

            crate::serial_println!("[RTL8139] Initialised on I/O base 0x{:04X}", self.io_base);
        }

        self.initialised = true;
        true
    }

    // ----------------------------------------------------------------
    // Transmit
    // ----------------------------------------------------------------

    /// Send an Ethernet frame (without FCS — the card appends CRC).
    ///
    /// Returns `true` on success.  Blocks until the previous descriptor using
    /// this slot has been sent (OWN bit is clear).
    pub fn send(&mut self, frame: &[u8]) -> bool {
        if !self.initialised {
            return false;
        }
        let len = frame.len();
        if len > TX_BUF_SIZE {
            return false;
        }

        let idx = self.tx_cur;
        let tsd = self.tsd_reg(idx);

        unsafe {
            // Wait for OWN bit to be set by us (card cleared it when done)
            // TSD OWN=1 means *we* own the descriptor (card done or never used)
            for _ in 0..2_000_000u32 {
                if self.ind(tsd) & TSD_OWN != 0 {
                    break;
                }
            }

            // Copy frame into TX buffer
            let dst = TX_BUFS.data[idx].as_mut_ptr();
            core::ptr::copy_nonoverlapping(frame.as_ptr(), dst, len);

            // Write TSD: size | early TX threshold=0
            // Setting OWN=0 (bit 13) gives ownership to the card
            self.outd(tsd, len as u32);
        }

        self.tx_cur = (self.tx_cur + 1) % TX_DESC_COUNT;
        true
    }

    // ----------------------------------------------------------------
    // Receive
    // ----------------------------------------------------------------

    /// Copy the next received frame into `buf`.  Returns the frame length, or
    /// 0 if the ring is empty.
    ///
    /// The RTL8139 prepends a 4-byte header to each packet in the ring:
    ///   [status: u16][length: u16] (little-endian)
    /// followed by the raw Ethernet frame.
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        if !self.initialised {
            return 0;
        }
        unsafe {
            // Check if buffer is empty
            if self.inb(RTL_CR) & CR_BUFE != 0 {
                return 0;
            }

            // Read the 4-byte packet header at rx_offset
            let ring = RX_BUF.data.as_ptr();
            let hdr_off = self.rx_offset;
            let status = u16::from_le_bytes([
                *ring.add(hdr_off % RX_BUF_SIZE),
                *ring.add((hdr_off + 1) % RX_BUF_SIZE),
            ]);
            let pkt_len = u16::from_le_bytes([
                *ring.add((hdr_off + 2) % RX_BUF_SIZE),
                *ring.add((hdr_off + 3) % RX_BUF_SIZE),
            ]) as usize;

            if status & RX_HDR_ROK == 0 || pkt_len < 4 || pkt_len > buf.len() + 4 {
                // Skip this packet
                self.rx_offset = (self.rx_offset + 4 + pkt_len + 3) & !3;
                self.update_capr();
                return 0;
            }

            // pkt_len includes the 4-byte CRC appended by the card
            let data_len = pkt_len - 4;
            let data_off = hdr_off + 4;
            let copy_len = core::cmp::min(data_len, buf.len());

            for i in 0..copy_len {
                buf[i] = *ring.add((data_off + i) % RX_BUF_SIZE);
            }

            // Advance read pointer: align to 4-byte boundary
            self.rx_offset = (data_off + pkt_len + 3) & !3;
            self.update_capr();

            copy_len
        }
    }

    pub fn has_recv(&self) -> bool {
        if !self.initialised {
            return false;
        }
        unsafe { self.inb(RTL_CR) & CR_BUFE == 0 }
    }

    /// Write the updated CAPR (Current Address of Packet Read).
    ///
    /// CAPR is written as (rx_offset - 16) to leave a 16-byte header margin.
    unsafe fn update_capr(&self) {
        let capr = (self.rx_offset.wrapping_sub(16)) as u16;
        self.outw(RTL_CAPR, capr);
    }

    // ----------------------------------------------------------------
    // Link status
    // ----------------------------------------------------------------

    pub fn link_up(&self) -> bool {
        unsafe { self.inb(RTL_MSR) & 0x04 == 0 } // MSR bit 2 = link down when set
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    // ----------------------------------------------------------------
    // ISR handling (call from IRQ handler)
    // ----------------------------------------------------------------

    /// Acknowledge and clear all pending interrupts.  Returns the ISR value.
    pub fn handle_irq(&self) -> u16 {
        unsafe {
            let isr = self.inw(RTL_ISR);
            self.outw(RTL_ISR, isr); // write-to-clear
            isr
        }
    }
}

// ============================================================================
// Global RTL8139 driver
// ============================================================================

pub static RTL8139: Mutex<Option<Rtl8139Driver>> = Mutex::new(None);

/// Probe PCI bus for an RTL8139 NIC and initialise it.
pub fn init(pci_devices: &[PciDevice]) {
    for &dev in pci_devices {
        if dev.vendor_id != PCI_VENDOR_REALTEK || dev.device_id != PCI_DEV_RTL8139 {
            continue;
        }
        let bar0 = unsafe { dev.read_bar(0) };
        if bar0 == 0 || bar0 & 1 == 0 {
            continue;
        } // must be I/O BAR
        let io_base = (bar0 & !3) as u16;

        let mut drv = Rtl8139Driver::new(io_base, dev);
        if drv.init() {
            *RTL8139.lock() = Some(drv);
            return;
        }
    }
    crate::serial_println!("[RTL8139] No RTL8139 NIC found");
}

/// Transmit an Ethernet frame.
pub fn send(frame: &[u8]) -> bool {
    match RTL8139.lock().as_mut() {
        Some(d) => d.send(frame),
        None => false,
    }
}

/// Receive one Ethernet frame into `buf`.  Returns the frame length or 0.
pub fn recv(buf: &mut [u8]) -> usize {
    match RTL8139.lock().as_mut() {
        Some(d) => d.recv(buf),
        None => 0,
    }
}

pub fn has_recv() -> bool {
    match RTL8139.lock().as_ref() {
        Some(d) => d.has_recv(),
        None => false,
    }
}

/// Return current link status.
pub fn link_up() -> bool {
    match RTL8139.lock().as_ref() {
        Some(d) => d.link_up(),
        None => false,
    }
}
