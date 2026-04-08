/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Intel E1000 Ethernet Driver (Real Hardware)
//!
//! Driver for Intel 82540EM Gigabit Ethernet Controller (emulated by QEMU).
//! Supports real packet transmission and reception with descriptor rings.

use super::netstack::NetworkInterface;
use crate::drivers::x86::pci::PciDevice;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

// E1000 Register Offsets
const E1000_REG_CTRL: u32 = 0x0000; // Device Control
const E1000_REG_STATUS: u32 = 0x0008; // Device Status
const E1000_REG_EEPROM: u32 = 0x0014; // EEPROM Read
const E1000_REG_CTRL_EXT: u32 = 0x0018; // Extended Device Control
const E1000_REG_ICR: u32 = 0x00C0; // Interrupt Cause Read
const E1000_REG_ITR: u32 = 0x00C4; // Interrupt Throttling Rate (×256 ns units)
const E1000_REG_IMS: u32 = 0x00D0; // Interrupt Mask Set

// IMS / ICR bit masks
const E1000_IMS_TXDW: u32 = 0x0001; // TX descriptor written back
const E1000_IMS_LSC: u32 = 0x0004; // Link status change
const E1000_IMS_RXT0: u32 = 0x0080; // RX timer interrupt
/// Adaptive ITR tiers (all in ×256 ns units):
///   IDLE  =  50 × 256 ns =  12.8 µs  → ~78 K IRQ/s max  (low-latency)
///   MID   = 200 × 256 ns =  51.2 µs  → ~19.5 K IRQ/s    (balanced)
///   BULK  = 500 × 256 ns = 128.0 µs  → ~7.8 K IRQ/s     (throughput)
const E1000_ITR_IDLE: u32 = 50;
const E1000_ITR_MID: u32 = 200;
const E1000_ITR_BULK: u32 = 500;

/// Maximum frames to batch into the TX ring before one RDT write.
/// 32 × 1460 B ≈ 46 KiB — fits inside a single 64 KiB TCP window slice.
const TX_BATCH_MAX: usize = 32;
const E1000_REG_RCTL: u32 = 0x0100; // Receive Control
const E1000_REG_TCTL: u32 = 0x0400; // Transmit Control
const E1000_REG_RDBAL: u32 = 0x2800; // RX Descriptor Base Low
const E1000_REG_RDBAH: u32 = 0x2804; // RX Descriptor Base High
const E1000_REG_RDLEN: u32 = 0x2808; // RX Descriptor Length
const E1000_REG_RDH: u32 = 0x2810; // RX Descriptor Head
const E1000_REG_RDT: u32 = 0x2818; // RX Descriptor Tail
const E1000_REG_TDBAL: u32 = 0x3800; // TX Descriptor Base Low
const E1000_REG_TDBAH: u32 = 0x3804; // TX Descriptor Base High
const E1000_REG_TDLEN: u32 = 0x3808; // TX Descriptor Length
const E1000_REG_TDH: u32 = 0x3810; // TX Descriptor Head
const E1000_REG_TDT: u32 = 0x3818; // TX Descriptor Tail
const E1000_REG_MTA: u32 = 0x5200; // Multicast Table Array

// Control Register Flags
const E1000_CTRL_RST: u32 = 0x04000000; // Device Reset
const E1000_CTRL_ASDE: u32 = 0x00000020; // Auto-Speed Detection Enable
const E1000_CTRL_SLU: u32 = 0x00000040; // Set Link Up

// Receive Control Flags
const E1000_RCTL_EN: u32 = 0x00000002; // Receiver Enable
const E1000_RCTL_UPE: u32 = 0x00000008; // Unicast Promiscuous
const E1000_RCTL_MPE: u32 = 0x00000010; // Multicast Promiscuous
const E1000_RCTL_BAM: u32 = 0x00008000; // Broadcast Accept Mode
const E1000_RCTL_BSIZE: u32 = 0x00000000; // Buffer Size (2048 bytes)
const E1000_RCTL_SECRC: u32 = 0x04000000; // Strip Ethernet CRC

// Transmit Control Flags
const E1000_TCTL_EN: u32 = 0x00000002; // Transmit Enable
const E1000_TCTL_PSP: u32 = 0x00000008; // Pad Short Packets
const E1000_TCTL_CT: u32 = 0x00000FF0; // Collision Threshold
const E1000_TCTL_COLD: u32 = 0x003FF000; // Collision Distance

// Descriptor flags
const E1000_TXD_CMD_EOP: u8 = 0x01; // End of Packet
const E1000_TXD_CMD_RS: u8 = 0x08; // Report Status
const E1000_TXD_STAT_DD: u8 = 0x01; // Descriptor Done

/// Descriptor ring depth.  256 entries give:
///   RX: 256 \u00d7 2 KiB = 512 KiB buffer, enough to absorb ~340 \u00b5s at Gigabit rate
///   TX: 256 slots so a full 1 MB TCP window (1 \u00d7 1460-B segments) fits without stall.
/// Must be a power-of-two and \u2265 8; hardware ring length register expects multiples of 8.
const NUM_RX_DESC: usize = 256;
const NUM_TX_DESC: usize = 256;
const ETH_MIN_FRAME_NO_FCS: usize = 60;
const TX_DESC_READY_SPINS: usize = 1_000_000;
const TX_DESC_READY_TIMEOUT_TICKS: u64 = 5;
const E1000_RESET_TIMEOUT_SPINS: usize = 100_000;
const E1000_EEPROM_TIMEOUT_SPINS: usize = 10_000;
const E1000_REG_VERIFY_TIMEOUT_SPINS: usize = 10_000;

// Simple buffer pool (static memory for MVP)
#[repr(align(4096))]
struct AlignedRxPool {
    data: [[u8; 2048]; NUM_RX_DESC],
}
#[repr(align(4096))]
struct AlignedTxPool {
    data: [[u8; 2048]; NUM_TX_DESC],
}

static mut RX_BUFFERS: AlignedRxPool = AlignedRxPool {
    data: [[0; 2048]; NUM_RX_DESC],
};
static mut TX_BUFFERS: AlignedTxPool = AlignedTxPool {
    data: [[0; 2048]; NUM_TX_DESC],
};
static mut RX_DESCS: [E1000RxDesc; NUM_RX_DESC] = [E1000RxDesc::new(); NUM_RX_DESC];
static mut TX_DESCS: [E1000TxDesc; NUM_TX_DESC] = [E1000TxDesc::new(); NUM_TX_DESC];

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct E1000RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

impl E1000RxDesc {
    const fn new() -> Self {
        E1000RxDesc {
            addr: 0,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct E1000TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

impl E1000TxDesc {
    const fn new() -> Self {
        E1000TxDesc {
            addr: 0,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }
}

pub struct E1000Driver {
    pci_device: PciDevice,
    mmio_base: u32,
    mac_address: [u8; 6],
    enabled: bool,
    /// Descriptor index the software will inspect next for completed RX data.
    rx_next: usize,
    /// Descriptor index most recently returned to hardware via RDT.
    rx_tail: usize,
    tx_tail: usize,
    /// Number of TX descriptors enqueued since the last RDT write.
    /// When this reaches TX_BATCH_MAX or flush_tx() is called, RDT is written once.
    tx_batch_pending: usize,
    /// Last ITR tier written to the register (avoids redundant MMIO writes).
    last_itr: u32,
}

// MMIO base for IRQ-safe interrupt acknowledge
static E1000_MMIO_BASE: AtomicU32 = AtomicU32::new(0);

impl E1000Driver {
    #[inline]
    fn effective_mmio_base(&self) -> u32 {
        if self.mmio_base >= 0x0010_0000 {
            return self.mmio_base;
        }
        E1000_MMIO_BASE.load(Ordering::Acquire)
    }

    #[inline]
    fn cached_mac_valid(&self) -> bool {
        self.mac_address != [0; 6] && self.mac_address != [0xFF; 6]
    }

    /// Create a new E1000 driver instance
    pub fn new(pci_device: PciDevice) -> Self {
        E1000Driver {
            pci_device,
            mmio_base: 0,
            mac_address: [0; 6],
            enabled: false,
            rx_next: 0,
            rx_tail: 0,
            tx_tail: 0,
            tx_batch_pending: 0,
            last_itr: E1000_ITR_MID,
        }
    }

    /// Initialize the E1000 device
    pub fn init(&mut self) -> Result<(), &'static str> {
        // Capture BAR0 before mutating PCI command bits so the MMIO base is stable.
        let bar0 = unsafe { self.pci_device.read_bar(0) };
        if bar0 == 0 {
            return Err("E1000: No MMIO base address");
        }
        let mmio_base = bar0 & !0xF; // Clear flag bits
        if mmio_base < 0x0010_0000 {
            return Err("E1000: MMIO base below minimum");
        }

        // Enable memory decoding + bus mastering for MMIO/DMA.
        unsafe {
            self.pci_device.enable_memory_space();
            self.pci_device.enable_bus_mastering();
        }

        // Enable bus mastering for DMA
        self.mmio_base = mmio_base;
        if self.mmio_base < 0x0010_0000 {
            return Err("E1000: MMIO base below minimum");
        }
        E1000_MMIO_BASE.store(self.mmio_base, Ordering::Release);

        self.verify_mmio_sanity()?;

        // Reset the device
        self.reset()?;

        // Read MAC address from EEPROM
        self.read_mac_address()?;

        // Initialize multicast table
        self.init_multicast_table()?;

        // Initialize RX/TX
        self.init_rx()?;
        self.init_tx()?;

        // Enable device
        self.enable()?;

        self.enabled = true;
        Ok(())
    }

    #[inline]
    fn initialized(&self) -> bool {
        self.effective_mmio_base() >= 0x0010_0000
    }

    #[inline]
    fn hardware_enabled(&self) -> bool {
        if !self.initialized() {
            return false;
        }
        let rctl = self.read_reg(E1000_REG_RCTL);
        let tctl = self.read_reg(E1000_REG_TCTL);
        (rctl & E1000_RCTL_EN) != 0 && (tctl & E1000_TCTL_EN) != 0
    }

    #[inline]
    fn ensure_enabled(&mut self) -> bool {
        if self.mmio_base < 0x0010_0000 {
            let recovered = E1000_MMIO_BASE.load(Ordering::Acquire);
            if recovered >= 0x0010_0000 {
                self.mmio_base = recovered;
            }
        }
        if !self.initialized() {
            return false;
        }
        if self.enabled || self.hardware_enabled() {
            self.enabled = true;
            return true;
        }

        // The driver object is only published after init() fully succeeds.
        // On legacy x86 the software `enabled` bit has proven less stable than
        // the actual device state, so the hot path treats a fully initialized
        // NIC as usable and only performs best-effort re-arming here.
        let _ = self.init_rx();
        let _ = self.init_tx();
        let _ = self.enable();
        self.enabled = true;
        true
    }

    #[inline(never)]
    fn mmio_addr(&self, reg: u32) -> Option<u32> {
        let addr = self.effective_mmio_base().checked_add(reg)?;
        if addr < 0x0010_0000 {
            return None;
        }
        Some(addr)
    }

    /// Reset the E1000 device
    #[inline(never)]
    fn reset(&mut self) -> Result<(), &'static str> {
        // Set reset bit
        self.write_reg(E1000_REG_CTRL, E1000_CTRL_RST);

        for _ in 0..E1000_RESET_TIMEOUT_SPINS {
            let ctrl = self.read_reg(E1000_REG_CTRL);
            if ctrl != 0xFFFF_FFFF && (ctrl & E1000_CTRL_RST) == 0 {
                self.write_reg(E1000_REG_IMS, 0);
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err("E1000: Reset timeout")
    }

    /// Read MAC address from EEPROM
    #[inline(never)]
    fn read_mac_address(&mut self) -> Result<(), &'static str> {
        // Read MAC address from EEPROM using E1000_REG_EEPROM
        // MAC is stored in EEPROM words 0-2 (6 bytes total)
        for i in 0..3 {
            let word = self.read_eeprom(i)?;
            let idx = (i * 2) as usize;
            self.mac_address[idx] = (word & 0xFF) as u8;
            self.mac_address[idx + 1] = ((word >> 8) & 0xFF) as u8;
        }
        if self.mac_address == [0; 6] || self.mac_address == [0xFF; 6] {
            return Err("E1000: EEPROM MAC invalid");
        }

        crate::serial_print!("[E1000] MAC address read from EEPROM: ");
        crate::serial_print!("{:02X}", self.mac_address[0]);
        crate::serial_print!(":{:02X}", self.mac_address[1]);
        crate::serial_print!(":{:02X}", self.mac_address[2]);
        crate::serial_print!(":{:02X}", self.mac_address[3]);
        crate::serial_print!(":{:02X}", self.mac_address[4]);
        crate::serial_println!(":{:02X}", self.mac_address[5]);
        Ok(())
    }

    /// Read a 16-bit word from EEPROM
    #[inline(never)]
    fn read_eeprom(&mut self, addr: u16) -> Result<u16, &'static str> {
        // Write EEPROM read request: address | start bit
        self.write_reg(E1000_REG_EEPROM, 0x00000001 | ((addr as u32) << 8));

        // Poll for done bit (bit 4)
        for _ in 0..E1000_EEPROM_TIMEOUT_SPINS {
            let result = self.read_reg(E1000_REG_EEPROM);
            if (result & 0x10) != 0 {
                return Ok(((result >> 16) & 0xFFFF) as u16);
            }
            core::hint::spin_loop();
        }
        Err("E1000: EEPROM timeout")
    }

    /// Initialize multicast table array (128 entries)
    #[inline(never)]
    fn init_multicast_table(&mut self) -> Result<(), &'static str> {
        // Clear all multicast table entries using E1000_REG_MTA
        for i in 0..128 {
            self.write_reg(E1000_REG_MTA + (i * 4), 0);
        }
        Ok(())
    }

    /// Initialize receive descriptors
    #[inline(never)]
    fn init_rx(&mut self) -> Result<(), &'static str> {
        unsafe {
            let rx_phys = RX_BUFFERS.data.as_ptr() as u32;
            crate::serial_println!(
                "[NET] Rx Buffers: {:#x} - {:#x}",
                rx_phys,
                rx_phys + (2048 * NUM_RX_DESC) as u32
            );
            crate::serial_println!("[NET] Rx Descriptors: {:#x}", &RX_DESCS as *const _ as u32);
            crate::serial_println!(
                "[NET] Tx Buffers: {:#x} - {:#x}",
                &TX_BUFFERS as *const _ as u32,
                &TX_BUFFERS as *const _ as u32 + (2048 * NUM_TX_DESC) as u32
            );
            crate::serial_println!("[NET] Tx Descriptors: {:#x}", &TX_DESCS as *const _ as u32);
            // Setup descriptor ring
            for i in 0..NUM_RX_DESC {
                RX_DESCS[i].addr = RX_BUFFERS.data[i].as_ptr() as u64;
                RX_DESCS[i].status = 0;
            }

            // Set descriptor base address
            let desc_addr = RX_DESCS.as_ptr() as u32;
            self.write_reg(E1000_REG_RDBAL, desc_addr);
            self.write_reg(E1000_REG_RDBAH, 0);

            // Set descriptor length
            self.write_reg(E1000_REG_RDLEN, (NUM_RX_DESC * 16) as u32);

            // Set head and tail
            self.write_reg(E1000_REG_RDH, 0);
            self.write_reg(E1000_REG_RDT, (NUM_RX_DESC - 1) as u32);
            self.rx_next = 0;
            self.rx_tail = NUM_RX_DESC - 1;

            // Enable receiver with promiscuous mode
            let rctl = E1000_RCTL_EN
                | E1000_RCTL_UPE
                | E1000_RCTL_MPE
                | E1000_RCTL_BAM
                | E1000_RCTL_BSIZE
                | E1000_RCTL_SECRC;
            self.write_reg(E1000_REG_RCTL, rctl);
        }
        self.verify_rx_registers()
    }

    /// Initialize transmit descriptors
    #[inline(never)]
    fn init_tx(&mut self) -> Result<(), &'static str> {
        unsafe {
            let tx_phys = TX_BUFFERS.data.as_ptr() as u32;
            crate::serial_println!(
                "[NET] Tx Buffers: {:#x} - {:#x}",
                tx_phys,
                tx_phys + (2048 * NUM_TX_DESC) as u32
            );
            crate::serial_println!("[NET] Tx Descriptors: {:#x}", &TX_DESCS as *const _ as u32);
            // Setup descriptor ring
            for i in 0..NUM_TX_DESC {
                TX_DESCS[i].addr = TX_BUFFERS.data[i].as_ptr() as u64;
                TX_DESCS[i].cmd = 0;
                TX_DESCS[i].status = E1000_TXD_STAT_DD;
            }

            // Set descriptor base address
            let desc_addr = TX_DESCS.as_ptr() as u32;
            self.write_reg(E1000_REG_TDBAL, desc_addr);
            self.write_reg(E1000_REG_TDBAH, 0);

            // Set descriptor length
            self.write_reg(E1000_REG_TDLEN, (NUM_TX_DESC * 16) as u32);

            // Set head and tail
            self.write_reg(E1000_REG_TDH, 0);
            self.write_reg(E1000_REG_TDT, 0);
            self.tx_tail = 0;

            // Enable transmitter with collision parameters
            let tctl = E1000_TCTL_EN | E1000_TCTL_PSP |
                       ((15 << 4) & E1000_TCTL_CT) |   // Collision threshold
                       ((64 << 12) & E1000_TCTL_COLD); // Collision distance
            self.write_reg(E1000_REG_TCTL, tctl);
        }
        self.verify_tx_registers()
    }

    /// Enable the device
    #[inline(never)]
    fn enable(&mut self) -> Result<(), &'static str> {
        let ctrl = E1000_CTRL_ASDE | E1000_CTRL_SLU;
        self.write_reg(E1000_REG_CTRL, ctrl);

        // Configure extended control register
        self.write_reg(E1000_REG_CTRL_EXT, 0);

        // Set interrupt throttle rate: start at MID tier (51 µs).
        // The reactor will call set_itr_adaptive() each poll cycle to tune this.
        self.write_reg(E1000_REG_ITR, E1000_ITR_MID);
        self.last_itr = E1000_ITR_MID;

        // Clear any stale interrupt causes before unmasking
        let _ = self.read_reg(E1000_REG_ICR);

        #[cfg(target_arch = "x86")]
        {
            // Legacy x86 uses the inline network reactor and does not need NIC IRQs
            // during early boot. Unmasking E1000 interrupts before the scheduler is
            // fully established can re-enter the half-initialized switch path and
            // fault on a null context.
            self.write_reg(E1000_REG_IMS, 0);
        }

        #[cfg(not(target_arch = "x86"))]
        {
            // Enable RX timer (RXT0), TX write-back (TXDW) and link-state-change (LSC)
            // interrupts so the hardware wakes the reactor rather than relying on
            // the scheduler round-tripping through yield_now().
            self.write_reg(
                E1000_REG_IMS,
                E1000_IMS_TXDW | E1000_IMS_LSC | E1000_IMS_RXT0,
            );
        }
        let ctrl_readback = self.read_reg(E1000_REG_CTRL);
        if ctrl_readback == 0 || ctrl_readback == 0xFFFF_FFFF {
            return Err("E1000: Enable register readback invalid");
        }
        Ok(())
    }

    fn enable_runtime_interrupts(&mut self) {
        if !self.ensure_enabled() {
            return;
        }
        let _ = self.read_reg(E1000_REG_ICR);
        self.write_reg(
            E1000_REG_IMS,
            E1000_IMS_TXDW | E1000_IMS_LSC | E1000_IMS_RXT0,
        );
    }

    fn ensure_runtime_link(&mut self) -> bool {
        if !self.ensure_enabled() {
            return false;
        }
        if self.is_link_up() {
            return true;
        }

        let ctrl = self.read_reg(E1000_REG_CTRL);
        self.write_reg(E1000_REG_CTRL, ctrl | E1000_CTRL_ASDE | E1000_CTRL_SLU);

        for _ in 0..E1000_REG_VERIFY_TIMEOUT_SPINS {
            if self.is_link_up() {
                return true;
            }
            core::hint::spin_loop();
        }

        false
    }

    fn verify_mmio_sanity(&self) -> Result<(), &'static str> {
        let ctrl = self.read_reg(E1000_REG_CTRL);
        let status = self.read_reg(E1000_REG_STATUS);
        if (ctrl == 0 && status == 0) || (ctrl == 0xFFFF_FFFF && status == 0xFFFF_FFFF) {
            return Err("E1000: MMIO read sanity check failed");
        }
        Ok(())
    }

    fn verify_rx_registers(&self) -> Result<(), &'static str> {
        let expected_base = unsafe { RX_DESCS.as_ptr() as u32 };
        self.wait_for_reg(
            E1000_REG_RDBAL,
            expected_base,
            "E1000: RX ring register verify failed",
        )?;
        self.wait_for_reg(E1000_REG_RDBAH, 0, "E1000: RX ring register verify failed")?;
        self.wait_for_reg(
            E1000_REG_RDLEN,
            (NUM_RX_DESC * 16) as u32,
            "E1000: RX ring register verify failed",
        )?;
        self.wait_for_reg(E1000_REG_RDH, 0, "E1000: RX ring register verify failed")?;
        self.wait_for_reg(
            E1000_REG_RDT,
            (NUM_RX_DESC - 1) as u32,
            "E1000: RX ring register verify failed",
        )
    }

    fn verify_tx_registers(&self) -> Result<(), &'static str> {
        let expected_base = unsafe { TX_DESCS.as_ptr() as u32 };
        self.wait_for_reg(
            E1000_REG_TDBAL,
            expected_base,
            "E1000: TX ring register verify failed",
        )?;
        self.wait_for_reg(E1000_REG_TDBAH, 0, "E1000: TX ring register verify failed")?;
        self.wait_for_reg(
            E1000_REG_TDLEN,
            (NUM_TX_DESC * 16) as u32,
            "E1000: TX ring register verify failed",
        )?;
        self.wait_for_reg(E1000_REG_TDH, 0, "E1000: TX ring register verify failed")?;
        self.wait_for_reg(E1000_REG_TDT, 0, "E1000: TX ring register verify failed")
    }

    fn wait_for_reg(&self, reg: u32, expected: u32, err: &'static str) -> Result<(), &'static str> {
        for _ in 0..E1000_REG_VERIFY_TIMEOUT_SPINS {
            if self.read_reg(reg) == expected {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(err)
    }

    /// Write to an E1000 register
    #[inline(never)]
    fn write_reg(&mut self, reg: u32, value: u32) {
        if let Some(addr) = self.mmio_addr(reg) {
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, value);
            }
        }
    }

    /// Read from an E1000 register
    #[inline(never)]
    fn read_reg(&self, reg: u32) -> u32 {
        if let Some(addr) = self.mmio_addr(reg) {
            unsafe {
                return core::ptr::read_volatile(addr as *const u32);
            }
        }
        0
    }

    /// Handle E1000 interrupt (clears ICR and processes events)
    pub fn handle_irq(&mut self) {
        let icr = self.read_reg(E1000_REG_ICR);

        if icr == 0 {
            return; // Not our interrupt
        }

        // Log interrupt cause for diagnostics
        if (icr & 0x80) != 0 {
            crate::serial_println!("[E1000] IRQ: RX packet received");
        }
        if (icr & 0x01) != 0 {
            crate::serial_println!("[E1000] IRQ: TX descriptor written back");
        }
        if (icr & 0x04) != 0 {
            crate::serial_println!("[E1000] IRQ: Link status change");
        }

        // Clear interrupt by reading ICR (already done above)
        // Additional processing could be added here
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Check if device is enabled
    pub fn is_enabled(&self) -> bool {
        self.initialized() && (self.enabled || self.hardware_enabled())
    }

    /// Receive an Ethernet frame (non-blocking, single frame).
    pub fn recv_frame(&mut self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if !self.ensure_enabled() {
            return Err("E1000: Device not enabled");
        }

        unsafe {
            let desc_idx = self.rx_next;
            let desc = &RX_DESCS[desc_idx];
            if desc.status & 0x01 == 0 {
                return Err("No packet available");
            }

            let len = desc.length as usize;
            if len > buffer.len() {
                return Err("Buffer too small");
            }

            crate::memory::asm_bindings::fast_memcpy(&mut buffer[..len], &RX_BUFFERS.data[desc_idx][..len]);

            RX_DESCS[desc_idx].status = 0;
            self.rx_tail = desc_idx;
            self.write_reg(E1000_REG_RDT, self.rx_tail as u32);
            self.rx_next = (desc_idx + 1) % NUM_RX_DESC;

            Ok(len)
        }
    }

    /// Drain up to `budget` RX frames in a **single lock window**, writing
    /// RDT once at the end.  Returns the number of frames received.
    ///
    /// Each `out_bufs[i]` is a `&mut [u8; 2048]`-sized slot; `out_lens[i]`
    /// receives the actual frame length.  Both slices must have length ≥ budget.
    pub fn recv_frames_burst(
        &mut self,
        out_bufs: &mut [[u8; 2048]],
        out_lens: &mut [usize],
        budget: usize,
    ) -> usize {
        if !self.ensure_enabled() {
            return 0;
        }
        let budget = budget
            .min(out_bufs.len())
            .min(out_lens.len())
            .min(NUM_RX_DESC);
        let mut received = 0usize;
        unsafe {
            while received < budget {
                let desc_idx = self.rx_next;
                let desc = &RX_DESCS[desc_idx];
                if desc.status & 0x01 == 0 {
                    break; // ring empty
                }
                let len = (desc.length as usize).min(2048);
                crate::memory::asm_bindings::fast_memcpy(
                    &mut out_bufs[received][..len],
                    &RX_BUFFERS.data[desc_idx][..len],
                );
                out_lens[received] = len;
                RX_DESCS[desc_idx].status = 0;
                self.rx_tail = desc_idx;
                self.rx_next = (desc_idx + 1) % NUM_RX_DESC;
                received += 1;
            }
            if received > 0 {
                // Single RDT write for the whole batch — one PCIe posted write.
                self.write_reg(E1000_REG_RDT, self.rx_tail as u32);
            }
        }
        received
    }

    /// Enqueue one frame into the TX ring **without** writing RDT.
    ///
    /// The frame is not visible to the hardware until `flush_tx_batch()` is
    /// called (or the batch depth reaches `TX_BATCH_MAX`, which auto-flushes).
    /// Use `send_frame()` for single-frame paths; use this + `flush_tx_batch()`
    /// for burst sends.
    #[inline]
    pub fn enqueue_tx_frame(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.ensure_enabled() {
            return Err("E1000: Device not enabled");
        }
        let frame_len = data.len().max(ETH_MIN_FRAME_NO_FCS);
        if frame_len > 2048 {
            return Err("Frame too large");
        }
        unsafe {
            let start_ticks = crate::scheduler::pit::get_ticks();
            let mut spins = 0usize;
            while TX_DESCS[self.tx_tail].status & E1000_TXD_STAT_DD == 0 {
                if spins >= TX_DESC_READY_SPINS
                    || crate::scheduler::pit::get_ticks().saturating_sub(start_ticks)
                        >= TX_DESC_READY_TIMEOUT_TICKS
                {
                    return Err("TX busy");
                }
                spins += 1;
                core::hint::spin_loop();
            }
            TX_BUFFERS.data[self.tx_tail][..frame_len].fill(0);
            crate::memory::asm_bindings::fast_memcpy(
                &mut TX_BUFFERS.data[self.tx_tail][..data.len()],
                data,
            );
            // Only the last descriptor in the batch needs RS; intermediate ones
            // use EOP alone so the NIC doesn't generate a write-back per frame.
            TX_DESCS[self.tx_tail].length = frame_len as u16;
            TX_DESCS[self.tx_tail].cmd = E1000_TXD_CMD_EOP; // RS added on flush
            TX_DESCS[self.tx_tail].status = 0;
            self.tx_tail = (self.tx_tail + 1) % NUM_TX_DESC;
            self.tx_batch_pending += 1;
        }
        if self.tx_batch_pending >= TX_BATCH_MAX {
            self.flush_tx_batch();
        }
        Ok(())
    }

    /// Commit all pending TX descriptors to the hardware with a single RDT
    /// write.  Sets RS on the last descriptor so we get one write-back IRQ.
    #[inline]
    pub fn flush_tx_batch(&mut self) {
        if self.tx_batch_pending == 0 {
            return;
        }
        unsafe {
            // Back up to the last enqueued descriptor and set RS.
            let last = (self.tx_tail + NUM_TX_DESC - 1) % NUM_TX_DESC;
            TX_DESCS[last].cmd |= E1000_TXD_CMD_RS;
        }
        self.write_reg(E1000_REG_TDT, self.tx_tail as u32);
        self.tx_batch_pending = 0;
    }

    /// Send a single Ethernet frame, flushing immediately.
    ///
    /// For bulk sends prefer `enqueue_tx_frame` + `flush_tx_batch`.
    pub fn send_frame(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.enqueue_tx_frame(data)?;
        self.flush_tx_batch();
        Ok(())
    }

    /// Send a slice of frames as one batched TX burst — single RDT write.
    ///
    /// Returns the number of frames successfully enqueued.
    pub fn send_frames_batch(&mut self, frames: &[&[u8]]) -> usize {
        let mut sent = 0usize;
        for &frame in frames {
            if self.enqueue_tx_frame(frame).is_err() {
                break;
            }
            sent += 1;
        }
        if self.tx_batch_pending > 0 {
            self.flush_tx_batch();
        }
        sent
    }

    /// Update the interrupt throttle register adaptively based on observed
    /// RX frame rate.
    ///
    /// | frames_per_poll | ITR tier | interval  | max IRQ/s |
    /// |-----------------|----------|-----------|----------|
    /// | < 8             | IDLE     | 12.8 µs   | ~78 K    |
    /// | 8 – 31          | MID      | 51.2 µs   | ~19.5 K  |
    /// | ≥ 32            | BULK     | 128.0 µs  | ~7.8 K   |
    pub fn set_itr_adaptive(&mut self, frames_per_poll: usize) {
        let new_itr = if frames_per_poll < 8 {
            E1000_ITR_IDLE
        } else if frames_per_poll < 32 {
            E1000_ITR_MID
        } else {
            E1000_ITR_BULK
        };
        if new_itr != self.last_itr {
            self.write_reg(E1000_REG_ITR, new_itr);
            self.last_itr = new_itr;
        }
    }

    /// Send an Ethernet frame (deprecated, use send_frame)
    pub fn send_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.send_frame(data)
    }

    /// Get link status
    pub fn is_link_up(&self) -> bool {
        let status = self.read_reg(E1000_REG_STATUS);
        (status & 0x02) != 0 // Link Up bit
    }
}

pub static E1000_DRIVER: Mutex<Option<E1000Driver>> = Mutex::new(None);

/// Initialize E1000 with detected PCI device
pub fn init(pci_device: PciDevice) -> Result<(), &'static str> {
    let mut driver = E1000Driver::new(pci_device);
    driver.init()?;

    *E1000_DRIVER.lock() = Some(driver);
    Ok(())
}

/// Get MAC address
pub fn get_mac_address() -> Option<[u8; 6]> {
    E1000_DRIVER.lock().as_ref().and_then(|d| {
        if d.cached_mac_valid() {
            Some(d.mac_address())
        } else {
            None
        }
    })
}

/// Enable runtime IRQ delivery after the dedicated network task is live.
pub fn enable_runtime_interrupts() {
    let mut driver = E1000_DRIVER.lock();
    if let Some(nic) = driver.as_mut() {
        nic.enable_runtime_interrupts();
    }
}

pub fn ensure_runtime_link() -> bool {
    let mut driver = E1000_DRIVER.lock();
    driver
        .as_mut()
        .map(|nic| nic.ensure_runtime_link())
        .unwrap_or(false)
}

pub fn driver_present() -> bool {
    E1000_DRIVER.lock().as_ref().is_some()
}

/// Check if link is up
pub fn is_link_up() -> bool {
    E1000_DRIVER
        .lock()
        .as_ref()
        .map(|d| d.is_link_up())
        .unwrap_or(false)
}

/// Handle E1000 IRQ (if enabled)
pub fn handle_irq() {
    let base = E1000_MMIO_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    unsafe {
        let addr = (base + E1000_REG_ICR) as *const u32;
        let _ = core::ptr::read_volatile(addr);
    }
}

/// Get MMIO base (for diagnostics)
pub fn mmio_base() -> u32 {
    E1000_MMIO_BASE.load(Ordering::Acquire)
}

// ============================================================================
// NetworkInterface Trait Implementation
// ============================================================================

impl NetworkInterface for E1000Driver {
    type Packet = [u8; 2048];

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        E1000Driver::send_frame(self, frame)
    }

    fn recv_frame(&mut self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        E1000Driver::recv_frame(self, buffer)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    fn is_link_up(&self) -> bool {
        E1000Driver::is_link_up(self)
    }
}
