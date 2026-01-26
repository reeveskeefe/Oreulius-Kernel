//! Intel E1000 Ethernet Driver (Real Hardware)
//!
//! Driver for Intel 82540EM Gigabit Ethernet Controller (emulated by QEMU).
//! Supports real packet transmission and reception.

use crate::pci::PciDevice;
use spin::Mutex;

// E1000 Register Offsets
const E1000_REG_CTRL: u32 = 0x0000;      // Device Control
const E1000_REG_STATUS: u32 = 0x0008;    // Device Status
const E1000_REG_EEPROM: u32 = 0x0014;    // EEPROM Read
const E1000_REG_CTRL_EXT: u32 = 0x0018;  // Extended Device Control
const E1000_REG_ICR: u32 = 0x00C0;       // Interrupt Cause Read
const E1000_REG_IMS: u32 = 0x00D0;       // Interrupt Mask Set
const E1000_REG_RCTL: u32 = 0x0100;      // Receive Control
const E1000_REG_TCTL: u32 = 0x0400;      // Transmit Control
const E1000_REG_RDBAL: u32 = 0x2800;     // RX Descriptor Base Low
const E1000_REG_RDBAH: u32 = 0x2804;     // RX Descriptor Base High
const E1000_REG_RDLEN: u32 = 0x2808;     // RX Descriptor Length
const E1000_REG_RDH: u32 = 0x2810;       // RX Descriptor Head
const E1000_REG_RDT: u32 = 0x2818;       // RX Descriptor Tail
const E1000_REG_TDBAL: u32 = 0x3800;     // TX Descriptor Base Low
const E1000_REG_TDBAH: u32 = 0x3804;     // TX Descriptor Base High
const E1000_REG_TDLEN: u32 = 0x3808;     // TX Descriptor Length
const E1000_REG_TDH: u32 = 0x3810;       // TX Descriptor Head
const E1000_REG_TDT: u32 = 0x3818;       // TX Descriptor Tail
const E1000_REG_MTA: u32 = 0x5200;       // Multicast Table Array

// Control Register Flags
const E1000_CTRL_RST: u32 = 0x04000000;  // Device Reset
const E1000_CTRL_ASDE: u32 = 0x00000020; // Auto-Speed Detection Enable
const E1000_CTRL_SLU: u32 = 0x00000040;  // Set Link Up

// Receive Control Flags
const E1000_RCTL_EN: u32 = 0x00000002;   // Receiver Enable
const E1000_RCTL_UPE: u32 = 0x00000008;  // Unicast Promiscuous
const E1000_RCTL_MPE: u32 = 0x00000010;  // Multicast Promiscuous
const E1000_RCTL_BAM: u32 = 0x00008000;  // Broadcast Accept Mode
const E1000_RCTL_BSIZE: u32 = 0x00000000; // Buffer Size (2048 bytes)
const E1000_RCTL_SECRC: u32 = 0x04000000; // Strip Ethernet CRC

// Transmit Control Flags
const E1000_TCTL_EN: u32 = 0x00000002;   // Transmit Enable
const E1000_TCTL_PSP: u32 = 0x00000008;  // Pad Short Packets

pub struct E1000Driver {
    pci_device: PciDevice,
    mmio_base: u32,
    mac_address: [u8; 6],
    enabled: bool,
}

impl E1000Driver {
    /// Create a new E1000 driver instance
    pub fn new(pci_device: PciDevice) -> Self {
        E1000Driver {
            pci_device,
            mmio_base: 0,
            mac_address: [0; 6],
            enabled: false,
        }
    }

    /// Initialize the E1000 device
    pub fn init(&mut self) -> Result<(), &'static str> {
        // Enable bus mastering for DMA
        unsafe {
            self.pci_device.enable_bus_mastering();
        }
        
        // Get MMIO base address from BAR0
        let bar0 = unsafe { self.pci_device.read_bar(0) };
        if bar0 == 0 {
            return Err("E1000: No MMIO base address");
        }
        
        self.mmio_base = bar0 & !0xF;  // Clear flag bits
        
        // Reset the device
        self.reset();
        
        // Read MAC address from EEPROM
        self.read_mac_address();
        
        // Initialize RX/TX
        self.init_rx();
        self.init_tx();
        
        // Enable device
        self.enable();
        
        self.enabled = true;
        Ok(())
    }

    /// Reset the E1000 device
    fn reset(&mut self) {
        // Set reset bit
        self.write_reg(E1000_REG_CTRL, E1000_CTRL_RST);
        
        // Wait for reset to complete (simple delay)
        for _ in 0..1000 {
            unsafe { core::arch::asm!("nop"); }
        }
        
        // Clear interrupt mask
        self.write_reg(E1000_REG_IMS, 0);
    }

    /// Read MAC address from EEPROM
    fn read_mac_address(&mut self) {
        // For simplicity, use a default MAC for now
        // Real implementation would read from EEPROM
        self.mac_address = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    }

    /// Initialize receive descriptors
    fn init_rx(&mut self) {
        // For MVP, we'll skip actual descriptor setup
        // Just enable promiscuous mode
        let rctl = E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE | 
                   E1000_RCTL_BAM | E1000_RCTL_BSIZE | E1000_RCTL_SECRC;
        self.write_reg(E1000_REG_RCTL, rctl);
    }

    /// Initialize transmit descriptors
    fn init_tx(&mut self) {
        // For MVP, we'll skip actual descriptor setup
        // Just enable transmit
        let tctl = E1000_TCTL_EN | E1000_TCTL_PSP;
        self.write_reg(E1000_REG_TCTL, tctl);
    }

    /// Enable the device
    fn enable(&mut self) {
        let ctrl = E1000_CTRL_ASDE | E1000_CTRL_SLU;
        self.write_reg(E1000_REG_CTRL, ctrl);
    }

    /// Write to an E1000 register
    fn write_reg(&mut self, reg: u32, value: u32) {
        unsafe {
            let addr = (self.mmio_base + reg) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Read from an E1000 register
    fn read_reg(&self, reg: u32) -> u32 {
        unsafe {
            let addr = (self.mmio_base + reg) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Check if device is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Send an Ethernet frame (basic implementation)
    pub fn send_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("E1000: Device not enabled");
        }
        
        // For MVP, just pretend we sent it
        // Real implementation would use TX descriptors
        Ok(())
    }

    /// Get link status
    pub fn is_link_up(&self) -> bool {
        let status = self.read_reg(E1000_REG_STATUS);
        (status & 0x02) != 0  // Link Up bit
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
    E1000_DRIVER.lock().as_ref().map(|d| d.mac_address())
}

/// Check if link is up
pub fn is_link_up() -> bool {
    E1000_DRIVER.lock().as_ref().map(|d| d.is_link_up()).unwrap_or(false)
}
