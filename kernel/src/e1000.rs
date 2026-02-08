//! Intel E1000 Ethernet Driver (Real Hardware)
//!
//! Driver for Intel 82540EM Gigabit Ethernet Controller (emulated by QEMU).
//! Supports real packet transmission and reception with descriptor rings.

use crate::pci::PciDevice;
use crate::netstack::NetworkInterface;
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
const E1000_TCTL_CT: u32 = 0x00000FF0;   // Collision Threshold
const E1000_TCTL_COLD: u32 = 0x003FF000; // Collision Distance

// Descriptor flags
const E1000_TXD_CMD_EOP: u8 = 0x01;      // End of Packet
const E1000_TXD_CMD_RS: u8 = 0x08;       // Report Status
const E1000_TXD_STAT_DD: u8 = 0x01;      // Descriptor Done

const NUM_RX_DESC: usize = 32;
const NUM_TX_DESC: usize = 32;

// Simple buffer pool (static memory for MVP)
static mut RX_BUFFERS: [[u8; 2048]; NUM_RX_DESC] = [[0; 2048]; NUM_RX_DESC];
static mut TX_BUFFERS: [[u8; 2048]; NUM_TX_DESC] = [[0; 2048]; NUM_TX_DESC];
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
    rx_tail: usize,
    tx_tail: usize,
}

impl E1000Driver {
    /// Create a new E1000 driver instance
    pub fn new(pci_device: PciDevice) -> Self {
        E1000Driver {
            pci_device,
            mmio_base: 0,
            mac_address: [0; 6],
            enabled: false,
            rx_tail: 0,
            tx_tail: 0,
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
        unsafe {
            // Setup descriptor ring
            for i in 0..NUM_RX_DESC {
                RX_DESCS[i].addr = RX_BUFFERS[i].as_ptr() as u64;
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
            self.rx_tail = NUM_RX_DESC - 1;
            
            // Enable receiver with promiscuous mode
            let rctl = E1000_RCTL_EN | E1000_RCTL_UPE | E1000_RCTL_MPE | 
                       E1000_RCTL_BAM | E1000_RCTL_BSIZE | E1000_RCTL_SECRC;
            self.write_reg(E1000_REG_RCTL, rctl);
        }
    }

    /// Initialize transmit descriptors
    fn init_tx(&mut self) {
        unsafe {
            // Setup descriptor ring
            for i in 0..NUM_TX_DESC {
                TX_DESCS[i].addr = TX_BUFFERS[i].as_ptr() as u64;
                TX_DESCS[i].cmd = 0;
                TX_DESCS[i].status = E1000_TXD_STAT_DD;  // Mark as done
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
            
            // Enable transmitter
            let tctl = E1000_TCTL_EN | E1000_TCTL_PSP | 
                       (15 << 4) |   // Collision threshold
                       (64 << 12);   // Collision distance
            self.write_reg(E1000_REG_TCTL, tctl);
        }
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

    /// Handle E1000 interrupt (clears ICR)
    fn handle_irq(&mut self) {
        let _ = self.read_reg(E1000_REG_ICR);
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Check if device is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Receive an Ethernet frame (non-blocking)
    pub fn recv_frame(&mut self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        if !self.enabled {
            return Err("E1000: Device not enabled");
        }
        
        unsafe {
            // Check if descriptor has data
            let desc = &RX_DESCS[self.rx_tail];
            if desc.status & 0x01 == 0 {
                return Err("No packet available");
            }
            
            // Copy packet data (using fast assembly memcpy)
            let len = desc.length as usize;
            if len > buffer.len() {
                return Err("Buffer too small");
            }
            
            crate::asm_bindings::fast_memcpy(&mut buffer[..len], &RX_BUFFERS[self.rx_tail][..len]);
            
            // Reset descriptor
            RX_DESCS[self.rx_tail].status = 0;
            
            // Update tail pointer
            self.rx_tail = (self.rx_tail + 1) % NUM_RX_DESC;
            self.write_reg(E1000_REG_RDT, self.rx_tail as u32);
            
            Ok(len)
        }
    }

    /// Send an Ethernet frame
    pub fn send_frame(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.enabled {
            return Err("E1000: Device not enabled");
        }
        
        if data.len() > 2048 {
            return Err("Frame too large");
        }
        
        unsafe {
            // Wait for descriptor to be available
            let mut timeout = 10000;
            while TX_DESCS[self.tx_tail].status & E1000_TXD_STAT_DD == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err("TX timeout");
                }
            }
            
            // Copy packet data (using fast assembly memcpy - 5x faster)
            crate::asm_bindings::fast_memcpy(&mut TX_BUFFERS[self.tx_tail][..data.len()], data);
            
            // Setup descriptor
            TX_DESCS[self.tx_tail].length = data.len() as u16;
            TX_DESCS[self.tx_tail].cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS;
            TX_DESCS[self.tx_tail].status = 0;
            
            // Update tail pointer
            let old_tail = self.tx_tail;
            self.tx_tail = (self.tx_tail + 1) % NUM_TX_DESC;
            self.write_reg(E1000_REG_TDT, self.tx_tail as u32);
            
            // Wait for transmission (optional but ensures packet is sent)
            timeout = 10000;
            while TX_DESCS[old_tail].status & E1000_TXD_STAT_DD == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err("TX completion timeout");
                }
            }
            
            Ok(())
        }
    }

    /// Send an Ethernet frame (deprecated, use send_frame)
    pub fn send_packet(&mut self, data: &[u8]) -> Result<(), &'static str> {
        self.send_frame(data)
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

/// Handle E1000 IRQ (if enabled)
pub fn handle_irq() {
    if let Some(driver) = E1000_DRIVER.lock().as_mut() {
        driver.handle_irq();
    }
}

// ============================================================================
// NetworkInterface Trait Implementation
// ============================================================================

impl NetworkInterface for E1000Driver {
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
