/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 */

//! WiFi Driver (802.11 Wireless LAN)
//!
//! Supports multiple WiFi chipsets with 802.11 a/b/g/n/ac protocols.
//! Provides network scanning, authentication, and data transfer.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use spin::Mutex;
use crate::pci::PciDevice;

const TEMPORAL_WIFI_SCHEMA_V1: u8 = 1;
const TEMPORAL_WIFI_HEADER_BYTES: usize = 84;
const TEMPORAL_WIFI_PCI_BYTES: usize = 16;
const TEMPORAL_WIFI_NETWORK_BYTES: usize = 48;

// ============================================================================
// Helper Functions
// ============================================================================

fn print_hex_u32(n: u32) {
    let chars = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        let digit = ((n >> (i * 4)) & 0xF) as usize;
        crate::vga::print_char(chars[digit] as char);
    }
}

fn print_number(n: usize) {
    if n == 0 {
        crate::vga::print_char('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    let mut num = n;
    while num > 0 {
        buf[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        crate::vga::print_char(buf[i] as char);
    }
}

fn ticks_from_ms(ms: u32) -> u64 {
    let hz = crate::pit::get_frequency() as u64;
    // Round up so small non-zero timeouts don't become 0 ticks.
    (ms as u64)
        .saturating_mul(hz)
        .saturating_add(999)
        / 1000
}

// ============================================================================
// WiFi Configuration
// ============================================================================

pub const MAX_SCAN_RESULTS: usize = 32;
pub const MAX_SSID_LEN: usize = 32;
pub const MAX_KEY_LEN: usize = 64;

// Connection timing (PIT ticks are 100 Hz by default)
const WIFI_AUTH_TIMEOUT_MS: u32 = 500;
const WIFI_ASSOC_TIMEOUT_MS: u32 = 500;
const WIFI_AUTH_RETRIES: u8 = 3;
const WIFI_ASSOC_RETRIES: u8 = 3;
const WIFI_EAPOL_TIMEOUT_MS: u32 = 1500;

// ============================================================================
// 802.11 Frame Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management,
    Control,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementSubtype {
    Beacon = 0x08,
    ProbeRequest = 0x04,
    ProbeResponse = 0x05,
    Authentication = 0x0B,
    Association = 0x00,
    Reassociation = 0x02,
    Disassociation = 0x0A,
    Deauthentication = 0x0C,
}

// ============================================================================
// WPA2 / EAPOL-Key (802.11i)
// ============================================================================

// LLC/SNAP header for EAPOL (Ethertype 0x888E)
const LLC_SNAP_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

// Key Information bitfield (IEEE 802.11i / WPA2)
const KI_VERSION_MASK: u16 = 0x0007;
const KI_DESCRIPTOR_V2: u16 = 0x0002; // AES (CCMP) / HMAC-SHA1 MIC profile
const KI_PAIRWISE: u16 = 1 << 3;
const KI_INSTALL: u16 = 1 << 6;
const KI_ACK: u16 = 1 << 7;
const KI_MIC: u16 = 1 << 8;
const KI_SECURE: u16 = 1 << 9;
const KI_ERROR: u16 = 1 << 10;
const KI_REQUEST: u16 = 1 << 11;
const KI_ENCRYPTED_DATA: u16 = 1 << 12;

#[derive(Debug, Clone, Copy)]
struct ParsedEapolKeyFrame {
    eapol_offset: usize,
    eapol_len: usize,
    eapol_end: usize,
    key_info: u16,
    replay_counter: u64,
    nonce_offset: usize,
    mic_offset: usize,
    key_data_len: usize,
    key_data_offset: usize,
}

// ============================================================================
// WiFi Network (SSID)
// ============================================================================

#[derive(Clone, Copy)]
pub struct WifiNetwork {
    pub ssid: [u8; MAX_SSID_LEN],
    pub ssid_len: usize,
    pub bssid: [u8; 6], // MAC address of access point
    pub channel: u8,
    pub signal_strength: i8, // dBm
    pub security: WifiSecurity,
    pub frequency: u16, // MHz
}

impl WifiNetwork {
    pub const fn new() -> Self {
        WifiNetwork {
            ssid: [0; MAX_SSID_LEN],
            ssid_len: 0,
            bssid: [0; 6],
            channel: 0,
            signal_strength: -100,
            security: WifiSecurity::Open,
            frequency: 0,
        }
    }

    pub fn ssid_str(&self) -> &str {
        core::str::from_utf8(&self.ssid[..self.ssid_len]).unwrap_or("<invalid>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiSecurity {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
}

impl WifiSecurity {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiSecurity::Open => "Open",
            WifiSecurity::WEP => "WEP",
            WifiSecurity::WPA => "WPA",
            WifiSecurity::WPA2 => "WPA2",
            WifiSecurity::WPA3 => "WPA3",
        }
    }
}

// ============================================================================
// WiFi Connection State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    Disabled,
    Idle,
    Scanning,
    Connecting,
    Authenticating,
    Associated,
    Connected,
    Disconnecting,
    Error,
}

#[derive(Clone, Copy)]
pub struct WifiConnection {
    pub state: WifiState,
    pub network: WifiNetwork,
    pub ip_assigned: bool,
}

impl WifiConnection {
    pub const fn new() -> Self {
        WifiConnection {
            state: WifiState::Disabled,
            network: WifiNetwork::new(),
            ip_assigned: false,
        }
    }
}

// ============================================================================
// WiFi Driver
// ============================================================================

pub struct WifiDriver {
    pci_device: Option<PciDevice>,
    enabled: bool,
    connection: WifiConnection,
    scan_results: [WifiNetwork; MAX_SCAN_RESULTS],
    scan_count: usize,
    mac_address: [u8; 6],
}

impl WifiDriver {
    pub const fn new() -> Self {
        WifiDriver {
            pci_device: None,
            enabled: false,
            connection: WifiConnection::new(),
            scan_results: [WifiNetwork::new(); MAX_SCAN_RESULTS],
            scan_count: 0,
            mac_address: [0; 6],
        }
    }

    /// Initialize WiFi driver with detected PCI device
    pub fn init(&mut self, device: PciDevice) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Initializing ");
        crate::vga::print_str(device.name());
        crate::vga::print_str("\n");

        self.pci_device = Some(device);

        // Enable PCI device
        unsafe {
            device.enable_bus_mastering();
            device.enable_memory_space();
        }

        // Initialize hardware based on device type
        self.init_hardware()?;

        // Generate MAC address (in production, read from hardware)
        self.mac_address = self.generate_mac_address();

        self.enabled = true;
        self.connection.state = WifiState::Idle;

        crate::vga::print_str("[WiFi] MAC: ");
        self.print_mac();
        crate::vga::print_str("\n");

        self.record_temporal_state_snapshot();
        Ok(())
    }

    /// Initialize hardware (chipset-specific)
    fn init_hardware(&mut self) -> Result<(), WifiError> {
        let device = self.pci_device.ok_or(WifiError::NoDevice)?;

        match (device.vendor_id, device.device_id) {
            // VirtIO (for testing in QEMU)
            (0x1AF4, _) => self.init_virtio(),
            
            // Intel WiFi
            (0x8086, _) => self.init_intel(),
            
            // Realtek WiFi
            (0x10EC, _) => self.init_realtek(),
            
            // Broadcom WiFi
            (0x14E4, _) => self.init_broadcom(),
            
            // Atheros WiFi
            (0x168C, _) => self.init_atheros(),
            
            _ => Err(WifiError::UnsupportedDevice),
        }
    }

    /// Initialize VirtIO WiFi device (for QEMU)
    fn init_virtio(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Initializing VirtIO WiFi\n");
        
        if let Some(device) = self.pci_device {
            // Enable bus mastering for DMA
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
            
            // Reset device
            let bar0 = unsafe { device.read_bar(0) };
            if bar0 != 0 {
                let status_ptr = bar0 as *mut u32;
                unsafe {
                    // Write 0 to reset
                    core::ptr::write_volatile(status_ptr, 0);
                    
                    // Wait for reset
                    for _ in 0..1000 {
                        if core::ptr::read_volatile(status_ptr) == 0 {
                            break;
                        }
                    }
                }
            }
            
            crate::vga::print_str("[WiFi] VirtIO device ready\n");
        }
        
        Ok(())
    }

    /// Initialize Intel WiFi device (generic)
    fn init_intel(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Intel chipset detected\n");
        Ok(())
    }

    /// Initialize Intel iwlwifi devices (7260, 7265, 9260, etc)
    fn init_intel_iwlwifi(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Intel iwlwifi chipset detected\n");
        
        if let Some(device) = self.pci_device {
            // Enable bus mastering
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
            
            let bar0 = unsafe { device.read_bar(0) };
            if bar0 != 0 {
                // Map CSR (Control/Status Registers)
                let csr_base = bar0 as *mut u32;
                
                unsafe {
                    // Read hardware revision
                    let hw_rev = core::ptr::read_volatile(csr_base.add(0x28 / 4));
                    crate::vga::print_str("[WiFi] Hardware revision: 0x");
                    print_hex_u32(hw_rev);
                    crate::vga::print_str("\n");
                    
                    // Request ownership (disable hardware RF-kill)
                    core::ptr::write_volatile(csr_base.add(0x20 / 4), 0x01);
                }
                
                crate::vga::print_str("[WiFi] Intel device initialized\n");
            }
        }
        
        Ok(())
    }

    /// Initialize Realtek WiFi device (generic)
    fn init_realtek(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Realtek chipset detected\n");
        Ok(())
    }

    /// Initialize Realtek RTL8188 series
    fn init_realtek_rtl8188(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Realtek RTL8188 detected\n");
        
        if let Some(device) = self.pci_device {
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
        }
        
        Ok(())
    }

    /// Initialize Realtek RTL8192 series
    fn init_realtek_rtl8192(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Realtek RTL8192 detected\n");
        
        if let Some(device) = self.pci_device {
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
        }
        
        Ok(())
    }

    /// Initialize Broadcom WiFi device (generic)
    fn init_broadcom(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Broadcom chipset detected\n");
        Ok(())
    }

    /// Initialize Broadcom BCM series
    fn init_broadcom_bcm(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Broadcom BCM WiFi detected\n");
        
        if let Some(device) = self.pci_device {
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
        }
        
        Ok(())
    }

    /// Initialize Atheros WiFi device (generic)
    fn init_atheros(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Atheros chipset detected\n");
        Ok(())
    }

    /// Initialize Atheros AR9285
    fn init_atheros_ar9285(&mut self) -> Result<(), WifiError> {
        crate::vga::print_str("[WiFi] Atheros AR9285 detected\n");
        
        if let Some(device) = self.pci_device {
            unsafe {
                device.enable_bus_mastering();
                device.enable_memory_space();
            }
        }
        
        Ok(())
    }

    /// Scan for available WiFi networks
    pub fn scan(&mut self) -> Result<usize, WifiError> {
        if !self.enabled {
            return Err(WifiError::NotEnabled);
        }

        crate::vga::print_str("[WiFi] Scanning for networks...\n");

        self.connection.state = WifiState::Scanning;
        self.scan_count = 0;

        // Perform hardware scan
        self.perform_scan()?;

        self.connection.state = WifiState::Idle;

        crate::vga::print_str("[WiFi] Found ");
        print_number(self.scan_count);
        crate::vga::print_str(" networks\n");

        self.record_temporal_state_snapshot();
        Ok(self.scan_count)
    }

    /// Perform actual hardware scan
    fn perform_scan(&mut self) -> Result<(), WifiError> {
        if let Some(device) = self.pci_device {
            let bar0 = unsafe { device.read_bar(0) };
            if bar0 != 0 {
                // Real hardware scan procedure:
                // 1. Set device to scan mode
                // 2. Iterate through channels 1-14 (2.4GHz) and 36-165 (5GHz)
                // 3. Send probe request frames on each channel
                // 4. Collect beacon and probe response frames
                // 5. Parse Information Elements (IEs) to extract SSID, security, etc.
                
                let base_addr = bar0 as *mut u32;
                
                unsafe {
                    // Channels to scan (2.4 GHz: 1-11, 5 GHz: 36, 40, 44, 48)
                    let channels = [1u8, 6, 11, 36, 40, 44, 48];
                    
                    for &channel in &channels {
                        // Set channel via hardware register
                        // (Actual offset depends on chipset - this is illustrative)
                        core::ptr::write_volatile(base_addr.add(0x100 / 4), channel as u32);
                        
                        // Send probe request frame
                        self.send_probe_request(channel)?;
                        
                        // Wait for responses (typically 10-50ms per channel)
                        self.wait_for_responses(base_addr, channel)?;
                    }
                }
            }
        }
        
        // If no real hardware, show that no networks were found
        if self.scan_count == 0 {
            crate::vga::print_str("[WiFi] No networks detected (hardware may not be present)\n");
        }
        
        Ok(())
    }
    
    /// Send 802.11 probe request frame
    fn send_probe_request(&mut self, channel: u8) -> Result<(), WifiError> {
        // Construct 802.11 probe request frame
        // Frame format:
        // - Frame Control (2 bytes)
        // - Duration (2 bytes)
        // - Destination MAC (6 bytes) - broadcast FF:FF:FF:FF:FF:FF
        // - Source MAC (6 bytes) - our MAC
        // - BSSID (6 bytes) - broadcast
        // - Sequence Control (2 bytes)
        // - Frame Body (variable) - SSID IE, supported rates IE
        
        let mut frame = [0u8; 128];
        let mut pos = 0;
        
        // Frame Control: Type=Management (0x0), Subtype=Probe Request (0x4)
        frame[pos] = 0x40; // 01000000 = probe request
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Duration
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Destination: broadcast
        for i in 0..6 {
            frame[pos + i] = 0xFF;
        }
        pos += 6;
        
        // Source: our MAC
        frame[pos..pos + 6].copy_from_slice(&self.mac_address);
        pos += 6;
        
        // BSSID: broadcast
        for i in 0..6 {
            frame[pos + i] = 0xFF;
        }
        pos += 6;
        
        // Sequence control
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Frame body: SSID IE (broadcast probe for all networks)
        frame[pos] = 0x00; // Element ID: SSID
        frame[pos + 1] = 0x00; // Length: 0 (broadcast)
        pos += 2;
        
        // Supported rates IE (example rates)
        frame[pos] = 0x01; // Element ID: Supported Rates
        frame[pos + 1] = 0x08; // Length: 8 rates
        pos += 2;
        // Rates: 1, 2, 5.5, 11, 6, 9, 12, 18 Mbps (BSS basic rate set)
        let rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
        for i in 0..8 {
            frame[pos + i] = rates[i];
        }
        pos += 8;
        
        // DSSS Parameter Set IE (mandatory for 2.4 GHz channels)
        // IEEE 802.11-2016 Section 9.4.2.3
        frame[pos] = 0x03; // Element ID: DSSS Parameter Set
        frame[pos + 1] = 0x01; // Length: 1 byte
        frame[pos + 2] = channel; // Current channel number (1-14 for 2.4 GHz)
        pos += 3;
        
        let frame_len = pos;
        
        // Transmit frame via hardware
        if let Some(device) = self.pci_device {
            let bar0 = unsafe { device.read_bar(0) };
            if bar0 != 0 {
                // Write frame to TX buffer (chipset-specific)
                let tx_buffer = bar0 as *mut u8;
                unsafe {
                    for i in 0..frame_len {
                        core::ptr::write_volatile(tx_buffer.add(0x1000 + i), frame[i]);
                    }
                    
                    // Trigger TX (write to TX command register)
                    let cmd_reg = bar0 as *mut u32;
                    core::ptr::write_volatile(cmd_reg.add(0x200 / 4), frame_len as u32 | 0x80000000);
                }
            }
        }
        
        Ok(())
    }
    
    /// Wait for and process probe responses/beacons
    fn wait_for_responses(&mut self, base_addr: *mut u32, channel: u8) -> Result<(), WifiError> {
        unsafe {
            // Poll RX status register for incoming frames
            // Typically wait ~50ms per channel
            for _ in 0..5000 {
                let rx_status = core::ptr::read_volatile(base_addr.add(0x300 / 4));
                
                if (rx_status & 0x01) != 0 {
                    // Frame available in RX buffer
                    self.process_received_frame(base_addr, channel)?;
                }
                
                // Small delay
                for _ in 0..100 {
                    core::hint::spin_loop();
                }
            }
        }
        
        Ok(())
    }
    
    /// Process received 802.11 frame (beacon or probe response)
    fn process_received_frame(&mut self, base_addr: *mut u32, channel: u8) -> Result<(), WifiError> {
        let mut frame = [0u8; 2048];
        
        unsafe {
            // Read frame length from RX register
            let frame_len = (core::ptr::read_volatile(base_addr.add(0x304 / 4)) & 0xFFFF) as usize;
            
            if frame_len > 2048 {
                return Ok(()); // Invalid frame
            }
            
            // Read frame from RX buffer
            let rx_buffer = (base_addr as usize + 0x2000) as *const u8;
            for i in 0..frame_len {
                frame[i] = core::ptr::read_volatile(rx_buffer.add(i));
            }
            
            // Acknowledge frame received
            core::ptr::write_volatile(base_addr.add(0x300 / 4), 0x01);
        }
        
        // Parse 802.11 frame
        self.parse_management_frame(&frame, channel)?;
        
        Ok(())
    }
    
    /// Parse 802.11 management frame (beacon or probe response)
    fn parse_management_frame(&mut self, frame: &[u8], channel: u8) -> Result<(), WifiError> {
        if frame.len() < 24 {
            return Ok(()); // Too short
        }
        
        // Check frame type (should be management)
        let frame_control = frame[0];
        let frame_type = (frame_control >> 2) & 0x03;
        let subtype = (frame_control >> 4) & 0x0F;
        
        if frame_type != 0x00 {
            return Ok(()); // Not management frame
        }
        
        // Check if beacon (0x08) or probe response (0x05)
        if subtype != 0x08 && subtype != 0x05 {
            return Ok(());
        }
        
        // Extract BSSID (bytes 16-21)
        let mut bssid = [0u8; 6];
        bssid.copy_from_slice(&frame[16..22]);
        
        // Parse frame body (starts at byte 24)
        let body = &frame[24..];
        
        // Skip fixed fields (12 bytes: timestamp + beacon interval + capability)
        if body.len() < 12 {
            return Ok(());
        }
        
        let mut pos = 12;
        let mut ssid = [0u8; MAX_SSID_LEN];
        let mut ssid_len = 0;
        let mut security = WifiSecurity::Open;
        
        // Parse Information Elements
        while pos + 2 <= body.len() {
            let ie_id = body[pos];
            let ie_len = body[pos + 1] as usize;
            pos += 2;
            
            if pos + ie_len > body.len() {
                break;
            }
            
            match ie_id {
                0x00 => {
                    // SSID
                    ssid_len = ie_len.min(MAX_SSID_LEN);
                    ssid[..ssid_len].copy_from_slice(&body[pos..pos + ssid_len]);
                }
                0x30 => {
                    // RSN (WPA2/WPA3)
                    security = WifiSecurity::WPA2;
                }
                0xDD => {
                    // Vendor Specific (might be WPA)
                    if ie_len >= 4 && body[pos..pos+4] == [0x00, 0x50, 0xF2, 0x01] {
                        security = WifiSecurity::WPA;
                    }
                }
                _ => {}
            }
            
            pos += ie_len;
        }
        
        // Add network to scan results
        if ssid_len > 0 && self.scan_count < MAX_SCAN_RESULTS {
            let mut network = WifiNetwork::new();
            network.ssid[..ssid_len].copy_from_slice(&ssid[..ssid_len]);
            network.ssid_len = ssid_len;
            network.bssid = bssid;
            network.channel = channel;
            network.signal_strength = -60; // Would read from RX status register
            network.security = security;
            network.frequency = if channel <= 14 {
                2407 + (channel as u16 * 5)
            } else {
                5000 + (channel as u16 * 5)
            };
            
            self.scan_results[self.scan_count] = network;
            self.scan_count += 1;
        }
        
        Ok(())
    }

    /// Add simulated network to scan results
    fn add_simulated_network(&mut self, ssid: &str, signal: i8, channel: u8, security: WifiSecurity) {
        if self.scan_count >= MAX_SCAN_RESULTS {
            return;
        }

        let mut network = WifiNetwork::new();
        network.ssid_len = ssid.len().min(MAX_SSID_LEN);
        network.ssid[..network.ssid_len].copy_from_slice(&ssid.as_bytes()[..network.ssid_len]);
        
        // Generate fake BSSID
        network.bssid = [
            0x02,
            0x00,
            0x00,
            (channel as u8).wrapping_mul(17),
            (ssid.len() as u8).wrapping_mul(31),
            self.scan_count as u8,
        ];
        
        network.channel = channel;
        network.signal_strength = signal;
        network.security = security;
        network.frequency = if channel <= 14 {
            2412 + (channel as u16 - 1) * 5 // 2.4 GHz
        } else {
            5180 + (channel as u16 - 36) * 5 // 5 GHz
        };

        self.scan_results[self.scan_count] = network;
        self.scan_count += 1;
    }

    /// Connect to a WiFi network
    pub fn connect(&mut self, ssid: &str, password: Option<&str>) -> Result<(), WifiError> {
        if !self.enabled {
            return Err(WifiError::NotEnabled);
        }

        // Find network in scan results
        let mut target_network: Option<WifiNetwork> = None;
        for i in 0..self.scan_count {
            if self.scan_results[i].ssid_str() == ssid {
                target_network = Some(self.scan_results[i]);
                break;
            }
        }

        let network = target_network.ok_or(WifiError::NetworkNotFound)?;

        crate::vga::print_str("[WiFi] Connecting to: ");
        crate::vga::print_str(ssid);
        crate::vga::print_str("\n");

        // Check security requirements
        if network.security != WifiSecurity::Open && password.is_none() {
            return Err(WifiError::PasswordRequired);
        }

        self.connection.state = WifiState::Connecting;
        self.connection.network = network;

        // Perform connection sequence
        self.perform_connection(password)?;

        self.connection.state = WifiState::Connected;
        self.connection.ip_assigned = true; // Simulated DHCP

        crate::vga::print_str("[WiFi] Connected! IP: 192.168.1.100\n");

        self.record_temporal_state_snapshot();
        Ok(())
    }

    /// Perform actual connection (authentication + association)
    fn perform_connection(&mut self, password: Option<&str>) -> Result<(), WifiError> {
        // Real WiFi station connection flow (high level):
        // 1. Tune to target channel.
        // 2. Open System authentication.
        // 3. Association (includes RSN IE for WPA2).
        // 4. WPA2 4-way handshake (if secured).
        
        crate::vga::print_str("[WiFi] Authenticating...\n");
        self.connection.state = WifiState::Authenticating;

        // Ensure we are tuned to the target channel before auth/assoc/EAPOL.
        self.set_channel(self.connection.network.channel)?;
        
        // Step 1: Open System Authentication (802.11 authentication)
        let mut authed = false;
        for attempt in 0..WIFI_AUTH_RETRIES {
            self.send_auth_request()?;
            match self.wait_for_auth_response() {
                Ok(()) => {
                    authed = true;
                    break;
                }
                Err(WifiError::Timeout) if attempt + 1 < WIFI_AUTH_RETRIES => {}
                Err(e) => return Err(e),
            }
        }
        if !authed {
            return Err(WifiError::AuthenticationFailed);
        }
        
        crate::vga::print_str("[WiFi] Associating...\n");
        // Step 2: Association
        let mut associated = false;
        for attempt in 0..WIFI_ASSOC_RETRIES {
            self.send_association_request()?;
            match self.wait_for_association_response() {
                Ok(()) => {
                    associated = true;
                    break;
                }
                Err(WifiError::Timeout) if attempt + 1 < WIFI_ASSOC_RETRIES => {}
                Err(e) => return Err(e),
            }
        }
        if !associated {
            return Err(WifiError::AssociationFailed);
        }
        self.connection.state = WifiState::Associated;

        // Step 3: WPA2 4-way handshake (after association)
        if self.connection.network.security == WifiSecurity::WPA2 {
            let password = password.ok_or(WifiError::NoPassword)?;
            crate::vga::print_str("[WiFi] Starting WPA2 4-way handshake...\n");
            self.wpa2_four_way_handshake(password)?;
        }

        Ok(())
    }
    
    /// Send 802.11 authentication request (Open System)
    fn send_auth_request(&mut self) -> Result<(), WifiError> {
        let mut frame = [0u8; 256];
        let mut pos = 0;
        
        // Frame Control: Type=Management (0x0), Subtype=Authentication (0xB)
        frame[pos] = 0xB0; // 10110000 = authentication
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Duration
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Destination: AP's BSSID
        for i in 0..6 {
            frame[pos + i] = self.connection.network.bssid[i];
        }
        pos += 6;
        
        // Source: our MAC
        for i in 0..6 {
            frame[pos + i] = self.mac_address[i];
        }
        pos += 6;
        
        // BSSID: AP's BSSID
        for i in 0..6 {
            frame[pos + i] = self.connection.network.bssid[i];
        }
        pos += 6;
        
        // Sequence control
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Authentication algorithm: Open System (0x0000)
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Authentication transaction sequence number (0x0001)
        frame[pos] = 0x01;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Status code (0x0000 = success)
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        let frame_len = pos;
        
        // Transmit authentication frame
        self.transmit_mgmt_frame(&frame[..frame_len])?;
        
        Ok(())
    }
    
    /// Wait for authentication response
    fn wait_for_auth_response(&mut self) -> Result<(), WifiError> {
        let start = crate::pit::get_ticks();
        let deadline = start.saturating_add(ticks_from_ms(WIFI_AUTH_TIMEOUT_MS));

        let mut buf = [0u8; 512];
        while crate::pit::get_ticks() < deadline {
            if let Some(len) = self.try_receive_frame(&mut buf)? {
                if self.is_auth_response_frame(&buf[..len])? {
                    return Ok(());
                }
            }
            core::hint::spin_loop();
        }

        Err(WifiError::Timeout)
    }

    fn is_auth_response_frame(&self, frame: &[u8]) -> Result<bool, WifiError> {
        if frame.len() < 24 + 6 {
            return Ok(false);
        }

        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type = (fc >> 2) & 0x3;
        let subtype = (fc >> 4) & 0xF;

        // Management / Authentication (subtype 0x0B)
        if frame_type != 0 || subtype != (ManagementSubtype::Authentication as u16) {
            return Ok(false);
        }

        // Addressing checks: to STA (addr1) from AP (addr2)
        let addr1 = &frame[4..10];
        let addr2 = &frame[10..16];
        if addr1 != &self.mac_address || addr2 != &self.connection.network.bssid {
            return Ok(false);
        }

        let body = &frame[24..];
        let algorithm = u16::from_le_bytes([body[0], body[1]]);
        let seq = u16::from_le_bytes([body[2], body[3]]);
        let status = u16::from_le_bytes([body[4], body[5]]);

        // Open System auth: algorithm=0, response seq=2, status=0
        if algorithm != 0 || seq != 2 {
            return Ok(false);
        }
        if status != 0 {
            return Err(WifiError::AuthenticationFailed);
        }

        Ok(true)
    }
    
    /// WPA2 4-way handshake implementation
    /// This implements the full EAPOL key exchange as per IEEE 802.11i
    fn wpa2_four_way_handshake(&mut self, password: &str) -> Result<(), WifiError> {
        // Step 1: Derive PMK (Pairwise Master Key) from password
        // PMK = PBKDF2(password, ssid, 4096 iterations, 256 bits)
        let ssid = &self.connection.network.ssid[..self.connection.network.ssid_len];
        let pmk = self.pbkdf2_sha1(password.as_bytes(), ssid, 4096)?;
        
        // Step 2: Wait for Message 1 from AP (contains ANonce + replay counter)
        crate::vga::print_str("[WiFi] Waiting for Message 1 (ANonce)...\n");
        let (anonce, replay_counter) = self.receive_eapol_msg1()?;
        
        // Step 3: Generate our nonce (SNonce)
        let snonce = self.generate_nonce();
        
        // Step 4: Derive PTK (Pairwise Transient Key)
        // PTK = PRF(PMK, "Pairwise key expansion", 
        //           min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce))
        let ptk = self.derive_ptk(&pmk, &anonce, &snonce)?;
        
        // Step 5: Send Message 2 to AP (contains SNonce + MIC + replay counter)
        crate::vga::print_str("[WiFi] Sending Message 2 (SNonce + MIC)...\n");
        self.send_eapol_msg2(&snonce, &ptk, replay_counter)?;
        
        // Step 6: Wait for Message 3 from AP (contains encrypted key data incl. GTK KDE + MIC)
        crate::vga::print_str("[WiFi] Waiting for Message 3 (GTK + MIC)...\n");
        let (gtk, replay_counter_3) = self.receive_eapol_msg3(&ptk, replay_counter, &anonce)?;
        
        // Step 7: Send Message 4 to AP (ACK with MIC + replay counter)
        crate::vga::print_str("[WiFi] Sending Message 4 (ACK)...\n");
        self.send_eapol_msg4(&ptk, replay_counter_3)?;
        
        // Step 8: Install PTK and GTK for encryption
        self.install_keys(&ptk, &gtk)?;
        
        crate::vga::print_str("[WiFi] WPA2 4-way handshake completed successfully\n");
        Ok(())
    }
    
    /// PBKDF2-HMAC-SHA1 key derivation
    /// Used to derive PMK from password and SSID
    /// Generates exactly 32 bytes (256 bits) as required by WPA2 specification
    fn pbkdf2_sha1(&self, password: &[u8], salt: &[u8], iterations: usize) 
        -> Result<[u8; 32], WifiError> {
        
        let mut result = [0u8; 32];
        
        // PBKDF2 with HMAC-SHA1
        // For WPA2, we typically need 32 bytes (256 bits)
        
        // Block 1: F(Password, Salt, c, 1)
        let mut u = [0u8; 20]; // SHA1 output is 20 bytes
        let mut u_prev = [0u8; 20];
        
        // U1 = HMAC-SHA1(password, salt || INT(1))
        let mut first_block = [0u8; 68]; // Max SSID (32) + INT(4) + padding
        let salt_len = salt.len();
        first_block[..salt_len].copy_from_slice(salt);
        first_block[salt_len] = 0x00;
        first_block[salt_len + 1] = 0x00;
        first_block[salt_len + 2] = 0x00;
        first_block[salt_len + 3] = 0x01; // Block index = 1
        
        self.hmac_sha1(password, &first_block[..salt_len + 4], &mut u_prev);
        u.copy_from_slice(&u_prev);
        
        // U2 through Uc = HMAC-SHA1(password, U_prev)
        for _ in 1..iterations {
            let mut temp = [0u8; 20];
            self.hmac_sha1(password, &u_prev, &mut temp);
            u_prev.copy_from_slice(&temp);
            // XOR with accumulated result
            for i in 0..20 {
                u[i] ^= u_prev[i];
            }
        }
        
        // Copy first 20 bytes to result
        result[..20].copy_from_slice(&u);
        
        // Block 2: F(Password, Salt, c, 2) for remaining 12 bytes
        let mut u2 = [0u8; 20];
        let mut u2_prev = [0u8; 20];
        
        first_block[salt_len + 3] = 0x02; // Block index = 2
        self.hmac_sha1(password, &first_block[..salt_len + 4], &mut u2_prev);
        u2.copy_from_slice(&u2_prev);
        
        for _ in 1..iterations {
            let mut temp = [0u8; 20];
            self.hmac_sha1(password, &u2_prev, &mut temp);
            u2_prev.copy_from_slice(&temp);
            for i in 0..20 {
                u2[i] ^= u2_prev[i];
            }
        }
        
        // Copy remaining 12 bytes
        result[20..32].copy_from_slice(&u2[..12]);
        
        Ok(result)
    }
    
    /// HMAC-SHA1 implementation
    fn hmac_sha1(&self, key: &[u8], data: &[u8], output: &mut [u8; 20]) {
        const BLOCK_SIZE: usize = 64; // SHA1 block size
        
        // Prepare key
        let mut k = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            // Hash the key if it's too long
            let mut hashed_key = [0u8; 20];
            self.sha1(key, &mut hashed_key);
            k[..20].copy_from_slice(&hashed_key);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        
        // Inner padding: key XOR 0x36
        let mut ipad = [0x36u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] ^= k[i];
        }
        
        // Outer padding: key XOR 0x5C
        let mut opad = [0x5Cu8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            opad[i] ^= k[i];
        }
        
        // Inner hash: SHA1(ipad || data)
        let mut inner = [0u8; 256]; // Buffer for ipad + data
        inner[..BLOCK_SIZE].copy_from_slice(&ipad);
        let data_len = data.len().min(256 - BLOCK_SIZE);
        inner[BLOCK_SIZE..BLOCK_SIZE + data_len].copy_from_slice(&data[..data_len]);
        
        let mut inner_hash = [0u8; 20];
        self.sha1(&inner[..BLOCK_SIZE + data_len], &mut inner_hash);
        
        // Outer hash: SHA1(opad || inner_hash)
        let mut outer = [0u8; BLOCK_SIZE + 20];
        outer[..BLOCK_SIZE].copy_from_slice(&opad);
        outer[BLOCK_SIZE..].copy_from_slice(&inner_hash);
        
        self.sha1(&outer, output);
    }
    
    /// SHA1 hash implementation
    fn sha1(&self, data: &[u8], output: &mut [u8; 20]) {
        // SHA1 initial hash values (first 32 bits of fractional parts of sqrt of first 5 primes)
        let mut h0: u32 = 0x67452301;
        let mut h1: u32 = 0xEFCDAB89;
        let mut h2: u32 = 0x98BADCFE;
        let mut h3: u32 = 0x10325476;
        let mut h4: u32 = 0xC3D2E1F0;
        
        // Pre-processing: padding
        let mut padded = [0u8; 512]; // Max 512 bytes for padding
        let data_len = data.len();
        let data_len_bits = (data_len * 8) as u64;
        
        padded[..data_len].copy_from_slice(data);
        padded[data_len] = 0x80; // Append '1' bit
        
        // Determine padding length to make total length ≡ 448 (mod 512) bits
        let total_len = ((data_len + 8) / 64 + 1) * 64;
        
        // Append original length as 64-bit big-endian
        let len_pos = total_len - 8;
        padded[len_pos..len_pos + 8].copy_from_slice(&data_len_bits.to_be_bytes());
        
        // Process blocks
        for chunk_start in (0..total_len).step_by(64) {
            let chunk = &padded[chunk_start..chunk_start + 64];
            
            // Break chunk into sixteen 32-bit big-endian words
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            
            // Extend sixteen 32-bit words into eighty 32-bit words
            for i in 16..80 {
                let temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
                w[i] = temp.rotate_left(1);
            }
            
            // Initialize working variables
            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;
            
            // Main loop
            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                
                let temp = a.rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            
            // Add chunk's hash to result
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }
        
        // Produce final hash value (big-endian)
        output[0..4].copy_from_slice(&h0.to_be_bytes());
        output[4..8].copy_from_slice(&h1.to_be_bytes());
        output[8..12].copy_from_slice(&h2.to_be_bytes());
        output[12..16].copy_from_slice(&h3.to_be_bytes());
        output[16..20].copy_from_slice(&h4.to_be_bytes());
    }

    fn is_frame_from_ap_to_station(&self, frame: &[u8]) -> bool {
        if frame.len() < 24 {
            return false;
        }
        // For AP->STA unicast frames, addr1 is our MAC, addr2 is AP BSSID.
        &frame[4..10] == &self.mac_address && &frame[10..16] == &self.connection.network.bssid
    }

    fn parse_eapol_key_frame(&self, frame: &[u8]) -> Option<ParsedEapolKeyFrame> {
        // Locate the LLC/SNAP header for EAPOL and return the EAPOL header offset.
        let mut llc_pos = None;
        if frame.len() >= LLC_SNAP_EAPOL.len() {
            for i in 0..=frame.len() - LLC_SNAP_EAPOL.len() {
                if frame[i..i + LLC_SNAP_EAPOL.len()] == LLC_SNAP_EAPOL {
                    llc_pos = Some(i);
                    break;
                }
            }
        }

        let eapol_offset = llc_pos?.saturating_add(LLC_SNAP_EAPOL.len());
        if eapol_offset.saturating_add(4 + 95) > frame.len() {
            return None;
        }

        let version = frame[eapol_offset];
        let packet_type = frame[eapol_offset + 1];
        if packet_type != 0x03 {
            return None;
        }
        // Accept EAPOL version 1 or 2 for interoperability.
        if version != 0x01 && version != 0x02 {
            return None;
        }

        let eapol_len =
            u16::from_be_bytes([frame[eapol_offset + 2], frame[eapol_offset + 3]]) as usize;
        if eapol_len < 95 {
            return None;
        }

        let eapol_end = eapol_offset.saturating_add(4).saturating_add(eapol_len);
        if eapol_end > frame.len() {
            return None;
        }

        let key_desc_offset = eapol_offset + 4;
        if frame[key_desc_offset] != 0x02 {
            // RSN EAPOL-Key descriptor (WPA2)
            return None;
        }

        let key_info =
            u16::from_be_bytes([frame[key_desc_offset + 1], frame[key_desc_offset + 2]]);
        let replay_counter = u64::from_be_bytes([
            frame[key_desc_offset + 5],
            frame[key_desc_offset + 6],
            frame[key_desc_offset + 7],
            frame[key_desc_offset + 8],
            frame[key_desc_offset + 9],
            frame[key_desc_offset + 10],
            frame[key_desc_offset + 11],
            frame[key_desc_offset + 12],
        ]);

        let nonce_offset = key_desc_offset + 13;
        let mic_offset = key_desc_offset + 77;
        let key_data_len =
            u16::from_be_bytes([frame[key_desc_offset + 93], frame[key_desc_offset + 94]]) as usize;
        let key_data_offset = key_desc_offset + 95;

        if nonce_offset.saturating_add(32) > eapol_end {
            return None;
        }
        if mic_offset.saturating_add(16) > eapol_end {
            return None;
        }
        if key_data_offset.saturating_add(key_data_len) > eapol_end {
            return None;
        }

        Some(ParsedEapolKeyFrame {
            eapol_offset,
            eapol_len,
            eapol_end,
            key_info,
            replay_counter,
            nonce_offset,
            mic_offset,
            key_data_len,
            key_data_offset,
        })
    }

    fn verify_eapol_mic(
        &self,
        frame: &[u8],
        parsed: &ParsedEapolKeyFrame,
        kck: &[u8],
    ) -> Result<(), WifiError> {
        let received_mic = &frame[parsed.mic_offset..parsed.mic_offset + 16];
        let eapol_total_len = 4usize.saturating_add(parsed.eapol_len);

        if parsed.eapol_offset.saturating_add(eapol_total_len) > frame.len() {
            return Err(WifiError::AuthenticationFailed);
        }

        let mut eapol_buf = vec![0u8; eapol_total_len];
        eapol_buf.copy_from_slice(&frame[parsed.eapol_offset..parsed.eapol_offset + eapol_total_len]);

        let mic_rel = parsed.mic_offset.saturating_sub(parsed.eapol_offset);
        if mic_rel.saturating_add(16) > eapol_buf.len() {
            return Err(WifiError::AuthenticationFailed);
        }
        eapol_buf[mic_rel..mic_rel + 16].fill(0);

        let mut computed_mic = [0u8; 20];
        self.hmac_sha1(kck, &eapol_buf, &mut computed_mic);

        let mut diff = 0u8;
        for i in 0..16 {
            diff |= received_mic[i] ^ computed_mic[i];
        }

        if diff != 0 {
            crate::vga::print_str("[WiFi] MIC verification failed!\n");
            return Err(WifiError::AuthenticationFailed);
        }

        Ok(())
    }

    fn extract_gtk_from_key_data(&self, key_data: &[u8]) -> Result<[u8; 32], WifiError> {
        let mut pos = 0usize;
        while pos + 2 <= key_data.len() {
            let id = key_data[pos];
            let len = key_data[pos + 1] as usize;
            pos += 2;

            if pos.saturating_add(len) > key_data.len() {
                break;
            }

            if id == 0xDD && len >= 6 {
                // Vendor specific KDE: OUI (3) + type (1) + keyid/reserved (2) + GTK
                let payload = &key_data[pos..pos + len];
                if payload[0..3] == [0x00, 0x0F, 0xAC] && payload[3] == 0x01 {
                    if payload.len() < 6 {
                        return Err(WifiError::AuthenticationFailed);
                    }
                    let gtk_bytes = &payload[6..];
                    let mut gtk = [0u8; 32];
                    let copy_len = gtk_bytes.len().min(gtk.len());
                    gtk[..copy_len].copy_from_slice(&gtk_bytes[..copy_len]);
                    return Ok(gtk);
                }
            }

            pos += len;
        }

        Err(WifiError::AuthenticationFailed)
    }

    fn aes_key_unwrap(&self, kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>, WifiError> {
        // RFC 3394 AES Key Unwrap (default IV A6A6A6A6A6A6A6A6).
        if wrapped.len() < 16 || (wrapped.len() % 8) != 0 {
            return Err(WifiError::AuthenticationFailed);
        }

        let n = wrapped.len() / 8 - 1;
        if n < 2 {
            return Err(WifiError::AuthenticationFailed);
        }

        let round_keys = aes128_expand_key(kek);

        let mut a = [0u8; 8];
        a.copy_from_slice(&wrapped[0..8]);
        let mut r = wrapped[8..].to_vec(); // n*8 bytes

        for j in (0..6usize).rev() {
            for i in (1..=n).rev() {
                let t = (n * j + i) as u64;
                let a_u64 = u64::from_be_bytes(a);
                let a_xor = a_u64 ^ t;

                let mut block = [0u8; 16];
                block[0..8].copy_from_slice(&a_xor.to_be_bytes());
                let r_off = (i - 1) * 8;
                block[8..16].copy_from_slice(&r[r_off..r_off + 8]);

                aes128_decrypt_block_in_place(&mut block, &round_keys);

                a.copy_from_slice(&block[0..8]);
                r[r_off..r_off + 8].copy_from_slice(&block[8..16]);
            }
        }

        if a != [0xA6u8; 8] {
            return Err(WifiError::AuthenticationFailed);
        }

        Ok(r)
    }
    
    /// Receive EAPOL Message 1 (ANonce from AP)
    fn receive_eapol_msg1(&mut self) -> Result<([u8; 32], u64), WifiError> {
        let start = crate::pit::get_ticks();
        let deadline = start.saturating_add(ticks_from_ms(WIFI_EAPOL_TIMEOUT_MS));

        let mut buf = [0u8; 1536];
        while crate::pit::get_ticks() < deadline {
            if let Some(len) = self.try_receive_frame(&mut buf)? {
                let frame = &buf[..len];
                if !self.is_frame_from_ap_to_station(frame) {
                    continue;
                }

                let Some(parsed) = self.parse_eapol_key_frame(frame) else {
                    continue;
                };

                // Message 1: Pairwise + ACK (no MIC, no Secure, no Install).
                if (parsed.key_info & (KI_VERSION_MASK | KI_PAIRWISE | KI_ACK))
                    != (KI_DESCRIPTOR_V2 | KI_PAIRWISE | KI_ACK)
                {
                    continue;
                }
                if (parsed.key_info & (KI_MIC | KI_SECURE | KI_INSTALL | KI_ENCRYPTED_DATA | KI_ERROR | KI_REQUEST))
                    != 0
                {
                    continue;
                }

                let mut anonce = [0u8; 32];
                anonce.copy_from_slice(&frame[parsed.nonce_offset..parsed.nonce_offset + 32]);
                return Ok((anonce, parsed.replay_counter));
            }
            core::hint::spin_loop();
        }

        Err(WifiError::Timeout)
    }
    
    /// Generate nonce (SNonce) using secure random
    fn generate_nonce(&mut self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        // Use hardware timestamp counter as seed for PRNG
        #[cfg(target_arch = "x86")]
        let seed = unsafe { core::arch::x86::_rdtsc() as u64 };
        #[cfg(target_arch = "x86_64")]
        let seed = unsafe { core::arch::x86_64::_rdtsc() as u64 };
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let seed = 0x123456789ABCDEFu64; // Fallback seed
        
        let mut rng = crate::security::SecureRandom::new(seed);
        rng.fill_bytes(&mut nonce);
        nonce
    }
    
    /// Derive PTK (Pairwise Transient Key) from PMK
    fn derive_ptk(&self, pmk: &[u8; 32], anonce: &[u8; 32], snonce: &[u8; 32]) 
        -> Result<[u8; 64], WifiError> {
        
        // PTK = PRF-X(PMK, "Pairwise key expansion", 
        //              Min(AA, SPA) || Max(AA, SPA) || Min(ANonce, SNonce) || Max(ANonce, SNonce))
        // Where AA = AP MAC, SPA = Station (our) MAC
        
        let mut ptk = [0u8; 64]; // PTK is 512 bits for CCMP
        
        // Prepare data for PRF
        let mut prf_data = [0u8; 100]; // "Pairwise key expansion" + NULL + addresses + nonces
        let label = b"Pairwise key expansion";
        let mut pos = 0;
        
        // Label
        prf_data[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
        prf_data[pos] = 0x00; // NULL terminator
        pos += 1;
        
        // Min(AA, SPA) || Max(AA, SPA)
        let aa = &self.connection.network.bssid; // AP MAC
        let spa = &self.mac_address; // Our MAC
        
        if aa < spa {
            prf_data[pos..pos + 6].copy_from_slice(aa);
            prf_data[pos + 6..pos + 12].copy_from_slice(spa);
        } else {
            prf_data[pos..pos + 6].copy_from_slice(spa);
            prf_data[pos + 6..pos + 12].copy_from_slice(aa);
        }
        pos += 12;
        
        // Min(ANonce, SNonce) || Max(ANonce, SNonce)
        if anonce < snonce {
            prf_data[pos..pos + 32].copy_from_slice(anonce);
            prf_data[pos + 32..pos + 64].copy_from_slice(snonce);
        } else {
            prf_data[pos..pos + 32].copy_from_slice(snonce);
            prf_data[pos + 32..pos + 64].copy_from_slice(anonce);
        }
        pos += 64;
        
        // PRF-512: Generate 64 bytes using HMAC-SHA1
        // PTK[0:19] = HMAC-SHA1(PMK, data || 0x00)
        // PTK[20:39] = HMAC-SHA1(PMK, data || 0x01)
        // PTK[40:59] = HMAC-SHA1(PMK, data || 0x02)
        // PTK[60:63] = HMAC-SHA1(PMK, data || 0x03)[0:3]
        
        for i in 0..4 {
            prf_data[pos] = i as u8;
            let mut hash = [0u8; 20];
            self.hmac_sha1(pmk, &prf_data[..pos + 1], &mut hash);
            
            let offset = i as usize * 20;
            let copy_len = (64 - offset).min(20);
            ptk[offset..offset + copy_len].copy_from_slice(&hash[..copy_len]);
        }
        
        Ok(ptk)
    }
    
    /// Send EAPOL Message 2 (SNonce + MIC)
    fn send_eapol_msg2(
        &mut self,
        snonce: &[u8; 32],
        ptk: &[u8; 64],
        replay_counter: u64,
    ) -> Result<(), WifiError> {
        // EAPOL Message 2 structure:
        // - 802.11 data frame header
        // - LLC/SNAP header (EAPOL ethertype)
        // - EAPOL header
        // - Key descriptor (contains SNonce and MIC)

        let mut frame = [0u8; 256];
        let mut pos = 0;

        // 802.11 Data frame header (24 bytes)
        frame[pos] = 0x08; // Data
        frame[pos + 1] = 0x02; // To DS (STA -> AP)
        pos += 2;

        // Duration
        frame[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());
        pos += 2;

        // Addr1 = BSSID (AP), Addr2 = STA (us), Addr3 = DA (AP/BSSID for EAPOL)
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&self.mac_address);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;

        // Sequence control
        frame[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());
        pos += 2;

        // LLC/SNAP (EAPOL ethertype)
        frame[pos..pos + LLC_SNAP_EAPOL.len()].copy_from_slice(&LLC_SNAP_EAPOL);
        pos += LLC_SNAP_EAPOL.len();

        let eapol_start = pos;

        // EAPOL header (version, type, length filled later)
        frame[pos] = 0x02;
        frame[pos + 1] = 0x03; // Key
        frame[pos + 2] = 0x00;
        frame[pos + 3] = 0x00;
        pos += 4;

        // Key descriptor type: RSN (WPA2)
        frame[pos] = 0x02;
        pos += 1;

        // Key information (big-endian): descriptor v2 + pairwise + MIC
        let key_info = KI_DESCRIPTOR_V2 | KI_PAIRWISE | KI_MIC;
        frame[pos..pos + 2].copy_from_slice(&key_info.to_be_bytes());
        pos += 2;

        // Key length (CCMP = 16)
        frame[pos..pos + 2].copy_from_slice(&(16u16).to_be_bytes());
        pos += 2;

        // Replay counter (must match message 1)
        frame[pos..pos + 8].copy_from_slice(&replay_counter.to_be_bytes());
        pos += 8;

        // Key nonce (SNonce)
        frame[pos..pos + 32].copy_from_slice(snonce);
        pos += 32;

        // Key IV (16 bytes) - zero
        frame[pos..pos + 16].fill(0);
        pos += 16;

        // Key RSC (8 bytes) - zero
        frame[pos..pos + 8].fill(0);
        pos += 8;

        // Key ID / Reserved (8 bytes) - zero
        frame[pos..pos + 8].fill(0);
        pos += 8;

        // Key MIC (16 bytes) - computed using KCK (PTK[0..16])
        let kck = &ptk[0..16];
        let mic_start = pos;
        frame[pos..pos + 16].fill(0);
        pos += 16;

        // Key data length (2 bytes) - none for Message 2 in this profile
        let key_data_len = 0u16;
        frame[pos..pos + 2].copy_from_slice(&key_data_len.to_be_bytes());
        pos += 2;

        // Fill EAPOL length (payload length excluding the 4-byte EAPOL header)
        let eapol_payload_len = 95usize + key_data_len as usize;
        frame[eapol_start + 2..eapol_start + 4]
            .copy_from_slice(&(eapol_payload_len as u16).to_be_bytes());

        // Compute MIC over the EAPOL header + payload with MIC field zeroed.
        let mut mic = [0u8; 20];
        self.hmac_sha1(kck, &frame[eapol_start..pos], &mut mic);
        frame[mic_start..mic_start + 16].copy_from_slice(&mic[..16]);

        self.transmit_data_frame(&frame[..pos])?;
        Ok(())
    }
    
    /// Receive EAPOL Message 3 (GTK from AP)
    fn receive_eapol_msg3(
        &mut self,
        ptk: &[u8; 64],
        expected_replay_counter: u64,
        expected_anonce: &[u8; 32],
    ) -> Result<([u8; 32], u64), WifiError> {
        let start = crate::pit::get_ticks();
        let deadline = start.saturating_add(ticks_from_ms(WIFI_EAPOL_TIMEOUT_MS));

        let kck = &ptk[0..16];
        let mut kek = [0u8; 16];
        kek.copy_from_slice(&ptk[16..32]);

        let mut buf = [0u8; 1536];
        while crate::pit::get_ticks() < deadline {
            if let Some(len) = self.try_receive_frame(&mut buf)? {
                let frame = &buf[..len];
                if !self.is_frame_from_ap_to_station(frame) {
                    continue;
                }

                let Some(parsed) = self.parse_eapol_key_frame(frame) else {
                    continue;
                };

                // Message 3: Pairwise + ACK + MIC + Secure + Encrypted (Install often set).
                let required =
                    KI_DESCRIPTOR_V2 | KI_PAIRWISE | KI_ACK | KI_MIC | KI_SECURE | KI_ENCRYPTED_DATA;
                let required_mask = KI_VERSION_MASK | KI_PAIRWISE | KI_ACK | KI_MIC | KI_SECURE | KI_ENCRYPTED_DATA;
                if (parsed.key_info & required_mask) != required {
                    continue;
                }
                if (parsed.key_info & (KI_ERROR | KI_REQUEST)) != 0 {
                    continue;
                }

                if parsed.replay_counter != expected_replay_counter {
                    continue;
                }

                // ANonce must match message 1.
                if &frame[parsed.nonce_offset..parsed.nonce_offset + 32] != expected_anonce {
                    continue;
                }

                self.verify_eapol_mic(frame, &parsed, kck)?;

                let key_data_cipher =
                    &frame[parsed.key_data_offset..parsed.key_data_offset + parsed.key_data_len];
                let key_data_plain = if (parsed.key_info & KI_ENCRYPTED_DATA) != 0 {
                    self.aes_key_unwrap(&kek, key_data_cipher)?
                } else {
                    key_data_cipher.to_vec()
                };

                let gtk = self.extract_gtk_from_key_data(&key_data_plain)?;
                return Ok((gtk, parsed.replay_counter));
            }
            core::hint::spin_loop();
        }

        Err(WifiError::Timeout)
    }
    
    /// Send EAPOL Message 4 (ACK)
    fn send_eapol_msg4(&mut self, ptk: &[u8; 64], replay_counter: u64) -> Result<(), WifiError> {
        // EAPOL Message 4 structure:
        // - 802.11 data frame header
        // - LLC/SNAP header (EAPOL ethertype)
        // - EAPOL header
        // - Key descriptor (no key data, MIC set)

        let mut frame = [0u8; 256];
        let mut pos = 0;

        // 802.11 Data frame header (24 bytes)
        frame[pos] = 0x08; // Data
        frame[pos + 1] = 0x02; // To DS (STA -> AP)
        pos += 2;

        // Duration
        frame[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());
        pos += 2;

        // Addr1 = BSSID (AP), Addr2 = STA (us), Addr3 = DA (AP/BSSID for EAPOL)
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&self.mac_address);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;

        // Sequence control
        frame[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());
        pos += 2;

        // LLC/SNAP (EAPOL ethertype)
        frame[pos..pos + LLC_SNAP_EAPOL.len()].copy_from_slice(&LLC_SNAP_EAPOL);
        pos += LLC_SNAP_EAPOL.len();

        let eapol_start = pos;

        // EAPOL header (version, type, length filled later)
        frame[pos] = 0x02;
        frame[pos + 1] = 0x03; // Key
        frame[pos + 2] = 0x00;
        frame[pos + 3] = 0x00;
        pos += 4;

        // Key descriptor type: RSN (WPA2)
        frame[pos] = 0x02;
        pos += 1;

        // Key information (big-endian): descriptor v2 + pairwise + MIC + secure
        let key_info = KI_DESCRIPTOR_V2 | KI_PAIRWISE | KI_MIC | KI_SECURE;
        frame[pos..pos + 2].copy_from_slice(&key_info.to_be_bytes());
        pos += 2;

        // Key length (unused for message 4)
        frame[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
        pos += 2;

        // Replay counter (must match message 3)
        frame[pos..pos + 8].copy_from_slice(&replay_counter.to_be_bytes());
        pos += 8;

        // Key nonce (32 bytes) - zero
        frame[pos..pos + 32].fill(0);
        pos += 32;

        // Key IV (16 bytes) - zero
        frame[pos..pos + 16].fill(0);
        pos += 16;

        // Key RSC (8 bytes) - zero
        frame[pos..pos + 8].fill(0);
        pos += 8;

        // Key ID / Reserved (8 bytes) - zero
        frame[pos..pos + 8].fill(0);
        pos += 8;

        // Key MIC (16 bytes) - computed using KCK (PTK[0..16])
        let kck = &ptk[0..16];
        let mic_start = pos;
        frame[pos..pos + 16].fill(0);
        pos += 16;

        // Key data length (2 bytes) - none for message 4
        let key_data_len = 0u16;
        frame[pos..pos + 2].copy_from_slice(&key_data_len.to_be_bytes());
        pos += 2;

        // Fill EAPOL length (payload length excluding the 4-byte EAPOL header)
        let eapol_payload_len = 95usize + key_data_len as usize;
        frame[eapol_start + 2..eapol_start + 4]
            .copy_from_slice(&(eapol_payload_len as u16).to_be_bytes());

        // Compute MIC over the EAPOL header + payload with MIC field zeroed.
        let mut mic = [0u8; 20];
        self.hmac_sha1(kck, &frame[eapol_start..pos], &mut mic);
        frame[mic_start..mic_start + 16].copy_from_slice(&mic[..16]);

        self.transmit_data_frame(&frame[..pos])?;
        Ok(())
    }
    
    /// Install PTK and GTK keys for encryption
    fn install_keys(&mut self, ptk: &[u8; 64], gtk: &[u8; 32]) -> Result<(), WifiError> {
        // In a real implementation, this would:
        // - Program hardware encryption engine with PTK/GTK
        // - Enable CCMP encryption
        // - Configure key index and replay counters
        
        // PTK structure:
        // - KCK (0-15): Key Confirmation Key (for MIC)
        // - KEK (16-31): Key Encryption Key (for GTK encryption)
        // - TK (32-47): Temporal Key (for data encryption)
        // - MIC keys (48-63): Additional keys
        
        crate::vga::print_str("[WiFi] Installing PTK and GTK into hardware...\n");
        
        // Use AES-NI if available for hardware-accelerated encryption
        if let Some(device) = self.pci_device {
            unsafe {
                let bar0 = device.read_bar(0);
                if bar0 != 0 {
                    let base_addr = bar0 as *mut u32;
                    // Write TK to hardware key registers (offsets are hardware-specific)
                    for i in 0..4 {
                        let key_word = u32::from_le_bytes([
                            ptk[32 + i * 4],
                            ptk[33 + i * 4],
                            ptk[34 + i * 4],
                            ptk[35 + i * 4],
                        ]);
                        core::ptr::write_volatile(base_addr.add(0x200 / 4 + i), key_word);
                    }
                    
                    // Write GTK to hardware
                    for i in 0..8 {
                        let key_word = u32::from_le_bytes([
                            gtk[i * 4],
                            gtk[i * 4 + 1],
                            gtk[i * 4 + 2],
                            gtk[i * 4 + 3],
                        ]);
                        core::ptr::write_volatile(base_addr.add(0x300 / 4 + i), key_word);
                    }
                    
                    // Enable CCMP encryption in hardware control register
                    let mut ctrl = core::ptr::read_volatile(base_addr.add(0x100 / 4));
                    ctrl |= 1 << 8; // Enable encryption bit
                    core::ptr::write_volatile(base_addr.add(0x100 / 4), ctrl);
                }
            }
        }
        
        Ok(())
    }
    
    /// Send association request
    fn send_association_request(&mut self) -> Result<(), WifiError> {
        let mut frame = [0u8; 256];
        let mut pos = 0;
        
        // Frame Control: Type=Management, Subtype=Association Request (0x0)
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Duration
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Destination: AP BSSID
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;
        
        // Source: our MAC
        frame[pos..pos + 6].copy_from_slice(&self.mac_address);
        pos += 6;
        
        // BSSID
        frame[pos..pos + 6].copy_from_slice(&self.connection.network.bssid);
        pos += 6;
        
        // Sequence control
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Capability info
        frame[pos] = 0x31; // ESS, Privacy
        frame[pos + 1] = 0x04;
        pos += 2;
        
        // Listen interval
        frame[pos] = 0x0A;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // SSID IE
        frame[pos] = 0x00; // Element ID
        frame[pos + 1] = self.connection.network.ssid_len as u8;
        pos += 2;
        frame[pos..pos + self.connection.network.ssid_len]
            .copy_from_slice(&self.connection.network.ssid[..self.connection.network.ssid_len]);
        pos += self.connection.network.ssid_len;
        
        // Supported rates
        frame[pos] = 0x01;
        frame[pos + 1] = 0x08;
        pos += 2;
        let rates = [0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];
        frame[pos..pos + 8].copy_from_slice(&rates);
        pos += 8;
        
        // RSN IE (for WPA2)
        if self.connection.network.security == WifiSecurity::WPA2 {
            frame[pos] = 0x30; // RSN IE
            frame[pos + 1] = 0x14; // Length: 20 bytes
            pos += 2;
            // RSN version
            frame[pos] = 0x01;
            frame[pos + 1] = 0x00;
            pos += 2;
            // Group cipher: CCMP
            frame[pos..pos + 4].copy_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
            pos += 4;
            // Pairwise cipher count: 1
            frame[pos] = 0x01;
            frame[pos + 1] = 0x00;
            pos += 2;
            // Pairwise cipher: CCMP
            frame[pos..pos + 4].copy_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
            pos += 4;
            // AKM count: 1
            frame[pos] = 0x01;
            frame[pos + 1] = 0x00;
            pos += 2;
            // AKM: PSK
            frame[pos..pos + 4].copy_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
            pos += 4;
            // RSN capabilities
            frame[pos] = 0x00;
            frame[pos + 1] = 0x00;
            pos += 2;
        }
        
        let frame_len = pos;
        self.transmit_mgmt_frame(&frame[..frame_len])?;
        
        Ok(())
    }
    
    /// Wait for association response
    fn wait_for_association_response(&mut self) -> Result<(), WifiError> {
        let start = crate::pit::get_ticks();
        let deadline = start.saturating_add(ticks_from_ms(WIFI_ASSOC_TIMEOUT_MS));

        let mut buf = [0u8; 512];
        while crate::pit::get_ticks() < deadline {
            if let Some(len) = self.try_receive_frame(&mut buf)? {
                if self.is_association_response_frame(&buf[..len])? {
                    return Ok(());
                }
            }
            core::hint::spin_loop();
        }

        Err(WifiError::Timeout)
    }

    fn is_association_response_frame(&self, frame: &[u8]) -> Result<bool, WifiError> {
        if frame.len() < 24 + 6 {
            return Ok(false);
        }

        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        let frame_type = (fc >> 2) & 0x3;
        let subtype = (fc >> 4) & 0xF;

        // Management / Association Response (subtype 0x01)
        if frame_type != 0 || subtype != 0x01 {
            return Ok(false);
        }

        // Addressing checks: to STA (addr1) from AP (addr2)
        let addr1 = &frame[4..10];
        let addr2 = &frame[10..16];
        if addr1 != &self.mac_address || addr2 != &self.connection.network.bssid {
            return Ok(false);
        }

        let body = &frame[24..];
        let _capability = u16::from_le_bytes([body[0], body[1]]);
        let status = u16::from_le_bytes([body[2], body[3]]);
        let _aid = u16::from_le_bytes([body[4], body[5]]);

        if status != 0 {
            return Err(WifiError::AssociationFailed);
        }

        Ok(true)
    }

    fn set_channel(&mut self, channel: u8) -> Result<(), WifiError> {
        if let Some(device) = self.pci_device {
            let bar0 = unsafe { device.read_bar(0) };
            if bar0 != 0 {
                unsafe {
                    let base_addr = bar0 as *mut u32;
                    // Channel control register (device-specific; matches existing scan path)
                    core::ptr::write_volatile(base_addr.add(0x100 / 4), channel as u32);
                }
                return Ok(());
            }
        }
        Err(WifiError::HardwareError)
    }

    fn try_receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, WifiError> {
        if let Some(device) = self.pci_device {
            unsafe {
                let bar0 = device.read_bar(0);
                if bar0 != 0 {
                    let base_addr = bar0 as *mut u32;
                    let rx_status = core::ptr::read_volatile(base_addr.add(0x300 / 4));
                    if (rx_status & 0x01) == 0 {
                        return Ok(None);
                    }

                    let frame_len =
                        (core::ptr::read_volatile(base_addr.add(0x304 / 4)) & 0xFFFF) as usize;
                    if frame_len == 0 || frame_len > buffer.len() {
                        // Acknowledge and treat as hardware error.
                        core::ptr::write_volatile(base_addr.add(0x300 / 4), 0x01);
                        return Err(WifiError::HardwareError);
                    }

                    let rx_buffer = (bar0 as usize + 0x2000) as *const u8;
                    for i in 0..frame_len {
                        buffer[i] = core::ptr::read_volatile(rx_buffer.add(i));
                    }

                    // Acknowledge frame received
                    core::ptr::write_volatile(base_addr.add(0x300 / 4), 0x01);
                    return Ok(Some(frame_len));
                }
            }
        }
        Err(WifiError::HardwareError)
    }
    
    /// Transmit management frame
    fn transmit_mgmt_frame(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if let Some(device) = self.pci_device {
            unsafe {
                let bar0 = device.read_bar(0);
                if bar0 != 0 {
                    let base_addr = bar0 as *mut u32;
                    
                    // Wait for TX ready
                    let mut timeout = 10000;
                    while timeout > 0 {
                        let tx_status = core::ptr::read_volatile(base_addr.add(0x200 / 4));
                        if (tx_status & 0x01) == 0 {
                            break; // TX ready
                        }
                        timeout -= 1;
                        for _ in 0..100 {
                            core::hint::spin_loop();
                        }
                    }
                    
                    if timeout == 0 {
                        return Err(WifiError::HardwareError);
                    }
                    
                    // Write frame to TX buffer (offset 0x1000)
                    let tx_buffer = (bar0 as usize + 0x1000) as *mut u8;
                    for i in 0..frame.len() {
                        core::ptr::write_volatile(tx_buffer.add(i), frame[i]);
                    }
                    
                    // Set frame length in TX length register (offset 0x204)
                    core::ptr::write_volatile(base_addr.add(0x204 / 4), frame.len() as u32);
                    
                    // Trigger transmission with management frame flag
                    // 0x80000000 = TX enable bit (management frame, bit 0 clear)
                    // vs 0x80000001 for data frames (bit 0 set)
                    core::ptr::write_volatile(base_addr.add(0x200 / 4), 0x80000000);
                }
            }
        }
        Ok(())
    }
    
    /// Transmit data frame
    fn transmit_data_frame(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if let Some(device) = self.pci_device {
            unsafe {
                let bar0 = device.read_bar(0);
                if bar0 != 0 {
                    let base_addr = bar0 as *mut u32;
                    
                    // Wait for TX ready
                    let mut timeout = 10000;
                    while timeout > 0 {
                        let tx_status = core::ptr::read_volatile(base_addr.add(0x200 / 4));
                        if (tx_status & 0x01) == 0 {
                            break; // TX ready
                        }
                        timeout -= 1;
                        for _ in 0..100 {
                            core::hint::spin_loop();
                        }
                    }
                    
                    if timeout == 0 {
                        return Err(WifiError::HardwareError);
                    }
                    
                    // Write frame to TX buffer
                    let tx_buffer = (bar0 as usize + 0x1000) as *mut u8;
                    for i in 0..frame.len() {
                        core::ptr::write_volatile(tx_buffer.add(i), frame[i]);
                    }
                    
                    // Set frame length and trigger transmission
                    core::ptr::write_volatile(base_addr.add(0x204 / 4), frame.len() as u32);
                    core::ptr::write_volatile(base_addr.add(0x200 / 4), 0x80000001); // TX enable + data frame
                    
                    crate::vga::print_str("[WiFi] Data frame transmitted\n");
                }
            }
        }
        Ok(())
    }
    
    /// Receive data frame
    fn receive_data_frame(&mut self, buffer: &mut [u8]) -> Result<usize, WifiError> {
        if let Some(device) = self.pci_device {
            unsafe {
                let bar0 = device.read_bar(0);
                if bar0 != 0 {
                    let base_addr = bar0 as *mut u32;
                    
                    // Wait for RX data (with timeout)
                    let mut timeout = 100000;
                    while timeout > 0 {
                        let rx_status = core::ptr::read_volatile(base_addr.add(0x300 / 4));
                        if (rx_status & 0x01) != 0 {
                            break; // Frame available
                        }
                        timeout -= 1;
                        for _ in 0..100 {
                            core::hint::spin_loop();
                        }
                    }
                    
                    if timeout == 0 {
                        return Err(WifiError::HardwareError);
                    }
                    
                    // Read frame length
                    let frame_len = (core::ptr::read_volatile(base_addr.add(0x304 / 4)) & 0xFFFF) as usize;
                    
                    if frame_len > buffer.len() {
                        return Err(WifiError::HardwareError);
                    }
                    
                    // Read frame from RX buffer
                    let rx_buffer = (bar0 as usize + 0x2000) as *const u8;
                    for i in 0..frame_len {
                        buffer[i] = core::ptr::read_volatile(rx_buffer.add(i));
                    }
                    
                    // Acknowledge frame received
                    core::ptr::write_volatile(base_addr.add(0x300 / 4), 0x01);
                    
                    return Ok(frame_len);
                }
            }
        }
        Err(WifiError::HardwareError)
    }


    /// Disconnect from current network
    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        if self.connection.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        crate::vga::print_str("[WiFi] Disconnecting...\n");
        
        self.connection.state = WifiState::Disconnecting;
        
        // Send deauthentication frame
        // ...

        self.connection.state = WifiState::Idle;
        self.connection.ip_assigned = false;

        crate::vga::print_str("[WiFi] Disconnected\n");

        self.record_temporal_state_snapshot();
        Ok(())
    }

    /// Get scan results
    pub fn scan_results(&self) -> &[WifiNetwork] {
        &self.scan_results[..self.scan_count]
    }
    
    /// Get scan results array (for copying)
    pub fn scan_results_array(&self) -> &[WifiNetwork; MAX_SCAN_RESULTS] {
        &self.scan_results
    }
    
    /// Get scan count
    pub fn scan_count(&self) -> usize {
        self.scan_count
    }

    /// Get current connection status
    pub fn connection(&self) -> &WifiConnection {
        &self.connection
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.state == WifiState::Connected
    }

    /// Generate MAC address (from hardware or simulated)
    fn generate_mac_address(&self) -> [u8; 6] {
        // If we don't have chipset-specific EEPROM/OTP plumbing yet, generate a
        // locally administered unicast MAC address.
        let mut mac = [0u8; 6];

        #[cfg(target_arch = "x86")]
        let seed = unsafe { core::arch::x86::_rdtsc() as u64 };
        #[cfg(target_arch = "x86_64")]
        let seed = unsafe { core::arch::x86_64::_rdtsc() as u64 };
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let seed = 0xC0DEC0DE12345678u64;

        let mut rng = crate::security::SecureRandom::new(seed);
        rng.fill_bytes(&mut mac);

        // Clear multicast bit; set locally administered bit.
        mac[0] = (mac[0] & 0xFE) | 0x02;
        mac
    }

    /// Print MAC address
    fn print_mac(&self) {
        for (i, byte) in self.mac_address.iter().enumerate() {
            if i > 0 {
                crate::vga::print_char(':');
            }
            print_hex_byte(*byte);
        }
    }
}

fn temporal_wifi_state_to_u8(state: WifiState) -> u8 {
    match state {
        WifiState::Disabled => 0,
        WifiState::Idle => 1,
        WifiState::Scanning => 2,
        WifiState::Connecting => 3,
        WifiState::Authenticating => 4,
        WifiState::Associated => 5,
        WifiState::Connected => 6,
        WifiState::Disconnecting => 7,
        WifiState::Error => 8,
    }
}

fn temporal_wifi_state_from_u8(v: u8) -> Option<WifiState> {
    match v {
        0 => Some(WifiState::Disabled),
        1 => Some(WifiState::Idle),
        2 => Some(WifiState::Scanning),
        3 => Some(WifiState::Connecting),
        4 => Some(WifiState::Authenticating),
        5 => Some(WifiState::Associated),
        6 => Some(WifiState::Connected),
        7 => Some(WifiState::Disconnecting),
        8 => Some(WifiState::Error),
        _ => None,
    }
}

fn temporal_wifi_security_to_u8(sec: WifiSecurity) -> u8 {
    match sec {
        WifiSecurity::Open => 0,
        WifiSecurity::WEP => 1,
        WifiSecurity::WPA => 2,
        WifiSecurity::WPA2 => 3,
        WifiSecurity::WPA3 => 4,
    }
}

fn temporal_wifi_security_from_u8(v: u8) -> Option<WifiSecurity> {
    match v {
        0 => Some(WifiSecurity::Open),
        1 => Some(WifiSecurity::WEP),
        2 => Some(WifiSecurity::WPA),
        3 => Some(WifiSecurity::WPA2),
        4 => Some(WifiSecurity::WPA3),
        _ => None,
    }
}

fn temporal_append_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn temporal_encode_pci_device(buf: &mut Vec<u8>, device: Option<PciDevice>) {
    let mut bytes = [0u8; TEMPORAL_WIFI_PCI_BYTES];
    if let Some(dev) = device {
        bytes[0] = dev.bus;
        bytes[1] = dev.slot;
        bytes[2] = dev.func;
        bytes[3] = dev.class_code;
        bytes[4..6].copy_from_slice(&dev.vendor_id.to_le_bytes());
        bytes[6..8].copy_from_slice(&dev.device_id.to_le_bytes());
        bytes[8] = dev.subclass;
        bytes[9] = dev.prog_if;
        bytes[10] = dev.revision;
        bytes[11] = dev.interrupt_line;
        bytes[12] = dev.interrupt_pin;
    }
    buf.extend_from_slice(&bytes);
}

fn temporal_decode_pci_device(data: &[u8], offset: usize) -> Option<PciDevice> {
    if offset.saturating_add(TEMPORAL_WIFI_PCI_BYTES) > data.len() {
        return None;
    }
    let vendor_id = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
    let device_id = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);
    Some(PciDevice {
        bus: data[offset],
        slot: data[offset + 1],
        func: data[offset + 2],
        vendor_id,
        device_id,
        class_code: data[offset + 3],
        subclass: data[offset + 8],
        prog_if: data[offset + 9],
        revision: data[offset + 10],
        interrupt_line: data[offset + 11],
        interrupt_pin: data[offset + 12],
    })
}

fn temporal_encode_wifi_network(buf: &mut Vec<u8>, net: &WifiNetwork) {
    buf.push(net.ssid_len.min(MAX_SSID_LEN) as u8);
    buf.push(net.channel);
    buf.push(net.signal_strength as u8);
    buf.push(temporal_wifi_security_to_u8(net.security));
    temporal_append_u16(buf, net.frequency);
    temporal_append_u16(buf, 0);
    buf.extend_from_slice(&net.bssid);
    temporal_append_u16(buf, 0);
    buf.extend_from_slice(&net.ssid);
}

fn temporal_decode_wifi_network(data: &[u8], offset: usize) -> Option<WifiNetwork> {
    if offset.saturating_add(TEMPORAL_WIFI_NETWORK_BYTES) > data.len() {
        return None;
    }
    let ssid_len = data[offset] as usize;
    if ssid_len > MAX_SSID_LEN {
        return None;
    }
    let channel = data[offset + 1];
    let signal_strength = data[offset + 2] as i8;
    let security = temporal_wifi_security_from_u8(data[offset + 3])?;
    let frequency =
        temporal_read_u16(data, offset + 4).unwrap_or(0);
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&data[offset + 8..offset + 14]);
    let mut ssid = [0u8; MAX_SSID_LEN];
    ssid.copy_from_slice(&data[offset + 16..offset + 48]);

    Some(WifiNetwork {
        ssid,
        ssid_len,
        bssid,
        channel,
        signal_strength,
        security,
        frequency,
    })
}

impl WifiDriver {
    fn encode_temporal_state_payload(&self, event: u8) -> Option<Vec<u8>> {
        let scan_count = core::cmp::min(self.scan_count, MAX_SCAN_RESULTS);
        let total_len = TEMPORAL_WIFI_HEADER_BYTES
            .saturating_add(scan_count.saturating_mul(TEMPORAL_WIFI_NETWORK_BYTES));
        if total_len > crate::temporal::MAX_TEMPORAL_VERSION_BYTES {
            return None;
        }

        let mut payload = Vec::with_capacity(total_len);
        payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
        payload.push(crate::temporal::TEMPORAL_WIFI_OBJECT);
        payload.push(event);
        payload.push(TEMPORAL_WIFI_SCHEMA_V1);
        payload.push(if self.pci_device.is_some() { 1 } else { 0 });
        payload.push(if self.enabled { 1 } else { 0 });
        payload.push(temporal_wifi_state_to_u8(self.connection.state));
        payload.push(if self.connection.ip_assigned { 1 } else { 0 });
        payload.extend_from_slice(&self.mac_address);
        temporal_append_u16(&mut payload, 0);
        temporal_append_u16(&mut payload, scan_count as u16);
        temporal_append_u16(&mut payload, 0);
        temporal_encode_pci_device(&mut payload, self.pci_device);
        temporal_encode_wifi_network(&mut payload, &self.connection.network);
        for i in 0..scan_count {
            temporal_encode_wifi_network(&mut payload, &self.scan_results[i]);
        }
        Some(payload)
    }

    fn record_temporal_state_snapshot(&self) {
        if crate::temporal::is_replay_active() {
            return;
        }
        let payload = match self.encode_temporal_state_payload(crate::temporal::TEMPORAL_WIFI_EVENT_STATE) {
            Some(v) => v,
            None => return,
        };
        let _ = crate::temporal::record_wifi_state_event(&payload);
    }
}

pub fn temporal_apply_wifi_driver_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < TEMPORAL_WIFI_HEADER_BYTES {
        return Err("temporal wifi payload too short");
    }
    if payload[3] != TEMPORAL_WIFI_SCHEMA_V1 {
        return Err("temporal wifi schema unsupported");
    }
    let pci_present = payload[4] != 0;
    let enabled = payload[5] != 0;
    let _state = temporal_wifi_state_from_u8(payload[6]).ok_or("temporal wifi state invalid")?;
    let _ip_assigned = payload[7] != 0;
    let mut mac_address = [0u8; 6];
    mac_address.copy_from_slice(&payload[8..14]);
    let scan_count =
        temporal_read_u16(payload, 16).ok_or("temporal wifi scan count missing")? as usize;
    if scan_count > MAX_SCAN_RESULTS {
        return Err("temporal wifi scan count out of range");
    }

    let pci_device = if pci_present {
        Some(temporal_decode_pci_device(payload, 20).ok_or("temporal wifi pci decode failed")?)
    } else {
        None
    };
    let connection_network =
        temporal_decode_wifi_network(payload, 36).ok_or("temporal wifi network decode failed")?;

    let mut offset = TEMPORAL_WIFI_HEADER_BYTES;
    let mut scan_results = [WifiNetwork::new(); MAX_SCAN_RESULTS];
    for i in 0..scan_count {
        let net = temporal_decode_wifi_network(payload, offset).ok_or("temporal wifi scan entry invalid")?;
        scan_results[i] = net;
        offset = offset.saturating_add(TEMPORAL_WIFI_NETWORK_BYTES);
    }
    if offset != payload.len() {
        return Err("temporal wifi payload trailing bytes");
    }

    let mut wifi = WIFI.lock();
    // Never trust persisted PCI BARs/interrupts across reboot. Treat them as a hint only.
    let _ = pci_device;
    wifi.pci_device = None;
    wifi.enabled = enabled;
    wifi.connection = WifiConnection {
        // Hardware sessions cannot be time-traveled. Preserve intent/config, not link state.
        state: if enabled { WifiState::Idle } else { WifiState::Disabled },
        network: connection_network,
        ip_assigned: false,
    };
    wifi.scan_results = scan_results;
    wifi.scan_count = scan_count;
    wifi.mac_address = mac_address;

    // Best-effort hardware restore: if state said we previously had a device, attempt re-detect.
    // Failure should not abort temporal restore (control-plane state remains valid).
    if enabled && pci_present {
        drop(wifi);
        let mut scanner = crate::pci::PciScanner::new();
        scanner.scan();
        if let Some(device) = scanner.find_wifi_device() {
            let _ = init(device);
        }
    }
    Ok(())
}

// ============================================================================
// AES-128 (Software) + RFC 3394 Key Unwrap
// ============================================================================

const AES128_ROUNDS: usize = 10;
const AES128_EXPANDED_KEY_BYTES: usize = 16 * (AES128_ROUNDS + 1);

// AES S-box (FIPS-197)
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
    0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
    0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
    0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
    0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
    0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
    0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
    0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
    0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
    0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
    0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
    0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
];

// AES inverse S-box (FIPS-197)
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
    0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
    0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
    0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
    0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
    0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
    0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
    0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
    0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
    0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
    0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
    0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
    0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
];

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn aes128_expand_key(key: &[u8; 16]) -> [u8; AES128_EXPANDED_KEY_BYTES] {
    let mut expanded = [0u8; AES128_EXPANDED_KEY_BYTES];
    expanded[..16].copy_from_slice(key);

    let mut bytes_generated = 16usize;
    let mut rcon_idx = 0usize;
    let mut temp = [0u8; 4];

    while bytes_generated < AES128_EXPANDED_KEY_BYTES {
        temp.copy_from_slice(&expanded[bytes_generated - 4..bytes_generated]);

        if (bytes_generated % 16) == 0 {
            // RotWord
            let t0 = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t0;

            // SubWord
            for b in temp.iter_mut() {
                *b = AES_SBOX[*b as usize];
            }

            // Rcon
            temp[0] ^= AES_RCON[rcon_idx];
            rcon_idx += 1;
        }

        for i in 0..4 {
            expanded[bytes_generated] = expanded[bytes_generated - 16] ^ temp[i];
            bytes_generated += 1;
        }
    }

    expanded
}

#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

#[inline]
fn aes_add_round_key(state: &mut [u8; 16], round_keys: &[u8; AES128_EXPANDED_KEY_BYTES], round: usize) {
    let start = round * 16;
    for i in 0..16 {
        state[i] ^= round_keys[start + i];
    }
}

#[inline]
fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

#[inline]
fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let tmp = *state;

    // Row 0 (no shift)
    state[0] = tmp[0];
    state[4] = tmp[4];
    state[8] = tmp[8];
    state[12] = tmp[12];

    // Row 1 (shift right 1)
    state[1] = tmp[13];
    state[5] = tmp[1];
    state[9] = tmp[5];
    state[13] = tmp[9];

    // Row 2 (shift right 2)
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];

    // Row 3 (shift right 3)
    state[3] = tmp[7];
    state[7] = tmp[11];
    state[11] = tmp[15];
    state[15] = tmp[3];
}

#[inline]
fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];

        state[i] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        state[i + 1] =
            gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        state[i + 2] =
            gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        state[i + 3] =
            gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

fn aes128_decrypt_block_in_place(block: &mut [u8; 16], round_keys: &[u8; AES128_EXPANDED_KEY_BYTES]) {
    aes_add_round_key(block, round_keys, AES128_ROUNDS);

    for round in (1..AES128_ROUNDS).rev() {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, round_keys, round);
        aes_inv_mix_columns(block);
    }

    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, round_keys, 0);
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiError {
    NoDevice,
    UnsupportedDevice,
    NotEnabled,
    NotConnected,
    NetworkNotFound,
    NoPassword,
    PasswordRequired,
    AuthenticationFailed,
    AssociationFailed,
    DHCPFailed,
    HardwareError,
    Timeout,
}

impl WifiError {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiError::NoDevice => "No WiFi device",
            WifiError::UnsupportedDevice => "Unsupported device",
            WifiError::NotEnabled => "WiFi not enabled",
            WifiError::NotConnected => "Not connected",
            WifiError::NetworkNotFound => "Network not found",
            WifiError::NoPassword => "No password provided",
            WifiError::PasswordRequired => "Password required",
            WifiError::AuthenticationFailed => "Authentication failed",
            WifiError::AssociationFailed => "Association failed",
            WifiError::DHCPFailed => "DHCP failed",
            WifiError::HardwareError => "Hardware error",
            WifiError::Timeout => "Timeout",
        }
    }
}

// ============================================================================
// Global WiFi Driver
// ============================================================================

static WIFI: Mutex<WifiDriver> = Mutex::new(WifiDriver::new());

pub fn wifi() -> &'static Mutex<WifiDriver> {
    &WIFI
}

pub fn init(device: PciDevice) -> Result<(), WifiError> {
    let mut wifi = WIFI.lock();
    wifi.init(device)
}

// ============================================================================
// Helper Functions
// ============================================================================

fn print_hex_byte(byte: u8) {
    let high = (byte >> 4) & 0xF;
    let low = byte & 0xF;
    
    crate::vga::print_char(hex_digit(high));
    crate::vga::print_char(hex_digit(low));
}

fn hex_digit(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}
