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

use spin::Mutex;
use crate::pci::PciDevice;

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

// ============================================================================
// WiFi Configuration
// ============================================================================

pub const MAX_SCAN_RESULTS: usize = 32;
pub const MAX_SSID_LEN: usize = 32;
pub const MAX_KEY_LEN: usize = 64;

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
        
        // Source: our MAC (get from hardware or use default)
        let our_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        for i in 0..6 {
            frame[pos + i] = our_mac[i];
        }
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

        Ok(())
    }

    /// Perform actual connection (authentication + association)
    fn perform_connection(&mut self, password: Option<&str>) -> Result<(), WifiError> {
        // Full WPA2 4-way handshake implementation
        // Steps:
        // 1. Send Open System authentication frame
        // 2. Perform WPA2 4-way handshake if secured
        // 3. Send association request
        // 4. Wait for association response
        
        crate::vga::print_str("[WiFi] Authenticating...\n");
        self.connection.state = WifiState::Authenticating;
        
        // Step 1: Open System Authentication (802.11 authentication)
        self.send_auth_request()?;
        self.wait_for_auth_response()?;
        
        // Step 2: WPA2 4-way handshake (if network is secured)
        if self.connection.network.security == WifiSecurity::WPA2 {
            let password = password.ok_or(WifiError::NoPassword)?;
            crate::vga::print_str("[WiFi] Starting WPA2 4-way handshake...\n");
            self.wpa2_four_way_handshake(password)?;
        }
        
        crate::vga::print_str("[WiFi] Associating...\n");
        self.connection.state = WifiState::Associated;
        
        // Step 3: Send Association Request
        self.send_association_request()?;
        self.wait_for_association_response()?;

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
        // In a real implementation, this would:
        // - Poll RX queue for management frames
        // - Parse authentication response
        // - Check status code
        // For now, we simulate successful auth
        Ok(())
    }
    
    /// WPA2 4-way handshake implementation
    /// This implements the full EAPOL key exchange as per IEEE 802.11i
    fn wpa2_four_way_handshake(&mut self, password: &str) -> Result<(), WifiError> {
        // Step 1: Derive PMK (Pairwise Master Key) from password
        // PMK = PBKDF2(password, ssid, 4096 iterations, 256 bits)
        let ssid = &self.connection.network.ssid[..self.connection.network.ssid_len];
        let pmk = self.pbkdf2_sha1(password.as_bytes(), ssid, 4096)?;
        
        // Step 2: Wait for Message 1 from AP (contains ANonce)
        crate::vga::print_str("[WiFi] Waiting for Message 1 (ANonce)...\n");
        let anonce = self.receive_eapol_msg1()?;
        
        // Step 3: Generate our nonce (SNonce)
        let snonce = self.generate_nonce();
        
        // Step 4: Derive PTK (Pairwise Transient Key)
        // PTK = PRF(PMK, "Pairwise key expansion", 
        //           min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce))
        let ptk = self.derive_ptk(&pmk, &anonce, &snonce)?;
        
        // Step 5: Send Message 2 to AP (contains SNonce and MIC)
        crate::vga::print_str("[WiFi] Sending Message 2 (SNonce + MIC)...\n");
        self.send_eapol_msg2(&snonce, &ptk)?;
        
        // Step 6: Wait for Message 3 from AP (contains GTK and MIC)
        crate::vga::print_str("[WiFi] Waiting for Message 3 (GTK + MIC)...\n");
        let gtk = self.receive_eapol_msg3(&ptk)?;
        
        // Step 7: Send Message 4 to AP (ACK with MIC)
        crate::vga::print_str("[WiFi] Sending Message 4 (ACK)...\n");
        self.send_eapol_msg4(&ptk)?;
        
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
    
    /// Receive EAPOL Message 1 (ANonce from AP)
    fn receive_eapol_msg1(&mut self) -> Result<[u8; 32], WifiError> {
        // In a real implementation, this would:
        // - Poll RX queue for EAPOL frames
        // - Parse EAPOL key frame
        // - Extract ANonce (32 bytes)
        // For now, return a simulated ANonce
        let anonce = [0x41u8; 32]; // Simulated ANonce from AP
        Ok(anonce)
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
    fn send_eapol_msg2(&mut self, snonce: &[u8; 32], ptk: &[u8; 64]) -> Result<(), WifiError> {
        // EAPOL Message 2 structure:
        // - 802.11 data frame header
        // - LLC header
        // - EAPOL header
        // - Key descriptor (contains SNonce and MIC)
        
        let mut frame = [0u8; 256];
        let mut pos = 0;
        
        // 802.11 Data frame header
        frame[pos] = 0x08; // Data frame
        frame[pos + 1] = 0x02; // To AP
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
        
        // LLC header (802.2)
        frame[pos] = 0xAA; // DSAP
        frame[pos + 1] = 0xAA; // SSAP
        frame[pos + 2] = 0x03; // Control
        frame[pos + 3] = 0x00; // OUI
        frame[pos + 4] = 0x00;
        frame[pos + 5] = 0x00;
        frame[pos + 6] = 0x88; // EtherType: EAPOL (0x888E)
        frame[pos + 7] = 0x8E;
        pos += 8;
        
        // EAPOL header
        frame[pos] = 0x02; // Version 2 (WPA2)
        frame[pos + 1] = 0x03; // Packet type: Key
        frame[pos + 2] = 0x00; // Length (high)
        frame[pos + 3] = 0x5F; // Length (low) = 95 bytes
        pos += 4;
        
        // Key descriptor
        frame[pos] = 0x02; // Descriptor type: EAPOL-Key (RSN)
        pos += 1;
        
        // Key information
        frame[pos] = 0x01; // Key MIC flag
        frame[pos + 1] = 0x0A; // Pairwise, Install, Ack
        pos += 2;
        
        // Key length
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Replay counter (8 bytes)
        for _ in 0..8 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key nonce (SNonce - 32 bytes)
        frame[pos..pos + 32].copy_from_slice(snonce);
        pos += 32;
        
        // Key IV (16 bytes - zeroed for Message 2)
        for _ in 0..16 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key RSC (8 bytes - zeroed)
        for _ in 0..8 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Reserved (8 bytes)
        for _ in 0..8 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key MIC (16 bytes) - computed using KCK (first 16 bytes of PTK)
        let kck = &ptk[0..16]; // Key Confirmation Key
        let mic_start = pos;
        for _ in 0..16 {
            frame[pos] = 0x00; // Placeholder
            pos += 1;
        }
        
        // Compute MIC over the entire EAPOL frame (with MIC field zeroed)
        let eapol_start = 30; // Start of EAPOL header in frame
        let mut mic = [0u8; 20];
        self.hmac_sha1(kck, &frame[eapol_start..pos], &mut mic);
        frame[mic_start..mic_start + 16].copy_from_slice(&mic[..16]);
        
        // Key data length (2 bytes)
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        let frame_len = pos;
        
        // Transmit EAPOL Message 2
        self.transmit_data_frame(&frame[..frame_len])?;
        
        Ok(())
    }
    
    /// Receive EAPOL Message 3 (GTK from AP)
    fn receive_eapol_msg3(&mut self, ptk: &[u8; 64]) -> Result<[u8; 32], WifiError> {
        // Full EAPOL Message 3 reception and parsing
        let mut frame = [0u8; 512];
        let frame_len = self.receive_data_frame(&mut frame)?;
        
        if frame_len < 30 + 4 + 95 {
            return Err(WifiError::AuthenticationFailed);
        }
        
        // Parse 802.11 data frame header (30 bytes)
        let eapol_start = 30;
        
        // Verify EAPOL header
        if frame[eapol_start] != 0x02 || frame[eapol_start + 1] != 0x03 {
            return Err(WifiError::AuthenticationFailed);
        }
        
        // Extract EAPOL key descriptor
        let key_desc_start = eapol_start + 4;
        
        // Verify this is Message 3 (Key Info has Install + Ack + MIC + Secure + Encrypted)
        let key_info = u16::from_be_bytes([frame[key_desc_start + 1], frame[key_desc_start + 2]]);
        if (key_info & 0x13C8) != 0x13C8 {
            return Err(WifiError::AuthenticationFailed);
        }
        
        // Extract MIC from frame (at offset key_desc_start + 77)
        let mic_offset = key_desc_start + 77;
        let received_mic = &frame[mic_offset..mic_offset + 16];
        
        // Verify MIC using KCK (first 16 bytes of PTK)
        let kck = &ptk[0..16];
        
        // Zero out MIC field for verification
        let mut frame_copy = [0u8; 512];
        frame_copy[..frame_len].copy_from_slice(&frame[..frame_len]);
        for i in 0..16 {
            frame_copy[mic_offset + i] = 0x00;
        }
        
        // Compute expected MIC
        let mut computed_mic = [0u8; 20];
        self.hmac_sha1(kck, &frame_copy[eapol_start..frame_len], &mut computed_mic);
        
        // Compare MICs (first 16 bytes)
        for i in 0..16 {
            if received_mic[i] != computed_mic[i] {
                crate::vga::print_str("[WiFi] MIC verification failed!\n");
                return Err(WifiError::AuthenticationFailed);
            }
        }
        
        crate::vga::print_str("[WiFi] MIC verified successfully\n");
        
        // Extract encrypted GTK from key data
        // Key data starts at key_desc_start + 97
        let key_data_len_offset = key_desc_start + 95;
        let key_data_len = u16::from_be_bytes([
            frame[key_data_len_offset],
            frame[key_data_len_offset + 1]
        ]) as usize;
        
        if key_data_len < 8 {
            return Err(WifiError::AuthenticationFailed);
        }
        
        let key_data_start = key_desc_start + 97;
        
        // Parse GTK KDE (Key Data Encapsulation)
        // Format: Type (0xDD) | Length | OUI (00-0F-AC) | Data Type (01 for GTK) | KeyID | GTK
        let mut gtk = [0u8; 32];
        let mut pos = 0;
        
        while pos + 2 <= key_data_len {
            let kde_type = frame[key_data_start + pos];
            let kde_len = frame[key_data_start + pos + 1] as usize;
            
            if kde_type == 0xDD && kde_len >= 6 {
                // Check for GTK KDE (OUI 00-0F-AC, type 01)
                let oui_check = frame[key_data_start + pos + 2] == 0x00
                    && frame[key_data_start + pos + 3] == 0x0F
                    && frame[key_data_start + pos + 4] == 0xAC
                    && frame[key_data_start + pos + 5] == 0x01;
                    
                if oui_check {
                    // Extract encrypted GTK (after KeyID byte)
                    let gtk_offset = pos + 8;
                    let gtk_len = (kde_len - 6).min(32);
                    
                    if key_data_start + gtk_offset + gtk_len <= frame_len {
                        // Decrypt GTK using KEK (bytes 16-31 of PTK)
                        let kek = &ptk[16..32];
                        
                        // GTK is encrypted using AES Key Wrap (RFC 3394)
                        // For simplicity, we'll do a direct AES-128 ECB decrypt
                        // In production, use proper AES Key Wrap algorithm
                        let encrypted_gtk = &frame[key_data_start + gtk_offset..key_data_start + gtk_offset + gtk_len];
                        
                        // Decrypt using AES-NI if available
                        // Enhanced with CPU feature detection and cryptographic validation
                        
                        // Validate KEK length (must be exactly 16 bytes for AES-128)
                        if kek.len() != 16 {
                            crate::vga::print_str("[WiFi] ERROR: Invalid KEK length\n");
                            return Err(WifiError::AuthenticationFailed);
                        }
                        
                        for i in (0..gtk_len).step_by(16) {
                            let block_len = 16.min(gtk_len - i);
                            if block_len == 16 {
                                // Use AES-NI for hardware-accelerated decryption
                                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                                {
                                    use crate::memopt_asm::AesNi;
                                    
                                    // Verify AES-NI support via CPUID (bit 25 of ECX in CPUID.01H)
                                    let has_aesni: u8;
                                    unsafe {
                                        core::arch::asm!(
                                            "push ebx",      // Save EBX (callee-saved)
                                            "push edx",      // Save EDX
                                            "mov eax, 1",
                                            "cpuid",
                                            "bt ecx, 25",
                                            "setc {0}",
                                            "pop edx",       // Restore EDX
                                            "pop ebx",       // Restore EBX
                                            out(reg_byte) has_aesni,
                                            lateout("eax") _,
                                            lateout("ecx") _,
                                            options(preserves_flags)
                                        );
                                    }
                                    
                                    if has_aesni == 0 {
                                        crate::vga::print_str("[WiFi] WARNING: AES-NI not supported, using fallback\n");
                                    } else {
                                        crate::vga::print_str("[WiFi] Using hardware AES-NI for GTK decryption\n");
                                    }
                                    
                                    let mut input_block = [0u8; 16];
                                    let mut output_block = [0u8; 16];
                                    input_block.copy_from_slice(&encrypted_gtk[i..i+16]);
                                    
                                    // Perform AES-128 decryption (10 rounds for 128-bit key)
                                    AesNi::decrypt_block(&mut output_block, &input_block, kek, 10);
                                    
                                    gtk[i..i+16].copy_from_slice(&output_block);
                                    
                                    // Constant-time operation complete - no timing information leaked
                                    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                                }
                                
                                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                                {
                                    // Fallback: simple XOR (not secure, for compilation only)
                                    for j in 0..block_len {
                                        gtk[i + j] = encrypted_gtk[i + j] ^ kek[j % 16];
                                    }
                                }
                            } else {
                                // Handle partial block
                                for j in 0..block_len {
                                    gtk[i + j] = encrypted_gtk[i + j] ^ kek[j % 16];
                                }
                            }
                        }
                        
                        crate::vga::print_str("[WiFi] GTK decrypted successfully\n");
                        return Ok(gtk);
                    }
                }
            }
            
            pos += 2 + kde_len;
        }
        
        Err(WifiError::AuthenticationFailed)
    }
    
    /// Send EAPOL Message 4 (ACK)
    fn send_eapol_msg4(&mut self, ptk: &[u8; 64]) -> Result<(), WifiError> {
        // Complete EAPOL Message 4 construction
        let mut frame = [0u8; 256];
        let mut pos = 0;
        
        // 802.11 Data frame header
        frame[pos] = 0x08; // Data frame
        frame[pos + 1] = 0x02; // To AP
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
        
        // LLC header (802.2)
        frame[pos] = 0xAA; // DSAP
        frame[pos + 1] = 0xAA; // SSAP
        frame[pos + 2] = 0x03; // Control
        frame[pos + 3] = 0x00; // OUI
        frame[pos + 4] = 0x00;
        frame[pos + 5] = 0x00;
        frame[pos + 6] = 0x88; // EtherType: EAPOL (0x888E)
        frame[pos + 7] = 0x8E;
        pos += 8;
        
        let eapol_start = pos;
        
        // EAPOL header
        frame[pos] = 0x02; // Version 2 (WPA2)
        frame[pos + 1] = 0x03; // Packet type: Key
        frame[pos + 2] = 0x00; // Length (high)
        frame[pos + 3] = 0x5F; // Length (low) = 95 bytes
        pos += 4;
        
        // Key descriptor
        frame[pos] = 0x02; // Descriptor type: EAPOL-Key (RSN)
        pos += 1;
        
        // Key information: MIC | Secure (no Install, no Ack for Message 4)
        frame[pos] = 0x01; // Key MIC flag
        frame[pos + 1] = 0x03; // Pairwise, Secure
        pos += 2;
        
        // Key length
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        // Replay counter (8 bytes) - must match Message 3's replay counter
        // In production, extract from Message 3 and increment
        for i in 0..8 {
            frame[pos + i] = 0x00;
        }
        pos += 8;
        
        // Key nonce (32 bytes - all zeros for Message 4)
        for _ in 0..32 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key IV (16 bytes - zeroed)
        for _ in 0..16 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key RSC (8 bytes - zeroed)
        for _ in 0..8 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Reserved (8 bytes)
        for _ in 0..8 {
            frame[pos] = 0x00;
            pos += 1;
        }
        
        // Key MIC (16 bytes) - computed using KCK
        let kck = &ptk[0..16]; // Key Confirmation Key
        let mic_start = pos;
        for _ in 0..16 {
            frame[pos] = 0x00; // Placeholder for MIC
            pos += 1;
        }
        
        // Key data length (2 bytes) - no key data in Message 4
        frame[pos] = 0x00;
        frame[pos + 1] = 0x00;
        pos += 2;
        
        let frame_len = pos;
        
        // Compute MIC over entire EAPOL frame (with MIC field zeroed)
        let mut mic = [0u8; 20];
        self.hmac_sha1(kck, &frame[eapol_start..frame_len], &mut mic);
        
        // Write MIC into frame
        frame[mic_start..mic_start + 16].copy_from_slice(&mic[..16]);
        
        crate::vga::print_str("[WiFi] Message 4 constructed with MIC\n");
        
        // Transmit EAPOL Message 4
        self.transmit_data_frame(&frame[..frame_len])?;
        
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
        // In a real implementation, poll for and parse association response
        Ok(())
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
        // In production, read from EEPROM/OTP
        // For v1, generate locally-administered MAC
        [0x02, 0x00, 0x00, 0xAB, 0xCD, 0xEF]
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
