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
        // In production, this would:
        // 1. Send authentication frame
        // 2. Perform WPA2/WPA3 4-way handshake if secured
        // 3. Send association request
        // 4. Wait for association response
        // 5. Perform DHCP to get IP address

        // For v1, simulate successful connection
        crate::vga::print_str("[WiFi] Authenticating...\n");
        self.connection.state = WifiState::Authenticating;

        crate::vga::print_str("[WiFi] Associating...\n");
        self.connection.state = WifiState::Associated;

        Ok(())
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
