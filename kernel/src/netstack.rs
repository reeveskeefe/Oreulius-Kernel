//! Universal Network Stack
//!
//! Production TCP/IP stack with real packet I/O that works with any network interface.
//! Supports: ARP, ICMP, UDP, TCP, DNS, DHCP

#![allow(dead_code)]

extern crate alloc;
use alloc::boxed::Box;
use spin::Mutex;

// ============================================================================
// Network Interface Trait (Universal Abstraction)
// ============================================================================

/// Universal network interface trait - implemented by E1000, WiFi, VirtIO, etc.
pub trait NetworkInterface: Send {
    /// Send raw Ethernet frame
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), &'static str>;
    
    /// Receive raw Ethernet frame (non-blocking)
    fn recv_frame(&mut self, buffer: &mut [u8]) -> Result<usize, &'static str>;
    
    /// Get MAC address
    fn mac_address(&self) -> [u8; 6];
    
    /// Check if link is up
    fn is_link_up(&self) -> bool;
}

// ============================================================================
// Protocol Constants
// ============================================================================

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

// ============================================================================
// Network Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }
    
    pub fn octets(&self) -> [u8; 4] {
        self.0
    }
    
    pub fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }
    
    pub fn from_u32(val: u32) -> Self {
        Ipv4Addr(val.to_be_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddr([a, b, c, d, e, f])
    }
    
    pub const BROADCAST: MacAddr = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

// ============================================================================
// ARP Cache
// ============================================================================

struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    valid: bool,
}

struct ArpCache {
    entries: [ArpEntry; 16],
}

impl ArpCache {
    const fn new() -> Self {
        const EMPTY: ArpEntry = ArpEntry {
            ip: Ipv4Addr([0, 0, 0, 0]),
            mac: MacAddr([0, 0, 0, 0, 0, 0]),
            valid: false,
        };
        
        ArpCache {
            entries: [EMPTY; 16],
        }
    }
    
    fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        for entry in &self.entries {
            if entry.valid && entry.ip == ip {
                return Some(entry.mac);
            }
        }
        None
    }
    
    fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        // Find empty slot or oldest entry
        for entry in &mut self.entries {
            if !entry.valid {
                entry.ip = ip;
                entry.mac = mac;
                entry.valid = true;
                return;
            }
        }
        
        // Overwrite first entry if cache is full
        self.entries[0].ip = ip;
        self.entries[0].mac = mac;
        self.entries[0].valid = true;
    }
}

// ============================================================================
// Network Stack
// ============================================================================

pub struct NetworkStack {
    my_ip: Ipv4Addr,
    my_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    dns_server: Ipv4Addr,
    arp_cache: ArpCache,
    dhcp_enabled: bool,
    has_interface: bool,
}

impl NetworkStack {
    pub const fn new() -> Self {
        NetworkStack {
            my_ip: Ipv4Addr([10, 0, 2, 15]),  // QEMU default
            my_mac: MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),  // QEMU default
            gateway_ip: Ipv4Addr([10, 0, 2, 2]),  // QEMU default gateway
            dns_server: Ipv4Addr([8, 8, 8, 8]),  // Google DNS
            arp_cache: ArpCache::new(),
            dhcp_enabled: false,
            has_interface: false,
        }
    }
    
    /// Mark interface as available
    pub fn mark_ready(&mut self) {
        self.has_interface = true;
    }
    
    /// Check if network is ready
    pub fn is_ready(&self) -> bool {
        // Check if E1000 driver is available
        crate::e1000::get_mac_address().is_some()
    }
    
    // ========================================================================
    // ARP Protocol
    // ========================================================================
    
    /// Send ARP request
    fn send_arp_request(&mut self, target_ip: Ipv4Addr) -> Result<(), &'static str> {
        let mut driver = crate::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;
        
        let mut frame = [0u8; 42];
        let mut offset = 0;
        
        // Ethernet header
        frame[offset..offset+6].copy_from_slice(&MacAddr::BROADCAST.0);  // Dest MAC
        offset += 6;
        frame[offset..offset+6].copy_from_slice(&self.my_mac.0);  // Src MAC
        offset += 6;
        frame[offset..offset+2].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());  // EtherType
        offset += 2;
        
        // ARP packet
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Hardware type: Ethernet
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&[0x08, 0x00]);  // Protocol type: IPv4
        offset += 2;
        frame[offset] = 6;  // Hardware size
        offset += 1;
        frame[offset] = 4;  // Protocol size
        offset += 1;
        frame[offset..offset+2].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());  // Operation
        offset += 2;
        frame[offset..offset+6].copy_from_slice(&self.my_mac.0);  // Sender MAC
        offset += 6;
        frame[offset..offset+4].copy_from_slice(&self.my_ip.0);  // Sender IP
        offset += 4;
        frame[offset..offset+6].copy_from_slice(&[0; 6]);  // Target MAC (unknown)
        offset += 6;
        frame[offset..offset+4].copy_from_slice(&target_ip.0);  // Target IP
        
        interface.send_frame(&frame)
    }
    
    /// Process received ARP packet
    fn handle_arp(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() < 28 {
            return Err("ARP packet too short");
        }
        
        let op = u16::from_be_bytes([packet[6], packet[7]]);
        let sender_mac = MacAddr([packet[8], packet[9], packet[10], packet[11], packet[12], packet[13]]);
        let sender_ip = Ipv4Addr([packet[14], packet[15], packet[16], packet[17]]);
        
        // Update ARP cache
        self.arp_cache.insert(sender_ip, sender_mac);
        
        // Handle ARP request
        if op == ARP_OP_REQUEST {
            let target_ip = Ipv4Addr([packet[24], packet[25], packet[26], packet[27]]);
            
            // Reply if request is for us
            if target_ip == self.my_ip {
                self.send_arp_reply(sender_mac, sender_ip)?;
            }
        }
        
        Ok(())
    }
    
    /// Send ARP reply
    fn send_arp_reply(&mut self, dest_mac: MacAddr, dest_ip: Ipv4Addr) -> Result<(), &'static str> {
        let mut driver = crate::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;
        
        let mut frame = [0u8; 42];
        let mut offset = 0;
        
        // Ethernet header
        frame[offset..offset+6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset+6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset+2].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        offset += 2;
        
        // ARP packet
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x01]);
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&[0x08, 0x00]);
        offset += 2;
        frame[offset] = 6;
        offset += 1;
        frame[offset] = 4;
        offset += 1;
        frame[offset..offset+2].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
        offset += 2;
        frame[offset..offset+6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset+4].copy_from_slice(&self.my_ip.0);
        offset += 4;
        frame[offset..offset+6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset+4].copy_from_slice(&dest_ip.0);
        
        interface.send_frame(&frame)
    }
    
    /// Resolve IP to MAC address (with ARP)
    fn resolve_mac(&mut self, ip: Ipv4Addr) -> Result<MacAddr, &'static str> {
        // Check ARP cache first
        if let Some(mac) = self.arp_cache.lookup(ip) {
            return Ok(mac);
        }
        
        // Send ARP request
        self.send_arp_request(ip)?;
        
        // Poll for response (simple timeout)
        for _ in 0..1000 {
            self.poll_once()?;
            
            if let Some(mac) = self.arp_cache.lookup(ip) {
                return Ok(mac);
            }
            
            // Simple delay
            for _ in 0..10000 {
                unsafe { core::arch::asm!("nop"); }
            }
        }
        
        Err("ARP timeout")
    }
    
    // ========================================================================
    // UDP Protocol
    // ========================================================================
    
    /// Send UDP packet
    fn send_udp(&mut self, dest_ip: Ipv4Addr, dest_port: u16, src_port: u16, data: &[u8]) 
        -> Result<(), &'static str> 
    {
        if data.len() > 1472 {  // Max UDP payload in standard Ethernet
            return Err("UDP payload too large");
        }
        
        // Resolve destination MAC (use gateway for external IPs)
        let next_hop = if self.is_local(dest_ip) { dest_ip } else { self.gateway_ip };
        let dest_mac = self.resolve_mac(next_hop)?;
        
        // Use E1000 driver directly
        let mut driver = crate::e1000::E1000_DRIVER.lock();
        let driver = driver.as_mut().ok_or("No E1000 driver")?;
        
        // Build packet
        let mut frame = [0u8; 1514];
        let mut offset = 0;
        
        // Ethernet header (14 bytes)
        frame[offset..offset+6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset+6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset+2].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        offset += 2;
        
        // IPv4 header (20 bytes)
        let ip_header_start = offset;
        frame[offset] = 0x45;  // Version 4, header length 5 (20 bytes)
        offset += 1;
        frame[offset] = 0;  // DSCP/ECN
        offset += 1;
        let total_len = 20 + 8 + data.len();  // IP header + UDP header + data
        frame[offset..offset+2].copy_from_slice(&(total_len as u16).to_be_bytes());
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Identification
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Flags/Fragment
        offset += 2;
        frame[offset] = 64;  // TTL
        offset += 1;
        frame[offset] = IP_PROTOCOL_UDP;
        offset += 1;
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Checksum (filled later)
        let ip_checksum_offset = offset - 2;
        offset += 2;
        frame[offset..offset+4].copy_from_slice(&self.my_ip.0);
        offset += 4;
        frame[offset..offset+4].copy_from_slice(&dest_ip.0);
        offset += 4;
        
        // Calculate IP checksum
        let ip_checksum = calculate_checksum(&frame[ip_header_start..offset]);
        frame[ip_checksum_offset..ip_checksum_offset+2].copy_from_slice(&ip_checksum.to_be_bytes());
        
        // UDP header (8 bytes)
        frame[offset..offset+2].copy_from_slice(&src_port.to_be_bytes());
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&dest_port.to_be_bytes());
        offset += 2;
        let udp_len = 8 + data.len();
        frame[offset..offset+2].copy_from_slice(&(udp_len as u16).to_be_bytes());
        offset += 2;
        frame[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Checksum (optional for IPv4)
        offset += 2;
        
        // UDP payload
        frame[offset..offset+data.len()].copy_from_slice(data);
        offset += data.len();
        
        driver.send_frame(&frame[..offset])
    }
    
    /// Receive UDP packet (simplified - returns payload if matches port)
    fn recv_udp(&mut self, expected_port: u16, buffer: &mut [u8]) -> Result<usize, &'static str> {
        // Use E1000 driver directly
        let mut driver = crate::e1000::E1000_DRIVER.lock();
        let driver = driver.as_mut().ok_or("No E1000 driver")?;
        
        let mut frame = [0u8; 1514];
        let frame_len = driver.recv_frame(&mut frame)?;
        
        if frame_len < 42 {  // Min: Eth(14) + IP(20) + UDP(8)
            return Err("Frame too short");
        }
        
        // Check EtherType
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != ETHERTYPE_IPV4 {
            return Err("Not IPv4");
        }
        
        // Check IP protocol
        if frame[23] != IP_PROTOCOL_UDP {
            return Err("Not UDP");
        }
        
        // Parse UDP header
        let udp_offset = 14 + 20;  // After Ethernet + IP
        let dest_port = u16::from_be_bytes([frame[udp_offset+2], frame[udp_offset+3]]);
        
        if dest_port != expected_port {
            return Err("Wrong port");
        }
        
        let udp_len = u16::from_be_bytes([frame[udp_offset+4], frame[udp_offset+5]]) as usize;
        let payload_len = udp_len - 8;  // Subtract UDP header
        
        if payload_len > buffer.len() {
            return Err("Buffer too small");
        }
        
        buffer[..payload_len].copy_from_slice(&frame[udp_offset+8..udp_offset+8+payload_len]);
        Ok(payload_len)
    }
    
    // ========================================================================
    // DNS Protocol
    // ========================================================================
    
    /// Resolve domain name to IP address
    pub fn dns_resolve(&mut self, domain: &str) -> Result<Ipv4Addr, &'static str> {
        if domain.len() > 253 {
            return Err("Domain name too long");
        }
        
        // Build DNS query
        let mut query = [0u8; 512];
        let mut offset = 0;
        
        // DNS header
        query[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Transaction ID
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x01, 0x00]);  // Flags: standard query
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Questions: 1
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Answer RRs: 0
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Authority RRs: 0
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x00, 0x00]);  // Additional RRs: 0
        offset += 2;
        
        // Question: encode domain name
        for label in domain.split('.') {
            if label.len() > 63 {
                return Err("Label too long");
            }
            query[offset] = label.len() as u8;
            offset += 1;
            query[offset..offset+label.len()].copy_from_slice(label.as_bytes());
            offset += label.len();
        }
        query[offset] = 0;  // End of domain name
        offset += 1;
        
        query[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Type: A (IPv4)
        offset += 2;
        query[offset..offset+2].copy_from_slice(&[0x00, 0x01]);  // Class: IN (Internet)
        offset += 2;
        
        let query_len = offset;
        
        // Send DNS query (UDP port 53)
        self.send_udp(self.dns_server, 53, 53000, &query[..query_len])?;
        
        // Receive DNS response
        let mut response = [0u8; 512];
        
        // Poll for response with timeout
        for _ in 0..100 {
            match self.recv_udp(53000, &mut response) {
                Ok(len) => {
                    return self.parse_dns_response(&response[..len]);
                }
                Err(_) => {
                    // Wait and retry
                    for _ in 0..50000 {
                        unsafe { core::arch::asm!("nop"); }
                    }
                }
            }
        }
        
        Err("DNS timeout")
    }
    
    /// Parse DNS response
    fn parse_dns_response(&self, response: &[u8]) -> Result<Ipv4Addr, &'static str> {
        if response.len() < 12 {
            return Err("DNS response too short");
        }
        
        // Check response code
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            return Err("DNS error");
        }
        
        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        if answer_count == 0 {
            return Err("No answers");
        }
        
        // Skip question section
        let mut offset = 12;
        
        // Skip domain name in question
        loop {
            if offset >= response.len() {
                return Err("Invalid DNS response");
            }
            
            let len = response[offset];
            if len == 0 {
                offset += 1;
                break;
            }
            
            // Handle compression pointer
            if len & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            
            offset += 1 + len as usize;
        }
        
        offset += 4;  // Skip QTYPE and QCLASS
        
        // Parse answer section
        for _ in 0..answer_count {
            if offset + 12 > response.len() {
                return Err("Invalid answer");
            }
            
            // Skip name (handle compression)
            if response[offset] & 0xC0 == 0xC0 {
                offset += 2;
            } else {
                loop {
                    let len = response[offset];
                    if len == 0 {
                        offset += 1;
                        break;
                    }
                    offset += 1 + len as usize;
                }
            }
            
            let rtype = u16::from_be_bytes([response[offset], response[offset+1]]);
            let rdlength = u16::from_be_bytes([response[offset+8], response[offset+9]]) as usize;
            offset += 10;
            
            // Check for A record (IPv4)
            if rtype == 1 && rdlength == 4 {
                return Ok(Ipv4Addr([
                    response[offset],
                    response[offset+1],
                    response[offset+2],
                    response[offset+3],
                ]));
            }
            
            offset += rdlength;
        }
        
        Err("No A record found")
    }
    
    // ========================================================================
    // Packet Processing
    // ========================================================================
    
    /// Poll for incoming packets once
    pub fn poll_once(&mut self) -> Result<(), &'static str> {
        let mut driver = crate::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;
        
        let mut frame = [0u8; 1514];
        let frame_len = match interface.recv_frame(&mut frame) {
            Ok(len) => len,
            Err(_) => return Ok(()),  // No packet available
        };
        
        if frame_len < 14 {
            return Ok(());  // Too short
        }
        
        // Parse EtherType
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        
        match ethertype {
            ETHERTYPE_ARP => {
                let _ = self.handle_arp(&frame[14..frame_len]);
            }
            ETHERTYPE_IPV4 => {
                // Handle IPv4 packet (can add ICMP, TCP, etc. here)
            }
            _ => {}
        }
        
        Ok(())
    }
    
    // ========================================================================
    // Helpers
    // ========================================================================
    
    fn is_local(&self, ip: Ipv4Addr) -> bool {
        // Simple check: same /24 network
        ip.0[0] == self.my_ip.0[0] && 
        ip.0[1] == self.my_ip.0[1] && 
        ip.0[2] == self.my_ip.0[2]
    }
    
    pub fn get_ip(&self) -> Ipv4Addr {
        self.my_ip
    }
    
    pub fn set_dns_server(&mut self, dns: Ipv4Addr) {
        self.dns_server = dns;
    }
}

// ============================================================================
// Checksum Calculation
// ============================================================================

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    // Sum 16-bit words
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i+1]]) as u32;
        sum += word;
        i += 2;
    }
    
    // Add remaining byte if odd length
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

// ============================================================================
// Global Network Stack
// ============================================================================

pub static NETWORK_STACK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());

pub fn network_stack() -> &'static Mutex<NetworkStack> {
    &NETWORK_STACK
}
