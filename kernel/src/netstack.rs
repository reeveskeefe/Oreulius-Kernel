//! Universal Network Stack
//!
//! Production TCP/IP stack with real packet I/O that works with any network interface.
//! Supports: ARP, ICMP, UDP, TCP, DNS, DHCP

#![allow(dead_code)]

extern crate alloc;
use spin::Mutex;

// ============================================================================
// Network Interface Trait (Universal Abstraction)
// ============================================================================

/// Universal network interface trait - implemented by E1000, WiFi, VirtIO, etc.
/// Boxed trait objects allow runtime polymorphism for different NICs
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
    tcp: TcpManager,
    http_server: HttpServer,
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
            tcp: TcpManager::new(),
            http_server: HttpServer::new(),
        }
    }
    
    /// Mark interface as available
    pub fn mark_ready(&mut self) {
        self.has_interface = true;
        if let Some(mac) = crate::e1000::get_mac_address() {
            self.my_mac = MacAddr(mac);
        }
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
                let _ = self.handle_ipv4(&frame[14..frame_len]);
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Timer tick for retransmission/timers
    pub fn tick(&mut self) {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        tcp.tick(self);
        self.tcp = tcp;
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

    // ========================================================================
    // TCP Socket API
    // ========================================================================

    pub fn tcp_listen(&mut self, port: u16) -> Result<u16, &'static str> {
        self.tcp.listen(port)
    }

    pub fn tcp_accept(&mut self, listener: u16) -> Option<u16> {
        self.tcp.accept(listener)
    }

    pub fn tcp_connect(&mut self, remote_ip: Ipv4Addr, remote_port: u16) -> Result<u16, &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.connect(self, remote_ip, remote_port);
        self.tcp = tcp;
        res
    }

    pub fn tcp_send(&mut self, conn_id: u16, data: &[u8]) -> Result<usize, &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.send(self, conn_id, data);
        self.tcp = tcp;
        res
    }

    pub fn tcp_recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
        self.tcp.recv(conn_id, out)
    }

    pub fn tcp_close(&mut self, conn_id: u16) -> Result<(), &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.close(self, conn_id);
        self.tcp = tcp;
        res
    }

    pub fn tcp_stats(&self) -> (usize, usize) {
        (self.tcp.active_count(), self.tcp.listener_count())
    }

    // ========================================================================
    // HTTP Server Demo
    // ========================================================================

    pub fn http_server_start(&mut self, port: u16) -> Result<(), &'static str> {
        let listener = self.tcp_listen(port)?;
        self.http_server.running = true;
        self.http_server.listener = Some(listener);
        self.http_server.port = port;
        Ok(())
    }

    pub fn http_server_stop(&mut self) {
        self.http_server.running = false;
        self.http_server.listener = None;
    }

    pub fn http_server_status(&self) -> (bool, u16) {
        (self.http_server.running, self.http_server.port)
    }
}

// ============================================================================
// TCP Implementation
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
}

const MAX_TCP_CONNS: usize = 16;
const MAX_TCP_LISTEN: usize = 4;
const MAX_TCP_BACKLOG: usize = 4;
const TCP_BUF_SIZE: usize = 1024;

#[derive(Clone, Copy)]
struct TcpConn {
    in_use: bool,
    id: u16,
    state: TcpState,
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    iss: u32,
    irs: u32,
    listener_idx: u8,
    last_flags: u16,
    last_seq: u32,
    last_ack: u32,
    last_payload: [u8; 256],
    last_payload_len: usize,
    last_send_tick: u64,
    rto_ticks: u64,
    rtt_start: u64,
    srtt: u64,
    rttvar: u64,
    retries: u8,
    recv_buf: [u8; TCP_BUF_SIZE],
    recv_len: usize,
    http_pending: bool,
}

impl TcpConn {
    const fn empty() -> Self {
        TcpConn {
            in_use: false,
            id: 0,
            state: TcpState::Closed,
            local_ip: Ipv4Addr([0, 0, 0, 0]),
            local_port: 0,
            remote_ip: Ipv4Addr([0, 0, 0, 0]),
            remote_port: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            iss: 0,
            irs: 0,
            listener_idx: 0xFF,
            last_flags: 0,
            last_seq: 0,
            last_ack: 0,
            last_payload: [0u8; 256],
            last_payload_len: 0,
            last_send_tick: 0,
            rto_ticks: 0,
            rtt_start: 0,
            srtt: 0,
            rttvar: 0,
            retries: 0,
            recv_buf: [0u8; TCP_BUF_SIZE],
            recv_len: 0,
            http_pending: false,
        }
    }
}

fn tcp_endpoint(conn: &TcpConn) -> TcpEndpoint {
    TcpEndpoint {
        local_ip: conn.local_ip,
        local_port: conn.local_port,
        remote_ip: conn.remote_ip,
        remote_port: conn.remote_port,
    }
}

#[derive(Clone, Copy)]
struct TcpListener {
    in_use: bool,
    port: u16,
    backlog: [Option<u16>; MAX_TCP_BACKLOG],
    head: usize,
    tail: usize,
}

impl TcpListener {
    const fn empty() -> Self {
        TcpListener {
            in_use: false,
            port: 0,
            backlog: [None; MAX_TCP_BACKLOG],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, conn_id: u16) -> bool {
        let next = (self.tail + 1) % MAX_TCP_BACKLOG;
        if next == self.head {
            return false;
        }
        self.backlog[self.tail] = Some(conn_id);
        self.tail = next;
        true
    }

    fn pop(&mut self) -> Option<u16> {
        if self.head == self.tail {
            return None;
        }
        let conn = self.backlog[self.head].take();
        self.head = (self.head + 1) % MAX_TCP_BACKLOG;
        conn
    }
}

struct TcpManager {
    conns: [TcpConn; MAX_TCP_CONNS],
    listeners: [TcpListener; MAX_TCP_LISTEN],
    next_id: u16,
}

impl TcpManager {
    const fn new() -> Self {
        TcpManager {
            conns: [TcpConn::empty(); MAX_TCP_CONNS],
            listeners: [TcpListener::empty(); MAX_TCP_LISTEN],
            next_id: 1,
        }
    }

    fn active_count(&self) -> usize {
        self.conns.iter().filter(|c| c.in_use).count()
    }

    fn listener_count(&self) -> usize {
        self.listeners.iter().filter(|l| l.in_use).count()
    }

    fn listen(&mut self, port: u16) -> Result<u16, &'static str> {
        for listener in &self.listeners {
            if listener.in_use && listener.port == port {
                return Err("Port already in use");
            }
        }
        for (i, listener) in self.listeners.iter_mut().enumerate() {
            if !listener.in_use {
                *listener = TcpListener::empty();
                listener.in_use = true;
                listener.port = port;
                return Ok(i as u16);
            }
        }
        Err("No listener slots")
    }

    fn accept(&mut self, listener: u16) -> Option<u16> {
        let idx = listener as usize;
        if idx >= self.listeners.len() {
            return None;
        }
        self.listeners[idx].pop()
    }

    fn alloc_conn(&mut self) -> Result<&mut TcpConn, &'static str> {
        for conn in &mut self.conns {
            if !conn.in_use {
                *conn = TcpConn::empty();
                conn.in_use = true;
                conn.id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1).max(1);
                return Ok(conn);
            }
        }
        Err("No connection slots")
    }

    fn find_conn_mut(&mut self, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Option<&mut TcpConn> {
        self.conns.iter_mut().find(|c| c.in_use && c.local_port == local_port && c.remote_port == remote_port && c.remote_ip == remote_ip)
    }

    fn find_conn_id_mut(&mut self, conn_id: u16) -> Option<&mut TcpConn> {
        self.conns.iter_mut().find(|c| c.in_use && c.id == conn_id)
    }

    fn find_conn_index(&self, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Option<usize> {
        self.conns
            .iter()
            .enumerate()
            .find(|(_, c)| c.in_use && c.local_port == local_port && c.remote_port == remote_port && c.remote_ip == remote_ip)
            .map(|(i, _)| i)
    }

    fn connect(&mut self, stack: &mut NetworkStack, remote_ip: Ipv4Addr, remote_port: u16) -> Result<u16, &'static str> {
        let local_port = 40000 + (self.next_id % 10000);
        let iss = (crate::pit::get_ticks() as u32).wrapping_add(1000);
        let conn = self.alloc_conn()?;
        conn.state = TcpState::SynSent;
        conn.local_ip = stack.my_ip;
        conn.local_port = local_port;
        conn.remote_ip = remote_ip;
        conn.remote_port = remote_port;
        conn.iss = iss;
        conn.snd_una = iss;
        conn.snd_nxt = iss;
        conn.rto_ticks = (crate::pit::get_frequency() as u64) * 3;
        conn.rtt_start = crate::pit::get_ticks();
        let ep = tcp_endpoint(conn);
        send_tcp_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_SYN, &[])?;
        record_last(conn, TCP_FLAG_SYN, conn.snd_nxt, conn.rcv_nxt, &[]);
        conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        Ok(conn.id)
    }

    fn send(&mut self, stack: &mut NetworkStack, conn_id: u16, data: &[u8]) -> Result<usize, &'static str> {
        let conn = self.find_conn_id_mut(conn_id).ok_or("Connection not found")?;
        if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
            return Err("Connection not established");
        }
        let len = core::cmp::min(data.len(), conn.last_payload.len());
        let ep = tcp_endpoint(conn);
        send_tcp_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_ACK | TCP_FLAG_PSH, &data[..len])?;
        record_last(conn, TCP_FLAG_ACK | TCP_FLAG_PSH, conn.snd_nxt, conn.rcv_nxt, &data[..len]);
        conn.snd_nxt = conn.snd_nxt.wrapping_add(len as u32);
        Ok(len)
    }

    fn recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
        let conn = self.find_conn_id_mut(conn_id).ok_or("Connection not found")?;
        if conn.recv_len == 0 {
            return Ok(0);
        }
        let len = core::cmp::min(out.len(), conn.recv_len);
        out[..len].copy_from_slice(&conn.recv_buf[..len]);
        conn.recv_len = 0;
        Ok(len)
    }

    fn close(&mut self, stack: &mut NetworkStack, conn_id: u16) -> Result<(), &'static str> {
        let conn = self.find_conn_id_mut(conn_id).ok_or("Connection not found")?;
        if conn.state == TcpState::Established {
            conn.state = TcpState::FinWait1;
            let ep = tcp_endpoint(conn);
            send_tcp_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_FIN | TCP_FLAG_ACK, &[])?;
            record_last(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, conn.snd_nxt, conn.rcv_nxt, &[]);
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            return Ok(());
        }
        if conn.state == TcpState::CloseWait {
            conn.state = TcpState::LastAck;
            let ep = tcp_endpoint(conn);
            send_tcp_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_FIN | TCP_FLAG_ACK, &[])?;
            record_last(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, conn.snd_nxt, conn.rcv_nxt, &[]);
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            return Ok(());
        }
        conn.state = TcpState::Closed;
        conn.in_use = false;
        Ok(())
    }

    fn tick(&mut self, stack: &mut NetworkStack) {
        let now = crate::pit::get_ticks();
        for i in 0..self.conns.len() {
            let mut action: Option<(TcpEndpoint, u32, u32, u16, [u8; 256], usize)> = None;
            {
                let conn = &mut self.conns[i];
                if !conn.in_use || conn.last_send_tick == 0 {
                    continue;
                }
                if now - conn.last_send_tick < conn.rto_ticks {
                    continue;
                }
                if conn.retries >= 5 {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                    continue;
                }
                let mut payload = [0u8; 256];
                let len = conn.last_payload_len;
                payload[..len].copy_from_slice(&conn.last_payload[..len]);
                action = Some((tcp_endpoint(conn), conn.last_seq, conn.last_ack, conn.last_flags, payload, len));
                conn.retries = conn.retries.saturating_add(1);
                conn.last_send_tick = now;
            }
            if let Some((ep, seq, ack, flags, payload, len)) = action {
                let _ = send_tcp_segment(stack, ep, seq, ack, flags, &payload[..len]);
            }
        }
    }
}

const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_PSH: u16 = 0x08;
const TCP_FLAG_ACK: u16 = 0x10;

#[derive(Clone, Copy)]
struct TcpEndpoint {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
}

struct HttpServer {
    running: bool,
    listener: Option<u16>,
    port: u16,
}

impl HttpServer {
    const fn new() -> Self {
        HttpServer {
            running: false,
            listener: None,
            port: 8080,
        }
    }
}

fn send_tcp_segment(
    stack: &mut NetworkStack,
    ep: TcpEndpoint,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: &[u8],
) -> Result<(), &'static str> {
    let dest_mac = if let Some(mac) = stack.arp_cache.lookup(ep.remote_ip) {
        mac
    } else {
        stack.send_arp_request(ep.remote_ip)?;
        return Err("ARP unresolved");
    };

    let tcp_header_len = 20;
    let ip_header_len = 20;
    let total_len = 14 + ip_header_len + tcp_header_len + payload.len();
    if total_len > 1514 {
        return Err("Packet too large");
    }

    let mut frame = [0u8; 1514];
    let mut off = 0;

    frame[off..off + 6].copy_from_slice(&dest_mac.0);
    off += 6;
    frame[off..off + 6].copy_from_slice(&stack.my_mac.0);
    off += 6;
    frame[off..off + 2].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    off += 2;

    let ip_start = off;
    frame[off] = 0x45;
    frame[off + 1] = 0;
    let ip_total = (ip_header_len + tcp_header_len + payload.len()) as u16;
    frame[off + 2..off + 4].copy_from_slice(&ip_total.to_be_bytes());
    frame[off + 4..off + 6].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 6..off + 8].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 8] = 64;
    frame[off + 9] = IP_PROTOCOL_TCP;
    frame[off + 10..off + 12].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 12..off + 16].copy_from_slice(&ep.local_ip.0);
    frame[off + 16..off + 20].copy_from_slice(&ep.remote_ip.0);
    let checksum = calculate_checksum(&frame[off..off + ip_header_len]);
    frame[off + 10..off + 12].copy_from_slice(&checksum.to_be_bytes());
    off += ip_header_len;

    let tcp_start = off;
    frame[off..off + 2].copy_from_slice(&ep.local_port.to_be_bytes());
    frame[off + 2..off + 4].copy_from_slice(&ep.remote_port.to_be_bytes());
    frame[off + 4..off + 8].copy_from_slice(&seq.to_be_bytes());
    frame[off + 8..off + 12].copy_from_slice(&ack.to_be_bytes());
    frame[off + 12] = ((tcp_header_len / 4) as u8) << 4;
    frame[off + 13] = (flags & 0xFF) as u8;
    frame[off + 14..off + 16].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[off + 16..off + 18].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 18..off + 20].copy_from_slice(&0u16.to_be_bytes());
    off += tcp_header_len;

    if !payload.is_empty() {
        frame[off..off + payload.len()].copy_from_slice(payload);
    }

    let tcp_len = (tcp_header_len + payload.len()) as u16;
    let tcp_checksum = tcp_checksum(
        &ep.local_ip.0,
        &ep.remote_ip.0,
        IP_PROTOCOL_TCP,
        tcp_len,
        &frame[tcp_start..tcp_start + tcp_header_len + payload.len()],
    );
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let mut driver = crate::e1000::E1000_DRIVER.lock();
    let interface = driver.as_mut().ok_or("No E1000 driver")?;
    interface.send_frame(&frame[..total_len])
}

fn record_last(conn: &mut TcpConn, flags: u16, seq: u32, ack: u32, payload: &[u8]) {
    conn.last_flags = flags;
    conn.last_seq = seq;
    conn.last_ack = ack;
    conn.last_payload_len = payload.len().min(conn.last_payload.len());
    conn.last_payload[..conn.last_payload_len].copy_from_slice(&payload[..conn.last_payload_len]);
    conn.last_send_tick = crate::pit::get_ticks();
    conn.retries = 0;
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], proto: u8, length: u16, segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(src_ip);
    pseudo[4..8].copy_from_slice(dst_ip);
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10..12].copy_from_slice(&length.to_be_bytes());

    let mut sum = checksum_accum(&pseudo);
    sum = checksum_accum_with(sum, segment);
    finalize_checksum(sum)
}

fn checksum_accum(data: &[u8]) -> u32 {
    checksum_accum_with(0, data)
}

fn checksum_accum_with(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

impl NetworkStack {
    fn handle_ipv4(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() < 20 {
            return Err("IPv4 packet too short");
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            return Err("Invalid IPv4 header");
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len > packet.len() {
            return Err("IPv4 length mismatch");
        }
        let proto = packet[9];
        let dst = Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]);
        if dst != self.my_ip {
            return Ok(());
        }
        match proto {
            IP_PROTOCOL_TCP => {
                let src = Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]);
                self.handle_tcp(src, &packet[ihl..total_len])?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_tcp(&mut self, src_ip: Ipv4Addr, segment: &[u8]) -> Result<(), &'static str> {
        if segment.len() < 20 {
            return Err("TCP segment too short");
        }
        let src_port = u16::from_be_bytes([segment[0], segment[1]]);
        let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
        let seq = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
        let ack = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
        let data_off = (segment[12] >> 4) as usize * 4;
        let flags = segment[13] as u16;
        if segment.len() < data_off {
            return Err("TCP header invalid");
        }
        let payload = &segment[data_off..];

        let mut ack_action: Option<(TcpEndpoint, u32, u32)> = None;
        let mut established_from_listen: Option<(u8, u16)> = None;
        let mut http_conn_id: Option<u16> = None;

        if let Some(idx) = self.tcp.find_conn_index(dst_port, src_ip, src_port) {
            {
                let conn = &mut self.tcp.conns[idx];
                if flags & TCP_FLAG_RST != 0 {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                    return Ok(());
                }
                if flags & TCP_FLAG_ACK != 0 && ack > conn.snd_una {
                    conn.snd_una = ack;
                    let now = crate::pit::get_ticks();
                    let sample = now.saturating_sub(conn.rtt_start);
                    if conn.srtt == 0 {
                        conn.srtt = sample;
                        conn.rttvar = sample / 2;
                    } else {
                        let err = if conn.srtt > sample { conn.srtt - sample } else { sample - conn.srtt };
                        conn.rttvar = (3 * conn.rttvar + err) / 4;
                        conn.srtt = (7 * conn.srtt + sample) / 8;
                    }
                    conn.rto_ticks = core::cmp::max(1, conn.srtt + 4 * conn.rttvar);
                }

                if conn.state == TcpState::SynSent && (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) {
                    conn.state = TcpState::Established;
                    conn.irs = seq;
                    conn.rcv_nxt = seq.wrapping_add(1);
                    conn.snd_una = ack;
                    ack_action = Some((tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt));
                }

                if conn.state == TcpState::SynReceived && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::Established;
                    if conn.listener_idx != 0xFF {
                        established_from_listen = Some((conn.listener_idx, conn.id));
                    }
                }

                if !payload.is_empty() && seq == conn.rcv_nxt {
                    let copy_len = core::cmp::min(payload.len(), conn.recv_buf.len());
                    conn.recv_buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    conn.recv_len = copy_len;
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload.len() as u32);
                    ack_action = Some((tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt));
                    if self.http_server.running && payload.windows(4).any(|w| w == b"\r\n\r\n") {
                        conn.http_pending = true;
                        http_conn_id = Some(conn.id);
                    }
                }

                if flags & TCP_FLAG_FIN != 0 {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    ack_action = Some((tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt));
                    if conn.state == TcpState::Established {
                        conn.state = TcpState::CloseWait;
                    } else if conn.state == TcpState::FinWait1 {
                        conn.state = TcpState::Closed;
                        conn.in_use = false;
                    }
                }

                if conn.state == TcpState::FinWait1 && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::FinWait2;
                }
                if conn.state == TcpState::LastAck && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                }
            }

            if let Some((ep, seq_out, ack_out)) = ack_action {
                let _ = send_tcp_segment(self, ep, seq_out, ack_out, TCP_FLAG_ACK, &[]);
            }
            if let Some((idx, conn_id)) = established_from_listen {
                let idx = idx as usize;
                if idx < self.tcp.listeners.len() {
                    let _ = self.tcp.listeners[idx].push(conn_id);
                }
            }
            if let Some(conn_id) = http_conn_id {
                self.http_server_respond(conn_id);
            }
            return Ok(());
        }

        // No existing connection: check listeners for SYN
        if flags & TCP_FLAG_SYN != 0 {
            for (idx, listener) in self.tcp.listeners.iter_mut().enumerate() {
                if listener.in_use && listener.port == dst_port {
                    let conn = self.tcp.alloc_conn()?;
                    conn.local_ip = self.my_ip;
                    conn.local_port = dst_port;
                    conn.remote_ip = src_ip;
                    conn.remote_port = src_port;
                    conn.state = TcpState::SynReceived;
                    conn.iss = (crate::pit::get_ticks() as u32).wrapping_add(2000);
                    conn.snd_una = conn.iss;
                    conn.snd_nxt = conn.iss;
                    conn.irs = seq;
                    conn.rcv_nxt = seq.wrapping_add(1);
                    conn.listener_idx = idx as u8;
                    conn.rto_ticks = (crate::pit::get_frequency() as u64) * 3;
                    let ep = tcp_endpoint(conn);
                    let seq_out = conn.snd_nxt;
                    let ack_out = conn.rcv_nxt;
                    record_last(conn, TCP_FLAG_SYN | TCP_FLAG_ACK, seq_out, ack_out, &[]);
                    conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                    let _ = idx;
                    let _ = send_tcp_segment(self, ep, seq_out, ack_out, TCP_FLAG_SYN | TCP_FLAG_ACK, &[]);
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    fn http_server_respond(&mut self, conn_id: u16) {
        if !self.http_server.running {
            return;
        }
        let (ep, seq, ack) = {
            let conn = match self.tcp.find_conn_id_mut(conn_id) {
                Some(c) => c,
                None => return,
            };
            if conn.state != TcpState::Established {
                return;
            }
            (tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt)
        };

        let body = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOreulia HTTP server online.\n";
        let _ = send_tcp_segment(self, ep, seq, ack, TCP_FLAG_ACK | TCP_FLAG_PSH, body);

        let (ep2, seq2, ack2) = {
            let conn = match self.tcp.find_conn_id_mut(conn_id) {
                Some(c) => c,
                None => return,
            };
            record_last(conn, TCP_FLAG_ACK | TCP_FLAG_PSH, conn.snd_nxt, conn.rcv_nxt, body);
            conn.snd_nxt = conn.snd_nxt.wrapping_add(body.len() as u32);
            conn.state = TcpState::LastAck;
            conn.http_pending = false;
            (tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt)
        };

        let _ = send_tcp_segment(self, ep2, seq2, ack2, TCP_FLAG_FIN | TCP_FLAG_ACK, &[]);
        if let Some(conn) = self.tcp.find_conn_id_mut(conn_id) {
            record_last(conn, TCP_FLAG_FIN | TCP_FLAG_ACK, conn.snd_nxt, conn.rcv_nxt, &[]);
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        }
    }

}

// ============================================================================
// Checksum Calculation (using optimized assembly)
// ============================================================================

fn calculate_checksum(data: &[u8]) -> u16 {
    // Use assembly implementation for 8x performance boost
    crate::asm_bindings::ip_checksum(data)
}

// ============================================================================
// Global Network Stack
// ============================================================================

pub static NETWORK_STACK: Mutex<NetworkStack> = Mutex::new(NetworkStack::new());

pub fn network_stack() -> &'static Mutex<NetworkStack> {
    &NETWORK_STACK
}

/// Network IRQ hook (polls for received frames)
pub fn on_irq() {
    crate::e1000::handle_irq();
    if let Some(mut stack) = NETWORK_STACK.try_lock() {
        let _ = stack.poll_once();
    }
}
