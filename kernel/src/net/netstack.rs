/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Universal Network Stack
//!
//! Production TCP/IP stack with real packet I/O that works with any network interface.
//! Supports: ARP, ICMP, UDP, TCP, DNS, DHCP

#![allow(dead_code)]

extern crate alloc;

// ============================================================================
// Network Interface Trait (Universal Abstraction)
// ============================================================================

/// Universal network interface trait - implemented by E1000, WiFi, VirtIO, etc.
/// Boxed trait objects allow runtime polymorphism for different NICs
pub trait NetworkInterface: Send {
    /// Wire-format packet type for this interface.
    ///
    /// Using a fixed-size Ethernet MTU array keeps the type zero-alloc and
    /// trivially `Send + 'static` for use in interrupt/DMA paths.
    type Packet: Send + 'static;

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

const CAPNET_MAX_RETX: usize = 8;
const CAPNET_RETX_INTERVAL_TICKS: u64 = 25;
const CAPNET_RETX_MAX_RETRIES: u8 = 4;

// DNS negative-cache: remember NXDOMAIN/timeout results for DNS_NEG_TTL_TICKS ticks
// to avoid hammering the network for domains we know are unreachable.
const DNS_NEG_CACHE_SIZE: usize = 8;
const DNS_NEG_TTL_TICKS: u64 = 3000; // ~3 s at 1 kHz PIT
const DNS_DOMAIN_MAX: usize = 64;   // max stored domain length

#[derive(Clone, Copy)]
struct DnsNegEntry {
    active: bool,
    expires: u64,
    domain: [u8; DNS_DOMAIN_MAX],
    domain_len: u8,
}

impl DnsNegEntry {
    const fn empty() -> Self {
        DnsNegEntry {
            active: false,
            expires: 0,
            domain: [0u8; DNS_DOMAIN_MAX],
            domain_len: 0,
        }
    }
}
const TEMPORAL_NETWORK_CONFIG_BYTES: usize = 32;
const TEMPORAL_NETWORK_CONFIG_FLAG_DHCP: u8 = 1 << 0;
const TEMPORAL_NETWORK_CONFIG_FLAG_HAS_INTERFACE: u8 = 1 << 1;

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
// ARP Cache (hash-indexed for O(1) expected lookup)
// ============================================================================

/// Number of ARP cache slots.  Must be a power of two for the hash mask trick.
const ARP_CACHE_SIZE: usize = 16;
const ARP_CACHE_MASK: u32 = (ARP_CACHE_SIZE - 1) as u32;

struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    valid: bool,
}

struct ArpCache {
    entries: [ArpEntry; ARP_CACHE_SIZE],
    /// Round-robin victim pointer for collision eviction.
    lru_idx: usize,
}

impl ArpCache {
    const fn new() -> Self {
        const EMPTY: ArpEntry = ArpEntry {
            ip: Ipv4Addr([0, 0, 0, 0]),
            mac: MacAddr([0, 0, 0, 0, 0, 0]),
            valid: false,
        };

        ArpCache {
            entries: [EMPTY; ARP_CACHE_SIZE],
            lru_idx: 0,
        }
    }

    /// Hash an IPv4 address to a bucket index.
    ///
    /// Uses a multiplicative hash: multiply by a Knuth constant then take the
    /// top bits.  This spreads sequential IPs across the table much better
    /// than a simple modulo.
    ///
    /// $$b = \lfloor \text{ip} \times 2654435761 \rfloor \bmod 16$$
    #[inline]
    fn bucket(ip: Ipv4Addr) -> usize {
        let key = ip.to_u32().wrapping_mul(2_654_435_761u32);
        (key & ARP_CACHE_MASK) as usize
    }

    /// O(1) expected lookup: check primary bucket first, then linear probe.
    fn lookup(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        let start = Self::bucket(ip);
        // Probe up to ARP_CACHE_SIZE slots (full table scan worst-case with
        // wrap-around, but in practice almost always one comparison).
        for i in 0..ARP_CACHE_SIZE {
            let idx = (start + i) % ARP_CACHE_SIZE;
            let e = &self.entries[idx];
            if !e.valid {
                return None; // empty slot terminates probe chain
            }
            if e.ip == ip {
                return Some(e.mac);
            }
        }
        None
    }

    fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        let start = Self::bucket(ip);
        // First pass: update existing entry or claim an empty slot.
        for i in 0..ARP_CACHE_SIZE {
            let idx = (start + i) % ARP_CACHE_SIZE;
            let e = &mut self.entries[idx];
            if e.valid && e.ip == ip {
                e.mac = mac; // refresh
                return;
            }
            if !e.valid {
                e.ip = ip;
                e.mac = mac;
                e.valid = true;
                return;
            }
        }
        // Table full: evict using round-robin starting from victim pointer
        // to avoid repeatedly thrashing the primary bucket.
        let victim = self.lru_idx;
        self.lru_idx = (self.lru_idx + 1) % ARP_CACHE_SIZE;
        self.entries[victim].ip = ip;
        self.entries[victim].mac = mac;
        self.entries[victim].valid = true;
    }
}

#[derive(Clone, Copy)]
struct CapNetRetransmitEntry {
    active: bool,
    peer_device_id: u64,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    seq: u32,
    retries: u8,
    next_retry_tick: u64,
    len: usize,
    frame: [u8; super::capnet::CAPNET_CTRL_MAX_FRAME_LEN],
}

impl CapNetRetransmitEntry {
    const fn empty() -> Self {
        CapNetRetransmitEntry {
            active: false,
            peer_device_id: 0,
            dest_ip: Ipv4Addr([0, 0, 0, 0]),
            dest_port: 0,
            seq: 0,
            retries: 0,
            next_retry_tick: 0,
            len: 0,
            frame: [0u8; super::capnet::CAPNET_CTRL_MAX_FRAME_LEN],
        }
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
    capnet_retx: [CapNetRetransmitEntry; CAPNET_MAX_RETX],
    tcp: TcpManager,
    http_server: HttpServer,
    dns_neg_cache: [DnsNegEntry; DNS_NEG_CACHE_SIZE],
}

impl NetworkStack {
    pub const fn new() -> Self {
        NetworkStack {
            my_ip: Ipv4Addr([10, 0, 2, 15]),                       // QEMU default
            my_mac: MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]), // QEMU default
            gateway_ip: Ipv4Addr([10, 0, 2, 2]),                   // QEMU default gateway
            dns_server: Ipv4Addr([8, 8, 8, 8]),                    // Google DNS
            arp_cache: ArpCache::new(),
            dhcp_enabled: false,
            has_interface: false,
            capnet_retx: [CapNetRetransmitEntry::empty(); CAPNET_MAX_RETX],
            tcp: TcpManager::new(),
            http_server: HttpServer::new(),
            dns_neg_cache: [DnsNegEntry::empty(); DNS_NEG_CACHE_SIZE],
        }
    }

    /// Mark interface as available
    pub fn mark_ready(&mut self) {
        let prev_has_interface = self.has_interface;
        let prev_mac = self.my_mac;
        self.has_interface = true;
        if let Some(mac) = super::e1000::get_mac_address() {
            self.my_mac = MacAddr(mac);
        }
        if self.has_interface != prev_has_interface || self.my_mac != prev_mac {
            self.record_temporal_network_config_event(
                crate::temporal::TEMPORAL_NETWORK_CONFIG_EVENT_STATE,
            );
        }
    }

    /// Check if network is ready
    pub fn is_ready(&self) -> bool {
        // Check if E1000 driver is available
        super::e1000::get_mac_address().is_some()
    }

    // ========================================================================
    // ARP Protocol
    // ========================================================================

    /// Send ARP request
    fn send_arp_request(&mut self, target_ip: Ipv4Addr) -> Result<(), &'static str> {
        let mut driver = super::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;

        let mut frame = [0u8; 42];
        let mut offset = 0;

        // Ethernet header
        frame[offset..offset + 6].copy_from_slice(&MacAddr::BROADCAST.0); // Dest MAC
        offset += 6;
        frame[offset..offset + 6].copy_from_slice(&self.my_mac.0); // Src MAC
        offset += 6;
        frame[offset..offset + 2].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes()); // EtherType
        offset += 2;

        // ARP packet
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
        offset += 2;
        frame[offset] = 6; // Hardware size
        offset += 1;
        frame[offset] = 4; // Protocol size
        offset += 1;
        frame[offset..offset + 2].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes()); // Operation
        offset += 2;
        frame[offset..offset + 6].copy_from_slice(&self.my_mac.0); // Sender MAC
        offset += 6;
        frame[offset..offset + 4].copy_from_slice(&self.my_ip.0); // Sender IP
        offset += 4;
        frame[offset..offset + 6].copy_from_slice(&[0; 6]); // Target MAC (unknown)
        offset += 6;
        frame[offset..offset + 4].copy_from_slice(&target_ip.0); // Target IP

        interface.send_frame(&frame)
    }

    /// Process received ARP packet
    fn handle_arp(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() < 28 {
            return Err("ARP packet too short");
        }

        let op = u16::from_be_bytes([packet[6], packet[7]]);
        let sender_mac = MacAddr([
            packet[8], packet[9], packet[10], packet[11], packet[12], packet[13],
        ]);
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
        let mut driver = super::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;

        let mut frame = [0u8; 42];
        let mut offset = 0;

        // Ethernet header
        frame[offset..offset + 6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset + 6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset + 2].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        offset += 2;

        // ARP packet
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x01]);
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x08, 0x00]);
        offset += 2;
        frame[offset] = 6;
        offset += 1;
        frame[offset] = 4;
        offset += 1;
        frame[offset..offset + 2].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
        offset += 2;
        frame[offset..offset + 6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset + 4].copy_from_slice(&self.my_ip.0);
        offset += 4;
        frame[offset..offset + 6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset + 4].copy_from_slice(&dest_ip.0);

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
                unsafe {
                    core::arch::asm!("nop");
                }
            }
        }

        Err("ARP timeout")
    }

    // ========================================================================
    // UDP Protocol
    // ========================================================================

    /// Send UDP packet
    fn send_udp(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        src_port: u16,
        data: &[u8],
    ) -> Result<(), &'static str> {
        if data.len() > 1472 {
            // Max UDP payload in standard Ethernet
            return Err("UDP payload too large");
        }

        // Resolve destination MAC (use gateway for external IPs)
        let next_hop = if self.is_local(dest_ip) {
            dest_ip
        } else {
            self.gateway_ip
        };
        let dest_mac = self.resolve_mac(next_hop)?;

        // Use E1000 driver directly
        let mut driver = super::e1000::E1000_DRIVER.lock();
        let driver = driver.as_mut().ok_or("No E1000 driver")?;

        // Build packet
        let mut frame = [0u8; 1514];
        let mut offset = 0;

        // Ethernet header (14 bytes)
        frame[offset..offset + 6].copy_from_slice(&dest_mac.0);
        offset += 6;
        frame[offset..offset + 6].copy_from_slice(&self.my_mac.0);
        offset += 6;
        frame[offset..offset + 2].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        offset += 2;

        // IPv4 header (20 bytes)
        let ip_header_start = offset;
        frame[offset] = 0x45; // Version 4, header length 5 (20 bytes)
        offset += 1;
        frame[offset] = 0; // DSCP/ECN
        offset += 1;
        let total_len = 20 + 8 + data.len(); // IP header + UDP header + data
        frame[offset..offset + 2].copy_from_slice(&(total_len as u16).to_be_bytes());
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Identification
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Flags/Fragment
        offset += 2;
        frame[offset] = 64; // TTL
        offset += 1;
        frame[offset] = IP_PROTOCOL_UDP;
        offset += 1;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Checksum (filled later)
        let ip_checksum_offset = offset - 2;
        offset += 2;
        frame[offset..offset + 4].copy_from_slice(&self.my_ip.0);
        offset += 4;
        frame[offset..offset + 4].copy_from_slice(&dest_ip.0);
        offset += 4;

        // Calculate IP checksum
        let ip_checksum = calculate_checksum(&frame[ip_header_start..offset]);
        frame[ip_checksum_offset..ip_checksum_offset + 2]
            .copy_from_slice(&ip_checksum.to_be_bytes());

        // UDP header (8 bytes)
        frame[offset..offset + 2].copy_from_slice(&src_port.to_be_bytes());
        offset += 2;
        frame[offset..offset + 2].copy_from_slice(&dest_port.to_be_bytes());
        offset += 2;
        let udp_len = 8 + data.len();
        frame[offset..offset + 2].copy_from_slice(&(udp_len as u16).to_be_bytes());
        offset += 2;
        let udp_checksum_offset = offset;
        frame[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // filled below
        offset += 2;

        // UDP payload
        frame[offset..offset + data.len()].copy_from_slice(data);
        offset += data.len();

        // RFC 768 / RFC 1071: compute UDP checksum over pseudo-header + UDP segment.
        // Use the same tcp_checksum() helper (pseudo-header is protocol-agnostic).
        let udp_seg_len = (2 + 2 + 2 + 2 + data.len()) as u16; // src+dst port + len + cksum + payload
        let udp_ck = tcp_checksum(
            &self.my_ip.0,
            &dest_ip.0,
            IP_PROTOCOL_UDP,
            udp_seg_len,
            &frame[udp_checksum_offset - 4..offset], // full UDP header+payload
        );
        frame[udp_checksum_offset..udp_checksum_offset + 2].copy_from_slice(&udp_ck.to_be_bytes());

        driver.send_frame(&frame[..offset])
    }

    /// Receive UDP packet (simplified - returns payload if matches port)
    fn recv_udp(&mut self, expected_port: u16, buffer: &mut [u8]) -> Result<usize, &'static str> {
        // Use E1000 driver directly
        let mut driver = super::e1000::E1000_DRIVER.lock();
        let driver = driver.as_mut().ok_or("No E1000 driver")?;

        let mut frame = [0u8; 1514];
        let frame_len = driver.recv_frame(&mut frame)?;

        if frame_len < 42 {
            // Min: Eth(14) + IP(20) + UDP(8)
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
        let udp_offset = 14 + 20; // After Ethernet + IP
        let dest_port = u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]);

        if dest_port != expected_port {
            return Err("Wrong port");
        }

        let udp_len = u16::from_be_bytes([frame[udp_offset + 4], frame[udp_offset + 5]]) as usize;
        let payload_len = udp_len - 8; // Subtract UDP header

        if payload_len > buffer.len() {
            return Err("Buffer too small");
        }

        buffer[..payload_len].copy_from_slice(&frame[udp_offset + 8..udp_offset + 8 + payload_len]);
        Ok(payload_len)
    }

    // ========================================================================
    // CapNet Control Channel (UDP)
    // ========================================================================

    pub fn capnet_send_hello(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
    ) -> Result<u32, &'static str> {
        let frame = super::capnet::build_hello_frame(peer_device_id, 0).map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        self.capnet_queue_retx(
            peer_device_id,
            dest_ip,
            dest_port,
            frame.seq,
            &frame.bytes[..frame.len],
        )?;
        Ok(frame.seq)
    }

    pub fn capnet_send_attest(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
        ack: u32,
    ) -> Result<u32, &'static str> {
        let frame = super::capnet::build_attest_frame(peer_device_id, ack)
            .map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        self.capnet_queue_retx(
            peer_device_id,
            dest_ip,
            dest_port,
            frame.seq,
            &frame.bytes[..frame.len],
        )?;
        Ok(frame.seq)
    }

    pub fn capnet_send_heartbeat(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
        ack: u32,
        ack_only: bool,
    ) -> Result<u32, &'static str> {
        let frame = super::capnet::build_heartbeat_frame(peer_device_id, ack, ack_only)
            .map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        if !ack_only {
            self.capnet_queue_retx(
                peer_device_id,
                dest_ip,
                dest_port,
                frame.seq,
                &frame.bytes[..frame.len],
            )?;
        }
        Ok(frame.seq)
    }

    pub fn capnet_send_token_offer(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
        mut token: super::capnet::CapabilityTokenV1,
    ) -> Result<u64, &'static str> {
        let frame = super::capnet::build_token_offer_frame(peer_device_id, 0, &mut token)
            .map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        self.capnet_queue_retx(
            peer_device_id,
            dest_ip,
            dest_port,
            frame.seq,
            &frame.bytes[..frame.len],
        )?;
        Ok(frame.token_id)
    }

    pub fn capnet_send_token_accept(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
        token_id: u64,
        ack: u32,
    ) -> Result<u32, &'static str> {
        let frame = super::capnet::build_token_accept_frame(peer_device_id, ack, token_id)
            .map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        // Token-accept frames are ack-only confirmations and do not need retransmit queueing.
        Ok(frame.seq)
    }

    pub fn capnet_send_token_revoke(
        &mut self,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        peer_device_id: u64,
        token_id: u64,
    ) -> Result<u32, &'static str> {
        let frame = super::capnet::build_token_revoke_frame(peer_device_id, 0, token_id)
            .map_err(|e| e.as_str())?;
        self.send_udp(
            dest_ip,
            dest_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &frame.bytes[..frame.len],
        )?;
        self.capnet_queue_retx(
            peer_device_id,
            dest_ip,
            dest_port,
            frame.seq,
            &frame.bytes[..frame.len],
        )?;
        Ok(frame.seq)
    }

    fn capnet_queue_retx(
        &mut self,
        peer_device_id: u64,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        seq: u32,
        frame: &[u8],
    ) -> Result<(), &'static str> {
        if seq == 0 {
            return Ok(());
        }
        if frame.len() > super::capnet::CAPNET_CTRL_MAX_FRAME_LEN {
            return Err("CapNet frame too large");
        }
        let mut free_idx = None;
        for i in 0..self.capnet_retx.len() {
            let slot = &self.capnet_retx[i];
            if slot.active && slot.peer_device_id == peer_device_id && slot.seq == seq {
                return Ok(());
            }
            if !slot.active && free_idx.is_none() {
                free_idx = Some(i);
            }
        }
        let idx = free_idx.ok_or("CapNet retransmit queue full")?;
        let mut slot = CapNetRetransmitEntry::empty();
        slot.active = true;
        slot.peer_device_id = peer_device_id;
        slot.dest_ip = dest_ip;
        slot.dest_port = dest_port;
        slot.seq = seq;
        slot.retries = 0;
        slot.next_retry_tick = crate::pit::get_ticks().saturating_add(CAPNET_RETX_INTERVAL_TICKS);
        slot.len = frame.len();
        slot.frame[..frame.len()].copy_from_slice(frame);
        self.capnet_retx[idx] = slot;
        Ok(())
    }

    fn capnet_ack_seq(&mut self, peer_device_id: u64, ack: u32) {
        if ack == 0 {
            return;
        }
        for i in 0..self.capnet_retx.len() {
            let slot = &mut self.capnet_retx[i];
            if slot.active && slot.peer_device_id == peer_device_id && slot.seq == ack {
                slot.active = false;
                slot.len = 0;
                slot.retries = 0;
            }
        }
    }

    fn capnet_retx_tick(&mut self, now: u64) {
        for i in 0..self.capnet_retx.len() {
            let mut frame_copy = [0u8; super::capnet::CAPNET_CTRL_MAX_FRAME_LEN];
            let (dest_ip, dest_port, len, should_send) = {
                let slot = &mut self.capnet_retx[i];
                if !slot.active || now < slot.next_retry_tick {
                    (Ipv4Addr([0, 0, 0, 0]), 0u16, 0usize, false)
                } else if slot.retries >= CAPNET_RETX_MAX_RETRIES {
                    slot.active = false;
                    crate::security::security().log_event(
                        crate::security::AuditEntry::new(
                            crate::security::SecurityEvent::RateLimitExceeded,
                            crate::ipc::ProcessId(0),
                            0,
                        )
                        .with_context(slot.seq as u64),
                    );
                    (Ipv4Addr([0, 0, 0, 0]), 0u16, 0usize, false)
                } else {
                    slot.retries = slot.retries.saturating_add(1);
                    // Exponential backoff: base * 2^min(retries, 4) — caps at 16x = 400 ticks
                    let backoff_shift = (slot.retries as u32).min(4);
                    slot.next_retry_tick = now.saturating_add(CAPNET_RETX_INTERVAL_TICKS << backoff_shift);
                    frame_copy[..slot.len].copy_from_slice(&slot.frame[..slot.len]);
                    (slot.dest_ip, slot.dest_port, slot.len, true)
                }
            };
            if should_send {
                let _ = self.send_udp(
                    dest_ip,
                    dest_port,
                    super::capnet::CAPNET_CONTROL_PORT,
                    &frame_copy[..len],
                );
            }
        }
    }

    // ========================================================================
    // DNS Protocol
    // ========================================================================

    /// Resolve domain name to IP address
    pub fn dns_resolve(&mut self, domain: &str) -> Result<Ipv4Addr, &'static str> {
        if domain.len() > 253 {
            return Err("Domain name too long");
        }

        // ---- Negative-cache check ----
        let now = crate::pit::get_ticks();
        let dlen = domain.len().min(DNS_DOMAIN_MAX);
        for slot in self.dns_neg_cache.iter_mut() {
            if !slot.active { continue; }
            if now >= slot.expires { slot.active = false; continue; }
            if slot.domain_len as usize == dlen
                && slot.domain[..dlen] == domain.as_bytes()[..dlen]
            {
                return Err("DNS negative cache");
            }
        }

        // Build DNS query
        let mut query = [0u8; 512];
        let mut offset = 0;

        // DNS header
        let txid = (crate::pit::get_ticks() as u16).wrapping_add(0xA5C3); // pseudo-random TX ID
        query[offset..offset + 2].copy_from_slice(&txid.to_be_bytes()); // Transaction ID (randomized)
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x01, 0x00]); // Flags: standard query
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Questions: 1
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Answer RRs: 0
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Authority RRs: 0
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x00, 0x00]); // Additional RRs: 0
        offset += 2;

        // Question: encode domain name
        for label in domain.split('.') {
            if label.len() > 63 {
                return Err("Label too long");
            }
            query[offset] = label.len() as u8;
            offset += 1;
            query[offset..offset + label.len()].copy_from_slice(label.as_bytes());
            offset += label.len();
        }
        query[offset] = 0; // End of domain name
        offset += 1;

        query[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Type: A (IPv4)
        offset += 2;
        query[offset..offset + 2].copy_from_slice(&[0x00, 0x01]); // Class: IN (Internet)
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
                        unsafe {
                            core::arch::asm!("nop");
                        }
                    }
                }
            }
        }

        // ---- Insert into negative cache on timeout ----
        let now = crate::pit::get_ticks();
        let dlen = domain.len().min(DNS_DOMAIN_MAX);
        // Find free slot or evict oldest
        let mut oldest_idx = 0usize;
        let mut oldest_exp = u64::MAX;
        let mut inserted = false;
        for (i, slot) in self.dns_neg_cache.iter_mut().enumerate() {
            if !slot.active || now >= slot.expires {
                slot.active = true;
                slot.expires = now.saturating_add(DNS_NEG_TTL_TICKS);
                slot.domain_len = dlen as u8;
                slot.domain = [0u8; DNS_DOMAIN_MAX];
                slot.domain[..dlen].copy_from_slice(&domain.as_bytes()[..dlen]);
                inserted = true;
                break;
            }
            if slot.expires < oldest_exp {
                oldest_exp = slot.expires;
                oldest_idx = i;
            }
        }
        if !inserted {
            let slot = &mut self.dns_neg_cache[oldest_idx];
            slot.active = true;
            slot.expires = now.saturating_add(DNS_NEG_TTL_TICKS);
            slot.domain_len = dlen as u8;
            slot.domain = [0u8; DNS_DOMAIN_MAX];
            slot.domain[..dlen].copy_from_slice(&domain.as_bytes()[..dlen]);
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

        offset += 4; // Skip QTYPE and QCLASS

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

            let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;

            // Check for A record (IPv4)
            if rtype == 1 && rdlength == 4 {
                return Ok(Ipv4Addr([
                    response[offset],
                    response[offset + 1],
                    response[offset + 2],
                    response[offset + 3],
                ]));
            }

            offset += rdlength;
        }

        Err("No A record found")
    }

    // ========================================================================
    // Packet Processing
    // ========================================================================

    /// Poll for incoming packets once (reads from NIC internally).
    pub fn poll_once(&mut self) -> Result<(), &'static str> {
        let mut frame = [0u8; 1514];
        let frame_len = {
            let mut driver = super::e1000::E1000_DRIVER.lock();
            let interface = driver.as_mut().ok_or("No E1000 driver")?;
            match interface.recv_frame(&mut frame) {
                Ok(len) => len,
                Err(_) => return Ok(()), // No packet available
            }
        };

        self.dispatch_frame(&frame[..frame_len])
    }

    /// Dispatch a pre-read Ethernet frame through the protocol stack.
    ///
    /// Used by the burst-drain path in `net_reactor` which reads frames from
    /// the NIC in bulk (single lock) and then processes them without holding
    /// the NIC lock.
    pub fn dispatch_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() < 14 {
            return Ok(()); // Too short
        }

        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        match ethertype {
            ETHERTYPE_ARP => {
                let _ = self.handle_arp(&frame[14..]);
            }
            ETHERTYPE_IPV4 => {
                let _ = self.handle_ipv4(&frame[14..]);
            }
            _ => {}
        }

        Ok(())
    }

    /// Timer tick for retransmission/timers
    pub fn tick(&mut self) {
        let now = crate::pit::get_ticks();
        self.capnet_retx_tick(now);
        for i in 0..self.tcp.conns.len() {
            let action;
            {
                let conn = &mut self.tcp.conns[i];
                if !conn.in_use || conn.last_send_tick == 0 {
                    continue;
                }
                if now - conn.last_send_tick < conn.rto_ticks {
                    continue;
                }
                if conn.retries >= 5 {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE,
                        conn.retries as u32,
                    );
                    continue;
                }
                let mut payload = [0u8; 256];
                let len = conn.last_payload_len;
                payload[..len].copy_from_slice(&conn.last_payload[..len]);
                action = Some((
                    tcp_endpoint(conn),
                    conn.last_seq,
                    conn.last_ack,
                    conn.last_flags,
                    payload,
                    len,
                ));
                conn.retries = conn.retries.saturating_add(1);
                conn.last_send_tick = now;
            }
            if let Some((ep, seq, ack, flags, payload, len)) = action {
                let _ = send_tcp_segment(self, ep, seq, ack, flags, &payload[..len], TCP_BUF_SIZE as u16);
            }
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn is_local(&self, ip: Ipv4Addr) -> bool {
        // Simple check: same /24 network
        ip.0[0] == self.my_ip.0[0] && ip.0[1] == self.my_ip.0[1] && ip.0[2] == self.my_ip.0[2]
    }

    pub fn get_ip(&self) -> Ipv4Addr {
        self.my_ip
    }

    pub fn set_dns_server(&mut self, dns: Ipv4Addr) {
        if self.dns_server == dns {
            return;
        }
        self.dns_server = dns;
        self.record_temporal_network_config_event(
            crate::temporal::TEMPORAL_NETWORK_CONFIG_EVENT_STATE,
        );
    }

    fn record_temporal_network_config_event(&self, event: u8) {
        if crate::temporal::is_replay_active() {
            return;
        }
        let mut payload = [0u8; TEMPORAL_NETWORK_CONFIG_BYTES];
        payload[0] = crate::temporal::TEMPORAL_OBJECT_ENCODING_V1;
        payload[1] = crate::temporal::TEMPORAL_NETWORK_CONFIG_OBJECT;
        payload[2] = event;
        let mut flags = 0u8;
        if self.dhcp_enabled {
            flags |= TEMPORAL_NETWORK_CONFIG_FLAG_DHCP;
        }
        if self.has_interface {
            flags |= TEMPORAL_NETWORK_CONFIG_FLAG_HAS_INTERFACE;
        }
        payload[3] = flags;
        payload[4..8].copy_from_slice(&self.my_ip.0);
        payload[8..14].copy_from_slice(&self.my_mac.0);
        payload[14..18].copy_from_slice(&self.gateway_ip.0);
        payload[18..22].copy_from_slice(&self.dns_server.0);
        payload[22..30].copy_from_slice(&crate::pit::get_ticks().to_le_bytes());
        let _ = crate::temporal::record_network_config_event(&payload);
    }

    pub fn temporal_apply_network_config_event(
        &mut self,
        my_ip: Ipv4Addr,
        my_mac: MacAddr,
        gateway_ip: Ipv4Addr,
        dns_server: Ipv4Addr,
        flags: u8,
        event: u8,
    ) -> Result<(), &'static str> {
        if event != crate::temporal::TEMPORAL_NETWORK_CONFIG_EVENT_STATE {
            return Err("Temporal network config event unsupported");
        }
        self.my_ip = my_ip;
        self.my_mac = my_mac;
        self.gateway_ip = gateway_ip;
        self.dns_server = dns_server;
        self.dhcp_enabled = (flags & TEMPORAL_NETWORK_CONFIG_FLAG_DHCP) != 0;
        self.has_interface = (flags & TEMPORAL_NETWORK_CONFIG_FLAG_HAS_INTERFACE) != 0;
        Ok(())
    }

    // ========================================================================
    // TCP Socket API
    // ========================================================================

    pub fn tcp_listen(&mut self, port: u16) -> Result<u16, &'static str> {
        let result = self.tcp.listen(port);
        if let Ok(listener_id) = result {
            let _ = crate::temporal::record_tcp_socket_listener_event(
                listener_id as u32,
                port,
                crate::temporal::TEMPORAL_SOCKET_EVENT_LISTEN,
            );
        }
        result
    }

    pub fn tcp_accept(&mut self, listener: u16) -> Option<u16> {
        let accepted = self.tcp.accept(listener);
        if let Some(conn_id) = accepted {
            if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                let _ = crate::temporal::record_tcp_socket_state_event(
                    conn.id as u32,
                    conn.state as u8,
                    conn.local_ip.0,
                    conn.local_port,
                    conn.remote_ip.0,
                    conn.remote_port,
                    crate::temporal::TEMPORAL_SOCKET_EVENT_ACCEPT,
                    listener as u32,
                );
            }
        }
        accepted
    }

    pub fn tcp_connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Result<u16, &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.connect(self, remote_ip, remote_port);
        self.tcp = tcp;
        if let Ok(conn_id) = res {
            if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                let _ = crate::temporal::record_tcp_socket_state_event(
                    conn.id as u32,
                    conn.state as u8,
                    conn.local_ip.0,
                    conn.local_port,
                    conn.remote_ip.0,
                    conn.remote_port,
                    crate::temporal::TEMPORAL_SOCKET_EVENT_CONNECT,
                    0,
                );
            }
        }
        res
    }

    pub fn tcp_send(&mut self, conn_id: u16, data: &[u8]) -> Result<usize, &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.send(self, conn_id, data);
        if let Ok(sent) = res {
            if sent > 0 {
                if let Some(conn) = tcp.find_conn_id(conn_id) {
                    let _ = crate::temporal::record_tcp_socket_data_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_SEND,
                        &data[..sent],
                    );
                }
            }
        }
        self.tcp = tcp;
        res
    }

    pub fn tcp_recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.recv(conn_id, out);
        if let Ok(read_len) = res {
            if read_len > 0 {
                if let Some(conn) = tcp.find_conn_id(conn_id) {
                    let _ = crate::temporal::record_tcp_socket_data_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_RECV,
                        &out[..read_len],
                    );
                }
            }
        }
        self.tcp = tcp;
        res
    }

    pub fn tcp_close(&mut self, conn_id: u16) -> Result<(), &'static str> {
        let pre_close_snapshot = self.tcp.find_conn_id(conn_id).copied();
        let mut tcp = core::mem::replace(&mut self.tcp, TcpManager::new());
        let res = tcp.close(self, conn_id);
        if res.is_ok() {
            if let Some(mut conn) = pre_close_snapshot {
                if let Some(updated) = tcp.find_conn_id(conn_id) {
                    conn = *updated;
                } else {
                    conn.state = TcpState::Closed;
                }
                let _ = crate::temporal::record_tcp_socket_state_event(
                    conn.id as u32,
                    conn.state as u8,
                    conn.local_ip.0,
                    conn.local_port,
                    conn.remote_ip.0,
                    conn.remote_port,
                    crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE,
                    0,
                );
            }
        }
        self.tcp = tcp;
        res
    }

    pub fn tcp_stats(&self) -> (usize, usize) {
        (self.tcp.active_count(), self.tcp.listener_count())
    }

    pub fn temporal_apply_tcp_listener_event(
        &mut self,
        listener_id: u16,
        port: u16,
        event: u8,
    ) -> Result<(), &'static str> {
        match event {
            crate::temporal::TEMPORAL_SOCKET_EVENT_LISTEN
            | crate::temporal::TEMPORAL_SOCKET_EVENT_ACCEPT
            | crate::temporal::TEMPORAL_SOCKET_EVENT_STATE => {
                let listener = self.tcp.ensure_listener_slot(listener_id)?;
                listener.in_use = true;
                listener.port = port;
            }
            crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE => {
                self.tcp.clear_listener_slot(listener_id);
            }
            _ => {}
        }
        Ok(())
    }

    pub fn temporal_apply_tcp_connection_event(
        &mut self,
        conn_id: u16,
        state_raw: u8,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        event: u8,
        aux: u32,
        preview: &[u8],
    ) -> Result<(), &'static str> {
        let state = tcp_state_from_temporal(state_raw);
        if event == crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE || state == TcpState::Closed {
            if let Some(conn) = self.tcp.find_conn_id_mut(conn_id) {
                conn.state = TcpState::Closed;
                conn.recv_len = 0;
                conn.in_use = false;
            }
            return Ok(());
        }

        let mut enqueue_listener: Option<usize> = None;
        {
            let conn = self.tcp.ensure_conn_with_id(conn_id)?;
            conn.in_use = true;
            conn.state = state;
            conn.local_ip = local_ip;
            conn.local_port = local_port;
            conn.remote_ip = remote_ip;
            conn.remote_port = remote_port;
            conn.http_pending = false;

            if event == crate::temporal::TEMPORAL_SOCKET_EVENT_ACCEPT {
                let listener_idx = aux as usize;
                conn.listener_idx = listener_idx as u8;
                enqueue_listener = Some(listener_idx);
            }

            if event == crate::temporal::TEMPORAL_SOCKET_EVENT_RECV {
                let copy_len = core::cmp::min(preview.len(), conn.recv_buf.len());
                if copy_len > 0 {
                    conn.recv_buf[..copy_len].copy_from_slice(&preview[..copy_len]);
                }
                conn.recv_len = copy_len;
            } else if event == crate::temporal::TEMPORAL_SOCKET_EVENT_SEND {
                let copy_len = core::cmp::min(preview.len(), conn.last_payload.len());
                if copy_len > 0 {
                    conn.last_payload[..copy_len].copy_from_slice(&preview[..copy_len]);
                }
                conn.last_payload_len = copy_len;
                conn.last_send_tick = crate::pit::get_ticks();
            }
        }

        if let Some(listener_idx) = enqueue_listener {
            if listener_idx < self.tcp.listeners.len() {
                let _ = self.tcp.listeners[listener_idx].push(conn_id);
            }
        }

        Ok(())
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
    TimeWait,
    CloseWait,
    LastAck,
}

const MAX_TCP_CONNS: usize = 16;
const MAX_TCP_LISTEN: usize = 4;
const MAX_TCP_BACKLOG: usize = 4;
const TCP_BUF_SIZE: usize = 65_535;
/// 2×MSL for the edge/embedded profile: 30 seconds at 100 Hz = 3,000 ticks.
const TCP_TIME_WAIT_TICKS: u64 = 3_000;
/// Delayed ACK: flush after this many unacknowledged segments (RFC 5681 §3.2).
const TCP_DELAYED_ACK_SEGMENTS: u8 = 2;
/// Delayed ACK: flush after this many ticks of silence (200 ms at 100 Hz).
const TCP_DELAYED_ACK_TICKS: u64 = 20;
/// RFC 1323 window scale shift: 2^4 = 16 → effective window 65535 × 16 = 1 MB.
const TCP_WSCALE: u8 = 4;
/// Effective maximum receive window after applying wscale.
const TCP_MAX_WINDOW: u32 = (TCP_BUF_SIZE as u32) << TCP_WSCALE;

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
    last_payload: [u8; 1460],
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
    /// Number of received segments not yet acknowledged (delayed-ACK counter).
    ack_pending: u8,
    /// Tick at which the first unacknowledged segment arrived.
    ack_pending_since: u64,
    /// Peer's window scale shift count (from SYN/SYN-ACK options; 0 if not negotiated).
    peer_wscale: u8,
    /// Peer's current send window in bytes (raw window × 2^peer_wscale).
    /// We must not send beyond conn.snd_una + snd_wnd.
    snd_wnd: u32,
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
            last_payload: [0u8; 1460],
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
            ack_pending: 0,
            ack_pending_since: 0,
            peer_wscale: 0,
            snd_wnd: 65_535, // conservative default until first ACK
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

/// Walk the TCP option bytes from a SYN or SYN-ACK and return the wscale
/// shift count (option kind = 3) if present, or `None` if the peer did not
/// include a window-scale option.
///
/// Option format (RFC 7323 §2):
///   EOL  (kind=0): 1-byte, stop parsing
///   NOP  (kind=1): 1-byte, skip
///   MSS  (kind=2): 4-byte total
///   WSCALE (kind=3): 3-byte total: [3, 3, shift_count]
fn parse_tcp_wscale_option(opts: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,               // EOL
            1 => { i += 1; }          // NOP
            kind => {
                if i + 1 >= opts.len() { break; }
                let len = opts[i + 1] as usize;
                if len < 2 { break; } // malformed
                if kind == 3 && len == 3 && i + 2 < opts.len() {
                    // Window scale: shift count is the 3rd byte
                    let shift = opts[i + 2];
                    // RFC 7323: shift count must be ≤ 14
                    return Some(shift.min(14));
                }
                i += len;
            }
        }
    }
    None
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

    fn ensure_listener_slot(&mut self, listener_id: u16) -> Result<&mut TcpListener, &'static str> {
        let idx = listener_id as usize;
        if idx >= self.listeners.len() {
            return Err("Invalid listener id");
        }
        Ok(&mut self.listeners[idx])
    }

    fn clear_listener_slot(&mut self, listener_id: u16) {
        let idx = listener_id as usize;
        if idx < self.listeners.len() {
            self.listeners[idx] = TcpListener::empty();
        }
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

    fn find_conn_mut(
        &mut self,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<&mut TcpConn> {
        self.conns.iter_mut().find(|c| {
            c.in_use
                && c.local_port == local_port
                && c.remote_port == remote_port
                && c.remote_ip == remote_ip
        })
    }

    fn find_conn_id_mut(&mut self, conn_id: u16) -> Option<&mut TcpConn> {
        self.conns.iter_mut().find(|c| c.in_use && c.id == conn_id)
    }

    fn find_conn_id(&self, conn_id: u16) -> Option<&TcpConn> {
        self.conns.iter().find(|c| c.in_use && c.id == conn_id)
    }

    fn ensure_conn_with_id(&mut self, conn_id: u16) -> Result<&mut TcpConn, &'static str> {
        if let Some(idx) = self.conns.iter().position(|c| c.in_use && c.id == conn_id) {
            return Ok(&mut self.conns[idx]);
        }

        let mut slot_idx = None;
        let mut i = 0usize;
        while i < self.conns.len() {
            if !self.conns[i].in_use {
                slot_idx = Some(i);
                break;
            }
            i += 1;
        }
        let idx = slot_idx.ok_or("No connection slots")?;

        self.conns[idx] = TcpConn::empty();
        self.conns[idx].in_use = true;
        self.conns[idx].id = conn_id;
        if self.next_id <= conn_id {
            self.next_id = conn_id.wrapping_add(1).max(1);
        }
        Ok(&mut self.conns[idx])
    }

    fn find_conn_index(
        &self,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<usize> {
        self.conns
            .iter()
            .enumerate()
            .find(|(_, c)| {
                c.in_use
                    && c.local_port == local_port
                    && c.remote_port == remote_port
                    && c.remote_ip == remote_ip
            })
            .map(|(i, _)| i)
    }

    fn connect(
        &mut self,
        stack: &mut NetworkStack,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Result<u16, &'static str> {
        let local_port = 40000 + (self.next_id % 10000);
        // RFC 6528: derive ISN from a keyed hash of the 4-tuple + tick to prevent
        // ISN prediction attacks.  SipHash-2-4 is already in the kernel.
        let tick = crate::pit::get_ticks();
        let ip_seed = u32::from_be_bytes(stack.my_ip.0) as u64;
        let remote_seed = u32::from_be_bytes(remote_ip.0) as u64;
        let k0 = tick ^ (ip_seed << 32 | remote_seed);
        let k1 = ((local_port as u64) << 16 | remote_port as u64)
            ^ tick.wrapping_add(0xDEAD_BEEF_CAFE_0011u64);
        let mut isn_data = [0u8; 12];
        isn_data[0..4].copy_from_slice(&stack.my_ip.0);
        isn_data[4..8].copy_from_slice(&remote_ip.0);
        isn_data[8..10].copy_from_slice(&local_port.to_le_bytes());
        isn_data[10..12].copy_from_slice(&remote_port.to_le_bytes());
        let iss = crate::security::security().cap_token_sign_with_key(k0, k1, &isn_data) as u32;
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
        let adv_win = conn_recv_window(conn);
        if let Err(e) = send_syn_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_SYN, adv_win) {
            conn.state = TcpState::Closed;
            conn.in_use = false;
            return Err(e);
        }
        record_last(conn, TCP_FLAG_SYN, conn.snd_nxt, conn.rcv_nxt, &[]);
        conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        Ok(conn.id)
    }

    fn send(
        &mut self,
        stack: &mut NetworkStack,
        conn_id: u16,
        data: &[u8],
    ) -> Result<usize, &'static str> {
        let conn = self
            .find_conn_id_mut(conn_id)
            .ok_or("Connection not found")?;
        if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
            return Err("Connection not established");
        }
        // RFC 5681 §3: respect the send window.  Pipeline as many full MSS
        // segments as the window allows, then send any remainder.
        const MSS: usize = 1460;
        let mut sent_total = 0usize;
        while sent_total < data.len() {
            // Peer's current receive window (from last ACK, already scaled).
            // Also bounded by our own TCP_MAX_WINDOW to avoid runaway.
            let peer_window = (conn.snd_wnd as usize).min(TCP_MAX_WINDOW as usize);
            let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
            let window = peer_window.saturating_sub(in_flight);
            if window == 0 {
                break; // window closed — caller should retry next tick
            }
            let chunk_max = window.min(MSS).min(data.len() - sent_total);
            if chunk_max == 0 { break; }
            let chunk = &data[sent_total..sent_total + chunk_max];
            let ep = tcp_endpoint(conn);
            let adv_win = conn_recv_window(conn);
            send_tcp_segment(
                stack,
                ep,
                conn.snd_nxt,
                conn.rcv_nxt,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                chunk,
                adv_win,
            )?;
            record_last(
                conn,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                conn.snd_nxt,
                conn.rcv_nxt,
                chunk,
            );
            conn.snd_nxt = conn.snd_nxt.wrapping_add(chunk_max as u32);
            sent_total += chunk_max;
        }
        Ok(sent_total)
    }

    fn recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
        let conn = self
            .find_conn_id_mut(conn_id)
            .ok_or("Connection not found")?;
        if conn.recv_len == 0 {
            return Ok(0);
        }
        let len = core::cmp::min(out.len(), conn.recv_len);
        out[..len].copy_from_slice(&conn.recv_buf[..len]);
        conn.recv_len = 0;
        Ok(len)
    }

    fn close(&mut self, stack: &mut NetworkStack, conn_id: u16) -> Result<(), &'static str> {
        let conn = self
            .find_conn_id_mut(conn_id)
            .ok_or("Connection not found")?;
        if conn.state == TcpState::Established {
            conn.state = TcpState::FinWait1;
            let ep = tcp_endpoint(conn);
            let adv_win = conn_recv_window(conn);
            send_tcp_segment(
                stack,
                ep,
                conn.snd_nxt,
                conn.rcv_nxt,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                &[],
                adv_win,
            )?;
            record_last(
                conn,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                conn.snd_nxt,
                conn.rcv_nxt,
                &[],
            );
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            return Ok(());
        }
        if conn.state == TcpState::CloseWait {
            conn.state = TcpState::LastAck;
            let ep = tcp_endpoint(conn);
            let adv_win = conn_recv_window(conn);
            send_tcp_segment(
                stack,
                ep,
                conn.snd_nxt,
                conn.rcv_nxt,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                &[],
                adv_win,
            )?;
            record_last(
                conn,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                conn.snd_nxt,
                conn.rcv_nxt,
                &[],
            );
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
            // Collect what work (if any) needs to be done outside the borrow.
            let delayed_ack: Option<(TcpEndpoint, u32, u32)>;
            let action: Option<(TcpEndpoint, u32, u32, u16, [u8; 1460], usize)>;
            {
                let conn = &mut self.conns[i];
                if !conn.in_use {
                    continue;
                }
                // TIME_WAIT expiry: hold the port for 2×MSL then free the slot.
                if conn.state == TcpState::TimeWait {
                    if now >= conn.last_send_tick + TCP_TIME_WAIT_TICKS {
                        conn.state = TcpState::Closed;
                        conn.in_use = false;
                    }
                    continue;
                }
                // Delayed ACK timer: if we have a pending ACK that has been sitting
                // longer than TCP_DELAYED_ACK_TICKS, flush it now.
                if conn.ack_pending > 0
                    && conn.ack_pending_since > 0
                    && now.saturating_sub(conn.ack_pending_since) >= TCP_DELAYED_ACK_TICKS
                {
                    let ep = tcp_endpoint(conn);
                    let seq_out = conn.snd_nxt;
                    let ack_out = conn.rcv_nxt;
                    conn.ack_pending = 0;
                    conn.ack_pending_since = 0;
                    delayed_ack = Some((ep, seq_out, ack_out));
                    action = None;
                } else {
                    delayed_ack = None;
                    if conn.last_send_tick == 0 {
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
                    let mut payload = [0u8; 1460];
                    let len = conn.last_payload_len;
                    payload[..len].copy_from_slice(&conn.last_payload[..len]);
                    action = Some((
                        tcp_endpoint(conn),
                        conn.last_seq,
                        conn.last_ack,
                        conn.last_flags,
                        payload,
                        len,
                    ));
                    conn.retries = conn.retries.saturating_add(1);
                    conn.last_send_tick = now;
                }
            }
            if let Some((ep, seq_out, ack_out)) = delayed_ack {
                let _ = send_tcp_segment(stack, ep, seq_out, ack_out, TCP_FLAG_ACK, &[], TCP_BUF_SIZE as u16);
            }
            if let Some((ep, seq, ack, flags, payload, len)) = action {
                let _ = send_tcp_segment(stack, ep, seq, ack, flags, &payload[..len], TCP_BUF_SIZE as u16);
            }
        }
    }
}

const TCP_FLAG_FIN: u16 = 0x01;
const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_RST: u16 = 0x04;
const TCP_FLAG_PSH: u16 = 0x08;
const TCP_FLAG_ACK: u16 = 0x10;

fn tcp_state_from_temporal(state: u8) -> TcpState {
    match state {
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynReceived,
        4 => TcpState::Established,
        5 => TcpState::FinWait1,
        6 => TcpState::FinWait2,
        7 => TcpState::CloseWait,
        8 => TcpState::LastAck,
        _ => TcpState::Closed,
    }
}

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

/// Compute the receive window to advertise for a connection.
///
/// Shrinks as the receive buffer fills so the peer doesn't overrun us:
/// $$W_{\text{adv}} = \min(\text{TCP\_BUF\_SIZE} - \text{recv\_len},\; 65535)$$
#[inline]
fn conn_recv_window(conn: &TcpConn) -> u16 {
    let avail = TCP_BUF_SIZE.saturating_sub(conn.recv_len);
    avail.min(0xFFFF) as u16
}

fn send_tcp_segment(
    stack: &mut NetworkStack,
    ep: TcpEndpoint,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: &[u8],
    adv_window: u16,
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
    let checksum = calculate_checksum(&frame[ip_start..ip_start + ip_header_len]);
    frame[off + 10..off + 12].copy_from_slice(&checksum.to_be_bytes());
    off += ip_header_len;

    let tcp_start = off;
    frame[off..off + 2].copy_from_slice(&ep.local_port.to_be_bytes());
    frame[off + 2..off + 4].copy_from_slice(&ep.remote_port.to_be_bytes());
    frame[off + 4..off + 8].copy_from_slice(&seq.to_be_bytes());
    frame[off + 8..off + 12].copy_from_slice(&ack.to_be_bytes());
    frame[off + 12] = ((tcp_header_len / 4) as u8) << 4;
    frame[off + 13] = (flags & 0xFF) as u8;
    // Advertise the caller-supplied receive window (already clamped to 65535).
    frame[off + 14..off + 16].copy_from_slice(&adv_window.to_be_bytes());
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

    let mut driver = super::e1000::E1000_DRIVER.lock();
    let interface = driver.as_mut().ok_or("No E1000 driver")?;
    interface.send_frame(&frame[..total_len])
}

/// Send a SYN or SYN-ACK with the full RFC 1323 / RFC 6691 option set:
///   kind=2 len=4 MSS=1460  (4 bytes)
///   kind=3 len=3 wscale=TCP_WSCALE  NOP  (3+1=4 bytes, aligned)
/// Total TCP options = 8 bytes → tcp_header_len = 28.
fn send_syn_segment(
    stack: &mut NetworkStack,
    ep: TcpEndpoint,
    seq: u32,
    ack: u32,
    flags: u16,
    adv_window: u16,
) -> Result<(), &'static str> {
    let dest_mac = if let Some(mac) = stack.arp_cache.lookup(ep.remote_ip) {
        mac
    } else {
        stack.send_arp_request(ep.remote_ip)?;
        return Err("ARP unresolved");
    };

    // TCP options: MSS(4) + NOP + WSCALE(3) + NOP = 8 bytes (32-bit aligned)
    let options: [u8; 8] = [
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
        0x01,                   // NOP
        0x03, 0x03, TCP_WSCALE, // window scale
    ];
    let tcp_header_len = 20 + options.len(); // 28
    let ip_header_len = 20;
    let total_len = 14 + ip_header_len + tcp_header_len;
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
    let ip_total = (ip_header_len + tcp_header_len) as u16;
    frame[off + 2..off + 4].copy_from_slice(&ip_total.to_be_bytes());
    frame[off + 4..off + 6].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 6..off + 8].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 8] = 64;
    frame[off + 9] = IP_PROTOCOL_TCP;
    frame[off + 10..off + 12].copy_from_slice(&0u16.to_be_bytes());
    frame[off + 12..off + 16].copy_from_slice(&ep.local_ip.0);
    frame[off + 16..off + 20].copy_from_slice(&ep.remote_ip.0);
    let checksum = calculate_checksum(&frame[ip_start..ip_start + ip_header_len]);
    frame[off + 10..off + 12].copy_from_slice(&checksum.to_be_bytes());
    off += ip_header_len;

    let tcp_start = off;
    frame[off..off + 2].copy_from_slice(&ep.local_port.to_be_bytes());
    frame[off + 2..off + 4].copy_from_slice(&ep.remote_port.to_be_bytes());
    frame[off + 4..off + 8].copy_from_slice(&seq.to_be_bytes());
    frame[off + 8..off + 12].copy_from_slice(&ack.to_be_bytes());
    frame[off + 12] = ((tcp_header_len / 4) as u8) << 4;
    frame[off + 13] = (flags & 0xFF) as u8;
    frame[off + 14..off + 16].copy_from_slice(&adv_window.to_be_bytes());
    frame[off + 16..off + 18].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    frame[off + 18..off + 20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer
    frame[off + 20..off + 28].copy_from_slice(&options);
    off += tcp_header_len;
    let _ = off;

    let tcp_len = tcp_header_len as u16;
    let tcp_checksum = tcp_checksum(
        &ep.local_ip.0,
        &ep.remote_ip.0,
        IP_PROTOCOL_TCP,
        tcp_len,
        &frame[tcp_start..tcp_start + tcp_header_len],
    );
    frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let mut driver = super::e1000::E1000_DRIVER.lock();
    let interface = driver.as_mut().ok_or("No E1000 driver")?;
    interface.send_frame(&frame[..total_len])
}

fn record_last(conn: &mut TcpConn, flags: u16, seq: u32, ack: u32, payload: &[u8]) {
    conn.last_flags = flags;
    conn.last_seq = seq;
    conn.last_ack = ack;
    conn.last_payload_len = payload.len().min(conn.last_payload.len());
    debug_assert!(
        payload.len() <= 1460,
        "TCP segment payload exceeds MSS (1460); retransmit buffer would truncate"
    );
    conn.last_payload[..conn.last_payload_len].copy_from_slice(&payload[..conn.last_payload_len]);
    conn.last_send_tick = crate::pit::get_ticks();
    // RFC 6298: reset rtt_start on every new segment so SRTT tracks real RTT,
    // not connection uptime.  Only update when payload advances snd_nxt.
    if !payload.is_empty() || (flags & TCP_FLAG_SYN != 0) {
        conn.rtt_start = conn.last_send_tick;
    }
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
            IP_PROTOCOL_UDP => {
                let src = Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]);
                self.handle_udp(src, &packet[ihl..total_len])?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_udp(&mut self, src_ip: Ipv4Addr, datagram: &[u8]) -> Result<(), &'static str> {
        if datagram.len() < 8 {
            return Err("UDP datagram too short");
        }
        let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
        let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
        let udp_len = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
        if udp_len < 8 || udp_len > datagram.len() {
            return Err("UDP length invalid");
        }
        let payload = &datagram[8..udp_len];
        if dst_port == super::capnet::CAPNET_CONTROL_PORT {
            self.handle_capnet_control(src_ip, src_port, payload)?;
        }
        Ok(())
    }

    fn handle_capnet_control(
        &mut self,
        src_ip: Ipv4Addr,
        src_port: u16,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        let now = crate::pit::get_ticks() as u64;
        let rx = match super::capnet::process_incoming_control_payload(payload, now) {
            Ok(v) => v,
            Err(e) => {
                crate::security::security().log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::IntegrityCheckFailed,
                        crate::ipc::ProcessId(0),
                        0,
                    )
                    .with_context(e as u64),
                );
                return Err(e.as_str());
            }
        };

        self.capnet_ack_seq(rx.peer_device_id, rx.ack);

        if rx.ack_only {
            return Ok(());
        }

        let (reply, queue_reply) = match rx.msg_type {
            super::capnet::CapNetControlType::TokenOffer => (
                super::capnet::build_token_accept_frame(rx.peer_device_id, rx.seq, rx.token_id)
                    .map_err(|e| e.as_str())?,
                true,
            ),
            super::capnet::CapNetControlType::TokenRevoke
            | super::capnet::CapNetControlType::TokenAccept
            | super::capnet::CapNetControlType::Hello
            | super::capnet::CapNetControlType::Attest
            | super::capnet::CapNetControlType::Heartbeat => (
                super::capnet::build_heartbeat_frame(rx.peer_device_id, rx.seq, true)
                    .map_err(|e| e.as_str())?,
                false,
            ),
        };

        self.send_udp(
            src_ip,
            src_port,
            super::capnet::CAPNET_CONTROL_PORT,
            &reply.bytes[..reply.len],
        )?;
        if queue_reply {
            self.capnet_queue_retx(
                rx.peer_device_id,
                src_ip,
                src_port,
                reply.seq,
                &reply.bytes[..reply.len],
            )?;
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
        let raw_window = u16::from_be_bytes([segment[14], segment[15]]);
        if segment.len() < data_off {
            return Err("TCP header invalid");
        }
        let payload = &segment[data_off..];

        // Parse TCP options to extract wscale (kind=3) and MSS (kind=2).
        // Only present when data_off > 20 (i.e. there are options bytes).
        let peer_wscale_opt: Option<u8> = if data_off > 20 && data_off <= segment.len() {
            parse_tcp_wscale_option(&segment[20..data_off])
        } else {
            None
        };

        let mut ack_action: Option<(TcpEndpoint, u32, u32)> = None;
        let mut established_from_listen: Option<(u8, u16)> = None;
        let mut http_conn_id: Option<u16> = None;

        if let Some(idx) = self.tcp.find_conn_index(dst_port, src_ip, src_port) {
            {
                let conn = &mut self.tcp.conns[idx];
                if flags & TCP_FLAG_RST != 0 {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE,
                        flags as u32,
                    );
                    return Ok(());
                }
                if flags & TCP_FLAG_ACK != 0 && ack > conn.snd_una {
                    conn.snd_una = ack;
                    // Update the peer's advertised receive window (RFC 1323 §2.2).
                    // The raw 16-bit window is left-shifted by the peer's wscale.
                    conn.snd_wnd = (raw_window as u32) << (conn.peer_wscale as u32);
                    let now = crate::pit::get_ticks();
                    let sample = now.saturating_sub(conn.rtt_start);
                    if conn.srtt == 0 {
                        conn.srtt = sample;
                        conn.rttvar = sample / 2;
                    } else {
                        let err = if conn.srtt > sample {
                            conn.srtt - sample
                        } else {
                            sample - conn.srtt
                        };
                        conn.rttvar = (3 * conn.rttvar + err) / 4;
                        conn.srtt = (7 * conn.srtt + sample) / 8;
                    }
                    conn.rto_ticks = core::cmp::max(1, conn.srtt + 4 * conn.rttvar);
                }

                if conn.state == TcpState::SynSent
                    && (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
                {
                    // Record the peer's window scale from the SYN-ACK options.
                    // If the peer didn't include wscale, treat it as 0 (RFC 7323 §2.2).
                    conn.peer_wscale = peer_wscale_opt.unwrap_or(0);
                    // Set initial send window from the SYN-ACK (scaled).
                    conn.snd_wnd = (raw_window as u32) << (conn.peer_wscale as u32);
                    conn.state = TcpState::Established;
                    conn.irs = seq;
                    conn.rcv_nxt = seq.wrapping_add(1);
                    conn.snd_una = ack;
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_STATE,
                        flags as u32,
                    );
                    ack_action = Some((tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt));
                }

                if conn.state == TcpState::SynReceived && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::Established;
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_ACCEPT,
                        flags as u32,
                    );
                    if conn.listener_idx != 0xFF {
                        established_from_listen = Some((conn.listener_idx, conn.id));
                    }
                }

                if !payload.is_empty() && seq == conn.rcv_nxt {
                    let copy_len = core::cmp::min(payload.len(), conn.recv_buf.len());
                    conn.recv_buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    conn.recv_len = copy_len;
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload.len() as u32);
                    let _ = crate::temporal::record_tcp_socket_data_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_RECV,
                        payload,
                    );
                    // Delayed ACK (RFC 5681 §3.2): accumulate up to TCP_DELAYED_ACK_SEGMENTS
                    // before sending an ACK.  Force immediate ACK on PSH or buffer-full.
                    conn.ack_pending = conn.ack_pending.saturating_add(1);
                    if conn.ack_pending_since == 0 {
                        conn.ack_pending_since = crate::pit::get_ticks();
                    }
                    let force_ack = (flags & TCP_FLAG_PSH != 0)
                        || conn.ack_pending as usize >= TCP_DELAYED_ACK_SEGMENTS as usize
                        || conn.recv_len >= conn.recv_buf.len();
                    if force_ack {
                        ack_action = Some((tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt));
                        conn.ack_pending = 0;
                        conn.ack_pending_since = 0;
                    }
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
                        let _ = crate::temporal::record_tcp_socket_state_event(
                            conn.id as u32,
                            conn.state as u8,
                            conn.local_ip.0,
                            conn.local_port,
                            conn.remote_ip.0,
                            conn.remote_port,
                            crate::temporal::TEMPORAL_SOCKET_EVENT_STATE,
                            flags as u32,
                        );
                    } else if conn.state == TcpState::FinWait1 {
                        // Simultaneous close: FIN before our ACK for FIN — go to Closed.
                        conn.state = TcpState::Closed;
                        conn.in_use = false;
                        let _ = crate::temporal::record_tcp_socket_state_event(
                            conn.id as u32,
                            conn.state as u8,
                            conn.local_ip.0,
                            conn.local_port,
                            conn.remote_ip.0,
                            conn.remote_port,
                            crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE,
                            flags as u32,
                        );
                    } else if conn.state == TcpState::FinWait2 {
                        // Normal 4-way close: peer sent FIN after we got ACK for ours.
                        // Enter TIME_WAIT for 2×MSL before freeing the port.
                        conn.state = TcpState::TimeWait;
                        conn.last_send_tick = crate::pit::get_ticks(); // start timer
                        let _ = crate::temporal::record_tcp_socket_state_event(
                            conn.id as u32,
                            conn.state as u8,
                            conn.local_ip.0,
                            conn.local_port,
                            conn.remote_ip.0,
                            conn.remote_port,
                            crate::temporal::TEMPORAL_SOCKET_EVENT_STATE,
                            flags as u32,
                        );
                    }
                }

                if conn.state == TcpState::FinWait1 && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::FinWait2;
                }
                if conn.state == TcpState::LastAck && (flags & TCP_FLAG_ACK != 0) {
                    conn.state = TcpState::Closed;
                    conn.in_use = false;
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_CLOSE,
                        flags as u32,
                    );
                }
            }

            if let Some((ep, seq_out, ack_out)) = ack_action {
                let _ = send_tcp_segment(self, ep, seq_out, ack_out, TCP_FLAG_ACK, &[], TCP_BUF_SIZE as u16);
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
                    let tick = crate::pit::get_ticks();
                    let k0 = tick ^ (u32::from_be_bytes(self.my_ip.0) as u64);
                    let k1 = ((dst_port as u64) << 16 | src_port as u64)
                        ^ tick.wrapping_add(0xBEEF_CAFE_DEAD_0001u64);
                    let mut isn_data = [0u8; 12];
                    isn_data[0..4].copy_from_slice(&self.my_ip.0);
                    isn_data[4..8].copy_from_slice(&src_ip.0);
                    isn_data[8..10].copy_from_slice(&dst_port.to_le_bytes());
                    isn_data[10..12].copy_from_slice(&src_port.to_le_bytes());
                    conn.iss = crate::security::security()
                        .cap_token_sign_with_key(k0, k1, &isn_data) as u32;
                    conn.snd_una = conn.iss;
                    conn.snd_nxt = conn.iss;
                    conn.irs = seq;
                    conn.rcv_nxt = seq.wrapping_add(1);
                    conn.listener_idx = idx as u8;
                    conn.rto_ticks = (crate::pit::get_frequency() as u64) * 3;
                    // Record the client's window scale from its SYN options.
                    conn.peer_wscale = peer_wscale_opt.unwrap_or(0);
                    // Initial send window from the SYN (scaled by client's wscale).
                    conn.snd_wnd = (raw_window as u32) << (conn.peer_wscale as u32);
                    let _ = crate::temporal::record_tcp_socket_state_event(
                        conn.id as u32,
                        conn.state as u8,
                        conn.local_ip.0,
                        conn.local_port,
                        conn.remote_ip.0,
                        conn.remote_port,
                        crate::temporal::TEMPORAL_SOCKET_EVENT_CONNECT,
                        flags as u32,
                    );
                    let ep = tcp_endpoint(conn);
                    let seq_out = conn.snd_nxt;
                    let ack_out = conn.rcv_nxt;
                    record_last(conn, TCP_FLAG_SYN | TCP_FLAG_ACK, seq_out, ack_out, &[]);
                    conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                    let _ = idx;
                    let adv_win = TCP_BUF_SIZE as u16;
                    let _ = send_syn_segment(
                        self,
                        ep,
                        seq_out,
                        ack_out,
                        TCP_FLAG_SYN | TCP_FLAG_ACK,
                        adv_win,
                    );
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
        let _ = send_tcp_segment(self, ep, seq, ack, TCP_FLAG_ACK | TCP_FLAG_PSH, body, TCP_BUF_SIZE as u16);

        let (ep2, seq2, ack2) = {
            let conn = match self.tcp.find_conn_id_mut(conn_id) {
                Some(c) => c,
                None => return,
            };
            record_last(
                conn,
                TCP_FLAG_ACK | TCP_FLAG_PSH,
                conn.snd_nxt,
                conn.rcv_nxt,
                body,
            );
            conn.snd_nxt = conn.snd_nxt.wrapping_add(body.len() as u32);
            conn.state = TcpState::LastAck;
            conn.http_pending = false;
            (tcp_endpoint(conn), conn.snd_nxt, conn.rcv_nxt)
        };

        let _ = send_tcp_segment(self, ep2, seq2, ack2, TCP_FLAG_FIN | TCP_FLAG_ACK, &[], TCP_BUF_SIZE as u16);
        if let Some(conn) = self.tcp.find_conn_id_mut(conn_id) {
            record_last(
                conn,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                conn.snd_nxt,
                conn.rcv_nxt,
                &[],
            );
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
