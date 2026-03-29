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
const DNS_CLIENT_SRC_PORT: u16 = 53000;
const DNS_SERVER_PORT: u16 = 53;
const UDP_RX_QUEUE_SIZE: usize = 8;
const UDP_RX_PAYLOAD_MAX: usize = 512;
const NET_READY_DEFAULT_WAIT_TICKS: u64 = 1000;
const ARP_DEFAULT_TIMEOUT_TICKS: u64 = 1000;
const DNS_RESPONSE_TIMEOUT_SECS: u64 = 4;
const DNS_QUERY_MAX_ATTEMPTS: usize = 2;
const DNS_DEBUG_ENABLED: bool = false;
const TCP_TEMPORAL_EVENTS_ENABLED: bool = false;
const NETWORK_CONFIG_TEMPORAL_EVENTS_ENABLED: bool = false;

// DNS negative-cache: remember NXDOMAIN/timeout results for DNS_NEG_TTL_TICKS ticks
// to avoid hammering the network for domains we know are unreachable.
const DNS_NEG_CACHE_SIZE: usize = 8;
const DNS_NEG_TTL_TICKS: u64 = 3000; // ~3 s at 1 kHz PIT
const DNS_DOMAIN_MAX: usize = 64; // max stored domain length

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

#[derive(Clone, Copy)]
struct UdpRxEntry {
    valid: bool,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    payload: [u8; UDP_RX_PAYLOAD_MAX],
}

impl UdpRxEntry {
    const fn empty() -> Self {
        UdpRxEntry {
            valid: false,
            src_ip: Ipv4Addr([0, 0, 0, 0]),
            src_port: 0,
            dst_port: 0,
            payload_len: 0,
            payload: [0u8; UDP_RX_PAYLOAD_MAX],
        }
    }
}
const TEMPORAL_NETWORK_CONFIG_BYTES: usize = 32;
const TEMPORAL_NETWORK_CONFIG_FLAG_DHCP: u8 = 1 << 0;
const TEMPORAL_NETWORK_CONFIG_FLAG_HAS_INTERFACE: u8 = 1 << 1;

// Reactor-owned staging buffers keep the hot DNS/UDP paths off the legacy x86
// task stack. The dedicated network task is the sole live owner of this stack.
static mut UDP_TX_STAGE: [u8; 1514] = [0u8; 1514];
static mut DNS_QUERY_STAGE: [u8; 512] = [0u8; 512];
static mut DNS_RESPONSE_STAGE: [u8; 512] = [0u8; 512];
static mut POLL_RX_STAGE: [u8; 1514] = [0u8; 1514];
static mut TCP_TX_STAGE: [u8; 1514] = [0u8; 1514];

#[inline]
fn backend_mac_address() -> Option<[u8; 6]> {
    #[cfg(target_arch = "aarch64")]
    {
        if super::virtio_net::is_available() {
            Some(super::virtio_net::mac_address())
        } else {
            None
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        super::e1000::get_mac_address()
    }
}

#[inline]
fn backend_link_up() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        super::virtio_net::is_link_up()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        super::e1000::is_link_up()
    }
}

#[inline]
fn backend_send_frame(frame: &[u8]) -> Result<(), &'static str> {
    #[cfg(target_arch = "aarch64")]
    {
        super::virtio_net::send(frame)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut driver = super::e1000::E1000_DRIVER.lock();
        let interface = driver.as_mut().ok_or("No E1000 driver")?;
        interface.send_frame(frame)
    }
}

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
    udp_rx_queue: [UdpRxEntry; UDP_RX_QUEUE_SIZE],
    dns_next_txid: u16,
    dns_debug_active: bool,
    dns_debug_txid: u16,
    dns_debug_miss_logged: bool,
}

impl NetworkStack {
    const QEMU_USERNET_IP: Ipv4Addr = Ipv4Addr([10, 0, 2, 15]);
    const QEMU_USERNET_GATEWAY: Ipv4Addr = Ipv4Addr([10, 0, 2, 2]);
    const QEMU_USERNET_DNS: Ipv4Addr = Ipv4Addr([10, 0, 2, 3]);

    #[inline]
    fn wait_timeout_ticks(default_ticks: u64) -> u64 {
        let freq = crate::pit::get_frequency() as u64;
        if freq == 0 {
            return default_ticks;
        }
        freq.max(default_ticks)
    }

    #[inline]
    fn link_ready(&self) -> bool {
        backend_mac_address().is_some() && backend_link_up()
    }

    #[inline]
    fn operational_link_ready(&self) -> bool {
        if self.link_ready() {
            return true;
        }

        #[cfg(target_arch = "x86")]
        {
            let mac_valid = self.my_mac.0 != [0; 6] && self.my_mac.0 != [0xFF; 6];
            return self.has_interface
                && self.interface_configured()
                && mac_valid
                && super::e1000::driver_present();
        }

        #[cfg(not(target_arch = "x86"))]
        {
            false
        }
    }

    #[inline]
    fn interface_configured(&self) -> bool {
        self.my_ip.0 != [0, 0, 0, 0]
            && self.gateway_ip.0 != [0, 0, 0, 0]
            && self.dns_server.0 != [0, 0, 0, 0]
    }

    #[inline]
    pub fn readiness_prereqs_met(&self) -> bool {
        return self.interface_configured() && self.operational_link_ready();
    }

    pub const fn new() -> Self {
        NetworkStack {
            my_ip: Self::QEMU_USERNET_IP,                          // QEMU default
            my_mac: MacAddr([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]), // QEMU default
            gateway_ip: Self::QEMU_USERNET_GATEWAY,                // QEMU default gateway
            dns_server: Self::QEMU_USERNET_DNS,                    // QEMU usernet DNS proxy
            arp_cache: ArpCache::new(),
            dhcp_enabled: false,
            has_interface: false,
            capnet_retx: [CapNetRetransmitEntry::empty(); CAPNET_MAX_RETX],
            tcp: TcpManager::new(),
            http_server: HttpServer::new(),
            dns_neg_cache: [DnsNegEntry::empty(); DNS_NEG_CACHE_SIZE],
            udp_rx_queue: [UdpRxEntry::empty(); UDP_RX_QUEUE_SIZE],
            dns_next_txid: 0,
            dns_debug_active: false,
            dns_debug_txid: 0,
            dns_debug_miss_logged: false,
        }
    }

    fn config_trace_enabled() -> bool {
        let Some(cmdline) = crate::arch::boot_info().cmdline_str() else {
            return false;
        };
        cmdline.split_whitespace().any(|token| {
            token == "oreulia.net_config_debug"
                || matches!(
                    token.strip_prefix("oreulia.net_config_debug="),
                    Some("1" | "true" | "on" | "yes")
                )
        })
    }

    fn log_config_state(&self, reason: &str) {
        if !Self::config_trace_enabled() {
            return;
        }
        crate::serial_print!("[NET-CONFIG] ");
        crate::serial_print!("{}", reason);
        crate::serial_print!(
            " ip={}.{}.{}.{}",
            self.my_ip.0[0],
            self.my_ip.0[1],
            self.my_ip.0[2],
            self.my_ip.0[3]
        );
        crate::serial_print!(
            " gw={}.{}.{}.{}",
            self.gateway_ip.0[0],
            self.gateway_ip.0[1],
            self.gateway_ip.0[2],
            self.gateway_ip.0[3]
        );
        crate::serial_print!(
            " dns={}.{}.{}.{}",
            self.dns_server.0[0],
            self.dns_server.0[1],
            self.dns_server.0[2],
            self.dns_server.0[3]
        );
        crate::serial_println!(" has_if={}", if self.has_interface { 1 } else { 0 });
    }

    pub fn seed_legacy_x86_qemu_defaults(&mut self) -> bool {
        if self.interface_configured() && self.has_interface {
            return false;
        }

        self.my_ip = Self::QEMU_USERNET_IP;
        self.gateway_ip = Self::QEMU_USERNET_GATEWAY;
        self.dns_server = Self::QEMU_USERNET_DNS;
        self.has_interface = true;
        self.dhcp_enabled = false;
        if let Some(mac) = backend_mac_address() {
            self.my_mac = MacAddr(mac);
        }
        self.log_config_state("seeded legacy-x86 qemu defaults");
        true
    }

    pub fn seed_aarch64_qemu_defaults(&mut self, mac: [u8; 6]) -> bool {
        if self.interface_configured() && self.my_mac.0 == mac {
            return false;
        }

        self.my_ip = Self::QEMU_USERNET_IP;
        self.gateway_ip = Self::QEMU_USERNET_GATEWAY;
        self.dns_server = Self::QEMU_USERNET_DNS;
        self.my_mac = MacAddr(mac);
        self.has_interface = false;
        self.dhcp_enabled = false;
        self.log_config_state("seeded aarch64 qemu defaults");
        true
    }

    /// Mark interface as available
    pub fn mark_ready(&mut self) {
        self.has_interface = true;
        if let Some(mac) = backend_mac_address() {
            self.my_mac = MacAddr(mac);
        }
    }

    /// Check if network is ready
    pub fn is_ready(&self) -> bool {
        self.has_interface && self.readiness_prereqs_met()
    }

    pub fn link_up(&self) -> bool {
        self.operational_link_ready()
    }

    pub fn get_mac(&self) -> [u8; 6] {
        self.my_mac.0
    }

    // ========================================================================
    // ARP Protocol
    // ========================================================================

    fn send_arp_request(&mut self, target_ip: Ipv4Addr) -> Result<(), &'static str> {
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

        backend_send_frame(&frame)
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

    fn send_arp_reply(&mut self, dest_mac: MacAddr, dest_ip: Ipv4Addr) -> Result<(), &'static str> {
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

        backend_send_frame(&frame)
    }

    /// Resolve IP to MAC address (with ARP)
    fn resolve_mac(&mut self, ip: Ipv4Addr) -> Result<MacAddr, &'static str> {
        // Check ARP cache first
        if let Some(mac) = self.arp_cache.lookup(ip) {
            return Ok(mac);
        }

        let link_deadline =
            crate::pit::get_ticks() + Self::wait_timeout_ticks(NET_READY_DEFAULT_WAIT_TICKS);
        while !self.operational_link_ready() {
            if crate::pit::get_ticks() >= link_deadline {
                return Err("Link down");
            }
            let _ = self.poll_once()?;
        }

        // Send ARP request
        self.send_arp_request(ip)?;

        let deadline =
            crate::pit::get_ticks() + Self::wait_timeout_ticks(ARP_DEFAULT_TIMEOUT_TICKS);
        while crate::pit::get_ticks() < deadline {
            let _ = self.poll_once()?;

            if let Some(mac) = self.arp_cache.lookup(ip) {
                return Ok(mac);
            }
        }

        Err("ARP timeout")
    }

    // ========================================================================
    // UDP Protocol
    // ========================================================================

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

        // Build packet
        let frame = unsafe { &mut *core::ptr::addr_of_mut!(UDP_TX_STAGE) };
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
        let ip_checksum_offset = offset;
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

        let udp_seg_len = udp_len as u16;
        let udp_checksum = tcp_checksum(
            &self.my_ip.0,
            &dest_ip.0,
            IP_PROTOCOL_UDP,
            udp_seg_len,
            &frame[udp_checksum_offset - 6..offset],
        );
        frame[udp_checksum_offset..udp_checksum_offset + 2]
            .copy_from_slice(&udp_checksum.to_be_bytes());

        backend_send_frame(&frame[..offset])
    }

    /// Dequeue the oldest valid UDP slot whose `dst_port` matches `expected_port`.
    ///
    /// Source validation is applied for well-known ports:
    ///   • `DNS_CLIENT_SRC_PORT` — slot must originate from `self.dns_server:53`.
    ///     Slots from any other source are silently discarded; accepting a DNS
    ///     response from an unexpected peer is equivalent to a spoofed injection.
    ///
    /// Oversized slots (payload > buffer) are **discarded** rather than left in the
    /// queue. Leaving them valid would stall every subsequent receive on that port.
    /// The caller receives `Err("Buffer too small")` only when at least one
    /// matching, source-valid slot was discarded for being oversized and no
    /// same-port slot of acceptable size was found. If no matching slot exists at
    /// all the error is `Err("No UDP packet available")`.
    fn recv_udp(&mut self, expected_port: u16, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let is_dns = expected_port == DNS_CLIENT_SRC_PORT;
        let mut found_oversized = false;

        for slot in &mut self.udp_rx_queue {
            if !slot.valid || slot.dst_port != expected_port {
                continue;
            }

            // Source validation: DNS responses must originate from the
            // configured DNS server on port 53.  Any other source (stale
            // broadcast, spoofed reply, wrong-server reply) is dropped so it
            // cannot poison the caller's response buffer.
            if is_dns {
                let from_dns_server =
                    slot.src_ip == self.dns_server && slot.src_port == DNS_SERVER_PORT;
                if !from_dns_server {
                    if self.dns_debug_active {
                        crate::serial_println!(
                            "[DNS-DEBUG] recv_udp discard unexpected source \
                             src={}.{}.{}.{}:{} expected_server={}.{}.{}.{}:{}",
                            slot.src_ip.0[0],
                            slot.src_ip.0[1],
                            slot.src_ip.0[2],
                            slot.src_ip.0[3],
                            slot.src_port,
                            self.dns_server.0[0],
                            self.dns_server.0[1],
                            self.dns_server.0[2],
                            self.dns_server.0[3],
                            DNS_SERVER_PORT,
                        );
                    }
                    *slot = UdpRxEntry::empty();
                    continue;
                }
            }

            // Oversized: discard the slot so it cannot permanently block the
            // queue, then continue scanning for a smaller matching packet.
            if slot.payload_len > buffer.len() {
                if is_dns && self.dns_debug_active {
                    crate::serial_println!(
                        "[DNS-DEBUG] recv_udp discard oversized slot \
                         src={}.{}.{}.{}:{} dst_port={} payload_len={} buffer_len={}",
                        slot.src_ip.0[0],
                        slot.src_ip.0[1],
                        slot.src_ip.0[2],
                        slot.src_ip.0[3],
                        slot.src_port,
                        slot.dst_port,
                        slot.payload_len,
                        buffer.len(),
                    );
                }
                *slot = UdpRxEntry::empty();
                found_oversized = true;
                continue;
            }

            // Valid, source-validated, correctly-sized slot — dequeue it.
            if is_dns && self.dns_debug_active {
                let rx_txid = if slot.payload_len >= 2 {
                    u16::from_be_bytes([slot.payload[0], slot.payload[1]])
                } else {
                    0
                };
                crate::serial_println!(
                    "[DNS-DEBUG] recv_udp dequeue src={}.{}.{}.{}:{} dst_port={} len={} txid=0x{:04x}",
                    slot.src_ip.0[0],
                    slot.src_ip.0[1],
                    slot.src_ip.0[2],
                    slot.src_ip.0[3],
                    slot.src_port,
                    slot.dst_port,
                    slot.payload_len,
                    rx_txid,
                );
            }
            buffer[..slot.payload_len].copy_from_slice(&slot.payload[..slot.payload_len]);
            let payload_len = slot.payload_len;
            *slot = UdpRxEntry::empty();
            return Ok(payload_len);
        }

        if found_oversized {
            return Err("Buffer too small");
        }

        if is_dns && self.dns_debug_active && !self.dns_debug_miss_logged {
            let queued = self.udp_rx_queue.iter().filter(|s| s.valid).count();
            crate::serial_println!(
                "[DNS-DEBUG] recv_udp queue miss expected_port={} queued_slots={} txid=0x{:04x}",
                expected_port,
                queued,
                self.dns_debug_txid,
            );
            self.dns_debug_miss_logged = true;
        }

        Err("No UDP packet available")
    }

    // ============================================================================
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
        let frame =
            super::capnet::build_attest_frame(peer_device_id, ack).map_err(|e| e.as_str())?;
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
                    slot.next_retry_tick =
                        now.saturating_add(CAPNET_RETX_INTERVAL_TICKS << backoff_shift);
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
        self.dns_resolve_with_progress(domain, |stack| {
            let _ = stack.poll_once();
        })
    }

    pub fn dns_resolve_with_progress<F>(
        &mut self,
        domain: &str,
        mut progress: F,
    ) -> Result<Ipv4Addr, &'static str>
    where
        F: FnMut(&mut Self),
    {
        if !self.is_ready() {
            if DNS_DEBUG_ENABLED {
                crate::serial_println!(
                    "[DNS-DEBUG] preflight ready={} has_if={} link={} ip={}.{}.{}.{} gw={}.{}.{}.{} dns={}.{}.{}.{}",
                    if self.is_ready() { 1 } else { 0 },
                    if self.has_interface { 1 } else { 0 },
                    if self.link_ready() { 1 } else { 0 },
                    self.my_ip.0[0],
                    self.my_ip.0[1],
                    self.my_ip.0[2],
                    self.my_ip.0[3],
                    self.gateway_ip.0[0],
                    self.gateway_ip.0[1],
                    self.gateway_ip.0[2],
                    self.gateway_ip.0[3],
                    self.dns_server.0[0],
                    self.dns_server.0[1],
                    self.dns_server.0[2],
                    self.dns_server.0[3],
                );
            }
            return Err("Network not ready");
        }

        if domain.len() > 253 {
            return Err("Domain name too long");
        }

        // ---- Negative-cache check ----
        let now = crate::pit::get_ticks();
        let dlen = domain.len().min(DNS_DOMAIN_MAX);
        for slot in self.dns_neg_cache.iter_mut() {
            if !slot.active {
                continue;
            }
            if now >= slot.expires {
                slot.active = false;
                continue;
            }
            if slot.domain_len as usize == dlen && slot.domain[..dlen] == domain.as_bytes()[..dlen]
            {
                return Err("DNS negative cache");
            }
        }

        for attempt in 0..DNS_QUERY_MAX_ATTEMPTS {
            self.clear_stale_dns_responses();

            // Build DNS query
            let query = unsafe { &mut DNS_QUERY_STAGE };
            query.fill(0);
            let mut offset = 0;

            // DNS header
            let txid = self.next_dns_txid();
            query[offset..offset + 2].copy_from_slice(&txid.to_be_bytes());
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

            self.dns_debug_begin(txid);
            if self.dns_debug_active {
                crate::serial_println!(
                    "[DNS-DEBUG] tx query domain={} txid=0x{:04x} attempt={} server={}.{}.{}.{} src_port={}",
                    domain,
                    txid,
                    attempt + 1,
                    self.dns_server.0[0],
                    self.dns_server.0[1],
                    self.dns_server.0[2],
                    self.dns_server.0[3],
                    DNS_CLIENT_SRC_PORT
                );
            }

            if let Err(e) = self.send_udp(
                self.dns_server,
                DNS_SERVER_PORT,
                DNS_CLIENT_SRC_PORT,
                &query[..query_len],
            ) {
                self.dns_debug_finish();
                return Err(e);
            }

            // Receive DNS response
            let response = unsafe { &mut DNS_RESPONSE_STAGE };
            response.fill(0);

            let dns_timeout_ticks = (crate::pit::get_frequency() as u64)
                .saturating_mul(DNS_RESPONSE_TIMEOUT_SECS)
                .max(200);
            let deadline = crate::pit::get_ticks().saturating_add(dns_timeout_ticks);
            while crate::pit::get_ticks() < deadline {
                match self.recv_udp(DNS_CLIENT_SRC_PORT, response) {
                    Ok(len) => {
                        let rx_txid = if len >= 2 {
                            u16::from_be_bytes([response[0], response[1]])
                        } else {
                            0
                        };
                        if self.dns_debug_active {
                            crate::serial_println!(
                                "[DNS-DEBUG] rx queued response len={} txid=0x{:04x} expected=0x{:04x}",
                                len,
                                rx_txid,
                                txid
                            );
                        }
                        if rx_txid != txid {
                            if self.dns_debug_active {
                                crate::serial_println!(
                                    "[DNS-DEBUG] ignore mismatched txid got=0x{:04x} expected=0x{:04x}",
                                    rx_txid,
                                    txid
                                );
                            }
                            continue;
                        }
                        let parse_result = self.parse_dns_response(&response[..len]);
                        self.dns_debug_finish();
                        return parse_result;
                    }
                    Err(_) => {
                        progress(self);
                    }
                }
            }

            if self.dns_debug_active {
                crate::serial_println!(
                    "[DNS-DEBUG] timeout waiting for response txid=0x{:04x} attempt={} domain={}",
                    txid,
                    attempt + 1,
                    domain
                );
            }
            self.dns_debug_finish();

            if attempt + 1 < DNS_QUERY_MAX_ATTEMPTS {
                progress(self);
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

    fn next_dns_txid(&mut self) -> u16 {
        if self.dns_next_txid == 0 {
            self.dns_next_txid = (crate::pit::get_ticks() as u16).wrapping_add(0xA5C3);
            if self.dns_next_txid == 0 {
                self.dns_next_txid = 1;
            }
        }

        let txid = self.dns_next_txid;
        self.dns_next_txid = self.dns_next_txid.wrapping_add(1);
        if self.dns_next_txid == 0 {
            self.dns_next_txid = 1;
        }
        txid
    }

    fn clear_stale_dns_responses(&mut self) {
        for slot in &mut self.udp_rx_queue {
            if !slot.valid || slot.dst_port != DNS_CLIENT_SRC_PORT {
                continue;
            }
            *slot = UdpRxEntry::empty();
        }
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

        if offset + 4 > response.len() {
            return Err("Invalid DNS question");
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
                    if offset >= response.len() {
                        return Err("Invalid answer name");
                    }
                    let len = response[offset];
                    if len == 0 {
                        offset += 1;
                        break;
                    }
                    if offset + 1 + len as usize > response.len() {
                        return Err("Invalid answer label");
                    }
                    offset += 1 + len as usize;
                }
            }

            if offset + 10 > response.len() {
                return Err("Invalid answer header");
            }
            let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let rdlength =
                u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
            offset += 10;
            if offset + rdlength > response.len() {
                return Err("Invalid answer data");
            }

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
    #[cfg(not(target_arch = "aarch64"))]
    pub fn poll_once(&mut self) -> Result<bool, &'static str> {
        let frame = unsafe { &mut *core::ptr::addr_of_mut!(POLL_RX_STAGE) };
        let frame_len = {
            let mut driver = super::e1000::E1000_DRIVER.lock();
            let interface = driver.as_mut().ok_or("No E1000 driver")?;
            match interface.recv_frame(frame) {
                Ok(len) => len,
                Err(_) => return Ok(false), // No packet available
            }
        };

        self.dispatch_frame(&frame[..frame_len])?;
        Ok(true)
    }
    #[cfg(target_arch = "aarch64")]
    pub fn poll_once(&mut self) -> Result<bool, &'static str> {
        let mut processed = false;
        super::virtio_net::poll_rx(|frame| {
            let _ = self.dispatch_frame(frame);
            processed = true;
        });
        Ok(processed)
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
                if self.dns_debug_active {
                    crate::serial_println!("[DNS-DEBUG] dispatch eth=arp len={}", frame.len());
                }
                let _ = self.handle_arp(&frame[14..]);
            }
            ETHERTYPE_IPV4 => {
                if self.dns_debug_active {
                    if frame.len() >= 34 {
                        let src = Ipv4Addr([frame[26], frame[27], frame[28], frame[29]]);
                        let dst = Ipv4Addr([frame[30], frame[31], frame[32], frame[33]]);
                        let proto = frame[23];
                        if self.dns_debug_ipv4_relevant(src, dst) {
                            crate::serial_println!(
                                "[DNS-DEBUG] dispatch eth=ipv4 src={}.{}.{}.{} dst={}.{}.{}.{} proto={} len={} txid=0x{:04x}",
                                src.0[0],
                                src.0[1],
                                src.0[2],
                                src.0[3],
                                dst.0[0],
                                dst.0[1],
                                dst.0[2],
                                dst.0[3],
                                proto,
                                frame.len(),
                                self.dns_debug_txid
                            );
                        }
                    } else {
                        crate::serial_println!(
                            "[DNS-DEBUG] dispatch eth=ipv4 short len={} txid=0x{:04x}",
                            frame.len(),
                            self.dns_debug_txid
                        );
                    }
                }
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
                    close_conn_preserving_recv(conn);
                    Self::maybe_record_tcp_socket_state_event(
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
                let _ = send_tcp_segment(
                    self,
                    ep,
                    seq,
                    ack,
                    flags,
                    &payload[..len],
                    TCP_ADVERTISED_WINDOW_MAX,
                );
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

    pub fn get_dns_server(&self) -> Ipv4Addr {
        self.dns_server
    }

    #[inline]
    fn dns_debug_begin(&mut self, txid: u16) {
        if !DNS_DEBUG_ENABLED {
            return;
        }
        self.dns_debug_active = true;
        self.dns_debug_txid = txid;
        self.dns_debug_miss_logged = false;
    }

    #[inline]
    fn dns_debug_finish(&mut self) {
        self.dns_debug_active = false;
        self.dns_debug_txid = 0;
        self.dns_debug_miss_logged = false;
    }

    #[inline]
    fn dns_debug_ipv4_relevant(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> bool {
        self.dns_debug_active
            && (src_ip == self.dns_server
                || src_ip == self.my_ip
                || dst_ip == self.my_ip
                || dst_ip == self.dns_server)
    }

    #[inline]
    fn dns_debug_udp_relevant(&self, src_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> bool {
        self.dns_debug_active
            && (src_ip == self.dns_server
                || src_port == DNS_SERVER_PORT
                || dst_port == DNS_CLIENT_SRC_PORT)
    }

    #[inline]
    fn tcp_connect_debug_active(&self) -> bool {
        false
    }

    #[inline]
    fn tcp_connect_debug_relevant_ipv4(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        proto: u8,
    ) -> bool {
        self.tcp_connect_debug_active()
            && proto == IP_PROTOCOL_TCP
            && (src_ip == self.my_ip || dst_ip == self.my_ip)
    }

    fn tcp_connect_debug_log_ipv4(
        &self,
        reason: &str,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        proto: u8,
        packet_len: usize,
        extra: usize,
    ) {
        if !self.tcp_connect_debug_relevant_ipv4(src_ip, dst_ip, proto) {
            return;
        }
        crate::serial_println!(
            "[TCP-CONNECT] ipv4 {} src={}.{}.{}.{} dst={}.{}.{}.{} proto={} len={} extra={}",
            reason,
            src_ip.0[0],
            src_ip.0[1],
            src_ip.0[2],
            src_ip.0[3],
            dst_ip.0[0],
            dst_ip.0[1],
            dst_ip.0[2],
            dst_ip.0[3],
            proto,
            packet_len,
            extra
        );
    }

    fn dns_debug_log_ipv4_reason(
        &self,
        reason: &str,
        src_ip: Option<Ipv4Addr>,
        dst_ip: Option<Ipv4Addr>,
        proto: Option<u8>,
        packet_len: usize,
        extra: usize,
    ) {
        if !self.dns_debug_active {
            return;
        }

        match (src_ip, dst_ip, proto) {
            (Some(src), Some(dst), Some(proto)) => crate::serial_println!(
                "[DNS-DEBUG] ipv4 {} src={}.{}.{}.{} dst={}.{}.{}.{} proto={} len={} extra={} txid=0x{:04x}",
                reason,
                src.0[0],
                src.0[1],
                src.0[2],
                src.0[3],
                dst.0[0],
                dst.0[1],
                dst.0[2],
                dst.0[3],
                proto,
                packet_len,
                extra,
                self.dns_debug_txid
            ),
            _ => crate::serial_println!(
                "[DNS-DEBUG] ipv4 {} len={} extra={} txid=0x{:04x}",
                reason,
                packet_len,
                extra,
                self.dns_debug_txid
            ),
        }
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
        if !NETWORK_CONFIG_TEMPORAL_EVENTS_ENABLED || crate::temporal::is_replay_active() {
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

    #[inline]
    fn maybe_record_tcp_socket_listener_event(listener_id: u32, port: u16, event: u8) {
        if TCP_TEMPORAL_EVENTS_ENABLED {
            let _ = crate::temporal::record_tcp_socket_listener_event(listener_id, port, event);
        }
    }

    #[inline]
    fn maybe_record_tcp_socket_state_event(
        conn_id: u32,
        state: u8,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        event: u8,
        detail: u32,
    ) {
        if TCP_TEMPORAL_EVENTS_ENABLED {
            let _ = crate::temporal::record_tcp_socket_state_event(
                conn_id,
                state,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                event,
                detail,
            );
        }
    }

    #[inline]
    fn maybe_record_tcp_socket_data_event(
        conn_id: u32,
        state: u8,
        local_ip: [u8; 4],
        local_port: u16,
        remote_ip: [u8; 4],
        remote_port: u16,
        event: u8,
        payload: &[u8],
    ) {
        if TCP_TEMPORAL_EVENTS_ENABLED {
            let _ = crate::temporal::record_tcp_socket_data_event(
                conn_id,
                state,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                event,
                payload,
            );
        }
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
        let has_interface = (flags & TEMPORAL_NETWORK_CONFIG_FLAG_HAS_INTERFACE) != 0;
        let ip_is_zero = my_ip.0 == [0, 0, 0, 0];
        let gateway_is_zero = gateway_ip.0 == [0, 0, 0, 0];
        let dns_is_zero = dns_server.0 == [0, 0, 0, 0];
        if !has_interface && ip_is_zero && gateway_is_zero && dns_is_zero {
            if self.interface_configured() {
                self.log_config_state("rejected empty temporal config over valid live state");
            } else {
                crate::serial_println!(
                    "[NET-CONFIG] rejecting empty temporal config state while interface absent"
                );
            }
            return Ok(());
        }
        if has_interface && (ip_is_zero || gateway_is_zero || dns_is_zero) {
            crate::serial_println!(
                "[NET-CONFIG] ignoring invalid temporal config ip={}.{}.{}.{} gw={}.{}.{}.{} dns={}.{}.{}.{}",
                my_ip.0[0],
                my_ip.0[1],
                my_ip.0[2],
                my_ip.0[3],
                gateway_ip.0[0],
                gateway_ip.0[1],
                gateway_ip.0[2],
                gateway_ip.0[3],
                dns_server.0[0],
                dns_server.0[1],
                dns_server.0[2],
                dns_server.0[3],
            );
            return Ok(());
        }
        if !has_interface && (!ip_is_zero || !gateway_is_zero || !dns_is_zero) {
            crate::serial_println!(
                "[NET-CONFIG] rejecting inconsistent temporal config ip={}.{}.{}.{} gw={}.{}.{}.{} dns={}.{}.{}.{} has_if=0",
                my_ip.0[0],
                my_ip.0[1],
                my_ip.0[2],
                my_ip.0[3],
                gateway_ip.0[0],
                gateway_ip.0[1],
                gateway_ip.0[2],
                gateway_ip.0[3],
                dns_server.0[0],
                dns_server.0[1],
                dns_server.0[2],
                dns_server.0[3],
            );
            return Ok(());
        }
        self.my_ip = my_ip;
        self.my_mac = my_mac;
        self.gateway_ip = gateway_ip;
        self.dns_server = dns_server;
        self.dhcp_enabled = (flags & TEMPORAL_NETWORK_CONFIG_FLAG_DHCP) != 0;
        self.has_interface = has_interface;
        self.log_config_state("accepted temporal config");
        Ok(())
    }

    // ========================================================================
    // TCP Socket API
    // ========================================================================

    pub fn tcp_listen(&mut self, port: u16) -> Result<u16, &'static str> {
        let result = self.tcp.listen(port);
        if let Ok(listener_id) = result {
            Self::maybe_record_tcp_socket_listener_event(
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
                Self::maybe_record_tcp_socket_state_event(
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

    fn with_tcp_manager<R>(&mut self, f: impl FnOnce(&mut TcpManager, &mut Self) -> R) -> R {
        let stack_ptr = self as *mut Self;
        let tcp_ptr = &mut self.tcp as *mut TcpManager;
        unsafe { f(&mut *tcp_ptr, &mut *stack_ptr) }
    }

    pub fn tcp_connect(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Result<u16, &'static str> {
        let res = self.with_tcp_manager(|tcp, stack| tcp.connect(stack, remote_ip, remote_port));
        if let Ok(conn_id) = res {
            if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                Self::maybe_record_tcp_socket_state_event(
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

    pub fn tcp_connection_state(&self, conn_id: u16) -> Option<u8> {
        self.tcp.find_conn_id(conn_id).map(|conn| conn.state as u8)
    }

    pub fn tcp_connection_eof(&self, conn_id: u16) -> bool {
        match self.tcp.find_conn_id(conn_id) {
            None => true,
            Some(conn) => {
                conn_recv_occupied(conn) == 0
                    && matches!(
                        conn.state,
                        TcpState::Closed
                            | TcpState::CloseWait
                            | TcpState::LastAck
                            | TcpState::TimeWait
                    )
            }
        }
    }

    pub fn tcp_send(&mut self, conn_id: u16, data: &[u8]) -> Result<usize, &'static str> {
        let res = self.with_tcp_manager(|tcp, stack| tcp.send(stack, conn_id, data));
        if let Ok(sent) = res {
            if sent > 0 {
                if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                    Self::maybe_record_tcp_socket_data_event(
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
        res
    }

    pub fn tcp_recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<usize, &'static str> {
        let (read_len, was_full) = self.tcp.recv(conn_id, out)?;
        if read_len > 0 {
            if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                Self::maybe_record_tcp_socket_data_event(
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
        if let Some(conn) = self.tcp.find_conn_id_mut(conn_id) {
            if conn.state == TcpState::Closed && conn_recv_occupied(conn) == 0 {
                conn.in_use = false;
            }
        }
        // Send window-update ACK if buffer was full before the read (peer's window was 0).
        if was_full {
            if let Some(conn) = self.tcp.find_conn_id(conn_id) {
                let ep = tcp_endpoint(conn);
                let seq = conn.snd_nxt;
                let ack = conn.rcv_nxt;
                let adv_win = conn_recv_window(conn);
                let _ = send_tcp_segment(self, ep, seq, ack, TCP_FLAG_ACK, &[], adv_win);
            }
        }
        Ok(read_len)
    }

    pub fn tcp_close(&mut self, conn_id: u16) -> Result<(), &'static str> {
        let pre_close_snapshot = self.tcp.find_conn_id(conn_id).copied();
        let res = self.with_tcp_manager(|tcp, stack| tcp.close(stack, conn_id));
        if res.is_ok() {
            if let Some(mut conn) = pre_close_snapshot {
                if let Some(updated) = self.tcp.find_conn_id(conn_id) {
                    conn = *updated;
                } else {
                    conn.state = TcpState::Closed;
                }
                Self::maybe_record_tcp_socket_state_event(
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
                conn.recv_head = 0;
                conn.recv_tail = 0;
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
                // Restore into ring — reset to clean state first then write from head.
                conn.recv_head = 0;
                conn.recv_tail = 0;
                let copy_len = core::cmp::min(preview.len(), TCP_BUF_SIZE);
                if copy_len > 0 {
                    conn.recv_buf[..copy_len].copy_from_slice(&preview[..copy_len]);
                    conn.recv_tail = copy_len;
                }
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

#[inline]
fn tcp_http_debug_conn(conn: &TcpConn) -> bool {
    conn.remote_port == 80
        || conn.remote_port == 443
        || conn.local_port == 80
        || conn.local_port == 443
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
/// Power-of-two receive buffer: allows O(1) ring-mask indexing.
const TCP_BUF_SIZE: usize = 65_536;
const TCP_BUF_MASK: usize = TCP_BUF_SIZE - 1;
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
const TCP_ADVERTISED_WINDOW_MAX: u16 = u16::MAX;

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
    /// Ring-buffer producer index (bytes written mod TCP_BUF_SIZE).
    recv_tail: usize,
    /// Ring-buffer consumer index (bytes consumed mod TCP_BUF_SIZE).
    recv_head: usize,
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
            recv_tail: 0,
            recv_head: 0,
            http_pending: false,
            ack_pending: 0,
            ack_pending_since: 0,
            peer_wscale: 0,
            snd_wnd: 65_535, // conservative default until first ACK
        }
    }
}

#[inline]
fn conn_recv_occupied(conn: &TcpConn) -> usize {
    conn.recv_tail.wrapping_sub(conn.recv_head) & TCP_BUF_MASK
}

#[inline]
fn close_conn_preserving_recv(conn: &mut TcpConn) {
    conn.state = TcpState::Closed;
    if conn_recv_occupied(conn) == 0 {
        conn.in_use = false;
    }
}

#[inline]
fn clear_retransmit_if_fully_acked(conn: &mut TcpConn) {
    if conn.snd_una < conn.snd_nxt {
        return;
    }
    conn.last_send_tick = 0;
    conn.last_payload_len = 0;
    conn.retries = 0;
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
            0 => break, // EOL
            1 => {
                i += 1;
            } // NOP
            kind => {
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    break;
                } // malformed
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
        if self.next_id == 0 {
            self.next_id = 1;
        }
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
        let mut syn_result = Err("TX busy");
        for _ in 0..8 {
            match send_syn_segment(stack, ep, conn.snd_nxt, conn.rcv_nxt, TCP_FLAG_SYN, adv_win) {
                Ok(()) => {
                    syn_result = Ok(());
                    break;
                }
                Err("TX busy") => {
                    let _ = stack.poll_once();
                }
                Err(e) => {
                    syn_result = Err(e);
                    break;
                }
            }
        }
        if let Err(e) = syn_result {
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
            if chunk_max == 0 {
                break;
            }
            let chunk = &data[sent_total..sent_total + chunk_max];
            let ep = tcp_endpoint(conn);
            let adv_win = conn_recv_window(conn);
            let mut sent = false;
            for _ in 0..8 {
                match send_tcp_segment(
                    stack,
                    ep,
                    conn.snd_nxt,
                    conn.rcv_nxt,
                    TCP_FLAG_ACK | TCP_FLAG_PSH,
                    chunk,
                    adv_win,
                ) {
                    Ok(()) => {
                        sent = true;
                        break;
                    }
                    Err("TX busy") => {
                        let _ = stack.poll_once();
                    }
                    Err(e) => return Err(e),
                }
            }
            if !sent {
                return Err("TX busy");
            }
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

    fn recv(&mut self, conn_id: u16, out: &mut [u8]) -> Result<(usize, bool), &'static str> {
        let conn = self
            .find_conn_id_mut(conn_id)
            .ok_or("Connection not found")?;
        let occupied = conn.recv_tail.wrapping_sub(conn.recv_head) & TCP_BUF_MASK;
        if occupied == 0 {
            return Ok((0, false));
        }
        // Was the buffer full before this read?
        let was_full = occupied >= TCP_BUF_SIZE - 1;
        let len = core::cmp::min(out.len(), occupied);
        let head = conn.recv_head & TCP_BUF_MASK;
        let first = core::cmp::min(len, TCP_BUF_SIZE - head);
        out[..first].copy_from_slice(&conn.recv_buf[head..head + first]);
        if first < len {
            out[first..len].copy_from_slice(&conn.recv_buf[..len - first]);
        }
        conn.recv_head = conn.recv_head.wrapping_add(len);
        Ok((len, was_full))
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
        close_conn_preserving_recv(conn);
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
                        close_conn_preserving_recv(conn);
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
                        close_conn_preserving_recv(conn);
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
                let _ = send_tcp_segment(
                    stack,
                    ep,
                    seq_out,
                    ack_out,
                    TCP_FLAG_ACK,
                    &[],
                    TCP_ADVERTISED_WINDOW_MAX,
                );
            }
            if let Some((ep, seq, ack, flags, payload, len)) = action {
                let _ = send_tcp_segment(
                    stack,
                    ep,
                    seq,
                    ack,
                    flags,
                    &payload[..len],
                    TCP_ADVERTISED_WINDOW_MAX,
                );
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
    // Bytes occupied in the ring = (tail - head) mod TCP_BUF_SIZE.
    // Free space = TCP_BUF_SIZE - occupied.
    let occupied = conn.recv_tail.wrapping_sub(conn.recv_head) & TCP_BUF_MASK;
    let free = TCP_BUF_SIZE.saturating_sub(occupied);
    free.min(0xFFFF) as u16
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
    let next_hop = if stack.is_local(ep.remote_ip) {
        ep.remote_ip
    } else {
        stack.gateway_ip
    };
    let dest_mac = stack.resolve_mac(next_hop)?;

    let tcp_header_len = 20;
    let ip_header_len = 20;
    let total_len = 14 + ip_header_len + tcp_header_len + payload.len();
    if total_len > 1514 {
        return Err("Packet too large");
    }

    let frame = unsafe { &mut *core::ptr::addr_of_mut!(TCP_TX_STAGE) };
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

    backend_send_frame(&frame[..total_len])
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
    let next_hop = if stack.is_local(ep.remote_ip) {
        ep.remote_ip
    } else {
        stack.gateway_ip
    };
    let dest_mac = stack.resolve_mac(next_hop)?;

    // TCP options: MSS(4) + NOP + WSCALE(3) + NOP = 8 bytes (32-bit aligned)
    let options: [u8; 8] = [
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
        0x01, // NOP
        0x03, 0x03, TCP_WSCALE, // window scale
    ];
    let tcp_header_len = 20 + options.len(); // 28
    let ip_header_len = 20;
    let total_len = 14 + ip_header_len + tcp_header_len;
    let frame = unsafe { &mut *core::ptr::addr_of_mut!(TCP_TX_STAGE) };
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

    backend_send_frame(&frame[..total_len])
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
            let src = if packet.len() >= 16 {
                Some(Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]))
            } else {
                None
            };
            let dst = if packet.len() >= 20 {
                Some(Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]))
            } else {
                None
            };
            if let (Some(src), Some(dst)) = (src, dst) {
                self.tcp_connect_debug_log_ipv4(
                    "reject packet-too-short",
                    src,
                    dst,
                    if packet.len() > 9 { packet[9] } else { 0 },
                    packet.len(),
                    20,
                );
            }
            self.dns_debug_log_ipv4_reason(
                "reject packet-too-short",
                None,
                None,
                None,
                packet.len(),
                20,
            );
            return Err("IPv4 packet too short");
        }
        let src = Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]);
        let dst = Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]);
        let proto = packet[9];
        let dns_relevant = self.dns_debug_ipv4_relevant(src, dst);
        if self.tcp_connect_debug_relevant_ipv4(src, dst, proto) {
            self.tcp_connect_debug_log_ipv4("dispatch", src, dst, proto, packet.len(), 0);
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if ihl < 20 || packet.len() < ihl {
            self.tcp_connect_debug_log_ipv4(
                "reject invalid-ihl",
                src,
                dst,
                proto,
                packet.len(),
                ihl,
            );
            if dns_relevant {
                self.dns_debug_log_ipv4_reason(
                    "reject invalid-ihl",
                    Some(src),
                    Some(dst),
                    Some(proto),
                    packet.len(),
                    ihl,
                );
            }
            return Err("Invalid IPv4 header");
        }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total_len > packet.len() {
            self.tcp_connect_debug_log_ipv4(
                "reject length-mismatch",
                src,
                dst,
                proto,
                packet.len(),
                total_len,
            );
            if dns_relevant {
                self.dns_debug_log_ipv4_reason(
                    "reject length-mismatch",
                    Some(src),
                    Some(dst),
                    Some(proto),
                    packet.len(),
                    total_len,
                );
            }
            return Err("IPv4 length mismatch");
        }
        if dst != self.my_ip {
            self.tcp_connect_debug_log_ipv4(
                "reject dst-mismatch",
                src,
                dst,
                proto,
                total_len,
                self.my_ip.to_u32() as usize,
            );
            if dns_relevant {
                self.dns_debug_log_ipv4_reason(
                    "reject dst-mismatch",
                    Some(src),
                    Some(dst),
                    Some(proto),
                    total_len,
                    self.my_ip.to_u32() as usize,
                );
            }
            return Ok(());
        }
        if self.tcp_connect_debug_relevant_ipv4(src, dst, proto) {
            self.tcp_connect_debug_log_ipv4("accept", src, dst, proto, total_len, ihl);
        }
        if proto != IP_PROTOCOL_UDP && dns_relevant {
            self.dns_debug_log_ipv4_reason(
                "reject proto-not-udp",
                Some(src),
                Some(dst),
                Some(proto),
                total_len,
                IP_PROTOCOL_UDP as usize,
            );
        }
        match proto {
            IP_PROTOCOL_TCP => {
                self.handle_tcp(src, &packet[ihl..total_len])?;
            }
            IP_PROTOCOL_UDP => {
                if dns_relevant {
                    self.dns_debug_log_ipv4_reason(
                        "accept udp",
                        Some(src),
                        Some(dst),
                        Some(proto),
                        total_len,
                        ihl,
                    );
                }
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
        if self.dns_debug_udp_relevant(src_ip, src_port, dst_port) {
            crate::serial_println!(
                "[DNS-DEBUG] udp ingress src={}.{}.{}.{}:{} dst_port={} payload_len={}",
                src_ip.0[0],
                src_ip.0[1],
                src_ip.0[2],
                src_ip.0[3],
                src_port,
                dst_port,
                payload.len()
            );
        }
        if dst_port == super::capnet::CAPNET_CONTROL_PORT {
            self.handle_capnet_control(src_ip, src_port, payload)?;
            return Ok(());
        }
        self.enqueue_udp(src_ip, src_port, dst_port, payload);
        Ok(())
    }

    fn enqueue_udp(&mut self, src_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) {
        if payload.len() > UDP_RX_PAYLOAD_MAX {
            if self.dns_debug_udp_relevant(src_ip, src_port, dst_port) {
                crate::serial_println!(
                    "[DNS-DEBUG] drop oversized UDP src_port={} dst_port={} len={}",
                    src_port,
                    dst_port,
                    payload.len()
                );
            }
            return;
        }

        for slot in &mut self.udp_rx_queue {
            if slot.valid {
                continue;
            }

            slot.valid = true;
            slot.src_ip = src_ip;
            slot.src_port = src_port;
            slot.dst_port = dst_port;
            slot.payload_len = payload.len();
            slot.payload[..payload.len()].copy_from_slice(payload);
            if self.dns_debug_udp_relevant(src_ip, src_port, dst_port) {
                crate::serial_println!(
                    "[DNS-DEBUG] queued UDP src_port={} dst_port={} len={}",
                    src_port,
                    dst_port,
                    payload.len()
                );
            }
            return;
        }

        if self.dns_debug_udp_relevant(src_ip, src_port, dst_port) {
            crate::serial_println!(
                "[DNS-DEBUG] drop full UDP queue src_port={} dst_port={} len={}",
                src_port,
                dst_port,
                payload.len()
            );
        }
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
                    close_conn_preserving_recv(conn);
                    Self::maybe_record_tcp_socket_state_event(
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
                    clear_retransmit_if_fully_acked(conn);
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
                    Self::maybe_record_tcp_socket_state_event(
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
                    Self::maybe_record_tcp_socket_state_event(
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
                    // Ring-buffer write: only copy as many bytes as fit in free space.
                    let occupied = conn.recv_tail.wrapping_sub(conn.recv_head) & TCP_BUF_MASK;
                    let free = TCP_BUF_SIZE.saturating_sub(occupied);
                    let copy_len = core::cmp::min(payload.len(), free);
                    // Split write at ring wrap boundary.
                    let tail = conn.recv_tail & TCP_BUF_MASK;
                    let first = core::cmp::min(copy_len, TCP_BUF_SIZE - tail);
                    conn.recv_buf[tail..tail + first].copy_from_slice(&payload[..first]);
                    if first < copy_len {
                        conn.recv_buf[..copy_len - first]
                            .copy_from_slice(&payload[first..copy_len]);
                    }
                    conn.recv_tail = conn.recv_tail.wrapping_add(copy_len);
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload.len() as u32);
                    Self::maybe_record_tcp_socket_data_event(
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
                    let occupied = conn.recv_tail.wrapping_sub(conn.recv_head) & TCP_BUF_MASK;
                    let force_ack = (flags & TCP_FLAG_PSH != 0)
                        || conn.ack_pending as usize >= TCP_DELAYED_ACK_SEGMENTS as usize
                        || occupied >= TCP_BUF_SIZE - 1;
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
                        Self::maybe_record_tcp_socket_state_event(
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
                        close_conn_preserving_recv(conn);
                        Self::maybe_record_tcp_socket_state_event(
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
                        Self::maybe_record_tcp_socket_state_event(
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
                    close_conn_preserving_recv(conn);
                    Self::maybe_record_tcp_socket_state_event(
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
                let _ = send_tcp_segment(
                    self,
                    ep,
                    seq_out,
                    ack_out,
                    TCP_FLAG_ACK,
                    &[],
                    TCP_ADVERTISED_WINDOW_MAX,
                );
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
                        .cap_token_sign_with_key(k0, k1, &isn_data)
                        as u32;
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
                    Self::maybe_record_tcp_socket_state_event(
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
                    let adv_win = TCP_ADVERTISED_WINDOW_MAX;
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
        let _ = send_tcp_segment(
            self,
            ep,
            seq,
            ack,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            body,
            TCP_ADVERTISED_WINDOW_MAX,
        );

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

        let _ = send_tcp_segment(
            self,
            ep2,
            seq2,
            ack2,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            &[],
            TCP_ADVERTISED_WINDOW_MAX,
        );
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
// Checksum Calculation
// ============================================================================

fn calculate_checksum(data: &[u8]) -> u16 {
    finalize_checksum(checksum_accum(data))
}

#[cfg(test)]
mod tests {
    use super::{Ipv4Addr, NetworkStack, DNS_CLIENT_SRC_PORT, DNS_SERVER_PORT};

    #[test]
    fn handle_udp_queues_non_capnet_payloads() {
        let mut stack = NetworkStack::new();
        let payload = b"dns reply bytes";
        let udp_len = (8 + payload.len()) as u16;
        let mut datagram = [0u8; 8 + 15];
        datagram[0..2].copy_from_slice(&53u16.to_be_bytes());
        datagram[2..4].copy_from_slice(&53000u16.to_be_bytes());
        datagram[4..6].copy_from_slice(&udp_len.to_be_bytes());
        datagram[8..8 + payload.len()].copy_from_slice(payload);

        stack
            .handle_udp(Ipv4Addr::new(8, 8, 8, 8), &datagram[..8 + payload.len()])
            .expect("queue UDP payload");

        let mut out = [0u8; 32];
        let len = stack.recv_udp(53000, &mut out).expect("receive queued UDP");
        assert_eq!(&out[..len], payload);
    }

    #[test]
    fn recv_udp_keeps_non_matching_packets_queued() {
        let mut stack = NetworkStack::new();
        let payload = b"queued later";
        let udp_len = (8 + payload.len()) as u16;
        let mut datagram = [0u8; 8 + 12];
        datagram[0..2].copy_from_slice(&53u16.to_be_bytes());
        datagram[2..4].copy_from_slice(&53000u16.to_be_bytes());
        datagram[4..6].copy_from_slice(&udp_len.to_be_bytes());
        datagram[8..8 + payload.len()].copy_from_slice(payload);

        stack
            .handle_udp(Ipv4Addr::new(1, 1, 1, 1), &datagram[..8 + payload.len()])
            .expect("queue UDP payload");

        let mut out = [0u8; 32];
        assert_eq!(
            stack.recv_udp(9999, &mut out),
            Err("No UDP packet available")
        );
        let len = stack.recv_udp(53000, &mut out).expect("receive queued UDP");
        assert_eq!(&out[..len], payload);
    }

    #[test]
    fn next_dns_txid_advances_monotonically() {
        let mut stack = NetworkStack::new();
        let first = stack.next_dns_txid();
        let second = stack.next_dns_txid();
        let third = stack.next_dns_txid();

        assert_ne!(first, 0);
        assert_eq!(second, first.wrapping_add(1));
        assert_eq!(third, second.wrapping_add(1));
    }

    #[test]
    fn clear_stale_dns_responses_removes_only_dns_client_port_entries() {
        let mut stack = NetworkStack::new();
        stack.enqueue_udp(
            Ipv4Addr::new(10, 0, 2, 3),
            DNS_SERVER_PORT,
            DNS_CLIENT_SRC_PORT,
            &[0x12, 0x34],
        );
        stack.enqueue_udp(
            Ipv4Addr::new(1, 1, 1, 1),
            1111,
            9999,
            b"keep me",
        );

        stack.clear_stale_dns_responses();

        let mut dns_out = [0u8; 16];
        assert_eq!(
            stack.recv_udp(DNS_CLIENT_SRC_PORT, &mut dns_out),
            Err("No UDP packet available")
        );

        let mut other_out = [0u8; 16];
        let len = stack.recv_udp(9999, &mut other_out).expect("non-DNS slot kept");
        assert_eq!(&other_out[..len], b"keep me");
    }

    #[test]
    fn fully_acked_segments_stop_retransmit_timer() {
        let mut conn = super::TcpConn::empty();
        conn.snd_una = 100;
        conn.snd_nxt = 120;
        conn.last_send_tick = 55;
        conn.last_payload_len = 20;
        conn.retries = 3;

        super::clear_retransmit_if_fully_acked(&mut conn);
        assert_eq!(conn.last_send_tick, 55);
        assert_eq!(conn.last_payload_len, 20);
        assert_eq!(conn.retries, 3);

        conn.snd_una = 120;
        super::clear_retransmit_if_fully_acked(&mut conn);
        assert_eq!(conn.last_send_tick, 0);
        assert_eq!(conn.last_payload_len, 0);
        assert_eq!(conn.retries, 0);
    }

    #[test]
    fn ipv4_checksum_matches_known_dns_header() {
        let header = [
            0x45, 0x00, 0x00, 0x39, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00,
            0x02, 0x0f, 0x0a, 0x00, 0x02, 0x03,
        ];
        assert_eq!(super::calculate_checksum(&header), 0x62a2);
    }
}
