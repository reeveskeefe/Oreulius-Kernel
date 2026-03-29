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

//! Oreulia Real Network Stack
//!
//! Production TCP/IP stack with WiFi support, real packet I/O, and HTTP client.
//! Features:
//! - WiFi scanning and connection
//! - TCP/IP stack with ARP, ICMP, UDP, TCP
//! - Real DNS resolver
//! - HTTP/1.1 and HTTP/2 client
//! - Capability-based security

#![allow(dead_code)]

pub mod capnet;
#[cfg(not(target_arch = "aarch64"))]
pub mod e1000;
pub mod net_reactor;
pub mod netstack;
#[cfg(not(target_arch = "aarch64"))]
pub mod rtl8139;
pub mod tls;
pub mod virtio_net;
#[cfg(not(target_arch = "aarch64"))]
pub mod wifi;

extern crate alloc;

#[cfg(not(target_arch = "aarch64"))]
use self::wifi::{WifiNetwork, WifiState};
use crate::ipc::ProcessId;
#[cfg(not(target_arch = "aarch64"))]
use crate::pci::PciDevice;
use alloc::vec::Vec;
use spin::Mutex;

const TEMPORAL_NETWORK_LEGACY_SCHEMA_V1: u8 = 1;
const TEMPORAL_NETWORK_LEGACY_HEADER_BYTES: usize = 32;
const TEMPORAL_NETWORK_LEGACY_TCP_ENTRY_BYTES: usize = 36;
const TEMPORAL_NETWORK_LEGACY_DNS_ENTRY_BYTES: usize = 80;
const NETWORK_SERVICE_TEMPORAL_EVENTS_ENABLED: bool = false;

// ============================================================================
// Network Configuration
// ============================================================================

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_DNS_CACHE: usize = 32;
pub const MTU: usize = 1500;
pub const TCP_BUFFER_SIZE: usize = 8192;
const HTTP_IO_CHUNK: usize = 1024;
const HTTP_HEADER_MAX: usize = 2048;

// ============================================================================
// IP Address Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }

    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Ipv4Addr(bytes)
    }

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }

    pub fn to_u32(&self) -> u32 {
        ((self.0[0] as u32) << 24)
            | ((self.0[1] as u32) << 16)
            | ((self.0[2] as u32) << 8)
            | (self.0[3] as u32)
    }

    pub fn from_u32(val: u32) -> Self {
        Ipv4Addr([
            ((val >> 24) & 0xFF) as u8,
            ((val >> 16) & 0xFF) as u8,
            ((val >> 8) & 0xFF) as u8,
            (val & 0xFF) as u8,
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddr([a, b, c, d, e, f])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl SocketAddr {
    pub fn new(ip: Ipv4Addr, port: u16) -> Self {
        SocketAddr { ip, port }
    }
}

// ============================================================================
// Protocol Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

// ============================================================================
// TCP Connection State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Clone, Copy)]
pub struct TcpConnection {
    pub id: u32,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: TcpState,
    pub owner: ProcessId,
    pub seq_num: u32,
    pub ack_num: u32,
    pub window_size: u16,
}

impl TcpConnection {
    pub const fn new() -> Self {
        TcpConnection {
            id: 0,
            local_addr: SocketAddr {
                ip: Ipv4Addr([0, 0, 0, 0]),
                port: 0,
            },
            remote_addr: SocketAddr {
                ip: Ipv4Addr([0, 0, 0, 0]),
                port: 0,
            },
            state: TcpState::Closed,
            owner: ProcessId(0),
            seq_num: 0,
            ack_num: 0,
            window_size: 65535,
        }
    }
}

// ============================================================================
// DNS Cache Entry
// ============================================================================

#[derive(Clone, Copy)]
pub struct DnsEntry {
    pub domain: [u8; 64],
    pub domain_len: usize,
    pub ip: Ipv4Addr,
    pub ttl: u32, // Time to live in seconds
    pub valid: bool,
}

impl DnsEntry {
    pub const fn new() -> Self {
        DnsEntry {
            domain: [0; 64],
            domain_len: 0,
            ip: Ipv4Addr([0, 0, 0, 0]),
            ttl: 0,
            valid: false,
        }
    }
}

// ============================================================================
// HTTP Request/Response
// ============================================================================

#[derive(Clone, Copy)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub host: [u8; 64],
    pub host_len: usize,
    pub path: [u8; 128],
    pub path_len: usize,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
        }
    }
}

pub struct HttpResponse {
    pub status_code: u16,
    pub body: [u8; 4096],
    pub body_len: usize,
}

impl HttpResponse {
    pub const fn new() -> Self {
        HttpResponse {
            status_code: 0,
            body: [0; 4096],
            body_len: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedHttpUrl<'a> {
    scheme: HttpScheme,
    host: &'a str,
    path: &'a str,
    port: u16,
}

// ============================================================================
// Network Service (Production)
// ============================================================================

pub struct NetworkService {
    wifi_enabled: bool,
    ip_address: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_server: Ipv4Addr,
    tcp_connections: [TcpConnection; MAX_CONNECTIONS],
    tcp_count: usize,
    dns_cache: [DnsEntry; MAX_DNS_CACHE],
    dns_cache_count: usize,
    next_conn_id: u32,
}

impl NetworkService {
    pub const fn new() -> Self {
        NetworkService {
            wifi_enabled: false,
            ip_address: Ipv4Addr([0, 0, 0, 0]),
            gateway: Ipv4Addr([192, 168, 1, 1]),
            dns_server: Ipv4Addr([10, 0, 2, 3]), // QEMU usernet DNS proxy
            tcp_connections: [TcpConnection::new(); MAX_CONNECTIONS],
            tcp_count: 0,
            dns_cache: [DnsEntry::new(); MAX_DNS_CACHE],
            dns_cache_count: 0,
            next_conn_id: 1,
        }
    }

    /// Initialize WiFi and network stack
    #[cfg(not(target_arch = "aarch64"))]
    pub fn init_wifi(&mut self, device: PciDevice) -> Result<(), NetworkError> {
        // Initialize WiFi driver
        self::wifi::init(device)?;
        self.wifi_enabled = true;
        self.record_temporal_state_snapshot();
        Ok(())
    }

    /// Scan for WiFi networks
    #[cfg(not(target_arch = "aarch64"))]
    pub fn wifi_scan(&self) -> Result<usize, NetworkError> {
        if !self.wifi_enabled {
            return Err(NetworkError::WiFiNotEnabled);
        }

        let mut wifi = self::wifi::wifi().lock();
        let count = wifi.scan()?;
        Ok(count)
    }

    /// Get WiFi scan results (call after wifi_scan)
    #[cfg(not(target_arch = "aarch64"))]
    pub fn wifi_get_scan_results(
        &self,
    ) -> Result<[WifiNetwork; self::wifi::MAX_SCAN_RESULTS], NetworkError> {
        if !self.wifi_enabled {
            return Err(NetworkError::WiFiNotEnabled);
        }

        let wifi = self::wifi::wifi().lock();
        Ok(*wifi.scan_results_array())
    }

    /// Get WiFi scan result count
    #[cfg(not(target_arch = "aarch64"))]
    pub fn wifi_scan_count(&self) -> usize {
        if !self.wifi_enabled {
            return 0;
        }

        let wifi = self::wifi::wifi().lock();
        wifi.scan_count()
    }

    /// Connect to WiFi network
    #[cfg(not(target_arch = "aarch64"))]
    pub fn wifi_connect(&mut self, ssid: &str, password: Option<&str>) -> Result<(), NetworkError> {
        if !self.wifi_enabled {
            return Err(NetworkError::WiFiNotEnabled);
        }

        let mut wifi = self::wifi::wifi().lock();
        wifi.connect(ssid, password)?;

        // Simulate DHCP - in production, implement real DHCP client
        self.ip_address = Ipv4Addr::new(192, 168, 1, 100);
        self.gateway = Ipv4Addr::new(192, 168, 1, 1);
        self.dns_server = Ipv4Addr::new(8, 8, 8, 8);

        self.record_temporal_state_snapshot();
        Ok(())
    }

    /// Get WiFi connection status
    #[cfg(not(target_arch = "aarch64"))]
    pub fn wifi_status(&self) -> Result<WifiState, NetworkError> {
        if !self.wifi_enabled {
            return Err(NetworkError::WiFiNotEnabled);
        }

        let wifi = self::wifi::wifi().lock();
        Ok(wifi.connection().state)
    }

    /// Resolve domain name to IP address (real DNS)
    pub fn dns_resolve(&mut self, domain: &str) -> Result<Ipv4Addr, NetworkError> {
        self.reactor_dns_resolve(domain)
    }

    /// Perform actual DNS query
    fn perform_dns_query(&self, domain: &str) -> Result<Ipv4Addr, NetworkError> {
        let resolved =
            net_reactor::dns_resolve(domain).map_err(|_| NetworkError::DnsQueryFailed)?;
        Ok(Ipv4Addr::from_bytes(resolved.0))
    }

    fn reactor_dns_resolve(&mut self, domain: &str) -> Result<Ipv4Addr, NetworkError> {
        for i in 0..self.dns_cache_count {
            let entry = &self.dns_cache[i];
            if entry.valid && entry.domain_len == domain.len() {
                let cached_domain =
                    core::str::from_utf8(&entry.domain[..entry.domain_len]).unwrap_or("");
                if cached_domain == domain {
                    return Ok(entry.ip);
                }
            }
        }

        let ip = self.perform_dns_query(domain)?;
        self.cache_dns_entry(domain, ip, 3600);
        Ok(ip)
    }

    /// Cache DNS entry
    fn cache_dns_entry(&mut self, domain: &str, ip: Ipv4Addr, ttl: u32) {
        if self.dns_cache_count >= MAX_DNS_CACHE {
            // Evict oldest entry
            self.dns_cache_count = MAX_DNS_CACHE - 1;
        }

        let mut entry = DnsEntry::new();
        entry.domain_len = domain.len().min(64);
        entry.domain[..entry.domain_len].copy_from_slice(&domain.as_bytes()[..entry.domain_len]);
        entry.ip = ip;
        entry.ttl = ttl;
        entry.valid = true;

        self.dns_cache[self.dns_cache_count] = entry;
        self.dns_cache_count += 1;
        self.record_temporal_state_snapshot();
    }

    /// Perform HTTP GET request (real implementation)
    pub fn http_get(&mut self, url: &str) -> Result<HttpResponse, NetworkError> {
        let parsed = parse_http_url(url);
        let path = if parsed.path.is_empty() {
            "/"
        } else {
            parsed.path
        };

        crate::serial_println!("[HTTP] GET {}{}", parsed.host, path);

        if parsed.scheme == HttpScheme::Https {
            return Err(NetworkError::TlsValidationUnavailable);
        }

        let ip = self.reactor_dns_resolve(parsed.host)?;

        crate::serial_println!(
            "[HTTP] Resolved to {}.{}.{}.{}",
            ip.octets()[0],
            ip.octets()[1],
            ip.octets()[2],
            ip.octets()[3]
        );

        let conn_id = net_reactor::tcp_connect(self::netstack::Ipv4Addr(ip.0), parsed.port)
            .map_err(|_| NetworkError::TcpConnectFailed)?;

        let response = (|| {
            let (request, request_len) =
                Self::build_http_request(HttpMethod::GET, parsed.host, path, parsed.port);
            if request_len == 0 {
                return Err(NetworkError::HttpRequestBuildFailed);
            }

            crate::serial_println!("[HTTP] Sending request...");
            self.reactor_tcp_send(conn_id, &request[..request_len])?;
            crate::serial_println!("[HTTP] Sent {} bytes via TCP", request_len);

            self.reactor_receive_http_response(conn_id)
        })();

        let _ = net_reactor::tcp_close(conn_id);
        response
    }

    /// Send TCP data through the reactor-owned TCP stack.
    fn reactor_tcp_send(&self, conn_id: u16, data: &[u8]) -> Result<(), NetworkError> {
        let timeout_ticks = (crate::pit::get_frequency() as u64)
            .saturating_mul(10)
            .max(1);
        let start_ticks = crate::pit::get_ticks();
        let mut sent_total = 0usize;

        while sent_total < data.len() {
            match net_reactor::tcp_send(conn_id, &data[sent_total..]) {
                Ok(sent_now) => {
                    if sent_now == 0 {
                        if crate::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                            return Err(NetworkError::TcpTimeout);
                        }
                        crate::quantum_scheduler::yield_now();
                        continue;
                    }
                    sent_total = sent_total.saturating_add(sent_now);
                }
                Err(e) => {
                    // SYN/SYN-ACK progression can race with immediate send attempts.
                    if e == "Connection not established" || e == "TX busy" {
                        if crate::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                            return Err(NetworkError::TcpTimeout);
                        }
                        crate::quantum_scheduler::yield_now();
                        continue;
                    }
                    return Err(NetworkError::TcpSendFailed);
                }
            }

            if crate::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                return Err(NetworkError::TcpTimeout);
            }
        }

        Ok(())
    }

    /// Build TCP segment with IP and Ethernet headers
    fn build_tcp_segment(
        &self,
        conn: &TcpConnection,
        data: &[u8],
        is_last: bool,
    ) -> Result<[u8; 1514], NetworkError> {
        let mut packet = [0u8; 1514];
        let mut offset = 0;

        let ip_header_len = 20usize;
        let tcp_header_len = 20usize;
        let frame_len = 14usize
            .saturating_add(ip_header_len)
            .saturating_add(tcp_header_len)
            .saturating_add(data.len());
        if frame_len > packet.len() || frame_len > (MTU + 14) {
            return Err(NetworkError::TcpSendFailed);
        }

        let dest_mac = [0xFFu8; 6];
        #[cfg(not(target_arch = "aarch64"))]
        let src_mac = self::e1000::get_mac_address().unwrap_or([0, 0, 0, 0, 0, 0]);
        #[cfg(target_arch = "aarch64")]
        let src_mac = self::virtio_net::mac_address();
        packet[offset..offset + 6].copy_from_slice(&dest_mac);
        offset += 6;
        packet[offset..offset + 6].copy_from_slice(&src_mac);
        offset += 6;
        packet[offset..offset + 2].copy_from_slice(&0x0800u16.to_be_bytes());
        offset += 2;

        let ip_start = offset;
        packet[offset] = 0x45;
        packet[offset + 1] = 0;
        let total_len = (ip_header_len + tcp_header_len + data.len()) as u16;
        packet[offset + 2..offset + 4].copy_from_slice(&total_len.to_be_bytes());
        let ip_id = (crate::pit::get_ticks() as u16).to_be_bytes();
        packet[offset + 4..offset + 6].copy_from_slice(&ip_id);
        packet[offset + 6..offset + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        packet[offset + 8] = 64;
        packet[offset + 9] = 6;
        packet[offset + 10..offset + 12].copy_from_slice(&0u16.to_be_bytes());
        packet[offset + 12..offset + 16].copy_from_slice(&conn.local_addr.ip.0);
        packet[offset + 16..offset + 20].copy_from_slice(&conn.remote_addr.ip.0);
        let ip_checksum = checksum16(&packet[ip_start..ip_start + ip_header_len]);
        packet[offset + 10..offset + 12].copy_from_slice(&ip_checksum.to_be_bytes());
        offset += ip_header_len;

        let tcp_start = offset;
        packet[offset..offset + 2].copy_from_slice(&conn.local_addr.port.to_be_bytes());
        packet[offset + 2..offset + 4].copy_from_slice(&conn.remote_addr.port.to_be_bytes());
        packet[offset + 4..offset + 8].copy_from_slice(&conn.seq_num.to_be_bytes());
        packet[offset + 8..offset + 12].copy_from_slice(&conn.ack_num.to_be_bytes());
        packet[offset + 12] = ((tcp_header_len / 4) as u8) << 4;
        packet[offset + 13] = if is_last { 0x18 } else { 0x10 };
        packet[offset + 14..offset + 16].copy_from_slice(&conn.window_size.to_be_bytes());
        packet[offset + 16..offset + 18].copy_from_slice(&0u16.to_be_bytes());
        packet[offset + 18..offset + 20].copy_from_slice(&0u16.to_be_bytes());
        offset += tcp_header_len;

        packet[offset..offset + data.len()].copy_from_slice(data);
        let tcp_len = (tcp_header_len + data.len()) as u16;
        let tcp_checksum = tcp_checksum(
            &conn.local_addr.ip.0,
            &conn.remote_addr.ip.0,
            6,
            tcp_len,
            &packet[tcp_start..tcp_start + tcp_header_len + data.len()],
        );
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(packet)
    }

    /// Send raw packet via network interface
    fn send_raw_packet(&self, packet: &[u8]) -> Result<(), NetworkError> {
        if packet.len() < 34 {
            return Err(NetworkError::TcpSendFailed);
        }
        let frame_len = if packet.len() >= 18 {
            let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
            if ethertype == 0x0800 {
                let ip_total = u16::from_be_bytes([packet[16], packet[17]]) as usize;
                core::cmp::min(packet.len(), 14usize.saturating_add(ip_total))
            } else {
                packet.len()
            }
        } else {
            packet.len()
        };
        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut driver = self::e1000::E1000_DRIVER.lock();
            let nic = driver.as_mut().ok_or(NetworkError::TcpSendFailed)?;
            nic.send_frame(&packet[..frame_len])
                .map_err(|_| NetworkError::TcpSendFailed)
        }
        #[cfg(target_arch = "aarch64")]
        {
            self::virtio_net::send(&packet[..frame_len]).map_err(|_| NetworkError::TcpSendFailed)
        }
    }

    /// Receive and parse HTTP response through the reactor-owned TCP stack.
    fn reactor_receive_http_response(&self, conn_id: u16) -> Result<HttpResponse, NetworkError> {
        let mut response = HttpResponse::new();
        let timeout_ticks = (crate::pit::get_frequency() as u64)
            .saturating_mul(12)
            .max(1);
        let start_ticks = crate::pit::get_ticks();
        let mut chunk = [0u8; HTTP_IO_CHUNK];
        let mut headers = [0u8; HTTP_HEADER_MAX];
        let mut headers_len = 0usize;
        let mut headers_done = false;
        let mut body_len = 0usize;
        let mut content_length: Option<usize> = None;
        let mut chunked = false;

        while crate::pit::get_ticks().saturating_sub(start_ticks) <= timeout_ticks {
            let read = match net_reactor::tcp_recv(conn_id, &mut chunk) {
                Ok(read) => read,
                Err(_) if headers_done => break,
                Err(_) => return Err(NetworkError::TcpReceiveFailed),
            };
            if read == 0 {
                if headers_done {
                    break;
                }
                crate::quantum_scheduler::yield_now();
                continue;
            }

            if !headers_done {
                let available = headers.len().saturating_sub(headers_len);
                if available == 0 {
                    return Err(NetworkError::HttpParseFailed);
                }
                let to_copy = core::cmp::min(read, available);
                headers[headers_len..headers_len + to_copy].copy_from_slice(&chunk[..to_copy]);
                headers_len += to_copy;
                if let Some(end) = find_http_header_end(&headers[..headers_len]) {
                    headers_done = true;
                    response.status_code = parse_http_status_code(&headers[..end]).unwrap_or(200);
                    content_length = parse_http_content_length(&headers[..end]);
                    chunked = http_transfer_chunked(&headers[..end]);
                    let payload_start = end.saturating_add(4);
                    if payload_start < headers_len {
                        let rem = headers_len - payload_start;
                        let copy_len = core::cmp::min(rem, response.body.len());
                        response.body[..copy_len]
                            .copy_from_slice(&headers[payload_start..payload_start + copy_len]);
                        body_len = copy_len;
                    }
                    if let Some(expected) = content_length {
                        if body_len >= expected {
                            break;
                        }
                    } else if chunked && has_chunked_terminator(&response.body[..body_len]) {
                        break;
                    }
                } else if to_copy < read {
                    return Err(NetworkError::HttpParseFailed);
                }
            } else {
                let space = response.body.len().saturating_sub(body_len);
                if space == 0 {
                    break;
                }
                let to_copy = core::cmp::min(read, space);
                response.body[body_len..body_len + to_copy].copy_from_slice(&chunk[..to_copy]);
                body_len += to_copy;
                if let Some(expected) = content_length {
                    if body_len >= expected {
                        break;
                    }
                } else if chunked && has_chunked_terminator(&response.body[..body_len]) {
                    break;
                }
            }
            crate::quantum_scheduler::yield_now();
        }

        if !headers_done {
            if crate::pit::get_ticks().saturating_sub(start_ticks) > timeout_ticks {
                return Err(NetworkError::HttpTimeout);
            }
            return Err(NetworkError::HttpParseFailed);
        }

        if chunked {
            response.body_len = decode_chunked_body_in_place(&mut response.body, body_len)
                .map_err(|_| NetworkError::HttpParseFailed)?;
        } else if let Some(expected) = content_length {
            response.body_len =
                core::cmp::min(body_len, core::cmp::min(expected, response.body.len()));
        } else {
            response.body_len = body_len;
        }

        Ok(response)
    }

    /// Build HTTP/1.1 request
    fn build_http_request(
        method: HttpMethod,
        host: &str,
        path: &str,
        port: u16,
    ) -> ([u8; 512], usize) {
        let mut buf = [0u8; 512];
        let mut pos = 0;
        let mut push = |bytes: &[u8]| {
            let remain = buf.len().saturating_sub(pos);
            if remain == 0 {
                return;
            }
            let len = core::cmp::min(remain, bytes.len());
            buf[pos..pos + len].copy_from_slice(&bytes[..len]);
            pos += len;
        };

        let request_path = if path.is_empty() { "/" } else { path };
        push(method.as_str().as_bytes());
        push(b" ");
        if request_path.starts_with('/') {
            push(request_path.as_bytes());
        } else {
            push(b"/");
            push(request_path.as_bytes());
        }
        push(b" HTTP/1.1\r\nHost: ");
        push(host.as_bytes());
        if port != 80 && port != 443 {
            push(b":");
            let mut port_digits = [0u8; 5];
            let port_len = u16_to_ascii(port, &mut port_digits);
            push(&port_digits[..port_len]);
        }
        push(b"\r\nConnection: close\r\nUser-Agent: Oreulia/1.0\r\nAccept: */*\r\n\r\n");

        (buf, pos)
    }

    /// Get network statistics
    pub fn stats(&self) -> NetworkStats {
        let reactor_info = net_reactor::get_info().ok();
        NetworkStats {
            wifi_enabled: self.wifi_enabled,
            ip_address: reactor_info
                .map(|i| Ipv4Addr::from_bytes(i.ip.0))
                .unwrap_or(self.ip_address),
            tcp_connections: reactor_info.map(|i| i.tcp_conns).unwrap_or(self.tcp_count),
            dns_cache_entries: self.dns_cache_count,
        }
    }
}

fn temporal_tcp_state_to_u8(state: TcpState) -> u8 {
    match state {
        TcpState::Closed => 0,
        TcpState::Listen => 1,
        TcpState::SynSent => 2,
        TcpState::SynReceived => 3,
        TcpState::Established => 4,
        TcpState::FinWait1 => 5,
        TcpState::FinWait2 => 6,
        TcpState::CloseWait => 7,
        TcpState::Closing => 8,
        TcpState::LastAck => 9,
        TcpState::TimeWait => 10,
    }
}

fn temporal_tcp_state_from_u8(v: u8) -> Option<TcpState> {
    match v {
        0 => Some(TcpState::Closed),
        1 => Some(TcpState::Listen),
        2 => Some(TcpState::SynSent),
        3 => Some(TcpState::SynReceived),
        4 => Some(TcpState::Established),
        5 => Some(TcpState::FinWait1),
        6 => Some(TcpState::FinWait2),
        7 => Some(TcpState::CloseWait),
        8 => Some(TcpState::Closing),
        9 => Some(TcpState::LastAck),
        10 => Some(TcpState::TimeWait),
        _ => None,
    }
}

fn temporal_append_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_append_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn temporal_read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

impl NetworkService {
    fn encode_temporal_state_payload(&self, event: u8) -> Option<Vec<u8>> {
        let tcp_count = core::cmp::min(self.tcp_count, MAX_CONNECTIONS);
        let dns_count = core::cmp::min(self.dns_cache_count, MAX_DNS_CACHE);

        let total_len = TEMPORAL_NETWORK_LEGACY_HEADER_BYTES
            .saturating_add(tcp_count.saturating_mul(TEMPORAL_NETWORK_LEGACY_TCP_ENTRY_BYTES))
            .saturating_add(dns_count.saturating_mul(TEMPORAL_NETWORK_LEGACY_DNS_ENTRY_BYTES));
        if total_len > crate::temporal::MAX_TEMPORAL_VERSION_BYTES {
            return None;
        }

        let mut payload = Vec::with_capacity(total_len);
        payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
        payload.push(crate::temporal::TEMPORAL_NETWORK_LEGACY_OBJECT);
        payload.push(event);
        payload.push(TEMPORAL_NETWORK_LEGACY_SCHEMA_V1);
        payload.push(if self.wifi_enabled { 1 } else { 0 });
        payload.push(0);
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(&self.ip_address.0);
        payload.extend_from_slice(&self.gateway.0);
        payload.extend_from_slice(&self.dns_server.0);
        temporal_append_u16(&mut payload, tcp_count as u16);
        temporal_append_u16(&mut payload, dns_count as u16);
        temporal_append_u32(&mut payload, self.next_conn_id);
        temporal_append_u32(&mut payload, 0);

        for i in 0..tcp_count {
            let conn = self.tcp_connections[i];
            temporal_append_u32(&mut payload, conn.id);
            payload.extend_from_slice(&conn.local_addr.ip.0);
            temporal_append_u16(&mut payload, conn.local_addr.port);
            payload.extend_from_slice(&conn.remote_addr.ip.0);
            temporal_append_u16(&mut payload, conn.remote_addr.port);
            payload.push(temporal_tcp_state_to_u8(conn.state));
            payload.push(0);
            payload.push(0);
            payload.push(0);
            temporal_append_u32(&mut payload, conn.owner.0);
            temporal_append_u32(&mut payload, conn.seq_num);
            temporal_append_u32(&mut payload, conn.ack_num);
            temporal_append_u16(&mut payload, conn.window_size);
            temporal_append_u16(&mut payload, 0);
        }

        for i in 0..dns_count {
            let entry = self.dns_cache[i];
            payload.push(if entry.valid { 1 } else { 0 });
            payload.push(entry.domain_len.min(64) as u8);
            temporal_append_u16(&mut payload, 0);
            temporal_append_u32(&mut payload, entry.ttl);
            payload.extend_from_slice(&entry.ip.0);
            temporal_append_u32(&mut payload, 0);
            payload.extend_from_slice(&entry.domain);
        }

        Some(payload)
    }

    fn record_temporal_state_snapshot(&self) {
        if !NETWORK_SERVICE_TEMPORAL_EVENTS_ENABLED || crate::temporal::is_replay_active() {
            return;
        }
        let payload = match self
            .encode_temporal_state_payload(crate::temporal::TEMPORAL_NETWORK_LEGACY_EVENT_STATE)
        {
            Some(v) => v,
            None => return,
        };
        let _ = crate::temporal::record_network_legacy_state_event(&payload);
    }
}

pub fn temporal_apply_network_service_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < TEMPORAL_NETWORK_LEGACY_HEADER_BYTES {
        return Err("temporal legacy network payload too short");
    }
    if payload[3] != TEMPORAL_NETWORK_LEGACY_SCHEMA_V1 {
        return Err("temporal legacy network schema unsupported");
    }

    let wifi_enabled = payload[4] != 0;
    let ip_address = Ipv4Addr([payload[8], payload[9], payload[10], payload[11]]);
    let gateway = Ipv4Addr([payload[12], payload[13], payload[14], payload[15]]);
    let dns_server = Ipv4Addr([payload[16], payload[17], payload[18], payload[19]]);
    let tcp_count =
        temporal_read_u16(payload, 20).ok_or("temporal legacy network tcp count missing")? as usize;
    let dns_count =
        temporal_read_u16(payload, 22).ok_or("temporal legacy network dns count missing")? as usize;
    if tcp_count > MAX_CONNECTIONS || dns_count > MAX_DNS_CACHE {
        return Err("temporal legacy network count out of range");
    }
    let next_conn_id =
        temporal_read_u32(payload, 24).ok_or("temporal legacy network next conn id missing")?;

    let mut offset = TEMPORAL_NETWORK_LEGACY_HEADER_BYTES;
    let mut tcp_connections = [TcpConnection::new(); MAX_CONNECTIONS];
    for i in 0..tcp_count {
        if offset.saturating_add(TEMPORAL_NETWORK_LEGACY_TCP_ENTRY_BYTES) > payload.len() {
            return Err("temporal legacy network tcp entry truncated");
        }
        let id =
            temporal_read_u32(payload, offset).ok_or("temporal legacy network conn id missing")?;
        let local_ip = Ipv4Addr([
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        let local_port = temporal_read_u16(payload, offset + 8)
            .ok_or("temporal legacy network local port missing")?;
        let remote_ip = Ipv4Addr([
            payload[offset + 10],
            payload[offset + 11],
            payload[offset + 12],
            payload[offset + 13],
        ]);
        let remote_port = temporal_read_u16(payload, offset + 14)
            .ok_or("temporal legacy network remote port missing")?;
        let state = temporal_tcp_state_from_u8(payload[offset + 16])
            .ok_or("temporal legacy network state invalid")?;
        let owner_pid = temporal_read_u32(payload, offset + 20)
            .ok_or("temporal legacy network owner missing")?;
        let seq_num =
            temporal_read_u32(payload, offset + 24).ok_or("temporal legacy network seq missing")?;
        let ack_num =
            temporal_read_u32(payload, offset + 28).ok_or("temporal legacy network ack missing")?;
        let window_size = temporal_read_u16(payload, offset + 32)
            .ok_or("temporal legacy network window missing")?;

        let mut conn = TcpConnection::new();
        conn.id = id;
        conn.local_addr = SocketAddr::new(local_ip, local_port);
        conn.remote_addr = SocketAddr::new(remote_ip, remote_port);
        conn.state = state;
        conn.owner = ProcessId(owner_pid);
        conn.seq_num = seq_num;
        conn.ack_num = ack_num;
        conn.window_size = window_size;
        tcp_connections[i] = conn;

        offset = offset.saturating_add(TEMPORAL_NETWORK_LEGACY_TCP_ENTRY_BYTES);
    }

    let mut dns_cache = [DnsEntry::new(); MAX_DNS_CACHE];
    for i in 0..dns_count {
        if offset.saturating_add(TEMPORAL_NETWORK_LEGACY_DNS_ENTRY_BYTES) > payload.len() {
            return Err("temporal legacy network dns entry truncated");
        }
        let valid = payload[offset] != 0;
        let domain_len = payload[offset + 1] as usize;
        let ttl =
            temporal_read_u32(payload, offset + 4).ok_or("temporal legacy network ttl missing")?;
        let ip = Ipv4Addr([
            payload[offset + 8],
            payload[offset + 9],
            payload[offset + 10],
            payload[offset + 11],
        ]);
        let mut domain = [0u8; 64];
        domain.copy_from_slice(&payload[offset + 16..offset + 80]);

        let mut entry = DnsEntry::new();
        entry.valid = valid;
        entry.domain_len = domain_len.min(64);
        entry.domain = domain;
        entry.ip = ip;
        entry.ttl = ttl;
        dns_cache[i] = entry;

        offset = offset.saturating_add(TEMPORAL_NETWORK_LEGACY_DNS_ENTRY_BYTES);
    }

    if offset != payload.len() {
        return Err("temporal legacy network payload trailing bytes");
    }

    let mut net = NETWORK.lock();
    net.wifi_enabled = wifi_enabled;
    net.ip_address = ip_address;
    net.gateway = gateway;
    net.dns_server = dns_server;
    net.tcp_connections = tcp_connections;
    net.tcp_count = tcp_count;
    net.dns_cache = dns_cache;
    net.dns_cache_count = dns_count;
    net.next_conn_id = next_conn_id;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkStats {
    pub wifi_enabled: bool,
    pub ip_address: Ipv4Addr,
    pub tcp_connections: usize,
    pub dns_cache_entries: usize,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    WiFiNotEnabled,
    #[cfg(not(target_arch = "aarch64"))]
    WiFiError(self::wifi::WifiError),
    NotConnected,
    DnsQueryFailed,
    TooManyConnections,
    ConnectionNotFound,
    TcpConnectFailed,
    TcpSendFailed,
    TcpReceiveFailed,
    TcpTimeout,
    HttpRequestBuildFailed,
    HttpParseFailed,
    HttpTimeout,
    UnsupportedScheme,
    TlsValidationUnavailable,
}

#[cfg(not(target_arch = "aarch64"))]
impl From<self::wifi::WifiError> for NetworkError {
    fn from(err: self::wifi::WifiError) -> Self {
        NetworkError::WiFiError(err)
    }
}

impl NetworkError {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkError::WiFiNotEnabled => "WiFi not enabled",
            #[cfg(not(target_arch = "aarch64"))]
            NetworkError::WiFiError(e) => e.as_str(),
            NetworkError::NotConnected => "Not connected",
            NetworkError::DnsQueryFailed => "DNS query failed",
            NetworkError::TooManyConnections => "Too many connections",
            NetworkError::ConnectionNotFound => "Connection not found",
            NetworkError::TcpConnectFailed => "TCP connect failed",
            NetworkError::TcpSendFailed => "TCP send failed",
            NetworkError::TcpReceiveFailed => "TCP receive failed",
            NetworkError::TcpTimeout => "TCP timeout",
            NetworkError::HttpRequestBuildFailed => "HTTP request build failed",
            NetworkError::HttpParseFailed => "HTTP parse failed",
            NetworkError::HttpTimeout => "HTTP timeout",
            NetworkError::UnsupportedScheme => "Unsupported URL scheme",
            NetworkError::TlsValidationUnavailable => {
                "HTTPS blocked: strict certificate validation is not implemented"
            }
        }
    }
}

// ============================================================================
// Global Network Service
// ============================================================================

static NETWORK: Mutex<NetworkService> = Mutex::new(NetworkService::new());

pub fn network() -> &'static Mutex<NetworkService> {
    &NETWORK
}

#[cfg(not(target_arch = "aarch64"))]
pub fn init(wifi_device: Option<PciDevice>) {
    let mut net = NETWORK.lock();

    if let Some(device) = wifi_device {
        match net.init_wifi(device) {
            Ok(()) => {
                crate::vga::print_str("[NET] WiFi initialized\n");
            }
            Err(e) => {
                crate::vga::print_str("[NET] WiFi init failed: ");
                crate::vga::print_str(e.as_str());
                crate::vga::print_str("\n");
            }
        }
    } else {
        crate::vga::print_str("[NET] No WiFi device found\n");
    }
}

#[cfg(target_arch = "aarch64")]
pub fn init() {
    // WiFi/PCI init is x86-only; AArch64 uses virtio-net.
    let _net = NETWORK.lock();
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_http_url(url: &str) -> ParsedHttpUrl<'_> {
    let (scheme, rest, default_port) = if url.starts_with("http://") {
        (HttpScheme::Http, &url[7..], 80u16)
    } else if url.starts_with("https://") {
        (HttpScheme::Https, &url[8..], 443u16)
    } else {
        (HttpScheme::Http, url, 80u16)
    };

    let (host_port, path) = if let Some(slash_pos) = rest.find('/') {
        (&rest[..slash_pos], &rest[slash_pos..])
    } else {
        (rest, "/")
    };

    if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];
        if !host.is_empty() {
            if let Some(port) = parse_u16_decimal(port_str.as_bytes()) {
                return ParsedHttpUrl {
                    scheme,
                    host,
                    path,
                    port,
                };
            }
        }
    }

    ParsedHttpUrl {
        scheme,
        host: host_port,
        path,
        port: default_port,
    }
}

fn parse_u16_decimal(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as u32);
        if value > u16::MAX as u32 {
            return None;
        }
    }
    Some(value as u16)
}

#[cfg(test)]
mod http_client_tests {
    use super::{http_transfer_chunked, parse_http_url, HttpMethod, HttpScheme, NetworkService};

    #[test]
    fn parse_http_url_preserves_scheme_and_port() {
        let http = parse_http_url("http://example.com/test");
        assert_eq!(http.scheme, HttpScheme::Http);
        assert_eq!(http.host, "example.com");
        assert_eq!(http.path, "/test");
        assert_eq!(http.port, 80);

        let https = parse_http_url("https://example.com:8443/secure");
        assert_eq!(https.scheme, HttpScheme::Https);
        assert_eq!(https.host, "example.com");
        assert_eq!(https.path, "/secure");
        assert_eq!(https.port, 8443);
    }

    #[test]
    fn build_http_request_writes_host_path_and_connection_close() {
        let (req, len) =
            NetworkService::build_http_request(HttpMethod::GET, "example.com", "/abc", 80);
        let text = core::str::from_utf8(&req[..len]).unwrap();
        assert!(text.starts_with("GET /abc HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: example.com\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
    }

    #[test]
    fn chunked_transfer_header_detection_is_case_insensitive() {
        let headers =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\nConnection: close\r\n\r\n";
        assert!(http_transfer_chunked(headers));
    }
}

fn u16_to_ascii(mut value: u16, out: &mut [u8; 5]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 5];
    let mut i = 0usize;
    while value > 0 {
        tmp[i] = (value % 10) as u8 + b'0';
        value /= 10;
        i += 1;
    }
    let mut written = 0usize;
    while i > 0 {
        i -= 1;
        out[written] = tmp[i];
        written += 1;
    }
    written
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], proto: u8, length: u16, segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = sum
        .wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32)
        .wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32)
        .wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32)
        .wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32)
        .wrapping_add(proto as u32)
        .wrapping_add(length as u32);

    let mut i = 0usize;
    while i + 1 < segment.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([segment[i], segment[i + 1]]) as u32);
        i += 2;
    }
    if i < segment.len() {
        sum = sum.wrapping_add((segment[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
    }
    !(sum as u16)
}

fn find_http_header_end(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i] == b'\r'
            && data[i + 1] == b'\n'
            && data[i + 2] == b'\r'
            && data[i + 3] == b'\n'
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_http_status_code(headers: &[u8]) -> Option<u16> {
    let line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(headers.len());
    let line = &headers[..line_end];
    if line.len() < 12 || &line[..5] != b"HTTP/" {
        return None;
    }
    let mut spaces = 0usize;
    let mut i = 0usize;
    while i < line.len() {
        if line[i] == b' ' {
            spaces += 1;
            if spaces == 1 {
                break;
            }
        }
        i += 1;
    }
    if i + 4 > line.len() {
        return None;
    }
    parse_u16_decimal(&line[i + 1..i + 4])
}

fn eq_ascii_case(a: u8, b: u8) -> bool {
    let al = if (b'A'..=b'Z').contains(&a) {
        a + 32
    } else {
        a
    };
    let bl = if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    };
    al == bl
}

fn starts_with_ascii_nocase(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    for i in 0..needle.len() {
        if !eq_ascii_case(hay[i], needle[i]) {
            return false;
        }
    }
    true
}

fn parse_http_content_length(headers: &[u8]) -> Option<usize> {
    for line in headers.split(|&b| b == b'\n') {
        let line = if !line.is_empty() && line[line.len() - 1] == b'\r' {
            &line[..line.len() - 1]
        } else {
            line
        };
        if starts_with_ascii_nocase(line, b"content-length:") {
            let value = &line[b"content-length:".len()..];
            let mut start = 0usize;
            while start < value.len() && (value[start] == b' ' || value[start] == b'\t') {
                start += 1;
            }
            let mut end = start;
            while end < value.len() && value[end].is_ascii_digit() {
                end += 1;
            }
            let mut parsed = 0usize;
            for &b in &value[start..end] {
                parsed = parsed
                    .saturating_mul(10)
                    .saturating_add((b - b'0') as usize);
            }
            return Some(parsed);
        }
    }
    None
}

fn http_transfer_chunked(headers: &[u8]) -> bool {
    for line in headers.split(|&b| b == b'\n') {
        let line = if !line.is_empty() && line[line.len() - 1] == b'\r' {
            &line[..line.len() - 1]
        } else {
            line
        };
        if !starts_with_ascii_nocase(line, b"transfer-encoding:") {
            continue;
        }
        if line.len() < 7 {
            continue;
        }
        let mut i = 0usize;
        while i + 7 <= line.len() {
            if starts_with_ascii_nocase(&line[i..i + 7], b"chunked") {
                return true;
            }
            i += 1;
        }
    }
    false
}

fn has_chunked_terminator(body: &[u8]) -> bool {
    if body.len() < 5 {
        return false;
    }
    let mut i = 0usize;
    while i + 5 <= body.len() {
        if body[i] == b'0'
            && body[i + 1] == b'\r'
            && body[i + 2] == b'\n'
            && body[i + 3] == b'\r'
            && body[i + 4] == b'\n'
        {
            return true;
        }
        i += 1;
    }
    false
}

fn decode_hex_size(line: &[u8]) -> Option<usize> {
    let mut value = 0usize;
    let mut saw_digit = false;
    for &b in line {
        if b == b';' {
            break;
        }
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return None,
        };
        saw_digit = true;
        value = value.saturating_mul(16).saturating_add(digit);
    }
    if saw_digit {
        Some(value)
    } else {
        None
    }
}

fn decode_chunked_body_in_place(body: &mut [u8], src_len: usize) -> Result<usize, ()> {
    let mut src = 0usize;
    let mut dst = 0usize;
    while src < src_len {
        let mut line_end = None;
        let mut i = src;
        while i + 1 < src_len {
            if body[i] == b'\r' && body[i + 1] == b'\n' {
                line_end = Some(i);
                break;
            }
            i += 1;
        }
        let line_end = line_end.ok_or(())?;
        let chunk_size = decode_hex_size(&body[src..line_end]).ok_or(())?;
        src = line_end + 2;
        if chunk_size == 0 {
            break;
        }
        if src + chunk_size > src_len {
            return Err(());
        }
        let copy_len = core::cmp::min(chunk_size, body.len().saturating_sub(dst));
        if copy_len > 0 {
            body.copy_within(src..src + copy_len, dst);
            dst += copy_len;
        }
        src += chunk_size;
        if src + 1 >= src_len || body[src] != b'\r' || body[src + 1] != b'\n' {
            return Err(());
        }
        src += 2;
    }
    Ok(dst)
}
