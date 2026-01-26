//! Oreulia Network Stack
//!
//! Capability-based networking with WASM protocol handlers.
//! Features:
//! - Fine-grained network capabilities
//! - HTTP/3 (QUIC) support
//! - Zero-trust networking
//! - Deterministic/replayable network sessions

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
use crate::ipc::ProcessId;

// ============================================================================
// Network Configuration
// ============================================================================

pub const MAX_INTERFACES: usize = 4;
pub const MAX_SOCKETS: usize = 64;
pub const MAX_PACKET_SIZE: usize = 1518; // Standard Ethernet MTU
pub const MAX_CONNECTIONS: usize = 32;

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

    pub fn is_loopback(&self) -> bool {
        self.0[0] == 127
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
    Quic, // HTTP/3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Send,
    Receive,
    Both,
}

// ============================================================================
// Network Capabilities
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct NetworkCapability {
    pub cap_id: u32,
    pub owner: ProcessId,
    pub cap_type: NetworkCapabilityType,
}

#[derive(Debug, Clone, Copy)]
pub enum NetworkCapabilityType {
    /// Raw packet access
    Packet {
        interface_id: u32,
        direction: PacketDirection,
    },
    
    /// Socket capability
    Socket {
        protocol: Protocol,
        local_port: Option<u16>,
        remote_addr: Option<SocketAddr>,
    },
    
    /// HTTP capability
    Http {
        allowed_host: Option<[u8; 64]>, // Restricted domain
        host_len: usize,
        use_http3: bool,
    },
    
    /// DNS capability
    Dns {
        allowed_domain: Option<[u8; 64]>,
        domain_len: usize,
    },
}

impl NetworkCapability {
    pub fn new_socket(cap_id: u32, owner: ProcessId, protocol: Protocol) -> Self {
        NetworkCapability {
            cap_id,
            owner,
            cap_type: NetworkCapabilityType::Socket {
                protocol,
                local_port: None,
                remote_addr: None,
            },
        }
    }

    pub fn new_http(cap_id: u32, owner: ProcessId, host: Option<&str>) -> Self {
        let (allowed_host, host_len) = if let Some(h) = host {
            let mut buf = [0u8; 64];
            let len = h.len().min(64);
            buf[..len].copy_from_slice(&h.as_bytes()[..len]);
            (Some(buf), len)
        } else {
            (None, 0)
        };

        NetworkCapability {
            cap_id,
            owner,
            cap_type: NetworkCapabilityType::Http {
                allowed_host,
                host_len,
                use_http3: true, // Default to HTTP/3
            },
        }
    }
}

// ============================================================================
// Network Interface
// ============================================================================

#[derive(Clone, Copy)]
pub struct NetworkInterface {
    pub id: u32,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mtu: u16,
    pub enabled: bool,
}

impl NetworkInterface {
    pub const fn new() -> Self {
        NetworkInterface {
            id: 0,
            mac: MacAddr([0, 0, 0, 0, 0, 0]),
            ip: Ipv4Addr([0, 0, 0, 0]),
            netmask: Ipv4Addr([255, 255, 255, 0]),
            gateway: Ipv4Addr([10, 0, 2, 2]),
            mtu: 1500,
            enabled: false,
        }
    }
}

// ============================================================================
// Socket
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Closed,
    Listening,
    Connecting,
    Connected,
    Closing,
}

#[derive(Clone, Copy)]
pub struct Socket {
    pub id: u32,
    pub protocol: Protocol,
    pub state: SocketState,
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: Option<SocketAddr>,
    pub owner: ProcessId,
}

impl Socket {
    pub const fn new() -> Self {
        Socket {
            id: 0,
            protocol: Protocol::Tcp,
            state: SocketState::Closed,
            local_addr: None,
            remote_addr: None,
            owner: ProcessId(0),
        }
    }
}

// ============================================================================
// HTTP/3 Connection
// ============================================================================

#[derive(Clone, Copy)]
pub struct Http3Connection {
    pub id: u32,
    pub host: [u8; 64],
    pub host_len: usize,
    pub port: u16,
    pub state: SocketState,
    pub owner: ProcessId,
}

impl Http3Connection {
    pub const fn new() -> Self {
        Http3Connection {
            id: 0,
            host: [0u8; 64],
            host_len: 0,
            port: 443,
            state: SocketState::Closed,
            owner: ProcessId(0),
        }
    }
}

// ============================================================================
// Network Service
// ============================================================================

pub struct NetworkService {
    interfaces: [NetworkInterface; MAX_INTERFACES],
    interface_count: usize,
    sockets: [Socket; MAX_SOCKETS],
    socket_count: usize,
    http3_connections: [Http3Connection; MAX_CONNECTIONS],
    http3_count: usize,
    next_cap_id: u32,
}

impl NetworkService {
    pub const fn new() -> Self {
        NetworkService {
            interfaces: [NetworkInterface::new(); MAX_INTERFACES],
            interface_count: 0,
            sockets: [Socket::new(); MAX_SOCKETS],
            socket_count: 0,
            http3_connections: [Http3Connection::new(); MAX_CONNECTIONS],
            http3_count: 0,
            next_cap_id: 1,
        }
    }

    /// Initialize default network interface (QEMU user networking)
    pub fn init_default_interface(&mut self) -> Result<u32, NetworkError> {
        if self.interface_count >= MAX_INTERFACES {
            return Err(NetworkError::TooManyInterfaces);
        }

        let id = self.interface_count as u32;
        self.interfaces[self.interface_count] = NetworkInterface {
            id,
            mac: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
            ip: Ipv4Addr::new(10, 0, 2, 15), // QEMU default
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            mtu: 1500,
            enabled: true,
        };
        self.interface_count += 1;

        Ok(id)
    }

    /// Get interface information
    pub fn get_interface(&self, id: u32) -> Option<&NetworkInterface> {
        self.interfaces.iter().find(|iface| iface.id == id && iface.enabled)
    }

    /// Create a socket
    pub fn create_socket(&mut self, protocol: Protocol, owner: ProcessId) -> Result<u32, NetworkError> {
        if self.socket_count >= MAX_SOCKETS {
            return Err(NetworkError::TooManySockets);
        }

        let id = self.socket_count as u32;
        self.sockets[self.socket_count] = Socket {
            id,
            protocol,
            state: SocketState::Closed,
            local_addr: None,
            remote_addr: None,
            owner,
        };
        self.socket_count += 1;

        Ok(id)
    }

    /// Connect to remote host
    pub fn connect(&mut self, socket_id: u32, remote: SocketAddr) -> Result<(), NetworkError> {
        let socket = self.sockets.iter_mut()
            .find(|s| s.id == socket_id)
            .ok_or(NetworkError::InvalidSocket)?;

        if socket.state != SocketState::Closed {
            return Err(NetworkError::AlreadyConnected);
        }

        socket.remote_addr = Some(remote);
        socket.state = SocketState::Connected;

        Ok(())
    }

    /// Create HTTP/3 connection
    pub fn create_http3_connection(&mut self, host: &str, port: u16, owner: ProcessId) -> Result<u32, NetworkError> {
        if self.http3_count >= MAX_CONNECTIONS {
            return Err(NetworkError::TooManyConnections);
        }

        let id = self.http3_count as u32;
        let mut conn = Http3Connection::new();
        conn.id = id;
        conn.host_len = host.len().min(64);
        conn.host[..conn.host_len].copy_from_slice(&host.as_bytes()[..conn.host_len]);
        conn.port = port;
        conn.state = SocketState::Connected; // Simplified for v0
        conn.owner = owner;

        self.http3_connections[self.http3_count] = conn;
        self.http3_count += 1;

        Ok(id)
    }

    /// Send HTTP/3 GET request
    pub fn http3_get(&self, conn_id: u32, path: &str) -> Result<[u8; 2048], NetworkError> {
        let conn = self.http3_connections.iter()
            .find(|c| c.id == conn_id)
            .ok_or(NetworkError::InvalidConnection)?;

        if conn.state != SocketState::Connected {
            return Err(NetworkError::NotConnected);
        }

        // For v0, simulate HTTP response
        let mut response = [0u8; 2048];
        let host_str = core::str::from_utf8(&conn.host[..conn.host_len])
            .unwrap_or("unknown");

        let response_text = format_response(host_str, path);
        let len = response_text.len().min(2048);
        response[..len].copy_from_slice(&response_text[..len]);

        Ok(response)
    }

    /// List all interfaces
    pub fn list_interfaces(&self) -> &[NetworkInterface] {
        &self.interfaces[..self.interface_count]
    }

    /// Get statistics
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            interface_count: self.interface_count,
            socket_count: self.socket_count,
            http3_count: self.http3_count,
        }
    }
}

/// Format a simulated HTTP response
fn format_response(host: &str, path: &str) -> [u8; 512] {
    let mut buf = [0u8; 512];
    let response = b"HTTP/3 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Oreulia HTTP/3 Client</h1><p>Connected to: ";
    let host_bytes = host.as_bytes();
    let path_bytes = path.as_bytes();
    let footer = b"</p><p>This is a simulated response for v0. Real HTTP/3 coming soon!</p></body></html>";
    
    let mut pos = 0;
    
    // Copy response header
    let len = response.len().min(512 - pos);
    buf[pos..pos + len].copy_from_slice(&response[..len]);
    pos += len;
    
    // Copy host
    if pos < 512 {
        let len = host_bytes.len().min(512 - pos);
        buf[pos..pos + len].copy_from_slice(&host_bytes[..len]);
        pos += len;
    }
    
    // Copy path
    if pos < 512 {
        let len = path_bytes.len().min(512 - pos);
        buf[pos..pos + len].copy_from_slice(&path_bytes[..len]);
        pos += len;
    }
    
    // Copy footer
    if pos < 512 {
        let len = footer.len().min(512 - pos);
        buf[pos..pos + len].copy_from_slice(&footer[..len]);
    }
    
    buf
}

#[derive(Debug, Clone, Copy)]
pub struct NetworkStats {
    pub interface_count: usize,
    pub socket_count: usize,
    pub http3_count: usize,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    TooManyInterfaces,
    TooManySockets,
    TooManyConnections,
    InvalidSocket,
    InvalidConnection,
    AlreadyConnected,
    NotConnected,
    PermissionDenied,
    InvalidAddress,
    Timeout,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkError::TooManyInterfaces => write!(f, "Too many interfaces"),
            NetworkError::TooManySockets => write!(f, "Too many sockets"),
            NetworkError::TooManyConnections => write!(f, "Too many connections"),
            NetworkError::InvalidSocket => write!(f, "Invalid socket"),
            NetworkError::InvalidConnection => write!(f, "Invalid connection"),
            NetworkError::AlreadyConnected => write!(f, "Already connected"),
            NetworkError::NotConnected => write!(f, "Not connected"),
            NetworkError::PermissionDenied => write!(f, "Permission denied"),
            NetworkError::InvalidAddress => write!(f, "Invalid address"),
            NetworkError::Timeout => write!(f, "Timeout"),
        }
    }
}

impl NetworkError {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkError::TooManyInterfaces => "Too many interfaces",
            NetworkError::TooManySockets => "Too many sockets",
            NetworkError::TooManyConnections => "Too many connections",
            NetworkError::InvalidSocket => "Invalid socket",
            NetworkError::InvalidConnection => "Invalid connection",
            NetworkError::AlreadyConnected => "Already connected",
            NetworkError::NotConnected => "Not connected",
            NetworkError::PermissionDenied => "Permission denied",
            NetworkError::InvalidAddress => "Invalid address",
            NetworkError::Timeout => "Timeout",
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

pub fn init() {
    let mut net = NETWORK.lock();
    match net.init_default_interface() {
        Ok(id) => {
            crate::vga::print_str("[NET] Initialized interface ");
            crate::vga::print_char((b'0' + id as u8) as char);
            crate::vga::print_str(" (10.0.2.15)\n");
        }
        Err(_) => {
            crate::vga::print_str("[NET] Failed to initialize interface\n");
        }
    }
}
