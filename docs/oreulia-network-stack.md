# Oreulia Network Stack

## Overview

Oreulia implements a **capability-based HTTP/3 network stack** that provides secure, modern web connectivity while maintaining the OS's zero-trust security model. All network access requires explicit capabilities, preventing ambient network authority.

## Architecture

### Design Principles

1. **Capability-Based**: No process can access the network without an explicit capability
2. **HTTP/3 First**: Modern QUIC-based protocol for efficient web connectivity
3. **WASM Protocol Handlers**: Network protocols run in sandboxed WASM instances
4. **Zero-Trust Networking**: All connections require explicit authorization
5. **Deterministic Replay**: Network sessions can be recorded and replayed for debugging

### Key Components

```
┌─────────────────────────────────────────────┐
│          Application Layer                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  WASM    │  │  WASM    │  │  WASM    │  │
│  │  App 1   │  │  App 2   │  │  App 3   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │             │         │
│       └─────────────┴─────────────┘         │
│                     │                       │
├─────────────────────┼───────────────────────┤
│                     ↓                       │
│          Network Syscalls                   │
│  ┌─────────────────────────────────────┐   │
│  │ oreulia_net_http_get()              │   │
│  │ oreulia_net_connect()               │   │
│  │ oreulia_dns_resolve()               │   │
│  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────┤
│          Capability Layer                   │
│  ┌─────────────────────────────────────┐   │
│  │ NetworkCapability::Http             │   │
│  │ NetworkCapability::Socket           │   │
│  │ NetworkCapability::Dns              │   │
│  │ NetworkCapability::Packet           │   │
│  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────┤
│          Network Service                    │
│  ┌─────────────────────────────────────┐   │
│  │ - HTTP/3 Connection Manager         │   │
│  │ - Socket Table                      │   │
│  │ - Interface Management              │   │
│  │ - DNS Cache (future)                │   │
│  └─────────────────────────────────────┘   │
├─────────────────────────────────────────────┤
│          Transport Layer (v0)               │
│  ┌─────────────────────────────────────┐   │
│  │ Simulated Network                   │   │
│  │ (Real VirtIO driver coming in v1)   │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Commands

### Network Help
```bash
network-help
```
Displays comprehensive documentation about the network stack, including:
- Command reference
- Architecture overview
- Capability model
- Security features
- Usage examples

### Network Info
```bash
net-info
```
Displays all network interfaces with:
- Interface ID
- Status (ENABLED/DISABLED)
- MAC address
- IPv4 address
- Netmask
- Gateway
- MTU (Maximum Transmission Unit)
- Statistics (active sockets, HTTP/3 connections)

Example output:
```
===== Network Interfaces =====

Interface 0:
  Status: ENABLED
  MAC: 52:54:00:12:34:56
  IPv4: 10.0.2.15
  Netmask: 255.255.255.0
  Gateway: 10.0.2.2
  MTU: 1500 bytes

Statistics:
  Active Sockets: 0
  HTTP/3 Connections: 0
```

### HTTP GET Request
```bash
http-get <url>
```
Performs an HTTP/3 GET request to the specified URL.

Examples:
```bash
http-get https://example.com
http-get http://api.example.com/data
http-get https://example.com/path/to/resource
```

Output:
```
Fetching: https://example.com
Protocol: HTTP/3 (QUIC)

Host: example.com
Path: /

===== Response =====

HTTP/3 200 OK
Content-Type: text/html

<html><body><h1>Oreulia HTTP/3 Client</h1>
<p>Connected to: example.com/</p>
<p>This is a simulated response for v0. Real HTTP/3 coming soon!</p>
</body></html>

Total bytes: 234
```

### DNS Resolution
```bash
dns-resolve <domain>
```
Resolves a domain name to an IPv4 address.

Examples:
```bash
dns-resolve example.com
dns-resolve localhost
dns-resolve github.com
```

Output:
```
Resolving: example.com
IPv4: 93.184.216.34
```

## Network Capabilities

### Capability Types

#### 1. Socket Capability
Grants access to TCP/UDP socket operations:
```rust
NetworkCapabilityType::Socket {
    protocol: Protocol::Tcp,
    local_port: Option<u16>,
    remote_addr: Option<SocketAddr>,
}
```

**Restrictions**:
- Can be limited to specific ports
- Can be restricted to specific remote addresses
- Protocol-specific (TCP vs UDP)

#### 2. HTTP Capability
Grants HTTP/3 request capability:
```rust
NetworkCapabilityType::Http {
    allowed_host: Option<[u8; 64]>,
    host_len: usize,
    use_http3: bool,
}
```

**Restrictions**:
- Can be restricted to specific hosts (e.g., only "api.example.com")
- Can enforce HTTP/3 vs HTTP/2
- Can include rate limiting (future)

#### 3. DNS Capability
Grants DNS resolution capability:
```rust
NetworkCapabilityType::Dns {
    allowed_domain: Option<[u8; 64]>,
    domain_len: usize,
}
```

**Restrictions**:
- Can be limited to specific domains
- Can include DNS query limits

#### 4. Packet Capability
Grants raw packet access (admin only):
```rust
NetworkCapabilityType::Packet {
    interface_id: u32,
    direction: PacketDirection,
}
```

**Restrictions**:
- Admin-only capability
- Can be read-only, write-only, or bidirectional
- Interface-specific

## WASM Network Syscalls

### oreulia_net_http_get
```wasm
;; Perform HTTP/3 GET request
;; Parameters:
;;   url_ptr: i32   - Pointer to URL string in WASM memory
;;   url_len: i32   - Length of URL string
;;   buf_ptr: i32   - Pointer to response buffer
;;   buf_len: i32   - Size of response buffer
;; Returns:
;;   i32 - Number of bytes written to buffer (-1 on error)
(import "oreulia" "net_http_get" 
  (func $net_http_get (param i32 i32 i32 i32) (result i32)))
```

### oreulia_net_connect
```wasm
;; Create a network socket connection
;; Parameters:
;;   host_ptr: i32  - Pointer to hostname string
;;   host_len: i32  - Length of hostname
;;   port: i32      - Port number
;; Returns:
;;   i32 - Socket ID (-1 on error)
(import "oreulia" "net_connect" 
  (func $net_connect (param i32 i32 i32) (result i32)))
```

### oreulia_dns_resolve
```wasm
;; Resolve domain name to IP address
;; Parameters:
;;   domain_ptr: i32 - Pointer to domain string
;;   domain_len: i32 - Length of domain string
;; Returns:
;;   i32 - IPv4 address as u32 (0 on error)
(import "oreulia" "dns_resolve" 
  (func $dns_resolve (param i32 i32) (result i32)))
```

## Implementation Details

### Network Service (kernel/src/net.rs)

The `NetworkService` struct manages all network operations:

```rust
pub struct NetworkService {
    interfaces: [NetworkInterface; MAX_INTERFACES],
    interface_count: usize,
    sockets: [Socket; MAX_SOCKETS],
    socket_count: usize,
    http3_connections: [Http3Connection; MAX_CONNECTIONS],
    http3_count: usize,
    next_cap_id: u32,
}
```

**Configuration**:
- `MAX_INTERFACES`: 4 interfaces
- `MAX_SOCKETS`: 64 concurrent sockets
- `MAX_CONNECTIONS`: 32 HTTP/3 connections
- `MAX_PACKET_SIZE`: 1518 bytes (standard Ethernet MTU)

### HTTP/3 Connection

Each HTTP/3 connection tracks:
```rust
pub struct Http3Connection {
    pub id: u32,
    pub host: [u8; 64],
    pub host_len: usize,
    pub port: u16,
    pub state: SocketState,
    pub owner: ProcessId,
}
```

### Network Interface

Default interface configuration (QEMU user networking):
```rust
NetworkInterface {
    id: 0,
    mac: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
    ip: Ipv4Addr::new(10, 0, 2, 15),
    netmask: Ipv4Addr::new(255, 255, 255, 0),
    gateway: Ipv4Addr::new(10, 0, 2, 2),
    mtu: 1500,
    enabled: true,
}
```

## Security Model

### Capability Isolation

1. **No Ambient Authority**: Processes cannot access network without explicit capability
2. **Fine-Grained Control**: Capabilities can restrict:
   - Specific hosts/domains
   - Port ranges
   - Protocols (TCP/UDP/ICMP)
   - Data rates (future)

3. **Capability Transfer**: Network capabilities can be transferred between processes via IPC
4. **Revocable**: Capabilities can be revoked at any time

### Example: Restricted HTTP Access

```rust
// Create HTTP capability limited to api.example.com
let http_cap = NetworkCapability::new_http(
    cap_id,
    owner_pid,
    Some("api.example.com")
);

// Process can ONLY access api.example.com
// Attempts to access other hosts will fail
```

## Version 0 Implementation

The current implementation (v0) provides:
- ✅ Capability-based architecture
- ✅ HTTP/3 API and commands
- ✅ Network syscalls for WASM
- ✅ DNS resolution
- ✅ Multiple network interfaces
- ⚠️  Simulated responses (no real network I/O yet)

### What's Simulated in v0

1. **HTTP responses**: Returns templated HTML responses
2. **DNS resolution**: Returns hardcoded IPs for known domains
3. **Network I/O**: No actual packet transmission

## Roadmap to v1

### Phase 1: VirtIO NIC Driver
- Implement PCI device detection
- VirtIO negotiation and feature detection
- RX/TX virtqueue management
- Packet reception and transmission
- Interrupt handling

### Phase 2: Real HTTP/3 Stack
- QUIC protocol implementation (in WASM)
- TLS 1.3 handshake
- HTTP/3 framing
- Stream multiplexing
- Connection migration

### Phase 3: Enhanced Features
- DNS caching
- Connection pooling
- Rate limiting per capability
- Network namespace isolation
- Time-travel debugging (record/replay)
- Custom protocol handlers in WASM

### Phase 4: Advanced Networking
- WebSocket support
- Custom application protocols
- P2P networking primitives
- Network capability marketplace
- Deterministic networking for distributed systems

## Usage Examples

### Basic Web Request
```bash
> network-help          # Learn about network commands
> net-info              # Check network status
> http-get https://example.com
```

### DNS and Connection
```bash
> dns-resolve example.com
Resolving: example.com
IPv4: 93.184.216.34

> http-get http://api.example.com/status
```

### From WASM Application
```wasm
;; Example WASM code for HTTP request
(module
  (import "oreulia" "net_http_get" 
    (func $http_get (param i32 i32 i32 i32) (result i32)))
  
  (memory 1)
  (data (i32.const 0) "https://example.com")
  
  (func (export "fetch")
    (local $bytes_read i32)
    
    ;; http_get(url_ptr=0, url_len=19, buf_ptr=100, buf_len=2048)
    (local.set $bytes_read
      (call $http_get
        (i32.const 0)     ;; URL pointer
        (i32.const 19)    ;; URL length
        (i32.const 100)   ;; Response buffer
        (i32.const 2048)  ;; Buffer size
      )
    )
    
    ;; Check result
    (if (i32.lt_s (local.get $bytes_read) (i32.const 0))
      (then
        ;; Error: failed to fetch
        unreachable
      )
    )
  )
)
```

## Error Handling

Network operations can fail with these errors:

```rust
pub enum NetworkError {
    TooManyInterfaces,    // Exceeded MAX_INTERFACES
    TooManySockets,       // Exceeded MAX_SOCKETS
    TooManyConnections,   // Exceeded MAX_CONNECTIONS
    InvalidSocket,        // Socket ID not found
    InvalidConnection,    // Connection ID not found
    AlreadyConnected,     // Socket already connected
    NotConnected,         // Operation requires connection
    PermissionDenied,     // Capability check failed
    InvalidAddress,       // Malformed IP/hostname
    Timeout,              // Operation timed out
}
```

## Performance Characteristics

### Memory Usage
- Each HTTP/3 connection: ~128 bytes
- Each socket: ~64 bytes
- Response buffer: Up to 2048 bytes per request
- Total network service: ~10 KB

### Latency (v1 with real networking)
- HTTP/3 request: ~50-200ms (depends on remote server)
- DNS resolution: ~20-100ms (with caching)
- Socket creation: <1ms
- Capability check: <1μs

### Throughput
- Target: 100 Mbps with VirtIO NIC
- HTTP/3 multiplexing: Up to 100 concurrent streams per connection
- Packet processing: ~10,000 packets/second

## Testing

### Manual Testing
```bash
# Build and run
cd kernel
./build.sh
./run.sh

# In QEMU
> network-help
> net-info
> http-get https://example.com
> dns-resolve example.com
```

### Automated Tests (future)
```bash
# Unit tests
cargo test --lib network

# Integration tests
cargo test --test network_integration

# Benchmark
cargo bench --bench network_bench
```

## Troubleshooting

### "No network interfaces configured"
- Check that `net::init()` is called in `rust_main()`
- Verify network module is included in lib.rs

### "Permission denied" on HTTP request
- Process needs NetworkCapability::Http
- Check capability table with process manager

### "Invalid address" error
- Verify URL format: `http://` or `https://` prefix
- Check domain name is valid (no special characters)

### VirtIO driver not found (v1)
- Ensure QEMU started with `-device virtio-net`
- Check PCI device enumeration in boot logs

## Contributing

To extend the network stack:

1. **Add new protocol**: Implement in WASM as protocol handler
2. **New capability type**: Add to `NetworkCapabilityType` enum
3. **New syscall**: Add to `WasmInstance::call_host_function()`
4. **New command**: Add to `commands.rs` match statement

See `docs/oreulia-capabilities.md` for capability system details.

## References

- [HTTP/3 Specification](https://www.rfc-editor.org/rfc/rfc9114.html)
- [QUIC Protocol](https://www.rfc-editor.org/rfc/rfc9000.html)
- [VirtIO Specification](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)
- [Capability-Based Security](https://en.wikipedia.org/wiki/Capability-based_security)

---

**Version**: 0.1.0  
**Status**: Development (v0 - Simulated networking)  
**Next Milestone**: VirtIO NIC driver implementation
