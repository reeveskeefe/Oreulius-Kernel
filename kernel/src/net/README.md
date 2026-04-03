# `kernel/src/net` — Kernel Networking Stack

The `net` module is the **complete in-kernel networking subsystem** for Oreulius. It contains everything from raw Ethernet frame handling and TCP/IP from scratch, through TLS 1.3, Wi-Fi 802.11, HTTP serving, async event loop, and the CapNet capability token distribution protocol. All network I/O is capability-gated — a process cannot open a TCP connection without holding a `Network` capability.

---

## Design Philosophy

1. **Capability-gated from the first packet.** The `NetworkService` checks the caller's capability before any socket operation. There is no ambient network access.
2. **No libc, no heap in hot paths.** The ring buffers, connection tables, and ARP caches are fixed-size static arrays. Dynamic allocation is only used in the TLS handshake and HTTP response assembly.
3. **CapNet as the inter-node trust layer.** Cross-kernel capability token transfer uses the CapNet protocol — a fixed-width, MAC-authenticated, replay-resistant token format that survives untrusted network links.
4. **Temporal persistence throughout.** Every network connection, DNS cache entry, Wi-Fi association, and CapNet peer table can be snapshotted and restored via the temporal system.

---

## Source Layout

| File | Architecture | Lines | Role |
|---|---|---|---|
| `mod.rs` | All | 1452 | `NetworkService` umbrella, `TcpConnection`, `HttpRequest/Response`, global init |
| `netstack.rs` | All | 3425 | Raw TCP/IP stack: ARP, IPv4, TCP state machine, DNS, HTTP server |
| `capnet.rs` | All | 3033 | CapNet v1 token format, peer session table, delegation/revocation journal |
| `net_reactor.rs` | All | 859 | Async event loop, IRQ-driven RX dispatch, high-level DNS/TCP/HTTP API |
| `tls.rs` | x86-64 | 1187 | TLS 1.3 session management over raw TCP sockets |
| `wifi.rs` | All | 2997 | 802.11 Wi-Fi driver (scan, associate, auth, EAPOL, data frames) |
| `rtl8139.rs` | x86-64 | 527 | RTL8139 Fast Ethernet PCI driver |
| `e1000.rs` | x86-64 | 756 | Intel e1000 Gigabit Ethernet PCI driver |
| `virtio_net.rs` | All | 608 | VirtIO network device driver (QEMU/KVM paravirtual NIC) |
| `capnet_test.rs` | All | 14 | Integration test stubs |

---

## `mod.rs` — `NetworkService` and Core Types

### Capacity Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_CONNECTIONS` | `64` | Maximum concurrent TCP connections |
| `MAX_DNS_CACHE` | `32` | DNS cache entries |
| `MTU` | `1500` | Maximum Transmission Unit (bytes) |
| `TCP_BUFFER_SIZE` | `8192` | Per-connection receive/send buffer size |

### `Ipv4Addr` and `MacAddr`

Both are thin newtypes over fixed-size byte arrays with formatting and comparison helpers. `Ipv4Addr([u8; 4])` and `MacAddr([u8; 6])`.

### `TcpState`

Tracks the TCP state machine per connection:

| State | Description |
|---|---|
| `Closed` | No connection |
| `Listen` | Accepting incoming connections |
| `SynSent` | SYN sent, awaiting SYN-ACK |
| `SynReceived` | SYN received, SYN-ACK sent |
| `Established` | Connection fully open |
| `FinWait1` / `FinWait2` | Initiating side closing |
| `CloseWait` | Remote side initiated close |
| `Closing` / `LastAck` / `TimeWait` | Teardown in progress |

### `TcpConnection`

| Field | Description |
|---|---|
| `local_addr`, `remote_addr` | `SocketAddr` endpoints |
| `state` | `TcpState` |
| `seq_num`, `ack_num` | Current sequence and acknowledgement numbers |
| `rx_buffer: [u8; TCP_BUFFER_SIZE]` | Receive ring buffer |
| `rx_head`, `rx_tail` | Ring buffer pointers |

### `NetworkService`

The global singleton accessed via `net::network()`. Wraps a `spin::Mutex`. Owns the `NetworkStack`, Wi-Fi driver reference, and connection table.

| Method | Description |
|---|---|
| `connect(addr, port, cap)` | Open a TCP connection (requires `Network` capability) |
| `send(conn_id, data, cap)` | Send data on an established connection |
| `recv(conn_id, buf, cap)` | Receive data |
| `close(conn_id, cap)` | Close a connection |
| `dns_resolve(domain, cap)` | Resolve a hostname via DNS |
| `http_get(url, cap)` | Perform an HTTP GET request |
| `listen(port, cap)` | Bind a TCP listener |

### `NetworkStats`

| Field | Description |
|---|---|
| `rx_packets`, `tx_packets` | Total packets received/sent |
| `rx_bytes`, `tx_bytes` | Total payload bytes |
| `tcp_connections_opened` | Lifetime TCP connect requests |
| `tcp_connections_closed` | Lifetime TCP close completions |
| `dns_cache_hits`, `dns_cache_misses` | DNS cache efficiency |
| `http_requests_served` | Total HTTP responses sent |
| `arp_cache_hits`, `arp_cache_misses` | ARP resolution efficiency |

### `NetworkError`

| Variant | Description |
|---|---|
| `ConnectionRefused` | Remote host rejected the connection |
| `ConnectionTimeout` | No response within timeout |
| `ConnectionReset` | TCP RST received |
| `DnsResolutionFailed` | DNS query returned NXDOMAIN or network error |
| `SendFailed` | Transmit path error |
| `RecvFailed` | Receive path error |
| `BufferFull` | TX or RX buffer exhausted |
| `InvalidAddress` | Malformed IP or hostname |
| `PermissionDenied` | Missing `Network` capability |
| `TooManyConnections` | `MAX_CONNECTIONS` reached |
| `WifiError(WifiError)` | Wi-Fi driver error (transparent forwarding) |

---

## `netstack.rs` — Raw TCP/IP Stack

The 3425-line core network stack. Implements Ethernet II framing, ARP resolution, IPv4 routing, TCP (full state machine), DNS (UDP stub resolver), and an HTTP/1.1 server — all without `std` or `libc`.

### `NetworkInterface` Trait

```rust
pub trait NetworkInterface: Send {
    fn send_frame(&mut self, data: &[u8]) -> Result<(), &'static str>;
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize>;
    fn mac_address(&self) -> MacAddr;
    fn link_up(&self) -> bool;
}
```

All three drivers (`rtl8139`, `e1000`, `virtio_net`) and the Wi-Fi driver implement this trait. `NetworkStack` holds a `Box<dyn NetworkInterface>` which is selected at `init()` time based on detected PCI hardware.

### `ArpCache`

A fixed-size array of `(Ipv4Addr, MacAddr, age_ticks)` entries. On ARP miss, the stack sends an ARP request and blocks the packet for up to one second. Entries expire after 60 seconds.

### `NetworkStack`

| Component | Capacity |
|---|---|
| ARP cache | 16 entries |
| DNS negative cache | `dyn` (up to `MAX_DNS_CACHE = 32`) |
| UDP RX staging buffer | Fixed-size slots for pending DNS replies |
| CapNet retransmit buffer | `CapNetRetransmitEntry` ring for unacknowledged control frames |
| TCP connection table | `MAX_CONNECTIONS` `TcpConn` entries |
| TCP listener table | 8 `TcpListener` entries |
| HTTP server | 1 `HttpServer` instance |

### TCP State Machine

`NetworkStack` maintains the full RFC 793 state machine per connection. Each `TcpConn` tracks:
- sequence number, acknowledgement number, window size
- retransmit timer and retry count
- per-connection RX ring buffer (`TCP_BUFFER_SIZE`)
- `TcpState`

### DNS Stub Resolver

`NetworkStack` uses a hard-coded upstream DNS server (configurable via persistence) and implements the minimal DNS query wire format: a 12-byte header, a single A-record question section. Responses are parsed for the first A record.

### HTTP Server

`HttpServer` binds to a configurable port and handles one active request at a time. It routes requests to a registered handler map. Used in the kernel shell via `http-server-start <port>`.

---

## `capnet.rs` — CapNet v1 Capability Token Protocol

CapNet is Oreulius's **secure inter-kernel capability transport protocol**. It solves the problem of transferring the kernel's capability model across a network link to remote Oreulius nodes without ambient trust.

### Token Format (`CapabilityTokenV1`)

Every CapNet token is a **116-byte fixed-width structure** (`CAPNET_TOKEN_V1_LEN = 116`):

| Field | Bytes | Description |
|---|---|---|
| `magic` | 4 | `0x544E_5043` ("CPNT") — validity sentinel |
| `version` | 1 | Protocol version (`1`) |
| `algorithm` | 1 | MAC algorithm: `1` = SipHash-2-4 kernel key; `2` = Ed25519 (reserved) |
| `delegation_depth` | 2 | How many times this token has been attenuated (max `32`) |
| `constraints` | 4 | Constraint bitmask |
| `cap_type` | 4 | `ServiceType` or capability type identifier |
| `rights` | 4 | Rights bitmask |
| `object_id` | 8 | Capability object identifier |
| `issuer_id` | 8 | Issuing kernel node ID |
| `holder_id` | 8 | Current holder node ID |
| `use_count` | 4 | Remaining uses (0 = unbounded) |
| `byte_quota` | 8 | Remaining byte budget |
| `session_id` | 8 | Session binding identifier |
| `measurement` | 32 | 32-byte measurement/hash bound |
| `mac` | 8 | SipHash-2-4 MAC over all preceding bytes |

### Constraint Bitmask

| Bit | Constant | Meaning |
|---|---|---|
| 0 | `CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE` | Token expires after `use_count` uses |
| 1 | `CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA` | Token expires after `byte_quota` bytes transferred |
| 2 | `CAPNET_CONSTRAINT_MEASUREMENT_BOUND` | Token is only valid if `measurement` matches runtime measurement |
| 3 | `CAPNET_CONSTRAINT_SESSION_BOUND` | Token is bound to a specific `session_id` |

### Control Protocol

CapNet peers communicate over a **control channel on UDP port `CAPNET_CONTROL_PORT = 48123`** using fixed-width 56-byte headers plus a token-sized payload:

| Frame Type | Description |
|---|---|
| `Hello` | Initial peer discovery and nonce exchange |
| `Heartbeat` | Session keepalive with sequence number |
| `Attest` | Remote attestation report frame |
| `TokenOffer` | Send a `CapabilityTokenV1` to a peer |
| `TokenAccept` | Acknowledge receipt of a token offer |
| `TokenRevoke` | Revoke a previously issued token |
| `AckOnly` | Pure acknowledgement (no payload) |

### Peer Session Table

Up to `CAPNET_MAX_PEERS = 32` peer sessions. Each `PeerSession` tracks:

| Field | Description |
|---|---|
| `peer_id` | Remote kernel node identifier |
| `remote_ip`, `remote_port` | Network endpoint |
| `trust_policy` | `PeerTrustPolicy`: `Untrusted`, `Verified`, `Attested`, `Trusted` |
| `send_seq`, `recv_seq` | Per-session sequence numbers (replay window) |
| `remote_token_ttl` | Epochs remaining before the remote token expires |

### Delegation and Revocation Journal

Every token delegation and revocation is logged to persistent storage:

- `DelegationRecord`: recorded when a token is issued to a peer. Stored in a ring of `CAPNET_MAX_DELEGATION_RECORDS = 128` entries.
- `RevocationTombstone`: recorded when a token is revoked. Stored in a ring of `CAPNET_MAX_REVOCATION_TOMBSTONES = 256` entries. Token IDs in the tombstone set are rejected on receipt.

`CAPNET_REVOKE_LOG_MAGIC = 0x4B56_5243` ("CRVK") marks valid revocation log entries.

### `CapNetControlFrame` Encode/Decode

| Function | Description |
|---|---|
| `decode_control_frame(bytes)` | Parse a raw byte slice into a `CapNetControlFrame`; fail-closed |
| `build_hello_frame(...)` | Encode a Hello frame |
| `build_attest_frame(...)` | Encode an Attest frame |
| `build_heartbeat_frame(...)` | Encode a Heartbeat frame |
| `build_token_offer_frame(...)` | Encode a TokenOffer frame |
| `build_token_accept_frame(...)` | Encode a TokenAccept frame |
| `enqueue_incoming_frame(bytes)` | Add an incoming frame to the kernel-side RX queue |
| `dequeue_incoming_frame()` | Pop the next frame from the RX queue |

### `SplitCap` and `LinearCapabilityToken`

`SplitCap<T, A, B>` is a generic split-view over capability token bytes for type-safe access to sub-regions. `LinearCapabilityToken<T, C>` is a trait that token types implement to provide constant-size serialization with explicit send/receive separation.

### Fuzz Regression

`CAPNET_FUZZ_REGRESSION_SEEDS` contains 10 known seed values from previous fuzz runs used as regression tests in CI. `CapNetFuzzStats`, `CapNetFuzzFailure`, `CapNetFuzzSoakStats`, and `CapNetFuzzRegressionStats` track fuzz campaign results.

---

## `net_reactor.rs` — Async Event Loop

The event reactor bridges hardware IRQs to the network stack and provides a high-level blocking API for the rest of the kernel.

### `NetInfo`

A snapshot struct returned by `get_info()`:

| Field | Description |
|---|---|
| `ip_addr` | Current IPv4 address |
| `mac_addr` | Hardware MAC address |
| `gateway` | Default gateway IP |
| `dns_server` | Upstream DNS server IP |
| `link_up` | Physical link state |
| `rx_packets`, `tx_packets` | Session packet counters |

### `on_irq()`

Called directly from the network card IRQ handler (`irq11`). Drains the NIC's receive ring, classifies frames (ARP / IPv4 / CapNet control), and dispatches to the appropriate stack path. This is the only function in `net_reactor` that runs in interrupt context.

### `run() -> !`

The reactor's main loop — called from a dedicated kernel thread. Polls the network stack for timer-driven TCP retransmits, DNS timeout, Wi-Fi keepalive, and CapNet heartbeat delivery.

### High-Level API

| Function | Description |
|---|---|
| `dns_resolve(domain)` | Blocking DNS resolution |
| `tcp_connect(remote_ip, port)` | Open a TCP connection; returns `conn_id` |
| `tcp_send(conn_id, data)` | Send data on an established connection |
| `tcp_recv(conn_id, buf)` | Receive data (blocking until data available) |
| `tcp_close(conn_id)` | Close a connection and drain state |
| `http_server_start(port)` | Bind the HTTP server to a port |
| `http_server_stop()` | Stop the HTTP server |
| `capnet_send_hello(...)` | Send a CapNet Hello frame to a peer |
| `capnet_send_heartbeat(...)` | Send a CapNet Heartbeat |
| `capnet_send_token_offer(...)` | Offer a capability token to a peer |
| `capnet_send_token_revoke(...)` | Revoke a token at a peer |
| `capnet_send_attest(...)` | Send an attestation frame |
| `capnet_send_token_accept(...)` | Accept a token offer |

---

## `tls.rs` — TLS 1.3 Session Manager

Implements a minimal TLS 1.3 client handshake and record layer over raw TCP connections. Used when WASM modules or kernel services need HTTPS.

### Session Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_TLS_SESSIONS` | `8` | Maximum concurrent TLS sessions |
| Key schedule | ECDHE P-256 | Ephemeral key exchange |
| Cipher suite | AES-128-GCM | Record encryption |
| MAC | Poly1305 | (fallback for platforms without AES-NI) |

### `HandshakeState`

| State | Description |
|---|---|
| `Idle` | No handshake in progress |
| `ClientHelloSent` | ClientHello transmitted |
| `ServerHelloReceived` | ServerHello parsed, key exchange in progress |
| `HandshakeComplete` | Keys established, record layer active |
| `Failed` | Handshake error; session must be freed |

### `TlsSession`

| Field | Description |
|---|---|
| `conn_id` | Underlying TCP connection handle |
| `host` | SNI hostname |
| `state` | `HandshakeState` |
| `traffic_keys` | `TrafficKeys` — current read/write AEAD keys and IVs |
| `rx_buf`, `tx_buf` | TLS record staging buffers |

### API

| Function | Description |
|---|---|
| `alloc_session(host, port, server_ip)` | Allocate a TLS session handle and start handshake |
| `session_mut(handle)` | Get a mutable reference to a `TlsSession` |
| `free_session(handle)` | Deallocate a TLS session |
| `tick_all()` | Drive handshake state machines and retransmit logic for all sessions |

---

## `wifi.rs` — 802.11 Wi-Fi Driver

Implements an 802.11b/g/n Wi-Fi driver supporting scan, association, WPA2-PSK authentication (EAPOL/4-way handshake), and data frame transmission.

### Capacity Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_SCAN_RESULTS` | `32` | Maximum networks from a scan |
| `MAX_SSID_LEN` | `32` | Maximum SSID length in bytes |
| `MAX_KEY_LEN` | `64` | Maximum WPA2 PSK length |

### `WifiState`

| State | Description |
|---|---|
| `Uninitialized` | Driver not started |
| `Idle` | Driver active, not associated |
| `Scanning` | Beacon scan in progress |
| `Authenticating` | 802.11 Authentication exchange |
| `Associating` | Association request/response |
| `Associated` | Layer-2 connected, no IP |
| `Connected` | IP configured, traffic possible |
| `Disconnecting` | Disassociation in progress |
| `Failed` | Unrecoverable driver error |

### `WifiSecurity`

| Variant | Description |
|---|---|
| `Open` | No encryption |
| `Wep` | WEP (deprecated, still parseable) |
| `WpaPsk` | WPA-PSK (TKIP) |
| `Wpa2Psk` | WPA2-PSK (CCMP/AES) |
| `Wpa3Sae` | WPA3-SAE |
| `Enterprise` | 802.1X/EAP enterprise |

### `WifiNetwork`

Scan result entry:

| Field | Description |
|---|---|
| `ssid: [u8; MAX_SSID_LEN]` | Network name |
| `bssid: MacAddr` | Access point MAC |
| `channel` | 802.11 channel number |
| `rssi` | Signal strength (dBm) |
| `security` | `WifiSecurity` type |
| `capabilities` | 802.11 capability information bitmask |

### `WifiDriver` Key Operations

| Function | Description |
|---|---|
| `init(device)` | Initialize PCI Wi-Fi device, detect firmware |
| `scan()` | Active/passive scan for nearby networks |
| `connect(network, passphrase)` | Associate and perform WPA2 4-way handshake |
| `disconnect()` | Send Deauth, unset IP |
| `send_frame(data)` | Transmit a raw Ethernet frame over Wi-Fi |
| `recv_frame(buf)` | Pull a received frame |
| `link_up()` | True if associated and IP is set |
| `temporal_apply_wifi_driver_payload(payload)` | Restore Wi-Fi driver state from temporal log |
| `temporal_required_reconnect_failure_self_check()` | Verify that temporal reconnect flag is set correctly |

### Frame Types

The driver parses management frames (Beacon, Probe Request/Response, Authentication, Association Request/Response, Deauthentication, Disassociation), control frames (ACK, RTS, CTS), and data frames (Data, QoS Data, Null function, CF-Ack).

---

## `rtl8139.rs` — RTL8139 Fast Ethernet Driver

PCI driver for the Realtek RTL8139 10/100 Mbps NIC (default QEMU user-mode network device). Implements `NetworkInterface`.

| Feature | Description |
|---|---|
| PCI BAR0 I/O port mapping | Registers accessed via `inb`/`outb` |
| TX ring | 4-slot `[u8; 1536]` TX descriptor ring |
| RX ring | 8 KiB + 1500 byte-wrap ring buffer |
| IRQ | Shared IRQ11; individual bits in ISR register |
| Capabilities | Full-duplex, auto-negotiate, 100BASE-TX |

---

## `e1000.rs` — Intel e1000 Gigabit Driver

PCI driver for the Intel e1000 82540/82545 Gigabit Ethernet NIC. Implements `NetworkInterface`.

| Feature | Description |
|---|---|
| PCI BAR0 MMIO | Registers memory-mapped via `PhysAddr` mapping |
| TX descriptor ring | 8 descriptors × `[u8; 2048]` |
| RX descriptor ring | 8 descriptors × `[u8; 2048]` |
| IRQ | Shared IRQ11; ICR register used for cause dispatch |
| Capabilities | Gigabit, TSO partial support, VLAN stripping |

---

## `virtio_net.rs` — VirtIO Network Driver

Paravirtual network driver for QEMU/KVM `virtio-net` devices. Implements `NetworkInterface`. Uses the VirtIO ring queue protocol over MMIO or PCI transport.

| Feature | Description |
|---|---|
| Transport | PCI or MMIO VirtIO device |
| TX virtqueue | Depth 16 |
| RX virtqueue | Depth 16 |
| MAC negotiation | Feature bit `VIRTIO_NET_F_MAC` |
| Status | `VIRTIO_NET_S_LINK_UP` bit queried for link state |

---

## Network Initialization Sequence

At kernel boot, `net::init()` performs:

1. PCI scan for RTL8139, e1000, or VirtIO NIC — first match is selected.
2. Driver `init()` called; MAC address read from NIC hardware.
3. `NetworkStack::new()` — allocate ARP cache, TCP tables, DNS cache, HTTP server.
4. `wifi::init(device)` — if a Wi-Fi PCI device is detected.
5. `net_reactor` thread spawned via `tasks::spawn("net_reactor", net_reactor::run)`.
6. DHCP discover broadcast if no static IP is configured in persistence.

---

## Shell Commands

| Command | Description |
|---|---|
| `net-info` | Print `NetInfo` — IP, MAC, gateway, link state |
| `net-stats` | Print `NetworkStats` |
| `ping <ip>` | ICMP echo request |
| `dns <host>` | Resolve a hostname |
| `tcp-connect <ip> <port>` | Open a TCP connection |
| `tcp-send <conn-id> <data>` | Send data on a connection |
| `tcp-close <conn-id>` | Close a connection |
| `http-get <url>` | HTTP GET request |
| `http-server-start <port>` | Start the in-kernel HTTP server |
| `http-server-stop` | Stop the HTTP server |
| `wifi-scan` | Scan for 802.11 networks |
| `wifi-connect <ssid> <pass>` | Associate to a Wi-Fi network |
| `wifi-disconnect` | Deassociate from current network |
| `wifi-status` | Print `WifiConnection` snapshot |
| `capnet-peers` | List CapNet peer sessions |
| `capnet-hello <ip>` | Send Hello to a remote Oreulius node |
| `capnet-attest <peer-id>` | Send attestation frame to a peer |
| `capnet-offer <peer-id> <token>` | Transfer a capability token to a peer |
| `capnet-revoke <token-id>` | Revoke a CapNet token |
| `tls-connect <host> <port>` | Open a TLS session |
