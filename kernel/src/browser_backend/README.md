# `browser_backend` — In-Kernel Browser Network Stack

The `browser_backend` module is the **in-kernel half** of the Oreulius browser
stack.  It owns every piece of network state that requires kernel privilege
(sockets, TLS, cookie storage, HTTP cache, capability tokens, audit) while
deliberately containing **none** of the components that can live safely in
userspace.

**Explicitly excluded from this module** — these live in the userspace renderer
process, which receives raw byte streams from this backend:

- HTML / CSS / JavaScript parsers
- Layout engine and render tree
- DOM and CSSOM
- JavaScript execution engine
- Any decoded media pipeline

---

## File Map

| File | Lines | Role |
|---|---|---|
| `mod.rs` | 72 | Public API surface — `init`, `tick`, `handle_request`; re-exports |
| `types.rs` | 360 | Core value types: `Url`, `Origin`, `BrowserCap`, `HttpMethod`, `MimeType`, `StatusCode`, `RedirectPolicy` |
| `protocol.rs` | 297 | IPC wire types: `BrowserRequest`, `BrowserResponse`, `BrowserEvent`, error enums |
| `service.rs` | 569 | Global singleton `BROWSER_SERVICE`; all request dispatch; navigate flow |
| `session.rs` | 312 | `BrowserSession` state (nav history, event queue); `SessionTable` with LCG cap generation |
| `fetch.rs` | 623 | Full HTTP/1.1 fetch pipeline: scheme → TLS → request → header parse → body stream |
| `transport.rs` | 330 | Transport layer: DNS resolution, TLS spin-loop, TCP send/receive, `TransportHandle` |
| `origin.rs` | 297 | Same-origin model, cross-origin policy enforcement, `OriginTable` per session |
| `cookie_jar.rs` | 460 | SameSite / Secure / HttpOnly cookie enforcement, domain/path matching |
| `cache.rs` | 377 | 2 MiB ring-buffer response cache, TTL-based lookup, ETag / Last-Modified support |
| `headers.rs` | 315 | Zero-allocation HTTP header parsing: status line, `parse_headers`, `decode_chunked` |
| `policy.rs` | 207 | Stateless `BrowserPolicy` checker: scheme, mixed-content, redirect, denylist |
| `content_filter.rs` | 252 | MIME sniffing, inline vs. download classification, `SniffResult` |
| `downloads.rs` | 235 | Capability-gated download jobs, `DownloadManager`, accept / reject lifecycle |
| `storage.rs` | 151 | VFS-backed per-session key/value store under `/browser/<session_id>/` |
| `audit.rs` | 221 | 128-entry ring-buffer audit log, 18 `AuditKind` variants |
| `temporal.rs` | 330 | Snapshot / restore stubs for kernel snapshot lifecycle |

**Total: 17 files, 5,340 lines — zero heap allocation, all `no_std`.**

---

## Architecture

```
 Userspace renderer process
        │  IPC
        ▼
 ┌──────────────────────────────────────────────┐
 │  mod.rs  (public gateway)                    │
 │    init() ─► service::init()                 │
 │    tick() ─► service::tick()                 │
 │    handle_request(req) ─► service::handle()  │
 └──────────────────┬───────────────────────────┘
                    │
 ┌──────────────────▼───────────────────────────┐
 │  service.rs  (global singleton)              │
 │  BROWSER_SERVICE: Mutex<BrowserBackendService>│
 │                                              │
 │  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
 │  │ sessions │  │ origins  │  │  cookies  │  │
 │  │session.rs│  │ origin.rs│  │cookie_jar │  │
 │  └──────────┘  └──────────┘  └───────────┘  │
 │                                              │
 │  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
 │  │  cache   │  │downloads │  │  storage  │  │
 │  │  cache.rs│  │downloads │  │ storage.rs│  │
 │  └──────────┘  └──────────┘  └───────────┘  │
 │                                              │
 │  ┌──────────┐  ┌──────────┐                 │
 │  │  audit   │  │ temporal │                 │
 │  │ audit.rs │  │temporal.rs│                │
 │  └──────────┘  └──────────┘                 │
 └───────────────────┬──────────────────────────┘
                     │  Navigate
 ┌───────────────────▼──────────────────────────┐
 │  fetch.rs  (HTTP/1.1 fetch pipeline)         │
 │   scheme check ─► BrowserPolicy              │
 │   cookie header ─► CookieJar                 │
 │   cache check ─► ResponseCache               │
 │   content filter ─► ContentFilter            │
 └───────────────────┬──────────────────────────┘
                     │  connect / send / recv
 ┌───────────────────▼──────────────────────────┐
 │  transport.rs  (TransportHandle)             │
 │   DNS ─► net::net_reactor::dns_resolve       │
 │   TLS ─► net::tls  (spin-poll handshake)     │
 │   TCP ─► net::net_reactor::tcp_*             │
 └──────────────────────────────────────────────┘
```

---

## Core Types (`types.rs`)

All types are fixed-size and `Copy`. No heap allocation anywhere.

### `Url`
```rust
pub struct Url {
    pub scheme:      Scheme,
    pub host:        [u8; 253],
    pub host_len:    usize,
    pub port:        u16,
    pub path:        [u8; 1024],
    pub path_len:    usize,
    pub query:       [u8; 512],
    pub query_len:   usize,
}
```
`Url::parse(raw: &[u8]) -> Option<Url>` — recognises `http://` and `https://`,
extracts host, optional port, path, and query string.

### `Origin`
```rust
pub struct Origin {
    pub scheme:   Scheme,
    pub host:     [u8; 253],
    pub host_len: usize,
    pub port:     u16,
}
```
`Origin::OPAQUE` — sentinel for origins that cannot be compared.
`Origin::from_url(url)` — derives origin tuple from a parsed `Url`.
`same_origin(a, b)` — strict (scheme, host, port) comparison.

### `BrowserCap`
```rust
pub struct BrowserCap(pub u64);
pub const INVALID: BrowserCap = BrowserCap(0);
```
MAC-style capability token.  `is_valid()` tests for non-zero. Generated via LCG
in `SessionTable::next_cap()`; verified on every privileged request call.

### Other Key Types

| Type | Definition | Notes |
|---|---|---|
| `BrowserSessionId` | `(u32)` | One per browser tab/context; up to 8 |
| `RequestId` | `(u32)` | Monotonic per-session fetch counter |
| `DownloadId` | `(u32)` | Download job handle |
| `Scheme` | `{ Http, Https, Unknown }` | `default_port()`, `is_secure()` |
| `HttpMethod` | `{ Get, Post, Head, Put, Delete, Options }` | `has_body()` |
| `MimeType` | `{ bytes[128], len }` | `is_text()`, `is_html()`, `is_json()`, `is_binary()` |
| `StatusCode` | `(u16)` | `is_success()`, `is_redirect()`, `is_client_error()`, `is_server_error()` |
| `RedirectPolicy` | `{ max_redirects: u8, follow_cross_origin: bool }` | `DEFAULT=(10,true)`, `NO_FOLLOW=(0,false)` |

---

## IPC Protocol (`protocol.rs`)

All communication between the renderer and this backend is structured.
No raw byte-stream dispatch.

### `BrowserRequest` (inbound from renderer)

| Variant | Fields | Action |
|---|---|---|
| `OpenSession` | `pid, profile[32]` | Allocate session slot and capability token |
| `CloseSession` | `session, cap` | Tear down all session state |
| `Navigate` | `session, cap, url[2048], method, body[4096], redirect` | Initiate or follow a fetch |
| `Subscribe` | `session, cap` | Enable event delivery to this session |
| `Unsubscribe` | `session, cap` | Disable event delivery |
| `AbortRequest` | `session, cap, request_id` | Best-effort abort of an in-flight request |
| `AcceptDownload` | `session, cap, dest_path[256]` | Accept a pending download offer |
| `RejectDownload` | `session, cap, download_id` | Reject a pending download offer |
| `PollEvents` | `session, cap` | Drain up to 8 queued events |

### `BrowserResponse` (outbound to renderer)

| Variant | Fields | Meaning |
|---|---|---|
| `SessionGranted` | `session, cap` | New session allocated |
| `RequestAccepted` | `request_id` | Navigate accepted; events will follow |
| `Subscribed` | — | Subscribe acknowledged |
| `Ok` | — | Generic success |
| `Error(BrowserError)` | — | Operation rejected |
| `Events` | `events[8], count` | Batch of up to 8 events |

### `BrowserEvent` (delivered via `PollEvents`)

| Variant | Fields |
|---|---|
| `Headers` | `request_id, status, mime, content_length, headers[32], header_count` |
| `BodyChunk` | `data[4096], data_len, is_last` |
| `Redirect` | `from_url[2048], to_url[2048], status` |
| `PolicyBlocked` | `reason: PolicyBlockReason` |
| `TlsState` | `result: TlsHandshakeResult` |
| `DownloadOffered` | `download_id, filename[256], mime, size_hint` |
| `DownloadComplete` | `bytes_written` |
| `Complete` | `request_id` |
| `FetchError` | `kind: FetchErrorKind, message[128]` |

### Protocol Constants

| Constant | Value | Purpose |
|---|---|---|
| `HEADER_NAME_MAX` | 64 | Max bytes in a response header name |
| `HEADER_VALUE_MAX` | 256 | Max bytes in a response header value |
| `MAX_RESPONSE_HEADERS` | 32 | Max headers per response |
| `BODY_CHUNK_MAX` | 4096 | Max bytes per `BodyChunk` event |
| `ERROR_MSG_MAX` | 128 | Max bytes in a `FetchError` message |

---

## Service Layer (`service.rs`)

### Global Singleton

```rust
pub struct BrowserBackendService {
    sessions:    SessionTable,
    origins:     OriginTable,
    cookies:     CookieJar,
    cache:       ResponseCache,
    downloads:   DownloadManager,
    storage:     StorageTable,
    audit:       AuditLog,
    epoch:       u64,
    initialised: bool,
}

pub static BROWSER_SERVICE: Mutex<BrowserBackendService> = Mutex::new(/* const new */);
```

Every subsystem is owned here.  The mutex guarantees all state is serialised.

### Request Dispatch

```
handle_request(req: BrowserRequest) -> BrowserResponse
    │
    ├─ OpenSession    ─► do_open_session(pid, profile)
    ├─ CloseSession   ─► verify_cap → do_close_session
    ├─ Navigate       ─► verify_cap → do_navigate
    ├─ Subscribe      ─► verify_cap → session.subscribed = true
    ├─ Unsubscribe    ─► verify_cap → session.subscribed = false
    ├─ AbortRequest   ─► verify_cap → audit → best-effort abort
    ├─ AcceptDownload ─► verify_cap → downloads.accept(dest_path)
    ├─ RejectDownload ─► verify_cap → downloads.reject(download_id)
    └─ PollEvents     ─► verify_cap → session.drain_events(out)
```

### `OpenSession` Flow

1. `sessions.find_by_pid(pid)` — reject if a session already exists for this PID
2. `sessions.open(pid)` — allocate slot; ID = slot + 1; generate `BrowserCap` via LCG
3. `origins.register(session)` — set up `OriginPolicy::open(OPAQUE)`
4. `storage.register(session)` — create `/browser/<id>/` in VFS
5. `audit.session_opened(session)`
6. Return `BrowserResponse::SessionGranted { session, cap }`

### `CloseSession` Flow

1. `verify_cap(session, cap)` — abort on mismatch
2. `sessions.close(session)`
3. `origins.unregister(session)`
4. `cookies.purge_session(session)`
5. `cache.purge_session(session)`
6. `downloads.purge_session(session)`
7. `storage.unregister(session)`
8. `audit.session_closed(session)`

### `Navigate` Flow (detailed)

```
verify_cap(session, cap)
    │
    ▼
Url::parse(url_raw)                     → BrowserError::InvalidUrl
    │
    ▼
BrowserPolicy.check_scheme(scheme)      → BrowserError::UnsupportedScheme
    │
    ▼
origins.check_navigation(session, url)  → audit + InternalError
    │
    ▼
request_id = session.alloc_request_id()
    │
    ▼
cache.lookup(session, url, epoch)  [GET only]
    │ cache hit ────────────────────► enqueue Headers + BodyChunk + Complete
    │                                  return RequestAccepted
    │ cache miss
    ▼
fetch_request(&FetchContext, events, &mut count)
    │
    ├── FetchOutcome::Complete    ─► origins.update_top_origin
    │                                session.push_nav(url)
    │                                audit.navigate_commit
    │
    ├── FetchOutcome::Redirect    ─► enqueue Redirect event
    │                                (service layer handles re-navigation)
    │
    ├── FetchOutcome::PolicyBlocked ► audit.policy_blocked + enqueue PolicyBlocked
    │
    └── FetchOutcome::Error       ─► enqueue FetchError event
```

### Capability Verification

```rust
fn verify_cap(session_id, cap) -> bool {
    session.cap == cap && cap.is_valid()
}
```

`BrowserCap(0)` is never issued (LCG always ORs result with 1); any zeroed
capability field is rejected immediately.

---

## Session Management (`session.rs`)

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_BROWSER_SESSIONS` | 8 | Maximum concurrent browser sessions |
| `NAV_HISTORY_DEPTH` | 32 | Ring buffer entries for navigation history |
| `EVENT_QUEUE_DEPTH` | 64 | Ring buffer entries for pending events |

### `BrowserSession` Structure

```rust
pub struct BrowserSession {
    pub id:         BrowserSessionId,
    pub pid:        ProcessId,
    pub cap:        BrowserCap,
    pub policy:     PolicyProfile,
    pub subscribed: bool,
    pub alive:      bool,

    // Navigation history ring
    nav_history: [NavigationEntry; 32],
    nav_head:    usize,
    nav_count:   usize,

    // Event queue ring
    event_queue: [Option<BrowserEvent>; 64],
    event_head:  usize,
    event_tail:  usize,
    event_count: usize,

    next_request_id: u32,
}
```

- `push_nav(url)` — serialises `Url` back to `scheme://host[:port]/path[?query]`;
  overwrites oldest entry on overflow
- `current_url()` — last `NavigationEntry`
- `alloc_request_id()` — wrapping counter; always skips 0
- `enqueue(ev)` — drops silently if queue is full (no blocking, no panic)
- `drain_events(out: &mut [Option<BrowserEvent>; 8])` — drains up to 8 per poll call

### `SessionTable`

```rust
pub struct SessionTable {
    slots:    [BrowserSession; MAX_BROWSER_SESSIONS],
    cap_seed: u64,
}
```

**LCG capability generator:**
```rust
fn next_cap(&mut self) -> BrowserCap {
    self.cap_seed = self.cap_seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    BrowserCap(self.cap_seed | 1)  // guaranteed odd and non-zero
}
```

**O(1) session lookup:** `find(id)` → `sessions.slots[id.0 - 1]`; no scan needed.

`restore(idx, id, pid, cap)` — temporal restoration hook; skips LCG, reuses stored cap.

---

## Fetch Pipeline (`fetch.rs`)

### Types

```rust
pub struct FetchContext<'a> {
    pub session: BrowserSessionId,
    pub request: RequestId,
    pub url:     &'a Url,
    pub method:  HttpMethod,
    pub body:    &'a [u8],
    pub profile: &'a PolicyProfile,
}

pub enum FetchOutcome {
    Complete,
    Redirect { status: u16, location: [u8; 2048], location_len: usize },
    PolicyBlocked(PolicyBlockReason),
    Error(FetchErrorKind),
}
```

### Pipeline Steps

```
fetch_request<const MAX_EVENTS>(ctx, events, count)
  1. BrowserPolicy.check_scheme(scheme)
  2. TransportHandle::connect(scheme, host, port)
       ├── HTTPS: DNS → tls::alloc_session → spin tls::tick_all ≤512 ticks
       └── HTTP:  DNS → net_reactor::tcp_connect
  3. Emit TlsState event (Established / Plaintext / Failed)
  4. Build Host: header (omit default port)
  5. Build /path?query string
  6. transport.send_http_request(method, path, host, body)
       → HTTP/1.1 in REQ_BUF[4096] scratch via BufWriter
  7. read_until_headers() → reads until \r\n\r\n; max RECV_BUF=8192 / MAX_HEADER_BLOCK=16384
  8. parse_status_line() → status_code + header_block_start
  9. parse_headers() → [ResponseHeader; 32]
 10. Extract Content-Length, Content-Type, chunked transfer flag
 11. Redirect check (301/302/303/307/308) → parse Location → return Redirect
 12. push_headers() event
 13. stream_body():
       chunked: decode_chunked() + leftover buffer loop
       identity: read in BODY_CHUNK_MAX=4096 pieces tracking content_length
       each slice: BodyChunk event
       final slice: is_last=true → Complete event
```

### Buffer Constants

| Name | Value | Purpose |
|---|---|---|
| `RECV_BUF` | 8192 | Single-read receive buffer |
| `MAX_HEADER_BLOCK` | 16384 | Maximum raw header block |
| `BODY_CHUNK_MAX` | 4096 (from protocol) | Max bytes per BodyChunk event |

---

## Transport Layer (`transport.rs`)

### `TransportHandle`

```rust
pub struct TransportHandle {
    scheme:     Scheme,
    tls_handle: i32,    // valid when Https (-1 otherwise)
    tcp_conn:   u16,    // valid when Http
    pub server_ip: [u8; 4],
}
```

### Connection Establishment

```
connect(scheme, host, port)
  DNS: net_reactor::dns_resolve(host_str) → Ipv4Addr
  
  HTTPS:
    tls::alloc_session(host, port, ip) → tls_handle: i32
    loop ≤ MAX_TICKS=512:
      tls::tick_all()
      if handshake_done(handle)  → break (Established)
      if handshake_failed(handle) → return Err(TlsHandshakeFailed)
  
  HTTP:
    net_reactor::tcp_connect(remote_addr, port) → tcp_conn: u16
```

### HTTP/1.1 Request Format

Built in a `REQ_BUF[4096]` scratch via `BufWriter`:
```
METHOD /path?query HTTP/1.1\r\n
Host: hostname[:port]\r\n
Connection: close\r\n
Accept: */*\r\n
[Content-Length: N\r\n]
\r\n
[body bytes]
```

### Read / Write

| Method | HTTPS | HTTP |
|---|---|---|
| `send` | `tls::session_mut(h).write(buf)` | `net_reactor::tcp_send(conn, buf)` |
| `read_raw` | `s.tick(); s.read(out)` | `net_reactor::tcp_recv(conn, out)` |
| `close` | `tls::free_session(h)` | `net_reactor::tcp_close(conn)` |

`read_exact_or_eof` — blocking read loop with `MAX_TICKS=512` timeout before
returning an error.

---

## Origin Security Model (`origin.rs`)

### `OriginPolicy`

```rust
pub struct OriginPolicy {
    pub top_origin:         Origin,
    pub allow_cross_origin: bool,
    pub allowlist:          [Origin; 32],
    pub allowlist_len:      usize,
}
```

Two constructors:
- `OriginPolicy::open(top)` — cross-origin allowed, no allowlist
- `OriginPolicy::same_origin_only(top)` — cross-origin blocked

### Origin Classification

```rust
pub enum OriginClassification {
    SameOrigin,
    SameSite,
    CrossOrigin,
    Opaque,
}
```

`classify(context, target)` — full classification:
- `SameOrigin`: exact (scheme, host, port) match
- `SameSite`: last-two-label registrable domain match, any scheme
- `CrossOrigin`: different origin, same-site check failed
- `Opaque`: target is `Origin::OPAQUE`

`same_site()` approximates registrable domain by comparing the last two DNS
labels (e.g. `sub.example.com` and `other.example.com` → same site).

### Check Results

```rust
pub enum OriginCheckResult {
    Allowed,
    BlockedByAllowlist,
    BlockedCrossOrigin,
    BlockedOpaque,
}
```

- `check_navigation(policy, url)` — permissive: cross-origin navigation allowed
  unless explicitly blocked
- `check_subresource(policy, url)` — strict: cross-origin subresources are
  blocked unless allowlist contains the target origin

### `OriginTable`

Maintains up to `MAX_SESSION_ORIGINS=16` per-session→policy mappings.
`update_top_origin(session, origin)` is called on every successful
`NavigateCommit` to reflect the current top-level document origin.

---

## Cookie Jar (`cookie_jar.rs`)

### Storage

```rust
pub struct CookieEntry {
    name:       [u8; 128],   // COOKIE_NAME_MAX
    value:      [u8; 4096],  // COOKIE_VALUE_MAX
    domain:     [u8; 253],
    path:       [u8; 256],
    session:    BrowserSessionId,
    http_only:  bool,
    secure:     bool,
    same_site:  SameSite,    // { Strict, Lax (default), None }
    expires:    u64,         // epoch seconds; 0 = session cookie
    active:     bool,
}
// MAX_COOKIES = 128
```

### `set()` — Cookie Ingestion Rules

1. Reject `Secure` attribute on non-HTTPS responses
2. Scope `Domain` to request host if attribute absent
3. `Max-Age ≤ 0` → delete existing matching cookie
4. Upsert: match by (name, domain); insert into free slot if no match

### `build_cookie_header()` — Outbound Cookie Rules

Filters by, in order:
1. **Expiry** — expired entries are removed in-place during scan
2. **Secure** — only sent over HTTPS
3. **SameSite::Strict** — blocked on cross-site navigation context
4. **SameSite::None** — requires `Secure`; blocked if not HTTPS
5. **Domain matching** — exact match or `.domain` suffix match
6. **Path matching** — cookie path must be a prefix of the request path

### Attribute Parsing

`parse_set_cookie_attrs(attrs, out)` — parses from the semicolon-separated
attributes portion of a `Set-Cookie` value: `Domain`, `Path`, `SameSite`,
`Max-Age`, `HttpOnly`, `Secure`.

---

## Response Cache (`cache.rs`)

### Layout

```
ResponseCache {
    entries:     [CacheEntry; 32],     // MAX_CACHE_ENTRIES
    pool:        [u8; 2 MiB],         // CACHE_BODY_POOL
    pool_write:  usize,               // ring-buffer write cursor
    count:       usize,
}
```

The body pool is a simple ring-buffer allocator.  New entries always advance
`pool_write`.  If the write would overlap an existing entry's body region,
that entry is invalidated first.

### Cache Key

`url_digest(url)` packs `scheme:host[:port]/path[?query]` into a 512-byte
fixed buffer.  Per-session; two sessions with identical URLs cache independently.

### Lookup

```rust
lookup(session, url, epoch) -> Option<usize>
```
- Session + digest must match
- TTL check: `(epoch - stored_at) > max_age` → cache miss

```rust
etag_value(idx)         // for If-None-Match conditional request
last_modified_value(idx) // for If-Modified-Since conditional request
```

### Cacheability

`is_cacheable(status)` accepts: **200, 203, 300, 301, 410** only.

`store(session, url, status, mime, body, etag, lm, max_age, epoch)`:
- Rejects bodies > `MAX_CACHED_BODY=256 KiB`
- Evicts any existing entry with the same URL key
- Evicts oldest entry if table full (`MAX_CACHE_ENTRIES=32`)

---

## HTTP Header Parsing (`headers.rs`)

Zero-allocation; all functions operate on byte slices.

### Functions

| Function | Signature | Purpose |
|---|---|---|
| `parse_status_line` | `(&[u8]) -> (u16, usize)` | Returns status code and byte offset of first header line |
| `parse_headers` | `(&[u8], &mut [ResponseHeader; 32]) -> usize` | Parse header block; returns count; lowercases header names |
| `get_header` | `(&[ResponseHeader], count, name) -> Option<&[u8]>` | Case-insensitive lookup by name |
| `parse_content_type` | `(&[u8]) -> MimeType` | Strips `; charset=...` parameters |
| `parse_content_length` | `(&[u8]) -> Option<u64>` | Decimal parse; saturating arithmetic |
| `parse_location` | `(&[u8], &mut [u8;2048]) -> Option<&[u8]>` | Trim OWS from `Location:` value |
| `parse_set_cookie` | `(&[u8]) -> (&[u8], &[u8])` | Returns `(cookie_pair, attrs)` split at first `;` |
| `is_chunked_transfer` | `(&[ResponseHeader], count) -> bool` | Checks `Transfer-Encoding: chunked` |
| `decode_chunked` | `(src, dst) -> (written, consumed, done)` | Decodes one pass of chunked body; `done=true` on terminal chunk |

`parse_headers` validates header names against RFC 7230 token characters before
accepting them.

---

## Security Policy (`policy.rs`)

### `BrowserPolicy` — Stateless Checker

All methods take only values; no mutable state.  Each returns
`Option<PolicyBlockReason>` — `None` means allowed.

| Method | Block condition |
|---|---|
| `check_scheme(scheme)` | Not in `ALLOWED_SCHEMES = [Http, Https]` |
| `check_mixed_content(page, resource, is_subresource)` | `is_subresource && page=HTTPS && resource=HTTP` |
| `check_redirect(from, to_url, count)` | `count ≥ MAX_REDIRECTS=10`; non-http(s) target; HTTPS→HTTP downgrade |
| `body_too_large(content_length)` | Declared length > `MAX_BODY_BYTES=64 MiB` |
| `should_offer_download(is_attachment, content_length)` | Attachment flag, or content ≥ `DOWNLOAD_PROMPT_THRESHOLD=1 MiB` |
| `check_tls_handshake_failed(secure)` | TLS failure on HTTPS connection |
| `check_denylist(host, len, denylist)` | Host found in session denylist (ASCII case-insensitive) |

HTTPS→HTTP redirects are **blocked** (active security downgrade).
HTTP→HTTP and HTTPS→HTTPS redirects pass unless over the hop limit.

### `PolicyProfile` — Per-Session Settings

```rust
pub struct PolicyProfile {
    pub allow_mixed_content: bool,
    pub max_redirects:       u8,
    pub max_body_bytes:      usize,
    pub denylist:            [[u8; 253]; 8],   // up to 8 hostnames
    pub denylist_len:        usize,
}
impl PolicyProfile {
    pub const DEFAULT: Self = /* allow_mixed_content=false, max_redirects=10, max_body_bytes=64MiB */;
}
```

`add_denylist(&mut self, host)` — appends a zero-terminated, lowercased ASCII
hostname to the per-session denylist.  No-op if all 8 slots are filled.

---

## Content Filter (`content_filter.rs`)

### Classification

```rust
pub enum SniffResult { Inline, Download, Block }
```

`ContentFilter::classify(declared_mime, is_attachment, sniff_bytes) -> SniffResult`:

```
is_attachment=true              → Download
prefix ∈ FORCE_DOWNLOAD list    → Download
prefix ∈ INLINE_SAFE list       → Inline
sniff_bytes not empty:
  ELF magic (\x7fELF)           → Download
  PE magic (MZ/ZM)              → Download
  ZIP magic (PK\x03\x04)        → Download
  GIF / PNG / JPEG signatures   → Inline
  <html / <!doc prefix          → Inline
unknown                         → Download  (safe default)
```

**MIME whitelist (inline safe):** `text/html`, `text/plain`, `text/xml`,
`application/xhtml+xml`, `application/xml`, `image/*`, `audio/*`, `video/*`,
`application/json`, `application/javascript`, `text/css`, `text/javascript`,
`font/*`, `application/pdf`

**Force-download list:** `application/octet-stream`, PE/ELF/Mach-O executables,
ZIP, TAR, gzip, bzip2, xz, 7z, RAR, Windows cabinet

### Helpers

| Method | Purpose |
|---|---|
| `is_attachment(content_disposition)` | Returns `true` if disposition type is `attachment` |
| `extract_filename(content_disposition, out)` | Parses `filename=` or `filename*=` attribute; writes to `out[256]`; returns length |

---

## Download Manager (`downloads.rs`)

### Job Lifecycle

```
offer()  →  Pending
              │
              ├── accept(dest_path)  →  Active
              │       │
              │       ├── record_progress(bytes)
              │       │
              │       ├── complete()  →  Complete
              │       │
              │       └── error()     →  Error
              │
              └── reject()  →  Rejected
```

### `DownloadJob`

```rust
pub struct DownloadJob {
    pub id:            DownloadId,
    pub session:       BrowserSessionId,
    pub request:       RequestId,
    pub state:         DownloadState,
    pub filename:      [u8; 256],
    pub filename_len:  usize,
    pub mime:          MimeType,
    pub size_hint:     u64,        // 0 = unknown
    pub dest_path:     [u8; 256],  // filled on AcceptDownload
    pub dest_path_len: usize,
    pub bytes_written: u64,
    pub active:        bool,
}
// MAX_DOWNLOADS = 16
```

### `DownloadManager` Operations

| Method | Guard |
|---|---|
| `offer(session, request, filename, mime, size_hint) -> Option<DownloadId>` | Returns `None` if table full |
| `accept(id, session, dest_path) -> bool` | Requires `Pending` state; session must match |
| `reject(id, session) -> bool` | Session must match |
| `record_progress(id, bytes)` | Saturating add to `bytes_written` |
| `complete(id)` | Marks `Complete` |
| `error(id)` | Marks `Error`; clears `active` |
| `dest_path(id) -> Option<(&[u8], usize)>` | Returns path for VFS write |
| `purge_session(session)` | Clears all jobs for a session (on `CloseSession`) |

---

## Per-Session Storage (`storage.rs`)

### Filesystem Layout

```
/browser/
  <session_id>/
    <key>     ← arbitrary ASCII key, used as filename
    <key2>
    ...
```

All path construction is stack-only: the base path `/browser/<id>/` fits in 64
bytes; full key paths fit in 128 bytes.

### `OriginStorage`

```rust
pub fn new(session: BrowserSessionId) -> Self
pub fn ensure_dir(&self) -> Result<(), StorageError>
pub fn write(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>
pub fn read(&self, key: &[u8], out: &mut [u8]) -> Result<usize, StorageError>
pub fn delete(&self, key: &[u8]) -> Result<(), StorageError>
```

- Keys are validated: ASCII alphanumeric / underscore / hyphen / dot, max
  `KEY_MAX=64` bytes
- Values max `VALUE_MAX=64 KiB` per write call
- Backed by `crate::fs::vfs::{mkdir, write_path, read_path, unlink}`

### `StorageError` Variants

`PathTooLong`, `KeyInvalid`, `WriteFailed`, `ReadFailed`, `NotFound`, `VfsError`

---

## Audit Log (`audit.rs`)

### Structure

```rust
pub struct AuditLog {
    ring: [AuditEntry; 128],    // AUDIT_LOG_SIZE
    head: usize,
    seq:  u32,                  // wrapping monotonic counter
}
```

`AuditEntry` is exactly 64 bytes (one cache line):

```
seq:     u32    — monotonic counter (wraps at u32::MAX)
session: u32    — BrowserSessionId (0 = kernel-initiated)
request: u32    — RequestId (0 = not applicable)
kind:    u8     — AuditKind variant
note:    [u8;32] — free-form ASCII annotation
_pad:    [u8;13]
```

### `AuditKind` Variants (18 total)

| Variant | Value | Emitted by |
|---|---|---|
| `SessionOpened` | 0 | `do_open_session` |
| `SessionClosed` | 1 | `do_close_session` |
| `NavigateStart` | 2 | `do_navigate` |
| `NavigateCommit` | 3 | `do_navigate` (on Complete) |
| `FetchStart` | 4 | `fetch_request` |
| `FetchComplete` | 5 | `fetch_request` |
| `PolicyBlocked` | 6 | fetch / service layer |
| `TlsEstablished` | 7 | `transport::connect` |
| `TlsFailed` | 8 | `transport::connect` |
| `DownloadOffered` | 9 | `downloads::offer` |
| `DownloadComplete` | 10 | `downloads::complete` |
| `CookieSet` | 11 | `cookie_jar::set` |
| `CacheHit` | 12 | `cache::lookup` |
| `CacheMiss` | 13 | `cache::lookup` |
| `RequestAborted` | 14 | `do_abort` |
| `RedirectFollowed` | 15 | `fetch_request` redirect path |
| `ContentFiltered` | 16 | content filter classification |
| `InternalError` | 17 | error paths |

### Iteration

```rust
// Oldest-first full scan
audit.iter() -> impl Iterator<Item = &AuditEntry>

// Incremental drain (journal-style)
audit.drain_since(after_seq: u32, f: FnMut(&AuditEntry))
```

---

## Temporal Persistence (`temporal.rs`)

### Snapshot Format

```
Offset  Size  Field
   0       4  magic = 0x42525357  ('BRSW')
   4       4  version = 1 (u32 LE)
   8       4  session_count (u32 LE)
  12+      N  session records:
               +0  session_id  u32 LE
               +4  pid         u32 LE
               +8  cap         u64 LE
              +16  alive       u8 (1=live)
              +17  reserved × 3
```

`RECORD_SIZE = 20` bytes per session.
Minimum snapshot: `12 + 8 × 20 = 172` bytes.

### API

```rust
snapshot(sessions: &SessionTable, out: &mut [u8]) -> usize
    // Returns bytes written (0 on buffer too small).

validate_snapshot(payload: &[u8]) -> bool
    // Magic + version check only; no state changes.

restore(sessions: &mut SessionTable, payload: &[u8]) -> usize
    // Restores session ID → slot mapping.
    // Capabilities are invalidated and must be re-issued.
    // Cookies, cache, and downloads are NOT restored (deferred).
    // Returns number of records processed.
```

> **Current limitation:** `restore()` is a stub.  Only the session slot
> mapping survives a snapshot/restore cycle.  Full persistence of cookies,
> response cache, and download state is deferred to a future kernel version.

---

## End-to-End Data Flow

### Successful `Navigate` → `Complete`

```
Renderer                         Kernel (browser_backend)
   │                                     │
   │──BrowserRequest::Navigate──────────►│
   │                                     │ verify_cap
   │                                     │ Url::parse
   │                                     │ check_scheme (BrowserPolicy)
   │                                     │ origins.check_navigation
   │                                     │ alloc_request_id
   │                                     │ cache.lookup → miss
   │                                     │ audit.fetch_start
   │                                     │ TransportHandle::connect
   │                                     │   dns_resolve
   │                                     │   tls::alloc_session + spin
   │                                     │   ─ TlsState(Established) ─►queue
   │                                     │ transport.send_http_request
   │                                     │ read_until_headers
   │                                     │ parse_status_line + parse_headers
   │                                     │ ─ Headers event ──────────────►queue
   │                                     │ stream_body (loop)
   │                                     │ ─ BodyChunk events ───────────►queue
   │                                     │ ─ Complete event ─────────────►queue
   │                                     │ cache.store
   │                                     │ origins.update_top_origin
   │                                     │ session.push_nav
   │                                     │ audit.navigate_commit
   │◄──BrowserResponse::RequestAccepted──│
   │                                     │
   │──BrowserRequest::PollEvents────────►│
   │◄──BrowserResponse::Events───────────│ (TlsState, Headers, BodyChunk…)
   │                                     │
   │──BrowserRequest::PollEvents────────►│
   │◄──BrowserResponse::Events───────────│ (…BodyChunk, Complete)
```

### Redirect Flow

```
                                         │ FetchOutcome::Redirect
                                         │ enqueue BrowserEvent::Redirect
                                         │ service re-calls do_navigate
                                         │ with new URL (up to max_redirects)
```

### PolicyBlocked Flow

```
                                         │ check_scheme / check_mixed_content
                                         │   / origins.check_navigation
                                         │   / check_denylist fails
                                         │ audit.policy_blocked
                                         │ enqueue BrowserEvent::PolicyBlocked
                                         │ return RequestAccepted (no body follows)
```

---

## Error Taxonomy

### `BrowserError` — IPC-level errors

| Variant | Meaning |
|---|---|
| `InvalidSession` | Unknown or dead session ID |
| `InvalidCapability` | Cap token mismatch |
| `SessionQuotaExceeded` | All 8 session slots allocated |
| `RequestQuotaExceeded` | Request ID counter exhausted |
| `InvalidUrl` | `Url::parse` returned `None` |
| `UnsupportedScheme` | Scheme not in `ALLOWED_SCHEMES` |
| `InvalidDownload` | Unknown / wrong-session download ID |
| `StorageError` | VFS operation failed |
| `InternalError` | Catch-all internal failure |

### `FetchErrorKind` — Transport / protocol errors

| Variant | Meaning |
|---|---|
| `DnsFailure` | DNS resolution returned no address |
| `ConnectionFailed` | TCP connect syscall failed |
| `TlsHandshakeFailed` | TLS handshake did not complete within MAX_TICKS |
| `ConnectionReset` | Peer reset mid-transfer |
| `ProtocolError` | Malformed HTTP response |
| `TooManyRedirects` | Redirect count ≥ MAX_REDIRECTS |
| `Aborted` | Aborted by `AbortRequest` |
| `InternalError` | Unexpected internal state |

### `PolicyBlockReason` — Security policy enforcement

| Variant | Condition |
|---|---|
| `MixedContent` | HTTP subresource on HTTPS page, or HTTPS→HTTP redirect |
| `OriginNotAllowed` | Host matched per-session denylist |
| `SchemeNotAllowed` | Non-http(s) scheme, or too many redirects |
| `Filtered` | ContentFilter classified as `Block` |
| `TlsCertificateError` | TLS handshake failed on a secure connection |

---

## Security Properties

| Property | Mechanism |
|---|---|
| Session isolation | Each session has an independent `BrowserCap` token; all operations require cap verification |
| Capability forgery prevention | LCG with 64-bit state; result always ORed with 1; cap=0 always invalid |
| No HTTP subresources on HTTPS pages | `BrowserPolicy::check_mixed_content` |
| No HTTPS→HTTP redirect downgrade | `BrowserPolicy::check_redirect` |
| No `data:` / `blob:` / custom scheme | `BrowserPolicy::check_scheme` (allowlist: http, https only) |
| Cookie Secure attribute enforced | `CookieJar::set` rejects Secure cookies on HTTP |
| SameSite enforcement | `build_cookie_header` filters Strict on cross-site; None requires Secure |
| Origin policy per session | `OriginTable` — cross-origin subresources blocked by default |
| Executable MIME force-download | `ContentFilter::classify` — ELF, PE, archives never inlined |
| Kernel-only state | All sensitive state (caps, cookies, session keys) is inside the kernel mutex; renderer sees only event streams |
| Audit trail | Every significant event emits an `AuditEntry` — policy blocks, session open/close, TLS, downloads — stored in a 128-entry ring |

---

## Design Constraints

- **`no_std`, no heap** — every buffer is a fixed-size array on the stack or in
  global statics.  No `Vec`, no `String`, no `Box`.
- **Single mutex** — `BROWSER_SERVICE` serialises all browser state.  Suitable
  for the current I/O model; a sharded design would be required for high
  parallelism.
- **HTTP/1.1 only** — the transport layer does not implement HTTP/2 or HTTP/3.
- **One session per PID** — `do_open_session` enforces a 1-to-1 mapping.
- **Synchronous fetch** — `fetch_request` blocks the kernel thread until
  the response is fully received.  Async I/O integration is a future item.
