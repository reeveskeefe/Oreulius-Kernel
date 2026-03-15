# Oreulia — IPC & Dataflow

**Status:** Implemented (v0 core, March 11, 2026)

For the full implementation roadmap from the current `kernel/src/ipc/mod.rs` root module to the target IPC architecture, see [docs/ipc/oreulia-ipc-implementation-roadmap.md](./oreulia-ipc-implementation-roadmap.md).

Current v0 limitations that matter for planning:

- `Channel::recv()` inside the core channel type still aliases `try_recv()`, but `IpcService::recv()` now blocks through scheduler wait queues when a schedulable process context exists and falls back to `WouldBlock` otherwise.
- capability attachments are signed and transferable, but not yet zero-sum linear by construction.
- `close()` now enters a draining state when queued messages remain, but it is not yet a full replay-complete graceful-closure protocol.
- temporal replay captures IPC state partially rather than reconstructing a full event-complete channel state.
- runtime diagnostics/selftests exist (`ipc-list`, `ipc-inspect`, `ipc-stats`, `ipc-selftest`), including blocked sender/receiver visibility, queue high-water tracking, backpressure hit counters, and a deterministic runtime wakeup scenario, but deeper admission/session/replay coverage is still planned.
- send/receive policy now goes through an explicit admission decision layer. The service-layer send/recv APIs are scheduler-backed when a schedulable current process exists, while the low-level channel helpers still expose raw nonblocking `WouldBlock` behavior. Backpressure policy is no longer only “full queue or not”: non-high-priority async channels now refuse once they cross the high-pressure threshold, while saturated reliable sends still defer on capacity.

Oreulia is dataflow-first: components communicate through message passing rather than shared global state or shared memory. The Inter-Process Communication (IPC) system is the primary mechanism for interaction between the kernel and user-mode (Wasm) applications.

---

## 1. Core Concepts

### 1.1 Channels
The fundamental primitive is the **Channel**.
- **Bidirectional**: Channels support both sending and receiving messages.
- **Bounded**: Each channel has a fixed capacity to ensure backpressure.
- **Capability-Gated**: A `Channel` is an object in the kernel; processes hold a `ChannelCapability` (handle) to access it.

### 1.2 Messages
Messages in Oreulia are strictly typed and delimited.
- **Data Payload**: Byte array (e.g., serialized struct or raw data).
- **Capability Payload**: Handles can be sent *inside* messages. This is how authority propagates (e.g., passing a `FileDescriptor` to a worker process).

---

## 2. Implementation Details

### 2.1 Syscall Interface
Wasm modules interact with IPC via dedicated imports:

```rust
// Interface from `oreulia-wasm-abi`
fn ipc_create() -> handle;
fn ipc_send(handle: u32, msg_ptr: u32, len: u32) -> status;
fn ipc_recv(handle: u32, buf_ptr: u32) -> len;
```

Kernel syscall boundary also exposes capability-attachment variants:
- `channel_send_caps(channel, msg_ptr, msg_len, caps_ptr, caps_count)`
- `channel_recv_caps(channel, buf_ptr, buf_len, caps_ptr, caps_count_out_ptr)`

`caps_ptr` is an array of packed capability descriptors (`SysIpcCapability`), max
`MAX_CAPS_PER_MESSAGE` entries.

### 2.2 Blocking & Yielding
- **Current v0 behavior**: `try_recv` is nonblocking. `IpcService::recv` parks the caller on a per-channel message wait queue until a message arrives or closure becomes visible, while `IpcService::send` parks reliable/capacity-controlled senders on a per-channel capacity wait queue when the channel is full. The core `Channel::{send,recv}` helpers remain the low-level nonblocking primitives used for compatibility and tests.
- **Current v0 close behavior**: closing a channel rejects new sends immediately and drains already-queued messages before the channel becomes terminally closed.
- **Current wake behavior**: send wakes one waiting receiver, receive wakes one capacity waiter, and terminal close wakes blocked waiters so they can observe closure instead of sleeping indefinitely.
- **Current fallback behavior**: if there is no schedulable current process context, the service-layer blocking paths fall back to `WouldBlock` instead of sleeping while holding kernel state.
- **Current observability**: `ipc-list`, `ipc-inspect`, and `ipc-stats` expose per-channel waiting receiver/sender counts, backpressure level, recommended pressure action, queue high-water mark, high/saturated send-pressure hit counters, and wake counters so blocked and saturated paths can be inspected at runtime.

---

## 3. Capability Transfer
This is the most powerful feature of Oreulia's IPC.

1. **Sender** includes a handle index in the message header.
2. **Kernel** verifies the sender owns that handle.
3. **Kernel** clones the underlying kernel object reference.
4. **Kernel** creates a new handle in the **Receiver's** capability table.
5. **Receiver** gets the new handle index in the message.

This mechanism allows "zero-trust" service discovery: a process doesn't need to "find" the filesystem service; it is *hand-delivered* a connection to it by the supervisor at startup.

- transferred rights are identical to sender’s capability rights
- service-pointer transfer additionally requires sender right `SERVICE_DELEGATE`
- imported capabilities are validated against capability type and kernel object liveness

Optional improvement:

- allow sender to attenuate at transfer time (preferred)
  - attach `(cap_id, rights_mask)`

Target roadmap change:

- replace copy-style transfer with a zero-sum capability-transfer path backed by `capability.rs`

### 3.1 Service Pointer Transfer Pattern

For directly callable function/service capabilities:
1. Provider registers a service pointer (`service_register`).
2. Provider exports and attaches capability on IPC send.
3. Consumer imports capability from received message.
4. Consumer invokes with `service_invoke`.

---

## 4. Temporal IPC Binary Protocol (v1)

Temporal service traffic is now a binary framed protocol (no text parsing).

### 4.1 Request frame

Little-endian, fixed 16-byte header:

| Offset | Size | Field |
|---|---:|---|
| 0 | 4 | `magic = 0x31504D54` (`"TMP1"`) |
| 4 | 1 | `version = 1` |
| 5 | 1 | `opcode` |
| 6 | 2 | `flags` (reserved, currently `0`) |
| 8 | 4 | `request_id` (echoed by response) |
| 12 | 2 | `payload_len` |
| 14 | 2 | `reserved` |

Payload follows immediately and must match `payload_len` exactly.

### 4.2 Response frame

Little-endian, fixed 20-byte header:

| Offset | Size | Field |
|---|---:|---|
| 0 | 4 | `magic = 0x31504D54` |
| 4 | 1 | `version = 1` |
| 5 | 1 | `opcode` (echoed) |
| 6 | 2 | `flags` (echoed) |
| 8 | 4 | `request_id` (echoed) |
| 12 | 4 | `status` (`0` success, negative error) |
| 16 | 2 | `payload_len` |
| 18 | 2 | `reserved` |

### 4.3 Opcodes and payload schemas

- `1 SNAPSHOT`: request payload `u16 path_len + path_bytes`; response payload `TemporalMeta[32]`.
- `2 LATEST`: request payload `u16 path_len + path_bytes`; response payload `TemporalMeta[32]`.
- `3 READ`: request payload `u64 version_id + u16 preview_len + u16 path_len + path_bytes`; response payload `u32 total_len + u32 returned_len + returned_bytes`.
- `4 ROLLBACK`: request payload `u64 version_id + u16 path_len + path_bytes`; response payload `RollbackMeta[16]`.
- `5 HISTORY`: request payload `u32 start_from_newest + u16 max_entries + u16 path_len + path_bytes`; response payload `u16 count + u16 reserved + count * HistoryRecord[64]`.
- `6 STATS`: request payload empty; response payload `TemporalStats[20]`.

### 4.4 Capability policy

- `SNAPSHOT`, `LATEST`, `READ`, `HISTORY` require attached filesystem capability with `READ`.
- `ROLLBACK` requires attached filesystem capability with `WRITE`.
- Path-scoped filesystem capabilities are enforced against requested temporal path.
- `STATS` requires no filesystem capability.

### 4.5 Status codes

- `0`: success
- `-1`: invalid frame
- `-2`: unsupported protocol version
- `-3`: unsupported opcode
- `-4`: invalid payload
- `-5`: missing/invalid capability attachment
- `-6`: permission denied (rights/scope)
- `-7`: object/version not found
- `-8`: internal/service failure

---

## 5. IPC patterns (conventions)

Kernel provides only channels; user space standardizes higher-level patterns.

### 5.1 Request/response

- client sends request message with a `reply_channel` capability
- server replies on the reply channel

### 5.2 Publish/subscribe

- publisher has a list of subscriber channels
- publisher sends events to each subscriber

### 5.3 Pipelines

- stage A → stage B → stage C
- backpressure propagates upstream via bounded queues

### 5.4 Supervision signals

- supervisor provides a control channel
- components report health, crashes, and state checkpoints

---

## 6. Error handling

Define a small set of IPC errors:

- `InvalidCap`: cap_id not present
- `PermissionDenied`: rights mismatch
- `WouldBlock`: channel full/empty
- `Closed`: endpoint closed (v1 if channel close semantics exist)
- `MessageTooLarge`: exceeds bounds
- `TooManyCaps`: exceeds bounds

---

## 7. Performance path (later)

v0 uses copy-based messaging.

Future optimizations:

- shared memory regions with explicit capabilities
- scatter-gather / iovecs
- zero-copy receive for large payloads

All must preserve:

- bounded resource usage
- explicit authority

See also: `docs/project/oreulia-mvp.md` → “Risks & mitigations” for current MVP performance tradeoffs.

---

## 8. Interaction with Wasm

Wasm modules can be restricted to:

- `channel_send(cap, data, caps...)`
- `channel_recv(cap) -> (data, caps...)`

This makes IPC the universal “syscall.”
