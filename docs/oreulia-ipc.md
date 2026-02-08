# Oreulia — IPC & Dataflow

**Status:** Implemented (Feb 8, 2026)

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

### 2.2 Blocking & Yielding
- **Receive**: If a channel is empty, `ipc_recv` will **block** the calling process and yield the CPU. The scheduler will wake the process when data arrives.
- **Send**: If a channel is full, `ipc_send` will block until space is available (providing natural backpressure).

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

Optional improvement:

- allow sender to attenuate at transfer time (preferred)
  - attach `(cap_id, rights_mask)`

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

See also: `docs/oreulia-mvp.md` → “Risks & mitigations” for current MVP performance tradeoffs.

---

## 8. Interaction with Wasm

Wasm modules can be restricted to:

- `channel_send(cap, data, caps...)`
- `channel_recv(cap) -> (data, caps...)`

This makes IPC the universal “syscall.”
