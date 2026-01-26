# Oreulia — IPC & Dataflow

**Status:** Draft (Jan 24, 2026)

Oreulia is dataflow-first: components communicate through message passing rather than shared global state.

This document specifies:

- kernel channels (v0)
- message format (v0)
- capability transfer over IPC
- backpressure expectations

---

## 1. Goals

- Simple, correct IPC primitive for early bring-up.
- Explicit capability transfer (authority moves over messages).
- Bounded queues to make backpressure explicit.
- A path to typed schemas later without blocking MVP.

Non-goals (v0):

- zero-copy everywhere
- complex routing/brokers in kernel

---

## 2. Channel model

### 2.1 Objects and endpoints

A `Channel` is a kernel object.

v0 options (choose one for implementation):

- **Unidirectional channel**: separate send/receive endpoints
- **Bidirectional channel**: single object supports send/receive with rights

Oreulia’s capability model naturally supports the bidirectional option:

- `Channel` object with rights `Send` and/or `Receive`

### 2.2 Bounded queues

Channels have bounded queues.

- `capacity`: number of messages or bytes
- send on full queue:
  - either blocks
  - or returns `WouldBlock`

v0 recommendation:

- return `WouldBlock` and let user space decide how/when to retry (simpler)

---

## 3. Message format (v0)

A message has two parts:

- `data`: opaque bytes
- `caps`: a list of capabilities to transfer

Constraints:

- `data_len` is bounded (e.g., 4 KiB v0)
- `caps_len` is bounded (e.g., 16 caps v0)

Rationale:

- keeps kernel copies small
- prevents capability spam

---

## 4. Capability transfer

### 4.1 Send semantics

When a sender attaches capability references:

- kernel verifies sender holds those caps
- kernel duplicates/derives transferable representations
- message enqueued carries “cap payloads”

### 4.2 Receive semantics

On receive:

- kernel dequeues the message
- kernel installs transferred caps into receiver’s capability table
- receiver obtains new `cap_id` values corresponding to received caps

### 4.3 Rights preservation and attenuation

Default transfer rule (v0):

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
