# Oreulius — IPC & Dataflow

**Status:** Implemented core IPC subsystem with bounded channels, capability-gated access, admission control, scheduler-backed blocking at the service layer, diagnostics, temporal service framing, ticketed zero-sum capability transfer, Temporal session typing, and replayable channel snapshots.

For the internal implementation reference, see [`kernel/src/ipc/README.md`](../../kernel/src/ipc/README.md). For the remaining work, see [oreulius-ipc-implementation-roadmap.md](./oreulius-ipc-implementation-roadmap.md).

Oreulius is dataflow-first: components communicate through explicit message passing rather than ambient shared state. The IPC system is the kernel's general-purpose transport for process communication, service discovery, capability propagation, and several binary service protocols.

---

## 1. Core Model

### 1.1 Channels

The core primitive is the **channel**.

- **Bounded:** every channel has a fixed queue capacity.
- **Capability-gated:** callers need a `ChannelCapability` with the appropriate rights.
- **Process-owned:** channel capabilities are tied to an owning `ProcessId`.
- **Backpressure-aware:** send/receive paths do not treat "full" or "empty" as a single undifferentiated error.

The current capacity model is:

| Constant | Value |
| --- | ---: |
| `CHANNEL_CAPACITY` | `4` messages |
| `MAX_CHANNELS` | `16` |
| `MAX_MESSAGE_SIZE` | `512` bytes |
| `MAX_CAPS_PER_MESSAGE` | `16` |

### 1.2 Messages

Messages carry:

- a bounded byte payload
- a causal `EventId`
- an optional `cause` link to another event
- zero or more attached capabilities
- the sending `ProcessId`

Oreulius uses message-carried capabilities to hand authority explicitly from one component to another rather than relying on global namespace lookups.

### 1.3 Rights

`ChannelCapability` currently exposes these rights:

- `SEND`
- `RECEIVE`
- `CLOSE`

The `ipc` module also includes an `AffineEndpoint<CAPACITY>` wrapper for linear endpoint delegation experiments. Message-carried capability transfer now uses one-time ticketed transfer semantics: export consumes the live source authority, import is one-time, and duplicate or tampered ticket reuse fails closed.

---

## 2. Current Implementation Structure

The old monolithic IPC implementation has already been split into dedicated modules under [`kernel/src/ipc`](../../kernel/src/ipc):

| File | Current role |
| --- | --- |
| `mod.rs` | façade, re-exports, singleton access, wait-address helpers |
| `types.rs` | scalar IPC types and shared constants |
| `message.rs` | `Message` construction and capability attachments |
| `rights.rs` | channel rights, channel capability, affine endpoint wrapper |
| `errors.rs` | public IPC error taxonomy |
| `ring.rs` | bounded FIFO queue |
| `channel.rs` | channel state machine and queue mutation |
| `admission.rs` | send/receive decision logic |
| `backpressure.rs` | pressure thresholds, actions, counters |
| `table.rs` | live channel registry |
| `service.rs` | `IpcService` and public kernel-facing API |
| `diagnostics.rs` | read-only channel and IPC snapshots |
| `selftest.rs` | deterministic runtime selftests |

This split is no longer aspirational. It is the implementation in tree today.

---

## 3. Admission, Backpressure, and Blocking

### 3.1 Admission control

Send and receive policy goes through explicit decision enums:

- `SendDecision::{Commit, Refuse, Defer}`
- `RecvDecision::{Deliver, Refuse, Defer}`

Admission currently checks:

- predictive restriction status from the security subsystem
- capability ownership and rights
- channel identity match
- closure state
- queue pressure / backpressure policy

This means IPC policy is no longer hidden in ad hoc channel mutation branches.

### 3.2 Backpressure

Backpressure is first-class.

- high pressure starts at `3 / 4` occupancy
- async channels can be refused under pressure depending on flags
- reliable bounded sends can defer and block for capacity
- counters and high-water data are tracked for diagnostics

### 3.3 Blocking semantics

There are two layers of receive/send behavior:

- low-level channel helpers remain nonblocking and can still return `WouldBlock`
- the service-layer APIs in `IpcService` block through scheduler wait queues when a schedulable current process exists

In practice:

- `IpcService::recv()` can block on a per-channel message wait key
- `IpcService::send()` can block on a per-channel capacity wait key
- if the runtime cannot stage a schedulable block, the service layer falls back to `WouldBlock`

This is an important distinction: Oreulius now has real blocking IPC behavior at the service boundary, but not every helper in the lower layers is itself a blocking API.

---

## 4. Channel Lifecycle

Oreulius no longer treats close as a single abrupt bit flip.

The current close model distinguishes:

- `Open`
- `Draining`
- terminal closed/sealed state

Current behavior:

- new sends are refused once drain begins
- queued messages remain deliverable while the channel drains
- receivers continue draining until the queue is empty
- blocked waiters are woken when close transitions make progress

Publicly visible errors include:

- `WouldBlock`
- `Closed`
- `ChannelDraining`
- `PermissionDenied`
- `InvalidCap`
- `MessageTooLarge`
- `TooManyCaps`
- `TooManyChannels`

`ChannelDraining` is important because it lets callers distinguish "shutting down but still draining accepted work" from "fully closed."

---

## 5. Capability Transfer and Service Discovery

### 5.1 Current capability transfer

Message-carried capabilities are currently:

- attached to a `Message`
- signed before insertion
- available to the receiver for explicit validation and import
- installable into the receiver's capability state through the existing import path

This is now capability-gated, auditable, and zero-sum by construction. Export consumes the live source authority, ticketed import is one-time, and the kernel self-check rejects duplicate or tampered ticket reuse.

### 5.2 Service discovery

Service discovery is no longer just an architectural idea. Oreulius now has a real service registry and introduction protocol under [`kernel/src/services/registry.rs`](../../kernel/src/services/registry.rs).

Current shell-visible surfaces include:

- `svc-request`
- `intro-demo`

The registry currently models service types such as:

- filesystem
- persistence
- network
- timer
- console
- temporal
- compositor
- fetch service

The design goal remains the same: no ambient global lookup as the primary authority path. Services are introduced explicitly through capability-mediated channels.

---

## 6. Temporal IPC Binary Protocol

Temporal service traffic is a binary-framed IPC protocol. It is no longer limited to snapshot/read/history basics.

### 6.1 Frame layout

Requests use a 16-byte little-endian header:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `magic = 0x31504D54` (`TMP1`) |
| 4 | 1 | `version = 1` |
| 5 | 1 | `opcode` |
| 6 | 2 | `flags` |
| 8 | 4 | `request_id` |
| 12 | 2 | `payload_len` |
| 14 | 2 | `reserved` |

Responses use a 20-byte little-endian header:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `magic = 0x31504D54` |
| 4 | 1 | `version = 1` |
| 5 | 1 | `opcode` |
| 6 | 2 | `flags` |
| 8 | 4 | `request_id` |
| 12 | 4 | `status` |
| 16 | 2 | `payload_len` |
| 18 | 2 | `reserved` |

### 6.2 Current opcodes

The current opcode set is:

| Opcode | Name |
| ---: | --- |
| `1` | `SNAPSHOT` |
| `2` | `LATEST` |
| `3` | `READ` |
| `4` | `ROLLBACK` |
| `5` | `HISTORY` |
| `6` | `STATS` |
| `7` | `BRANCH_CREATE` |
| `8` | `BRANCH_CHECKOUT` |
| `9` | `BRANCH_LIST` |
| `10` | `MERGE` |

### 6.3 Current status codes

| Status | Meaning |
| ---: | --- |
| `0` | success |
| `-1` | invalid frame |
| `-2` | unsupported version |
| `-3` | unsupported opcode |
| `-4` | invalid payload |
| `-5` | missing or invalid capability |
| `-6` | permission denied |
| `-7` | not found |
| `-8` | internal failure |
| `-9` | conflict |

### 6.4 Capability policy

Temporal IPC enforces attached filesystem capability rights:

- `SNAPSHOT`, `LATEST`, `READ`, and `HISTORY` require `READ`
- `ROLLBACK` requires `WRITE`
- `BRANCH_CREATE`, `BRANCH_CHECKOUT`, and `MERGE` require `WRITE`
- `BRANCH_LIST` requires `READ`
- `STATS` requires no filesystem capability

Branch and merge operations are part of the current protocol surface and should be documented as such; older six-opcode descriptions are stale.

### 6.5 Session typing

Temporal channels can also be bound to a `TemporalSessionState` at the kernel layer.

When a channel is bound this way:

- the session id must match the frame payload
- request and response phases are checked explicitly
- malformed frames and invalid phase transitions are rejected by the channel validator

This is the current Temporal pilot for protocol/session-typed IPC. Other IPC paths remain unbound unless they opt into a typed session state.

---

## 7. Wasm IPC Surface

Wasm currently imports IPC through the execution host surface in [`kernel/src/execution/wasm.rs`](../../kernel/src/execution/wasm.rs).

Current IPC-related host functions are:

| Host id | Import name |
| ---: | --- |
| `3` | `channel_send` / `oreulius_channel_send` |
| `4` | `channel_recv` / `oreulius_channel_recv` |
| `10` | `channel_send_cap` / `oreulius_channel_send_cap` |

The public Wasm SDK wrapper in [`wasm/sdk/src/ipc.rs`](../../wasm/sdk/src/ipc.rs) currently exposes the basic send/recv path. The lower-level raw ABI file may lag behind the real host-id mapping and should not be treated as the authoritative source over the kernel host dispatch table.

---

## 8. Diagnostics and Runtime Inspection

Oreulius now has real IPC diagnostics, not just theory notes.

The shell currently exposes:

- `ipc-list`
- `ipc-inspect <channel-id>`
- `ipc-stats`
- `ipc-selftest`

These commands surface runtime information such as:

- live channel count
- queue occupancy
- closure state
- waiter counts
- backpressure levels and recommended actions
- queue high-water marks
- send-pressure hit counters
- deterministic selftest results

This diagnostic surface is part of the actual implementation and should be used as the source of truth when inspecting IPC behavior.

---

## 9. What Is Still Incomplete

Oreulius's IPC subsystem is much further along than earlier docs suggested, but there are still a few open items on top of the implemented core.

The most important remaining gaps are now:

- **Broader protocol coverage:** Temporal is the first typed protocol; other IPC services can still remain unbound until they opt into a protocol state machine.
- **Proof/refinement coverage:** the new IPC semantics are runtime-checked, but they still need stronger proof-trace and refinement coverage if the project wants higher verification tiers.
- **Docs and wrapper parity:** some secondary ABI/docs surfaces still need to be kept aligned with the kernel implementation as IPC semantics continue to settle.

Those gaps sit on top of a production-usable IPC core and runtime self-check surface, not a hypothetical subsystem.

---

## 10. Design Direction

The long-term Oreulius IPC direction remains:

- explicit authority transfer instead of ambient lookup
- bounded queues and inspectable backpressure
- scheduler-integrated blocking at the service boundary
- auditable capability propagation
- richer temporal reconstruction over time

What changed since the older docs is that much of that foundation is now implemented, not merely planned.
