# Oreulia Kernel Observers

> **Status:** Fully implemented. WASM host ABI IDs 106–108. Core: `kernel/src/execution/wasm.rs` (`OBSERVER_REGISTRY`, `observer_notify`). SDK: `wasm/sdk/src/observer.rs`. Integrated with temporal cap sweep, process lifecycle, security manager, polyglot linker, and kernel mesh.

---

## 1. Overview

Kernel Observers are a first-class, non-privileged mechanism for WASM modules to receive live event notifications from the kernel without polling, system call overhead, or access to privileged kernel state. A WASM module subscribes to one or more event categories, receives a kernel-owned IPC channel, and drains events at its own rate. The kernel pushes notifications asynchronously into the channel; the observer reads them via `observer_query`.

This design achieves three goals simultaneously:

1. **Live observability** — no polling or sleep loops; events are pushed by the kernel as they happen.
2. **Capability-based isolation** — the observer receives events through an ordinary IPC channel backed by the capability system, not a raw memory mapping. It cannot peek at kernel internals beyond the structured 32-byte event payloads.
3. **Composability** — observers themselves emit a `POLYGLOT_LINK` event when a new observer subscribes, enabling chains of monitoring modules to bootstrap against one another.

The observer bus is intentionally low-bandwidth: all events are fixed 32 bytes, the registry holds at most 4 concurrent observers, and delivery is best-effort (the kernel does not block on a full channel).

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  WASM Observer Module                                                │
│  observer::subscribe(CAPABILITY_OP | PROCESS_LIFECYCLE)             │
│  loop { observer::query(&mut events) }                              │
└─────────────────────────────┬────────────────────────────────────────┘
                              │  WASM host ABI (IDs 106–108)
┌─────────────────────────────▼────────────────────────────────────────┐
│  Observer Host Functions  (kernel/src/execution/wasm.rs)            │
│  host_observer_subscribe / observer_unsubscribe / observer_query     │
└──────────┬──────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────────┐
│  OBSERVER_REGISTRY: Mutex<ObserverRegistry>                         │
│  4 × ObserverEntry { active, instance_id, channel_id,              │
│                       event_mask, owner_pid }                       │
└──────────┬──────────────────────────────────────────────────────────┘
           │  observer_notify(event_type, payload)
    ┌──────┴─────────────────────────────────────────────────────────┐
    │  IPC Channel per observer (kernel_pid = 0 owns write end)      │
    │  32-byte messages; observer reads via observer_query           │
    └────────────────────────────────────────────────────────────────┘

Event injection sites:
  temporal_cap_tick()          → CAPABILITY_OP   (auto-revoke)
  process spawn                → PROCESS_LIFECYCLE
  SecurityManager anomaly      → ANOMALY_DETECTED
  polyglot_link()              → POLYGLOT_LINK
  observer_subscribe()         → POLYGLOT_LINK   (bootstrap notification)
  kernel mesh migrate-flush    → POLYGLOT_LINK
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/execution/wasm.rs` | `observer_events` module, `ObserverEntry`, `ObserverRegistry`, `OBSERVER_REGISTRY`, host functions IDs 106–108, `observer_notify()` |
| `wasm/sdk/src/observer.rs` | SDK: `subscribe`, `unsubscribe`, `query`, `ObserverEvent`, event constants |
| `kernel/src/security/mod.rs` | Calls `observer_notify(ANOMALY_DETECTED, ...)` |
| `kernel/src/temporal/mod.rs` | `temporal_cap_tick()` calls `observer_notify(CAPABILITY_OP, ...)` |
| `kernel/src/execution/polyglot.rs` | `polyglot_link()` calls `observer_notify(POLYGLOT_LINK, ...)` |

---

## 3. Formal Model

### 3.1 Event system

**Definition O.1 (Event Type).** An event type is a power-of-two bit in the 32-bit event mask:

| Constant | Bit | Semantics |
|---|---|---|
| `CAPABILITY_OP` | 0 | A capability was granted or revoked |
| `PROCESS_LIFECYCLE` | 1 | A process was spawned or exited |
| `ANOMALY_DETECTED` | 2 | The SecurityManager detected anomalous behavior |
| `IPC_ACTIVITY` | 3 | An IPC channel send or receive occurred |
| `MEMORY_PRESSURE` | 4 | Allocator hit a threshold |
| `POLYGLOT_LINK` | 5 | A cross-language module link was established (or new observer subscribed) |
| `ALL` | `0x3F` | All six event types |

**Definition O.2 (Event Payload).** Every event is a fixed 32-byte message:

```
bytes  0– 3:  event_type (u32 LE)
bytes  4– 7:  field_a (u32 LE)  — primary subject (per-event semantics below)
bytes  8–11:  field_b (u32 LE)  — secondary field (per-event semantics below)
bytes 12–31:  reserved / padding (zeroed)
```

**Definition O.3 (Event Mask).** An observer's subscription is a bitmask $M$. It receives event $e$ iff $e \mathbin{\&} M \neq 0$.

**Definition O.4 (Observer Subscription).** An active subscription is a tuple $(\text{instance\_id}, \text{channel\_id}, M, \text{owner\_pid})$.

**Proposition O.5 (Isolation).** An observer WASM module receives only structured 32-byte payloads through its IPC channel. It cannot observe kernel memory, other processes' capability tables, or raw hardware state via the observer mechanism.

*Proof.* `observer_notify` encodes exactly 32 bytes per event and writes them to the IPC channel. The WASM module reads events via `observer_query` which copies from the IPC channel into its own WASM linear memory. No other memory access path exists. $\square$

**Proposition O.6 (Best-Effort Delivery).** If an observer's IPC channel is full, `observer_notify` does not block and the event is silently dropped for that observer.

*Proof.* `observer_notify` calls `ipc().send(&channel_id, &msg_buf)` which returns a `Result`. The `Ok`/`Err` return is not inspected; no retry or blocking occurs. $\square$

### 3.2 Subscription lifecycle

**Definition O.7 (Bootstrap Notification).** When a new observer subscribes successfully, `observer_notify(POLYGLOT_LINK, &event_mask_bytes)` is called before the host function returns. All *existing* observers with `POLYGLOT_LINK` in their mask receive this notification.

**Proposition O.8 (No Self-Notification at Subscribe Time).** The new subscriber's entry is placed in the registry before `observer_notify` is called, but IPC delivery iterates only entries that were already active before the call. Whether the implementation includes the new entry depends on iteration order; however, the new subscriber's channel is just created and empty, so even if it receives the bootstrap event it is not a security concern.

### 3.3 Observer event semantics per type

| Event Type | `field_a` | `field_b` |
|---|---|---|
| `CAPABILITY_OP` | PID of affected process | Operation tag: `0x01`=GRANT, `0x02`=REVOKE |
| `PROCESS_LIFECYCLE` | Parent PID (`0` = kernel) | Child PID |
| `ANOMALY_DETECTED` | Anomalous process PID | Anomaly score (0–255) |
| `IPC_ACTIVITY` | Sender PID | Channel ID |
| `MEMORY_PRESSURE` | Allocated pages | Free pages remaining |
| `POLYGLOT_LINK` | Source module instance ID | Target module instance ID (or new event_mask for bootstrap) |

---

## 4. Data Structures

### 4.1 Event type constants

```rust
pub mod observer_events {
    pub const CAPABILITY_OP:     u32 = 1 << 0;
    pub const PROCESS_LIFECYCLE: u32 = 1 << 1;
    pub const ANOMALY_DETECTED:  u32 = 1 << 2;
    pub const IPC_ACTIVITY:      u32 = 1 << 3;
    pub const MEMORY_PRESSURE:   u32 = 1 << 4;
    pub const POLYGLOT_LINK:     u32 = 1 << 5;
    pub const ALL:               u32 = 0x0000_003F;
}
```

### 4.2 `ObserverEntry` and `ObserverRegistry`

```rust
const MAX_OBSERVER_SLOTS: usize = 4;

struct ObserverEntry {
    active:      bool,
    instance_id: usize,    // WASM module instance ID of subscriber
    channel_id:  u32,      // IPC channel for event delivery
    event_mask:  u32,      // bitmask of subscribed event types
    owner_pid:   ProcessId,
}

struct ObserverRegistry {
    entries: [ObserverEntry; 4],
}

static OBSERVER_REGISTRY: Mutex<ObserverRegistry>
```

---

## 5. WASM Host ABI (IDs 106–108)

### ID 106 — `observer_subscribe(event_mask: i32) → i32`

Registers the calling module as an observer for the specified event categories:

1. Validates `event_mask != 0` (returns `−1` on zero mask).
2. Creates an IPC channel pair: kernel process (`pid = 0`) owns the write end; the subscriber owns the read end via `channel_id`.
3. If IPC channel creation fails, returns `−2`.
4. Finds a free slot in `OBSERVER_REGISTRY` (4 slots). Returns `−3` if full.
5. Records `ObserverEntry { active: true, instance_id, channel_id, event_mask, owner_pid }`.
6. Calls `observer_notify(POLYGLOT_LINK, &event_mask.to_le_bytes())` — notifies all *existing* observers that a new observer with this mask has subscribed.
7. Returns `channel_id as i32` on success.

### ID 107 — `observer_unsubscribe() → i32`

Deregisters the calling module's observer subscription:

1. Searches `OBSERVER_REGISTRY` for an entry with `instance_id == self.instance_id`.
2. Sets `entry.active = false`.
3. Closes the IPC channel via `ipc().close(&close_cap)`.
4. Returns `0` on success, `−1` if no subscription was active.

### ID 108 — `observer_query(buf_ptr: i32, buf_len: i32) → i32`

Drains buffered events from the observer's IPC channel into WASM memory:

1. Verifies the calling module has an active subscription (`−1` if not registered).
2. Reads WASM memory starting at `buf_ptr`, up to `buf_len / 32` event slots.
3. For each pending message in the IPC channel: copies 32 bytes into WASM memory, advances write pointer.
4. Returns the count of events written (may be zero if channel is empty).

---

## 6. `observer_notify` — Kernel Push Path

```rust
pub fn observer_notify(event_type: u32, payload: &[u8]) {
    let mut msg_buf = [0u8; 32];
    msg_buf[0..4].copy_from_slice(&event_type.to_le_bytes());
    let copy_len = payload.len().min(28);
    msg_buf[4..4+copy_len].copy_from_slice(&payload[..copy_len]);

    let registry = OBSERVER_REGISTRY.lock();
    for entry in registry.entries.iter() {
        if entry.active && (entry.event_mask & event_type) != 0 {
            let _ = ipc().send(&entry.channel_id, &msg_buf);
            // best-effort; errors silently dropped
        }
    }
}
```

This function is called from:

| Caller | Event type | Payload |
|---|---|---|
| `temporal_cap_tick()` | `CAPABILITY_OP` | `[pid_le(4B), 0x02, 0, 0, 0]` |
| Process spawn | `PROCESS_LIFECYCLE` | `[parent_pid_le(4B), child_pid_le(4B)]` |
| `SecurityManager::check()` | `ANOMALY_DETECTED` | `[pid_le(4B), score as u8, ...]` |
| `polyglot_link()` | `POLYGLOT_LINK` | `[src_id_le(4B), tgt_id_le(4B)]` |
| `observer_subscribe()` | `POLYGLOT_LINK` | `[event_mask_le(4B)]` |
| Kernel mesh migrate-flush | `POLYGLOT_LINK` | mesh-defined payload |

---

## 7. SDK Usage

```rust
use oreulia_sdk::observer::{self, observer_events, ObserverEvent};

// ── Subscribe to capability and lifecycle events ────────────────────────────
let channel_id = observer::subscribe(
    observer_events::CAPABILITY_OP | observer_events::PROCESS_LIFECYCLE
).expect("observer registry full");

// ── Event loop (blocking iteration) ────────────────────────────────────────
let mut event_buf = [ObserverEvent::default(); 16];
loop {
    let count = observer::query(&mut event_buf);
    for i in 0..count {
        let ev = &event_buf[i];
        match ev.event_type {
            observer_events::CAPABILITY_OP => {
                let pid    = ev.field_a;
                let op_tag = ev.field_b;  // 0x01=GRANT, 0x02=REVOKE
                // ...
            }
            observer_events::PROCESS_LIFECYCLE => {
                let parent_pid = ev.field_a;
                let child_pid  = ev.field_b;
                // ...
            }
            _ => {}
        }
    }
    // yield back to scheduler if no events
    if count == 0 { oreulia_sdk::sched::yield_now(); }
}

// ── Unsubscribe ─────────────────────────────────────────────────────────────
observer::unsubscribe();

// ── SDK types ───────────────────────────────────────────────────────────────
pub struct ObserverEvent {
    pub event_type: u32,
    pub field_a:    u32,
    pub field_b:    u32,
    pub _reserved:  [u8; 20],
}
impl ObserverEvent {
    pub fn from_bytes(bytes: &[u8; 32]) -> Self { /* LE decode */ }
}
```

---

## 8. Use Cases

### 8.1 Anomaly detection telemetry daemon

A security daemon subscribes to `ANOMALY_DETECTED`. When an anomaly event arrives with a high score (`field_b > 200`), it immediately requests capability revocation for `field_a` (the anomalous PID) via the capability API. Because the observer channel is IPC-backed, this daemon does not need to run in kernel mode.

```rust
let _ch = observer::subscribe(observer_events::ANOMALY_DETECTED).unwrap();
loop {
    for ev in drain_events() {
        if ev.event_type == ANOMALY_DETECTED && ev.field_b > 200 {
            capability_api::revoke_all_for_pid(ev.field_a);
        }
    }
}
```

### 8.2 Live capability audit log

A logging service subscribes to `CAPABILITY_OP | PROCESS_LIFECYCLE`. It records every event to a persistent append-only log. No kernel modification needed; the log is purely userspace.

### 8.3 Observer chaining

Observer A subscribes to all events (`ALL`). When it receives a `POLYGLOT_LINK` event with a new event_mask payload, it knows a new observer just subscribed. It can forward interesting events to that observer's IPC channel directly, creating a fan-out topology without kernel involvement.

### 8.4 Memory pressure reaction

A memory manager subscribes to `MEMORY_PRESSURE`. On receiving an event, it frees cached pages and notifies services to reduce their working sets. `field_a` (allocated pages) and `field_b` (free pages) give the current memory state without requiring a syscall.

---

## 9. Integration: Temporal Cap Auto-Revocation

When `temporal_cap_tick()` sweeps the `TEMPORAL_CAP_TABLE` and finds an expired capability, it calls:

```rust
observer_notify(
    observer_events::CAPABILITY_OP,
    &[
        pid_bytes[0], pid_bytes[1], pid_bytes[2], pid_bytes[3],
        0x02,  // REVOKE tag
        0, 0, 0,
    ]
);
```

An observer subscribed to `CAPABILITY_OP` sees the PID in `field_a` and `0x02` as the low byte of `field_b`. This allows observers to distinguish automatic expiry (tag `0x02`) from proactive revocation requests issued by modules.

---

## 10. Known Limitations

| Limitation | Detail |
|---|---|
| **4 observer slots** | `MAX_OBSERVER_SLOTS = 4`. A kernel that needs more simultaneous observers must fan out within a single subscriber. |
| **Best-effort delivery** | If the IPC channel buffer is full, events are silently dropped. Observers must drain their channel promptly. No replay or missed-event indicator. |
| **32-byte payload cap** | Payloads longer than 28 bytes are silently truncated. Structured events use the standard `field_a`/`field_b` encoding for this reason. |
| **No event history** | `observer_query` drains live messages only. An observer that subscribes after a burst of events misses them entirely. |
| **No priority** | All 4 observer slots are treated equally; there is no priority ordering for delivery. |
| **IPC_ACTIVITY and MEMORY_PRESSURE not wired** | As of this writing, `IPC_ACTIVITY` and `MEMORY_PRESSURE` event types are defined and exported but not yet connected to injection sites inside the kernel. They can be subscribed to without error; no events will arrive. |
