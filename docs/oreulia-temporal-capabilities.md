# Oreulia Temporal Capabilities with Revocable History

> **Status:** Fully implemented. WASM host ABI IDs 116–120. Scheduler auto-sweep: `temporal_cap_tick()`. SDK: `wasm/sdk/src/temporal.rs`. Kernel subsystems: `kernel/src/execution/wasm.rs` (TEMPORAL_CAP_TABLE, TEMPORAL_CHECKPOINT_STORE), `kernel/src/temporal/mod.rs` (temporal event log).

---

## 1. Overview

Temporal Capabilities redefine what an OS capability *is*. In classical capability-based systems a capability is a static, unforgeable token of authority: you have it or you don't. Temporal Capabilities in Oreulia extend this with two new primitives that make capabilities **temporal objects**:

1. **Time-bound grants** — a capability is minted with a deadline, expressed in 100 Hz PIT ticks. When the deadline passes the kernel auto-revokes it with no module polling required.
2. **Transactional checkpoints** — a process can snapshot its entire capability set at any moment, perform potentially-risky operations, then atomically roll back to the snapshot: all capabilities granted after the snapshot are revoked and the snapshotted set is re-instated.

Together these two primitives make capability grants behave like **smart contracts on system state**: they carry their own temporal validity, their own rollback policy, and they integrate directly with the kernel's audit and observer infrastructure.

### Key properties

| Property | Mechanism |
|---|---|
| Deadline enforcement | `TEMPORAL_CAP_TABLE` (32 slots); swept by `temporal_cap_tick()` on every scheduler tick |
| Resolution | 100 Hz PIT (10 ms per tick); minimum grant = 1 tick |
| Manual revocation | `temporal_cap_revoke` (ID 117) or `CapabilityManager::revoke_capability` |
| Lifetime query | `temporal_cap_check` (ID 118) returns remaining ticks |
| Checkpoint capacity | 8 outstanding checkpoints per kernel; 16 capabilities per snapshot |
| Rollback atomicity | All post-snapshot caps revoked first; then snapshot re-granted from temporal log |
| Audit integration | Every grant and revoke written to `temporal::record_capability_event()` |
| Observer integration | `observer_notify(CAPABILITY_OP, ...)` emitted on auto-revocation |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  WASM Module                                                     │
│  temporal::cap_grant()  temporal::checkpoint_create()           │
│  temporal::cap_revoke() temporal::checkpoint_rollback()         │
│  temporal::cap_check()                                          │
└────────────────────────┬────────────────────────────────────────┘
                         │  WASM host ABI (IDs 116–120)
┌────────────────────────▼────────────────────────────────────────┐
│  Temporal Cap Host Functions  (kernel/src/execution/wasm.rs)    │
│  host_temporal_cap_grant / cap_revoke / cap_check               │
│  host_temporal_checkpoint_create / checkpoint_rollback          │
└──────────┬─────────────────────────────────┬───────────────────┘
           │                                 │
    ┌──────▼──────────────────┐   ┌──────────▼───────────────────┐
    │  TEMPORAL_CAP_TABLE      │   │  TEMPORAL_CHECKPOINT_STORE   │
    │  32 × TemporalCapSlot    │   │  8 × TemporalCheckpoint      │
    │  (pid, cap_id,           │   │  16 caps each                │
    │   expires_at, cap_type,  │   │  (cap_id, object_id,         │
    │   object_id)             │   │   cap_type, rights)          │
    └──────────────┬───────────┘   └──────────────────────────────┘
                   │
    ┌──────────────▼───────────────────────────────────────────────┐
    │  temporal_cap_tick()  (called from scheduler tick, 100 Hz)  │
    │  Sweeps TEMPORAL_CAP_TABLE, calls revoke_capability()        │
    │  on each expired slot, notifies observer bus                 │
    └─────────────────────────────────────────────────────────────┘
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/execution/wasm.rs` | Host functions (IDs 116–120), `TEMPORAL_CAP_TABLE`, `TEMPORAL_CHECKPOINT_STORE`, `temporal_cap_tick()` |
| `kernel/src/temporal/mod.rs` | `record_capability_event()`, temporal log persistence, `is_replay_active()` |
| `wasm/sdk/src/temporal.rs` | High-level SDK: `cap_grant`, `cap_revoke`, `cap_check`, `checkpoint_create`, `checkpoint_rollback`, `TemporalCap` RAII guard |
| `wasm/sdk/src/raw/oreulia.rs` | Raw FFI bindings for IDs 116–120 |

---

## 3. Formal Model

### 3.1 Capability time-validity

**Definition T.1 (Temporal Capability).** A temporal capability is a tuple $(c, t_{\text{issued}}, t_{\text{expires}}, r)$ where $c$ is the capability ID, $t_{\text{issued}}$ is the PIT tick at grant time, $t_{\text{expires}} = t_{\text{issued}} + \Delta$ for deadline $\Delta$ ticks, and $r$ is the rights bitmask.

**Definition T.2 (Time-bound validity predicate).** A temporal capability $(c, t_i, t_e, r)$ is valid at tick $t$ iff:

$$t_i \leq t \leq t_e$$

The kernel auto-revokes when $t > t_e$, i.e., the validity window is closed on the left by issuance and open on the right (the next sweep after $t_e$ triggers revocation).

**Definition T.3 (PIT tick).** The hardware PIT fires at 100 Hz; each tick corresponds to $\Delta t = 10\text{ ms}$. A deadline of $\Delta$ ticks corresponds to a real-time upper bound of $\Delta \times 10\text{ ms}$.

**Proposition T.4 (Auto-revocation soundness).** If `temporal_cap_tick()` is called at every PIT interrupt, then no expired capability remains active for more than one tick beyond its deadline.

*Proof.* `temporal_cap_tick()` reads `now = get_ticks()` and revokes every slot where `s.expires_at <= now`. Since the PIT fires at most every `TICK_PERIOD` and `temporal_cap_tick()` is registered in the PIT interrupt handler, it runs within one tick of expiry. $\square$

**Proposition T.5 (Deadline Monotonicity).** Refreshing (re-granting) a capability with a new deadline $\Delta'$ does not extend the expiry of the original capability. The original is revoked; a new `cap_id` is issued.

*Proof.* `host_temporal_cap_grant` always calls `capability_manager().grant_capability()` which assigns a fresh `cap_id`. No mutation of an existing slot's `expires_at` is performed. $\square$

### 3.2 Checkpoint-rollback model

**Definition T.6 (Capability Snapshot).** A capability snapshot for process $p$ at tick $t_s$ is the set $S_p(t_s) = \{(c_i, \text{object\_id}_i, \text{cap\_type}_i, r_i)\}$ of all capabilities active for $p$ at $t_s$.

**Definition T.7 (Post-snapshot grant set).** Let $G_p(t_s, t)$ be the set of capabilities granted to $p$ strictly after $t_s$ and before rollback time $t$. These are the capabilities that must be revoked on rollback.

**Definition T.8 (Rollback operation).** A checkpoint rollback at time $t$ for process $p$ with checkpoint $(t_s, S_p(t_s))$:

1. Revokes all $c \in G_p(t_s, t)$ via `revoke_capability`.
2. Re-grants all $(c_i, \text{obj}_i, \text{type}_i, r_i) \in S_p(t_s)$ via `grant_capability`.

**Proposition T.9 (Rollback capability-set equivalence).** After a successful rollback, the active capability set for $p$ equals $S_p(t_s)$ (modulo fresh `cap_id` values, since re-grant allocates new IDs).

*Proof.* Step 1 removes all post-snapshot grants. Step 2 re-grants exactly $|S_p(t_s)|$ capabilities. No other process's capability set is affected. $\square$

**Corollary T.10 (No authority leakage through rollback).** Rollback cannot grant $p$ any capability it did not hold at checkpoint time. $S_p(t_s)$ is computed from the live capability table at snapshot time; no capabilities are added by the rollback path itself.

### 3.3 Temporal event log integration

Every grant and revoke records a `TemporalCapabilityEvent` in `temporal::record_capability_event()`:

$$\text{event} = (\text{pid}, \text{cap\_type}, \text{object\_id}, \text{rights}, \text{event\_type}, \text{cap\_id})$$

where `event_type ∈ {GRANT, REVOKE}`. These events are written to the temporal store and survive kernel restart. On boot, `temporal_apply_capability_event()` replays grants; it is guarded by `is_replay_active()` to prevent re-emission of new events during replay.

**Lemma T.11 (Temporal log consistency under replay).** The temporal log contains exactly one GRANT and at most one REVOKE event per `(pid, cap_id)` pair. Rollback and auto-revoke both emit REVOKE events, so the log faithfully reconstructs the authority timeline.

---

## 4. WASM Host ABI (IDs 116–120)

### ID 116 — `temporal_cap_grant(cap_type: i32, rights: i32, expires_ticks: i32) → i32`

Grants a time-bound capability to the calling process:

1. Validates `cap_type` via `CapabilityType::from_raw(cap_type_raw)`.
2. Derives `object_id = now_ticks XOR (pid × 0x9E3779B97F4A7C15)` — a unique, process-scoped, tick-mixed identifier.
3. Calls `capability_manager().grant_capability(pid, object_id, cap_type, rights, pid)`.
4. Registers a `TemporalCapSlot` in `TEMPORAL_CAP_TABLE`: `expires_at = now + expires_ticks`.
5. Writes a GRANT event to the temporal log (skipped if `is_replay_active()`).

Returns `cap_id ≥ 0` on success; negative error codes:
- `−1` — invalid `cap_type`
- `−2` — capability table full for this process
- `−3` — `TEMPORAL_CAP_TABLE` full (32 slots)

### ID 117 — `temporal_cap_revoke(cap_id: i32) → i32`

Immediately revokes `cap_id` owned by the calling process:

1. Calls `capability_manager().revoke_capability(pid, cap_id)`.
2. Removes the matching slot from `TEMPORAL_CAP_TABLE`.
3. Writes a REVOKE event to the temporal log.

Returns `0` on success, `−1` if `cap_id` not found.

### ID 118 — `temporal_cap_check(cap_id: i32) → i32`

Returns the remaining lifetime in PIT ticks:

$$\text{remaining} = \max(0, \text{expires\_at} - \text{now})$$

Returns `−1` if `cap_id` is not found in `TEMPORAL_CAP_TABLE` (it may have already expired and been swept, or may be a non-temporal capability). Returns `0` if expiring this tick.

### ID 119 — `temporal_checkpoint_create() → i32`

Snapshots the calling process's entire capability set:

1. Calls `capability_manager().list_capabilities_for_pid(pid)` — returns all active `OreuliaCapability` entries.
2. Finds a free slot in `TEMPORAL_CHECKPOINT_STORE` (8 slots max).
3. Copies up to `MAX_CAPS_PER_CHECKPOINT = 16` capabilities as `TemporalCheckpointEntry` records: `{cap_id, object_id, cap_type, rights}`.
4. Records `tick = now` for the snapshot timestamp.

Returns `checkpoint_id ≥ 1` on success, `−1` if the store is full.

### ID 120 — `temporal_checkpoint_rollback(checkpoint_id: i32) → i32`

Rolls back the calling process to a previously created checkpoint:

1. Locates `checkpoint_id` in `TEMPORAL_CHECKPOINT_STORE` (must be owned by `pid`).
2. Enumerates all current capabilities for `pid` via `list_capabilities_for_pid`. Any capability whose `cap_id` is **not** in the snapshot is revoked via `revoke_capability`.
3. For each `TemporalCheckpointEntry` in the snapshot, calls `grant_capability` to re-create the capability.
4. Marks the checkpoint slot inactive (consumed on use).

Returns `0` on success, `−1` if checkpoint not found or not owned by this process, `−2` if re-grant fails (insufficient kernel resources).

---

## 5. Data Structures

### 5.1 `TemporalCapSlot`

```rust
struct TemporalCapSlot {
    active:     bool,
    pid:        u32,       // owning process
    cap_id:     u32,       // capability ID in CapabilityManager
    expires_at: u64,       // absolute PIT tick (auto-revoke when now >= expires_at)
    cap_type:   u8,        // raw capability type tag
    object_id:  u64,       // object this capability authorizes access to
}
```

Capacity: `TEMPORAL_CAP_TABLE: Mutex<TemporalCapTable>`, 32 slots (`MAX_TEMPORAL_CAP_SLOTS = 32`).

### 5.2 `TemporalCheckpoint`

```rust
struct TemporalCheckpointEntry {
    cap_id:    u32,
    object_id: u64,
    cap_type:  u8,
    rights:    u32,
}

struct TemporalCheckpoint {
    active:    bool,
    id:        u32,          // checkpoint_id returned to WASM
    pid:       u32,          // owning process
    tick:      u64,          // PIT tick at snapshot time
    cap_count: u8,           // number of valid entries
    caps:      [TemporalCheckpointEntry; 16],
}
```

Capacity: `TEMPORAL_CHECKPOINT_STORE: Mutex<CheckpointStore>`, 8 slots (`MAX_TEMPORAL_CHECKPOINTS = 8`), 16 capabilities each (`MAX_CAPS_PER_CHECKPOINT = 16`).

### 5.3 `temporal_cap_tick()`

```
Called from: PIT interrupt handler (100 Hz)

for each active TemporalCapSlot s:
    if now >= s.expires_at:
        capability_manager().revoke_capability(ProcessId(s.pid), s.cap_id)
        serial_println!("[temporal] auto-revoked cap {} for pid {}", ...)
        observer_notify(CAPABILITY_OP, [pid_bytes..., 0x02, 0, 0, 0])
        s.active = false
```

The `0x02` tag in the observer payload identifies the event as a REVOKE (as opposed to GRANT = `0x01`), allowing observer WASM modules to distinguish the cause.

---

## 6. SDK Usage

```rust
use oreulia_sdk::temporal;

// ── Time-bound grant ────────────────────────────────────────────────────────
// Grant FS_READ access for ~10 seconds (100 Hz × 1000 ticks).
let cap_id = temporal::cap_grant(
    14,        // cap_type: FS_READ
    0x4000,    // rights: FS_READ bitmask
    1000,      // expires after 1000 PIT ticks = 10 seconds
).expect("grant failed");

// Query remaining lifetime.
match temporal::cap_check(cap_id) {
    Some(ticks) => { /* ticks remaining */ }
    None        => { /* already expired / not time-bound */ }
}

// Manual early revocation.
temporal::cap_revoke(cap_id).ok();

// ── RAII scoped grant ───────────────────────────────────────────────────────
{
    let _guard = temporal::TemporalCap::new(
        temporal::cap_grant(14, 0x4000, 500).expect("grant failed")
    );
    // … use the capability …
    // auto-revoked when _guard drops (calls cap_revoke internally)
}

// ── Checkpoint + rollback ───────────────────────────────────────────────────
// Snapshot current capability set.
let cp = temporal::checkpoint_create().expect("checkpoint table full");

// Do risky work (may grant additional capabilities).
let risky_cap = temporal::cap_grant(5, 0x0100, 200).unwrap();

// Something went wrong — roll back.
temporal::checkpoint_rollback(cp).expect("rollback failed");
// risky_cap is now revoked; original set restored.
```

---

## 7. Integration Points

### 7.1 Scheduler tick integration

`temporal_cap_tick()` is called from the PIT interrupt handler on every tick. It does not block: it acquires `TEMPORAL_CAP_TABLE` under a spinlock, collects expired `(pid, cap_id)` pairs into a fixed-size stack array, releases the lock, then performs revocations and observer notifications outside the lock. The lock-free revocation phase prevents priority inversion on the scheduler hot path.

### 7.2 Temporal event log

Every grant/revoke is journaled via `temporal::record_capability_event(pid, cap_type, object_id, rights, origin_pid, event_type, cap_id)`. The temporal module's persistence subsystem snapshots these events to the durable store. On boot, `temporal_apply_capability_event()` processes the journal to reconstruct the authority state from the last checkpoint — so capability grants can survive kernel restarts.

### 7.3 Observer bus

Auto-revocations emit `observer_notify(CAPABILITY_OP, payload)` where `payload[0..3] = pid_le, payload[4] = 0x02 (REVOKE)`. WASM observer modules subscribed to `CAPABILITY_OP` events will receive this notification on their IPC channel (see `oreulia-kernel-observers.md`).

### 7.4 Intent graph

The intent graph's adaptive restriction pathway can call `temporal_cap_grant` with a very short deadline as a non-binary authority degradation: instead of outright revocation, a module is granted a new short-lived copy of its capability — effectively rate-limiting how long it can exercise authority in any continuous window.

---

## 8. Formal Properties and Corollaries

**Theorem T.12 (Temporal Confinement).** A module that holds only temporal capabilities cannot exercise authority beyond its configured deadline, regardless of whether it calls `cap_revoke` proactively.

*Proof.* `temporal_cap_tick()` sweeps all active slots at every PIT tick. Any slot with `expires_at <= now` is revoked via `capability_manager().revoke_capability()` before the next instruction can be scheduled. The scheduler only runs WASM modules between ticks. $\square$

**Proposition T.13 (Checkpoint Isolation).** Checkpoint-rollback for process $p$ does not affect capability tables of any other process $p' \neq p$.

*Proof.* The rollback path calls `list_capabilities_for_pid(p)` and all subsequent `revoke_capability(p, ...)` and `grant_capability(p, ...)` operations are scoped to process $p$. The `CapabilityManager` per-task table is indexed by `ProcessId`. $\square$

**Proposition T.14 (Rollback Does Not Escalate Rights).** Re-granted capabilities after rollback carry the same `rights` as the snapshotted entries, not elevated rights.

*Proof.* `TemporalCheckpointEntry.rights` is copied from the live capability at snapshot time. `grant_capability` is called with exactly these rights. No rights-inflation step exists in the rollback path. $\square$

**Lemma T.15 (No Orphaned Expiry Slots).** When a capability is revoked manually via `temporal_cap_revoke` or through `CapabilityManager`, its slot in `TEMPORAL_CAP_TABLE` is deactivated.

*Proof.* `host_temporal_cap_revoke` explicitly iterates `TEMPORAL_CAP_TABLE` and sets `slots[i].active = false` for the matching `(pid, cap_id)` pair after the revocation call. Auto-revoke in `temporal_cap_tick()` similarly marks slots inactive. $\square$

**Corollary T.16 (Sweep Idempotency).** Calling `temporal_cap_tick()` multiple times on an already-expired, already-revoked capability is safe. The capability manager's `revoke_capability` is idempotent for non-existent caps; the slot is already inactive so the expiry check `s.active && now >= s.expires_at` fails. $\square$

---

## 9. Known Limitations

| Limitation | Detail |
|---|---|
| **16-cap checkpoint limit** | `MAX_CAPS_PER_CHECKPOINT = 16`; processes with more than 16 active capabilities get a truncated snapshot. The `host_temporal_checkpoint_create` implementation silently truncates beyond 16 entries. |
| **8 outstanding checkpoints** | `MAX_TEMPORAL_CHECKPOINTS = 8`. A process that creates checkpoints without rolling back or consuming them will exhaust the store and receive `−1`. |
| **Rollback uses fresh cap IDs** | Re-granted capabilities receive new `cap_id` values from `CapabilityManager`. Any code that cached the old `cap_id` before rollback will hold stale handles. |
| **10 ms sweep granularity** | Expiry is accurate to ±1 tick (10 ms). If a process must rely on sub-10 ms capability lifetimes, the PIT frequency must be increased. |
| **No cross-process rollback** | Rollback is scoped to the calling process only. There is no mechanism to atomically roll back capabilities across a group of processes. |
| **Temporal log replay reuses old rights** | The temporal event log records rights at grant time. If the rights model changes between a crash and recovery, replayed events use the old bitmask. |
