# Oreulius - Capabilities (Authority Model)


This document describes Oreulius's current capability model: how authority is
represented, how it moves between tasks and peers, how it is revoked, and how
the kernel enforces it.

Oreulius's core rule remains simple:

**No ambient authority.** If code can perform an operation, that authority must
arrive through a capability or a validated remote lease.

Related documents:

- `docs/capability/oreulius-policy-contracts.md` - conditional capability use
- `docs/capability/oreulius-kernel-mesh.md` - CapNet token transport and mesh ABI
- `docs/capability/oreulius-intent-graph-predictive-revocation.md` - predictive restrictions

---

## 1. Current model at a glance

Oreulius now has two authority carriers:

1. **Local capabilities** stored in a per-task capability table.
2. **Remote capability leases** installed from validated CapNet tokens.

Both feed the same enforcement path. A kernel operation succeeds only if the
kernel can prove all of the following:

- the caller is the owner of a valid capability table entry, or holds a valid remote lease
- the capability or lease targets the required object/type
- the requested rights are a subset of the granted rights
- any time, replay, session, owner, or use-budget constraints still hold
- the security manager has not rate-limited or predictively restricted the caller

This is stricter than a classic "handle table only" design because authority in
Oreulius is not just looked up, it is also signed, audited, replay-aware, and
optionally revocable through temporal and predictive mechanisms.

---

## 2. Local capability representation

The kernel's local authority primitive is `OreuliusCapability` in
`kernel/src/capability/mod.rs`.

Each local capability carries:

- `cap_id`: task-local capability handle
- `object_id`: target kernel object or service object
- `cap_type`: the authority class
- `rights`: rights bitmask
- `origin`: the process that granted or derived it
- `granted_at`: logical tick when it was installed
- `label_hash`: lightweight audit/debug metadata
- `token`: signed integrity token for the capability payload
- `parent_cap_id`: provenance edge for delegation/attenuation tracking

### 2.1 Unforgeability

Local capabilities are not plain integers. The handle is only an index into the
task's capability table. The actual authority record is kernel-owned, and the
record is integrity-protected by a signed capability token.

The token is a SipHash-2-4 MAC over a **48-byte fixed payload** structured as:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Context marker `0x4B43_4150` (ASCII `"KCAP"`) |
| 4 | 4 | Owner PID (`owner.0`) |
| 8 | 4 | `cap_id` |
| 12 | 8 | `object_id` |
| 20 | 4 | `cap_type as u32` |
| 24 | 4 | `rights.bits` |
| 28 | 4 | `origin.0` (granting PID) |
| 32 | 8 | `granted_at` (PIT tick) |
| 40 | 4 | `label_hash` |
| 44 | 4 | Reserved (zero) |

Changing the owner, rights, object, or any field without re-signing with the
correct owner PID invalidates the MAC. The verification call is
`OreuliusCapability::verify_token(owner)` → resolves to
`SecurityManager::cap_token_verify`.

### 2.2 Table limits

The current implementation uses:

- `MAX_CAPABILITIES = 256` local capabilities per task
- `MAX_REMOTE_LEASES = 128` active remote leases
- `MAX_QUARANTINED_CAPS = 256` quarantined capability slots

These are implementation limits, not architectural guarantees.

---

## 3. Capability taxonomy and rights

### 3.1 Type discriminant values

The `CapabilityType` enum is `repr(u8)`. Discriminant values are used when
storing caps in IPC envelopes and CapNet tokens:

| Type | Discriminant | Purpose |
|---|---|---|
| `Channel` | `0` | IPC channel authority |
| `Task` | `1` | Task/process control |
| `Spawner` | `2` | Controlled process/module creation |
| `Console` | `10` | Console I/O authority |
| `Clock` | `11` | Monotonic time access |
| `Store` | `12` | Persistence / snapshot log access |
| `Filesystem` | `13` | Filesystem object access |
| `ServicePointer` | `14` | Service endpoint invocation/delegation |
| `CrossLanguage` | `15` | Polyglot service-link capability (issued by host syscall 105) |
| `Reserved` | `255` | Sentinel / uninitialized |

`CapabilityType::from_raw(u8)` returns `None` for any value not in the above
table (values 3–9, 16–254 are unrecognized).

### 3.2 Rights bitmask — all 21 named constants

The `Rights` struct wraps a `u32` bitmask. All named constants:

| Constant | Bit | Mask | Applicable type |
|---|---|---|---|
| `CHANNEL_SEND` | 0 | `0x0000_0001` | `Channel` |
| `CHANNEL_RECEIVE` | 1 | `0x0000_0002` | `Channel` |
| `CHANNEL_CLONE_SENDER` | 2 | `0x0000_0004` | `Channel` |
| `CHANNEL_CREATE` | 3 | `0x0000_0008` | `Channel` |
| `TASK_SIGNAL` | 4 | `0x0000_0010` | `Task` |
| `TASK_JOIN` | 5 | `0x0000_0020` | `Task` |
| `SPAWNER_SPAWN` | 6 | `0x0000_0040` | `Spawner` |
| `CONSOLE_WRITE` | 7 | `0x0000_0080` | `Console` |
| `CONSOLE_READ` | 8 | `0x0000_0100` | `Console` |
| `CLOCK_READ_MONOTONIC` | 9 | `0x0000_0200` | `Clock` |
| `STORE_APPEND_LOG` | 10 | `0x0000_0400` | `Store` |
| `STORE_READ_LOG` | 11 | `0x0000_0800` | `Store` |
| `STORE_WRITE_SNAPSHOT` | 12 | `0x0000_1000` | `Store` |
| `STORE_READ_SNAPSHOT` | 13 | `0x0000_2000` | `Store` |
| `FS_READ` | 14 | `0x0000_4000` | `Filesystem` |
| `FS_WRITE` | 15 | `0x0000_8000` | `Filesystem` |
| `FS_DELETE` | 16 | `0x0001_0000` | `Filesystem` |
| `FS_LIST` | 17 | `0x0002_0000` | `Filesystem` |
| `SERVICE_INVOKE` | 18 | `0x0004_0000` | `ServicePointer`, `CrossLanguage` |
| `SERVICE_DELEGATE` | 19 | `0x0008_0000` | `ServicePointer` |
| `SERVICE_INTROSPECT` | 20 | `0x0010_0000` | `ServicePointer` |

Special values: `Rights::NONE = 0`, `Rights::ALL = 0xFFFF_FFFF`.

Attenuation is enforced by `Rights::is_subset_of` (bitwise: `(new & !old) == 0`).
Note that `SERVICE_DELEGATE` is required for a `ServicePointer` capability to
be exported via `export_ipc_capability`; missing it returns an error before any
transfer is staged.

### 3.3 Notes

- `CrossLanguage` is a first-class capability type. The `label_hash` lower byte
  stores the destination `LanguageTag` for cheap audit reads.
- The VFS subsystem layers richer directory/process capabilities and quotas on
  top of this core authority model.
- CapNet tokens reuse the same `CapabilityType` discriminant values when
  installing remote leases via `install_remote_lease_from_capnet_token`.

---

## 4. Core operations

### 4.1 Grant

`grant_capability(pid, object_id, cap_type, rights, origin)` installs a new
capability into the target task table, signs it, audits it, and records a
temporal capability event when replay is not active.

### 4.2 Transfer

Capabilities can move between tasks:

- directly through the capability manager's transfer path
- through IPC export/import for supported types
- through service-pointer injection/import paths

Transfers preserve provenance. The destination capability records
`parent_cap_id = Some(source_cap_id)`.

### 4.3 Attenuation

Attenuation is implemented and enforced as a strict subset rule:

- a derived capability may only remove rights
- any attempt to add rights is rejected as `InvalidAttenuation`
- the attenuated capability records `parent_cap_id = Some(original_cap_id)` to
  preserve provenance continuity

This is the core no-amplification invariant for local capability derivation.

### 4.4 Clone / inheritance

Task cloning (`clone_task_capabilities`) copies capability table entries slot-by-slot
into the child task while re-signing each token for the child PID. This preserves
slot layout while preventing cross-owner token reuse.

### 4.5 Revocation

Revocation is no longer deferred. The current implementation supports:

- single-capability revoke by `cap_id` (`revoke_capability`) — also prunes
  all delegation edges from `cap_graph`
- revoke-all for a PID (`revoke_all_capabilities` / `revoke_all_for_pid`)
- revoke by `(cap_type, rights_mask)` match within a task table
- predictive revocation into quarantine (`predictive_revoke_capabilities`)
- remote lease revoke by CapNet `token_id` (`revoke_remote_lease_by_token`)

Revoke events emit temporal records (when not in replay) and fire an observer
notification via `CAPABILITY_OP`.

### 4.6 IPC capability export / staged transfer

Capabilities can be serialized into IPC envelopes for cross-process transfer.
The transfer uses a three-phase commit protocol:

```
export_ipc_capability(owner_pid, cap_id):
  1. take_capability(owner_pid, cap_id)          — removes cap from source table
  2. Check SERVICE_DELEGATE right for ServicePointer caps
  3. alloc_ipc_ticket_id()                       — monotone u64, wraps at max
  4. Build ipc::Capability envelope (116 bytes)  — includes ticket_id, MAC
  5. stage_ipc_transfer(...)                     — ledger entry in pending_ipc_transfers[128]
  6. persist_ipc_transfers_locked(...)           — temporal snapshot
  Returns the ipc::Capability envelope

Consume path (receiver):
  consume_ipc_transfer(source_pid, ticket_id, &cap)
    — verifies ticket/source/envelope match exactly once
    — removes entry from ledger + persists
    — caller installs cap in destination table

Rollback path (if receiver fails):
  rollback_ipc_transfer(source_pid, ticket_id)
    — restores cap to source table at original slot via restore_capability
    — removes ledger entry + persists
```

The pending transfer ledger holds up to `MAX_PENDING_IPC_TRANSFERS = 128` slots.
A temporal snapshot is written on every stage/consume/rollback, enabling
recovery of in-flight transfers after crash-restart.

The extra words in the IPC envelope carry:
- `extra[0]` = `label_hash`
- `extra[1]` = `parent_cap_id.unwrap_or(0)`
- `extra[3]` = `cap_type as u32`

---

## 5. Provenance and delegation graph

Oreulius tracks capability ancestry through `parent_cap_id` and the capability
graph helper in `cap_graph`.

This graph is used to:

- record delegation edges
- reject invalid delegation patterns
- preserve auditable ancestry during transfer/attenuation

The current security model therefore treats delegation as a first-class,
observable event rather than a silent table copy.

---

## 6. Remote capability leases (CapNet integration)

Oreulius does not limit authority transfer to local IPC. Validated CapNet tokens
can install **remote capability leases** into the kernel.

`RemoteCapabilityLease` currently carries:

- `token_id`
- `owner_pid` or `owner_any`
- `issuer_device_id`
- `measurement_hash`
- `session_id`
- `object_id`
- `cap_type`
- `rights`
- `not_before`
- `expires_at`
- `revoked`
- bounded-use state (`enforce_use_budget`, `uses_remaining`)
- `mapped_cap_id` for owner-bound local table projection

### 6.1 Two lease modes

Remote leases operate in two forms:

- **Owner-bound lease**: the token context binds to a specific local PID and
  installs a mapped local capability entry.
- **Owner-any lease**: the token is not projected into a local slot and is
  checked directly in the fallback remote-lease path.

### 6.2 Lease installation

`install_remote_lease_from_capnet_token()` translates a verified
`CapabilityTokenV1` into a local lease:

- capability type is decoded from the CapNet token
- `context == 0` means owner-any
- bounded-use flags become `uses_remaining`
- time bounds become `not_before` and `expires_at`
- owner-bound leases may reuse prior mapped slots when refreshed

### 6.3 Lease revocation

Remote leases can be revoked by token identity:

- `revoke_remote_lease_by_token(token_id)`

This removes the backing lease and also tears down any mapped local capability
projection associated with it.

---

## 7. Enforcement path

The current enforcement hot path is `check_capability(pid, object_id, cap_type, required_rights) → bool`.

The sequence is:

1. **Kernel bypass.** PID 0 always returns `true`.
2. **Quarantine restore.** `restore_quarantined_capabilities(pid)` opportunistically
   restores any capability whose `restore_at_tick ≤ now`.
3. **Intent probe.** `sec.intent_capability_probe(pid, cap_type, rights_bits, object_id)`
   feeds the event into the per-process intent graph window.
4. **Predictive restriction gate.** `sec.is_predictively_restricted(pid, cap_type, rights_bits)`:
   if true, calls `predictive_revoke_capabilities(pid, cap_type, rights_bits, restore_at)`,
   logs `CapabilityRevoked` + `PermissionDenied`, and returns `false`.
5. **Rate limiting.** `sec.validate_capability(pid, rights_bits, rights_bits)`. Returns
   `false` on error.
6. **Local table scan.** Iterates `CapabilityTable::entries` for the process:
   - `verify_capability_access(owner, cap, req)` checks MAC, type, object_id, rights.
   - On success, calls `evaluate_mapped_remote_capability(pid, cap_id, ...)` which
     returns one of three decisions:
     - **`Allow`** — the local cap is backed by an active, valid owner-bound lease;
       use-budget decremented; `CapabilityUsed` logged; return `true`.
     - **`Deny`** — lease found but expired, revoked, or rights insufficient;
       `InvalidCapability` logged; skip to next entry.
     - **`NotMapped`** — no matching lease; local cap is self-sufficient;
       `CapabilityUsed` logged; return `true`.
   - On `InvalidCapability` error from `verify_capability_access`, logs
     `InvalidCapability` event.
7. **Owner-any fallback.** `check_remote_capability_access(pid, object_id, cap_type, rights)`
   scans leases where `mapped_cap_id == 0` and `owner_any == true` (or `owner_pid == pid`).
   Enforces time bounds and use budgets; logs `CapabilityUsed` on success.
8. **Denial.** `intent_capability_denied` + `PermissionDenied` logged; return `false`.

This means capability enforcement is not just a table lookup. It is:

- MAC integrity-checked (SipHash-2-4)
- rights-checked (bitwise subset)
- object/type-checked
- time-aware (not_before / expires_at)
- use-budget-aware (uses_remaining)
- predictive-restriction-aware
- remote-lease-aware (two distinct code paths)
- fully audited at every decision point

### 7.1 Quarantine subsystem

Predictive revocation does not permanently remove capabilities. Instead, matching
capabilities are moved into the quarantine array:

```rust
struct QuarantinedCapability {
    owner_pid:       ProcessId,
    cap:             OreuliusCapability,
    restore_at_tick: u64,             // earliest PIT tick for restoration
}
// MAX_QUARANTINED_CAPS = 256
```

Restore is attempted on every `check_capability` call for that PID (step 2 above).
The kernel enforces `restore_at_tick >= now + Hz` (minimum 1 second) to prevent
immediate oscillation. `force_restore_quarantined_capabilities(pid)` bypasses the
timer (used by operator recovery commands). Remote leases are revoked (not
quarantined) under the predictive path.

---

## 8. Auditing and observability

Capability operations are tracked through the security audit path
(`security::AuditEntry` + `SecurityEvent`).

Current audited `SecurityEvent` variants:

| Event | Trigger |
|---|---|
| `CapabilityCreated` | `grant_capability`, `install_remote_lease` |
| `CapabilityTransferred` | `transfer_capability` |
| `CapabilityUsed` | Successful local or remote-lease check |
| `InvalidCapability` | MAC failure, type mismatch during scan |
| `CapabilityRevoked` | `revoke_capability`, teardown, predictive revoke, quarantine drain |
| `PermissionDenied` | Final denial in `check_capability` |

In addition, `grant_capability` and `revoke_capability` fire an observer
notification on non-aarch64 builds:

```rust
// 8-byte payload on CAPABILITY_OP observer channel:
[pid: 4B LE][cap_type: 1B][action: 1B][0: 2B]
// action: 0 = grant, 1 = revoke
observer_notify(observer_events::CAPABILITY_OP, &payload);
```

This allows WASM observer modules subscribed to `CAPABILITY_OP` to react to
capability lifecycle events in real time.

Useful shell surfaces for inspection include:

- `cap-list` — list capabilities for a PID
- `cap-test-atten` — test attenuation enforcement
- `cap-arch` — dump capability architecture
- `capnet-lease-list` — list active remote leases
- `capnet-demo` — CapNet token demo
- `formal-verify` — run `formal_capability_self_check()` and graph checks

Oreulius also records provenance metadata such as origin PID, grant tick, and
delegation ancestry, making capability debugging materially easier than in
ambient-authority systems.

---

## 9. Temporal integration

Capabilities are integrated with the temporal subsystem.

When replay is not active, grant/revoke operations emit temporal capability
events. On replay or restore, `temporal_apply_capability_event()` rebuilds the
capability state by reapplying:

- grant events
- revoke events

This keeps capability authority aligned with temporal rollback instead of
silently drifting away from historical object state.

Temporal capability work is also extended elsewhere in the tree by:

- temporal capability checkpoints
- temporal capability grant/revoke syscalls
- redaction-aware temporal restore paths

This document only covers the core capability manager integration.

---

## 10. Policy and predictive extensions

Oreulius's capability model is no longer "rights only."

Two important extensions sit on top of the base model:

- **Policy contracts**: small bytecode policies bound to capabilities and
  evaluated by the kernel
- **Predictive revocation / quarantine**: the security manager can temporarily
  revoke or quarantine capabilities when the intent graph predicts abuse

Those mechanisms are real parts of the current enforcement design, but they are
documented in their dedicated papers:

- `docs/capability/oreulius-policy-contracts.md`
- `docs/capability/oreulius-intent-graph-predictive-revocation.md`

---

## 11. What this document does not claim

This document deliberately does not claim:

- POSIX-style ambient file or socket authority
- unconstrained capability minting by unprivileged code
- arbitrary rights amplification through delegation
- unlimited or permanent remote leases
- a complete substitute for the more detailed CapNet mesh specification

For wire formats, peer sessions, token identity, replay windows, and CapNet
transport semantics, see `docs/capability/oreulius-kernel-mesh.md`.
