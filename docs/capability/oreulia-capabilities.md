# Oreulia - Capabilities (Authority Model)

**Status:** Implemented / Core (updated for current main)

This document describes Oreulia's current capability model: how authority is
represented, how it moves between tasks and peers, how it is revoked, and how
the kernel enforces it.

Oreulia's core rule remains simple:

**No ambient authority.** If code can perform an operation, that authority must
arrive through a capability or a validated remote lease.

Related documents:

- `docs/capability/oreulia-policy-contracts.md` - conditional capability use
- `docs/capability/oreulia-kernel-mesh.md` - CapNet token transport and mesh ABI
- `docs/capability/oreulia-intent-graph-predictive-revocation.md` - predictive restrictions

---

## 1. Current model at a glance

Oreulia now has two authority carriers:

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
Oreulia is not just looked up, it is also signed, audited, replay-aware, and
optionally revocable through temporal and predictive mechanisms.

---

## 2. Local capability representation

The kernel's local authority primitive is `OreuliaCapability` in
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

The token payload includes:

- owner PID
- `cap_id`
- `object_id`
- `cap_type`
- rights bits
- origin PID
- grant tick
- label hash

Changing the owner, rights, or object without re-signing invalidates the token.

### 2.2 Table limits

The current implementation uses:

- `MAX_CAPABILITIES = 256` local capabilities per task
- `MAX_REMOTE_LEASES = 128` active remote leases
- `MAX_QUARANTINED_CAPS = 256` quarantined capability slots

These are implementation limits, not architectural guarantees.

---

## 3. Capability taxonomy and rights

The current core capability taxonomy is:

| Capability type | Purpose | Current rights |
|---|---|---|
| `Channel` | IPC channel authority | `Send`, `Receive`, `CloneSender`, `Create` |
| `Task` | Task/process control | `Signal`, `Join` |
| `Spawner` | Controlled process/module creation | `Spawn` |
| `Console` | Console I/O authority | `Write`, `Read` |
| `Clock` | Monotonic time access | `ReadMonotonic` |
| `Store` | Persistence / snapshot log access | `AppendLog`, `ReadLog`, `WriteSnapshot`, `ReadSnapshot` |
| `Filesystem` | Filesystem object access | `Read`, `Write`, `Delete`, `List` |
| `ServicePointer` | Service endpoint invocation/delegation | `Invoke`, `Delegate`, `Introspect` |
| `CrossLanguage` | Polyglot service-link capability | currently issued with `Invoke` semantics |

Notes:

- `CrossLanguage` is a first-class capability type in the core capability module.
- The VFS subsystem layers richer directory/process capabilities and quotas on
  top of this core authority model.
- CapNet tokens reuse the same capability type namespace when installing remote
  leases.

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

This is the core no-amplification invariant for local capability derivation.

### 4.4 Clone / inheritance

Task cloning copies capability table entries into the child task while
re-signing them for the child PID. This preserves slot layout while preventing
cross-owner token reuse.

### 4.5 Revocation

Revocation is no longer deferred. The current implementation supports:

- single-capability revoke by `cap_id`
- revoke-all for a PID
- revoke by `(cap_type, object_id)` match
- predictive revocation into quarantine
- remote lease revoke by CapNet `token_id`

The older "MVP: no revocation" description is obsolete.

---

## 5. Provenance and delegation graph

Oreulia tracks capability ancestry through `parent_cap_id` and the capability
graph helper in `cap_graph`.

This graph is used to:

- record delegation edges
- reject invalid delegation patterns
- preserve auditable ancestry during transfer/attenuation

The current security model therefore treats delegation as a first-class,
observable event rather than a silent table copy.

---

## 6. Remote capability leases (CapNet integration)

Oreulia does not limit authority transfer to local IPC. Validated CapNet tokens
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

The current enforcement hot path is `check_capability()`.

The sequence is:

1. Kernel PID 0 bypasses checks.
2. Expired quarantined capabilities may be restored.
3. The security manager records an intent probe.
4. Predictive restriction may revoke matching capabilities before access.
5. Rate limiting / validation is applied.
6. Local table entries are scanned and token-verified.
7. If a local entry is a mapped remote lease, the lease constraints are checked.
8. If no local entry succeeds, owner-any remote leases are checked.
9. Successes and failures are audited.

This means capability enforcement is not just a table lookup. It is:

- integrity-checked
- rights-checked
- object/type-checked
- time-aware
- predictive-restriction-aware
- remote-lease-aware
- fully audited

---

## 8. Auditing and observability

Capability operations are tracked through the security audit path.

Current audited events include:

- capability creation
- transfer
- use
- invalid capability presentation
- revocation
- permission denial

Useful shell surfaces for inspection include:

- `cap-list`
- `cap-test-atten`
- `cap-arch`
- `capnet-lease-list`
- `capnet-demo`
- `formal-verify`

Oreulia also records provenance metadata such as origin PID, grant tick, and
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

Oreulia's capability model is no longer "rights only."

Two important extensions sit on top of the base model:

- **Policy contracts**: small bytecode policies bound to capabilities and
  evaluated by the kernel
- **Predictive revocation / quarantine**: the security manager can temporarily
  revoke or quarantine capabilities when the intent graph predicts abuse

Those mechanisms are real parts of the current enforcement design, but they are
documented in their dedicated papers:

- `docs/capability/oreulia-policy-contracts.md`
- `docs/capability/oreulia-intent-graph-predictive-revocation.md`

---

## 11. What this document does not claim

This document deliberately does not claim:

- POSIX-style ambient file or socket authority
- unconstrained capability minting by unprivileged code
- arbitrary rights amplification through delegation
- unlimited or permanent remote leases
- a complete substitute for the more detailed CapNet mesh specification

For wire formats, peer sessions, token identity, replay windows, and CapNet
transport semantics, see `docs/capability/oreulia-kernel-mesh.md`.
