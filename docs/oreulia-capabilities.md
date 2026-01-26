# Oreulia — Capabilities (Authority Model)

**Status:** Draft (Jan 24, 2026)

This document specifies Oreulia’s capability model: what a capability is, how it is represented, how it is transferred, and how rights are enforced.

Oreulia’s core rule: **no ambient authority**. If you can do a thing, you hold a capability that grants that authority.

---

## 1. Definitions

### 1.1 Capability

A capability is an **unforgeable reference** to an object plus an associated **rights set**.

- Unforgeable: tasks cannot invent capabilities.
- Transferable: capabilities can be sent over IPC.
- Attenuatable: capabilities can be reduced to fewer rights.

### 1.2 Object

An object is a kernel-managed resource (or a service-mediated resource) addressed by a kernel handle.

Examples:

- channel
- console endpoint
- clock endpoint
- persistence log
- module instance

### 1.3 Rights

Rights describe what operations are permitted on an object.

Examples:

- `Send`, `Receive`, `CloneSender`
- `Write`, `Read`
- `Append`, `Snapshot`

---

## 2. Representation (v0)

### 2.1 Handle type

In v0, represent capabilities as:

- `cap_id`: a small integer local to a task (index into a per-task capability table)

The capability table entry contains:

- `object_id` (kernel-internal)
- `rights` (bitset)
- metadata (optional): auditing labels, origin, timestamps

### 2.2 Unforgeability

A task may only obtain a `cap_id` by:

- being created with it (inherited from parent/supervisor)
- receiving it through IPC (capability transfer)

No syscall accepts raw `object_id` values.

---

## 3. Core operations

### 3.1 Create

Creation is privileged; generally performed by:

- the kernel (for kernel objects like channels)
- trusted services (for service-managed resources like logs)

Creation produces a capability with an initial rights set.

### 3.2 Transfer

Capabilities are transferred via channel messages:

- a message carries bytes + a list of capability references
- on receive, the kernel installs received capabilities into the receiver’s table

Transfer is explicit:

- sender chooses which caps to attach
- receiver chooses whether to accept or drop

### 3.3 Attenuate

Attenuation derives a new capability with a subset of rights.

Rules:

- `derived.rights ⊆ original.rights`
- derived caps may be transferred independently

Attenuation primitives:

- kernel call: `cap_attenuate(cap_id, rights_mask) -> new_cap_id`

### 3.4 Duplicate

Duplication creates another reference with the same rights.

- Optional; can be modeled as `attenuate` with same rights.

---

## 4. Enforcement

Every privileged action requires a capability check.

Examples:

- to write to console, must hold `Console` object capability with `Write`
- to send on a channel, must hold `Channel` with `Send`
- to spawn a module, must hold `Spawner` with `Spawn`

The kernel enforcement rule:

- all syscalls/host calls operate on `cap_id`
- kernel resolves `cap_id` to an object and verifies rights

---

## 5. Capability taxonomy (initial)

This is a starting taxonomy; it should stay small early.

### 5.1 Kernel-level

- `Channel`
  - rights: `Send`, `Receive`
- `Task`
  - rights: `Signal`, `Join` (optional)
- `Spawner`
  - rights: `Spawn`

### 5.2 System services

- `Console`
  - rights: `Write`
- `Clock`
  - rights: `ReadMonotonic`
- `Store`
  - rights: `AppendLog`, `ReadLog`, `WriteSnapshot`, `ReadSnapshot`
- `Filesystem`
  - rights: `Read`, `Write`, `Delete`, `List` (optional)

---

## 6. Revocation (v1+)

Revocation is intentionally deferred in MVP. Design options:

1. **No revocation** (simplest): rely on lifetimes and restart.
2. **Epoch-based**: object carries epoch; capabilities carry epoch; mismatch invalid.
3. **Indirection table**: capabilities point to revocable slots.
4. **Service-mediated**: services enforce dynamic policies and can deny operations.

Recommendation:

- MVP: no revocation
- v1: service-mediated revocation for user-space resources; consider epoch for kernel objects

---

## 7. Auditing and debugging

A key benefit of capabilities is observability.

Recommended metadata (optional, but valuable):

- capability origin (who granted it)
- grant timestamp (logical time)
- label (“console-write for hello_flow”)

This supports:

- “who can write to console?” queries
- determinism analysis (“what inputs exist?”)

---

## 8. Interaction with determinism

Determinism requires that sources of nondeterminism are capability-gated.

- time only via `Clock` capability
- randomness only via `Entropy` capability (future)
- external I/O only via explicit service capabilities

In record/replay:

- the supervisor can substitute “live” capabilities with “replay” ones.

See also: `docs/oreulia-mvp.md` → “Risks & mitigations” for MVP testing priorities around capability correctness.
