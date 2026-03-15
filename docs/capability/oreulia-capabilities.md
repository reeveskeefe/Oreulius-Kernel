# Oreulia — Capabilities (Authority Model)

**Status:** Implemented / Core (Feb 8, 2026)

This document specifies Oreulia’s capability model: what a capability is, how it is represented, how it is transferred, and how rights are enforced.

Oreulia’s core rule: **no ambient authority**. If you can do a thing, you hold a capability that grants that authority.

---

## 1. Definitions

### 1.1 Capability

A capability is an **unforgeable reference** to an object plus an associated **rights set**.

- **Unforgeable**: Tasks cannot invent capabilities; they must be granted.
- **Transferable**: Capabilities can be sent over IPC channels.
- **Attenuatable**: Capabilities can be reduced to fewer rights (e.g., Read+Write -> Read-Only).

### 1.2 Object

An object is a kernel-managed resource (or a service-mediated resource) addressed by a kernel handle.

Examples:
- `Channel`
- `FileDescriptor`
- `Process`
- `ServiceRegistry`

---

## 2. Representation

### 2.1 Handle Type

Capabilities are represented components as:

- `Handle`: A simple integer (index into a per-process capability table).
- **Kernel Table**: The kernel maintains a secure table mapping `(ProcessID, Handle) -> (KernelObjectRef, Rights)`.

This ensures that a process cannot simply "guess" a pointer or ID to access an object it doesn't own.

### 2.2 Unforgeability

A task may only obtain a `Handle` by:

- **Inheritance**: Being created with it (inherited from parent/supervisor).
- **IPC Transfer**: Receiving it in a message from another process.

No syscall accepts raw `object_id` or pointer values.

---

## 3. Core Operations

### 3.1 Create

Creation is privileged or capability-derived.
- Calling `ipc_create()` creates a new Channel and returns two handles (one for each end).
- Calling `fs_open()` uses a Directory capability to create/access a File capability.

### 3.2 Transfer

Capabilities are transferred via channel messages:

- A message header includes a list of `Handle` indices to send.
- The kernel **moves** or **copies** the underlying capability reference to the receiver's table.
- The receiver gets new, valid `Handle` indices.

### 3.3 Attenuation

A process can create a "weaker" handle from a strong one before sending it.
- **Example**: Creating a Read-Only file handle from a Read-Write handle before passing it to an untrusted plugin.


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

See also: `docs/project/oreulia-mvp.md` → “Risks & mitigations” for MVP testing priorities around capability correctness.
