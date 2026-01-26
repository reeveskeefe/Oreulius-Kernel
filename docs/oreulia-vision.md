# Oreulia — Vision & Core Architecture (Draft)

**Status:** Draft (Jan 24, 2026)

Oreulia is an experimental operating system designed to make *authority*, *time*, *state*, and *communication* explicit.

The goal is not “Unix, but again.” Oreulia is intentionally shaped around:

- **Capability-based security**: no ambient authority; access is granted explicitly.
- **Dataflow + message passing**: components communicate through typed channels, not shared global state.
- **Wasm-native execution**: applications are WebAssembly modules with a small, explicit host interface.
- **Determinism (as a product feature)**: the OS can replay and reason about executions.
- **Persistence (as the default)**: state is durable and recoverable by design, not an afterthought.

This document describes the conceptual model and an initial architecture suitable for a QEMU-first prototype.

---

## 1. Non-goals (early)

Oreulia’s early milestones prioritize proving the model over hardware breadth.

- Not targeting real hardware drivers initially (QEMU/virtio first).
- Not providing POSIX compatibility as a primary goal.
- Not implementing a full graphical desktop early.
- Not promising broad language runtimes outside Wasm initially.

---

## 2. Core principles

### 2.1 No ambient authority

In Oreulia, **nothing is globally accessible by default**.

- There is no “global filesystem,” “global network,” or “global clock” accessible by name.
- Access is obtained by **receiving a capability**.
- Names (like paths) are *views* provided by an authority-bearing component, not a universal primitive.

### 2.2 Everything is a component

The system is composed of components (services and apps) that:

- run as isolated tasks,
- communicate by message passing,
- hold capabilities in explicit tables,
- can be supervised and restarted.

### 2.3 Dataflow-first

The primary abstraction is a **message channel** between components.

- Components emit events and consume inputs.
- “System calls” are modeled as message exchanges via capabilities.
- Backpressure is a first-class concept.

### 2.4 Persistence-first

Oreulia treats durable state like a core OS concern.

- Components can opt into durable state via persistent objects/logs.
- The OS can restart and reconstruct component graphs.
- The default system story includes crash recovery.

### 2.5 Deterministic execution as an OS feature

Oreulia aims to make executions:

- reproducible (replay),
- debuggable (time travel),
- auditable (why did this happen?).

This requires controlling sources of nondeterminism (time, randomness, external I/O) behind explicit capabilities.

### 2.6 Wasm-native, not “Wasm as an app format”

Wasm is the initial application ABI:

- stable sandbox boundary,
- portable bytecode,
- structured imports/exports for capability injection,
- simple story for multi-language apps.

---

## 3. Threat model (initial)

Oreulia’s security posture assumes:

- Apps/components may be malicious or compromised.
- The kernel is trusted; everything else is *less* trusted.
- Authority must be explicit and inspectable.

Security goals:

- Prevent ambient access (no unrequested filesystem/network/clock).
- Minimize attack surface of the “syscall layer.”
- Enable confinement and least privilege.
- Make privilege escalation paths visible in capability graphs.

---

## 4. The Oreulia kernel concept

### 4.1 Kernel responsibilities

The kernel provides only what must be privileged:

- Task scheduling
- Address-space isolation (eventually user mode)
- IPC primitives (fast, bounded message passing)
- Capability enforcement (unforgeable handles)
- Time/entropy virtualization hooks (for determinism)
- Basic device mediation (QEMU/virtio first)

### 4.2 User space responsibilities

Most “OS personality” lives in user space services:

- supervisor/init
- persistent storage service
- filesystem service (capability-gated durable storage)
- namespace services (if any)
- console/log service
- module loader (Wasm)
- networking stack (later)

---

## 5. Capabilities: the authority model

### 5.1 Definition

A **capability** is an unforgeable token that grants a specific set of rights over an object.

Examples:

- `Console.Write`
- `Clock.ReadMonotonic`
- `Store.AppendLog`
- `Store.ReadSnapshot`
- `Channel.Send` / `Channel.Receive`
- `Module.Spawn`

Capabilities are not names; they’re *authority*.

### 5.2 Capability operations

Minimum operations:

- **Create**: kernel or privileged service creates capabilities.
- **Transfer**: send capabilities over channels.
- **Attenuate**: derive a capability with fewer rights.
- **Revoke** (v1 optional): invalidate capabilities based on a revocation scheme.

### 5.3 Capability graphs

Oreulia treats the system’s authority structure as a graph:

- nodes: components + objects
- edges: capability grants

This supports auditing (“who can do what?”), and also supports determinism (“what external inputs exist?”).

---

## 6. IPC and dataflow

### 6.1 Channels

A channel is a kernel-managed object with:

- bounded queue
- backpressure behavior
- ability to carry data + capability transfers

Initial messaging can be simple:

- fixed-size messages or scatter-gather
- copy-based IPC first (optimize later)

### 6.2 Dataflow conventions

Oreulia can standardize patterns:

- request/response
- publish/subscribe
- pipelines (transform stages)
- supervision signals

---

## 7. Persistence model

Oreulia’s “persistence-first” story can be built around event logs.

### 7.1 Durable primitives (initial)

- **Append-only logs**: durable sequence of events
- **Snapshots**: point-in-time state images
- **Object store** (later): durable objects keyed by capability

### 7.2 Crash recovery

Recovery is a first-class boot path:

- the supervisor reads durable state,
- reconstructs component graph,
- replays logs to restore state,
- continues.

This provides a clean alignment with determinism and auditing.

---

## 8. Determinism and time

### 8.1 Sources of nondeterminism

- wall-clock time
- entropy/randomness
- network inputs
- device timing
- scheduling decisions

### 8.2 Oreulia approach

- Expose time/randomness only via explicit capabilities.
- For replay, record “external” inputs as an event log.
- Use deterministic scheduling modes in development/testing.

A practical v1 approach:

- kernel offers a “virtual clock” service interface
- the supervisor can run in **record** or **replay** mode

---

## 9. Wasm-native execution model

### 9.1 Modules

Applications are Wasm modules that:

- import only the interfaces they need
- receive capabilities at instantiation
- communicate via channels

### 9.2 Host interface

Keep the host surface small and capability-oriented:

- `channel_send(handle, bytes, caps...)`
- `channel_recv(handle) -> (bytes, caps...)`
- `yield()` / `sleep(handle, duration)` (time via a capability)

Avoid a large POSIX-like syscall set.

### 9.3 Loader and linking

A user-space loader service:

- validates modules
- instantiates with provided capabilities
- manages module lifecycle

---

## 10. QEMU-first implementation shape

### 10.1 Recommended early target

- Boot in QEMU
- Serial console output
- Virtio block (for durable logs) — later

### 10.2 Initial milestone list

- **M0**: Boot + serial logging
- **M1**: Interrupts + timer
- **M2**: Kernel channels + scheduler
- **M3**: Capability table + transfer over channels
- **M4**: Minimal supervisor in user space (or kernel task initially)
- **M5**: Wasm loader service + run a module that prints via a console capability
- **M6**: Append-only log + record/replay harness

---

## 11. Open design questions

These are intentionally undecided early to keep iteration fast.

- **Microkernel vs monolithic**: how much stays in kernel?
- **Revocation model**: epoch-based, indirection tables, or service-mediated?
- **Message format**: typed schema (e.g., flatbuffers) vs simple bytes v1?
- **Persistence semantics**: exactly-once vs at-least-once replay?
- **Scheduling determinism**: strict determinism mode vs “best effort”?

---

## 12. Next document(s)

Suggested follow-ups:

- `docs/oreulia-mvp.md`: concrete MVP requirements for first bootable QEMU release
- `docs/oreulia-capabilities.md`: capability taxonomy, attenuation, transfer, revocation
- `docs/oreulia-ipc.md`: message formats, backpressure, performance path
- `docs/oreulia-persistence.md`: log/snapshot design, recovery, replay
- `docs/oreulia-wasm-abi.md`: host interface, imports/exports, safety constraints
