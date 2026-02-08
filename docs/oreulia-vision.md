# Oreulia — Vision & Core Architecture

**Status:** Prototype / Alpha (Feb 8, 2026)

Oreulia is an experimental operating system that combines the **capability-based security** of microkernels with the **performance and pragmatism** of a modern hybrid kernel.

The goal is to provide a secure, Wasm-native environment without sacrificing the essential features expected of a real operating system (Networking, Filesystems, Performance).

Oreulia is intentionally shaped around:

- **Capability-based security**: No ambient authority; access is granted explicitly through handles.
- **Hybrid-Kernel Architecture**: Critical paths (Networking, VFS, JIT) are in-kernel for performance; policies are capability-gated.
- **Wasm-native execution**: Applications are WebAssembly modules compiled to native code via an in-kernel JIT.
- **Dataflow + message passing**: Components communicate through typed channels.
- **Determinism & Persistence**: Built-in mechanisms for state durability and replayability.

---

## 1. Evolution from Initial Vision

Oreulia started as a minimal research microkernel but has evolved into a practical hybrid system.

- **Networking**: Originally planned as a user-space experiment, Oreulia now features a comprehensive **in-kernel TCP/IP stack** (Ethernet, ARP, IP, UDP, TCP, DNS, DHCP) and high-performance drivers (e1000, rtl8139, virtio-net) to support real-world connectivity.
- **Filesystem**: Originally envisioned as a flat object store, Oreulia now implements a **Unix-like Virtual File System (VFS)** with inodes, directory hierarchies, and mount points, backend by virtual block devices.
- **Execution**: Moved from a simple Wasm interpreter to a **High-Performance JIT Compiler**, converting Wasm bytecode to native x86 machine code at runtime for near-native performance.

---

## 2. Core Principles

### 2.1 No Ambient Authority

In Oreulia, **nothing is globally accessible by default**.

- There is no "global filesystem" or "global network" accessible by arbitrary names to user apps.
- Access is obtained by **receiving a capability**.
- Even though the kernel implements a global VFS, a process only sees the sub-tree exposed to its root capability.

### 2.2 Hybrid Performance, Microkernel Safety

The system adopts a hybrid approach:

- **Kernel Space**: Handles hardware abstraction, protocol stacks (TCP/IP), filesystem logic (VFS), and JIT compilation. This minimizes context switches for high-throughput operations.
- **User Space (Wasm)**: Applications run in sandboxed Wasm environments. They interact with kernel services purely through capability-guarded system calls (imports).

### 2.3 Dataflow-First

The primary abstraction is a **message channel** between components.

- Components emit events and consume inputs.
- "System calls" are modeled as message exchanges or direct capability invocations.
- Backpressure is a first-class concept.

### 2.4 Persistence-First

Oreulia treats durable state like a core OS concern.

- Components can opt into durable state via persistent objects/logs.
- The default system story includes crash recovery and snapshotting.

### 2.5 Deterministic Execution

Oreulia aims to make executions:

- Reproducible (replay inputs).
- Debuggable (time travel).
- Auditable (provenance tracking).

### 2.6 Wasm-Native with JIT

Wasm is the application ABI, but it is not interpreted slowly.
- **In-Kernel JIT**: Converts Wasm to x86 machine code.
- **Sandboxing**: Memory safety is enforced by Wasm limits and bounds checking.
- **Interface**: A clearly defined ABI (`oreulia-wasm-abi.md`) maps Wasm imports to kernel capabilities.

---

## 3. Threat Model

Oreulia’s security posture assumes:

- **Untrusted Apps**: Applications are potentially malicious or buggy and are strictly confined by the Wasm sandbox.
- **Trusted Kernel**: The kernel (Rust + Assembly) is the TCB (Trusted Computing Base). It enforces capability logic.
- **Explicit Authority**: No component can access a resource (file, network socket, service) without a valid capability handle.

Security goals:

- **Isolation**: Crash in one app cannot bring down the kernel or other apps.
- **Least Privilege**: Apps start with zero capabilities and are granted only what they need.
- **Auditability**: Capability grants and flows can be logged and visualized.


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
