# Oreulius — Vision and Current Direction

**Status:** Active research kernel / alpha system.

Oreulius is a capability-based, WASM-first kernel built around explicit authority, temporal state, auditable delegation, and a multi-architecture runtime surface.

---

## 1. What Oreulius is trying to be

Oreulius is shaped around five ideas:

- access to files, channels, services, and higher-level control surfaces is granted explicitly through capabilities
- WebAssembly is the intended application ABI, with both interpreted and JIT-backed execution paths
- rollback, branching, merge, and state history are part of the system model
- IPC, service discovery, service pointers, CapNet delegation, observers, and policy controls build on the same authority model
- shell-driven regression commands, fuzzing hooks, formal checks, and live diagnostics are part of the engineering surface

The project favors explicit authority, bounded queues, replayability, and auditability over POSIX compatibility or broad legacy application support.

---

## 2. What Oreulius currently is

Oreulius is no longer just a paper design or a boot-to-prompt experiment.

Current state of Oreulius:
- the kernel already includes:
  - capability management and delegation tracking
  - IPC channels and service introduction
  - temporal state operations
  - persistence and snapshot machinery
  - a WebAssembly runtime with typed service pointers and JIT support
  - in-kernel networking and CapNet control-plane machinery
  - shell-visible formal, fuzz, and regression tooling



---

## 3. Architectural stance

Oreulius is best described as a capability-based hybrid kernel with a dataflow and service orientation.

### 3.1 Kernel-resident responsibilities

The kernel currently owns the privileged substrate:

- scheduling and process, runtime coordination
- capability enforcement
- IPC channels and channel policy
- temporal and persistence integration
- core filesystem and network paths
- WebAssembly execution and host ABI dispatch
- service registration/introduction surfaces


### 3.2 Capability-mediated service model

Oreulius is a model where

- services are registered explicitly
- introductions are capability-mediated
- service pointers can be invoked directly
- higher-order policy, audit, and revocation layers sit on top of those same capability edges

The same authority model is reused across local services, message transfer, temporal policy, and network delegation.

### 3.3 Temporal model


Current temporal direction includes:

- versioned objects
- snapshot and history queries
- rollback
- branching
- merge

The implementation is real, but replay completeness is still underway!

---

## 4. What Oreulius is not

Oreulius is not:


Oreulius is also not yet a desktop-first end-user OS. A desktop direction is valid, but only as a staged program with explicit milestones and acceptance, and some pretty hard and complex design considerations and architecture styles, it itself cannot ever be a full Operating system by design without some serious work. I wouldnt even consider oreulius alone as a codebase much of a full fledged operating system, that could ever be used as a daily driver. There are many things needed from outside rust, outside a unikernel, and outside wasm-first principles, that would necessitate complete and total new from scratch components and massive seperate codebases.

For example, The project intentionally does not optimize around libc compatibility, `/proc`, ambient file/path semantics, or conventional Unix process personality. For alot to work, with most General purpose everyday tasks, youd need to stop viewing oreulius as just a kernel, but view it as a component of a much larger architecture.

The kernel is not already fully verified or fully free of implementation risk. The project has meaningful hardening and proof work, Right now id prefer to call it “security-oriented and auditable".

---

## 6. Portability and execution model


### Current execution posture

Oreulius is WASM-first, not WASM-only, but the project is built around WebAssembly as the primary workload ABI:

- host imports are explicit
- service pointers and IPC integrate with the runtime
- JIT support exists but is still architecture-uneven
- the runtime has become a major kernel subsystem rather than a side experiment

---


### 7. Its real strength is the combination of:

- capability-native design
- temporal semantics
- WebAssembly execution
- network-capability delegation
- shell-visible verification and regression infrastructure

That combination is still unusual, and it is the real reason the project is worth continuing.

---

## 8. Current gaps that matter to the vision

The vision is larger than the current implementation in a few important places.
