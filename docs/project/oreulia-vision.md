# Oreulius — Vision and Current Direction

**Status:** Active research kernel / alpha system.

Oreulius is a **capability-native, WASM-first kernel** built around explicit authority, temporal state, auditable delegation, and a small but real multi-architecture runtime surface. It is not trying to be a Linux-compatible general-purpose OS. It is trying to be a defensible execution substrate for isolated WebAssembly workloads, capability-mediated services, and deterministic or replay-oriented systems work.

---

## 1. What Oreulius is trying to be

Oreulius is shaped around five durable ideas:

- **No ambient authority:** access to files, channels, services, and higher-level control surfaces is granted explicitly through capabilities.
- **WASM-first execution:** WebAssembly is the intended application ABI, with both interpreted and JIT-backed execution paths.
- **Temporal state as a kernel concern:** rollback, branching, merge, and state history are not bolt-ons; they are part of the system model.
- **Capability-mediated composition:** IPC, service discovery, service pointers, CapNet delegation, observers, and policy controls all build on the same authority model.
- **Inspectable and verifiable behavior:** shell-driven regression commands, fuzzing hooks, formal checks, and live diagnostics are treated as first-class engineering surfaces.

The project is intentionally opinionated: Oreulius favors explicit authority, bounded queues, replayability, and auditability over POSIX compatibility or broad legacy application support.

---

## 2. What Oreulius currently is

Oreulius is no longer just a paper design or a boot-to-prompt experiment.

Current project reality:

- real bring-up paths exist for `i686`, `x86_64`, and `AArch64`
- `i686` remains the most feature-complete path
- `x86_64` and `AArch64` have real QEMU bring-up, shell, network, and runtime surfaces, but feature parity remains uneven
- the kernel already includes:
  - capability management and delegation tracking
  - IPC channels and service introduction
  - temporal state operations
  - persistence and snapshot machinery
  - a WebAssembly runtime with typed service pointers and JIT support
  - in-kernel networking and CapNet control-plane machinery
  - shell-visible formal, fuzz, and regression tooling

That matters because the project vision should now be read as a direction built on top of a real kernel, not as a speculative wishlist.

---

## 3. Architectural stance

Oreulius is best described as a **capability-native hybrid kernel** with a strong dataflow and service orientation.

### 3.1 Kernel-resident responsibilities

The kernel currently owns the privileged substrate:

- scheduling and process/runtime coordination
- capability enforcement
- IPC channels and channel policy
- temporal and persistence integration
- core filesystem and network paths
- WebAssembly execution and host ABI dispatch
- service registration/introduction surfaces

This is not a “minimal microkernel with everything in userspace” design anymore. Several performance-sensitive or semantics-heavy components already live in kernel space by design.

### 3.2 Capability-mediated service model

Oreulius does not treat service access as ambient namespace access. Instead, it is moving toward a model where:

- services are registered explicitly
- introductions are capability-mediated
- service pointers can be invoked directly
- higher-order policy, audit, and revocation layers sit on top of those same capability edges

This is one of the project’s clearest through-lines: the same authority model is reused across local services, message transfer, temporal policy, and network delegation.

### 3.3 Temporal model

Oreulius treats state history as operational infrastructure, not just backup machinery.

Current temporal direction includes:

- versioned objects
- snapshot and history queries
- rollback
- branching
- merge

The implementation is real, but replay completeness is still partial in some subsystems. The project vision remains larger than the current replay fidelity.

---

## 4. What Oreulius is not

Oreulius is not:

- a POSIX- or Linux-compatible operating system
- a native application compatibility layer
- a drop-in container host
- a completed production-hardened appliance OS
- a broadly validated physical-hardware platform

Oreulius is also not yet a desktop-first end-user OS today. A desktop direction
is valid, but only as a staged program with explicit milestones and acceptance
criteria, not as a marketing relabel.

The project intentionally does **not** optimize around libc compatibility, `/proc`, ambient file/path semantics, or conventional Unix process personality.

## 4.1 Desktop track (explicit program)

To avoid identity drift, desktop capability is tracked as a separate execution
program with clear phases:

- Phase D0 (now): compositor and framebuffer paths are wired and testable; shell remains the default control surface.
- Phase D1: single-session window demo with deterministic present, focus, and input routing on x86_64 QEMU.
- Phase D2: capability-scoped multi-window session model and stable app-facing IPC contract.
- Phase D3: desktop shell/session manager and daily-usable interaction loop.

This keeps credibility: the project can pursue a GUI future without pretending
it is already a finished desktop product.

---

## 5. Security and trust model

Oreulius assumes:

- workloads may be buggy or hostile
- kernel logic is part of the trusted computing base
- authority should be explicit, attenuable, and auditable
- policy should be enforceable inline, not only after the fact

This shows up in several concrete areas:

- capability checks on privileged operations
- delegation tracking and graph-style lineage
- typed and capability-gated service invocation
- predictive or policy-linked restriction work
- observer and diagnostics surfaces for runtime inspection

What it does **not** mean is that the kernel is already fully verified or fully free of implementation risk. The project has meaningful hardening and proof work, but the right public claim is “security-oriented and auditable,” not “formally complete.”

---

## 6. Portability and execution model

Oreulius is now a multi-architecture kernel project, but not a parity-complete one.

### Current runtime posture

- `i686`: deepest path, richest runtime surface
- `x86_64`: real Multiboot2 bring-up with working shell and current network regression lane
- `AArch64`: real QEMU `virt` bring-up with current network regression lane and virtio-mmio runtime surfaces

### Current execution posture

Oreulius is WASM-first, not WASM-only in an ideological sense, but the project is built around WebAssembly as the primary workload ABI:

- host imports are explicit
- service pointers and IPC integrate with the runtime
- JIT support exists but is still architecture-uneven
- the runtime has become a major kernel subsystem rather than a side experiment

---

## 7. Current strategic value of the project

Oreulius is most compelling today as:

- a research vehicle for capability systems and explicit authority flow
- a platform for temporal/persistent state experiments
- a testbed for auditable in-kernel service composition
- a WASM-native edge/runtime kernel prototype
- a basis for future attested or replay-oriented service platforms

Its real strength is the combination of:

- capability-native design
- temporal semantics
- WebAssembly execution
- network-capability delegation
- shell-visible verification and regression infrastructure

That combination is still unusual, and it is the real reason the project is worth continuing.

---

## 8. Current gaps that matter to the vision

The vision is larger than the current implementation in a few important places.

Still uneven or not yet finished:

- architecture parity, especially outside `i686`
- replay completeness across all subsystems
- zero-sum capability transfer in every path
- broader production hardening and hardware validation
- fully normalized higher-level service docs and SDK surfaces
- broader operational tooling beyond the current QEMU-first workflow set

These are not side issues. They are the main work required to move Oreulius from “strong research kernel with real subsystems” toward a more deployable platform.

---

## 9. Project direction

The right near-term direction for Oreulius is not “become Linux.” It is:

- deepen the capability and temporal semantics already present
- tighten docs so they match the implementation exactly
- preserve and expand regression coverage
- continue bringing non-`i686` runtimes closer to parity
- keep the public claims narrower and more defensible than the internal ambition

That discipline matters. Oreulius becomes more credible when its docs describe the real kernel that exists today while still pointing clearly at the longer-range model it is trying to reach.
