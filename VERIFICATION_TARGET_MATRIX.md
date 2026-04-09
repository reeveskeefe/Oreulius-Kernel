# Oreulius Verification Target Matrix And Proof Plan

Status: Active planning document

This document defines the full verification target map for Oreulius, the staged proof plan, and the conditions under which the project may honestly claim:

- fully verified verification artifacts
- fully verified code
- fully verified entire system behavior

It is intentionally stricter than a theorem inventory. Its purpose is to define what must be true before broad verification claims are defensible.

---

## 1. Executive Position

Kernels are difficult to verify because they are large, stateful, concurrent, architecture-dependent systems with behavior spread across Rust, assembly, boot code, MMU state, interrupt entry, runtime dispatch, and external tooling.

The most important lesson from past high-assurance kernels is not merely that verification is possible, but that scope discipline matters. Small kernels with narrow interfaces and tightly bounded behavior are more tractable to line-by-line proof than broad, unified kernels with richer runtime surfaces.

Oreulius is not pursuing verification by shrinking the kernel into an artificially tiny artifact. Oreulius is pursuing verification by shrinking the proof boundary to the semantic control points that actually enforce authority, isolation, privilege, replay, and correctness.

That is the core design decision.

Instead of minimizing code indiscriminately, Oreulius treats verification as a targeted, compositional program:

- identify the semantic choke points that control authority and correctness
- formally specify the invariants that must hold at those choke points
- prove that any execution crossing those boundaries preserves the invariants
- explicitly model the rest of the system as environment, trusted base, or deferred target

For Oreulius, the relevant choke points include:

- capability operations
- ABI entry points
- syscall dispatch
- host-call dispatch
- trap and privilege transitions
- page-mapping and execution-permission transitions
- temporal snapshot, rollback, and merge operations
- capability-mediated IPC and service dispatch
- persistence encode, decode, and recovery boundaries

This is especially suitable for a capability kernel that is broad, replayable, and temporal. A capability kernel naturally centralizes authority transitions. A temporal kernel naturally centralizes history and replay semantics. Those are exactly the kinds of surfaces a verifier can target effectively.

---

## 2. Verification Philosophy

Oreulius does not treat verification as:

- "the proofs compile"
- "the docs look aligned"
- "the code resembles the model"

Oreulius treats verification as the stronger claim:

\[
Assumptions \implies \text{the running system cannot violate the stated properties}
\]

for a clearly bounded configuration.

That means full verification requires proving both:

- each layer individually
- the composition of those layers together

If a single behavior-changing layer is omitted, the whole-system claim is overstated.

---


## 3. The Seven Major Verification Targets

### 3.1 Verify the specification itself

Before code can be proved, the specification must be complete, meaningful, and non-contradictory.

This requires:

- invariants that do not conflict
- a well-formed state model
- transition rules that are total or explicitly partial
- precisely stated security properties
- an explicit threat model
- an explicit assumption model

For Oreulius, specification completeness includes:

- capability provenance
- no rights escalation
- no ambient authority
- privilege transition rules
- temporal monotonicity
- replay safety
- memory isolation
- `W^X`
- control-flow integrity
- IPC safety
- network delegation safety
- persistence recovery semantics
- scheduler semantics
- interrupt ordering
- process lifecycle semantics
- ABI semantics for host functions

If the spec is incomplete, the proofs can be mechanically correct and still fail to prove the intended system claim.

### 3.2 Verify the proof artifacts

This is the repository governance layer.

Full artifact verification requires:

- every proof artifact compiles
- every theorem record corresponds to a real mechanized proof
- every proof dependency is explicit
- no orphan proof claims exist in docs
- no theorem status overstates what is actually proven
- proof outputs are reproducible
- artifact hashes are stable
- commit bindings are stable
- assumptions are versioned and traceable
- mapping documents are checked, not aspirational

This is the minimum standard for the claim:

\[
\text{ArtifactClaim} \equiv \text{CompleteInventory} \land \text{ReproducibleArtifacts} \land \text{TraceableClaims}
\]

### 3.3 Verify the formal models for each subsystem

This is the subsystem-theory layer.

For Oreulius, the target set includes at least:

- security and capability core
- memory and isolation core
- privilege, syscall, and trap core
- execution core
- temporal core
- IPC, registry, and service core
- persistence core
- networking and CapNet core
- scheduling and concurrency core
- filesystem and VFS core
- device and architecture core, where included in claim scope

### 3.4 Verify correspondence from model to real code

This is the refinement layer.

For each verified subsystem:

- Rust state must map to formal state
- each implementation transition must map to a legal model transition
- outputs must match the modeled behavior
- error paths must match the model
- concurrency behavior must match the model or its assumptions
- assembly stubs must preserve required invariants

Without this layer, the project has model proofs, not implementation proofs.

### 3.5 Verify architecture-specific low-level code

Any honest "entire system" claim includes:

- boot paths
- context switch assembly
- syscall entry stubs
- interrupt entry stubs
- MMU manipulation
- TLB semantics
- exception vectors
- privilege return instructions

At minimum, the project must explicitly classify this layer as either:

- verified
- trusted but audited
- trusted and unverified

### 3.6 Verify the toolchain and trusted computing base

Even verified source code does not automatically imply a verified binary.

The trusted base includes:

- proof assistant kernel
- compiler
- assembler
- linker
- build scripts
- image packaging
- CPU semantics assumptions
- QEMU fidelity assumptions when QEMU is part of the evidence story

An honest top-level statement therefore has the form:

\[
\text{VerifiedSystem} \text{ relative to } TCB \land HW\_Assumptions \land Model\_Assumptions
\]

### 3.7 Verify composition across subsystems

Subsystem proofs do not automatically compose.

Composition targets include:

- capability + IPC
- capability + networking
- capability + temporal rollback
- JIT + `W^X` + CFI + privilege boundaries
- persistence + recovery + temporal restore
- scheduler + locks + interrupt ordering
- ABI dispatch + memory safety + capability enforcement
- process lifecycle + revocation + cleanup
- `mmap` + VFS + page faults + writeback

This is the difference between:

- all pieces proved
- and the system proved

---

## 4. Claim Tiers

Oreulius should use staged verification claims, not one oversized slogan.

### Stage 1: Fully verified verification artifacts

Requirements:

- theorem inventory complete
- assumption inventory complete
- traceability complete
- artifact generation reproducible
- CI checks complete
- no uncited proof claims in docs
- every theorem tied to a compiled artifact
- every artifact tied to exact commit and toolchain
- proof status language conservative and accurate

### Stage 2: Fully verified capability and privilege core

Requirements:

- capability model verified
- no-forgery and no-escalation properties verified
- privilege transition model verified
- syscall gate exclusivity verified
- implementation-to-model mapping completed for those surfaces

### Stage 3: Fully verified memory and JIT safety core

Requirements:

- memory isolation
- page-permission invariants
- `W^X`
- CFI
- JIT emission safety
- implementation refinement for the covered execution surfaces

### Stage 4: Fully verified temporal and persistence core

Requirements:

- snapshot correctness
- rollback correctness
- merge semantics
- persistence roundtrip
- recovery correctness
- restore correctness

### Stage 5: Fully verified composed trusted core

Requirements:

- composition proofs across the trusted core subsystems
- explicit exclusion of non-verified modules
- explicit architecture and configuration scope

### Stage 6: Fully verified whole-system profile

Requirements:

- one exact architecture
- one exact configuration
- one explicit trusted base
- one explicit hardware or QEMU scope
- no excluded subsystem hidden inside the claim

For example:

- `x86_64`
- QEMU-backed execution model
- no GPU/compositor claims
- no WiFi claims
- no excluded drivers within scope

This is the level at which "entire system" becomes defensible.

---

## 7. Oreulius Target Programs

This section converts the high-level ladder into named Oreulius verification programs.

### Program A: Artifact integrity and proof governance

Targets:

- theorem index completeness
- manifest completeness
- assumption completeness
- traceability completeness
- reproducibility of proof outputs
- status and claim consistency across repo

### Program B: Capability and authority verification

Targets:

- provenance
- no forgery
- no escalation
- revoke correctness
- transfer correctness
- delegation DAG acyclicity
- entanglement correctness
- policy contract correctness
- temporal capability correctness
- observer correctness

### Program C: Memory and privilege safety

Targets:

- allocator safety
- page-table safety
- process isolation
- sandbox isolation
- no user-to-kernel memory violation
- syscall gate exclusivity
- trap and return correctness
- `W^X`
- CFI
- JIT sealing correctness

### Program D: Execution semantics

Targets:

- interpreter correctness
- JIT refinement to interpreter
- ABI dispatcher correctness
- service pointer typing correctness
- WASI surface correctness
- host ABI correctness for the claimed host function set

### Program E: Temporal and persistence correctness

Targets:

- snapshot correctness
- rollback correctness
- branch correctness
- merge correctness
- monotonicity
- persistence roundtrip
- crash recovery correctness
- schema evolution safety
- restore correctness

### Program F: IPC, services, and registry correctness

Targets:

- channel semantics
- send/receive correctness
- capability passing correctness
- registry consistency
- service discovery correctness
- cross-process invocation correctness

### Program G: Network, CapNet, and mesh correctness

Targets:

- token mint correctness
- routing correctness
- replay resistance
- lease expiry
- revocation visibility
- migration correctness
- peer identity and session assumptions
- control-plane invariants

### Program H: Scheduler, concurrency, and locks

Targets:

- scheduler state machine
- process lifecycle state machine
- wake and block semantics
- lock DAG properties
- wait-free ring guarantees, if claimed
- interrupt scheduling interaction
- starvation or fairness properties, if claimed
- AArch64 timer tick / reschedule-pending boundary

### Program I: VFS, `mmap`, and storage semantics

Targets:

- VFS correctness
- FD correctness
- `mmap` correctness
- page-fault fill correctness
- writeback correctness
- mount semantics
- path resolution safety

### Program J: Boot, architecture, and assembly

Targets:

- i686 boot and runtime
- x86_64 Multiboot2 path
- AArch64 raw image and DTB path
- AArch64 timer tick / reschedule-pending boundary
- AArch64 syscall boundary stubs
- AArch64 context-switch handoff
- interrupt stubs
- context switching
- MMU backends
- TLB flush and load correctness
- architecture-specific privilege semantics

These AArch64 Program J boundaries are the ones tracked as **T5** in the
verification proof matrix. The residual raw-image / firmware edge remains a
named TCB assumption under `ASM-HW-001`.

### Program K: Toolchain and TCB accounting

Targets:

- proof assistant trust statement
- compiler trust statement
- assembler and linker trust statement
- build reproducibility statement
- QEMU vs hardware scope statement
- hardware assumption statement

### Program L: Composition

Targets:

- B + C
- C + D
- D + E
- B + F
- B + G
- E + I
- H + all stateful cores
- J + C + D

---

## 8. Subsystem Proof Target Matrix

### 8.1 Security and authority core

Required proof targets:

- capability table correctness
- grant semantics
- derive semantics
- revoke semantics
- transfer semantics
- no capability forgery
- no rights escalation
- delegation DAG acyclicity
- revocation propagation correctness
- capability liveness and inactive semantics
- temporal capability semantics
- policy binding and evaluation semantics
- entanglement semantics
- observer and event semantics for authority changes

### 8.2 Memory and isolation core

Required proof targets:

- allocator region safety
- page table correctness model
- process address-space separation
- sandboxed WASM memory confinement
- no user access to kernel-only memory
- mapping and unmapping correctness
- copy-on-write correctness, if claimed
- memory protection transition correctness
- `W^X` invariants
- executable page sealing correctness

### 8.3 Privilege, entry, and trap core

Required proof targets:

- syscall gate exclusivity
- ring transition correctness
- trap entry and exit correctness
- no unintended privilege entry paths
- interrupt and exception frame integrity
- architecture-specific privilege invariants

### 8.4 Execution core

Required proof targets:

- WASM interpreter semantics
- JIT semantic equivalence
- JIT code emission correctness
- indirect branch validity and CFI
- host-call dispatch correctness
- service pointer typing correctness
- typed invocation correctness

### 8.5 Temporal core

Required proof targets:

- snapshot creation semantics
- rollback semantics
- branch creation semantics
- merge semantics
- logical clock monotonicity
- audit trail consistency
- restore correctness
- checkpoint semantics
- temporal capability rollback semantics

### 8.6 IPC, registry, and services

Required proof targets:

- channel safety
- send and receive ordering
- capability passing correctness
- service registration correctness
- service lookup and invoke correctness
- cross-PID pointer validity
- registry consistency

### 8.7 Persistence

Required proof targets:

- write acknowledgment semantics
- crash recovery correctness
- codec roundtrip correctness
- integrity tag behavior
- schema migration semantics
- store consistency and uniqueness properties

### 7.8 Networking and CapNet

Required proof targets:

- token minting semantics
- token routing semantics
- peer identity model
- replay protection
- nonce uniqueness assumptions
- lease expiry semantics
- delegation visibility and revocation model
- migration transfer correctness
- session authenticity assumptions

### 8.9 Scheduling and concurrency

Required proof targets:

- scheduler state invariants
- no illegal process state transitions
- runnable and blocking semantics
- lock ordering or deadlock exclusions, if claimed
- wait-free ring properties, if claimed
- concurrency interference assumptions
- fairness, starvation, and boundedness, if claimed
- AArch64 timer tick / reschedule-pending boundary

### 8.10 Filesystem and VFS

Required proof targets:

- path resolution model
- file descriptor semantics
- read and write correctness
- mount-state invariants
- `mmap` contract correctness
- lazy page-fill correctness for file-backed mappings, if claimed
- writeback semantics

### 8.11 Device and architecture

Required proof targets:

- boot handoff correctness
- MMU backend semantics
- TLB invalidation semantics
- interrupt controller correctness
- serial correctness where security-critical
- virtio, block, and network driver models where included in scope

---

## 9. The Semantic Control Point Strategy

The central Oreulius verification decision is:

do not tie the verifier to physical kernel size; tie it to semantic control points.

This means the verification boundary is defined by authority-enforcing and correctness-enforcing pathways rather than by "all code equally."

Examples:

- capability grant, derive, revoke, and transfer paths
- syscall and host ABI dispatch boundaries
- privilege entry and return boundaries
- page permission and execution-permission transitions
- temporal mutation entry points
- persistence encode/decode and recovery entry points
- IPC send, receive, and capability-transfer boundaries

This strategy is novel in emphasis, even if not novel in spirit. Traditional microkernel verification reduces the kernel until the proof problem is tractable. Oreulius instead aims to preserve a broad kernel while aggressively structuring the proof boundary around auditable, enforceable choke points.

Formally, if \( C \) is the set of semantic control points, the claim is not:

\[
\forall code \in Kernel.\; Verified(code)
\]

The staged claim is closer to:

\[
\forall e \in Executions.\; Crossing(C, e) \implies PreservesInvariant(e)
\]

with the non-covered environment declared explicitly.

This does not eliminate the need for whole-system verification later. It makes early verification practical, modular, and honest.

---

## 10. Deliverables For The Alpha Verification Program

Before alpha release, Oreulius should target:

1. complete artifact governance and traceability
2. verified capability and privilege core
3. verified memory and JIT safety core
4. verified temporal and persistence core
5. explicit TCB and architecture scope statement
6. one named composed trusted-core profile

Recommended first defensible whole-profile candidate:

- one architecture
- one QEMU-backed configuration
- no excluded graphics or WiFi claims
- no unverified driver claims beyond the trusted-base statement

---

## 11. Summary

To say Oreulius fully verified everything, the project must prove:

- the specification
- the proof artifacts
- the formal models
- the implementation refinement
- the low-level boot, trap, MMU, and assembly boundary
- the toolchain and trusted-base assumptions
- and the composition of all subsystems together

If any one of those is missing, the project has not yet fully verified the entire system.
