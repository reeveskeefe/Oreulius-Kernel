# Oreulius Verification Target Matrix

Status: **Living Document — Alpha Roadmap**
Last updated: 2026-04-09

This document is the authoritative map of what it means to fully verify Oreulius.
It defines:

- the 5 claim tiers used across this repo
- the 12 verification programs (A–L) that together constitute whole-system verification
- the exact subsystem / property / status table for each program
- a defensible definition of the "entire system" target
- the staged milestones that lead toward it

This is not a marketing document. It is a technical obligation register.

---

## 1. Claim Tiers

Every property and every theorem in this repo is assigned exactly one tier.
No claim may be stated above its actual tier in any doc, README, or release note.

| Tier | Label | Meaning |
|------|-------|---------|
| **T0** | Not Claimed | Property exists in the system but no verification claim is made at this time. May still have runtime tests. |
| **T1** | Spec Only | Property is precisely named in `spec/INVARIANTS.md`, `spec/ASSUMPTIONS.md`, or `spec/THREAT_MODEL.md`. No mechanized proof yet. |
| **T2** | Model Proven | Mechanized Coq proof exists over an abstract model. Code-to-model correspondence is documented as an open obligation in `mapping/CODE_MODEL_TRACE.md`. |
| **T3** | Model + Trace | T2 level, plus `CO-SYNTAX-001` `// MODEL:` annotations are present in all relevant Rust source files and `CO-SEM-001` obligations are annotated. |
| **T4** | Refinement Proven | Formal refinement or simulation proof explicitly connects the real Rust implementation state to the abstract model. Model proofs compose with implementation. |
| **T5** | Full Stack | T4 level, plus architecture-specific stubs (boot, trap, MMU, context-switch) are verified or explicitly bounded as TCB assumptions, and composition with adjacent subsystems is proven. |

**Honest summary of the repo as of 2026-04-04:**
Most proven theorems are currently **T2**. Syntactic annotation (T3) is partial.
T4 and T5 are the primary open obligations for the alpha release roadmap.

---

## 2. "Entire System" Definition

The phrase "entire system verified" is only meaningful relative to an explicit scope.

The Oreulius defensible whole-system target is:

> **Oreulius x86\_64 QEMU Profile** — the kernel compiled for `x86_64-oreulia`,
> booted under `qemu-system-x86_64` with the Multiboot2 loader, running WASM
> applications via the JIT, with VirtIO block and no external network drivers,
> and with all unverified modules (GPU, WiFi, real-time subsystems) excluded
> from the claim.

Outside that profile, all claims are explicitly bounded by `ASM-MODEL-001`.

Specific exclusions from any "verified" claim unless explicitly noted:
- AArch64 architecture (separate, staged target — see Program J)
- i686 architecture (legacy; T0 for most programs)
- GPU, WiFi, DMA, IOMMU
- Unverified third-party drivers
- The Coq/Rocq proof assistant kernel itself (trusted base — see Program K)
- The Rust compiler, assembler, and linker (trusted base — see Program K)
- Microarchitectural side-channels (explicitly out of scope per `ASM-HW-001`)

---

## 3. Program A — Artifact Integrity and Proof Governance

**Goal:** Every theorem claim in the repo is backed by a real compiled artifact, correctly described, and reproducible.

| Property | Status | Evidence |
|----------|--------|----------|
| All `.v` theory files compile to `.vo` under Rocq 9.1.1 | **T2** ✅ | `proof_check.sh` / CI `coq-proofs` job |
| Every theorem record in `THEOREM_INDEX.md` maps to a compiled `.vo` | **T2** ✅ | Manifest cross-check |
| No theorem is stated as Proven in docs without a corresponding `.Qed` in a `.v` file | **T2** ✅ | `proof_check.sh` grep gate |
| All assumptions are named, versioned, and in `spec/ASSUMPTIONS.md` | **T2** ✅ | `ASM-MODEL-001`, `ASM-HW-001`, `ASM-TOOL-001` |
| Artifact manifest (`artifacts/manifest.json`) is complete and tied to commit | **T2** ✅ | `artifacts/manifest.json` |
| Proof outputs are reproducible in CI (pinned Rocq 9.1.1 via apt PPA) | **T2** ✅ | `ci/proof-check.yml` |
| No uncited proof claims exist in any `.md` doc in the repo | **T1** — open | Needs doc-audit script |
| Every theory file has an explicit dependency list in `THEOREM_INDEX.md` | **T2** ✅ | Partial — `ipc_flow.v` dependencies listed; others pending |
| Proof status language is conservative: no "proven" where model only | **T2** ✅ | See tier definitions above; tracked here |

**Open obligation:** Add doc-audit CI gate that scans all `.md` files for theorem-status language and rejects overclaiming.

---

## 4. Program B — Capability and Authority Core

**Goal:** Prove that the capability system correctly enforces all authority invariants from creation through revocation.

### 4.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-CAP-001 | Capability provenance — no forged token can enter the table outside `cap_grant` / `cap_derive` | **T2** | `ipc_flow.v` |
| THM-NET-001 (Part B) | No expired or revoked capability is accepted by CapNet | **T2** | `capnet_integrity.v` |

### 4.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| No rights escalation — derived caps carry only a subset of parent rights | **T1** | Invariant stated; no mechanized proof yet |
| DAG acyclicity — the capability delegation graph has no cycles | **T1** | `cap_graph.rs` exists; no Coq model for the graph structure |
| Revocation propagation correctness — revoking a cap revokes all descendants | **T1** | Described in `oreulia-capabilities.md`; not mechanized |
| Transfer correctness — transferred caps are removed from sender | **T0** | Not yet specified formally |
| Capability liveness — a revoked cap is permanently inactive; no resurrection | **T1** | |
| Temporal capability semantics — caps with time bounds expire correctly | **T1** | Partially covered by THM-TMP-001 model; explicit cap-time interaction not proven |
| Policy contract binding — caps can carry policy predicates that are always evaluated | **T1** | `oreulia-policy-contracts.md` describes; no Coq model |
| Entanglement semantics — entangled caps revoke together atomically | **T1** | Described in `oreulia-capability-entanglement.md`; not mechanized |
| Observer/event correctness — authority-change events are faithfully emitted | **T0** | |

**Implementation surfaces:** `kernel/src/capability/mod.rs`, `kernel/src/capability/cap_graph.rs`

**Priority path to T3:** Add `cap_graph` Coq model for DAG + acyclicity + revocation subtree. This is the highest-value open item in Program B.

---

## 5. Program C — Memory and Privilege Safety

**Goal:** Prove that no process can access memory outside its grant, and that privilege transitions are exclusive to the kernel gate.

### 5.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-MEM-001 | Allocator region safety + cross-process non-overlap + WASM sandbox confinement | **T2** | `memory_isolation.v` |
| THM-WX-001 | No page is simultaneously writable and executable | **T2** | `wx_cfi.v` |
| THM-CFI-001 | All JIT indirect branches target valid function-table entries; no mid-stream jump | **T2** | `wx_cfi.v` |
| THM-PRIV-001 | Only the syscall gate can enter ring-0; `SyscallTransition` closed-world invariant | **T2** | `privilege_safety.v` |

### 5.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Page-table correctness model — map/unmap transitions are safe | **T0** | Real page table manipulations in `arch/` are not modeled |
| COW correctness — copy-on-write fork produces isolated pages | **T0** | Present in runtime; theory not started |
| Memory protection transitions — transitions between permission states are safe | **T1** | W^X covers one transition; full transition algebra not proven |
| Executable page sealing correctness — sealed pages cannot be re-opened for write | **T1** | Partially in THM-WX-001; sealing state machine not fully modeled |
| Trap entry/exit frame integrity — kernel stack not corruptible on trap entry | **T1** | `privilege_safety.v` covers ring, not frame; open refinement obligation |
| Interrupt/exception frame integrity | **T0** | |
| AArch64 privilege invariants | **T0** | x86_64 only so far |

**Implementation surfaces:** `kernel/src/memory/`, `kernel/src/security/memory_isolation.rs`, `kernel/src/platform/syscall.rs`, `kernel/src/arch/x86_runtime.rs`

---

## 6. Program D — Execution Semantics

**Goal:** Prove that the WASM runtime (interpreter + JIT) faithfully and safely executes programs within their resource grants.

### 6.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-WX-001 | JIT W^X lifecycle | **T2** | `wx_cfi.v` |
| THM-CFI-001 | JIT CFI correctness | **T2** | `wx_cfi.v` |

### 6.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| WASM interpreter semantic correctness — each opcode correctly advances state | **T0** | Large but tractable; foundation of JIT refinement |
| JIT semantic equivalence — JIT-compiled code produces same observable output as interpreter | **T0** | Depends on interpreter correctness above |
| JIT code emission correctness — emitted x86_64 bytes correctly encode the intended instructions | **T0** | Requires instruction-level model |
| Host-call dispatch correctness — ABI shim correctly maps WASM calls to kernel services | **T1** | Runtime-enforced by `formal_host_dispatch_self_check()`; abstract dispatcher theory still pending |
| Service pointer typing correctness — service pointers cannot be mis-typed at call site | **T1** | Runtime-enforced by `formal_service_pointer_conformance_self_check()`; no mechanized service-pointer model yet |
| WASI surface correctness — frozen WASI Preview 1 compatibility surface preserves documented metadata and live behavior | **T1** | Runtime-enforced by `formal_wasi_preview1_self_check()`; no mechanized WASI model yet |
| Polyglot/native host resolution correctness — typed native host resolution preserves exact-export link identity and fail-closed teardown behavior across guest bindings | **T1** | Runtime-enforced by `formal_polyglot_abi_self_check()`; no mechanized polyglot model yet |
| Full-WASM policy contract sandboxing — policies must fail closed unless they export the exact `policy_check(ctx_ptr, ctx_len) -> i32` entry point and remain host-import free | **T1** | Runtime-enforced by policy self-checks and the capability policy path |
| Mesh migration self-bytecode fallback — zero-length `mesh_migrate` payloads must snapshot the caller's module bytecode | **T1** | Runtime-enforced by the mesh migration self-check path |
| Net connect resolution path — `oreulius_net_connect` must resolve IPv4 literals or hostnames before opening a real reactor-backed TCP handle | **T1** | Runtime-enforced by the networking host path and parser self-check |
| Polyglot provenance audit — `polyglot_link` must emit a provenance/audit record when a link is established | **T1** | Runtime-enforced by the polyglot link path and security audit log |

**Note:** The JIT semantic equivalence proof (interpreter → JIT) is Program D's primary multi-year research obligation. For alpha, the honest claim is: W^X and CFI hold at the model level (T2); full execution semantic correctness is not claimed.

**Implementation surfaces:** `kernel/src/execution/wasm_jit.rs`, `kernel/src/execution/wasm.rs`, `kernel/src/execution/host_abi.rs`

---

## 7. Program E — Temporal and Persistence Core

**Goal:** Prove that snapshot, rollback, branch, and persistence operations preserve object integrity and monotonicity.

### 7.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-TMP-001 | Temporal monotonicity — clock never rolls back; merge/fmap timestamp laws | **T2** | `temporal_logic.v` |
| THM-PER-001 | Persistence roundtrip — acknowledged writes survive crash-and-restart; codec correctness | **T2** | `persistence.v` |

### 7.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Branch creation semantics — branch shares no mutable state with parent | **T1** | Model for branching not yet in `temporal_logic.v` |
| Rollback semantics — rollback to snapshot S cannot expose state written after S | **T1** | Monotonicity proven; rollback isolation independent property |
| Temporal capability rollback — rolling back an object also rolls back its capability state | **T1** | Interaction between Program B and Program E |
| Schema migration semantics — migrated objects satisfy new schema after migration | **T0** | |
| Audit trail consistency — every temporal transition is recorded and non-repudiable | **T1** | |

**Implementation surfaces:** `kernel/src/temporal/mod.rs`, `kernel/src/temporal/persistence.rs`

---

## 8. Program F — IPC, Services, and Registry

**Goal:** Prove that inter-process communication is capability-gated, ordered correctly, and safe across PID boundaries.

### 8.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-CAP-001 (IPC clauses) | Channel capability provenance; IPC send/recv requires valid token | **T2** | `ipc_flow.v` |

### 8.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Send/receive ordering model — messages are delivered in channel order | **T1** | FIFO property not yet mechanized |
| Capability passing correctness — passed caps are correctly transferred, not copied | **T1** | Runtime-checked by `ipc::run_selftest()` and depends on Program B transfer semantics |
| Protocol/session typing — Temporal-bound channels enforce session ids and phase transitions | **T1** | Runtime-checked by `ipc::run_selftest()`; no mechanized protocol model yet |
| Replay-complete IPC state reconstruction — queue, wait queues, closure, protocol, and counter state round-trip through snapshot restore | **T1** | Runtime-checked by `ipc::run_selftest()`; no mechanized replay model yet |
| Service registration correctness — names are unique in the registry | **T0** | |
| Service lookup/invoke correctness — lookup always returns the registered handler | **T0** | |
| Cross-PID pointer validity — no process may dereference another's raw pointers | **T1** | Depends on Program C page isolation |
| Registry consistency under concurrent registration | **T0** | Depends on Program H lock model |

**Implementation surfaces:** `kernel/src/ipc/channel.rs`, `kernel/src/ipc/`, `kernel/src/capability/mod.rs`

### 8.3 Runtime-Enforced IPC Boundaries

These are runtime conformance checks exercised by `ipc::run_selftest()` and the `ipc-selftest` / `formal-verify` shell surfaces. They are not mechanized theorems yet.

| ID | Boundary | Status | Evidence |
|---|---|---|---|
| IPC-TRANSFER-001 | Ticketed message-carried capability transfer is zero-sum and one-time; duplicate or tampered ticket reuse fails closed | Runtime Checked | `kernel/src/ipc/selftest.rs::case_ticketed_capability_transfer_once` |
| IPC-PROTO-001 | Temporal-bound IPC channels enforce session ids and phase transitions when protocol state is bound | Runtime Checked | `kernel/src/ipc/selftest.rs::case_temporal_protocol_typing` |
| IPC-SNAPSHOT-001 | IPC channel snapshots round-trip committed queue, wait queues, closure, protocol, and counter state | Runtime Checked | `kernel/src/ipc/selftest.rs::case_temporal_snapshot_roundtrip` |

---

## 9. Program G — Network, CapNet, and Mesh

**Goal:** Prove that CapNet enforces capability-gated forwarding, replay resistance, and correct revocation visibility across peers.

### 9.1 Already Proven (T2)

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-NET-001 (Part A) | Message integrity — accepted messages have unforgeable caps | **T2** | `capnet_integrity.v` |
| THM-NET-001 (Part B) | Freshness — expired/revoked caps are rejected | **T2** | `capnet_integrity.v` |

### 9.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Nonce uniqueness — no two valid tokens share a nonce within a replay window | **T1** | Assumed; model-level nonce model pending |
| Lease expiry semantics — leases expire at the correct time relative to the logical clock | **T1** | Interaction with THM-TMP-001 clock |
| Revocation visibility — a revoked cap becomes invalid at all peers within one protocol round | **T1** | Partial in THM-NET-001; multi-hop propagation not modeled |
| Delegation visibility model — delegated caps are only visible to explicitly granted peers | **T0** | |
| Migration transfer correctness — a capability migrated to a new peer is removed from the origin | **T0** | |
| Peer identity / session authenticity | **T0** | Cryptographic assumptions outside the Coq model |

**Implementation surfaces:** `kernel/src/net/capnet.rs`, `kernel/src/net/`

---

## 10. Program H — Scheduler and Concurrency

**Goal:** Prove that the scheduler's state machine is correct, lock ordering prevents deadlock, and concurrency interference is bounded.

### 10.1 Already Proven

This section now mixes the long-standing T2 scheduler properties with the
AArch64 Program J boundary proof that has been promoted to T5. The row below
is the only AArch64 entry in this table.

| Theorem | Property | Tier | Theory |
|---------|----------|------|--------|
| THM-LOCK-001 | Lock DAG acyclicity — no deadlock cycle in the modeled lock order | **T2** | `lock_dag.v` |
| THM-SCH-001 | Scheduler entropy / process-state transition safety | **T2** | `scheduler_entropy.v` |
| A64-SCHED-001 | AArch64 timer tick / reschedule-pending boundary | **T5** | `aarch64_sched_tick.v` |

### 10.2 Open Properties (T1 or T0)

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Runnable/blocking state machine completeness — no process can become stuck in an unrecoverable unlisted state | **T1** | State machine in `scheduler_entropy.v` may not cover all real states |
| Wait-free ring buffer properties — if claimed wait-free, must be proven | **T0** | Not currently claimed wait-free; T0 |
| Interrupt/scheduler interaction — interrupt delivery cannot corrupt scheduler queues | **T0** | Concurrency model does not yet include interrupt interleaving |
| Starvation freedom / fairness — if claimed, must be proven | **T0** | Not currently claimed |
| Concurrency interference assumptions — all assumptions about concurrent execution are explicit | **T1** | `ASM-HW-001` covers atomicity; concurrent interference model not complete |

**Implementation surfaces:** `kernel/src/scheduler/slice_scheduler.rs`, `kernel/src/ipc/`

---

## 11. Program I — VFS, mmap, and Storage Semantics

**Goal:** Prove that the file system, memory-mapped I/O, and storage layer are safe and consistent.

### 11.1 Current Status

All properties in Program I are **T0 or T1**. No mechanized proofs exist yet.

| Property | Current Tier | Notes |
|----------|-------------|-------|
| Path resolution correctness | **T0** | |
| File descriptor uniqueness | **T0** | |
| Read/write capability gating | **T1** | Follows from Program B if cap model is extended |
| mmap correctness — mapped region is backed by the correct file range | **T0** | |
| Lazy page-fill correctness — faulted page contains correct file content | **T0** | |
| Writeback semantics — dirty pages are eventually flushed | **T0** | |
| Mount-state invariants | **T0** | |

**Note:** Program I is not in scope for any alpha "verified" claim. Its status is T0; runtime tests provide the only current correctness evidence.

**Implementation surfaces:** `kernel/src/fs/`

---

## 12. Program J — Boot, Architecture, and Assembly Boundary

**Goal:** Verify or explicitly bound the low-level architecture-specific code: boot handoff, trap entry/exit, context switch, MMU manipulation.

### 12.1 Current Status

The AArch64 rows in Program J are now **T5**. The x86/i686 rows remain **T0**
unless separately noted. This is the honest hard boundary of the current proof
corpus.

| Property | Arch | Current Tier | Notes |
|----------|------|-------------|-------|
| i686 boot handoff correctness | i686 | **T0** | |
| x86\_64 Multiboot2 bring-up | x86\_64 | **T0** | |
| AArch64 Image + DTB bring-up | AArch64 | **T5** | Proven by `A64-DTB-001` and `A64-BOOT-002`; raw-image firmware edges are bounded explicitly under `ASM-HW-001` |
| Syscall entry stub correctness | x86\_64 | **T0** | Covered by `only_gate_enters_kernel` at ring model level (T2); actual asm stub not modeled |
| Interrupt entry stub correctness | x86\_64 | **T0** | |
| Context-switch assembly correctness | x86\_64 | **T0** | |
| MMU backend — map/unmap/protect | x86\_64 | **T0** | |
| TLB flush correctness | x86\_64 | **T0** | |
| Privilege return instruction correctness | x86\_64 | **T0** | |
| AArch64 exception vectors | AArch64 | **T5** | Proven by `A64-VECTOR-001` |
| AArch64 trap entry / return | AArch64 | **T5** | Proven by `A64-VECTOR-001`; syscall return path is separately traced by `A64-SYSCALL-001` |
| AArch64 MMU backend setup | AArch64 | **T5** | Proven by `A64-MMU-001` |
| AArch64 scheduler tick / reschedule-pending boundary | AArch64 | **T5** | Proven by `A64-SCHED-001`; tick hook sets pending and context-switch bookkeeping clears it |
| AArch64 syscall boundary stubs | AArch64 | **T5** | Proven by `A64-SYSCALL-001` |
| AArch64 context-switch assembly | AArch64 | **T5** | Proven by `A64-SWITCH-001` |

**Explicit TCB declaration:** The remaining raw-image / firmware handoff edge
is bounded explicitly under `ASM-HW-001`. The ring-transition proof
(THM-PRIV-001) still holds at the abstract ring model level; it does not cover
the assembly implementation. The AArch64 target is intentionally tracked
separately so a proof claim never silently generalizes from x86 to DTB-based
bring-up.

This boundary must be explicitly stated in every release claim.

**Implementation surfaces:** `kernel/src/arch/x86_runtime.rs`, `kernel/src/platform/syscall.rs`, assembly stubs in `kernel/src/arch/`

---

## 13. Program K — Toolchain and Trusted Computing Base

**Goal:** Explicitly bound the TCB so that "verified" claims are stated relative to it, not as absolute claims.

| TCB Component | Current Handling |
|---------------|-----------------|
| Coq / Rocq Prover 9.1.1 | Trusted kernel under `ASM-TOOL-001`. Only Stdlib — no axioms beyond `Classical`. |
| Rust compiler (rustc nightly, see `rust-toolchain`) | Trusted base — compiler correctness not proven. All verified properties are source-level. |
| LLVM / assembler / linker | Trusted base — binary may differ from source model. Explicit open obligation. |
| `build.rs` / build scripts | Not verified. Build script correctness is an explicit gap. |
| ISO / image packaging | Not verified. |
| QEMU `qemu-system-x86_64` | Trusted execution model for all runtime evidence. QEMU ≠ real hardware; stated explicitly under `ASM-HW-001`. |
| Target CPU microarchitecture | Trusted hardware model. Side-channels out of scope per `ASM-HW-001`. |

**The correct form of any "verified" release claim:**

> *"Properties X, Y, Z are proven to hold at the source level in the Oreulius
> x86\_64 QEMU profile, relative to the Rocq 9.1.1 proof kernel, the Rust
> compiler, assembler, linker, and QEMU hardware model as the trusted base,
> and subject to the assumptions in `spec/ASSUMPTIONS.md`."*

No claim shall omit the TCB qualification.

---

## 14. Program L — Composition

**Goal:** Prove that the per-subsystem properties hold jointly when subsystems interact.

Subsystem-local proofs are necessary but not sufficient. The composition layer is what makes the whole system claim defensible.

### 14.1 Open Composition Obligations

| Composition Pair | Required Property | Current Tier | Blocking On |
|-----------------|-------------------|-------------|-------------|
| **B + C** — Capability + Memory | Cap-gated memory allocation: a process cannot allocate outside its granted region | **T1** | T3 for both B and C first |
| **C + D** — Memory + JIT | JIT-emitted code stays within the allocated JIT buffer and cannot escape to kernel memory | **T2** (partial — THM-WX-001 + THM-MEM-001 overlap) | Explicit composition lemma needed |
| **D + E** — JIT + Temporal | A temporal rollback correctly invalidates JIT-compiled pages from the rolled-back epoch | **T0** | Program E rollback + Program D sealing |
| **B + F** — Capability + IPC | Every IPC message is backed by a valid, non-revoked capability at the point of delivery | **T2** (partial — `ipc_flow.v` covers this path) | Refinement (T4) |
| **B + G** — Capability + CapNet | Forwarded CapNet capabilities cannot exceed the delegating peer's own rights | **T2** (partial — THM-NET-001 covers attenuation) | Multi-hop model |
| **E + I** — Temporal + VFS | Temporal snapshot of a file-backed object is consistent with the VFS state at that timestamp | **T0** | Program I not started |
| **H + all stateful** — Scheduler + everything | Scheduler preemption does not corrupt any subsystem's internal invariant | **T0** | Requires interrupt interleaving in all models |
| **J + C + D** — Boot + Memory + JIT | The machine is in a well-formed memory state before any user process executes | **T0** | Program J not started |

### 14.2 Already Partially Proven Compositions

The following theorem pairs are already checked for consistency in their theory files but do not yet have explicit composition lemmas:

- THM-WX-001 depends on THM-MEM-001 (explicit `Dependencies:` field in THEOREM_INDEX.md)
- THM-CFI-001 depends on THM-WX-001 (explicit)
- THM-PER-001 depends on THM-TMP-001 (explicit)

These dependency declarations are the current foundation of Program L.

---

## 15. Staged Milestones

The following stages map the programs above to concrete release milestones. No stage may be claimed complete until all properties in it reach the listed tier.

### Stage 1 — Fully Verified Artifacts *(Target: Alpha)*

All of Program A reaches T2 or above. Theorem inventory complete. No overclaiming.

**Current status:** T2 for all active theorems. Doc-audit gate is open.

### Stage 2 — Verified Capability and Privilege Core *(Target: Alpha+)*

Program B: provenance, no-forgery, DAG acyclicity, revocation propagation reach T3.
Program C: THM-MEM-001, THM-WX-001, THM-CFI-001, THM-PRIV-001 reach T3 (syntactic annotations complete).
Composition B+C has an explicit T2 lemma.

### Stage 3 — Verified Memory and JIT Safety Core *(Target: Beta)*

Program C properties reach T4 for x86\_64 (refinement obligations from `CODE_MODEL_TRACE.md` discharged).
Program D pre-requisite: WASM interpreter semantic model written and proven at T2 (no interpreter Coq model exists yet — this is a Stage 3 entry condition, not an existing artifact).
Program D: JIT semantic equivalence proof started, building on the newly established T2 interpreter model.
Composition C+D has explicit T2 lemma.

### Stage 4 — Verified Temporal and Persistence Core *(Target: Beta)*

Program E: rollback isolation and branch semantics reach T3.
Program E: temporal capability rollback (B+E composition) reaches T2.

### Stage 5 — Verified Composed Trusted Core *(Target: RC)*

Programs B, C, D (partial), E at T3 or above.
Compositions B+C, C+D, B+F, B+G, D+E all have explicit T2 or better lemmas.
Program H: scheduler state machine and lock DAG reach T3.
Program K: TCB statement is final and explicitly versioned.

### Stage 6 — Full-System Verification Profile *(Target: Post-1.0)*

x86\_64 QEMU profile only.
Programs B, C, E at T4.
Program J: x86\_64 boot, syscall stub, context-switch at explicit TCB boundary with audit.
Program L: all composition pairs for the x86\_64 QEMU profile have T2 lemmas.
Program K: TCB statement is final, reproducible, and tied to exact toolchain versions.

This is the honest minimum for a defensible whole-system claim in the x86\_64 QEMU profile.

---

## 16. What Cannot Be Claimed Yet

The following claims are **not supportable** at any current stage of this repo and must not appear in docs, READMEs, or release announcements without explicit qualification:

| Claim | Why It Is Not Yet Supportable |
|-------|-------------------------------|
| "The Oreulius kernel is formally verified" (unconditional) | Requires Stage 6. Most subsystems are T2 (model only). |
| "The code is proven correct" | T4 refinement proofs do not yet exist for any subsystem. |
| "The entire system is verified" | Requires Program L composition proofs and Program J asm boundary. Neither is complete. |
| "Verified across all architectures" | AArch64 and i686 are explicitly T0 for Programs C, D, J. |
| "Verified drivers, VFS, networking" | Programs I, G (partially), J are T0–T1 only. |
| "Equivalent to seL4 verification" | seL4 includes full functional correctness + C-to-binary refinement. Oreulius is currently T2 (model-level) with a roadmap to T4. Different scope and claim tier. |

---

## 17. Cross-References

| Document | Role |
|----------|------|
| `spec/INVARIANTS.md` | Canonical invariant IDs referenced in this matrix |
| `spec/ASSUMPTIONS.md` | All `ASM-*` assumption IDs used above |
| `spec/THREAT_MODEL.md` | Threat model that scopes what "correct" means |
| `proof/THEOREM_INDEX.md` | Per-theorem records with artifact paths and commit bindings |
| `mapping/CODE_MODEL_TRACE.md` | Code-to-model correspondence obligations (T3/T4 tracking) |
| `artifacts/manifest.json` | Generated artifact manifest with hashes |
| `DECISION.md` | Toolchain choice and theorem status summary |
| `parity-matrix.json` | Architecture parity for subsystems |
