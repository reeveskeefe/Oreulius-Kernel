# ThingsYetToDo — Master Status

This document consolidates the status of all tracked work items across the
`ThingsYetToDo/` directory. It replaces three previously planned but never
created files (`incompleteimplementations.md`, `SRCReorganization.md`,
`innovativeideas.md`) and serves as the single source of truth for
outstanding / completed engineering backlog.

---

## 1. Incomplete Implementations

> Previously tracked in `incompleteimplementations.md` (never created as a
> separate file; consolidated here).

| Item | Status | Notes |
|------|--------|-------|
| WiFi subsystem (`NetworkError::WiFiNotEnabled`) | ✅ Complete | Hardware-absent advisory message added to shell commands |
| HTTP client (`cmd_http_get`) | ✅ Complete | Emulation-context advisory added |
| CapNet CTMC mass proofs | ✅ Complete | `ipc_flow.v` §4 + §5 proven and compiled |
| W^X JIT invariant | ✅ Complete | `wx_cfi.v` `jit_pipeline_preserves_wx` proven |
| Scheduler EWMA proofs | ✅ Complete | `scheduler_entropy.v` all lemmas compile |
| Lock-DAG ordering proofs | ✅ Complete | `lock_dag.v` compiles |
| Temporal functor proofs | ✅ Complete | `temporal_logic.v` compiles |
| THM-MEM-001 (memory isolation) | ⏳ InProgress | Structural axioms stated; full proof deferred |
| THM-NET-001 (CapNet isolation) | ⏳ InProgress | Model axioms stated in `ipc_flow.v`; full proof deferred |
| THM-PER-001 (temporal persistence) | ⏳ InProgress | Functor model complete; persistence layer proof deferred |
| THM-PRIV-001 (privilege separation) | ⏳ InProgress | Deferred to after capability graph proof is extended |

---

## 2. Source Reorganization

> Previously tracked in `SRCReorganization.md` (never created as a separate
> file; consolidated here).

| Area | Status | Notes |
|------|--------|-------|
| `kernel/src/` orphaned modules (`interrupts.rs`, `qemu.rs`, `timer.rs`, `main.rs`) | ✅ Resolved | Files removed; see `StuffYetToBeIntegrated.md` |
| `kernel/src/asm/context_switch.asm.bak` | ✅ Resolved | Backup deleted |
| Boot experiment archives | ✅ Resolved | Under `kernel/archive/boot-experiments/` |
| `verification/theories/` file structure | ✅ Resolved | 5 `.v` files, all compile on Rocq 9.1.1 |
| `docs/ci-evidence/` evidence directory | ✅ Created | Boot log, fuzz sample, CapNet regression sample |
| Multi-arch build scripts | ✅ Resolved | x86_64 and aarch64 build scripts present and functional |
| Service daemon structure | ✅ Resolved | `services/telemetry_daemon/` in place |

---

## 3. Innovative Ideas Backlog

> Previously tracked in `innovativeideas.md` (never created as a separate
> file; consolidated here). These are features / research directions that
> are either implemented, deferred to a future milestone, or actively
> under design.

| Idea | Status | Notes |
|------|--------|-------|
| Intent-graph predictive revocation | ✅ Designed | See `docs/oreulia-intent-graph-predictive-revocation.md` |
| JIT security resolution (W^X + CFI) | ✅ Proven | `wx_cfi.v` theorem complete |
| Polymorphic mathematical architecture | ⏳ Design | See `ThingsYetToDo/Polymorphic_Mathematical_Architecture.md` |
| Temporal adapters + durable persistence | ✅ Designed | See `docs/oreulia-temporal-adapters-durable-persistence.md` |
| Service pointer capabilities | ✅ Designed | See `docs/oreulia-service-pointer-capabilities.md` |
| WASM ABI + JIT pairwise transition coverage | ✅ Designed | See `docs/oreulia-wasm-jit-pairwise-transition-coverage.md` |
| AI Edge Node procurement path | ⏳ Deferred | See `ThingsYetToDo/AIEdgeNodeProcurement.md` |
| Real shot at xAI integration | ⏳ Deferred | See `ThingsYetToDo/realshotatXai.md` |
| Formal verification runway (all 8 theorems) | ⏳ InProgress | 2 of 8 proven; 6 remain InProgress |
| CapNet zero-copy IPC over shared memory | ⏳ Design | Architecturally modeled in `docs/capnet.md` |

---

## 4. Multi-Arch Production Parity

| Milestone | Status |
|-----------|--------|
| All 15 roadmap steps | ✅ Complete — see `ThingsYetToDo/MultiArchProductionParityRoadmap.md` |

---

## 5. Formal Verification Runway

| Theorem | Status | Artifact |
|---------|--------|---------|
| THM-CAP-001 (capability provenance) | ✅ **Proven** | `ipc_flow.v` §5 |
| THM-WX-001  (W^X invariant) | ✅ **Proven** | `wx_cfi.v` |
| THM-CFI-001 (CFI entry-point) | ⏳ Partial | `wx_cfi.v` (axiom + 1 lemma) |
| THM-TMP-001 (temporal monotonicity) | ⏳ InProgress | `temporal_logic.v` |
| THM-MEM-001 (memory isolation) | ⏳ InProgress | `temporal_logic.v` |
| THM-PER-001 (persistence) | ⏳ InProgress | `temporal_logic.v` |
| THM-NET-001 (network isolation) | ⏳ InProgress | `ipc_flow.v` |
| THM-PRIV-001 (privilege separation) | ⏳ InProgress | `ipc_flow.v` |

Toolchain: **Rocq Prover 9.1.1** / OCaml 5.4.0 — pinned in `verification/DECISION.md`.

---

*Last updated: 2026-03-14*
