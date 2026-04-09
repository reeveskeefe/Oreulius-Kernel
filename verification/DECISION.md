# Verification Toolchain Decision

Status: **Active**

## Proof Assistant
- Choice: **Coq / The Rocq Prover**
- Version: **9.1.1** (`coqc --version` → `The Rocq Prover, version 9.1.1`)
- Installed via: `brew install coq` (macOS) / `apt-get install coq` (Ubuntu CI)

## Runtime / Package Tooling
- OCaml version: **5.4.0** (ships with Rocq 9.1.1 Homebrew formula)
- opam: optional — not required; all `.v` files compile with bare `coqc` against Stdlib
- Pin/lock strategy: **pinned in CI via apt PPA (`rocq-prover/rocq`) for exact 9.1.1;
  locally via Homebrew. No opam lock needed — all theories use only `Stdlib.*`.**

## Rationale
- **Why Coq / Rocq**: Mature ITP; `Stdlib.ZArith`, `Stdlib.micromega.Lia`, and
  `Stdlib.Lists.List` are sufficient for the fixed-point arithmetic and list-based
  invariants in the Oreulius kernel model. The `lia` tactic discharges all linear
  arithmetic goals automatically, keeping proof scripts short and auditable.
- **Why not Lean 4 / Isabelle**: Lean 4's stdlib coverage for fixed-point integer
  arithmetic was immature as of 2026-Q1; Isabelle is heavier to install in CI.
- **Deviations from default**: None. All `Require Import` paths use `Stdlib.*`
  (Rocq 9.x canonical path, replacing the `Coq.*` prefix from older releases).

## Theorem Status Summary (as of 2026-04-09)

| Theorem ID    | Invariant     | Status         | Artifact                               |
|--------------|--------------|---------------|---------------------------------------|
| THM-CAP-001  | INV-CAP-001  | **Proven**     | `verification/theories/ipc_flow.v`    |
| THM-WX-001   | INV-WX-001   | **Proven**     | `verification/theories/wx_cfi.v`      |
| THM-MEM-001  | INV-MEM-001  | **Proven** ✅  | `verification/theories/memory_isolation.v` (MemRegion model; memory_region_isolation Theorem…Qed) |
| THM-CFI-001  | INV-CFI-001  | **Proven** ✅  | `verification/theories/wx_cfi.v` (FunctionTable model; cfi_jit_targets_valid Theorem…Qed) |
| THM-TMP-001  | INV-TMP-001  | InProgress     | `verification/theories/temporal_logic.v` |
| THM-PER-001  | INV-PER-001  | **Proven** ✅  | `verification/theories/persistence.v` (SnapshotStore model; PersistenceRoundtrip Theorem…Qed) |
| THM-NET-001  | INV-NET-001  | **Proven** ✅  | `verification/theories/capnet_integrity.v` (ForwardCap model; capnet_message_integrity Theorem…Qed) |
| THM-PRIV-001 | INV-PRIV-001 | **Proven** ✅  | `verification/theories/privilege_safety.v` (CpuState ring model; only_gate_enters_kernel Theorem…Qed) |
| A64-SCHED-001 | INV-A64-006 | **Proven** ✅  | `verification/theories/aarch64_sched_tick.v` (A64SchedState model; a64_scheduler_tick_boundary_refinement Theorem…Qed) |
