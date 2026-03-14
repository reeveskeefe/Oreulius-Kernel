# Code <-> Model Traceability

## Correspondence Obligations

### CO-SYNTAX-001 — Syntactic Correspondence
Every kernel data structure that appears in a Coq theory must have an
accompanying comment in its Rust source file of the form:
`// MODEL: <TheoryFile>.<TypeName>` so that reviewers can cross-reference
the implementation with its formal counterpart without searching.

**Status**: Partially met. `ipc_flow.v` references `CapToken`, `Channel`, and
`IpcMessage`; corresponding Rust structs in
`kernel/src/capability/mod.rs` and `kernel/src/ipc/channel.rs` carry
`// MODEL:` comments. Remaining subsystems (temporal, CapNet, JIT) are
scheduled for annotation in the next cycle.

### CO-SEM-001 — Semantic Correspondence
Each proved theorem must reference only the Coq types that correspond
one-to-one with the runtime types used in the actual kernel code path
exercised by the CI smoke test. No phantom or stub types may be introduced
solely to make a proof go through.

**Status**: Met for `ipc_flow.v` (PMA-IPC-001 through PMA-IPC-005). The
`handle_ipc_message` and `revoke_capability` Coq functions mirror the
implementations in `kernel/src/ipc/` and `kernel/src/capability/`. Theorems
in `lock_dag.v` and `scheduler_entropy.v` use abstract state machines that
are semantically equivalent to their Rust counterparts but do not yet have
`CO-SEM` annotations.

### CO-BOUNDARY-001 — Boundary Correspondence
All trust boundary crossings identified in `THREAT_MODEL.md` must have a
corresponding Coq lemma or axiom that states the safety property at that
boundary. If no proof exists, the boundary must be listed under
`ASM-MODEL-001` (out-of-scope) and the gap recorded here.

**Status**: Ring-0/Ring-3 boundary and WASM linear-memory boundary are covered
by the JIT bounds-checking invariant (THM-WX-001 / THM-CFI-001, InProgress).
CapNet Peer Boundary is covered by `ipc_flow.v` PMA-IPC-005. Scheduler Domain
boundary is covered by `scheduler_entropy.v`. The firmware/BIOS boundary is
explicitly out of scope per `ASM-MODEL-001`.

## Per-Subsystem Mapping

| Subsystem | Implementation Files | Specification Files |
|---|---|---|
| Capability | `kernel/src/capability/mod.rs`, `kernel/src/capability/cap_graph.rs` | `spec/capability.*`, `theories/ipc_flow.v` |
| Temporal | `kernel/src/temporal/mod.rs`, `kernel/src/temporal/persistence.rs` | `spec/temporal.*`, `theories/temporal_logic.v` |
| CapNet | `kernel/src/net/capnet.rs` | `spec/capnet.*`, `theories/ipc_flow.v` (PMA-IPC-005) |
| JIT | `kernel/src/execution/wasm_jit.rs` | `spec/jit.*` (pending) |
| Privilege Transitions | `kernel/src/arch/x86_runtime.rs`, `kernel/src/platform/syscall.rs` | `spec/priv.*` (pending) |
| Scheduler | `kernel/src/scheduler/quantum_scheduler.rs` | `spec/scheduler.*`, `theories/scheduler_entropy.v`, `theories/lock_dag.v` |
