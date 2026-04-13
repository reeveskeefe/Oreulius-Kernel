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
boundary is covered by `scheduler_entropy.v`, with the AArch64 tick / pending
boundary tracked separately by `aarch64_sched_tick.v`. The AArch64 syscall
boundary is covered by `aarch64_syscall.v`, and the AArch64 scheduler handoff
boundary is covered by `aarch64_context_switch.v`. The firmware/BIOS boundary
is explicitly out of scope per `ASM-MODEL-001`. The host-dispatch table
boundary, the WASI Preview 1 compatibility surface, and the service-pointer
invoke/revoke boundary are now runtime-enforced by `formal-verify`, and the
polyglot registry/link boundary joins them in the same category. None yet have
Coq theories, so they remain below T2 until modeled.

## Per-Subsystem Mapping

| Subsystem | Implementation Files | Specification Files |
|---|---|---|
| Capability | `kernel/src/capability/mod.rs`, `kernel/src/capability/cap_graph.rs` | `spec/capability.*`, `theories/ipc_flow.v` |
| Temporal | `kernel/src/temporal/mod.rs`, `kernel/src/temporal/persistence.rs` | `spec/temporal.*`, `theories/temporal_logic.v` |
| CapNet | `kernel/src/net/capnet.rs` | `spec/capnet.*`, `theories/ipc_flow.v` (PMA-IPC-005) |
| JIT | `kernel/src/execution/wasm_jit.rs` | `spec/jit.*` (pending) |
| Host ABI dispatcher | `kernel/src/execution/wasm.rs`, `kernel/src/shell/commands.rs` | `spec/abi.*` (pending); runtime evidence `formal_host_dispatch_self_check()` |
| WASI Preview 1 compatibility surface | `kernel/src/execution/wasm.rs`, `kernel/src/services/wasi.rs`, `kernel/src/fs/vfs.rs`, `wasm/sdk/src/raw/wasi.rs`, `wasm/sdk/src/fs.rs` | `spec/wasi.*` (pending); runtime evidence `formal_wasi_preview1_self_check()` |
| Service pointer / native typed invoke boundary | `kernel/src/execution/wasm.rs`, `kernel/src/capability/mod.rs`, `wasm/sdk/src/service.rs`, `wasm/sdk/src/polyglot.rs` | `spec/service-pointer.*` (pending); runtime evidence `formal_service_pointer_conformance_self_check()` |
| Polyglot registry and exact-export link boundary | `kernel/src/execution/wasm.rs`, `wasm/sdk/src/polyglot.rs`, `wasm/sdk/src/raw/oreulius.rs` | `spec/polyglot.*` (pending); runtime evidence `formal_polyglot_abi_self_check()` |
| Privilege Transitions | `kernel/src/arch/x86_runtime.rs`, `kernel/src/platform/syscall.rs` | `spec/priv.*` (pending) |
| AArch64 DTB discovery | `kernel/src/arch/aarch64_runtime.rs`, `kernel/src/arch/aarch64_dtb.rs`, `kernel/src/arch/aarch64_virt.rs` | `spec/aarch64.*`, `theories/aarch64_dtb.v` |
| AArch64 boot handoff | `kernel/src/arch/aarch64_virt.rs`, `kernel/src/arch/aarch64_runtime.rs` | `spec/aarch64.*`, `theories/aarch64_handoff.v` |
| AArch64 trap/vector boundary | `kernel/src/arch/aarch64_vectors.rs`, `kernel/src/arch/aarch64_virt.rs`, `kernel/src/arch/aarch64_runtime.rs` | `spec/aarch64.*`, `theories/aarch64_vectors.v` |
| AArch64 MMU bring-up | `kernel/src/arch/mmu_aarch64.rs`, `kernel/src/arch/aarch64_runtime.rs`, `kernel/src/arch/aarch64_virt.rs` | `spec/aarch64.*`, `theories/aarch64_mmu.v` |
| AArch64 scheduler tick boundary | `kernel/src/arch/aarch64_virt.rs`, `kernel/src/scheduler/slice_scheduler.rs` | `spec/aarch64.*`, `theories/aarch64_sched_tick.v` |
| AArch64 syscall boundary | `kernel/src/arch/aarch64_vectors.rs`, `kernel/src/platform/syscall.rs` | `spec/aarch64.*`, `theories/aarch64_syscall.v` |
| AArch64 scheduler handoff / context-switch boundary | `kernel/src/scheduler/scheduler_platform.rs`, `kernel/src/asm/aarch64_scheduler.S`, `kernel/src/scheduler/slice_scheduler.rs` | `spec/aarch64.*`, `theories/aarch64_context_switch.v` |
| Scheduler | `kernel/src/scheduler/slice_scheduler.rs` | `spec/scheduler.*`, `theories/scheduler_entropy.v`, `theories/lock_dag.v` |
