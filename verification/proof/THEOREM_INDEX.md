# Theorem Index

This index tracks proof artifacts only. Runtime self-checks and shell-visible
evidence surfaces are documented in the kernel tree and referenced here only by
boundary.

| ID | Theory | Status | Notes |
|---|---|---|---|
| TEMP-001 | `theories/temporal_logic.v` | Scaffolded | Monotonic temporal step model |
| IPC-001 | `theories/ipc_flow.v` | Scaffolded | Attenuation monotonicity |
| WXCFI-001 | `theories/wx_cfi.v` | Scaffolded | Writable and executable states remain disjoint |
| LOCK-001 | `theories/lock_dag.v` | Scaffolded | Lock ordering has no self-edge |
| SCHED-001 | `theories/scheduler_entropy.v` | Scaffolded | Scheduler fuel consumption stays bounded |
| A64-DTB-001 | `theories/aarch64_dtb.v` | Proven | DTB header and slice bounds remain within the declared blob |
| A64-BOOT-002 | `theories/aarch64_handoff.v` | Proven | Boot handoff surfaces the same DTB pointer into runtime |
| A64-VECTOR-001 | `theories/aarch64_vectors.v` | Proven | Installed vector base and lower-EL sync dispatch preserve the trap boundary |
| A64-MMU-001 | `theories/aarch64_mmu.v` | Proven | MMU bring-up establishes a root and preserves modeled W^X separation |
| A64-SCHED-001 | `theories/aarch64_sched_tick.v` | Proven | Timer tick boundary sets reschedule-pending only at slice boundaries and timeslice updates reject zero |
| A64-SYSCALL-001 | `theories/aarch64_syscall.v` | Proven (extension planned) | AArch64 syscall dispatcher and return-frame boundary remain within the modeled gate; current wave extends invalid-frame state-corruption exclusion |
| A64-SWITCH-001 | `theories/aarch64_context_switch.v` | Proven | AArch64 scheduler handoff preserves the selected ProcessContext and switch bookkeeping |

## Runtime-Enforced ABI Boundaries

These are not mechanized theorems yet. They are boundary records for runtime
conformance checks that now gate `formal-verify` and must be modeled before any
T2+ proof claim is made.

| ID | Boundary | Status | Runtime Evidence |
|---|---|---|---|
| ABI-DISPATCH-001 | Frozen host-dispatch table preserves host ID, name, arity, result shape, and alias metadata | Runtime Checked | `kernel/src/execution/wasm.rs::formal_host_dispatch_self_check()` |
| WASI-ABI-001 | Frozen WASI Preview 1 compatibility surface (IDs `45–90`) preserves dispatcher metadata and live ABI behavior | Runtime Checked | `kernel/src/execution/wasm.rs::formal_wasi_preview1_self_check()` |
| POLYGLOT-ABI-001 | Frozen polyglot host surface (IDs `103–105`) preserves dispatcher metadata, exact-export linking, and teardown purge behavior | Runtime Checked | `kernel/src/execution/wasm.rs::formal_polyglot_abi_self_check()` |
| SPTR-001 | Service-pointer import, invoke, revoke, typed-slot round-trip, and post-revoke rejection preserve typed service-pointer authority boundaries | Runtime Checked | `kernel/src/execution/wasm.rs::formal_service_pointer_conformance_self_check()` |
| POLICY-ABI-001 | Full-WASM policy contracts fail closed unless they export `policy_check(ctx_ptr, ctx_len) -> i32` and remain host-import free | Runtime Checked | `kernel/src/execution/wasm.rs::policy_tests::full_wasm_policy_contract_permits_minimal_policy_check_blob` |
| MESH-MIGRATE-001 | Zero-length `mesh_migrate` payloads snapshot the caller's stored module bytecode instead of queuing an empty blob | Runtime Checked | `kernel/src/execution/wasm.rs::policy_tests::mesh_migrate_uses_module_bytecode_when_payload_is_empty` |
| NET-CONNECT-001 | `oreulius_net_connect` resolves IPv4 literals or DNS names and returns a real reactor-backed TCP connection handle | Runtime Checked | `kernel/src/execution/wasm.rs::policy_tests::parse_net_host_accepts_ipv4_literal` |
| POLYGLOT-AUDIT-001 | `polyglot_link` records provenance/audit state when a cross-language service link is created | Runtime Checked | `kernel/src/execution/wasm.rs::host_polyglot_link` / `kernel/src/security/mod.rs::log_event` |
| OBS-EVENT-SCHEMA-001 | Observability event schema v1 remains stable and versioned for proof-runtime evidence correlation | Runtime Checked | `verification/artifacts/observability_event_schema_v1.md` / `kernel/src/observability/event.rs` |

## Runtime-Enforced IPC Boundaries

These are runtime conformance checks exercised by `ipc::run_selftest()` and the `ipc-selftest` / `formal-verify` shell surfaces. They are not mechanized theorems yet.

| ID | Boundary | Status | Runtime Evidence |
|---|---|---|---|
| IPC-TRANSFER-001 | Ticketed message-carried capability transfer is zero-sum and one-time; duplicate or tampered ticket reuse fails closed | Runtime Checked | `kernel/src/ipc/selftest.rs::case_ticketed_capability_transfer_once` |
| IPC-PROTO-001 | Temporal-bound IPC channels enforce session ids and phase transitions when protocol state is bound | Runtime Checked | `kernel/src/ipc/selftest.rs::case_temporal_protocol_typing` |
| IPC-SNAPSHOT-001 | IPC channel snapshots round-trip committed queue, wait queues, closure, protocol, and counter state | Runtime Checked | `kernel/src/ipc/selftest.rs::case_temporal_snapshot_roundtrip` |

## Phase 1B: Runtime-Enforced Invariant & Boundary Checks

These are severity-classified invariant checks with deterministic failure policy dispatch. They are exercised by five negative-trace tests and backed by structured observability emission.

| ID | Boundary | Status | Runtime Evidence | Phase |
|---|---|---|---|---|
| INV-SCHED-FAIR-001 | Scheduler fairness window: runnable must be 0 OR serviced > 0 | Runtime Checked | `kernel/src/scheduler/process.rs::scheduler_negative_trace_closure_chain` (severity: Progress) | 1B |
| INV-SYSCALL-NUM-001 | Syscall number must be ≤ configured maximum (64) | Runtime Checked | `kernel/src/platform/syscall.rs::syscall_negative_trace_closure_chain` (severity: Consistency) | 1B |
| INV-SYSCALL-FRAME-001 | User exception frame pointer must be non-null and within address limit | Runtime Checked | `kernel/src/arch/aarch64_vectors.rs::trap_negative_trace_closure_chain` (severity: Safety) | 1B |
| INV-MMU-MAP-001 | Virtual address and length must be page-aligned to page_size | Runtime Checked | `kernel/src/arch/mmu_aarch64.rs::mmu_negative_trace_closure_chain` (severity: Safety) | 1B |
| INV-MMU-WX-001 | Write and execute permissions must remain disjoint (W^X enforcement) | Runtime Checked | See INV-MMU-MAP-001 test and `kernel/src/invariants/mmu.rs::check_permission_transition()` | 1B |
| INV-DTB-HEADER-001 | Device tree blob header size must be within declared bounds | Runtime Checked | `kernel/src/arch/aarch64_dtb.rs::dtb_negative_trace_closure_chain` (severity: Safety) | 1B |

### Failure Policy Runtime Dispatch

All Phase 1B invariant checks route violations through `kernel/src/failure/policy.rs::classify()` and emit structured events:
- **InvariantViolation** event at check failure
- **FailurePolicyAction** event at dispatch decision
- **TerminalFailure** event when action is FailStop (for non-recoverable violations)

Policies are:
- Scheduler violations → **Isolate** (process isolation)
- Syscall violations → **Isolate** (process isolation)
- MMU violations → **FailStop** (kernel fault, non-recoverable)
- DTB violations → **Degrade** (graceful degradation)
- Capability violations → **FailStop** (kernel fault, non-recoverable)
- Depth > 1 (recursive failure) → **FailStop** (0xDEAD fallback)

### Test Helper Utility

Closure-chain test assertions are centralized in `kernel/src/observability/test_helpers.rs::assert_closure_chain_closure()` to:
1. Verify event count increased (events were emitted)
2. Check all expected event types are present in sequence
3. Verify failure outcome subsystem and action match expected values

This reduces test boilerplate by ~240 lines across five boundaries.
