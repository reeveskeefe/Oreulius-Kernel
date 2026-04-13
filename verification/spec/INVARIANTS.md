# Verification Invariants

These invariants define the safety properties the verification workspace tracks.

- INV-001: Capability attenuation must never increase authority.
- INV-002: Replay windows must reject duplicate or expired transcripts.
- INV-003: Writable and executable memory states must remain disjoint where
  W^X is claimed.
- INV-004: Lock ordering must not admit self-deadlock edges in the modeled DAG.
- INV-005: Scheduler fuel consumption must remain bounded by the declared
  execution budget.
- INV-006: Generated proof evidence must remain outside the runtime dependency
  graph.
- INV-007: Full-WASM policy contracts must fail closed unless they export the
  exact `policy_check(ctx_ptr, ctx_len) -> i32` entry point and satisfy the
  sandbox constraints documented in the runtime README.
- INV-008: `mesh_migrate(..., wasm_len = 0)` must migrate the caller's stored
  module bytecode rather than an empty payload.
- INV-009: `oreulius_net_connect(...)` must either resolve a dotted-quad IPv4
  literal directly or resolve a hostname via the network stack before opening
  a real TCP connection handle.
- INV-010: `polyglot_link(...)` must emit a provenance/audit record when a
  cross-language service link is created.
- INV-011: Ticketed IPC capability transfer must be zero-sum and one-time,
  with duplicate or tampered ticket reuse failing closed.
- INV-012: Temporal-bound IPC channels must enforce session ids and phase
  transitions when protocol state is bound to a channel.
- INV-013: IPC channel snapshots must round-trip committed queue contents,
  wait queues, closure state, protocol state, and observable counters.
- INV-A64-001: AArch64 boot handoff must preserve a well-formed handoff state
  from QEMU `virt` into the kernel entrypoint.
- INV-A64-002: AArch64 DTB parsing must not widen the trusted input set beyond
  the selected boot-time device tree.
- INV-A64-003: AArch64 exception vectors and trap return paths must preserve
  kernel/user privilege separation.
- INV-A64-004: AArch64 MMU setup must preserve the intended executable,
  writable, and mapped regions for the bring-up profile.
- INV-A64-005: AArch64 syscall entry stubs must remain the only modeled user to
  kernel entry path for the verified profile.
- INV-A64-006: AArch64 timer ticks must only mark reschedule-pending at
  quantum boundaries, and context-switch bookkeeping must clear that pending
  state before the next dispatch step.
- INV-A64-007: AArch64 context-switch handoff must preserve the selected
  `ProcessContext` fields across the modeled switch/load entrypoints and must
  not invent a second privilege transition.
