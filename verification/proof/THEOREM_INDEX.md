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
| A64-SCHED-001 | `theories/aarch64_sched_tick.v` | Proven | Timer tick boundary sets reschedule-pending only at quantum boundaries and quantum updates reject zero |
| A64-SYSCALL-001 | `theories/aarch64_syscall.v` | Proven | AArch64 syscall dispatcher and return-frame boundary remain within the modeled gate |
| A64-SWITCH-001 | `theories/aarch64_context_switch.v` | Proven | AArch64 scheduler handoff preserves the selected ProcessContext and switch bookkeeping |
