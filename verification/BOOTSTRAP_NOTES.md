# Bootstrap Notes

Fresh-state required reading completed:
- README.md verification + temporal sections
- docs/runtime/oreulius-jit-security-resolution.md
- docs/capability/capnet.md
- docs/storage/oreulius-temporal-adapters-durable-persistence.md
- docs/services/oreulius-service-pointer-capabilities.md
- kernel/src/commands.rs
- kernel/src/temporal.rs
- kernel/src/capnet.rs
- kernel/src/wasm_jit.rs
- kernel/src/syscall.rs

## Subsystem Summary

| Subsystem | Module | Status |
|-----------|--------|--------|
| Capability manager | `kernel/src/capability/mod.rs` | Implemented — `CapabilityType` (9 variants), `Rights` bitflags, `cap_grant`/`cap_derive`, `check_capability` |
| WASM JIT | `kernel/src/execution/wasm_jit.rs` | Implemented — single-pass x86/x86_64 JIT, W^X lifecycle, CFI gating, `TranslationProof` certificates |
| Intent graph / security | `kernel/src/security/intent_graph.rs` | Implemented — 9×9 CTMC, Euler step, risk scoring, staged enforcement, cooldown timers |
| Temporal objects | `kernel/src/temporal/` | Implemented — monotonic clock, snapshot/restore, crash-recovery roundtrip |
| VFS / filesystem | `kernel/src/fs/` | Implemented — capability-gated key-value store, IPC glue, persistence journal |
| IPC / CapNet | `kernel/src/ipc/`, `kernel/src/net/capnet.rs` | Implemented — channel table, capability-checked send/recv, revocation |
| Scheduler | `kernel/src/scheduler/` | Implemented — preemptive MLFQ, context-switch assembly, per-process quantum |
| Shell | `kernel/src/shell/commands.rs` | Implemented — all advertised commands dispatch to real kernel logic (0 stubs) |

## Toolchain
- Rust: see `kernel/rust-toolchain`
- Coq / Rocq Prover: 9.1.1 (see `verification/DECISION.md` and `verification/ENVIRONMENT.md`)
- QEMU: `qemu-system-i386`, `qemu-system-x86_64`, `qemu-system-aarch64`

## Verification Entry Point
```bash
bash verification/scripts/proof_check.sh   # structural CI gate
coqc verification/theories/ipc_flow.v      # capability + CTMC proofs (THM-CAP-001, Proven)
coqc verification/theories/wx_cfi.v        # W^X invariant proof (THM-WX-001, Proven)
bash kernel/formal-verify.sh               # QEMU runtime gate
```
