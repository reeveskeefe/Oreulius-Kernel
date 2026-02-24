# Multi-Arch Production Parity Roadmap (Internal TODO)

## Purpose

This document tracks the remaining work required to move Oreulia from
`multi-arch bring-up` to `cross-arch feature parity + production-grade runtime`.

It is intentionally codebase-specific. Each track is tied to current modules,
QEMU launch paths, and CI workflows already present in this repository.

## Current Baseline (What Exists Today)

- `i686` legacy boot/runtime path is functional and CI-smoked.
- `x86_64` bring-up/runtime path boots under Multiboot2/GRUB, runs a serial shell under the shared scheduler,
  and has working MMU/traps/timer/JIT user-entry plumbing with CI-covered JIT checks (`jitbench`, `jitfuzz`, bounded `jitfuzzreg`).
- `AArch64` QEMU `virt` bring-up path boots raw `Image`, parses DTB, runs MMU/GIC/timer,
  shared scheduler, serial shell, and `virtio-mmio` block + VFS shell smoke.
- CI smoke exists:
  - `.github/workflows/multiarch-qemu-smoke.yml`
  - `kernel/ci/smoke-i686.sh`
  - `kernel/ci/smoke-x86_64.sh`
  - `kernel/ci/smoke-aarch64.sh`
- CI extended regression exists (nightly/manual, multi-arch):
  - `.github/workflows/multiarch-qemu-extended.yml`
  - `kernel/ci/extended-x86_64.sh`
  - `kernel/ci/extended-aarch64.sh`
  - `kernel/ci/soak-i686.sh`

## Not Done (The Remaining Gap)

The following are **not** complete and block an honest "porting complete / production-ready" claim:

- Full feature parity across arches (especially usermode/JIT/trampolines)
- Production-grade driver coverage and hardware breadth (beyond QEMU `virt`)
- Long-run stability, fault-injection, stress/perf validation
- Full process/scheduler parity and subsystem parity across all three architectures

## Program Tracks

## 1. Feature Parity Across Architectures (Usermode / JIT / Trampolines)

### Current known gaps

- `x86_64`: user-entry/trampoline path is implemented and CI-smoked, but the `wasm_jit` x86_64 backend is still subset coverage (not full opcode parity).
- `AArch64`: bring-up shell/runtime exists, but no usermode/JIT entry/trampoline parity.
- Shared scheduler has AArch64 bring-up integration, but user process creation paths remain stubbed in `kernel/src/quantum_scheduler.rs`.

### TODO (methodical)

- [x] Port `x86_64` usermode entry/trampoline path in `kernel/src/wasm.rs` and `kernel/src/usermode.rs`
  - Replaced the x86_64 preflight-only path with real user entry/return handling (`iretq` + return handoff).
  - Trap-return + error propagation paths are wired and runtime-smoked via `jitcall`.
- [x] Add `x86_64` JIT execution CI step (not just `jitpre` / `jitcall` expected-error path)
  - `jitbench` is now a real x86_64 WASM JIT execution check in extended x86_64 QEMU CI.
  - Bounded `jitfuzz` and real `jitfuzzreg` dry-run are also exercised in extended x86_64 CI.
- [ ] Expand `x86_64` `wasm_jit` backend coverage from subset support to broader opcode parity
  - Current x86_64 backend supports a useful fuzz/test subset (arith/locals/load/store), but not full parity.
- [x] Achieve full guided-bin pairwise fuzz transition coverage for the current x86_64 JIT fuzz generator model
  - `jit_fuzz` now computes an admissible edge matrix (`E_adm`) for the 14-bin guided generator, reports both full and admissible pairwise coverage, and uses a deterministic pair-cover prepass.
  - Current result reaches `Opcode edges hit (full): 196 / 196` and `Opcode edges hit (admissible): 196 / 196` for the present 14-bin generator abstraction.
  - This is a generator-level pairwise milestone, not full WASM opcode parity or CFG/control-flow coverage.
- [ ] Implement `AArch64` usermode transition and trap return path (`EL0` entry/return)
  - Includes syscall/exception return ABI and register frame handling.
- [ ] Add `AArch64` JIT sandbox/user-entry path (or explicit interpreter-only mode until JIT backend lands)
  - If JIT backend remains unported, make interpreter path first-class and CI-covered.
- [ ] Introduce a shared "WASM execution capability matrix" doc/test
  - Distinguish interpreter, JIT-preflight, JIT-exec by arch.

### Exit criteria

- `i686`, `x86_64`, `AArch64` each have a documented and CI-tested WASM execution mode.
- No architecture silently falls back to unsupported/stubbed user entry.
- `quantum_scheduler::add_user_process` is no longer stubbed on production-target arches.

## 2. Driver Coverage and Hardware Breadth (Beyond QEMU `virt`)

### Current known gaps

- Driver coverage is still bring-up oriented (QEMU-friendly paths, partial virtio, legacy x86 devices).
- AArch64 support is validated on QEMU `virt`, not real boards.
- x86_64 path is bring-up shell level, not broad hardware runtime parity.

### TODO (methodical)

- [ ] Establish a target hardware matrix (minimum supported platforms)
  - x86_64: QEMU + one physical x86_64 machine class
  - AArch64: QEMU `virt` + at least one real board family
  - i686: legacy support scope explicitly documented
- [ ] Promote virtio drivers to shared backends (PCI + MMIO transport neutrality)
  - `virtio_blk` has started; extend to net and console paths.
- [ ] Implement x86_64 PCI/virtio bring-up parity with AArch64 MMIO virtio coverage
- [ ] Add board-specific boot/run scripts and serial log capture for real boards
  - `kernel/run-*.sh` style launchers for reproducible validation
- [ ] Add driver capability table in README (per-arch, per-platform)

### Exit criteria

- At least one non-QEMU AArch64 board boots to shell and runs block/VFS smoke.
- x86_64 supports a modern virtio-backed device path in addition to bring-up shell.
- Driver support matrix is explicit and CI/manual test procedures are documented.

## 3. Long-Run Stability, Fault Injection, Stress / Perf Validation

### Current known gaps

- CI now includes smoke + extended QEMU regressions, but long-run soak/perf trend tracking is still limited.
- Limited automated evidence for interrupt/timer/scheduler stability over time.
- AArch64 `vmtest` shared-scheduler abort storm was fixed and `A64_INCLUDE_VMTEST=1` is re-enabled by default in extended CI;
  keep watching for regressions under longer soak runs.

### TODO (methodical)

- [x] Add extended QEMU regression workflows (nightly/manual)
  - Multi-arch soak and fault-injection suites
  - Preserve logs/artifacts for triage
- [x] Add fault-injection command coverage
  - x86_64: `int3`, page fault/COW tests, JIT preflight failure path
  - AArch64: `brk`, `vmtest`, UART/GIC diagnostics, virtio reinit
- [x] Add stress loops
  - Repeated block I/O, VFS ops, scheduler tick load, trap tests
- [ ] Add baseline performance probes (even if shell-level initially)
  - Capture durations for repeated block read/write loops
  - Track regressions over time in CI artifacts
- [ ] Add crash signature triage checklist (panic, exception dumps, timeout classes)

### Exit criteria

- Nightly extended regression runs on `x86_64` + `AArch64` (and i686 boot soak) with stored logs.
- Failures are classified (boot fail / prompt timeout / command timeout / panic / trap).
- A stable baseline of repeated runtime operations is exercised automatically.

## 4. Process / Scheduler / Subsystem Parity

### Current known gaps

- AArch64 shared scheduler is enabled and used for the shell runtime, but runtime behavior is still bring-up grade.
- Shared process backend is bridged into `vfs_platform` (scheduler-driven PID sync is in place), but full subsystem parity is incomplete.
- User process and fork/COW scheduler paths are still stubbed or partial on non-legacy paths.

### TODO (methodical)

- [ ] Complete `quantum_scheduler` runtime portability for pointer-width and arch assumptions
  - Remove remaining `u32` runtime assumptions in user process paths
- [ ] Implement user process scheduling on `x86_64` and `AArch64`
  - `add_user_process`, context creation, address-space activation, return path
- [ ] Replace bring-up AArch64 scheduler counters with full scheduler runtime integration
  - Timer IRQ -> shared scheduler tick -> actual preemption / switching across >1 runnable task
- [ ] Unify PID/process state transitions between scheduler and shared process backend
  - Remove bring-up-only compatibility shims and duplicate process bookkeeping
- [ ] Audit subsystem parity by arch (`vfs`, `wasm`, `usermode`, `ipc`, `capability`, `security`)
  - Build a "compiled / runtime-tested / unsupported" matrix per subsystem

### Exit criteria

- AArch64 runs multiple scheduled kernel tasks and at least one user task under shared scheduler.
- `vfs_platform` bridge behaves as adapter only, not a shadow process manager.
- Scheduler/process PID synchronization is fully driven by scheduler runtime paths (already started).

## Cross-Cutting Work (Required to Finish All Tracks)

- [ ] Make CI status machine-readable
  - Keep a single checklist/matrix file for parity status that CI/docs can reference.
- [ ] Add "definition of done" labels to `ThingsYetToDo/RelevancyNeeds.md`
  - Prevent vague claims of completion.
- [ ] Add release gating checklist
  - Build matrix, smoke matrix, extended regression, hardware matrix, known limitations.

## Execution Order (Recommended)

1. Stabilize validation first (extended CI + soak/fault scripts + artifacts).
2. Expand `x86_64` JIT backend opcode/runtime coverage so the x86_64 path is not stuck at subset-only JIT support (pairwise infrastructure for the current 14-bin generator is now in place and complete).
3. Port `AArch64` usermode + user process scheduler path.
4. Expand shared virtio drivers and real-board AArch64 bring-up.
5. Run nightly regressions long enough to establish confidence before changing README claims again.

## Completion Rule (for "Porting Done")

Do **not** mark "porting complete" until all are true:

- `x86_64` and `AArch64` have documented boot + shell + usermode execution paths
- shared scheduler/process backend runtime paths work on all supported arches
- driver matrix and hardware scope are explicit
- extended regressions run automatically and are stable
- unsupported/bring-up-only paths are clearly labeled in docs
