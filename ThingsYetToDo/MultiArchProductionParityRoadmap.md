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

## 5. AArch64 Implementation Program (Dependency Ordered)

### Reality check

The AArch64 path is no longer blocked on first-stage boot code. The boot/runtime
base already exists:

- `kernel/src/lib.rs` has a real `rust_main_aarch64_bringup()` path.
- `kernel/src/arch/aarch64_virt.rs` already covers DTB parsing, PL011, vectors,
  GICv2, timer IRQs, and `virtio-mmio` bring-up diagnostics.
- `kernel/src/arch/mmu_aarch64.rs` is already a real MMU backend, not a placeholder.

The main remaining blockers are different:

- `kernel/src/lib.rs` still compiles out too much of the shared kernel behind
  `#[cfg(not(target_arch = "aarch64"))]`.
- `kernel/src/process_platform.rs` still treats AArch64 process lifecycle hooks
  as no-ops.
- `kernel/src/quantum_scheduler.rs` and `kernel/src/vfs_platform.rs` still rely on
  AArch64 bring-up bridge paths for process creation and synchronization.
- `kernel/src/asm/aarch64_scheduler.S` still documents bring-up-grade scheduler
  assumptions that need to be removed before claiming runtime parity.

This means the remaining AArch64 work is primarily shared-kernel integration,
runtime normalization, and user-mode completion, not fresh board bring-up.

### Phase A: Expand the AArch64 compile surface

- Audit every `#[cfg(not(target_arch = "aarch64"))]` gate in `kernel/src/lib.rs`.
- Re-enable platform-neutral or mostly platform-neutral modules first:
  - `capability`
  - `security`
  - `registry`
  - `replay`
  - `temporal`
  - `crypto`
  - `ipc`
  - `fs`
  - `wasm`
- Keep genuinely x86-only modules gated until later:
  - `gdt`
  - `idt_asm`
  - `pci`
  - `e1000`
  - `pit`
  - legacy VGA/framebuffer/input paths
- Where AArch64-specific backends are missing, add temporary explicit
  unsupported stubs only for those narrow interfaces instead of compiling out
  entire shared subsystems.

### Phase A exit criteria

- `cargo check --target aarch64-unknown-none` fails only on intentionally
  unsupported drivers or explicitly deferred features, not on core shared
  subsystems.
- `kernel/src/lib.rs` no longer defines AArch64 as a reduced kernel build by default.

### Phase B: Replace bring-up bridges with normal runtime paths

- Remove `aarch64_register_default_shared_process_bridge()` from the steady-state
  AArch64 boot/runtime path once the shared process backend can run natively.
- Eliminate `aarch64_spawn_process()` fallback use from
  `kernel/src/quantum_scheduler.rs`.
- Convert `vfs_platform`'s AArch64 process synchronization from a shadow process
  manager into a thin adapter only.
- Keep the serial shell, but make it a normal consumer of shared runtime paths
  rather than an alternate AArch64-only execution model.

### Phase B exit criteria

- Shared scheduler/process bookkeeping owns PID and task lifecycle on AArch64.
- `vfs_platform` is no longer carrying AArch64-specific shadow process state.

### Phase C: Implement real process lifecycle integration

- Implement `on_process_spawn()` in `kernel/src/process_platform.rs` for AArch64.
- Implement `on_process_terminate()` in `kernel/src/process_platform.rs` for AArch64.
- Implement `on_process_restore_spawn()` in `kernel/src/process_platform.rs` for AArch64.
- Ensure these hooks initialize and tear down:
  - capability state
  - security state
  - temporal process events
  - IPC/process-owned runtime resources once `ipc` is enabled
- Remove temporary AArch64-only placeholder process/capability behavior as shared
  subsystem support lands.

### Phase C exit criteria

- Process lifecycle side effects are architecture-neutral.
- AArch64 process creation and termination participate in the same capability,
  security, and temporal model as the other active arches.

### Phase D: Harden scheduler and preemption

- Remove bring-up assumptions from `kernel/src/asm/aarch64_scheduler.S`.
- Validate that kernel threads do not fault before first scheduled entry.
- Ensure timer IRQs drive the shared scheduler tick on AArch64, not a
  bring-up-only compatibility hook.
- Exercise multiple runnable kernel tasks, wait/wake, blocking paths, and
  scheduler-driven task transitions under load.

### Phase D exit criteria

- AArch64 runs the shell plus background kernel tasks under the shared scheduler.
- Preemption, wakeups, and timer-driven scheduling work without AArch64-only
  compatibility shims.

### Phase E: Add syscall and EL0 user-mode parity

- Enable `syscall` on AArch64 in the normal crate build.
- Implement the AArch64 EL0 entry/return path and saved-register ABI.
- Support one real AArch64 user task path through the shared scheduler/runtime.
- First milestone should stay narrow:
  - `yield`
  - `sleep`
  - `exit`
  - one syscall smoke path
  - one user-process smoke path
- Do not block this phase on `fork_current_cow()` support.

### Phase E exit criteria

- At least one AArch64 user task executes at EL0 and returns through the shared
  scheduler/syscall path.
- No AArch64 user execution path is silently routed through a bring-up shell-only fallback.

### Phase F: Re-enable shared subsystem parity

- Bring up shared runtime subsystems in this order:
  - `ipc`
  - `vfs`
  - `temporal`
  - `registry`
  - `wasm`
  - `net_reactor`
  - `netstack`
- Use `virtio-mmio` as the canonical AArch64 backend for block and network work.
- Do not block AArch64 parity on PCI or `e1000`.
- Collapse remaining AArch64 command-surface caveats so `commands_shared` is the
  real user-facing shell surface.

### Phase F exit criteria

- AArch64 shared subsystems compile and have runtime smoke coverage.
- The shell surface is shared-first, not bring-up-first.

### Phase G: Complete the remaining 64-bit follow-ons

- Add a real ELF64/AArch64 exec path in `kernel/src/elf.rs`.
- Either implement AArch64 `fork_current_cow()` or mark it as an explicit,
  tested, documented non-goal for the current milestone.
- Add an AArch64 WASM execution mode that is not ambiguous:
  - interpreter-only and fully documented, or
  - real JIT/user-entry support with CI.

### Phase G exit criteria

- AArch64 has a documented 64-bit execution story, not only a shell/runtime story.
- README status can move beyond "bring-up/runtime parity in progress" language.

### AArch64 non-goals for the first honest completion claim

- Do not require PCI/e1000 parity before claiming AArch64 QEMU `virt` runtime parity.
- Do not require real-board support before the shared-kernel AArch64 runtime path is complete in QEMU.
- Do not require full JIT opcode parity before claiming AArch64 support if the
  interpreter path is first-class, documented, and CI-tested.
- Do not block initial AArch64 completion on `fork_current_cow()` if the user-mode
  and syscall model is otherwise real and the limitation is explicit.

## Cross-Cutting Work (Required to Finish All Tracks)

- [ ] Make CI status machine-readable
  - Keep a single checklist/matrix file for parity status that CI/docs can reference.
- [ ] Add "definition of done" labels to `ThingsYetToDo/RelevancyNeeds.md`
  - Prevent vague claims of completion.
- [ ] Add release gating checklist
  - Build matrix, smoke matrix, extended regression, hardware matrix, known limitations.

## Execution Order (Recommended)

1. Stabilize validation first (extended CI + soak/fault scripts + artifacts).
2. Execute AArch64 Phase A through Phase C first:
   - expand the compile surface
   - remove bridge dependencies
   - implement real process lifecycle hooks
3. Execute AArch64 Phase D through Phase F next:
   - harden scheduler/preemption
   - add EL0/syscall path
   - restore shared subsystem parity
4. Expand `x86_64` JIT backend opcode/runtime coverage so the x86_64 path is not stuck at subset-only JIT support (pairwise infrastructure for the current 14-bin generator is now in place and complete).
5. Expand shared virtio drivers and then real-board AArch64 bring-up.
6. Run nightly regressions long enough to establish confidence before changing README claims again.

## Completion Rule (for "Porting Done")

Do **not** mark "porting complete" until all are true:

- `x86_64` and `AArch64` have documented boot + shell + usermode execution paths
- shared scheduler/process backend runtime paths work on all supported arches
- driver matrix and hardware scope are explicit
- extended regressions run automatically and are stable
- unsupported/bring-up-only paths are clearly labeled in docs
