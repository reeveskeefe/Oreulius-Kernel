# `kernel/src/scheduler` — Preemptive Process Scheduler

The `scheduler` module is the **execution engine of the Oreulius kernel**. It owns every concern related to process lifecycle, multi-level priority scheduling, timer-driven preemption, blocking and wakeup primitives, context switching, FPU state management, and the persistent temporal snapshot of all in-flight process state. All other kernel subsystems that need to yield, sleep, block, or spawn must go through this module.

---

## Design Overview

The scheduler is a **multi-level feedback queue (MLFQ) preemptive scheduler** with the following properties:

- **Three priority levels** (`High`, `Normal`, `Low`) with separate ready queues; a process dropped from High will re-enter at Normal after consuming its full timeslice.
- **Slice decay**: each priority level has a fixed timeslice in PIT ticks. A process that voluntarily yields early is rewarded; one that burns its entire timeslice is demoted.
- **Entropy scheduling (PMA §3)**: each `ProcessInfo` tracks EWMA yield density and page-fault density. The scheduler uses these to distinguish CPU-bound processes from I/O-bound ones and adjusts scheduling pressure accordingly.
- **Lazy FPU (PMA §5.1)**: FPU/SIMD registers are not saved on every context switch. A `CR0.TS` trap fires on first FPU use; `handle_fpu_trap()` saves the owner's state, restores the new process's state (if any), and clears the trap bit.
- **Futex-like wait queues**: up to `MAX_WAIT_QUEUES = 64` wait queues keyed by arbitrary `usize` addresses allow processes to block on mutexes, IPC channels, and timer wakeups without polling.

---

## Source Layout

| File | Architecture | Lines | Role |
|---|---|---|---|
| `mod.rs` | All | 22 | Module re-exports |
| `pit.rs` | All | 141 | Programmable Interval Timer — 100 Hz tick source |
| `process.rs` | All | 939 | `Process` PCB, `ProcessTable`, `ProcessManager`, capability table, `ProcessState`, `ProcessPriority` |
| `process_asm.rs` | x86 | 390 | `TaskContext`, `fast_context_switch`, `enter_user_mode`, TSS helpers (extern "C" assembly bindings) |
| `process_platform.rs` | x86 | 53 | `Pid` newtype and platform-specific process helpers |
| `slice_scheduler.rs` | All | 3153 | `SliceScheduler` — MLFQ, wait queues, entropy scheduling, temporal persistence |
| `scheduler.rs` | All | 604 | `Scheduler` facade, `SchedulerStats`, global instance, `on_timer_tick` |
| `scheduler_platform.rs` | All | 615 | `ProcessContext`, `IrqFlags`, `irq_save_disable`, `irq_restore` — arch-specific context/IRQ primitives |
| `scheduler_runtime_platform.rs` | All | 106 | Runtime platform helpers used within `slice_scheduler.rs` |
| `tasks.rs` | All | 233 | High-level task spawning helpers |

---

## `pit.rs` — Programmable Interval Timer

The PIT (Intel 8253/8254 compatible) is the tick source for all scheduler preemption on x86. On aarch64 the generic timer (`cntpct_el0`) is used instead.

### Configuration

| Constant | Value | Description |
|---|---|---|
| `PIT_FREQUENCY` | `1193182 Hz` | PIT crystal oscillator frequency |
| `TIMER_HZ` | `100 Hz` | Target interrupt frequency |
| `divisor` | `11931` | PIT reload value (`PIT_FREQUENCY / TIMER_HZ`) |

The PIT is programmed in mode 2 (rate generator): command byte `0x36` written to `I/O port 0x43`, then divisor low/high bytes to `I/O port 0x40`.

### Tick Counter

The global tick counter is split across two `AtomicU32` values (`TICKS_LO` + `TICKS_HI`) to provide a 64-bit counter without a 64-bit atomic. `get_ticks()` reads both with a retry loop to avoid a torn read across the `TICKS_LO` overflow boundary.

### API

| Function | Description |
|---|---|
| `init()` | Program the PIT divisor; no-op on aarch64 |
| `tick()` | Called by IRQ0 handler; increments tick counter |
| `get_ticks() -> u64` | Return current monotonic tick count |
| `try_get_ticks() -> Option<u64>` | Non-blocking `get_ticks` (always `Some`) |
| `get_frequency() -> u32` | Return `100` on x86; aarch64 generic timer Hz on AArch64 |
| `sleep_ms(ms)` | Busy-wait for N milliseconds (HLT on x86, spin on aarch64) |

---

## `process.rs` — Process Control Block

### Capacity Constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_PROCESSES` | `64` | Maximum concurrent processes |
| `MAX_CAPS_PER_PROCESS` | `128` | Maximum capability slots per process |
| `MAX_FD` | `32` | File descriptor table size (fd 0..2 reserved for stdio) |
| `STACK_SIZE` | `65536 bytes` (64 KiB) | Per-process stack allocation |

### `ProcessState`

| State | Description |
|---|---|
| `Ready` | Queued in a ready queue, waiting for CPU |
| `Running` | Currently executing on CPU |
| `Blocked` | Waiting on a resource (I/O, timer, wait queue) |
| `WaitingOnChannel` | Blocked on an IPC channel `recv` |
| `Terminated` | Exited; slot retained for parent `wait()` |

### `ProcessPriority`

| Variant | Value | Timeslice |
|---|---|---|
| `High` | `3` | `SLICE_HIGH = 20` ticks (200 ms) |
| `Normal` | `2` | `SLICE_NORMAL = 10` ticks (100 ms) |
| `Low` | `1` | `SLICE_LOW = 5` ticks (50 ms) |

### `Process` (PCB)

| Field | Type | Description |
|---|---|---|
| `pid` | `Pid` | Process identifier |
| `name` | `[u8; 32]` | Null-terminated ASCII name |
| `state` | `ProcessState` | Current lifecycle state |
| `priority` | `ProcessPriority` | Scheduling priority class |
| `parent` | `Option<Pid>` | Parent PID (`None` for `init`) |
| `capabilities` | `CapabilityTable` | 128-slot capability store |
| `stack_ptr` | `usize` | Saved stack pointer |
| `program_counter` | `usize` | Saved instruction pointer |
| `cpu_time` | `u64` | Total CPU ticks consumed |
| `created_at` | `u64` | PIT tick at creation |
| `fd_table` | `[Option<u64>; 32]` | File descriptor table |
| `page_dir_phys` | `PhysAddr` | Physical address of page-table root (`0` = not set) |
| `fpu_state` | `FpuState([u8; 512])` | 16-byte-aligned FXSAVE/FXRSTOR buffer |
| `has_used_fpu` | `bool` | Whether FPU has been touched (lazy init) |

### `CapabilityVariant`

A process's capability table holds `StoredCapability` entries that may be:

| Variant | Description |
|---|---|
| `Channel(ChannelCapability)` | IPC channel send/recv rights |
| `Filesystem { cap_id, rights }` | VFS access rights |
| `Generic { cap_id, ... }` | Arbitrary capability type |

### `ProcessManager`

Global singleton accessed via `process_manager()`. Wraps a `ProcessTable`
(fixed array of `MAX_PROCESSES` `Option<Process>` slots) and provides:

| Method | Description |
|---|---|
| `create(name, parent)` | Allocate a PCB, assign a `Pid`, set state to `Ready` |
| `get(pid)` | Borrow a process slot |
| `get_mut(pid)` | Mutably borrow a process slot |
| `terminate(pid)` | Mark process `Terminated` |
| `current_pid()` | Return the currently running `Pid` |

### `ProcessError`

| Variant | Description |
|---|---|
| `TooManyProcesses` | `MAX_PROCESSES` reached |
| `ProcessNotFound` | `Pid` does not exist |
| `InvalidState` | Operation invalid for current `ProcessState` |
| `FdTableFull` | No free file descriptor slots |
| `CapabilityTableFull` | No free capability slots |
| `InvalidFd` | File descriptor out of range or unallocated |
| `PermissionDenied` | Insufficient rights |

---

## `process_asm.rs` — Context Switch Assembly Bindings

Low-level `extern "C"` bindings to x86 assembly routines.

### `TaskContext` — CPU Register Save Frame

```text
struct TaskContext {
  esp, ebp, ebx, esi, edi  — callee-saved registers
  eip                       — return address / instruction pointer
  eflags                    — CPU flags (initial: 0x202 = IF set)
  cr3                       — page directory physical address
}
```

### Assembly Externals

| Function | Description |
|---|---|
| `tss_load(tss_selector)` | Load the Task State Segment selector into TR |
| `tss_set_kernel_stack(tss, esp0, ss0)` | Set the Ring-0 stack pointer in the TSS |
| `tss_get_esp0(tss)` | Read the current TSS Ring-0 stack pointer |
| `fast_context_switch(from, to)` | Save callee-saved registers + EIP + EFLAGS + CR3 into `from`; restore from `to`; returns to `to.eip` |
| `enter_kernel_mode()` | Jump to kernel privilege level |
| `enter_user_mode(esp, eip, cs, ds)` | IRET to userspace at the specified CS:EIP with DS segment |

`fast_context_switch` is the hot path — it is called on every voluntary yield and every preemptive context switch. It saves only the callee-saved registers (matching the C ABI), not the full GPR set. The caller (interrupt handler or yield path) saves caller-saved registers before calling it.

---

## `slice_scheduler.rs` — MLFQ Core

The 3153-line heart of the scheduler. Contains `SliceScheduler`, its ready/wait queue machinery, entropy scheduling state, block/wake primitives, and temporal persistence.

### `SliceScheduler` Fields

| Field | Description |
|---|---|
| `processes` | `[Option<ProcessInfo>; MAX_PROCESSES]` — all PCB+context pairs |
| `current_pid` | Currently running process |
| `fpu_owner` | Which process currently holds live FPU registers |
| `ready_queues` | `[ReadyQueue; 3]` — one per priority level (`Low=0`, `Normal=1`, `High=2`) |
| `wait_queues` | `[WaitQueue; MAX_WAIT_QUEUES]` — futex-style wait queues |
| `stats` | `SchedulerStats` — switch/preemption counters |

### `ProcessInfo` — Extended Scheduling State

On top of the base `Process` PCB, each `ProcessInfo` adds:

| Field | Description |
|---|---|
| `context` | `ProcessContext` — arch-specific saved register state |
| `kernel_stack_top` | Top of per-process Ring-0 entry stack |
| `stack` | `Option<Box<[u8; STACK_SIZE]>>` — kernel stack allocation |
| `address_space` | `Option<Box<AddressSpace>>` — user address space (None for kernel threads) |
| `slice_remaining` | Ticks left in current scheduling slot |
| `total_cpu_time` | Lifetime CPU ticks |
| `total_wait_time` | Lifetime ticks spent waiting |
| `last_scheduled` | PIT tick at last schedule-in |
| `switches` | Total context switches into this process |
| `yield_count` | Cooperative yield counter (reset per window) |
| `pagefault_count` | Page-fault counter (kernel-side accounting) |
| `ewma_yield` | EWMA of yield density: `(ewma × 7 + sample) >> 3` |
| `ewma_fault` | EWMA of fault density |
| `has_used_fpu` | First-use FPU flag |
| `fpu_dirty` | FPU registers contain unsaved state for this process |
| `fpu_state` | `ExtFpuState` — 2816-byte XSAVE/XRSTOR area (covers full AVX-512 on x86-64; Q0–Q31/FPSR/FPCR on AArch64) |

### Slice Sizing

| Priority | Constant | Value | Wall-Clock |
|---|---|---|---|
| High | `SLICE_HIGH` | 20 ticks | 200 ms |
| Normal | `SLICE_NORMAL` | 10 ticks | 100 ms |
| Low | `SLICE_LOW` | 5 ticks | 50 ms |

Stack sizes are capped on 32-bit x86 targets:

| Target | `KERNEL_THREAD_STACK_BYTES` |
|---|---|
| `target_arch = "x86"` | 256 KiB |
| all others | 1 MiB |

### Kernel Stacks

Four statically allocated 4096-byte-aligned stacks (`KERNEL_STACK_0..3`) are provided for kernel threads that do not have a heap-allocated stack (e.g., IRQ handlers, init thread). Heap-backed `Box<[u8; STACK_SIZE]>` stacks are used for forked/user processes.

### Block/Wake Primitives

The scheduler implements a futex-style block/wake interface:

| Function | Description |
|---|---|
| `block_on(addr)` | Block the current process on a wait queue keyed by `addr` |
| `prepare_block_on(addr, state)` | Multi-step block: save IRQ state, return `BlockOnPlan` |
| `prepare_block_custom(state)` | Block on a custom `ProcessState` |
| `commit_block(plan)` | Actually transition the process to blocked and reschedule |
| `wake_process(pid)` | Wake a specific process by PID |
| `wake_one(addr)` | Wake the first waiter on a wait queue address |
| `wake_all(addr)` | Wake all waiters on a wait queue address |
| `waiter_count(addr)` | Query the number of processes waiting on an address |
| `sleep_until(pid, wake_time)` | Block until a specific tick (timer sleep) |
| `yield_now()` | Voluntary yield — process returns to back of ready queue |
| `enqueue_ready_pid(pid, priority)` | Add a PID to the appropriate ready queue |

`BlockOnPlan` uses `Drop` to restore IRQ flags if not committed — preventing IRQ leaks on error paths.

### Entropy Benchmarking

`EntropyBenchResult` and `entropy_bench_results()` provide runtime measurements of the scheduler's entropy sources (yield density and fault density statistics). These are used by the security module's intent graph to calibrate anomaly baselines.

### Temporal Persistence

The scheduler participates in the temporal snapshot system. `temporal_apply_scheduler_payload(payload)` restores scheduler state from a temporal log entry. The binary format is:

| Section | Bytes | Content |
|---|---|---|
| Header | 60 | Schema version, process count, wait queue count, tick, stats |
| Per-process | 44 × N | Pid, state, priority, cpu_time, wait_time, slice_remaining |
| Wait queue header | 12 × M | Address, waiter count, active flag, wake_time |

### Shell Commands

| Command | Description |
|---|---|
| `ps` | List all processes with state, priority, CPU time |
| `kill <pid>` | Terminate a process |
| `scheduler-stats` | Print `SchedulerStats` (switches, preemptions, yields) |
| `sched-overview` | Print `SchedulerOverview` (live per-state counts) |
| `sleep <ms>` | Sleep the shell process for N milliseconds |
| `yield` | Voluntary yield from the shell |

---

## `scheduler.rs` — Facade and Global Instance

Wraps `SliceScheduler` in a `DagSpinlock<DAG_LEVEL_SCHEDULER>` for deadlock-safe access from IRQ handlers and syscall context. The `Scheduler` struct in this file serves as the minimal non-`SliceScheduler` facade used during early boot before the full scheduler is initialised.

| Global | Type | Description |
|---|---|---|
| `SCHEDULER` | `DagSpinlock<DAG_LEVEL_SCHEDULER, Scheduler>` | The primary scheduler lock |

| Function | Description |
|---|---|
| `scheduler()` | Return reference to the global `DagSpinlock` |
| `on_timer_tick()` | Called by PIT IRQ handler — tick timeslice, preempt if expired |
| `maybe_reschedule()` | Called at syscall return — yield if a higher-priority process is ready |
| `yield_cpu()` | Public yield entry point |
| `sleep(ms)` | Public sleep entry point |
