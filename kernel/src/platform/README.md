# `kernel/src/platform` — Architecture Abstraction & CPU Primitives

The `platform` module is the **hardware interface layer** of the Oreulius kernel. It owns every concern that must be written differently for different CPU architectures: the Global Descriptor Table, the Interrupt Descriptor Table, syscall dispatch, privilege-level transitions, and the lock-ordering DAG that prevents deadlocks across interrupt and scheduler contexts. Code in every other module that needs to route an interrupt, invoke a syscall, or enter userspace passes through this module.

---

## Design Philosophy

1. **Single point of privilege transition.** All paths from Ring-3 to Ring-0 — whether via `INT 0x80`, `SYSENTER`, x86-64 `SYSCALL`, or the AArch64 SVC exception — converge in `syscall.rs`. No other module handles privilege transitions.
2. **Deadlock-free by construction.** `interrupt_dag.rs` implements a compile-time topological priority system for spinlocks. A lock at level N can only be acquired from code running at level > N. Lock-order inversions are caught by the compiler, not at runtime.
3. **Minimal ISR surface.** Interrupt and exception stubs are generated uniformly. The stub saves minimal state, dispatches to a Rust handler, restores state, and returns. The heavy logic lives in `scheduler`, `security`, and `net` — not here.

---

## Source Layout

| File | Architecture | Lines | Role |
|---|---|---|---|
| `mod.rs` | All | 13 | Module re-exports |
| `gdt.rs` | x86 | 229 | Global Descriptor Table, Task State Segment setup |
| `idt_asm.rs` | x86 | 721 | Interrupt Descriptor Table structs (`IdtEntry`, `IdtPointer`), ISR/IRQ stub dispatch |
| `interrupt_dag.rs` | All | 164 | Compile-time deadlock-free spinlock DAG (`DagSpinlock`, `InterruptContext`) |
| `syscall.rs` | All | 1948 | `SyscallNumber` enum, `handle_syscall`, `SavedRegisters`, multi-arch dispatch |
| `usermode.rs` | All | 539 | `enter_user_mode_test`, `run_fork_test`, WASM module tracking |

---

## `gdt.rs` — Global Descriptor Table

Sets up the x86 GDT with five mandatory segments plus a TSS descriptor.

### GDT Segment Layout

| Index | Selector | Description |
|---|---|---|
| 0 | `0x00` | Null descriptor |
| 1 | `KERNEL_CS = 0x08` | Kernel code segment (Ring-0, DPL=0) |
| 2 | `KERNEL_DS = 0x10` | Kernel data segment (Ring-0) |
| 3 | `USER_CS = 0x1B` | User code segment (Ring-3, DPL=3) |
| 4 | `USER_DS = 0x23` | User data segment (Ring-3) |
| 5 | `TSS_SEL = 0x28` | Task State Segment descriptor |

### Task State Segment (`Tss`)

The TSS holds the Ring-0 stack pointer (`esp0`/`ss0`) that the CPU loads automatically when an interrupt or syscall arrives from Ring-3.

`gdt::init()`:
1. Fills the GDT with the six entries above.
2. Writes the GDT pointer and calls `LGDT`.
3. Reloads all segment registers (`CS` via far-jump, `DS/ES/FS/GS/SS` via `MOV`).
4. Initialises the TSS with the kernel data stack base.
5. Calls `tss_load(TSS_SEL)` to install the TSS into TR.

---

## `idt_asm.rs` — Interrupt Descriptor Table

### `IdtEntry` Layout

```text
struct IdtEntry {
  base_low: u16     — handler address bits 0–15
  selector: u16     — code segment (KERNEL_CS)
  zero: u8          — reserved, must be 0
  flags: u8         — type + DPL + present bit
  base_high: u16    — handler address bits 16–31
}
```

`set_handler(handler, selector, flags)` packs a handler address into the split low/high fields.

### `IdtPointer`

`{ limit: u16, base: u32 }` — passed to `LIDT` instruction. `limit = (IDT_ENTRIES × 8) - 1`.

### ISR and IRQ Stub Strategy

Every exception and IRQ entry point is a small assembly stub that:
1. Pushes an error code (or a zero pad for exceptions that don't push one automatically).
2. Pushes all GPRs (`PUSHA`).
3. Calls the Rust handler.
4. Pops all GPRs (`POPA`).
5. Returns with `IRET`.

Stubs for exceptions `isr0..isr31` handle CPU exceptions (divide-by-zero, page fault, general protection, etc.). Stubs for `irq0..irq15` handle hardware interrupt lines:

| IRQ | Device | Handler |
|---|---|---|
| `irq0` | PIT timer | `pit::tick()` + `scheduler::on_timer_tick()` |
| `irq1` | PS/2 keyboard | Keyboard input handler |
| `irq3` | COM2 serial | Serial debug port |
| `irq4` | COM1 serial | Serial console |
| `irq9` | PCI/ACPI | General PCI line |
| `irq11` | RTL8139/e1000 | Network card RX |
| `irq14..15` | ATA/IDE | Storage interrupts |

After the PIC-based handler finishes it sends the End-of-Interrupt (`EOI`) command to the PIC controller (`outb 0x20, 0x20` for master; `outb 0xA0, 0x20` for slave IRQs ≥ 8).

The IDT table is a static 256-entry `[IdtEntry; 256]` owned by `idt_asm.rs`. `idt_asm::init()` installs all handlers and calls `LIDT`.

---

## `interrupt_dag.rs` — Compile-Time Deadlock-Free Spinlock DAG

This is one of Oreulius's most unusual kernel-level innovations. Every spinlock in the kernel carries a **compile-time priority level constant**. The `DagSpinlock<LEVEL, T>` type, combined with `InterruptContext<LEVEL>`, enforces at monomorphization time that a lock at level N can only be acquired from an execution context at level > N.

### Priority Levels

| Constant | Value | Assigned To |
|---|---|---|
| `DAG_LEVEL_VFS` | `5` | VFS / flat-FS spinlocks |
| `DAG_LEVEL_THREAD` | `8` | Per-thread state locks |
| `DAG_LEVEL_SCHEDULER` | `10` | Scheduler process table |
| `DAG_LEVEL_SYSCALL` | `15` | Syscall handler context |
| `DAG_LEVEL_IRQ` | `20` | Hardware interrupt handlers |

A lock at level 5 (VFS) can be acquired from level 10 (scheduler). It can **NOT** be acquired from level 4 or lower. Attempting to do so produces a compiler error:

```
DEADLOCK PREVENTED: acquire_lock target level must be strictly less than context level
```

### How It Works

```rust
struct AssertLt<const A: u8, const B: u8>;
impl<const A: u8, const B: u8> AssertLt<A, B> {
    const VALID: () = assert!(A < B, "DEADLOCK PREVENTED: ...");
}
```

`InterruptContext::acquire_lock::<TARGET_LEVEL, T, F, R>()` evaluates `AssertLt::<TARGET_LEVEL, LEVEL>::VALID` eagerly during monomorphization. If `TARGET_LEVEL >= LEVEL` the crate does not compile.

Additionally, `acquire_lock` **disables hardware interrupts** for the duration of the closure using `IrqGuard` (which saves and restores RFLAGS / DAIF). This prevents the classic spin-deadlock where an IRQ handler tries to acquire a lock already held by the interrupted code on the same CPU core.

### Types

| Type | Description |
|---|---|
| `DagSpinlock<LEVEL, T>` | A `spin::Mutex<T>` with an attached compile-time level constant |
| `InterruptContext<LEVEL>` | A zero-size proof token that the current code is executing at `LEVEL` |
| `IrqGuard` | RAII guard that disables interrupts on construction, restores on drop |

`InterruptContext` tokens are created only in architecture-level interrupt entry points (`irq_context()`) and scheduler/VFS bootstrap helpers (`syscall_context()`, `thread_context()`). Arbitrary kernel code cannot construct them — the API enforces this through `unsafe fn new()`.

---

## `syscall.rs` — System Call Dispatch

The unified syscall layer that handles all privilege-level transitions on all supported architectures.

### Entry Points

| Entry Point | Architecture | Mechanism |
|---|---|---|
| `sysenter_handler_rust` | x86 | `SYSENTER` instruction (fast system call, Intel) |
| `syscall_handler_rust` | x86-64 | `SYSCALL` instruction (AMD64 ABI) |
| `oreulius_syscall_dispatch` | x86 | `INT 0x80` (legacy interrupt-based) |
| `aarch64_syscall_from_exception` | AArch64 | `SVC #0` exception vector |

All four paths converge at `handle_syscall(args, caller_pid)` after normalising arguments into `SyscallArgs`.

### `SyscallArgs`

All architectures pass syscall arguments in the same logical positions; the per-arch entry stubs translate registers to this struct:

```rust
struct SyscallArgs {
    number: u32,   // EAX / x0 / R7
    arg1: u32,     // EBX / x1 / R1
    arg2: u32,     // ECX / x2 / R2
    arg3: u32,     // EDX / x3 / R3
    arg4: u32,     // ESI / x4
    arg5: u32,     // EDI / x5
}
```

### `SyscallNumber` — Full ABI

| Group | Number | Name | Description |
|---|---|---|---|
| Process | 0 | `Exit` | Terminate the calling process |
| Process | 1 | `Fork` | Clone the calling process |
| Process | 2 | `Yield` | Voluntary scheduler yield |
| Process | 3 | `GetPid` | Return the calling process's PID |
| Process | 4 | `Sleep` | Sleep for N milliseconds |
| Process | 5 | `Exec` | Replace current process image |
| IPC | 10 | `ChannelCreate` | Create an IPC channel pair |
| IPC | 11 | `ChannelSend` | Send a message on a channel |
| IPC | 12 | `ChannelRecv` | Receive a message from a channel |
| IPC | 13 | `ChannelClose` | Close a channel endpoint |
| IPC | 14 | `ChannelSendCaps` | Send a message with capability transfer |
| IPC | 15 | `ChannelRecvCaps` | Receive a message with capability transfer |
| FS | 20 | `FileOpen` | Open a VFS file |
| FS | 21 | `FileRead` | Read from a file descriptor |
| FS | 22 | `FileWrite` | Write to a file descriptor |
| FS | 23 | `FileClose` | Close a file descriptor |
| FS | 24 | `FileDelete` | Delete a VFS file |
| FS | 25 | `DirList` | List a directory |
| Memory | 30 | `MemoryAlloc` | Allocate heap pages |
| Memory | 31 | `MemoryFree` | Free heap pages |
| Memory | 32 | `MemoryMap` | Map anonymous or file-backed memory |
| Memory | 33 | `MemoryUnmap` | Unmap a region |
| Capability | 40 | `CapabilityGrant` | Transfer a capability to another process |
| Capability | 41 | `CapabilityRevoke` | Revoke a capability |
| Capability | 42 | `CapabilityQuery` | Query capability rights |
| Capability | 43 | `CapabilityRevokeForPid` | Privileged cross-PID revocation (Math Daemon only, PMA §6.2) |
| Console | 50 | `ConsoleWrite` | Write to the console |
| Console | 51 | `ConsoleRead` | Read from the console |
| WASM | 60 | `WasmLoad` | Load and instantiate a WASM module |
| WASM | 61 | `WasmCall` | Call a function in a loaded WASM module |
| WASM | 62 | `ServicePointerRegister` | Register a service function pointer |
| WASM | 63 | `ServicePointerInvoke` | Invoke a registered service pointer |
| WASM | 64 | `ServicePointerRevoke` | Revoke a service pointer |
| JIT | 250 | `JitReturn` | Return from a JIT-compiled function |
| — | 0xFFFFFFFF | `Invalid` | Unknown syscall number |

`CapabilityRevokeForPid` is a privileged system call that can only be issued by the process with `PID == MATH_DAEMON_PID`. Any other caller receives `PermissionDenied`. This is the mechanism by which the out-of-band telemetry daemon sends adaptive revocations back into the kernel.

### `MemoryMap` ABI

`MemoryMap` (`32`) uses the shared five-argument syscall frame:

| Arg | Meaning |
|---|---|
| `arg1` | Requested address, or `0` for kernel-chosen placement |
| `arg2` | Mapping length in bytes |
| `arg3` | Protection mask (`READ=1`, `WRITE=2`, `EXEC=4`) |
| `arg4` | Mapping flags |
| `arg5` | Anonymous: `0`. File-backed: packed `(offset_pages << 16) | fd` |

Defined flag bits:

| Flag | Bit | Meaning |
|---|---|---|
| `MAP_ANONYMOUS` | `1 << 0` | Create an anonymous mapping |
| `MAP_SHARED` | `1 << 1` | Request shared/writeback file semantics |

Current semantics:

- `MAP_ANONYMOUS` routes to anonymous user mappings.
- Without `MAP_ANONYMOUS`, the kernel resolves `fd` to a VFS file source and installs a lazy `VmaKind::File` mapping.
- File-backed mappings are fault-filled a page at a time from either in-memory VFS files or mounted VFS files.
- `MAP_SHARED|PROT_WRITE` mappings are flushed back to the underlying file on unmap and on process teardown.
- Shared mappings currently provide writeback semantics, not coherent multi-process shared-page semantics.
- Raw block / virtio raw handles are rejected for file-backed `MemoryMap`.

### `SavedRegisters`

The syscall entry stubs push a `SavedRegisters` frame onto the kernel stack before calling `handle_syscall`. The layout is architecture-specific:

- **x86**: `pusha`-style frame (`edi, esi, ebp, esp, ebx, edx, ecx, eax`) + `cs, ds, eip, eflags`
- **x86-64**: all 15 GPRs + `rip, rflags, rsp, ss`
- **AArch64**: `x0..x30, sp, pc, pstate`

### `SyscallStats`

`syscall::get_stats()` returns a `SyscallStats` snapshot:

| Field | Description |
|---|---|
| `total_calls` | Total syscall invocations |
| `by_number[256]` | Per-syscall-number call count |
| `permission_denials` | Total `PermissionDenied` results |
| `invalid_calls` | Total `Invalid` syscall numbers received |

---

## `usermode.rs` — Privilege Transition Tests

Provides `enter_user_mode_test()` and `run_fork_test()` helpers used from the kernel shell to validate Ring-3 entry and process forking. These are debug/validation entry points — not part of the production process creation path (which goes through `process_manager().create()` + `slice_scheduler::init()`).

`set_current_wasm_module(id)` / `current_wasm_module()` track which WASM module the current process is executing in, used by the WASM sandbox to correctly restore context on WASI syscall return.
