# `kernel/src/asm` — Assembly Layer

The `asm` directory is the lowest layer of the Oreulia kernel: hand-written assembly that provides the primitives the Rust kernel cannot express portably or efficiently. It covers three target architectures (i686, x86-64, AArch64) and is organised into two generations of files — a legacy 32-bit layer (bare filenames such as `context_switch.asm`, `process.asm`) plus architecture-prefixed 64-bit successors (`x86_64_shims.asm`, `x86_64_atomics.asm`, …; `aarch64_*.S`). The 32-bit files are still live for the `i686-oreulia` target; the 64-bit files are linked for all x86-64 builds.

All `.asm` files target NASM syntax. The two `.S` files target GAS (GNU Assembler) and are used exclusively for the AArch64 target.

---

## Table of Contents

1. [File Map](#file-map)
2. [Boot Infrastructure](#boot-infrastructure)
3. [AArch64 Vectors and Scheduler](#aarch64-vectors-and-scheduler)
4. [Context Switch and Per-Arch Scheduler Shims](#context-switch-and-per-arch-scheduler-shims)
5. [GDT and IDT](#gdt-and-idt)
6. [Interrupt and I/O Control](#interrupt-and-io-control)
7. [Syscall and Sysenter Paths](#syscall-and-sysenter-paths)
8. [Atomics and Spinlocks](#atomics-and-spinlocks)
9. [Memory Primitives](#memory-primitives)
10. [Copy-on-Write and Page Management](#copy-on-write-and-page-management)
11. [FPU and SIMD Context](#fpu-and-simd-context)
12. [CPU Feature Detection](#cpu-feature-detection)
13. [Performance Counters and Microbenchmarks](#performance-counters-and-microbenchmarks)
14. [Cryptographic Primitives](#cryptographic-primitives)
15. [Hash and Endian Utilities](#hash-and-endian-utilities)
16. [Temporal Log Helpers](#temporal-log-helpers)
17. [Network Packet Parsing](#network-packet-parsing)
18. [DMA Engine](#dma-engine)
19. [ACPI Power Management](#acpi-power-management)
20. [SGX Enclave Primitives](#sgx-enclave-primitives)
21. [PIC 8259A Control](#pic-8259a-control)
22. [Capability Graph SIMD Scanner](#capability-graph-simd-scanner)
23. [x86-64 Unified Shims](#x86-64-unified-shims)
24. [Process Utilities (32-bit)](#process-utilities-32-bit)
25. [Legacy and x86-64 Dual-File Guide](#legacy-and-x86-64-dual-file-guide)

---

## File Map

| File | Lines | Arch | Role |
|---|---|---|---|
| `boot.asm` | 79 | x86 | Multiboot1 entry: BSS clear, VGA init, `rust_main` call |
| `boot_x86_64_mb2.asm` | 193 | x86-64 | Multiboot2 entry: BSS clear, 64-bit mode, `rust_main` call |
| `boot_aarch64_virt.S` | 49 | AArch64 | QEMU virt entry: DTB handoff, BSS clear, `rust_main` call |
| `aarch64_vectors.S` | 122 | AArch64 | 2 KiB VBAR_EL1 table; 16-slot GPR save/restore; dispatch to Rust |
| `aarch64_scheduler.S` | 139 | AArch64 | Callee-save context switch, thread and user-entry trampolines |
| `gdt.asm` | 25 | x86 | `gdt_load` via `lgdt` |
| `idt.asm` | 600 | x86 | IDT: `idt_load`, `idt_set_gate`, isr0–31, irq0–15, PIC, APIC, NMI |
| `interrupt.asm` | 131 | x86 | Interrupt control, CR register I/O, `asm_jit_fault_resume` |
| `context_switch.asm` | 214 | x86 | `asm_switch_context`, `asm_save/load_context`, trampolines |
| `process.asm` | 801 | x86 | TSS, context switch, user entry, FPU, I/O ports, MSR, bit ops |
| `syscall_entry.asm` | 199 | x86 | 32-bit `syscall_entry` |
| `sysenter.asm` | 44 | x86 | Legacy `sysenter_entry` (SYSENTER fast path) |
| `atomic.asm` | 215 | x86 | 32-bit atomics, spinlock, fences |
| `memory.asm` | 235 | x86 | 32-bit `fast_memcpy/memset/memcmp`, IP/TCP checksums |
| `cpu_features.asm` | 252 | x86 | 32-bit CPUID, SSE/AVX detection, FXSAVE/FXRSTOR |
| `perf.asm` | 359 | x86 | RDTSC, RDPMC, microbenchmarks, cache prefetch |
| `crypto.asm` | 135 | x86 | 32-bit FNV-1a, DJB2, SDBM, XOR cipher |
| `temporal.asm` | 153 | x86 | 32-bit `temporal_fnv1a32`, hash pair, Merkle root |
| `network.asm` | 99 | x86 | Endian swap, Ethernet/IPv4 fast parse |
| `cow.asm` | 614 | x86 | Page fault handler, CoW, TLB flush, paging control, refcounts |
| `sgx.asm` | 119 | x86 | `sgx_encls`, `sgx_enclu`, leaf-12 CPUID, feature-ctrl MSR |
| `dma.asm` | 651 | x86 | DMA channel init/transfer, scatter-gather, stats |
| `acpi.asm` | 673 | x86 | RSDP scan, PM1 registers, sleep/shutdown, C/P-states, battery |
| `memopt.asm` | 715 | x86 | NT stores, SSE string ops, CRC32, AES-NI, fast memory pool |
| `x86_64_shims.asm` | 814 | x86-64 | Full-64 shim: interrupt control, descriptor table ops, context switch, JIT, syscall, exception stubs |
| `x86_64_memory.asm` | 155 | x86-64 | 64-bit `fast_memcpy` (REP MOVSQ), `fast_memset` (REP STOSQ), `fast_memcmp`, IP checksum |
| `x86_64_atomics.asm` | 173 | x86-64 | 64-bit lock-prefix atomics, `atomic_inc/dec_refcount` |
| `x86_64_spinlock.asm` | 136 | x86-64 | Ticket-locked spinlock: init, lock, trylock, unlock, `lock_timeout` |
| `x86_64_cpu_features.asm` | 260 | x86-64 | 64-bit CPUID, SSE/AVX probe, RDRAND, RDTSC fenced pair |
| `x86_64_perf.asm` | 192 | x86-64 | 64-bit microbenchmarks: nop, load, store, add, mul, div, lock |
| `x86_64_crypto.asm` | 526 | x86-64 | SHA-256 (hand-rolled + HW), AES-NI 128-bit, CRC32c (SSE4.2) |
| `x86_64_hashes.asm` | 141 | x86-64 | FNV-1a, DJB2, SDBM, `swap_endian_16/32/64` |
| `x86_64_temporal.asm` | 218 | x86-64 | 64-bit temporal helpers: copy, FNV, hash pair, Merkle root |
| `x86_64_fpu.asm` | 156 | x86-64 | `fpu_init`, trap enable/disable, `fpu_context_save/restore`, context size |
| `x86_64_sysenter.asm` | 239 | x86-64 | `setup_syscall_msrs`, `setup_sysenter_msrs`, `syscall_entry_64`, `sysenter_entry` |
| `x86_64_pic.asm` | 194 | x86-64 | PIC 8259A: remap, EOI, mask/unmask per-IRQ, disable |
| `x86_64_sgx.asm` | 270 | x86-64 | 64-bit `sgx_encls/enclu`, leaf-12, feature-ctrl, `sgx_eremove` |
| `x86_64_simd_scan.asm` | 303 | x86-64 | Cap-graph edge scan: SSE2 and AVX2 vectorised, `cap_graph_find_edge` |
| **Total** | **10,593** | | |

---

## Boot Infrastructure

### `boot.asm` — x86 Multiboot1

Entry point `_start` for `i686-oreulia` GRUB boots. Executes entirely in 32-bit protected mode. On entry, EAX holds the Multiboot magic and EBX the Multiboot info pointer; these are immediately stashed in `esi`/`edx` to survive the BSS clear that follows.

**Boot sequence:**

```
_start:
  1.  Save EAX (magic) → ESI, EBX (info_ptr) → EDX
  2.  VGA 0xB8000 clear (80×25 text, 2000 words, attr 0x07)
  3.  Write "BOOT" at top-left (4 words)
  4.  BSS clear: [sbss, ebss) → 0  (REP STOSD)
  5.  Set ESP = stack_top  (131072-byte static stack in .bss)
  6.  Push EDX, ESI; call arch_x86_record_boot_handoff(magic, info_ptr)
  7.  Write "CALL" to VGA
  8.  call rust_main
  9.  On return: write "FAIL" in red, CLI, HLT loop
```

**Externals used:** `rust_main`, `arch_x86_record_boot_handoff`, `sbss`, `ebss`

**`.bss` layout:**

```
stack_bottom:  resb 131072   ; 128 KiB initial stack
stack_top:
```

---

### `boot_x86_64_mb2.asm` — x86-64 Multiboot2

Entry point `_start` for `x86_64-oreulia` Multiboot2 GRUB builds. The `.multiboot2` section at the top of the binary contains the 8-byte-aligned tag list required by the Multiboot2 spec. The `.rodata` section holds a GDT + GDTR for the 16→32→64 bit mode transition. The `.bss` section holds the early 128 KiB boot stack.

**Externals:** `rust_main`, `arch_x86_record_boot_handoff`, `sbss`, `ebss`

---

### `boot_aarch64_virt.S` — AArch64 QEMU Virt

Entry point `_start` for QEMU `-machine virt -cpu cortex-a72` (or equivalent) loaded as a bare ELF. QEMU passes the DTB physical address in `x0`.

**Boot sequence:**

```
_start:
  1.  x19 ← x0  (preserve DTB pointer)
  2.  If x19 == 0: fallback DTB address = 0x4400_0000 (movz + movk)
  3.  SP ← __boot_stack_top
  4.  BSS clear: [sbss, ebss) → xzr  (8-byte stride, STR XZR)
  5.  x0 ← x19; BL arch_aarch64_record_boot_handoff
  6.  BL rust_main
  7.  On return: WFE loop
```

**Externals:** `rust_main`, `arch_aarch64_record_boot_handoff`, `sbss`, `ebss`, `__boot_stack_top`

---

## AArch64 Vectors and Scheduler

### `aarch64_vectors.S` — Exception Vector Table

Provides the 2 KiB VBAR_EL1-aligned vector table. `install_stub_vectors()` (in `aarch64_vectors.rs`) copies the table and sets `VBAR_EL1`.

**Key assembly macros:**

| Macro | Args | Expands to |
|---|---|---|
| `SAVE_GPRS` | — | `SUB SP, SP, #256`; STP pairs for x0–x29, STR x30 |
| `RESTORE_GPRS` | — | LDP pairs for x0–x29, LDR x30; `ADD SP, SP, #256` |
| `VECTOR_TABLE_ENTRY handler` | handler label | `B handler`; `.space 0x7C` (pad to 128 bytes) |
| `VECTOR_HANDLER name, slot` | name, slot# | Full slot body: SAVE_GPRS → read ESR/ELR/SPSR/FAR → BL dispatch → optional ELR advance → RESTORE_GPRS → ERET |

**`VEC_FRAME_SIZE = 256`** — stack frame size for GPR spill.

**Table layout:**

```
__oreulia_aarch64_vectors_start:   ← aligned to 2048 bytes (0x800)
  slot 0..3   (CurrentEL SP0):   B __oreulia_vec_slot0 .. slot3
  slot 4..7   (CurrentEL SPx):   B __oreulia_vec_slot4 .. slot7
  slot 8..11  (LowerEL AArch64): B __oreulia_vec_slot8 .. slot11
  slot 12..15 (LowerEL AArch32): B __oreulia_vec_slot12 .. slot15
[handler bodies follow]
  __oreulia_vec_slot{N}: VECTOR_HANDLER with slot = N
```

**Dispatch contract:**

1. Each `VECTOR_HANDLER` saves all 31 GPRs (x0–x30) to stack.
2. Calls `oreulia_aarch64_vector_dispatch(slot, esr_el1, elr_el1, spsr_el1, far_el1)`.
3. If the Rust handler returns a non-zero byte delta in `x0`, it is added to `ELR_EL1` before `ERET` (used for self-test BRK advancement).

**Exported symbol:** `__oreulia_aarch64_vectors_start`

---

### `aarch64_scheduler.S` — Context Switching

Implements the cooperative context-switch primitives for the AArch64 scheduler. The context layout matches `kernel/src/scheduler_platform.rs` (`AArch64 ProcessContext`):

| Field | Offset | Register / Content |
|---|---|---|
| `x19..x20` | 0 | callee-saved pair |
| `x21..x22` | 16 | callee-saved pair |
| `x23..x24` | 32 | callee-saved pair |
| `x25..x26` | 48 | callee-saved pair |
| `x27..x28` | 64 | callee-saved pair |
| `x29 (fp)` + `x30 (lr)` | 80 | frame pointer + link register |
| `sp` | 96 | stack pointer |
| `pc` | 104 | resume address |
| `DAIF` | 112 | interrupt mask state |
| `TTBR0_EL1` | 120 | user page table root |
| `esp_shadow` | 128 | low 32 bits of SP (for debugger) |

**SAVE_CALLEE / RESTORE_CALLEE macros:** save/restore `x19..x30` with STP/LDP pairs.

**Exported functions:**

```
aarch64_sched_load_context(x0: *const ProcessContext)
    → sets TTBR0_EL1, restores DAIF, SP, callee-saves, BRs to saved PC
      (does not return — first run of a fresh context jumps to PC field)

aarch64_sched_switch_context(x0: *mut old_ctx, x1: *const new_ctx)
    → saves x19..x30, SP, DAIF, TTBR0_EL1 into *old_ctx
    → sets PC field in *old_ctx to resume label
    → falls through to load_context(*new_ctx)
    → returns via saved PC in old_ctx on next switch-back

aarch64_thread_start_trampoline
    → called as the initial PC of a new kernel thread
    → reads entry function pointer from x19 (set by init_kernel_thread_context)
    → BLR x19; then WFE loop if thread returns

aarch64_kernel_user_entry_trampoline
    → called as PC for a new user process
    → x19 = EL0 entry VA, x20 = EL0 stack top (set by add_user_process)
    → MSR SP_EL0, x20
    → enables FP/SIMD: ORR CPACR_EL1 bits [21:20] = 0b11
    → SPSR_EL1 = 0 (EL0t, all DAIF bits clear)
    → ELR_EL1 = x19
    → ERET → jumps to EL0 entry
```

---

## Context Switch and Per-Arch Scheduler Shims

### `context_switch.asm` — x86 32-bit Context Switch

Implements the x86 cooperative context-switch. The context is a struct holding `eip`, `esp`, and callee-save registers.

**Exported symbols:**

| Symbol | Description |
|---|---|
| `asm_switch_context(old, new)` | Save current context into `*old`; load `*new` |
| `asm_save_context(ctx)` | Save current state into `*ctx` |
| `asm_load_context(ctx)` | Restore context from `*ctx` |
| `thread_start_trampoline` | Entry point for new x86 kernel threads |
| `_thread_start_trampoline` | Underscore alias (ABI compatibility) |
| `kernel_user_entry_trampoline` | Kernel→user ring transition for x86 |
| `asm_dbg_ctx_ptr` | Debug: current context pointer |
| `asm_dbg_eip_target` | Debug: EIP about to be loaded |
| `asm_dbg_esp_loaded` | Debug: ESP value when loaded |
| `asm_dbg_entry_popped` | Debug: entry address popped from stack |
| `asm_dbg_stage` | Debug: switch stage counter |
| `asm_sw_old_ptr` | Switch debug: old context pointer |
| `asm_sw_new_ptr` | Switch debug: new context pointer |
| `asm_sw_saved_old_eip` | Switch debug: saved EIP of outgoing context |
| `asm_sw_new_eip` | Switch debug: target EIP of incoming context |
| `asm_sw_new_esp` | Switch debug: target ESP of incoming context |
| `asm_sw_stage` | Switch debug: current switch stage |

---

## GDT and IDT

### `gdt.asm`

```
gdt_load(gdt_descriptor_ptr: *const GdtDescriptor)
    → LGDT [argument]; RETF to reload CS
```

Single function; 25 lines total. x86 32-bit only. The 64-bit equivalent is in `x86_64_shims.asm`.

---

### `idt.asm` — x86 IDT (600 lines)

The most feature-complete legacy file. Provides the complete x86 32-bit interrupt infrastructure.

**Descriptor table operations:**

```
idt_load(idtr_ptr)     → LIDT [argument]
idt_set_gate(vector, handler_addr, selector, type_attr)
                       → writes 8-byte IDT gate at vector slot
```

**ISR stubs — no error code (vectors 0–7, 9, 15–31 etc.):**

```
; Generated by %macro DEFINE_ISR_NOERR 1
isr0 .. isr{N}:
    push byte 0    ; dummy error code
    push byte N    ; vector number
    jmp isr_common_stub
```

**ISR stubs — with error code (vectors 8, 10–14, 17, 21):**

```
; Generated by %macro DEFINE_ISR_ERR 1
isr8, isr10 .. isr14, isr17, isr21:
    ; CPU pushes error code automatically
    push byte N
    jmp isr_common_stub
```

**IRQ stubs:**

```
irq0 .. irq15:
    push byte 0
    push byte (N + 32)
    jmp irq_common_stub
```

**8259A PIC operations:**

```
pic_send_eoi(irq: u8)
    → if irq >= 8: out PIC2_CMD, EOI; out PIC1_CMD, EOI
pic_remap(offset1, offset2)
    → ICW1..4 initialisation sequence for master (offset1) + slave (offset2)
pic_disable()
    → out 0xA1, 0xFF; out 0x21, 0xFF  (mask all IRQs)
```

**APIC operations:**

```
apic_write(reg_offset, value)  → MMIO write to LAPIC base + reg_offset
apic_read(reg_offset) → u32    → MMIO read
apic_send_eoi()                → write 0 to LAPIC[0xB0]
```

**Fast interrupt control:**

```
fast_cli()                  → CLI; RET
fast_sti()                  → STI; RET
fast_cli_save() → u32       → PUSHFD; CLI; POP EAX; RET (returns old EFLAGS)
fast_sti_restore(flags: u32)→ PUSH arg; POPFD; RET
```

**Software interrupt injection:**

```
trigger_interrupt(vector: u8) → INT N  (NASM `int` with computed vector)
```

**Interrupt counters:**

```
get_interrupt_count(vector: u8) → u32
increment_interrupt_count(vector: u8)
clear_interrupt_counts()
```

**NMI management:**

```
enable_nmi()   → RMW to I/O port 0x70, clear NMI disable bit
disable_nmi()  → RMW to I/O port 0x70, set  NMI disable bit
```

**Exception name lookup:**

```
get_exception_name(vector: u8) → *const u8   (pointer to .rodata string)
```

---

## Interrupt and I/O Control

### `interrupt.asm` — x86 Interrupt Primitives

```
asm_enable_interrupts()   → STI
asm_disable_interrupts()  → CLI
asm_halt()                → HLT
asm_read_tsc() → u64      → RDTSC; pack EDX:EAX → 64-bit return
asm_io_wait()             → OUT 0x80, AL (one IO-bus cycle delay)
asm_read_cr0() → u32      → MOV EAX, CR0
asm_write_cr0(val)        → MOV CR0, val
asm_read_cr3() → u32      → MOV EAX, CR3
asm_write_cr3(val)        → MOV CR3, val  (TLB flush)
asm_read_cr4() → u32      → MOV EAX, CR4
asm_write_cr4(val)        → MOV CR4, val
asm_stac()                → STAC  (set AC flag; allows user-mem access in CPL0)
asm_clac()                → CLAC  (clear AC flag)
asm_jit_fault_resume()    → restores saved EIP/ESP from JIT fault frame
asm_outb(port, value)     → OUT port, AL
asm_inb(port) → u8        → IN AL, port
```

---

## Syscall and Sysenter Paths

### `syscall_entry.asm` — x86 SYSCALL (32-bit)

`global syscall_entry` — the SYSCALL handler registered via the STAR/LSTAR MSR on 32-bit builds. Saves full trap frame, invokes the Rust dispatch table, restores and SYSRET.

### `sysenter.asm` — x86 SYSENTER (legacy)

`global sysenter_entry` — handles Intel SYSENTER fast path for older CPUs that do not support SYSCALL. 44 lines.

### `x86_64_sysenter.asm` — x86-64 SYSCALL + SYSENTER

```
setup_syscall_msrs()
    → program IA32_STAR (segment selectors), IA32_LSTAR (syscall_entry_64 addr),
      IA32_FMASK (RFLAGS mask on entry), IA32_CSTAR (compat mode handler)

setup_sysenter_msrs()
    → program IA32_SYSENTER_CS/EIP/ESP for IA32_SYSENTER fast path on 64-bit CPUs

syscall_entry_64:
    → SWAPGS; save RSP; load kernel RSP from per-CPU scratch
    → save full caller frame (RAX..R15, RFLAGS, RIP, RSP)
    → call oreulia_syscall_dispatch(frame_ptr)
    → restore frame; SWAPGS; SYSRETQ

sysenter_entry:
    → 64-bit SYSENTER handler (for compatibility mode callers)
```

---

## Atomics and Spinlocks

### `atomic.asm` — x86 32-bit Atomics

All operations use `LOCK`-prefixed instructions or `CMPXCHG` for full hardware serialisation.

**Atomic RMW operations:**

| Function | Instruction |
|---|---|
| `asm_atomic_load(addr) → u32` | `MOV EAX, [addr]` (aligned load is atomic on x86) |
| `asm_atomic_store(addr, val)` | `XCHG [addr], reg` |
| `asm_atomic_add(addr, val)` | `LOCK ADD [addr], val` |
| `asm_atomic_sub(addr, val)` | `LOCK SUB [addr], val` |
| `asm_atomic_inc(addr)` | `LOCK INC DWORD [addr]` |
| `asm_atomic_dec(addr)` | `LOCK DEC DWORD [addr]` |
| `asm_atomic_swap(addr, val) → u32` | `XCHG [addr], reg` |
| `asm_atomic_cmpxchg(addr, expected, desired) → u32` | `LOCK CMPXCHG [addr], desired` |
| `asm_atomic_cmpxchg_weak(...)` | Same as strong on x86 |
| `asm_atomic_and(addr, mask)` | `LOCK AND [addr], mask` |
| `asm_atomic_or(addr, mask)` | `LOCK OR  [addr], mask` |
| `asm_atomic_xor(addr, mask)` | `LOCK XOR [addr], mask` |

**Spinlock (32-bit):**

```
asm_spinlock_init(lock)     → MOV [lock], 0
asm_spinlock_lock(lock)     → XCHG-based spin loop (test-and-set)
asm_spinlock_unlock(lock)   → MOV [lock], 0; MFENCE
asm_spinlock_trylock(lock) → u32  → single XCHG; returns 0 if lock acquired
```

**Memory fences:**

```
asm_pause()    → PAUSE (spin-wait hint; reduces power and memory traffic)
asm_mfence()   → MFENCE
asm_lfence()   → LFENCE
asm_sfence()   → SFENCE
```

---

### `x86_64_atomics.asm` — x86-64 64-bit Atomics

All of the 32-bit operations re-implemented with 64-bit operand sizes plus two reference-count helpers:

```
atomic_inc_refcount(ptr: *mut u64) → LOCK INC QWORD [ptr]
atomic_dec_refcount(ptr: *mut u64) → LOCK DEC QWORD [ptr]; returns ZF (1 if reached 0)
```

---

### `x86_64_spinlock.asm` — Ticket Spinlock

Ticket-based spinlock to guarantee FIFO acquisition order, preventing starvation.

```
asm_spinlock_init(lock)      → write {ticket:0, serving:0} pair to *lock
asm_spinlock_lock(lock)      → LOCK XADD to claim ticket; PAUSE-spin until serving == ticket
asm_spinlock_trylock(lock)   → peek serving; attempt CMPXCHG; returns bool
asm_spinlock_unlock(lock)    → INC serving field; MFENCE
asm_spinlock_lock_timeout(lock, max_spins) → u32
    → spin LOCK XADD as above but decrement counter;
       returns 1 if acquired, 0 if timed out
```

---

## Memory Primitives

### `memory.asm` / `x86_64_memory.asm` — Fast Memory Operations

| Function | 32-bit (`memory.asm`) | 64-bit (`x86_64_memory.asm`) | Implementation |
|---|---|---|---|
| `asm_fast_memcpy(dst, src, n)` | REP MOVSD | REP MOVSQ + MOVSB tail | bulk dword/qword copy |
| `asm_fast_memset(dst, val, n)` | REP STOSD | REP STOSQ + STOSB tail | bulk fill |
| `asm_fast_memcmp(a, b, n)` | byte loop with REPE CMPSB | qword REPE CMPSQ + byte tail | 0/1 result |
| `asm_checksum_ip(buf, len)` | 16-bit add-with-carry loop | 32-bit accumulate → fold | RFC 1071 checksum |
| `asm_checksum_tcp(buf, len)` | same | — | pseudo-header aware |

---

### `memopt.asm` — Memory Optimisation Primitives (715 lines)

Provides the highest-throughput memory routines using SSE/AVX instruction sets plus hardware-accelerated CRC32 and AES.

**Cache control:**

```
cache_flush_line(addr)     → CLFLUSH [addr]
cache_prefetch(addr, hint) → PREFETCHT0/T1/T2/NTA based on hint
cache_flush_all()          → WBINVD
cache_invalidate_all()     → INVD
```

**Non-temporal stores:**

```
memcpy_nt(dst, src, n)      → MOVNTQ 64-bit NT stores with 8-byte loop
memset_nt(dst, val, n)      → MOVNTQ fill
memcpy_nt_sse(dst, src, n)  → MOVNTPS 128-bit NT stores (SSE)
memcpy_nt_avx(dst, src, n)  → VMOVNTPS 256-bit NT stores (AVX)
```

**SSE string operations:**

```
strlen_sse(s) → usize         → PCMPEQB + PMOVMSKB scan
strcmp_sse(a, b) → i32         → PCMPEQB loop; returns sign of first diff
memchr_sse(buf, byte, n) → *u8 → PCMPEQB + BITMASK scan
```

**Hardware CRC32:**

```
crc32_hw(buf, len, seed) → u32  → CRC32 instruction (SSE4.2) byte-at-a-time
crc32_update(crc, byte) → u32   → single-byte CRC32 update
```

**AES (AESNI):**

```
aes_encrypt_block(key, plaintext, ciphertext)
    → AESENC / AESENCLAST 10-round AES-128 using NI instructions
aes_decrypt_block(key, ciphertext, plaintext)
    → AESDEC / AESDECLAST
```

**Memory pool:**

```
mempool_alloc_fast(pool_ptr) → *mut u8
    → CAS on free-list head pointer; returns block or NULL
mempool_free_fast(pool_ptr, block)
    → LOCK CMPXCHG insert block at head of free list
```

**Statistics:**

```
get_memopt_stats() → *const MemoptStats
    → pointer to .data stats block: (alloc_count, free_count, cache_flush_count)
```

---

## Copy-on-Write and Page Management

### `cow.asm` — x86 CoW + Paging (614 lines)

The 32-bit page management implementation. The x86-64 companion lives in `mmu_x86_64.rs` (Rust) + `x86_64_shims.asm` and `cow.asm` is the 32-bit reference implementation.

**Page fault handler:**

```
page_fault_handler:
    → reads CR2 (fault address)
    → calls into Rust page_fault_dispatch
    → if faulting page is CoW: allocate frame, copy, clear PTE_COW, re-map writable
    → IRETD
```

**Physical page operations:**

```
copy_page_physical(src_phys, dst_phys)
    → map both frames into scratch area, MOVSD 4096/4 = 1024 iterations, unmap
copy_page_fast(src_virt, dst_virt)
    → direct REP MOVSD 1024 dwords (both already mapped)
zero_page(addr)
    → REP STOSD 1024 dwords using XOR EAX, EAX
zero_page_fast(addr)
    → same but with 4-dword unrolled prologue for pipeline fill
```

**TLB management:**

```
flush_tlb_single(virt_addr)  → INVLPG [virt_addr]
flush_tlb_all()              → MOV CR3, CR3  (reload causes full TLB flush)
```

**Paging control:**

```
load_page_directory(pd_phys)    → MOV CR3, pd_phys
get_page_directory() → u32      → MOV EAX, CR3
enable_paging()                 → set CR0.PG bit
disable_paging()                → clear CR0.PG bit
is_paging_enabled() → u32       → test CR0.PG; return 1/0
```

**PTE manipulation:**

```
set_page_flags(pte_addr, flags)    → OR  [pte_addr], flags
clear_page_flags(pte_addr, flags)  → AND [pte_addr], ~flags
mark_page_cow(pte_addr)            → set bit 9 (soft CoW), clear bit 1 (writable)
is_page_cow(pte_value) → u32       → test bit 9; return 1/0
clear_page_cow(pte_addr)           → clear bit 9; set bit 1 (restore writable)
atomic_set_page_flags(pte_addr, flags)   → LOCK OR
atomic_clear_page_flags(pte_addr, flags) → LOCK AND
```

**Reference counters:**

```
atomic_inc_refcount(ptr)        → LOCK INC DWORD [ptr]
atomic_dec_refcount(ptr) → u32  → LOCK DEC DWORD [ptr]; return new value
```

**Memory barriers:**

```
memory_barrier()  → MFENCE
load_barrier()    → LFENCE
store_barrier()   → SFENCE
```

**Fault and CoW statistics:**

```
get_page_fault_count()  → u32   (from .data counter)
get_cow_fault_count()   → u32
get_page_copy_count()   → u32
increment_page_fault_count()
increment_cow_fault_count()
increment_page_copy_count()
```

**Process fork:**

```
asm_fork_process(old_pd_phys, new_pd_phys)
    → copies page directory, marks all writable pages CoW in both PDs
    → returns kernel-thread-like context for child
```

---

## FPU and SIMD Context

### `x86_64_fpu.asm` — x86-64 FPU Context Management

```
fpu_init()
    → FINIT (reset x87 control word)
    → set MXCSR to 0x1F80 (all exceptions masked, round-to-nearest)
    → zero XMM0–15 via XORPS

fpu_trap_enable()
    → set CR0.TS bit (FPU trap on first use; lazy context switch)

fpu_trap_disable()
    → clear CR0.TS bit (allow FPU use without trap)

fpu_context_save(buf: *mut u8)
    → FXSAVE64 [buf]   (saves 512 bytes: x87 + MMX + XMM0–15 + MXCSR)

fpu_context_restore(buf: *const u8)
    → FXRSTOR64 [buf]

fpu_context_size() → usize
    → returns 512 (FXSAVE area size)
```

The `fpu_context_size` function is queried at runtime so higher layers can allocate correctly-sized save buffers without encoding the constant.

---

## CPU Feature Detection

### `cpu_features.asm` — x86 32-bit CPU Detection

```
asm_cpuid(leaf, sub) → (eax, ebx, ecx, edx)
    → CPUID with EAX=leaf, ECX=sub; stores all 4 outputs to caller-provided pointers
asm_has_sse() → u32     → CPUID 1: test EDX bit 25
asm_has_sse2() → u32    → CPUID 1: test EDX bit 26
asm_has_sse3() → u32    → CPUID 1: test ECX bit 0
asm_has_sse4_1() → u32  → CPUID 1: test ECX bit 19
asm_has_sse4_2() → u32  → CPUID 1: test ECX bit 20
asm_has_avx() → u32     → CPUID 1: test ECX bit 28
asm_get_cpu_vendor(buf: *mut [u8; 13])  → writes 12-byte vendor string + null
asm_get_cpu_features(buf: *mut CpuFeatures)
asm_get_cache_info(level, buf)
asm_rdrand() → u32      → RDRAND; retry on CF=0
asm_xsave_supported() → u32  → CPUID 1 ECX bit 26
asm_fxsave(buf: *mut u8)    → FXSAVE [buf]
asm_fxrstor(buf: *const u8) → FXRSTOR [buf]
```

### `x86_64_cpu_features.asm` — x86-64 64-bit CPU Detection

All the same functions but 64-bit, plus:

```
asm_rdtsc_begin() → u64   → LFENCE; RDTSC; pack EDX:EAX  (serialised start)
asm_rdtsc_end() → u64     → RDTSCP; LFENCE; pack EDX:EAX (serialised end)
asm_read_tsc() → u64      → RDTSC; combine EDX:EAX
get_interrupt_count() → u32       → load from BSS counter
increment_interrupt_count()       → LOCK INC
```

`BSS` layout: `_interrupt_count: resq 1` (one 64-bit counter).

---

## Performance Counters and Microbenchmarks

### `perf.asm` — x86 32-bit Performance

```
asm_rdtsc_begin() → u64   → CPUID (serialise); RDTSC
asm_rdtsc_end() → u64     → RDTSCP; CPUID
asm_rdpmc(counter) → u64  → RDPMC ECX=counter; pack EDX:EAX
asm_serialize()           → CPUID EAX=0 (full serialisation barrier)
asm_lfence_rdtsc() → u64  → LFENCE; RDTSC

; Microbenchmarks — each returns TSC delta for 1000 iterations:
asm_benchmark_nop()   → u64
asm_benchmark_add()   → u64
asm_benchmark_mul()   → u64
asm_benchmark_div()   → u64
asm_benchmark_load()  → u64
asm_benchmark_store() → u64
asm_benchmark_lock()  → u64  (LOCK INC loop)

; Cache control:
asm_clflush(addr)        → CLFLUSH [addr]
asm_prefetch_t0(addr)    → PREFETCHT0
asm_prefetch_t1(addr)    → PREFETCHT1
asm_prefetch_t2(addr)    → PREFETCHT2
asm_prefetch_nta(addr)   → PREFETCHNTA
```

### `x86_64_perf.asm` — x86-64 64-bit Benchmarks

Subset of `perf.asm` implemented with 64-bit operands: `asm_benchmark_nop/load/store/add/mul/div/lock`. Each runs a 1000-iteration hot loop and returns the RDTSC delta.

---

## Cryptographic Primitives

### `crypto.asm` — x86 32-bit Hashes and Cipher

```
asm_hash_fnv1a(data, len) → u32
    → FNV-1a 32-bit: offset basis 2166136261, prime 16777619, byte-at-a-time
asm_hash_djb2(data: *const u8) → u32
    → DJB2: hash = 5381; loop: hash = hash * 33 XOR byte
asm_hash_sdbm(data: *const u8) → u32
    → SDBM: hash = 0; loop: hash = hash * 65599 + byte
asm_xor_cipher(buf, key, len)
    → XOR each byte with key; in-place
```

### `x86_64_crypto.asm` — x86-64 SHA-256 + AES-NI + CRC32c (526 lines)

**SHA-256:**

```
asm_sha256_init(ctx: *mut Sha256Context)
    → loads initial hash values H0..H7 into context

asm_sha256_update(ctx, data, len)
    → processes 64-byte blocks; calls sha256_compress_block per block
    → handles partial final block with padding

sha256_compress_block(state: *mut [u32; 8], block: *const [u8; 64])
    → manual 64-round SHA-256 compression (no SHA-NI)

sha256_transform_hw(state, data)
    → SHA-NI accelerated transform using SHA256RNDS2 + SHA256MSG1/2
      (requires SHA extension; checked at call site)
```

**AES-128 (AESNI):**

```
aes128_key_expand(key: *const [u8;16], sched: *mut [u8;176])
    → AESKEYGENASSIST-based key schedule expansion (11 round keys)

aes128_block_encrypt(sched, plain, cipher)   alias: asm_aesni_encrypt
    → 10×(AESENC), AESENCLAST using round keys from schedule

aes128_block_decrypt(sched, cipher, plain)   alias: asm_aesni_decrypt
    → AESIMC round-key inversion then 10×(AESDEC), AESDECLAST
```

**CRC32c (SSE4.2):**

```
asm_crc32c_u8(crc, byte) → u32
    → CRC32 EAX, byte_reg

asm_crc32c_u32(crc, word) → u32
    → CRC32 EAX, dword_reg

asm_crc32c_buf(crc, buf, len) → u32
    → 8-byte loop: CRC32 RAX, QWORD [buf]; then byte tail
```

---

## Hash and Endian Utilities

### `x86_64_hashes.asm`

```
asm_hash_fnv1a(data, len) → u64   → 64-bit FNV-1a (basis 14695981039346656037, prime 1099511628211)
asm_hash_djb2(s: *const u8) → u64  → 64-bit DJB2
asm_hash_sdbm(s: *const u8) → u64  → 64-bit SDBM

asm_swap_endian_16(v: u16) → u16   → XCHG AL, AH; RET
asm_swap_endian_32(v: u32) → u32   → BSWAP EAX; RET
asm_swap_endian_64(v: u64) → u64   → BSWAP RAX; RET
```

---

## Temporal Log Helpers

### `temporal.asm` — 32-bit Temporal Primitives

```
temporal_fnv1a32(data, len) → u32    → inline FNV-1a 32-bit
temporal_hash_pair(a, b) → u32       → H = FNV(H(a), b); combines two u32 hashes
temporal_merkle_root_u32(leaves, n) → u32
    → pairwise temporal_hash_pair reduction; produces Merkle root of n leaves
temporal_copy_bytes(dst, src, n)     → REP MOVSB
temporal_zero_bytes(dst, n)          → REP STOSB, XOR AL, AL
```

### `x86_64_temporal.asm` — 64-bit Temporal Primitives

64-bit re-implementation of all the same functions. `temporal_merkle_root_u32` uses a fully unrolled 8-leaf optimised path for the common case (`n = 8`), falling back to the general loop for other sizes.

---

## Network Packet Parsing

### `network.asm`

```
asm_swap_endian_16(v) → u16   → XCHG AL, AH (network ↔ host byte order for u16)
asm_swap_endian_32(v) → u32   → BSWAP EAX   (for IPv4 address / u32 fields)
asm_parse_ethernet_frame(buf, len, out: *mut EthHeader)
    → reads 14-byte Ethernet header; validates minimums; copies dst/src MAC + ethertype
asm_parse_ipv4_header(buf, len, out: *mut Ipv4Header)
    → reads IPv4 fixed header (20 bytes); validates version=4, IHL≥5; fills struct
```

---

## DMA Engine

### `dma.asm` — ISA/PCI DMA Channel Management (651 lines)

```
dma_init_channel(channel, direction, mode)
    → program ISA DMA controller registers: cascade/single mode, direction (read/write),
      channel number; disable channel before setup, re-enable after
dma_start_transfer(channel, phys_addr, count)
    → set page register, address register, count register; enable channel
dma_stop_transfer(channel)
    → disable (mask) DMA channel
dma_is_complete(channel) → u32
    → read DMA status register; return 1 if terminal count reached
dma_get_remaining_count(channel) → u32
    → read count register; return remaining bytes

dma_scatter_gather(channel, sglist: *const SgEntry, count)
    → iterate scatter-gather list; call dma_start_transfer per entry; wait for TC
dma_setup_descriptor_list(descriptor_list, entry_count)
    → populate DMA descriptor table in memory for bus-mastering DMA

dma_reset_controller()
    → issue master reset to DMA controller; re-initialize all channels
get_dma_stats() → *const DmaStats
reset_dma_stats()
```

---

## ACPI Power Management

### `acpi.asm` — ACPI Infrastructure (673 lines)

```
; Table discovery:
acpi_find_rsdp(search_range_start, len) → *const Rsdp
    → scan for signature "RSD PTR " at 16-byte boundaries
acpi_checksum(table_addr, len) → u8
    → byte-sum table; return remainder mod 256 (must be 0 for valid tables)
acpi_find_table(rsdp, signature: *const u8) → *const AcpiSdtHeader
    → walk RSDT/XSDT; return pointer to matching 4-byte signature

; PM1 register access:
acpi_read_pm1_control(fadt) → u32
acpi_write_pm1_control(fadt, value)
acpi_read_pm1_status(fadt) → u32
acpi_write_pm1_status(fadt, value)

; Power transitions:
acpi_enter_sleep_state(fadt, sleep_type_a, sleep_type_b)
    → set SLP_EN + SLP_TYP in PM1a/PM1b control registers; HLT
acpi_shutdown()
    → acpi_enter_sleep_state with S5 type fields
acpi_reboot()
    → write 0x06 to I/O port 0xCF9 (PCI reset) or write keyboard controller reset

; Thermal zones:
acpi_read_thermal_zone(tz_ptr) → u32  → read _TMP via ACPI namespace eval
acpi_set_cooling_policy(tz_ptr, policy)  → write _CRT/_PSV threshold

; CPU idle C-states:
acpi_enter_c1()  → HLT
acpi_enter_c2()  → OUT [PM_TMR], AL  (bus cycle stall)
acpi_enter_c3()  → bus-master stall + cache flush + HLT

; P-states:
acpi_set_pstate(cpu, pstate)  → write _PCT control register via WRMSR
acpi_get_pstate(cpu) → u32    → read _PCT status register via RDMSR

; Battery:
acpi_get_battery_status(bat_ptr) → u32   → read _BST: charging/discharging flag
acpi_get_battery_capacity(bat_ptr) → u32 → read _BIF: design capacity

; Event management:
acpi_enable_events(fadt, event_mask)
acpi_get_event_status(fadt) → u32
acpi_clear_event(fadt, event_bit)

; Diagnostics:
get_acpi_stats() → *const AcpiStats
```

---

## SGX Enclave Primitives

### `sgx.asm` — x86 32-bit SGX Instructions

```
sgx_encls(leaf, rbx, rcx, rdx) → u32  → ENCLS leaf; for EPC management (EPC_CREATE, ELD, ...)
sgx_cpuid_leaf12(sub) → (eax, ebx, ecx, edx)  → CPUID EAX=12h, ECX=sub
sgx_read_feature_ctrl() → u64   → RDMSR IA32_FEATURE_CONTROL; check SGX enable bits
sgx_write_sgxlepubkeyhash(qword[4])  → WRMSR IA32_SGXLEPUBKEYHASH0..3
sgx_enclu(leaf, ...)             → ENCLU leaf; for enclave calls (EENTER, EEXIT, ...)
```

### `x86_64_sgx.asm` — x86-64 SGX (270 lines)

```
sgx_encls(leaf, rbx, rcx, rdx) → rax   → 64-bit ENCLS
sgx_enclu(leaf, rbx, rcx, rdx) → rax   → 64-bit ENCLU
sgx_cpuid_leaf12(sub, out_ptr)          → CPUID EAX=12h; stores 4 outputs
sgx_read_feature_ctrl() → u64          → RDMSR IA32_FEATURE_CONTROL
sgx_write_sgxlepubkeyhash(hash_ptr)     → four WRMSR calls for hash words 0..3
sgx_eremove(epc_page_ptr) → u32        → ENCLS with leaf EREMOVE; returns 0 on success
```

---

## PIC 8259A Control

### `x86_64_pic.asm` — x86-64 PIC Control (194 lines)

Provides dedicated 64-bit implementations of the PIC helper functions also present in `idt.asm`.

```
pic_remap(offset1, offset2)
    → full ICW1..ICW4 initialisation; remaps master to offset1, slave to offset1+8

pic_send_eoi(irq: u8)
    → if irq >= 8: send EOI to PIC2 (port 0xA0); always send EOI to PIC1 (port 0x20)

pic_mask_irq(irq: u8)
    → compute mask bit; READ/OR/WRITE to appropriate data port (0x21 or 0xA1)

pic_unmask_irq(irq: u8)
    → compute mask bit; READ/AND-NOT/WRITE to appropriate data port

pic_disable()
    → OUT 0x21, 0xFF; OUT 0xA1, 0xFF  (mask all 16 IRQs)
```

---

## Capability Graph SIMD Scanner

### `x86_64_simd_scan.asm` — SIMD Cap-Graph Edge Scanner (303 lines)

Provides highly-optimised inner loops for scanning the capability graph's adjacency matrix. These are called by `capnet.rs` when verifying edge membership in large capability graphs.

```
cap_graph_scan_edges_sse2(
    edge_data:   *const u64,   // packed edge adjacency array
    edge_count:  u32,
    source_id:   u32,
    target_mask: u64,
    out_matches: *mut u32      // index array of matching edges
) → u32                        // number of matches found
    → loads 2 u64s at a time (128-bit SSE2 register)
    → PCMPEQQ + PMOVMSKB to test both entries simultaneously
    → unrolled 8-entry inner loop

cap_graph_scan_edges_avx2(
    edge_data, edge_count, source_id, target_mask, out_matches
) → u32
    → loads 4 u64s at a time (256-bit YMM register via VMOVDQU)
    → VPCMPEQQ + VPMOVMSKB 4-way parallel test
    → unrolled 16-entry inner loop for maximum throughput

cap_graph_find_edge(
    edge_data:  *const u64,
    edge_count: u32,
    source_id:  u32,
    target_id:  u32
) → i32                       // index into edge_data, or -1 if not found
    → scalar fallback for small graphs or individual lookups
```

**Dispatch:** `capnet.rs` queries `asm_has_avx()` at initialisation; routes to `avx2` variant if available, `sse2` variant on older hardware, scalar fallback on anything else.

---

## x86-64 Unified Shims

### `x86_64_shims.asm` — The Complete x86-64 Bring-Up Layer (814 lines)

The largest file in the directory. Provides the definitive x86-64 implementation of every primitive that `x86_64_runtime.rs` calls from Rust. Supersedes the corresponding 32-bit implementations for `x86_64-oreulia` builds.

**Interrupt and I/O:**

```
asm_enable_interrupts()     → STI
asm_disable_interrupts()    → CLI
asm_halt()                  → HLT
fast_sti()                  → STI; RET
fast_cli_save() → u64       → PUSHFQ; CLI; POP RAX
fast_sti_restore(flags)     → PUSH flags; POPFQ
get_interrupt_state() → u32 → PUSHFQ; POP; test IF bit; return 0/1
asm_outb(port, val)         → OUT port_reg, AL
asm_inb(port) → u8          → IN AL, port_reg
```

**Control register and system register access:**

```
asm_read_cr0() → u64   → MOV RAX, CR0
asm_write_cr0(v)       → MOV CR0, v
asm_read_cr4() → u64   → MOV RAX, CR4
asm_write_cr4(v)       → MOV CR4, v
get_page_directory() → u64  → MOV RAX, CR3
load_page_directory(v)      → MOV CR3, v
flush_tlb_single(va)        → INVLPG [va]
flush_tlb_all()             → MOV CR3, CR3
enable_paging()             → set CR0.PG via read-modify-write
is_paging_enabled() → u32   → test CR0.PG; return 0/1
read_msr(msr) → u64         → RDMSR ECX=msr; combine EDX:EAX
write_msr(msr, val)         → WRMSR
```

**Memory barriers:**

```
memory_barrier()  → MFENCE
load_barrier()    → LFENCE
store_barrier()   → SFENCE
```

**Descriptor table operations:**

```
gdt_load(gdtr_ptr)          → LGDT [ptr]
idt_load(idtr_ptr)          → LIDT [ptr]
tss_load(selector)          → LTR ax
tss_set_kernel_stack(rsp0)  → updates TSS.RSP0 via direct memory write
```

**FPU (delegating shims):**

```
save_fpu_state(buf)     → FXSAVE64 [buf]
restore_fpu_state(buf)  → FXRSTOR64 [buf]
```

**Scheduler context switch (x86-64):**

```
x86_64_sched_switch_context(old_ctx: *mut Ctx, new_ctx: *const Ctx)
    → save RBX/RBP/R12–R15 + RSP + return-address (ADR) into *old_ctx
    → load from *new_ctx; BR to saved PC in new context

x86_64_sched_load_context(ctx: *const Ctx)
    → load RSP + callee-saves from *ctx; JMP to ctx.pc

x86_64_thread_start_trampoline
    → first PC for new kernel threads; calls entry function from R12; HLT loop
```

**Legacy bridge (same calling convention as 32-bit files):**

```
asm_switch_context(old, new)   → delegates to x86_64_sched_switch_context
asm_load_context(ctx)          → delegates to x86_64_sched_load_context
thread_start_trampoline        → alias for x86_64_thread_start_trampoline
kernel_user_entry_trampoline   → legacy alias for enter_user_mode path
```

**JIT support:**

```
x64_jit_callpage_exec(entry_va: u64, arg0: u64, jit_stack_top: u64) → u64
    → switches to JIT stack; calls entry_va; restores kernel stack; returns result

asm_jit_fault_resume()
    → invoked from page fault handler after CoW recovery
    → restores interrupted RIP/RSP from saved fault frame and IRETQ

jit_user_enter(rip, rsp, rflags)
    → transition to user-mode JIT code via synthetic IRETQ frame
```

**User-mode entry:**

```
enter_user_mode(rip, rsp, rflags, arg0, arg1)
    → build IRETQ frame; set CS=USER_CS, SS=USER_DS; IRETQ
```

**Syscall fast path:**

```
syscall_entry:
    → SWAPGS; save RSP into kernel scratch; load kernel RSP
    → push minimal frame (RCX=user RIP, R11=user RFLAGS, RAX=syscall nr)
    → call oreulia_syscall_dispatch(nr, a0..a5)
    → pop; SWAPGS; SYSRETQ

x86_64_syscall_return_resume(ret_val, user_rip, user_rflags, user_rsp)
    → used by the scheduler to return to a context that was pre-empted mid-syscall
```

**x86-64 exception/IRQ stubs:**

```
x64_interrupt_common:
    → called from all 256 IDT stubs
    → pushes error code + vector (or 0 + vector for non-error vectors)
    → saves full GPR frame (RAX..R15 + segments)
    → calls x86_64_trap_dispatch(vector, error, &frame)
    → restores frame; IRETQ
```

**Generic zero-return stubs:** ~70 lines of stub functions that return 0/null for unimplemented 32-bit backend entry points, preventing link failures on x86-64 builds that include the legacy Rust object files.

---

## Process Utilities (32-bit)

### `process.asm` — x86 32-bit Process Primitives (801 lines)

The broadest single file in the 32-bit layer — a comprehensive kernel utility library.

**TSS management:**

```
tss_load(selector)         → LTR ax
tss_set_kernel_stack(esp0) → writes directly to TSS.ESP0 field
tss_get_esp0() → u32       → reads TSS.ESP0 field
```

**Context switch:**

```
fast_context_switch(old_ctx, new_ctx)
    → minimal PUSH/POP callee-save path (EBX, ESI, EDI, EBP, ESP)
    → restores PC via RET
```

**Ring transitions:**

```
enter_kernel_mode()       → adjust segment registers for CPL0
enter_user_mode(eip, esp) → build IRET frame for CPL3 IRET
jit_user_enter(eip, esp)  → JIT-specific user entry
```

**FPU (32-bit):**

```
save_fpu_state(buf)    → FXSAVE [buf]   (32-bit form, 512 bytes)
restore_fpu_state(buf) → FXRSTOR [buf]
```

**EFLAGS / interrupt state:**

```
get_interrupt_state() → u32      → PUSHFD; test IF bit
set_interrupt_state(flags)       → AND/OR EFLAGS
disable_interrupts_save() → u32  → PUSHFD; CLI; return old flags
restore_interrupts(saved_flags)  → PUSH saved; POPFD
```

**Spinlock (process.asm inline version):**

```
spinlock_acquire(lock)         → test-and-set XCHG loop
spinlock_release(lock)         → MOV [lock], 0
spinlock_try_acquire(lock) → u32→ single XCHG attempt; 0=acquired
```

**CPU identification:**

```
get_cpu_vendor(buf)     → CPUID EAX=0; write 12-byte string
get_cpu_features()      → CPUID EAX=1; return EDX
has_sse() → u32         → test EDX bit 25 from CPUID 1
has_sse2() → u32        → test EDX bit 26
has_avx() → u32         → test ECX bit 28
```

**I/O ports:**

```
inb(port) → u8,   inw(port) → u16,   inl(port) → u32
outb(port, val),  outw(port, val),    outl(port, val)
```

**MSR / PMC / TSC:**

```
read_msr(msr) → u64      → RDMSR
write_msr(msr, val)      → WRMSR
read_pmc(counter) → u64  → RDPMC
read_tsc_64() → u64      → RDTSC; combine EDX:EAX
```

**Memory:**

```
fast_memcpy(dst, src, n)   → REP MOVSD
fast_memset(dst, val, n)   → REP STOSD
fast_memcmp(a, b, n) → i32 → REPE CMPSB; sign result
```

**Bit operations:**

```
find_first_set_bit(v) → u32  → BSF EAX, arg
find_last_set_bit(v) → u32   → BSR EAX, arg
count_set_bits(v) → u32      → POPCNT EAX, arg
```

**Context switch count:**

```
get_context_switch_count() → u32
increment_context_switch_count()
```

---

## Legacy and x86-64 Dual-File Guide

Many functions exist in both a legacy x86 file and an `x86_64_*` counterpart. The build system selects the correct object via the Cargo target JSON — never links both. The table below maps the canonical function name to both homes:

| Function | 32-bit file | 64-bit file |
|---|---|---|
| `asm_fast_memcpy` | `memory.asm` | `x86_64_memory.asm` |
| `asm_fast_memset` | `memory.asm` | `x86_64_memory.asm` |
| `asm_atomic_load` | `atomic.asm` | `x86_64_atomics.asm` |
| `asm_spinlock_lock` | `atomic.asm` | `x86_64_spinlock.asm` |
| `asm_hash_fnv1a` | `crypto.asm` | `x86_64_hashes.asm` |
| `asm_cpuid` | `cpu_features.asm` | `x86_64_cpu_features.asm` |
| `asm_has_avx` | `cpu_features.asm` | `x86_64_cpu_features.asm` |
| `temporal_fnv1a32` | `temporal.asm` | `x86_64_temporal.asm` |
| `temporal_merkle_root_u32` | `temporal.asm` | `x86_64_temporal.asm` |
| `save_fpu_state` | `process.asm` | `x86_64_shims.asm` |
| `gdt_load` | `gdt.asm` | `x86_64_shims.asm` |
| `idt_load` | `idt.asm` | `x86_64_shims.asm` |
| `tss_load` | `process.asm` | `x86_64_shims.asm` |
| `flush_tlb_single` | `cow.asm` | `x86_64_shims.asm` |
| `pic_remap` | `idt.asm` | `x86_64_pic.asm` |
| `pic_send_eoi` | `idt.asm` | `x86_64_pic.asm` |
| `sgx_encls` | `sgx.asm` | `x86_64_sgx.asm` |
| `asm_benchmark_nop` | `perf.asm` | `x86_64_perf.asm` |

The `aarch64_*` files have no 32-bit counterpart; they are only ever linked for `aarch64-oreulia` targets.
