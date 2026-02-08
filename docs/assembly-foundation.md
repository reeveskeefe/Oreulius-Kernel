# Assembly Foundation Implementation

## Overview
Comprehensive x86 assembly implementation providing low-level kernel primitives with Rust bindings.

## Modules

### 1. **cow.asm** - Copy-on-Write Paging (500+ lines)
Advanced virtual memory management with SSE optimization.

**Key Features:**
- Page fault handler (INT 14 entry point)
- SSE-optimized page copying (movaps, 16-byte transfers)
- Atomic operations for SMP safety (LOCK OR/AND, XADD)
- Memory barriers (MFENCE/LFENCE/SFENCE)
- TLB management (INVLPG, CR3 reload)
- COW bit manipulation (mark/check/clear)
- Statistics tracking (page faults, COW faults, copies)

**Rust Bindings:** `paging.rs`

---

### 2. **process.asm** - Process Management (700+ lines)
Fast context switching, TSS operations, and privilege level transitions.

**Key Features:**

#### Task State Segment (TSS)
```asm
tss_load              ; Load TSS into task register
tss_set_kernel_stack  ; Set ESP0 for privilege transitions
tss_get_esp0          ; Get current kernel stack pointer
```

#### Context Switching
```asm
fast_context_switch   ; Optimized context switch with CR3 caching
                      ; Only reloads page directory if different
```
**Context Structure:**
- ESP, EBP, EBX, ESI, EDI (registers)
- EIP (return address)
- EFLAGS (CPU flags)
- CR3 (page directory)

#### Privilege Transitions
```asm
enter_kernel_mode     ; Ring 3 → Ring 0
enter_user_mode       ; Ring 0 → Ring 3 (builds IRET frame)
```

#### FPU/SSE State Management
```asm
save_fpu_state        ; FXSAVE/FSAVE (512 bytes)
restore_fpu_state     ; FXRSTOR/FRSTOR
                      ; Auto-detects SSE support via CPUID
```

#### Interrupt State
```asm
get_interrupt_state   ; Returns IF flag
set_interrupt_state   ; Enable/disable interrupts
disable_interrupts_save  ; CLI and return old state
restore_interrupts    ; Restore previous interrupt state
```

#### Spinlocks (SMP-safe)
```asm
spinlock_acquire      ; XCHG-based spinlock
spinlock_release      ; Release lock
spinlock_try_acquire  ; Non-blocking acquire
```

#### CPU Detection
```asm
get_cpu_vendor        ; 12-byte vendor string (GenuineIntel, etc.)
get_cpu_features      ; CPUID feature flags
has_sse / has_sse2 / has_avx  ; Feature detection
```

#### Port I/O
```asm
inb / inw / inl       ; Read byte/word/dword
outb / outw / outl    ; Write byte/word/dword
```

#### MSR Operations
```asm
read_msr              ; Read Model Specific Register
write_msr             ; Write MSR
```

#### Performance Counters
```asm
read_pmc              ; Read performance counter
read_tsc_64           ; Read timestamp counter
```

#### Memory Operations
```asm
fast_memcpy           ; REP MOVSD optimized copy
fast_memset           ; REP STOSD optimized set
fast_memcmp           ; REPE CMPSB compare
```

#### Bit Operations
```asm
find_first_set_bit    ; BSF instruction
find_last_set_bit     ; BSR instruction
count_set_bits        ; POPCNT (with fallback)
```

#### Statistics
```asm
get_context_switch_count
increment_context_switch_count
get_interrupt_count
increment_interrupt_count
```

**Rust Bindings:** `process_asm.rs`
- `TaskContext` struct
- `Spinlock` RAII wrapper
- `InterruptGuard` RAII wrapper
- `CpuVendor` / `CpuFeatures` detection
- `Port<T>` typed I/O abstraction
- `Msr` register abstraction
- `PerfCounter` / `Tsc` counters
- `FastMem` operations
- `BitOps` utilities

---

### 3. **idt.asm** - Interrupt Descriptor Table (800+ lines)
Hardware interrupt handlers and exception vectors.

**Key Features:**

#### IDT Management
```asm
idt_load              ; LIDT instruction
idt_set_gate          ; Configure IDT entry
```

#### Exception Handlers (ISR 0-31)
All CPU exceptions with proper error code handling:
- **ISR 0:** Divide-by-zero
- **ISR 1:** Debug
- **ISR 2:** Non-maskable interrupt
- **ISR 3:** Breakpoint
- **ISR 6:** Invalid opcode
- **ISR 8:** Double fault (with error code)
- **ISR 13:** General protection fault (with error code)
- **ISR 14:** Page fault (with error code)
- **ISR 17:** Alignment check
- **ISR 18:** Machine check
- ... and all others

**Common Stub:**
```asm
isr_common_stub:
    pushad              ; Save all GPRs
    push ds/es/fs/gs    ; Save segment registers
    call rust_exception_handler
    ; Restore and IRETD
```

#### IRQ Handlers (IRQ 0-15, vectors 32-47)
Hardware interrupt handlers with PIC support:
- **IRQ 0:** PIT Timer
- **IRQ 1:** Keyboard
- **IRQ 2:** Cascade (slave PIC)
- **IRQ 8:** RTC
- **IRQ 12:** PS/2 Mouse
- **IRQ 14/15:** ATA controllers

**Common Stub:**
```asm
irq_common_stub:
    pushad
    push segments
    call rust_irq_handler
    ; EOI sent in Rust
```

#### PIC (8259) Management
```asm
pic_send_eoi          ; Send End-Of-Interrupt
pic_remap             ; Remap IRQs to 32-47
pic_disable           ; Mask all interrupts
```

#### APIC Operations
```asm
apic_write            ; Write APIC register
apic_read             ; Read APIC register
apic_send_eoi         ; Send APIC EOI
```

#### Interrupt Control
```asm
fast_cli / fast_sti   ; Quick interrupt disable/enable
fast_cli_save         ; Save EFLAGS and CLI
fast_sti_restore      ; Restore EFLAGS
trigger_interrupt     ; Software interrupt
```

#### NMI Control
```asm
enable_nmi            ; Enable non-maskable interrupts
disable_nmi           ; Disable NMI
```

#### Statistics
```asm
interrupt_counts      ; 256-entry counter array
get_interrupt_count   ; Get count for vector
increment_interrupt_count  ; Atomic increment
clear_interrupt_counts     ; Reset all
```

#### Exception Names
```rodata
exception_names       ; String table for exception names
get_exception_name    ; Get name by vector
```

**Rust Bindings:** `idt_asm.rs`
- `IdtEntry` structure (8 bytes)
- `IdtPointer` for LIDT
- `InterruptFrame` passed to handlers
- `Exception` enum (0-31)
- `Irq` enum (0-15, remapped to 32-47)
- `Idt` manager with `init_exceptions()` / `init_irqs()`
- `Pic` manager
- `InterruptStats`
- `rust_exception_handler()` - prints exception info and halts
- `rust_irq_handler()` - dispatches IRQs and sends EOI

---

## Build Integration

**build.sh additions:**
```bash
nasm -f elf32 src/asm/cow.asm -o target/cow.o
nasm -f elf32 src/asm/process.asm -o target/process.o
nasm -f elf32 src/asm/idt.asm -o target/idt.o
nasm -f elf32 src/syscall_entry.asm -o target/syscall_entry.o

# Linker includes all object files
x86_64-elf-ld ... target/cow.o target/process.o target/idt.o target/syscall_entry.o ...
```

**Status:** ✅ All assembly files compile successfully

---

## Performance Characteristics

### Context Switch
- **Registers:** 8 GPRs + EIP + EFLAGS + CR3 = 11 values
- **CR3 optimization:** Only reload if page directory differs
- **Typical cost:** ~100-200 cycles (without CR3 reload)
- **With TLB flush:** ~1000+ cycles

### Page Copying
- **SSE path:** 256 iterations × movaps = 16 bytes/iteration = 4KB
- **Throughput:** ~4-8 GB/s (depends on memory bandwidth)
- **Fallback:** REP MOVSD (4 bytes/iteration, 1024 iterations)

### Spinlock
- **XCHG:** Atomic, full memory barrier
- **PAUSE:** Reduces contention on hyperthreading
- **Typical uncontended:** ~10-20 cycles

### Interrupt Latency
- **Hardware:** CPU pushes SS, ESP, EFLAGS, CS, EIP (~10 cycles)
- **Assembly stub:** PUSHAD + segment saves (~15 cycles)
- **To Rust:** Call overhead (~5 cycles)
- **Total:** ~30-50 cycles to reach Rust handler

---

## Safety Model

### Assembly Safety
1. **Atomic operations:** LOCK prefix for all shared data
2. **Memory barriers:** Explicit MFENCE/LFENCE/SFENCE
3. **Register preservation:** All callee-saved registers preserved
4. **Stack alignment:** Maintains 16-byte alignment for SSE
5. **Error codes:** Proper handling of CPU-pushed error codes

### Rust Integration
1. **`unsafe` blocks:** All assembly calls wrapped in `unsafe`
2. **Type safety:** Typed wrappers (Port<u8>, Msr, etc.)
3. **RAII guards:** InterruptGuard, Spinlock auto-cleanup
4. **Const safety:** Compile-time initialization where possible
5. **Documentation:** All assembly functions documented

---

## Usage Examples

### Context Switching
```rust
use process_asm::{TaskContext, fast_context_switch};

let mut current = TaskContext::new();
let next = get_next_task();

unsafe {
    fast_context_switch(&mut current, &next);
}
// Now running in next task's context
```

### Interrupt Handling
```rust
use idt_asm::{Idt, Pic, FLAG_PRESENT, GATE_INTERRUPT_32};

let mut idt = Idt::new();
idt.init_exceptions(0x08); // Code segment selector
idt.init_irqs(0x08);

Pic::remap(32, 40); // Remap IRQs to 32-47
idt.load();

// Enable interrupts
unsafe { fast_sti() }
```

### Port I/O
```rust
use process_asm::Port;

let port = Port::<u8>::new(0x3F8); // COM1
port.write(b'H');
let status = port.read();
```

### Spinlock
```rust
use process_asm::Spinlock;

static LOCK: Spinlock = Spinlock::new();

fn critical_section() {
    LOCK.acquire();
    // Critical section
    LOCK.release();
}
```

### Interrupt Guard
```rust
use process_asm::InterruptGuard;

fn atomic_operation() {
    let _guard = InterruptGuard::new(); // CLI
    // Interrupts disabled here
} // STI on drop
```

---

## Testing Status

- ✅ Assembly compilation (NASM)
- ✅ Object file generation
- ✅ Linker integration
- ✅ Rust binding compilation
- ⏳ Runtime testing (pending IDT registration)
- ⏳ COW page fault testing
- ⏳ Context switch benchmarks
- ⏳ Interrupt handler verification

---

## Next Steps

1. **Register IDT handlers** in kernel initialization
2. **Test exception handling** with divide-by-zero
3. **Test IRQ handling** with timer/keyboard
4. **Benchmark context switch** performance
5. **Test COW mechanism** with fork()
6. **Implement process scheduler** using context switch
7. **Add user processes** to test privilege transitions
8. **Performance profiling** with TSC/PMC

---

## Technical Notes

### x86 Calling Convention (cdecl)
- **Arguments:** Pushed on stack right-to-left
- **Return:** EAX (EDX:EAX for 64-bit)
- **Callee-saved:** EBX, ESI, EDI, EBP
- **Caller-saved:** EAX, ECX, EDX
- **Stack cleanup:** Caller pops arguments

### Interrupt Frame Layout
```
High addresses
+------------------+
| SS               | (if privilege change)
| ESP              | (if privilege change)
| EFLAGS           |
| CS               |
| EIP              | ← CPU pushes these
+------------------+
| Error Code       | ← CPU pushes (some exceptions)
| Interrupt Number | ← Assembly pushes
+------------------+
| EAX              |
| ECX              |
| EDX              |
| EBX              |
| ESP              |
| EBP              |
| ESI              |
| EDI              | ← PUSHAD
+------------------+
| DS               |
| ES               |
| FS               |
| GS               | ← Assembly pushes segments
+------------------+ ← ESP when calling Rust
Low addresses
```

### CR3 Structure
```
31                12 11     5 4 3 2 1 0
+------------------+--------+-+-+-+-+-+-+
| Page Dir Base    | Ignored|P|P|W|C| |
|  (Physical Addr) |        |C|W|C|D| |
+------------------+--------+-+-+-+-+-+-+
```

### Page Table Entry (COW)
```
31                12 11 9 8 7 6 5 4 3 2 1 0
+------------------+-----+-+-+-+-+-+-+-+-+-+-+
| Physical Address | AVL |G|P|D|A|P|P|U|R|P|
|                  |     | |A|I| |C|W|/|/| |
|                  |     | |T|R| |D|T|S|W| |
+------------------+-----+-+-+-+-+-+-+-+-+-+-+
                     ↑ Bit 9 = COW flag
                               ↑ Bit 1 = Writable
```

---

## Resources

- **Intel SDM:** Software Developer's Manual (Volumes 1-3)
- **OSDev Wiki:** https://wiki.osdev.org/
- **x86 Instruction Reference:** https://www.felixcloutier.com/x86/
- **NASM Manual:** https://www.nasm.us/doc/

---

**Total Assembly Lines:** 2000+
**Rust Binding Lines:** 1000+
**Coverage:** Process management, interrupts, memory, I/O, atomics, performance
