# Oreulia — Assembly Quick Reference

**Status:** Reference (Mar 29, 2026)

This guide provides a quick reference for developers working with the kernel's low-level assembly bindings. These functions are exposed via `crate::asm_bindings`, which is re-exported from the `memory` subsystem:

```rust
// Declaration: kernel/src/memory/asm_bindings.rs
// Re-export:   pub use memory::{asm_bindings, hardened_allocator};  (lib.rs)
use crate::asm_bindings::*;
```

---

## 1. Diagnostics Commands

| Command | Description | Use Case |
|---------|-------------|----------|
| `cpu-info` | Display CPU vendor, features, SIMD support | Check hardware capabilities |
| `cpu-bench` | Benchmark instruction throughput | Performance analysis |
| `atomic-test` | Test atomic operations | Verify lock-free correctness |
| `spinlock-test` | Test spinlock implementation | Validate synchronization |

---

## 2. Data Structures

These `#[repr(C)]` structs are defined in `asm_bindings.rs` and must match the assembly layout exactly.

### `ProcessContext` (40 bytes)

```rust
#[repr(C)]
pub struct ProcessContext {
    pub ebx: u32,     // +0
    pub ecx: u32,     // +4
    pub edx: u32,     // +8
    pub esi: u32,     // +12
    pub edi: u32,     // +16
    pub ebp: u32,     // +20
    pub esp: u32,     // +24
    pub eip: u32,     // +28
    pub eflags: u32,  // +32  (default: 0x202 — IF set)
    pub cr3: u32,     // +36
}
```

### `CpuIdResult`

```rust
#[repr(C)]
pub struct CpuIdResult { pub eax: u32, pub ebx: u32, pub ecx: u32, pub edx: u32 }
```

### `CpuFeatures`

```rust
#[repr(C)]
pub struct CpuFeatures { pub ecx_features: u32, pub edx_features: u32 }
```

### `CacheInfo`

```rust
#[repr(C)]
pub struct CacheInfo { pub eax: u32, pub ebx: u32, pub ecx: u32, pub edx: u32 }
```

---

## 3. CPU Feature Detection

```rust
use crate::asm_bindings::*;

// SSE/AVX detection
if has_sse()    { /* Use SSE    */ }
if has_sse2()   { /* Use SSE2   */ }
if has_sse3()   { /* Use SSE3   */ }
if has_sse4_1() { /* Use SSE4.1 */ }
if has_sse4_2() { /* Use SSE4.2 */ }
if has_avx()    { /* Use AVX    */ }

// XSAVE / FPU state
if has_xsave() {
    let mut area = [0u8; 512];
    fxsave(&mut area);   // Save FPU/SSE state
    fxrstor(&area);      // Restore FPU/SSE state
}

// CPU vendor — returns [u8; 12], not &str
let raw = get_cpu_vendor();
// b"GenuineIntel" or b"AuthenticAMD"
if let Ok(s) = core::str::from_utf8(&raw) { /* use s */ }

// Raw CPUID
let result: CpuIdResult = cpuid(0x1, 0);

// Feature flag structs
let features: CpuFeatures = get_cpu_features();
let cache:    CacheInfo   = get_cache_info();

// Hardware random (checks RDRAND support first)
if has_rdrand() {
    if let Some(rand) = try_rdrand() {
        // Use hardware entropy
    }
}
```

---

## 4. Atomic Operations

```rust
use crate::asm_bindings::*;

let mut value: u32 = 100;

// Load / Store
let x = atomic_load(&value);
atomic_store(&mut value, 200);

// Arithmetic — add/sub return old value; inc/dec return new value
let old = atomic_add(&mut value, 10);
let old = atomic_sub(&mut value, 5);
let new = atomic_inc(&mut value);
let new = atomic_dec(&mut value);

// Exchange
let old = atomic_swap(&mut value, 999);

// Compare-and-swap (strong)
let old = atomic_cmpxchg(&mut value, expected, desired);
if old == expected { /* success */ } else { /* retry */ }

// Bitwise
atomic_and(&mut value, mask);
atomic_or(&mut value, bits);
atomic_xor(&mut value, bits);
```

---

## 5. Spinlock

```rust
use crate::asm_bindings::Spinlock;

let mut lock = Spinlock::new();
lock.init();

// Blocking acquire
lock.lock();
// critical section
lock.unlock();

// Non-blocking try
if lock.try_lock() {
    // Got the lock
    lock.unlock();
} else {
    // Lock was held — defer work
}
```

---

## 6. Context Switching

```rust
use crate::asm_bindings::*;

// Save current context, load new context
asm_switch_context(old_ctx_ptr, new_ctx_ptr);

// Save only
asm_save_context(ctx_ptr);  // returns 0

// Load only (does not return)
asm_load_context(ctx_ptr);

// WASM / thread start trampoline (does not return)
thread_start_trampoline();

// Ring-0 → Ring-3 iret transition (does not return)
// Expects [esp+0]=user_entry, [esp+4]=user_stack on the kernel stack
kernel_user_entry_trampoline();

// Unwind a JIT-sandbox page fault frame
asm_jit_fault_resume();
```

---

## 7. CR Register & SMAP Control

```rust
use crate::asm_bindings::*;

let cr0 = read_cr0();
write_cr0(cr0 | 0x1);

let cr3 = read_cr3();
write_cr3(new_page_dir_addr);

let cr4 = read_cr4();
write_cr4(cr4);

// SMAP: supervisor-access-to-user-pages control
stac();  // Set AC flag   — allow supervisor access to user pages
clac();  // Clear AC flag — deny  supervisor access to user pages
```

---

## 8. Port I/O

```rust
use crate::asm_bindings::*;

unsafe { outb(0x3F8, byte_value); }  // Write byte to COM1
let b = unsafe { inb(0x3F8) };       // Read byte from COM1
```

---

## 9. Performance Measurement

```rust
use crate::asm_bindings::*;

// Manual timing
let start = rdtsc_begin();
expensive_operation();
let end   = rdtsc_end();
let cycles = end.wrapping_sub(start);

// Closure wrapper
let cycles = measure_cycles(|| { expensive_operation(); });

// Instruction benchmarks (returns total cycles for N iterations)
let nop   = benchmark_nop(100_000);
let add   = benchmark_add(100_000);
let mul   = benchmark_mul(100_000);
let div   = benchmark_div(100_000);
let load  = benchmark_load(&value, 100_000);
let store = benchmark_store(&mut value, 100_000);
let lock  = benchmark_lock(&mut value, 100_000);

// Performance counter
let pmc = unsafe { asm_rdpmc(0) };         // counter 0

// Instruction serialization
unsafe { asm_serialize(); }                // CPUID serialize
let ts  = unsafe { asm_lfence_rdtsc() };  // LFENCE + RDTSC
```

---

## 10. Memory Fences

```rust
use crate::asm_bindings::*;

load_fence();    // LFENCE — acquire (before reading shared data)
store_fence();   // SFENCE — release (after writing shared data)
memory_fence();  // MFENCE — full fence

while !condition {
    pause();  // PAUSE — spin-wait hint (saves power, improves hyperthreading)
}
```

---

## 11. Memory Operations

```rust
use crate::asm_bindings::*;

// REP MOVSD — ~5× faster than byte loop
fast_memcpy(&mut dst, &src);

// REP STOSD — ~4× faster than byte loop
fast_memset(&mut buf, 0x42);

// REP CMPSB
let equal = fast_memcmp(&a, &b);

// XOR cipher (obfuscation only — not cryptographically secure)
xor_cipher(&mut data, key_byte);
```

---

## 12. Cache Control

```rust
use crate::asm_bindings::*;

clflush(&data[0]);       // Flush cache line to RAM
prefetch_t0(&data[0]);   // Pull into L1 cache
prefetch_t1(&data[0]);   // Pull into L2 cache
prefetch_t2(&data[0]);   // Pull into L3 cache
prefetch_nta(&data[0]);  // Non-temporal (minimal cache pollution)
```

---

## 13. Network Utilities

```rust
use crate::asm_bindings::*;

// Byte-order conversion (symmetric — htons == ntohs on all platforms)
let net16  = htons(host16_value);
let host16 = ntohs(net16_value);
let net32  = htonl(host32_value);
let host32 = ntohl(net32_value);

// Checksums
let ip_csum  = ip_checksum(&ip_header_bytes);
let tcp_csum = tcp_checksum(&segment, src_ip, dst_ip, proto);

// Frame / header parsing
let mut dst_mac   = [0u8; 6];
let mut src_mac   = [0u8; 6];
let mut ethertype: u16 = 0;
unsafe { asm_parse_ethernet_frame(pkt_ptr, &mut dst_mac, &mut src_mac, &mut ethertype); }

let mut ver_ihl:   u8  = 0;
let mut total_len: u16 = 0;
let mut protocol:  u8  = 0;
let mut src_ip:    u32 = 0;
let mut dst_ip:    u32 = 0;
unsafe { asm_parse_ipv4_header(ip_ptr, &mut ver_ihl, &mut total_len, &mut protocol, &mut src_ip, &mut dst_ip); }
```

---

## 14. Cryptographic Hashes

```rust
use crate::asm_bindings::*;

let fnv  = hash_data(data);   // FNV-1a
let djb2 = hash_djb2(data);   // DJB2
let sdbm = hash_sdbm(data);   // SDBM
```

---

## 15. Interrupt Control

```rust
use crate::asm_bindings::*;

enable_interrupts();           // STI
disable_interrupts();          // CLI
hlt();                         // HLT — wait for next interrupt
let ts = read_timestamp();     // RDTSC (raw, no serialization)
```

---

## 16. Performance Tips

### Minimize LOCK overhead
```rust
// Bad: lock on every iteration
for _ in 0..1000 { atomic_inc(&mut counter); }

// Good: accumulate locally, commit once
let mut local = 0u32;
for _ in 0..1000 { local += 1; }
atomic_add(&mut counter, local);
```

### Use PAUSE in spin loops
```rust
while atomic_load(&flag) == 0 {
    pause();
}
```

### Prefer try-lock over blocking
```rust
if lock.try_lock() {
    process();
    lock.unlock();
} else {
    defer_work(process);
}
```

### Cache-aware prefetching
```rust
for i in 0..data.len() {
    if i + 8 < data.len() { prefetch_t0(&data[i + 8]); }
    process(&data[i]);
}
```

### Align hot data to cache lines
```rust
#[repr(align(64))]
struct HotData { counter: u32 }
```

---

## 17. Instruction Latency Reference

| Operation | Cycles | Notes |
|-----------|--------|-------|
| NOP | 0–1 | May be eliminated |
| ADD | 1 | Throughput: 3–4/cycle |
| MUL | 3–5 | Integer multiply |
| DIV | 12–40 | Slowest integer op |
| LOAD | 3–4 | L1 cache hit |
| STORE | 1 | Write-through |
| LOCK ADD | 20–50 | Bus lock overhead |
| CMPXCHG | 20–50 | With LOCK prefix |
| PAUSE | 5–10 | Spin-wait hint |

### Typical Results — Intel Core i5 (Haswell)
```
NOP:   0 cycles/op  (superscalar)
ADD:   0 cycles/op  (superscalar)
MUL:   3 cycles/op
DIV:  12 cycles/op
LOAD:  4 cycles/op  (L1)
STORE: 1 cycles/op
LOCK: 25 cycles/op  (~25× overhead)
```

### Expected Kernel Performance
- Spinlock acquire/release: 12–30 cycles
- Context switch (no TLB flush): 50–100 cycles
- Atomic increment: 20–50 cycles
- CAS: 20–50 cycles

---

## 18. Common Patterns

### Lock-Free Counter
```rust
fn increment_counter(counter: &mut u32) -> u32 { atomic_inc(counter) }
```

### CAS Loop
```rust
fn update_with_function(value: &mut u32, f: impl Fn(u32) -> u32) {
    loop {
        let old = atomic_load(value);
        let new = f(old);
        if atomic_cmpxchg(value, old, new) == old { break; }
        pause();
    }
}
```

### Bounded Retry
```rust
fn try_atomic_update(value: &mut u32, max_retries: u32) -> bool {
    for _ in 0..max_retries {
        let old = atomic_load(value);
        if atomic_cmpxchg(value, old, old + 1) == old { return true; }
        pause();
    }
    false
}
```

---

## 19. Debugging Tips

1. **Verify atomics** — run `atomic-test` from the kernel shell.
2. **Check CPU features** — run `cpu-info` before using SIMD or RDRAND.
3. **Baseline perf** — run `cpu-bench` to establish instruction costs on your hardware.
4. **Profile hot paths** — wrap suspected bottlenecks with `measure_cycles()`.
5. **Test spinlocks** — run `spinlock-test` to verify lock/unlock correctness.

---

## 20. Assembly File Locations

All assembly lives under `kernel/src/asm/`. The Rust safe-wrapper module is `kernel/src/memory/asm_bindings.rs`.

```
kernel/src/asm/
│
│  ── Shared (all architectures) ──────────────────────────────
├── atomic.asm              # Atomic ops, spinlocks, fences
├── context_switch.asm      # Process context switching, trampolines
├── cpu_features.asm        # CPUID, feature detection
├── crypto.asm              # FNV-1a / DJB2 / SDBM hashes, XOR cipher
├── interrupt.asm           # STI, CLI, HLT, RDTSC, I/O wait, CR regs
├── memory.asm              # memcpy, memset, memcmp (REP MOVSD/STOSD)
├── network.asm             # Endian swap, IP/TCP checksums, frame parse
├── perf.asm                # RDTSC, RDPMC, benchmarks, prefetch, clflush
├── acpi.asm                # ACPI table access helpers
├── boot.asm                # i686 Multiboot1 boot entry
├── boot_x86_64_mb2.asm     # x86_64 Multiboot2 boot entry
├── cow.asm                 # Copy-on-write page helpers
├── dma.asm                 # DMA transfer primitives
├── gdt.asm                 # GDT load / reload helpers
├── idt.asm                 # IDT load helpers
├── memopt.asm              # Memory optimisation primitives
├── process.asm             # Process-level assembly helpers
├── sgx.asm                 # SGX enclave support (shared stubs)
├── syscall_entry.asm       # Syscall entry point (INT 0x80 / SYSCALL)
├── sysenter.asm            # SYSENTER fast-call path (i686)
├── temporal.asm            # Temporal snapshot assembly helpers
│
│  ── x86_64-specific ─────────────────────────────────────────
├── x86_64_atomics.asm      # 64-bit atomic operations
├── x86_64_cpu_features.asm # x86_64 CPUID / feature probes
├── x86_64_crypto.asm       # x86_64 crypto primitives
├── x86_64_fpu.asm          # FXSAVE / FXRSTOR / XSAVE area management
├── x86_64_hashes.asm       # x86_64-optimised hash routines
├── x86_64_memory.asm       # x86_64 REP-based memory ops
├── x86_64_perf.asm         # x86_64 RDTSC / RDPMC / benchmarks
├── x86_64_pic.asm          # x86_64 PIC / APIC helpers
├── x86_64_sgx.asm          # x86_64 SGX ENCLS / ENCLU stubs
├── x86_64_shims.asm        # x86_64 ABI shims / calling-convention adapters
├── x86_64_simd_scan.asm    # SSE/AVX bulk memory scan
├── x86_64_spinlock.asm     # x86_64 CMPXCHG-based spinlock
├── x86_64_sysenter.asm     # x86_64 SYSCALL entry / exit
├── x86_64_temporal.asm     # x86_64 temporal snapshot helpers
│
│  ── AArch64-specific ────────────────────────────────────────
├── aarch64_scheduler.S     # AArch64 context-switch / scheduler primitives
├── aarch64_vectors.S       # AArch64 exception vector table
└── boot_aarch64_virt.S     # AArch64 QEMU virt boot entry
```

---

## 21. Build Commands

```bash
# ── i686 (most complete runtime path) ──────────────────────
cd kernel && ./build.sh
./run.sh
# or directly:
qemu-system-i386 -cdrom oreulia.iso

# Quick Rust-only rebuild (i686)
cargo +nightly-2024-01-01 build --release --target ./i686-oreulia.json

# ── x86_64 (Multiboot2 + GRUB) ─────────────────────────────
cd kernel && ./build-x86_64-full.sh
./run-x86_64-mb2-grub.sh

# ── AArch64 (QEMU virt) ────────────────────────────────────
cd kernel && ./build-aarch64-virt.sh
./run-aarch64-virt-image.sh

# With virtio-blk MMIO
./run-aarch64-virt-image-virtio-blk-mmio.sh

# With virtio-net + virtio-blk MMIO
./run-aarch64-virt-image-virtio-net-blk-mmio.sh
```

---

## Further Reading

- Intel® 64 and IA-32 Architectures Software Developer's Manual
- Intel® 64 and IA-32 Architectures Optimization Reference Manual
- ARM Architecture Reference Manual (ARMv8-A)
- Linux kernel atomic operations (`arch/x86/include/asm/atomic.h`)
- Rust `core::sync::atomic` documentation
