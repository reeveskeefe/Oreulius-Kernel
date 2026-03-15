# Oreulia — Assembly Quick Reference

**Status:** Reference (Feb 8, 2026)

This guide provides a quick reference for developers working with the kernel's low-level assembly bindings. These functions are exposed via `crate::asm_bindings`.

---

## 1. Diagnostics Commands

| Command | Description | Use Case |
|---------|-------------|----------|
| `cpu-info` | Display CPU vendor, features, SIMD support | Check hardware capabilities |
| `cpu-bench` | Benchmark instruction throughput | Performance analysis |
| `atomic-test` | Test atomic operations | Verify lock-free correctness |
| `spinlock-test` | Test spinlock implementation | Validate synchronization |
| `asm-test` | Original assembly tests | Legacy performance tests |

## CPU Feature Detection

```rust
use crate::asm_bindings::*;

// Check SIMD support
if has_sse2() { /* Use SSE2 */ }
if has_sse3() { /* Use SSE3 */ }
if has_avx() { /* Use AVX */ }

// Get vendor
let vendor = get_cpu_vendor();
// "GenuineIntel" or "AuthenticAMD"

// Hardware random
if let Some(rand) = try_rdrand() {
    // Use hardware entropy
}
```

## Atomic Operations API

```rust
use crate::asm_bindings::*;

let mut value: u32 = 100;

// Load/Store
let x = atomic_load(&value);
atomic_store(&mut value, 200);

// Arithmetic
let old = atomic_add(&mut value, 10);  // Returns old value
let old = atomic_sub(&mut value, 5);   // Returns old value
let new = atomic_inc(&mut value);      // Returns new value
let new = atomic_dec(&mut value);      // Returns new value

// Exchange
let old = atomic_swap(&mut value, 999);

// Compare-and-swap
let old = atomic_cmpxchg(&mut value, expected, desired);
if old == expected {
    // Success - stored desired
} else {
    // Failure - value != expected
}

// Bitwise
atomic_and(&mut value, mask);
atomic_or(&mut value, bits);
atomic_xor(&mut value, bits);
```

## Spinlock Usage

```rust
use crate::asm_bindings::Spinlock;

let mut lock = Spinlock::new();
lock.init();

// Blocking acquire
lock.lock();
// Critical section
lock.unlock();

// Non-blocking try
if lock.try_lock() {
    // Got the lock
    lock.unlock();
} else {
    // Lock was held
}
```

## Performance Measurement

```rust
use crate::asm_bindings::*;

// Method 1: Manual timing
let start = rdtsc_begin();
expensive_operation();
let end = rdtsc_end();
let cycles = end.wrapping_sub(start);

// Method 2: Closure wrapper
let cycles = measure_cycles(|| {
    expensive_operation();
});

// Microbenchmarks
let cycles_add = benchmark_add(100000);
let cycles_mul = benchmark_mul(100000);
let cycles_div = benchmark_div(100000);
```

## Memory Fences

```rust
use crate::asm_bindings::*;

// Acquire semantics (before reading shared data)
load_fence();  // LFENCE

// Release semantics (after writing shared data)
store_fence();  // SFENCE

// Full fence (both loads and stores)
memory_fence();  // MFENCE

// Spin-wait hint (in busy loops)
while !condition {
    pause();  // Reduces power and improves hyperthreading
}
```

## Cache Control

```rust
use crate::asm_bindings::*;

// Flush cache line (ensure data written to RAM)
clflush(&data[0]);

// Prefetch (bring data into cache before use)
prefetch_t0(&data[0]);  // L1 cache (most aggressive)
prefetch_t1(&data[0]);  // L2 cache
prefetch_t2(&data[0]);  // L3 cache
prefetch_nta(&data[0]); // Non-temporal (minimal pollution)
```

## Performance Tips

### 1. Minimize LOCK Overhead
```rust
// ❌ Bad: Frequent atomic operations
for i in 0..1000 {
    atomic_inc(&mut counter);  // ~20-50 cycles each
}

// ✓ Good: Batch and update once
let mut local = 0;
for i in 0..1000 {
    local += 1;  // ~1 cycle
}
atomic_add(&mut counter, local);  // ~20-50 cycles once
```

### 2. Use PAUSE in Spin Loops
```rust
// ❌ Bad: Busy-wait without hint
while atomic_load(&flag) == 0 {
    // Wastes power, bad for hyperthreading
}

// ✓ Good: Hint to CPU
while atomic_load(&flag) == 0 {
    pause();  // Reduces power, improves hyperthreading
}
```

### 3. Prefer Try-Lock Over Blocking
```rust
// ❌ Bad: Always block
lock.lock();
process();
lock.unlock();

// ✓ Good: Try first, defer if busy
if lock.try_lock() {
    process();
    lock.unlock();
} else {
    // Queue for later processing
    defer_work(process);
}
```

### 4. Cache-Aware Prefetching
```rust
// ✓ Good: Prefetch before loop
for i in 0..data.len() {
    if i + 8 < data.len() {
        prefetch_t0(&data[i + 8]);  // Prefetch ahead
    }
    process(&data[i]);
}
```

### 5. Align Hot Data
```rust
// ✓ Good: Cache-line aligned (64 bytes)
#[repr(align(64))]
struct HotData {
    counter: u32,
    // ... other frequently accessed fields
}
```

## Instruction Latency Reference

| Operation | Cycles | Notes |
|-----------|--------|-------|
| NOP | 0-1 | May be eliminated |
| ADD | 1 | Throughput: 3-4/cycle |
| MUL | 3-5 | Integer multiply |
| DIV | 12-40 | Slowest integer op |
| LOAD | 3-4 | L1 cache hit |
| STORE | 1 | Write-through |
| LOCK ADD | 20-50 | Bus lock overhead |
| CMPXCHG | 20-50 | With LOCK prefix |
| PAUSE | 5-10 | Spin-wait hint |

## Typical Benchmark Results

### Intel Core i5 (Haswell)
```
NOP:     0 cycles/op
ADD:     0 cycles/op (superscalar)
MUL:     3 cycles/op
DIV:     12 cycles/op
LOAD:    4 cycles/op (L1)
STORE:   1 cycles/op
LOCK:    25 cycles/op (~25x overhead)
```

### Expected Performance
- **Spinlock**: 12-30 cycles/acquire-release
- **Context switch**: 50-100 cycles (no TLB flush)
- **Atomic increment**: 20-50 cycles
- **Compare-and-swap**: 20-50 cycles

## Common Patterns

### Lock-Free Counter
```rust
fn increment_counter(counter: &mut u32) -> u32 {
    atomic_inc(counter)
}
```

### CAS Loop
```rust
fn update_with_function(value: &mut u32, f: impl Fn(u32) -> u32) {
    loop {
        let old = atomic_load(value);
        let new = f(old);
        if atomic_cmpxchg(value, old, new) == old {
            break;
        }
        pause();
    }
}
```

### Double-Checked Locking
```rust
static mut INITIALIZED: u32 = 0;
static mut LOCK: u32 = 0;

fn initialize_once() {
    // Fast path
    if atomic_load(&INITIALIZED) != 0 {
        return;
    }
    
    // Slow path
    let mut lock_value: u32 = 0;
    unsafe {
        asm_spinlock_lock(&mut lock_value as *mut u32);
    }
    
    if atomic_load(&INITIALIZED) == 0 {
        // Do initialization
        init();
        atomic_store(&mut INITIALIZED, 1);
    }
    
    unsafe {
        asm_spinlock_unlock(&mut lock_value as *mut u32);
    }
}
```

### Bounded Retry
```rust
fn try_atomic_update(value: &mut u32, max_retries: u32) -> bool {
    for _ in 0..max_retries {
        let old = atomic_load(value);
        let new = old + 1;
        if atomic_cmpxchg(value, old, new) == old {
            return true;
        }
        pause();
    }
    false  // Failed after max retries
}
```

## Debugging Tips

### 1. Verify Atomic Correctness
Run `atomic-test` to ensure all atomic operations work as expected.

### 2. Check CPU Features
Run `cpu-info` to verify hardware support before using SIMD or RDRAND.

### 3. Measure Performance
Use `cpu-bench` to establish baseline instruction costs on your hardware.

### 4. Profile Hot Paths
Use `measure_cycles()` around suspected bottlenecks.

### 5. Test Spinlocks
Run `spinlock-test` to verify lock/unlock correctness and measure overhead.

## Assembly File Locations

```
kernel/asm/
├── atomic.asm          # Atomic ops, spinlocks, fences
├── context_switch.asm  # Process context switching
├── cpu_features.asm    # CPUID, feature detection
├── crypto.asm          # Hash functions
├── interrupt.asm       # Interrupt control
├── memory.asm          # memcpy, memset, memcmp
├── network.asm         # Endian swap, checksums
└── perf.asm            # Timing, benchmarks, prefetch
```

## Build Commands

```bash
# Full build
cd kernel && ./build.sh

# Quick rebuild (if only Rust changed)
cargo +nightly-2023-11-01 build --release --target ./i686-oreulia.json

# Run in QEMU
./run.sh
# or
qemu-system-i386 -cdrom oreulia.iso
```

## Further Reading

- Intel® 64 and IA-32 Architectures Software Developer's Manual
- "Intel® 64 and IA-32 Architectures Optimization Reference Manual"
- Linux kernel atomic operations (`arch/x86/include/asm/atomic.h`)
- Rust `core::sync::atomic` documentation
