# `kernel/src/memory` — Memory Management Subsystem

The `memory` module is the **foundation layer** of the Oreulia kernel. Every other subsystem depends on it for allocation, physical frame tracking, JIT arena management, hardware-accelerated memory operations, and the wait-free telemetry ring. It also provides the only path through which the kernel crosses the boundary from safe Rust into raw assembly operations — CR register access, CPUID, RDTSC, I/O port instructions, and context switch primitives all live here.

---

## Design Philosophy

1. **Fail-closed on corruption.** The `HardenedAllocator` wraps every allocation with a pre/post canary (`0xDEADBEEF`) and a poison guard byte (`0xAA`). Any violation panics the kernel immediately rather than allowing silent heap corruption.
2. **Two allocators, two purposes.** The standard `LockedBumpAllocator` (fast, no overhead) is used for normal kernel heap allocations. The `LockedHardenedAllocator` (canary guards, backtrace capture, stats tracking) is used for security-sensitive allocations such as capability tables and cryptographic key material.
3. **Physical frame accounting without page tables.** Physical frame reference counts are stored in a flat static array (`FRAME_REFCOUNTS`). This intentionally avoids a page table walker dependency during early boot when the virtual address space is not yet fully configured.
4. **JIT arena is a separate region.** WASM JIT code must be placed in a distinct virtual address range so that code and data cannot be confused, and so that a JIT region overflow cannot corrupt the general heap.
5. **Assembly stays in one file.** All `extern "C"` assembly bindings — context switching, I/O ports, CR registers, CPUID, timers, fences, atomics — are collected in `asm_bindings.rs` to give a single searchable reference for anything that requires inline assembly.

---

## Source Layout

| File | Lines | Role |
|---|---|---|
| `mod.rs` | 334 | `BumpAllocator`, `LockedBumpAllocator`, frame allocator, JIT arena, global `#[global_allocator]` binding |
| `hardened_allocator.rs` | 412 | `HardenedAllocator` with canary guards, guard bytes, stats, backtrace capture |
| `asm_bindings.rs` | 896 | All `extern "C"` assembly bindings: context switch, I/O ports, CR regs, CPUID, RDTSC, atomics, benchmarks |
| `wait_free_ring.rs` | 288 | `WaitFreeRingBuffer<T, N>` lock-free SPSC ring; `TELEMETRY_RING` global; `TelemetryEvent` |
| `aarch64_alloc.rs` | 124 | AArch64-specific physical page allocator shim |

---

## `mod.rs` — Primary Heap and Frame Allocator

### Capacity Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_FRAMES` | `8192` | Maximum physical frames tracked by the frame allocator |
| `PAGE_SIZE` | `4096` | Physical page size (4 KiB) |
| `HOST_TEST_HEAP` | `2 MiB` | Static heap backing store for host-mode tests |
| `HOST_TEST_JIT_ARENA` | `512 KiB` | Static JIT arena backing store for host-mode tests |

### `BumpAllocator`

A simple linear bump allocator. Not thread-safe on its own; always used through `LockedBumpAllocator`.

| Field | Description |
|---|---|
| `heap_start` | First byte of usable heap |
| `heap_end` | One byte past the end of the heap |
| `next` | Next free address (monotonically increasing) |

Key methods:

| Method | Description |
|---|---|
| `const fn new()` | Construct a zeroed allocator (safe for use in statics) |
| `init(heap_start, heap_size)` | Set the heap range; must be called before any allocation |
| `alloc(layout)` | Allocate with alignment; returns `Ok(ptr)` or `Err("out of memory")` |
| `dealloc(_ptr, _layout)` | No-op (bump allocator never frees) |

### `LockedBumpAllocator`

`pub struct LockedBumpAllocator(Mutex<BumpAllocator>)` — registered as the kernel's `#[global_allocator]`. All `Box`, `Vec`, and `String` allocations in the kernel path through here.

The global instance is:
```rust
static ALLOCATOR: LockedBumpAllocator = LockedBumpAllocator(Mutex::new(BumpAllocator::new()));
```

### JIT Arena

A separate memory region for WASM JIT-compiled code output. Managed independently of the main heap.

| Function | Description |
|---|---|
| `init_jit_arena()` | Initialize the JIT arena from a sysmap region |
| `jit_allocate(size, align)` | Bump-allocate within the JIT arena |
| `jit_allocate_pages(count)` | Allocate `count` 4 KiB pages from the JIT arena |
| `jit_arena_range()` | Return `(start, end)` of the JIT arena |
| `jit_arena_contains_range(base, size)` | Range check — is `[base, base+size)` fully inside the JIT arena? |

### Physical Frame Allocator

A flat bitmap + reference count array for physical page frame tracking. No heap required.

| Constant | Description |
|---|---|
| `MAX_FRAMES = 8192` | Tracks up to 32 MiB of physical memory (8192 × 4 KiB) |

| Function | Description |
|---|---|
| `allocate_frame()` | Find a free frame, increment its refcount to 1, return physical address |
| `allocate_pages(count)` | Allocate `count` contiguous physical frames |
| `deallocate_pages(base, count)` | Stub (deallocation not yet implemented) |
| `get_refcount(phys_addr)` | Read the reference count for a frame |
| `inc_refcount(phys_addr)` | Increment a frame's reference count |
| `dec_refcount(phys_addr)` | Decrement; panics on underflow |

### Heap and JIT Range Queries

| Function | Description |
|---|---|
| `heap_range()` | Return `(start, end)` of the general-purpose heap |
| `jit_arena_range()` | Return `(start, end)` of the JIT arena |

---

## `hardened_allocator.rs` — Security-Grade Allocator

The `HardenedAllocator` adds defensive features around the bump allocator for allocations that require integrity guarantees:

- A `u32` pre-canary (`0xDEADBEEF`) written before the allocation payload.
- A `u32` post-canary (`0xDEADBEEF`) written after the allocation payload.
- A guard poison byte (`0xAA`) in the gap between the header and the payload.
- An `#[cfg(debug_assertions)]` 4-frame backtrace captured at allocation time using `asm_save_context` return addresses.
- A live `AllocatorStats` maintained continuously.

### `AllocationHeader` (private)

| Field | Size | Description |
|---|---|---|
| `canary_pre` | `u32` | Must equal `0xDEADBEEF` at deallocation |
| `size` | `usize` | Requested payload size |
| `layout_size` | `usize` | Actual allocated layout size |
| `layout_align` | `usize` | Alignment requirement |
| `allocation_id` (debug) | `u64` | Monotonically increasing allocation identifier |
| `backtrace` (debug) | `[usize; 4]` | Return addresses: RA0 = direct caller, RA1-3 = frames up |
| `canary_post` | `u32` | Must equal `0xDEADBEEF` at deallocation |

### `AllocatorStats`

| Field | Type | Description |
|---|---|---|
| `total_allocations` | `u64` | Lifetime allocation count |
| `total_deallocations` | `u64` | Lifetime deallocation count |
| `current_allocations` | `u64` | Currently live allocations |
| `peak_allocations` | `u64` | Highest ever concurrent allocations |
| `bytes_allocated` | `usize` | Lifetime bytes allocated |
| `bytes_freed` | `usize` | Lifetime bytes freed |
| `bytes_in_use` | `usize` | Current live bytes |
| `peak_bytes_in_use` | `usize` | High-water mark of live bytes |
| `fragmentation_score` | `f32` | 0.0 = no fragmentation, 1.0 = fully fragmented |
| `heap_efficiency` | `f32` | 0.0 = empty, 1.0 = fully utilized |
| `guard_page_violations` | `u64` | Count of guard pattern corruption detections |
| `canary_violations` | `u64` | Count of canary value overwrites detected |

### `HardenedAllocator` API

| Function | Description |
|---|---|
| `const fn new()` | Zero-initialize (safe for static) |
| `init(heap_start, heap_size)` | Set the managed range |
| `alloc(layout)` | Allocate with canary and guard byte injection |
| `dealloc(ptr, layout)` | Verify canaries on free; panic on violation |
| `get_stats()` | Return a copy of `AllocatorStats` |
| `check_leaks()` | (debug) Return `Vec<(addr, size, id)>` of unreleased allocations |
| `update_fragmentation()` | Recompute `fragmentation_score` and return it |

### `LockedHardenedAllocator`

```rust
pub struct LockedHardenedAllocator(pub Mutex<HardenedAllocator>);
```

The global instance `HARDENED_ALLOCATOR` is initialized during `memory::init()`.

---

## `wait_free_ring.rs` — Lock-Free SPSC Telemetry Ring

A wait-free, `const`-generic single-producer/single-consumer ring buffer backed purely by `AtomicUsize` head and tail. Zero allocation. Safe across interrupt-context producers.

### `WaitFreeRingBuffer<T, const N: usize>`

| Field | Description |
|---|---|
| `buf: [UnsafeCell<MaybeUninit<T>>; N]` | Backing storage |
| `head: AtomicUsize` | Consumer pop pointer |
| `tail: AtomicUsize` | Producer push pointer |

| Method | Description |
|---|---|
| `const fn new()` | Construct (safe in statics) |
| `push(item)` | Enqueue; returns `false` if full |
| `pop()` | Dequeue; returns `None` if empty |
| `is_empty()` | True if no unread items |
| `len()` | Approximate number of unread items |

### `TelemetryEvent`

Events pushed from across the kernel to the telemetry ring:

| Field | Type | Description |
|---|---|---|
| `timestamp` | `u64` | RDTSC timestamp at event time |
| `event_type` | `u8` | Event category code |
| `process_id` | `u8` | PID that generated the event |
| `cap_type` | `u8` | Capability type involved |
| `data` | `[u8; 13]` | Event-specific payload |

Special constant: `TELEMETRY_CAP_TYPE_VFS_WATCH = 0xFE` — marks VFS inotify-style events.

### Global Ring

```rust
pub const TELEMETRY_RING_CAPACITY: usize = 256;
pub static TELEMETRY_RING: WaitFreeRingBuffer<TelemetryEvent, TELEMETRY_RING_CAPACITY>;
```

`drain_telemetry_to_serial(limit)` drains up to `limit` events, serializing each as a binary record prefixed with `DRAIN_MAGIC = [0xEF, 0xBE, 0xAD, 0xDE]`, and writes them to the kernel serial port.

---

## `asm_bindings.rs` — Hardware Abstraction through Assembly

All `unsafe extern "C"` assembly imports and safe Rust wrappers are collected here. The assembly implementations live in `kernel/src/arch/` `.asm` files.

### Context Switch

| Function | Description |
|---|---|
| `asm_switch_context(old_ctx, new_ctx)` | Save current registers to `old_ctx`; load `new_ctx` |
| `asm_save_context(ctx)` | Save-only; returns `0` |
| `asm_load_context(ctx) -> !` | Load-only; never returns |
| `thread_start_trampoline() -> !` | Thread entry point; pops entry function from stack |
| `user_mode_trampoline() -> !` | Kernel → Ring-3 transition |
| `ProcessContext` struct | `eip, esp, ebp, ebx, esi, edi, eflags, cs, ds, ss, cr3` |

### I/O Ports

| Function | Description |
|---|---|
| `outb(port, value)` | Write byte to x86 I/O port (unsafe) |
| `inb(port) -> u8` | Read byte from x86 I/O port (unsafe) |
| `ntohs`, `htons`, `ntohl`, `htonl` | Network byte-order conversions (implemented in Rust) |

### CR Register Access

| Function | Description |
|---|---|
| `read_cr0() -> u32` | Read CR0 (PE, PG, MP, TS, WP flags) |
| `write_cr0(value)` | Write CR0 |
| `read_cr3() -> u32` | Read CR3 (page directory base) |
| `write_cr3(page_dir_addr)` | Load page directory |
| `read_cr4() -> u32` | Read CR4 (PAE, PSE, OSFXSR, OSXSAVE flags) |
| `write_cr4(value)` | Write CR4 |

### SMAP/SMEP

| Function | Description |
|---|---|
| `stac()` | Set AC flag — allow user-space memory access in the kernel |
| `clac()` | Clear AC flag — re-enable SMAP protection |

### Interrupt Control

| Function | Description |
|---|---|
| `enable_interrupts()` | `sti` — enable hardware interrupts |
| `disable_interrupts()` | `cli` — disable hardware interrupts |
| `hlt()` | Halt the CPU until next interrupt |
| `pause()` | `pause` — spin-loop hint |

### Memory Barriers

| Function | Description |
|---|---|
| `memory_fence()` | Full read+write fence (`mfence`) |
| `load_fence()` | Load-only fence (`lfence`) |
| `store_fence()` | Store-only fence (`sfence`) |

### Bulk Memory Operations

| Function | Description |
|---|---|
| `fast_memcpy(dest, src)` | Optimized `rep movsb` bulk copy |
| `fast_memset(dest, value)` | Optimized `rep stosb` bulk fill |
| `fast_memcmp(a, b) -> bool` | Optimized bulk compare; returns true if equal |

### Checksum and Hash

| Function | Description |
|---|---|
| `ip_checksum(header) -> u16` | RFC 791 IP header one's complement checksum |
| `tcp_checksum(data, src_ip, dst_ip, proto) -> u16` | TCP pseudo-header checksum |
| `hash_data(data) -> u32` | General-purpose non-cryptographic hash (dispatcher) |
| `hash_djb2(data) -> u32` | DJB2 hash |
| `hash_sdbm(data) -> u32` | SDBM hash |

### CPU Feature Detection

| Function | Description |
|---|---|
| `cpuid(eax, ecx) -> CpuIdResult` | Raw `CPUID` instruction |
| `has_sse() -> bool` | SSE support |
| `has_sse2() -> bool` | SSE2 support |
| `has_sse3() -> bool` | SSE3 support |
| `has_sse4_1() -> bool` | SSE 4.1 support |
| `has_sse4_2() -> bool` | SSE 4.2 support |
| `has_avx() -> bool` | AVX support |
| `has_rdrand() -> bool` | RDRAND instruction present |
| `has_xsave() -> bool` | XSAVE/XRSTOR support (required for AVX-512 FPU state) |
| `get_cpu_vendor() -> [u8; 12]` | CPU vendor string ("GenuineIntel", "AuthenticAMD", etc.) |
| `get_cpu_features() -> CpuFeatures` | Struct of individual feature flags |
| `get_cache_info() -> CacheInfo` | L1/L2/L3 size and associativity |

### Hardware RNG

| Function | Description |
|---|---|
| `try_rdrand() -> Option<u32>` | Attempt one RDRAND sample; `None` if not supported or fails |

### Cycle-Accurate Timing

| Function | Description |
|---|---|
| `rdtsc_begin() -> u64` | Serializing RDTSC read for interval start (includes `cpuid` fence) |
| `rdtsc_end() -> u64` | Serializing RDTSC read for interval end (includes `lfence`) |
| `measure_cycles(f: F) -> u64` | Run `f` and return elapsed cycles |

### Microbenchmarks

| Function | Description |
|---|---|
| `benchmark_nop(iterations) -> u64` | Cycles per NOP instruction |
| `benchmark_add(iterations) -> u64` | Cycles per ADD instruction |
| `benchmark_mul(iterations) -> u64` | Cycles per MUL instruction |
| `benchmark_div(iterations) -> u64` | Cycles per DIV instruction |
| `benchmark_load(ptr, iterations) -> u64` | L1/L2/L3 load latency |
| `benchmark_store(ptr, iterations) -> u64` | Store throughput |
| `benchmark_lock(ptr, iterations) -> u64` | LOCK prefix overhead |

### Cache Management

| Function | Description |
|---|---|
| `clflush(addr)` | Flush a cache line from all CPU caches |
| `prefetch_t0(addr)` | Prefetch into L1 cache |
| `prefetch_t1(addr)` | Prefetch into L2 cache |
| `prefetch_t2(addr)` | Prefetch into L3 cache |
| `prefetch_nta(addr)` | Non-temporal prefetch (bypass all caches) |

### Software Atomics

These provide sequentially-consistent atomic operations over `*mut u32` for environments where Rust's `AtomicU32` is unavailable (early boot, very old targets):

| Function | Description |
|---|---|
| `atomic_load(ptr) -> u32` | Load with acquire semantics |
| `atomic_store(ptr, value)` | Store with release semantics |
| `atomic_add(ptr, value) -> u32` | Fetch-and-add; returns old value |
| `atomic_sub(ptr, value) -> u32` | Fetch-and-sub; returns old value |
| `atomic_inc(ptr) -> u32` | Fetch-and-increment |
| `atomic_dec(ptr) -> u32` | Fetch-and-decrement |
| `atomic_swap(ptr, new_value) -> u32` | Unconditional exchange; returns old value |
| `atomic_cmpxchg(ptr, expected, desired) -> u32` | Compare-and-swap; returns old value |
| `atomic_and(ptr, value)` | Bitwise AND in place |
| `atomic_or(ptr, value)` | Bitwise OR in place |
| `atomic_xor(ptr, value)` | Bitwise XOR in place |

---

## `aarch64_alloc.rs` — AArch64 Physical Allocator

A 124-line shim that provides an architecture-specific physical page allocator for the AArch64 (`virt` machine) boot environment. It maps the same interface as the x86 frame allocator in `mod.rs` so that upper-layer code is architecture-agnostic.

---

## Memory Layout at Boot

The kernel memory layout established by `memory::init()`:

| Region | Notes |
|---|---|
| `[0x0000_0000, 0x0010_0000)` | First 1 MiB — legacy BIOS/UEFI reserved |
| `[KERNEL_START, KERNEL_END)` | Kernel `.text`, `.rodata`, `.data`, `.bss` |
| `[HEAP_START, HEAP_END)` | `BumpAllocator` region — varies by sysmap |
| `[JIT_ARENA_START, JIT_ARENA_END)` | WASM JIT output pages |
| Physical frame table | `FRAME_REFCOUNTS[8192]` — 32 KiB static array |

---

## Shell Commands

| Command | Description |
|---|---|
| `mem-info` | Print heap range, JIT arena range, and frame stats |
| `mem-stats` | Print `AllocatorStats` from the hardened allocator |
| `mem-telemetry` | Drain the `TELEMETRY_RING` to serial output |
| `mem-bench` | Run the microbenchmark suite (NOP/ADD/MUL/DIV/LOAD/STORE/LOCK) |
| `cpu-info` | Print vendor string, feature flags, and cache info via CPUID |
| `rdrand` | Sample one 32-bit value from the hardware RNG |
