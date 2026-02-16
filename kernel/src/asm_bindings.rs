/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! Assembly function bindings for Oreulia OS
//! 
//! High-performance assembly routines for critical kernel operations.
//! These functions are implemented in assembly for maximum speed and efficiency.

#![allow(dead_code)]

extern "C" {
    // ===== Context Switching (context_switch.asm) =====
    /// Fast context switch between two processes
    /// Saves current context to old_ctx, loads from new_ctx
    pub fn asm_switch_context(old_ctx: *mut ProcessContext, new_ctx: *const ProcessContext);
    
    /// Save current context to memory, returns 0
    pub fn asm_save_context(ctx: *mut ProcessContext) -> i32;
    
    /// Load context from memory (does not return)
    pub fn asm_load_context(ctx: *const ProcessContext) -> !;
    
    /// Thread start trampoline - pops entry function from stack and calls it
    pub fn thread_start_trampoline() -> !;

    // ===== Memory Operations (memory.asm) =====
    /// Ultra-fast memcpy using rep movsd (5x faster than byte-by-byte)
    pub fn asm_fast_memcpy(dest: *mut u8, src: *const u8, count: usize);
    
    /// Fast memset using rep stosd (4x faster than byte-by-byte)
    pub fn asm_fast_memset(dest: *mut u8, value: u8, count: usize);
    
    /// Fast memcmp, returns 0 if equal, 1 if not equal
    pub fn asm_fast_memcmp(ptr1: *const u8, ptr2: *const u8, count: usize) -> i32;
    
    /// IPv4 header checksum (RFC 1071)
    pub fn asm_checksum_ip(header: *const u8, len: usize) -> u16;
    
    /// TCP/UDP checksum with pseudo-header (RFC 793, RFC 768)
    pub fn asm_checksum_tcp(data: *const u8, len: usize, src_ip: u32, dst_ip: u32, proto: u8) -> u16;
    
    // ===== Interrupt & CPU Control (interrupt.asm) =====
    /// Enable CPU interrupts (STI)
    pub fn asm_enable_interrupts();
    
    /// Disable CPU interrupts (CLI)
    pub fn asm_disable_interrupts();
    
    /// Halt CPU until next interrupt (HLT)
    pub fn asm_halt();
    
    /// Read CPU Time Stamp Counter (RDTSC)
    pub fn asm_read_tsc() -> u64;
    
    /// I/O wait operation (~1μs delay)
    pub fn asm_io_wait();
    
    /// Read CR0 control register
    pub fn asm_read_cr0() -> u32;
    
    /// Write CR0 control register
    pub fn asm_write_cr0(value: u32);
    
    /// Read CR3 page directory register
    pub fn asm_read_cr3() -> u32;
    
    /// Write CR3 page directory register
    pub fn asm_write_cr3(page_dir_addr: u32);

    /// Read CR4 control register
    pub fn asm_read_cr4() -> u32;

    /// Write CR4 control register
    pub fn asm_write_cr4(value: u32);

    /// Set AC flag (SMAP: allow supervisor access to user pages)
    pub fn asm_stac();

    /// Clear AC flag (SMAP: disallow supervisor access to user pages)
    pub fn asm_clac();

    /// Resume from a JIT sandbox page fault by unwinding the JIT frame
    pub fn asm_jit_fault_resume();

    // ===== Port I/O (ports.asm) =====
    /// Output byte to port
    pub fn asm_outb(port: u16, value: u8);
    
    /// Input byte from port
    pub fn asm_inb(port: u16) -> u8;
    
    // ===== Network Operations (network.asm) =====
    /// Swap 16-bit endianness (network byte order conversion)
    pub fn asm_swap_endian_16(value: u16) -> u16;
    
    /// Swap 32-bit endianness (network byte order conversion)
    pub fn asm_swap_endian_32(value: u32) -> u32;
    
    /// Parse Ethernet frame header
    pub fn asm_parse_ethernet_frame(
        packet: *const u8,
        dst_mac: *mut [u8; 6],
        src_mac: *mut [u8; 6],
        ethertype: *mut u16,
    );
    
    /// Parse IPv4 header fields
    pub fn asm_parse_ipv4_header(
        ip_header: *const u8,
        version_ihl: *mut u8,
        total_length: *mut u16,
        protocol: *mut u8,
        src_ip: *mut u32,
        dst_ip: *mut u32,
    );
    
    // ===== Cryptographic Operations (crypto.asm) =====
    /// FNV-1a hash (fast non-cryptographic hash)
    pub fn asm_hash_fnv1a(data: *const u8, len: usize) -> u32;
    
    /// DJB2 hash (Dan Bernstein's algorithm)
    pub fn asm_hash_djb2(data: *const u8, len: usize) -> u32;
    
    /// SDBM hash (alternative fast hash)
    pub fn asm_hash_sdbm(data: *const u8, len: usize) -> u32;
    
    /// Simple XOR cipher (for obfuscation, not cryptographically secure)
    pub fn asm_xor_cipher(data: *mut u8, len: usize, key: u8);
    
    // ===== CPU Features (cpu_features.asm) =====
    /// Execute CPUID instruction
    pub fn asm_cpuid(eax_in: u32, ecx_in: u32, result: *mut CpuIdResult);
    
    /// Check if SSE is supported
    pub fn asm_has_sse() -> u32;
    
    /// Check if SSE2 is supported
    pub fn asm_has_sse2() -> u32;
    
    /// Check if SSE3 is supported
    pub fn asm_has_sse3() -> u32;
    
    /// Check if SSE4.1 is supported
    pub fn asm_has_sse4_1() -> u32;
    
    /// Check if SSE4.2 is supported
    pub fn asm_has_sse4_2() -> u32;
    
    /// Check if AVX is supported
    pub fn asm_has_avx() -> u32;
    
    /// Get CPU vendor string
    pub fn asm_get_cpu_vendor(vendor_str: *mut [u8; 12]);
    
    /// Get CPU feature flags
    pub fn asm_get_cpu_features(features: *mut CpuFeatures);
    
    /// Get CPU cache information
    pub fn asm_get_cache_info(cache_info: *mut CacheInfo);
    
    /// Read hardware random number (RDRAND)
    pub fn asm_rdrand(value: *mut u32) -> i32;
    
    /// Check if XSAVE is supported
    pub fn asm_xsave_supported() -> u32;
    
    /// Save FPU/SSE state
    pub fn asm_fxsave(save_area: *mut [u8; 512]);
    
    /// Restore FPU/SSE state
    pub fn asm_fxrstor(save_area: *const [u8; 512]);
    
    // ===== Atomic Operations (atomic.asm) =====
    /// Atomic load with acquire semantics
    pub fn asm_atomic_load(ptr: *const u32) -> u32;
    
    /// Atomic store with release semantics
    pub fn asm_atomic_store(ptr: *mut u32, value: u32);
    
    /// Atomic add, returns old value
    pub fn asm_atomic_add(ptr: *mut u32, value: u32) -> u32;
    
    /// Atomic subtract, returns old value
    pub fn asm_atomic_sub(ptr: *mut u32, value: u32) -> u32;
    
    /// Atomic increment, returns new value
    pub fn asm_atomic_inc(ptr: *mut u32) -> u32;
    
    /// Atomic decrement, returns new value
    pub fn asm_atomic_dec(ptr: *mut u32) -> u32;
    
    /// Atomic swap (exchange)
    pub fn asm_atomic_swap(ptr: *mut u32, new_value: u32) -> u32;
    
    /// Atomic compare-and-swap (strong)
    pub fn asm_atomic_cmpxchg(ptr: *mut u32, expected: u32, desired: u32) -> u32;
    
    /// Atomic compare-and-swap (weak)
    pub fn asm_atomic_cmpxchg_weak(ptr: *mut u32, expected: u32, desired: u32) -> u32;
    
    /// Atomic bitwise AND
    pub fn asm_atomic_and(ptr: *mut u32, value: u32);
    
    /// Atomic bitwise OR
    pub fn asm_atomic_or(ptr: *mut u32, value: u32);
    
    /// Atomic bitwise XOR
    pub fn asm_atomic_xor(ptr: *mut u32, value: u32);
    
    /// Initialize spinlock
    pub fn asm_spinlock_init(lock: *mut u32);
    
    /// Acquire spinlock (blocking)
    pub fn asm_spinlock_lock(lock: *mut u32);
    
    /// Release spinlock
    pub fn asm_spinlock_unlock(lock: *mut u32);
    
    /// Try to acquire spinlock (non-blocking)
    pub fn asm_spinlock_trylock(lock: *mut u32) -> i32;
    
    /// PAUSE instruction (spin-wait hint)
    pub fn asm_pause();
    
    /// Full memory fence (MFENCE)
    pub fn asm_mfence();
    
    /// Load fence (LFENCE)
    pub fn asm_lfence();
    
    /// Store fence (SFENCE)
    pub fn asm_sfence();
    
    // ===== Performance (perf.asm) =====
    /// Begin cycle-accurate timing
    pub fn asm_rdtsc_begin() -> u64;
    
    /// End cycle-accurate timing
    pub fn asm_rdtsc_end() -> u64;
    
    /// Read performance monitoring counter
    pub fn asm_rdpmc(counter: u32) -> u64;
    
    /// Serialize instruction execution
    pub fn asm_serialize();
    
    /// LFENCE + RDTSC
    pub fn asm_lfence_rdtsc() -> u64;
    
    /// Benchmark NOP instruction
    pub fn asm_benchmark_nop(iterations: u32) -> u64;
    
    /// Benchmark ADD instruction
    pub fn asm_benchmark_add(iterations: u32) -> u64;
    
    /// Benchmark MUL instruction
    pub fn asm_benchmark_mul(iterations: u32) -> u64;
    
    /// Benchmark DIV instruction
    pub fn asm_benchmark_div(iterations: u32) -> u64;
    
    /// Benchmark memory LOAD
    pub fn asm_benchmark_load(ptr: *const u32, iterations: u32) -> u64;
    
    /// Benchmark memory STORE
    pub fn asm_benchmark_store(ptr: *mut u32, iterations: u32) -> u64;
    
    /// Benchmark LOCK prefix overhead
    pub fn asm_benchmark_lock(ptr: *mut u32, iterations: u32) -> u64;
    
    /// Flush cache line
    pub fn asm_clflush(addr: *const u8);
    
    /// Prefetch to L1 cache
    pub fn asm_prefetch_t0(addr: *const u8);
    
    /// Prefetch to L2 cache
    pub fn asm_prefetch_t1(addr: *const u8);
    
    /// Prefetch to L3 cache
    pub fn asm_prefetch_t2(addr: *const u8);
    
    /// Prefetch (non-temporal)
    pub fn asm_prefetch_nta(addr: *const u8);
}

/// Process context structure (must match assembly layout)
/// Layout: 40 bytes total
///   +0:  EBX, +4:  ECX, +8:  EDX, +12: ESI
///   +16: EDI, +20: EBP, +24: ESP, +28: EIP, +32: EFLAGS, +36: CR3
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessContext {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
    pub eflags: u32,
    pub cr3: u32,
}

impl ProcessContext {
    /// Create a new context with default values
    pub const fn new() -> Self {
        ProcessContext {
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            ebp: 0,
            esp: 0,
            eip: 0,
            eflags: 0x202, // IF flag set (interrupts enabled)
            cr3: 0,
        }
    }
}

/// CPUID result structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuIdResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// CPU feature flags
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    pub ecx_features: u32,  // Feature flags in ECX
    pub edx_features: u32,  // Feature flags in EDX
}

/// CPU cache information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CacheInfo {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Spinlock structure
#[repr(C)]
pub struct Spinlock {
    lock: u32,
}

impl Spinlock {
    /// Create a new unlocked spinlock
    pub const fn new() -> Self {
        Spinlock { lock: 0 }
    }
    
    /// Initialize the spinlock
    pub fn init(&mut self) {
        unsafe { asm_spinlock_init(&mut self.lock as *mut u32); }
    }
    
    /// Acquire the spinlock (blocking)
    pub fn lock(&mut self) {
        unsafe { asm_spinlock_lock(&mut self.lock as *mut u32); }
    }
    
    /// Release the spinlock
    pub fn unlock(&mut self) {
        unsafe { asm_spinlock_unlock(&mut self.lock as *mut u32); }
    }
    
    /// Try to acquire the spinlock (non-blocking)
    /// Returns true if acquired, false otherwise
    pub fn try_lock(&mut self) -> bool {
        unsafe { asm_spinlock_trylock(&mut self.lock as *mut u32) != 0 }
    }
}

// ===== Safe Rust Wrappers =====

/// Safe wrapper for fast memcpy
pub fn fast_memcpy(dest: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dest.len(), src.len());
    if len > 0 {
        unsafe {
            asm_fast_memcpy(dest.as_mut_ptr(), src.as_ptr(), len);
        }
    }
}

/// Safe wrapper for fast memset
pub fn fast_memset(dest: &mut [u8], value: u8) {
    if !dest.is_empty() {
        unsafe {
            asm_fast_memset(dest.as_mut_ptr(), value, dest.len());
        }
    }
}

/// Safe wrapper for fast memcmp
pub fn fast_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.is_empty() {
        return true;
    }
    unsafe { asm_fast_memcmp(a.as_ptr(), b.as_ptr(), a.len()) == 0 }
}

/// Calculate IPv4 header checksum
pub fn ip_checksum(header: &[u8]) -> u16 {
    if header.is_empty() {
        return 0;
    }
    unsafe { asm_checksum_ip(header.as_ptr(), header.len()) }
}

/// Calculate TCP/UDP checksum with pseudo-header
pub fn tcp_checksum(data: &[u8], src_ip: u32, dst_ip: u32, protocol: u8) -> u16 {
    if data.is_empty() {
        return 0;
    }
    unsafe { asm_checksum_tcp(data.as_ptr(), data.len(), src_ip, dst_ip, protocol) }
}

/// Hash data using FNV-1a algorithm
pub fn hash_data(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 2166136261; // FNV offset basis
    }
    unsafe { asm_hash_fnv1a(data.as_ptr(), data.len()) }
}

/// Hash data using DJB2 algorithm
pub fn hash_djb2(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 5381;
    }
    unsafe { asm_hash_djb2(data.as_ptr(), data.len()) }
}

/// Hash data using SDBM algorithm
pub fn hash_sdbm(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    unsafe { asm_hash_sdbm(data.as_ptr(), data.len()) }
}

/// XOR cipher for simple obfuscation
pub fn xor_cipher(data: &mut [u8], key: u8) {
    if !data.is_empty() {
        unsafe {
            asm_xor_cipher(data.as_mut_ptr(), data.len(), key);
        }
    }
}

/// Read CPU timestamp counter (for high-precision timing)
pub fn read_timestamp() -> u64 {
    unsafe { asm_read_tsc() }
}

/// Enable CPU interrupts
pub fn enable_interrupts() {
    unsafe { asm_enable_interrupts(); }
}

/// Disable CPU interrupts
pub fn disable_interrupts() {
    unsafe { asm_disable_interrupts(); }
}

/// Halt CPU until next interrupt
pub fn hlt() {
    unsafe { asm_halt(); }
}

/// Read CR0 control register
pub fn read_cr0() -> u32 {
    unsafe { asm_read_cr0() }
}

/// Write CR0 control register
pub fn write_cr0(value: u32) {
    unsafe { asm_write_cr0(value) };
}

/// Read CR3 page directory register
pub fn read_cr3() -> u32 {
    unsafe { asm_read_cr3() }
}

/// Write CR3 page directory register (updates page tables)
pub fn write_cr3(page_dir_addr: u32) {
    unsafe { asm_write_cr3(page_dir_addr); }
}

/// Read CR4 control register
pub fn read_cr4() -> u32 {
    unsafe { asm_read_cr4() }
}

/// Write CR4 control register
pub fn write_cr4(value: u32) {
    unsafe { asm_write_cr4(value) };
}

/// Temporarily allow supervisor access to user pages (SMAP)
pub fn stac() {
    unsafe { asm_stac(); }
}

/// Disallow supervisor access to user pages (SMAP)
pub fn clac() {
    unsafe { asm_clac(); }
}

/// Convert 16-bit value from network byte order to host byte order
pub fn ntohs(value: u16) -> u16 {
    unsafe { asm_swap_endian_16(value) }
}

/// Convert 16-bit value from host byte order to network byte order
pub fn htons(value: u16) -> u16 {
    unsafe { asm_swap_endian_16(value) }
}

/// Convert 32-bit value from network byte order to host byte order
pub fn ntohl(value: u32) -> u32 {
    unsafe { asm_swap_endian_32(value) }
}

/// Convert 32-bit value from host byte order to network byte order
pub fn htonl(value: u32) -> u32 {
    unsafe { asm_swap_endian_32(value) }
}

// ===== CPU Feature Detection Wrappers =====

/// Execute CPUID instruction safely
pub fn cpuid(eax: u32, ecx: u32) -> CpuIdResult {
    let mut result = CpuIdResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    unsafe {
        asm_cpuid(eax, ecx, &mut result as *mut CpuIdResult);
    }
    result
}

/// Check if SSE is supported
pub fn has_sse() -> bool {
    unsafe { asm_has_sse() != 0 }
}

/// Check if SSE2 is supported
pub fn has_sse2() -> bool {
    unsafe { asm_has_sse2() != 0 }
}

/// Check if SSE3 is supported
pub fn has_sse3() -> bool {
    unsafe { asm_has_sse3() != 0 }
}

/// Check if SSE4.1 is supported
pub fn has_sse4_1() -> bool {
    unsafe { asm_has_sse4_1() != 0 }
}

/// Check if SSE4.2 is supported
pub fn has_sse4_2() -> bool {
    unsafe { asm_has_sse4_2() != 0 }
}

/// Check if AVX is supported
pub fn has_avx() -> bool {
    unsafe { asm_has_avx() != 0 }
}

/// Get CPU vendor string
pub fn get_cpu_vendor() -> [u8; 12] {
    let mut vendor = [0u8; 12];
    unsafe {
        asm_get_cpu_vendor(&mut vendor as *mut [u8; 12]);
    }
    vendor
}

/// Get CPU feature flags
pub fn get_cpu_features() -> CpuFeatures {
    let mut features = CpuFeatures {
        ecx_features: 0,
        edx_features: 0,
    };
    unsafe {
        asm_get_cpu_features(&mut features as *mut CpuFeatures);
    }
    features
}

/// Get CPU cache information
pub fn get_cache_info() -> CacheInfo {
    let mut info = CacheInfo {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    };
    unsafe {
        asm_get_cache_info(&mut info as *mut CacheInfo);
    }
    info
}

/// Try to get hardware random number
pub fn try_rdrand() -> Option<u32> {
    if !has_rdrand() {
        return None;
    }
    let mut value: u32 = 0;
    unsafe {
        if asm_rdrand(&mut value as *mut u32) != 0 {
            Some(value)
        } else {
            None
        }
    }
}

/// Check if CPU supports RDRAND (CPUID.01H:ECX.RDRAND[bit 30]).
pub fn has_rdrand() -> bool {
    let result = cpuid(1, 0);
    (result.ecx & (1 << 30)) != 0
}

/// Check if XSAVE is supported
pub fn has_xsave() -> bool {
    unsafe { asm_xsave_supported() != 0 }
}

// ===== Atomic Operations Wrappers =====

/// Atomic load with acquire semantics
pub fn atomic_load(ptr: &u32) -> u32 {
    unsafe { asm_atomic_load(ptr as *const u32) }
}

/// Atomic store with release semantics
pub fn atomic_store(ptr: &mut u32, value: u32) {
    unsafe { asm_atomic_store(ptr as *mut u32, value); }
}

/// Atomic add, returns old value
pub fn atomic_add(ptr: &mut u32, value: u32) -> u32 {
    unsafe { asm_atomic_add(ptr as *mut u32, value) }
}

/// Atomic subtract, returns old value
pub fn atomic_sub(ptr: &mut u32, value: u32) -> u32 {
    unsafe { asm_atomic_sub(ptr as *mut u32, value) }
}

/// Atomic increment, returns new value
pub fn atomic_inc(ptr: &mut u32) -> u32 {
    unsafe { asm_atomic_inc(ptr as *mut u32) }
}

/// Atomic decrement, returns new value
pub fn atomic_dec(ptr: &mut u32) -> u32 {
    unsafe { asm_atomic_dec(ptr as *mut u32) }
}

/// Atomic swap (exchange), returns old value
pub fn atomic_swap(ptr: &mut u32, new_value: u32) -> u32 {
    unsafe { asm_atomic_swap(ptr as *mut u32, new_value) }
}

/// Atomic compare-and-swap
/// Returns old value; if old == expected, stores desired
pub fn atomic_cmpxchg(ptr: &mut u32, expected: u32, desired: u32) -> u32 {
    unsafe { asm_atomic_cmpxchg(ptr as *mut u32, expected, desired) }
}

/// Atomic bitwise AND
pub fn atomic_and(ptr: &mut u32, value: u32) {
    unsafe { asm_atomic_and(ptr as *mut u32, value); }
}

/// Atomic bitwise OR
pub fn atomic_or(ptr: &mut u32, value: u32) {
    unsafe { asm_atomic_or(ptr as *mut u32, value); }
}

/// Atomic bitwise XOR
pub fn atomic_xor(ptr: &mut u32, value: u32) {
    unsafe { asm_atomic_xor(ptr as *mut u32, value); }
}

/// PAUSE instruction (spin-wait hint)
pub fn pause() {
    unsafe { asm_pause(); }
}

/// Full memory fence
pub fn memory_fence() {
    unsafe { asm_mfence(); }
}

/// Load fence
pub fn load_fence() {
    unsafe { asm_lfence(); }
}

/// Store fence
pub fn store_fence() {
    unsafe { asm_sfence(); }
}

// ===== Performance Measurement Wrappers =====

/// Begin cycle-accurate timing measurement
pub fn rdtsc_begin() -> u64 {
    unsafe { asm_rdtsc_begin() }
}

/// End cycle-accurate timing measurement
pub fn rdtsc_end() -> u64 {
    unsafe { asm_rdtsc_end() }
}

/// Measure cycles for a closure
pub fn measure_cycles<F: FnOnce()>(f: F) -> u64 {
    let start = rdtsc_begin();
    f();
    let end = rdtsc_end();
    end.wrapping_sub(start)
}

/// Benchmark NOP instruction throughput
pub fn benchmark_nop(iterations: u32) -> u64 {
    unsafe { asm_benchmark_nop(iterations) }
}

/// Benchmark ADD instruction throughput
pub fn benchmark_add(iterations: u32) -> u64 {
    unsafe { asm_benchmark_add(iterations) }
}

/// Benchmark MUL instruction throughput
pub fn benchmark_mul(iterations: u32) -> u64 {
    unsafe { asm_benchmark_mul(iterations) }
}

/// Benchmark DIV instruction throughput
pub fn benchmark_div(iterations: u32) -> u64 {
    unsafe { asm_benchmark_div(iterations) }
}

/// Benchmark memory LOAD throughput
pub fn benchmark_load(ptr: &u32, iterations: u32) -> u64 {
    unsafe { asm_benchmark_load(ptr as *const u32, iterations) }
}

/// Benchmark memory STORE throughput
pub fn benchmark_store(ptr: &mut u32, iterations: u32) -> u64 {
    unsafe { asm_benchmark_store(ptr as *mut u32, iterations) }
}

/// Benchmark LOCK prefix overhead
pub fn benchmark_lock(ptr: &mut u32, iterations: u32) -> u64 {
    unsafe { asm_benchmark_lock(ptr as *mut u32, iterations) }
}

/// Flush cache line containing address
pub fn clflush(addr: &u8) {
    unsafe { asm_clflush(addr as *const u8); }
}

/// Prefetch data into L1 cache
pub fn prefetch_t0(addr: &u8) {
    unsafe { asm_prefetch_t0(addr as *const u8); }
}

/// Prefetch data into L2 cache
pub fn prefetch_t1(addr: &u8) {
    unsafe { asm_prefetch_t1(addr as *const u8); }
}

/// Prefetch data into L3 cache
pub fn prefetch_t2(addr: &u8) {
    unsafe { asm_prefetch_t2(addr as *const u8); }
}

/// Prefetch data (non-temporal)
pub fn prefetch_nta(addr: &u8) {
    unsafe { asm_prefetch_nta(addr as *const u8); }
}

/// Output byte to port
pub unsafe fn outb(port: u16, value: u8) {
    asm_outb(port, value);
}

/// Input byte from port
pub unsafe fn inb(port: u16) -> u8 {
    asm_inb(port)
}
