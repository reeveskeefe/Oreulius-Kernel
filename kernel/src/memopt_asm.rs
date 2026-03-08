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

// Memory Optimization Assembly Bindings
// Cache management, prefetching, and high-performance operations

/// Cache prefetch locality hint
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Locality {
    None = 0,   // NTA - non-temporal (no cache pollution)
    Low = 1,    // T2 - low temporal locality
    Medium = 2, // T1 - medium temporal locality
    High = 3,   // T0 - high temporal locality
}

/// Memory optimization statistics
#[derive(Debug, Default)]
pub struct MemOptStats {
    pub cache_flushes: u32,
    pub nt_copies: u32,
    pub hw_crc_calls: u32,
    pub aes_encryptions: u32,
}

extern "C" {
    // Cache management
    pub fn cache_flush_line(addr: *const u8);
    pub fn cache_prefetch(addr: *const u8, locality: u8);
    pub fn cache_flush_all();
    pub fn cache_invalidate_all();

    // Non-temporal operations
    pub fn memcpy_nt(dst: *mut u8, src: *const u8, count: u32);
    pub fn memset_nt(dst: *mut u8, value: u8, count: u32);
    pub fn memcpy_nt_sse(dst: *mut u8, src: *const u8, count: u32);
    pub fn memcpy_nt_avx(dst: *mut u8, src: *const u8, count: u32);

    // SSE string operations
    pub fn strlen_sse(s: *const u8) -> u32;
    pub fn strcmp_sse(s1: *const u8, s2: *const u8) -> i32;
    pub fn memchr_sse(ptr: *const u8, value: u8, count: u32) -> *const u8;

    // Hardware CRC32
    pub fn crc32_hw(crc: u32, data: *const u8, length: u32) -> u32;
    pub fn crc32_update(crc: u32, byte: u8) -> u32;

    // AES-NI
    pub fn aes_encrypt_block(output: *mut u8, input: *const u8, key: *const u8, rounds: u32);
    pub fn aes_decrypt_block(output: *mut u8, input: *const u8, key: *const u8, rounds: u32);

    // Fast memory pool
    pub fn mempool_alloc_fast(pool: *mut u8, free_list: *mut u32) -> *mut u8;
    pub fn mempool_free_fast(pool: *mut u8, ptr: *mut u8, free_list: *mut u32);

    // Statistics
    pub fn get_memopt_stats(flushes: *mut u32, nt: *mut u32, crc: *mut u32, aes: *mut u32);
}

/// Cache management utilities
pub struct Cache;

impl Cache {
    /// Flush a single cache line
    pub fn flush_line(addr: *const u8) {
        unsafe { cache_flush_line(addr) }
    }

    /// Prefetch data into cache
    pub fn prefetch(addr: *const u8, locality: Locality) {
        unsafe { cache_prefetch(addr, locality as u8) }
    }

    /// Flush all cache (write-back)
    pub fn flush_all() {
        unsafe { cache_flush_all() }
    }

    /// Invalidate all cache (no write-back)
    pub fn invalidate_all() {
        unsafe { cache_invalidate_all() }
    }
}

/// Non-temporal memory operations (bypass cache)
pub struct NonTemporal;

impl NonTemporal {
    /// Copy memory without polluting cache
    pub unsafe fn copy(dst: *mut u8, src: *const u8, count: usize) {
        memcpy_nt(dst, src, count as u32);
    }

    /// Set memory without polluting cache
    pub unsafe fn set(dst: *mut u8, value: u8, count: usize) {
        memset_nt(dst, value, count as u32);
    }

    /// SSE-optimized copy (64-byte blocks)
    pub unsafe fn copy_sse(dst: *mut u8, src: *const u8, count: usize) {
        memcpy_nt_sse(dst, src, count as u32);
    }

    /// AVX-optimized copy (128-byte blocks, requires AVX)
    pub unsafe fn copy_avx(dst: *mut u8, src: *const u8, count: usize) {
        memcpy_nt_avx(dst, src, count as u32);
    }
}

/// SSE-accelerated string operations
pub struct SseString;

impl SseString {
    /// Compute string length using SSE
    pub unsafe fn strlen(s: *const u8) -> usize {
        strlen_sse(s) as usize
    }

    /// Compare strings using SSE
    pub unsafe fn strcmp(s1: *const u8, s2: *const u8) -> i32 {
        strcmp_sse(s1, s2)
    }

    /// Find byte in memory using SSE
    pub unsafe fn memchr(ptr: *const u8, value: u8, count: usize) -> Option<*const u8> {
        let result = memchr_sse(ptr, value, count as u32);
        if result.is_null() {
            None
        } else {
            Some(result)
        }
    }
}

/// Hardware CRC32 (requires SSE4.2)
pub struct Crc32;

impl Crc32 {
    pub const INIT: u32 = 0xFFFFFFFF;

    /// Calculate CRC32 using hardware instruction
    pub fn calculate(data: &[u8]) -> u32 {
        unsafe { crc32_hw(Self::INIT, data.as_ptr(), data.len() as u32) }
    }

    /// Update CRC32 with additional data
    pub fn update(crc: u32, data: &[u8]) -> u32 {
        unsafe { crc32_hw(crc, data.as_ptr(), data.len() as u32) }
    }

    /// Update CRC32 with single byte
    pub fn update_byte(crc: u32, byte: u8) -> u32 {
        unsafe { crc32_update(crc, byte) }
    }
}

/// AES-NI hardware encryption (requires AES-NI)
pub struct AesNi;

impl AesNi {
    pub const BLOCK_SIZE: usize = 16;

    /// Encrypt single block (128-bit)
    pub fn encrypt_block(
        output: &mut [u8; 16],
        input: &[u8; 16],
        key_schedule: &[u8],
        rounds: u32,
    ) {
        unsafe {
            aes_encrypt_block(
                output.as_mut_ptr(),
                input.as_ptr(),
                key_schedule.as_ptr(),
                rounds,
            );
        }
    }

    /// Decrypt single block (128-bit)
    pub fn decrypt_block(
        output: &mut [u8; 16],
        input: &[u8; 16],
        key_schedule: &[u8],
        rounds: u32,
    ) {
        unsafe {
            aes_decrypt_block(
                output.as_mut_ptr(),
                input.as_ptr(),
                key_schedule.as_ptr(),
                rounds,
            );
        }
    }
}

/// Lock-free memory pool
pub struct MemPool {
    pool: *mut u8,
    free_list: u32,
}

impl MemPool {
    pub const fn new(pool: *mut u8) -> Self {
        Self { pool, free_list: 0 }
    }

    /// Allocate from pool (lock-free)
    pub fn alloc(&mut self) -> Option<*mut u8> {
        let ptr = unsafe { mempool_alloc_fast(self.pool, &mut self.free_list) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// Free to pool (lock-free)
    pub fn free(&mut self, ptr: *mut u8) {
        unsafe { mempool_free_fast(self.pool, ptr, &mut self.free_list) }
    }
}

/// Memory optimization statistics
pub struct MemOptStatsAccessor;

impl MemOptStatsAccessor {
    pub fn get() -> MemOptStats {
        let mut stats = MemOptStats::default();
        unsafe {
            get_memopt_stats(
                &mut stats.cache_flushes,
                &mut stats.nt_copies,
                &mut stats.hw_crc_calls,
                &mut stats.aes_encryptions,
            );
        }
        stats
    }
}

/// Prefetch iterator wrapper
pub struct Prefetch<'a, T> {
    slice: &'a [T],
    index: usize,
    locality: Locality,
}

impl<'a, T> Prefetch<'a, T> {
    pub fn new(slice: &'a [T], locality: Locality) -> Self {
        // Prefetch first element
        if !slice.is_empty() {
            Cache::prefetch(slice.as_ptr() as *const u8, locality);
        }
        Self {
            slice,
            index: 0,
            locality,
        }
    }
}

impl<'a, T> Iterator for Prefetch<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.slice.len() {
            return None;
        }

        // Prefetch next element
        if self.index + 1 < self.slice.len() {
            let next_ptr = unsafe { self.slice.as_ptr().add(self.index + 1) };
            Cache::prefetch(next_ptr as *const u8, self.locality);
        }

        let item = &self.slice[self.index];
        self.index += 1;
        Some(item)
    }
}

/// Extension trait for prefetching
pub trait PrefetchExt<T> {
    fn prefetch_iter(&self, locality: Locality) -> Prefetch<T>;
}

impl<T> PrefetchExt<T> for [T] {
    fn prefetch_iter(&self, locality: Locality) -> Prefetch<T> {
        Prefetch::new(self, locality)
    }
}
