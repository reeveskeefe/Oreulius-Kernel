/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Hardened Memory Allocator with Guard Pages and Leak Detection
//!
//! Features:
//! - Guard pages before/after allocations to detect overflows
//! - Canary values in allocation headers
//! - Leak detection in debug builds
//! - Fragmentation metrics
//! - Allocation tracking and statistics

#[cfg(debug_assertions)]
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use spin::Mutex; // Used for allocation tracking

extern "C" {
    static _heap_start: usize;
    static _heap_end: usize;
}

/// Magic canary value (0xDEADBEEF)
const CANARY: u32 = 0xDEADBEEF;

/// Guard page pattern (unmapped or poisoned)
const GUARD_PATTERN: u8 = 0xAA;

/// Minimum allocation size
const MIN_ALLOC: usize = 16;

/// Allocation header with metadata
#[repr(C)]
struct AllocationHeader {
    canary_pre: u32,
    size: usize,
    layout_size: usize,
    layout_align: usize,
    #[cfg(debug_assertions)]
    allocation_id: u64,
    #[cfg(debug_assertions)]
    backtrace: [usize; 4], // Simple backtrace
    canary_post: u32,
}

/// Statistics for allocator
#[derive(Clone, Copy, Debug)]
pub struct AllocatorStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub current_allocations: u64,
    pub peak_allocations: u64,
    pub bytes_allocated: usize,
    pub bytes_freed: usize,
    pub bytes_in_use: usize,
    pub peak_bytes_in_use: usize,
    pub fragmentation_score: f32, // 0.0 = no fragmentation, 1.0 = high
    pub heap_efficiency: f32,     // 0.0 = empty, 1.0 = fully used
    pub guard_page_violations: u64,
    pub canary_violations: u64,
}

/// Hardened bump allocator with guards
pub struct HardenedAllocator {
    heap_start: usize,
    heap_end: usize,
    next: usize,
    stats: AllocatorStats,
    #[cfg(debug_assertions)]
    allocations: Vec<(usize, usize, u64)>, // (addr, size, id)
    #[cfg(debug_assertions)]
    next_id: u64,
}

impl HardenedAllocator {
    pub const fn new() -> Self {
        HardenedAllocator {
            heap_start: 0,
            heap_end: 0,
            next: 0,
            stats: AllocatorStats {
                total_allocations: 0,
                total_deallocations: 0,
                current_allocations: 0,
                peak_allocations: 0,
                bytes_allocated: 0,
                bytes_freed: 0,
                bytes_in_use: 0,
                peak_bytes_in_use: 0,
                fragmentation_score: 0.0,
                heap_efficiency: 0.0,
                guard_page_violations: 0,
                canary_violations: 0,
            },
            #[cfg(debug_assertions)]
            allocations: Vec::new(),
            #[cfg(debug_assertions)]
            next_id: 1,
        }
    }

    pub unsafe fn init(&mut self) {
        self.heap_start = &_heap_start as *const usize as usize;
        self.heap_end = &_heap_end as *const usize as usize;
        self.next = self.heap_start;
    }

    /// Allocate with guard pages and canaries
    pub unsafe fn allocate(&mut self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(MIN_ALLOC);
        let align = layout.align();

        // Calculate total size: guard + header + allocation + guard
        let header_size = core::mem::size_of::<AllocationHeader>();
        let guard_size = 4096; // One page
        let total_size = guard_size + header_size + size + guard_size;

        // Align to page boundary for guards
        let alloc_start = align_up(self.next, 4096);
        let alloc_end = alloc_start + total_size;

        if alloc_end > self.heap_end {
            return ptr::null_mut(); // Out of memory
        }

        // Write guard pages
        self.write_guard_page(alloc_start, guard_size);
        self.write_guard_page(alloc_end - guard_size, guard_size);

        // Write allocation header
        let header_ptr = (alloc_start + guard_size) as *mut AllocationHeader;
        let header = AllocationHeader {
            canary_pre: CANARY,
            size,
            layout_size: layout.size(),
            layout_align: align,
            #[cfg(debug_assertions)]
            allocation_id: self.next_id,
            #[cfg(debug_assertions)]
            backtrace: [0; 4], // TODO: capture actual backtrace
            canary_post: CANARY,
        };
        ptr::write(header_ptr, header);

        // User data starts after header
        let user_ptr = (header_ptr as usize + header_size) as *mut u8;

        // Update allocator state
        self.next = alloc_end;
        self.stats.total_allocations += 1;
        self.stats.current_allocations += 1;
        self.stats.bytes_allocated += total_size;
        self.stats.bytes_in_use += total_size;

        if self.stats.current_allocations > self.stats.peak_allocations {
            self.stats.peak_allocations = self.stats.current_allocations;
        }

        if self.stats.bytes_in_use > self.stats.peak_bytes_in_use {
            self.stats.peak_bytes_in_use = self.stats.bytes_in_use;
        }

        #[cfg(debug_assertions)]
        {
            self.allocations
                .push((user_ptr as usize, size, self.next_id));
            self.next_id += 1;
        }

        user_ptr
    }

    /// Deallocate and check guards/canaries
    pub unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let header_size = core::mem::size_of::<AllocationHeader>();
        let header_ptr = (ptr as usize - header_size) as *const AllocationHeader;
        let header = ptr::read(header_ptr);

        // Validate that the layout size matches the allocation
        if header.size != layout.size() {
            #[cfg(debug_assertions)]
            panic!(
                "Layout size mismatch: expected {}, got {}",
                header.size,
                layout.size()
            );
        }

        // Verify canaries
        if header.canary_pre != CANARY || header.canary_post != CANARY {
            self.stats.canary_violations += 1;
            // In production, might want to panic or log
            #[cfg(debug_assertions)]
            panic!("Canary corruption detected at {:p}", ptr);
        }

        // Verify guard pages
        let guard_size = 4096;
        let alloc_start = (header_ptr as usize).saturating_sub(guard_size);
        let alloc_end = ptr as usize + header.size + guard_size;

        if !self.check_guard_page(alloc_start, guard_size) {
            self.stats.guard_page_violations += 1;
            #[cfg(debug_assertions)]
            panic!("Guard page violation (underflow) at {:p}", ptr);
        }

        if !self.check_guard_page(alloc_end - guard_size, guard_size) {
            self.stats.guard_page_violations += 1;
            #[cfg(debug_assertions)]
            panic!("Guard page violation (overflow) at {:p}", ptr);
        }

        // Update statistics
        self.stats.total_deallocations += 1;
        self.stats.current_allocations = self.stats.current_allocations.saturating_sub(1);
        let total_size = guard_size + header_size + header.size + guard_size;
        self.stats.bytes_freed += total_size;
        self.stats.bytes_in_use = self.stats.bytes_in_use.saturating_sub(total_size);

        #[cfg(debug_assertions)]
        {
            // Remove from tracking
            self.allocations
                .retain(|(addr, _, _)| *addr != ptr as usize);
        }

        // Note: Bump allocator doesn't actually free memory
        // A real allocator would return memory to free list here
    }

    /// Write guard page pattern
    unsafe fn write_guard_page(&self, addr: usize, size: usize) {
        let slice = core::slice::from_raw_parts_mut(addr as *mut u8, size);
        slice.fill(GUARD_PATTERN);
    }

    /// Check if guard page is intact
    unsafe fn check_guard_page(&self, addr: usize, size: usize) -> bool {
        let slice = core::slice::from_raw_parts(addr as *const u8, size);
        slice.iter().all(|&b| b == GUARD_PATTERN)
    }

    /// Get allocator statistics
    pub fn get_stats(&self) -> AllocatorStats {
        self.stats
    }

    /// Check for memory leaks (debug builds only)
    #[cfg(debug_assertions)]
    pub fn check_leaks(&self) -> Vec<(usize, usize, u64)> {
        self.allocations.clone()
    }

    /// Calculate fragmentation score
    pub fn update_fragmentation_score(&mut self) {
        let total_heap = self.heap_end - self.heap_start;
        let used = self.next - self.heap_start;
        let efficiency = if total_heap > 0 {
            (used as f32) / (total_heap as f32)
        } else {
            0.0
        };

        // Store heap efficiency for monitoring
        self.stats.heap_efficiency = efficiency;

        // Simple fragmentation metric: wasted space / total space
        let wasted = self.stats.bytes_allocated - self.stats.bytes_in_use;
        self.stats.fragmentation_score = if total_heap > 0 {
            (wasted as f32) / (total_heap as f32)
        } else {
            0.0
        };
    }
}

/// Align value up to alignment
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}

/// Locked allocator wrapper
pub struct LockedHardenedAllocator(pub Mutex<HardenedAllocator>);

unsafe impl GlobalAlloc for LockedHardenedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = self.0.lock();
        allocator.allocate(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut allocator = self.0.lock();
        allocator.deallocate(ptr, layout);
    }
}

/// Global hardened allocator
// Note: Commented out as global_allocator - using bump allocator from memory.rs for now
// To use hardened allocator, comment out memory.rs global_allocator and uncomment this
// #[global_allocator]
static HARDENED_ALLOCATOR: LockedHardenedAllocator =
    LockedHardenedAllocator(Mutex::new(HardenedAllocator::new()));

/// Initialize hardened allocator
pub fn init() {
    unsafe {
        HARDENED_ALLOCATOR.0.lock().init();
    }
}

/// Get allocator statistics
pub fn get_stats() -> AllocatorStats {
    HARDENED_ALLOCATOR.0.lock().get_stats()
}

/// Check for memory leaks (debug only)
#[cfg(debug_assertions)]
pub fn check_leaks() -> Vec<(usize, usize, u64)> {
    HARDENED_ALLOCATOR.0.lock().check_leaks()
}

/// Update and get fragmentation score
pub fn update_fragmentation() -> f32 {
    let mut allocator = HARDENED_ALLOCATOR.0.lock();
    allocator.update_fragmentation_score();
    allocator.get_stats().fragmentation_score
}
