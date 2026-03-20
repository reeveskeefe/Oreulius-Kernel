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

#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Reserve the front of the linker heap for the AArch64 MMU page-table allocator.
/// The MMU backend currently allocates page tables from `_heap_start.._heap_end`
/// during bring-up; without this carve-out, general heap allocations can overwrite
/// page tables and corrupt translations.
pub(crate) const AARCH64_MMU_PT_RESERVE_BYTES: usize = 1024 * 1024; // 1 MiB

struct AArch64BumpAllocator;

#[global_allocator]
static AARCH64_GLOBAL_ALLOCATOR: AArch64BumpAllocator = AArch64BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static HEAP_START: AtomicUsize = AtomicUsize::new(0);
static HEAP_END: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "host-tests"))]
static HOST_TEST_AARCH64_HEAP: [u8; 2 * 1024 * 1024] = [0; 2 * 1024 * 1024];

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn ensure_heap_initialized() {
    if HEAP_END.load(Ordering::Acquire) != 0 {
        return;
    }

    #[cfg(any(test, feature = "host-tests"))]
    let (start, end) = (
        HOST_TEST_AARCH64_HEAP.as_ptr() as usize,
        HOST_TEST_AARCH64_HEAP.as_ptr() as usize + HOST_TEST_AARCH64_HEAP.len(),
    );

    #[cfg(not(any(test, feature = "host-tests")))]
    extern "C" {
        static _heap_start: u8;
        static _heap_end: u8;
    }

    #[cfg(not(any(test, feature = "host-tests")))]
    let (start, end) = unsafe {
        (
            core::ptr::addr_of!(_heap_start) as usize,
            core::ptr::addr_of!(_heap_end) as usize,
        )
    };

    if end <= start {
        return;
    }

    let alloc_start = start.saturating_add(AARCH64_MMU_PT_RESERVE_BYTES).min(end);
    let alloc_start = align_up(alloc_start, 16);
    let _ = HEAP_START.compare_exchange(0, alloc_start, Ordering::AcqRel, Ordering::Acquire);
    let _ = HEAP_NEXT.compare_exchange(0, alloc_start, Ordering::AcqRel, Ordering::Acquire);
    let _ = HEAP_END.compare_exchange(0, end, Ordering::AcqRel, Ordering::Acquire);
}

unsafe impl GlobalAlloc for AArch64BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ensure_heap_initialized();

        let end = HEAP_END.load(Ordering::Acquire);
        if end == 0 {
            return null_mut();
        }

        let size = layout.size().max(1);
        let align = layout.align().max(1);
        let mut cur = HEAP_NEXT.load(Ordering::Acquire);

        loop {
            let aligned = align_up(cur, align);
            let Some(next) = aligned.checked_add(size) else {
                return null_mut();
            };
            if next > end {
                return null_mut();
            }

            match HEAP_NEXT.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => cur = actual,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bring-up allocator: no reclamation.
    }
}

pub fn heap_range() -> (usize, usize) {
    ensure_heap_initialized();
    (
        HEAP_START.load(Ordering::Acquire),
        HEAP_END.load(Ordering::Acquire),
    )
}
