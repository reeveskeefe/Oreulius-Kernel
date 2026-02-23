/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

struct AArch64BumpAllocator;

#[global_allocator]
static AARCH64_GLOBAL_ALLOCATOR: AArch64BumpAllocator = AArch64BumpAllocator;

static HEAP_NEXT: AtomicUsize = AtomicUsize::new(0);
static HEAP_END: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn ensure_heap_initialized() {
    if HEAP_END.load(Ordering::Acquire) != 0 {
        return;
    }

    extern "C" {
        static _heap_start: u8;
        static _heap_end: u8;
    }

    let (start, end) = unsafe {
        (
            core::ptr::addr_of!(_heap_start) as usize,
            core::ptr::addr_of!(_heap_end) as usize,
        )
    };

    if end <= start {
        return;
    }

    let _ = HEAP_NEXT.compare_exchange(0, start, Ordering::AcqRel, Ordering::Acquire);
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
