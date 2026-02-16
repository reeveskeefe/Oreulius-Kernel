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

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

extern "C" {
    static _heap_start: usize;
    static _heap_end: usize;
    static _jit_arena_start: usize;
    static _jit_arena_end: usize;
}

pub struct BumpAllocator {
    heap_start: usize,
    heap_end: usize,
    next: usize,
    allocations: usize,
}

impl BumpAllocator {
    pub const fn new() -> Self {
        BumpAllocator {
            heap_start: 0,
            heap_end: 0,
            next: 0,
            allocations: 0,
        }
    }

    pub unsafe fn init(&mut self) {
        self.heap_start = &_heap_start as *const usize as usize;
        self.heap_end = &_heap_end as *const usize as usize;
        self.next = self.heap_start;
    }
}

pub struct LockedBumpAllocator(Mutex<BumpAllocator>);

unsafe impl GlobalAlloc for LockedBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = self.0.lock();

        let alloc_start = align_up(allocator.next, layout.align());
        let alloc_end = alloc_start.saturating_add(layout.size());

        if alloc_end > allocator.heap_end {
            ptr::null_mut()
        } else {
            allocator.next = alloc_end;
            allocator.allocations += 1;
            alloc_start as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator doesn't support deallocation
    }
}

fn align_up(addr: usize, align: usize) -> usize {
    let align_mask = align - 1;
    (addr + align_mask) & !align_mask
}

#[global_allocator]
static ALLOCATOR: LockedBumpAllocator = LockedBumpAllocator(Mutex::new(BumpAllocator::new()));

pub fn init() {
    unsafe {
        ALLOCATOR.0.lock().init();
    }
    init_jit_arena();
}

// ============================================================================
// Frame Management (for COW)
// ============================================================================

/// Max supported physical frames (32MB / 4KB = 8192)
const MAX_FRAMES: usize = 8192;
const PAGE_SIZE: usize = 4096;

// ============================================================================
// Dedicated JIT Arena (for executable buffers)
// ============================================================================

static JIT_ARENA_START: AtomicUsize = AtomicUsize::new(0);
static JIT_ARENA_END: AtomicUsize = AtomicUsize::new(0);

struct JitArena {
    next: usize,
}

impl JitArena {
    const fn new() -> Self {
        JitArena { next: 0 }
    }
}

static JIT_ARENA: Mutex<JitArena> = Mutex::new(JitArena::new());

fn init_jit_arena() {
    let start = unsafe { &_jit_arena_start as *const usize as usize };
    let end = unsafe { &_jit_arena_end as *const usize as usize };
    if end <= start {
        return;
    }
    JIT_ARENA_START.store(start, Ordering::Relaxed);
    JIT_ARENA_END.store(end, Ordering::Relaxed);
    let mut arena = JIT_ARENA.lock();
    arena.next = start;
    unsafe {
        ptr::write_bytes(start as *mut u8, 0, end - start);
    }
}

pub fn jit_arena_range() -> (usize, usize) {
    (
        JIT_ARENA_START.load(Ordering::Relaxed),
        JIT_ARENA_END.load(Ordering::Relaxed),
    )
}

pub fn jit_allocate(size: usize, align: usize) -> Result<usize, &'static str> {
    if size == 0 {
        return Err("Invalid allocation size");
    }
    let (start, end) = jit_arena_range();
    if start == 0 || end == 0 || end <= start {
        return Err("JIT arena not initialized");
    }
    let mut arena = JIT_ARENA.lock();
    let base = align_up(core::cmp::max(arena.next, start), align);
    let alloc_end = base.checked_add(size).ok_or("Size overflow")?;
    if alloc_end > end {
        return Err("JIT arena out of memory");
    }
    arena.next = alloc_end;
    Ok(base)
}

pub fn jit_allocate_pages(count: usize) -> Result<usize, &'static str> {
    if count == 0 {
        return Err("Invalid page count");
    }
    let size = count.checked_mul(PAGE_SIZE).ok_or("Size overflow")?;
    jit_allocate(size, PAGE_SIZE)
}

// Import atomic refcount operations from assembly
extern "C" {
    fn atomic_inc_refcount(refcount_addr: *mut u32) -> u32;
    fn atomic_dec_refcount(refcount_addr: *mut u32) -> u32;
}

/// Physical frame reference counting (thread-safe via atomic operations)
static mut FRAME_REFCOUNTS: [u32; MAX_FRAMES] = [0; MAX_FRAMES];

/// Get refcount for a physical frame
pub fn get_refcount(phys_addr: usize) -> u32 {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe { core::ptr::read_volatile(&FRAME_REFCOUNTS[frame_idx]) }
    } else {
        0
    }
}

/// Increment refcount (atomic operation for multicore safety)
pub fn inc_refcount(phys_addr: usize) {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe {
            let refcount_ptr = &mut FRAME_REFCOUNTS[frame_idx] as *mut u32;
            let new_count = atomic_inc_refcount(refcount_ptr);
            // Check for overflow (wrapped from u32::MAX to 0)
            if new_count == 0 {
                // Overflow protection: decrement back
                atomic_dec_refcount(refcount_ptr);
            }
        }
    }
}

/// Decrement refcount (atomic operation for multicore safety)
pub fn dec_refcount(phys_addr: usize) {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe {
            let refcount_ptr = &mut FRAME_REFCOUNTS[frame_idx] as *mut u32;
            atomic_dec_refcount(refcount_ptr);
        }
    }
}

/// Allocate a physical frame (syscall helper stub)
pub fn allocate_frame() -> Result<usize, &'static str> {
    // Allocate 4KB from the heap directly, ensuring alignment
    let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).map_err(|_| "Layout Error")?;
    unsafe {
        let ptr = ALLOCATOR.alloc(layout);
        if ptr.is_null() {
            Err("Out of memory")
        } else {
            let addr = ptr as usize;
            // Initialize refcount to 1
            let frame_idx = addr / PAGE_SIZE;
            if frame_idx < MAX_FRAMES {
                FRAME_REFCOUNTS[frame_idx] = 1;
            }
            // Zero the page
            ptr::write_bytes(ptr, 0, PAGE_SIZE);
            Ok(addr)
        }
    }
}

/// Allocate multiple contiguous pages (page-aligned).
pub fn allocate_pages(count: usize) -> Result<usize, &'static str> {
    if count == 0 {
        return Err("Invalid page count");
    }
    let size = count.checked_mul(PAGE_SIZE).ok_or("Size overflow")?;
    let layout = Layout::from_size_align(size, PAGE_SIZE).map_err(|_| "Layout Error")?;
    unsafe {
        let ptr = ALLOCATOR.alloc(layout);
        if ptr.is_null() {
            return Err("Out of memory");
        }
        let base = ptr as usize;
        // Initialize refcounts per 4KB page
        for i in 0..count {
            let addr = base + (i * PAGE_SIZE);
            let frame_idx = addr / PAGE_SIZE;
            if frame_idx < MAX_FRAMES {
                FRAME_REFCOUNTS[frame_idx] = 1;
            }
        }
        // Zero the pages
        ptr::write_bytes(ptr, 0, size);
        Ok(base)
    }
}
