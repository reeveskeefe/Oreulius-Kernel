use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use spin::Mutex;

extern "C" {
    static _heap_start: usize;
    static _heap_end: usize;
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
}