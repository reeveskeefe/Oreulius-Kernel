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

// ============================================================================
// Frame Management (for COW)
// ============================================================================

/// Max supported physical frames (32MB / 4KB = 8192)
const MAX_FRAMES: usize = 8192;
const PAGE_SIZE: usize = 4096;

/// simple reference counting for physical frames
/// TODO: Make this thread-safe/atomic in future
static mut FRAME_REFCOUNTS: [u8; MAX_FRAMES] = [0; MAX_FRAMES];

/// Get refcount for a physical frame
pub fn get_refcount(phys_addr: usize) -> u8 {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe { FRAME_REFCOUNTS[frame_idx] }
    } else {
        0
    }
}

/// Increment refcount
pub fn inc_refcount(phys_addr: usize) {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe { 
            if FRAME_REFCOUNTS[frame_idx] < 255 {
                FRAME_REFCOUNTS[frame_idx] += 1; 
            }
        }
    }
}

/// Decrement refcount
pub fn dec_refcount(phys_addr: usize) {
    let frame_idx = phys_addr / PAGE_SIZE;
    if frame_idx < MAX_FRAMES {
        unsafe { 
            if FRAME_REFCOUNTS[frame_idx] > 0 {
                FRAME_REFCOUNTS[frame_idx] -= 1; 
            }
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
