use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

const QUEUE_SIZE: usize = 1024;
const TENSOR_DIM: usize = 128;

#[repr(C)]
struct QueueHeader {
    head: AtomicUsize,
    tail: AtomicUsize,
}

#[repr(C)]
struct QueueEntry {
    data: [i32; TENSOR_DIM],
}

#[repr(C)]
struct TelemetryRingBuffer {
    header: QueueHeader,
    entries: [QueueEntry; QUEUE_SIZE],
}

/// Represents a pointer to the memory-mapped ring buffer exported by the microkernel.
pub struct MmapTelemetryQueue {
    mapped_ptr: *mut u8,
    size: usize,
}

impl MmapTelemetryQueue {
    pub fn new() -> MmapTelemetryQueue {
        println!("Binding to microkernel wait-free telemetry queue via mmap...");
        
        let size = std::mem::size_of::<TelemetryRingBuffer>();
        
        // In a true implementation, we would open `/dev/oreulia_telemetry` and libc::mmap it.
        // For development, we simulate the mapped memory with an aligned allocation.
        // We leak this allocation because the daemon runs indefinitely and holds the 
        // queue reference for its lifetime.
        
        // Ensure proper alignment
        let layout = std::alloc::Layout::new::<TelemetryRingBuffer>();
        let mapped_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if mapped_ptr.is_null() {
            panic!("Failed to allocate bounded queue memory");
        }

        // Initialize header
        let buf = unsafe { &mut *(mapped_ptr as *mut TelemetryRingBuffer) };
        buf.header.head.store(0, Ordering::Relaxed);
        buf.header.tail.store(0, Ordering::Relaxed);

        MmapTelemetryQueue {
            mapped_ptr,
            size,
        }
    }

    /// Fetches the raw tensor scalar struct from the queue, returning None if empty.
    pub fn poll_tensor<const DIM: usize>(&self) -> Option<[i32; DIM]> {
        // Assert dimensionality matches hardware queue limits
        assert_eq!(DIM, TENSOR_DIM);
        
        let buf = unsafe { &*(self.mapped_ptr as *const TelemetryRingBuffer) };
        
        let head = buf.header.head.load(Ordering::Acquire);
        let tail = buf.header.tail.load(Ordering::Relaxed);
        
        if head == tail {
            // Queue is empty
            return None;
        }
        
        // Calculate the actual index in the ring buffer
        let index = tail % QUEUE_SIZE;
        
        // Read the tensor data
        let mut result = [0i32; DIM];
        let entry = &buf.entries[index];
        
        // Simulate reading the data
        for i in 0..DIM {
            result[i] = entry.data[i];
        }
        
        // Advance the tail pointer mathematically provable wait-free manner
        buf.header.tail.store(tail.wrapping_add(1), Ordering::Release);
        
        Some(result)
    }
}

impl Drop for MmapTelemetryQueue {
    fn drop(&mut self) {
        if !self.mapped_ptr.is_null() {
            let layout = std::alloc::Layout::new::<TelemetryRingBuffer>();
            unsafe { std::alloc::dealloc(self.mapped_ptr, layout) };
        }
    }
}
