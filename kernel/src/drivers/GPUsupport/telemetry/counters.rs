/*!
 * GPU counters.
 */

use core::sync::atomic::{AtomicU64, Ordering};

pub static GPU_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static GPU_FENCE_STALLS: AtomicU64 = AtomicU64::new(0);
pub static GPU_QUEUE_SUBMITS: AtomicU64 = AtomicU64::new(0);

pub fn snapshot() -> (u64, u64, u64) {
    (
        GPU_FAULT_COUNT.load(Ordering::Relaxed),
        GPU_FENCE_STALLS.load(Ordering::Relaxed),
        GPU_QUEUE_SUBMITS.load(Ordering::Relaxed),
    )
}

