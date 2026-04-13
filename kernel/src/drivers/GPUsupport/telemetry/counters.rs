/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * GPU counters.
 */

use core::sync::atomic::{AtomicU32, Ordering};

pub static GPU_FAULT_COUNT: AtomicU32 = AtomicU32::new(0);
pub static GPU_FENCE_STALLS: AtomicU32 = AtomicU32::new(0);
pub static GPU_QUEUE_SUBMITS: AtomicU32 = AtomicU32::new(0);

pub fn snapshot() -> (u32, u32, u32) {
    (
        GPU_FAULT_COUNT.load(Ordering::Relaxed),
        GPU_FENCE_STALLS.load(Ordering::Relaxed),
        GPU_QUEUE_SUBMITS.load(Ordering::Relaxed),
    )
}
