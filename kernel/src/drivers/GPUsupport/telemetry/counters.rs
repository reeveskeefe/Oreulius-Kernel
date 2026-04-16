// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


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
