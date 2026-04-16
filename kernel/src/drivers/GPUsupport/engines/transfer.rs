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
 * Normalized transfer queue.
 */

use super::packets::TransferPacket;
use crate::drivers::x86::gpu_support::errors::GpuError;
use crate::drivers::x86::gpu_support::telemetry::counters;
use crate::drivers::x86::gpu_support::transport::fence::GpuFence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferQueue {
    pub submissions: u32,
}

impl TransferQueue {
    pub const fn new() -> Self {
        TransferQueue { submissions: 0 }
    }

    pub fn submit(&mut self, packet: &TransferPacket) -> Result<GpuFence, GpuError> {
        if packet.bytes == 0 {
            return Err(GpuError::InvalidPacket);
        }
        self.submissions = self.submissions.saturating_add(1);
        counters::GPU_QUEUE_SUBMITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(GpuFence::alloc())
    }
}
