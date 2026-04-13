/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * Normalized compute queue.
 */

use super::packets::ComputePacket;
use crate::drivers::x86::gpu_support::errors::GpuError;
use crate::drivers::x86::gpu_support::telemetry::counters;
use crate::drivers::x86::gpu_support::transport::fence::GpuFence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeQueue {
    pub submissions: u32,
}

impl ComputeQueue {
    pub const fn new() -> Self {
        ComputeQueue { submissions: 0 }
    }

    pub fn submit(&mut self, packet: &ComputePacket) -> Result<GpuFence, GpuError> {
        if packet.grid_x == 0 || packet.grid_y == 0 || packet.grid_z == 0 {
            return Err(GpuError::InvalidPacket);
        }
        self.submissions = self.submissions.saturating_add(1);
        counters::GPU_QUEUE_SUBMITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(GpuFence::alloc())
    }
}
