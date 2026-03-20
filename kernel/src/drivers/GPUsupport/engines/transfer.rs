/*!
 * Normalized transfer queue.
 */

use super::packets::TransferPacket;
use crate::drivers::gpu_support::errors::GpuError;
use crate::drivers::gpu_support::telemetry::counters;
use crate::drivers::gpu_support::transport::fence::GpuFence;

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
