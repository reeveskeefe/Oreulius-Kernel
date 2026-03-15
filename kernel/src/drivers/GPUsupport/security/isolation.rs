/*!
 * DMA and mapping isolation policy.
 */

use crate::drivers::gpu_support::memory::bo::BufferObject;

pub fn validate_buffer_owner(buffer: &BufferObject, owner_pid: u32) -> bool {
    buffer.owner.0 == owner_pid
}

