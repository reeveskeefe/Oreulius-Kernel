use crate::drivers::gpu_support::backend::ScanoutOps;
use crate::drivers::gpu_support::engines::packets::{ComputePacket, TransferPacket};
use crate::drivers::gpu_support::errors::GpuError;
use crate::drivers::gpu_support::transport::fence::GpuFence;

pub struct FakeGpu;

impl ScanoutOps for FakeGpu {
    fn put_pixel(&self, _x: u32, _y: u32, _r: u8, _g: u8, _b: u8) {}
    fn fill_rect(&self, _x: u32, _y: u32, _w: u32, _h: u32, _r: u8, _g: u8, _b: u8) {}
    fn flush(&self) {}
    fn width(&self) -> u32 { 64 }
    fn height(&self) -> u32 { 64 }
    fn is_available(&self) -> bool { true }
}

impl FakeGpu {
    pub fn submit_transfer(&self, packet: &TransferPacket) -> Result<GpuFence, GpuError> {
        if packet.bytes == 0 {
            return Err(GpuError::InvalidPacket);
        }
        Ok(GpuFence::alloc())
    }

    pub fn submit_compute(&self, packet: &ComputePacket) -> Result<GpuFence, GpuError> {
        if packet.grid_x == 0 {
            return Err(GpuError::InvalidPacket);
        }
        Ok(GpuFence::alloc())
    }
}

