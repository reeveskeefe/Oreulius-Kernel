/*!
 * Virtio-gpu scanout backend scaffold.
 */

use crate::drivers::gpu_support::core::{GpuClass, GpuProbeReport};
use crate::drivers::gpu_support::errors::GpuError;

use super::simplefb;

pub fn supports(report: &GpuProbeReport) -> bool {
    report.class == GpuClass::VirtioGpu
}

pub fn activate(mb2_ptr: u32) -> Result<(), GpuError> {
    let _ = simplefb::activate(mb2_ptr)?;
    Ok(())
}

pub fn put_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
    simplefb::put_pixel(x, y, r, g, b);
}
pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
    simplefb::fill_rect(x, y, w, h, r, g, b);
}
pub fn flush() {
    simplefb::flush();
}
pub fn dimensions() -> (u32, u32) {
    simplefb::dimensions()
}
pub fn is_available() -> bool {
    simplefb::is_available()
}
