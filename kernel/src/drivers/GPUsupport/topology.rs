/*!
 * GPU resource graph and aperture descriptors.
 */

use super::caps::GpuEngineMask;
use super::core::GpuBarInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApertureKind {
    Mmio,
    Framebuffer,
    Doorbell,
    CommandQueue,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuAperture {
    pub kind: ApertureKind,
    pub bar: GpuBarInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuResourceGraph {
    pub apertures: [Option<GpuAperture>; 8],
    pub engines: GpuEngineMask,
}

impl GpuResourceGraph {
    pub const fn new(engines: GpuEngineMask) -> Self {
        GpuResourceGraph {
            apertures: [None, None, None, None, None, None, None, None],
            engines,
        }
    }
}

