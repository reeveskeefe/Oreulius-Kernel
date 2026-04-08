/*!
 * Shared GPU identity and probe types.
 */

use crate::drivers::x86::pci::PciDevice;

use super::caps::GpuCapabilities;
use super::display::scanout::ScanoutBackendId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuTier {
    ProbeOnly,
    Scanout,
    Transfer2D,
    Compute,
    Optimized,
}

impl GpuTier {
    pub const fn rank(self) -> u8 {
        match self {
            GpuTier::ProbeOnly => 0,
            GpuTier::Scanout => 1,
            GpuTier::Transfer2D => 2,
            GpuTier::Compute => 3,
            GpuTier::Optimized => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuClass {
    Framebuffer,
    VirtioGpu,
    Qxl,
    Bochs,
    IntelFamily,
    AmdFamily,
    NvidiaFamily,
    UnknownDisplay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuBarInfo {
    pub index: u8,
    pub base: u64,
    pub size_hint: u64,
    pub is_mmio: bool,
    pub is_64bit: bool,
    pub prefetchable: bool,
}

impl GpuBarInfo {
    pub const fn empty(index: u8) -> Self {
        GpuBarInfo {
            index,
            base: 0,
            size_hint: 0,
            is_mmio: false,
            is_64bit: false,
            prefetchable: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GpuProbeReport {
    pub pci: Option<PciDevice>,
    pub class: GpuClass,
    pub tier: GpuTier,
    pub caps: GpuCapabilities,
    pub irq_line: u8,
    pub bars: [Option<GpuBarInfo>; 6],
    pub backend: ScanoutBackendId,
    pub firmware_required: bool,
}

impl GpuProbeReport {
    pub const fn framebuffer(
        tier: GpuTier,
        caps: GpuCapabilities,
        backend: ScanoutBackendId,
    ) -> Self {
        GpuProbeReport {
            pci: None,
            class: GpuClass::Framebuffer,
            tier,
            caps,
            irq_line: 0,
            bars: [None, None, None, None, None, None],
            backend,
            firmware_required: false,
        }
    }
}
