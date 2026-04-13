/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * GPU capability descriptors and engine masks.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuEngineMask {
    bits: u32,
}

impl GpuEngineMask {
    pub const DISPLAY: u32 = 1 << 0;
    pub const TRANSFER: u32 = 1 << 1;
    pub const COMPUTE: u32 = 1 << 2;

    pub const fn empty() -> Self {
        GpuEngineMask { bits: 0 }
    }

    pub const fn display_only() -> Self {
        GpuEngineMask {
            bits: Self::DISPLAY,
        }
    }

    pub const fn with_transfer() -> Self {
        GpuEngineMask {
            bits: Self::DISPLAY | Self::TRANSFER,
        }
    }

    pub const fn with_compute() -> Self {
        GpuEngineMask {
            bits: Self::DISPLAY | Self::TRANSFER | Self::COMPUTE,
        }
    }

    pub const fn contains(&self, bit: u32) -> bool {
        (self.bits & bit) == bit
    }

    pub const fn bits(&self) -> u32 {
        self.bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuCapabilities {
    pub scanout_planes: u8,
    pub cursor: bool,
    pub transfer: bool,
    pub compute: bool,
    pub fences: bool,
    pub firmware_required: bool,
    pub engines: GpuEngineMask,
}

impl GpuCapabilities {
    pub const fn probe_only() -> Self {
        GpuCapabilities {
            scanout_planes: 0,
            cursor: false,
            transfer: false,
            compute: false,
            fences: false,
            firmware_required: false,
            engines: GpuEngineMask::empty(),
        }
    }

    pub const fn scanout() -> Self {
        GpuCapabilities {
            scanout_planes: 1,
            cursor: true,
            transfer: false,
            compute: false,
            fences: true,
            firmware_required: false,
            engines: GpuEngineMask::display_only(),
        }
    }

    pub const fn transfer2d() -> Self {
        GpuCapabilities {
            scanout_planes: 1,
            cursor: true,
            transfer: true,
            compute: false,
            fences: true,
            firmware_required: false,
            engines: GpuEngineMask::with_transfer(),
        }
    }

    pub const fn compute(firmware_required: bool) -> Self {
        GpuCapabilities {
            scanout_planes: 1,
            cursor: true,
            transfer: true,
            compute: true,
            fences: true,
            firmware_required,
            engines: GpuEngineMask::with_compute(),
        }
    }
}
