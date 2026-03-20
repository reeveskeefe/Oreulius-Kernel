/*!
 * AMD family GPU plugin — Tier 1 scanout bringup.
 *
 * Covers AMD/ATI display controllers (DC/DCE/DCN generations).
 *
 * Tier claimed: **Scanout** — we adopt the firmware-programmed linear
 * framebuffer via simplefb.  BAR0 is mapped and the DCE CRTC source-size
 * register is read to verify an active display path before claiming Scanout.
 *
 * Display engine registers are from the publicly documented AMD Display Core
 * register spec (DC register headers in the Linux amdgpu driver, MIT license).
 *
 * No compute submission is claimed.  AMD family devices that expose a proper
 * ring-based command processor will be promoted to higher tiers by a future
 * AMDKfd integration layer.
 */

use crate::drivers::gpu_support::caps::GpuCapabilities;
use crate::drivers::gpu_support::core::{GpuClass, GpuProbeReport, GpuTier};
use crate::drivers::gpu_support::display::scanout::ScanoutBackendId;
use crate::drivers::gpu_support::drivers::simplefb;
use crate::drivers::gpu_support::errors::GpuError;
use crate::drivers::gpu_support::transport::mmio::MmioRegion;

// ---------------------------------------------------------------------------
// Public AMD DCE/DCN register offsets
// Sourced from the amdgpu open-source driver (kernel.org/pub/linux/kernel)
// ---------------------------------------------------------------------------

/// D1CRTC_STATUS_FRAME_COUNT — CRTC0 frame counter (non-zero when active).
const REG_D1CRTC_STATUS: usize = 0x60E8;
/// D1GRPH_X_START / D1GRPH_Y_START / D1GRPH_WIDTH / D1GRPH_HEIGHT
/// Combined source window for plane 0 (DCE 4.0+).
const REG_D1GRPH_PRIMARY_SURFACE_ADDRESS: usize = 0x6110;
/// CRTC_H_TOTAL register (DCN 1.0 offset for CRTC0).
const REG_DCN_CRTC0_H_TOTAL: usize = 0x1B034;

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

pub fn supports(report: &GpuProbeReport) -> bool {
    report.class == GpuClass::AmdFamily
}

/// Check whether DCE CRTC0 is active by reading the frame counter.
///
/// A non-zero, non-sentinel frame count means the BIOS/firmware has already
/// programmed a live mode on this CRTC.
pub fn detect_dce_crtc0(bar0_base: usize) -> bool {
    let region = MmioRegion::new(bar0_base, 0x80000);
    match unsafe { region.read_u32(REG_D1CRTC_STATUS) } {
        None | Some(0) | Some(0xFFFF_FFFF) => false,
        Some(_) => true,
    }
}

/// Attempt to identify the primary surface address from DCE plane registers.
///
/// Returns the physical surface address if readable, or `None`.
pub fn dce_primary_surface_addr(bar0_base: usize) -> Option<u64> {
    let region = MmioRegion::new(bar0_base, 0x80000);
    match unsafe { region.read_u32(REG_D1GRPH_PRIMARY_SURFACE_ADDRESS) } {
        None | Some(0) | Some(0xFFFF_FFFF) => None,
        Some(lo) => Some(lo as u64),
    }
}

/// Probe AMD display engine from a pre-parsed `GpuProbeReport`.
///
/// If BAR0 is MMIO-accessible and CRTC0 is active, upgrades the tier to
/// Scanout and routes through simplefb.
pub fn probe_display(report: &GpuProbeReport, _mb2_ptr: u32) -> GpuProbeReport {
    let bar0 = report
        .bars
        .iter()
        .flatten()
        .find(|b| b.index == 0 && b.is_mmio);

    let crtc_active = bar0
        .map(|b| b.base > 0 && detect_dce_crtc0(b.base as usize))
        .unwrap_or(false);

    if crtc_active {
        crate::serial_println!("[AMD GPU] DCE CRTC0 active — routing to simplefb");
        GpuProbeReport {
            class: GpuClass::AmdFamily,
            tier: GpuTier::Scanout,
            caps: GpuCapabilities::scanout(),
            backend: ScanoutBackendId::SimpleFramebuffer,
            ..(*report)
        }
    } else {
        crate::serial_println!("[AMD GPU] CRTC inactive — staying at ProbeOnly");
        *report
    }
}

/// Activate AMD family scanout via simplefb.
pub fn activate(mb2_ptr: u32) -> Result<(), GpuError> {
    simplefb::activate(mb2_ptr).map(|_| ())
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
