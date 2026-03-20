/*!
 * Intel family GPU plugin — Tier 1 scanout bringup.
 *
 * This module covers the Intel integrated graphics family (i915-class and
 * later).  The implementation targets the earliest safe milestone:
 *
 * - BAR0 MMIO identification
 * - Display Engine detection via MMIO register reads
 * - Linear framebuffer scanout using existing simplefb path
 * - Honest Tier 1 (Scanout) claim — no compute or transfer until a real
 *   command submission path is proven
 *
 * # Safety
 * All MMIO register reads use `read_volatile` through validated BAR windows.
 * We only access registers whose offsets and semantics are publicly documented
 * in Intel open-source driver specifications and the Intel Graphics Developer's
 * Manual.
 */

use crate::drivers::gpu_support::caps::GpuCapabilities;
use crate::drivers::gpu_support::core::{GpuBarInfo, GpuClass, GpuProbeReport, GpuTier};
use crate::drivers::gpu_support::display::scanout::ScanoutBackendId;
use crate::drivers::gpu_support::drivers::simplefb;
use crate::drivers::gpu_support::errors::GpuError;
use crate::drivers::gpu_support::transport::mmio::MmioRegion;

// ---------------------------------------------------------------------------
// Public well-documented Intel display register offsets
// (Intel Open Source Technology Center, Graphics Developer's Manual)
// ---------------------------------------------------------------------------

/// DSPSURF — Display A surface base address (Gen4+).
const REG_DSPASURF: usize = 0x7019C;
/// HTOTAL — Horizontal total (pipe A).
const REG_HTOTAL_A: usize = 0x60000;
/// VTOTAL — Vertical total (pipe A).
const REG_VTOTAL_A: usize = 0x60004;
/// PIPEASRC — Pipe A source size (width-1 | height-1).
const REG_PIPEASRC: usize = 0x6001C;

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

pub fn supports(report: &GpuProbeReport) -> bool {
    report.class == GpuClass::IntelFamily
}

/// Try to read the pipe A source size register to detect active display.
///
/// Returns `(width, height)` if successful, `(0, 0)` if the register read
/// is unavailable or returns a zero value.
pub fn detect_pipe_a_size(bar0: &GpuBarInfo) -> (u32, u32) {
    if !bar0.is_mmio || bar0.base == 0 {
        return (0, 0);
    }
    let region = MmioRegion::new(bar0.base as usize, 0x100000);
    let raw = unsafe { region.read_u32(REG_PIPEASRC) };
    match raw {
        None | Some(0) | Some(0xFFFF_FFFF) => (0, 0),
        Some(v) => {
            let w = ((v >> 16) & 0xFFF) + 1;
            let h = (v & 0xFFF) + 1;
            (w, h)
        }
    }
}

/// Probe the Intel display engine from a pre-parsed `GpuProbeReport`.
///
/// If BAR0 is accessible and PIPEASRC shows a live mode, the report is
/// upgraded to `Tier::Scanout` and we attempt simplefb-based activation.
pub fn probe_display(report: &GpuProbeReport, mb2_ptr: u32) -> GpuProbeReport {
    let bar0 = report
        .bars
        .iter()
        .flatten()
        .find(|b| b.index == 0 && b.is_mmio);

    let (pipe_w, pipe_h) = bar0.map(|b| detect_pipe_a_size(b)).unwrap_or((0, 0));

    if pipe_w > 0 && pipe_h > 0 {
        // Display engine is active and reporting a live resolution.
        // Upgrade to Scanout by routing through simplefb — the firmware / BIOS
        // has already programmed the scanout surface; we just adopt it.
        let firmware_fb = unsafe { simplefb::detect_mb2_framebuffer(mb2_ptr) };
        crate::serial_println!(
            "[Intel GPU] Pipe A active: {}×{} — routing to simplefb (mb2_fb={:?})",
            pipe_w,
            pipe_h,
            firmware_fb.is_some(),
        );
        GpuProbeReport {
            class: GpuClass::IntelFamily,
            tier: GpuTier::Scanout,
            caps: GpuCapabilities::scanout(),
            backend: ScanoutBackendId::SimpleFramebuffer,
            ..(*report)
        }
    } else {
        // Pipe not visible; stay at ProbeOnly.
        crate::serial_println!("[Intel GPU] Pipe A inactive — staying at ProbeOnly");
        *report
    }
}

/// Activate Intel family scanout.
///
/// For now we rely on the simplefb path to find and adopt the firmware-
/// programmed linear framebuffer.
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
