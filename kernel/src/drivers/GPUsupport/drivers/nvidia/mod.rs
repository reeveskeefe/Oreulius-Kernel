/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * NVIDIA family GPU plugin — Tier 1 scanout bringup.
 *
 * Covers NVIDIA NV50 (G80) and later display controllers.
 *
 * Tier claimed: **Scanout** — we adopt the firmware-programmed EFI/VBIOS
 * linear framebuffer via simplefb.  BAR0 is mapped and the NV_PMC_BOOT_0
 * register is read to confirm this is a known-family device before claiming
 * Scanout.
 *
 * NVIDIA register offsets are from the publicly documented Nouveau driver
 * reverse-engineering database (envytools, MIT license) and the open NVIDIA
 * open-source kernel driver headers (nvidia-open, MIT/GPLv2 dual license).
 *
 * No compute or display-engine command submission is claimed.  NVIDIA family
 * devices that expose a supported GSP-RM interface will be promoted to higher
 * tiers by a future GSP-RM integration layer.
 */

use crate::drivers::x86::gpu_support::caps::GpuCapabilities;
use crate::drivers::x86::gpu_support::core::{GpuClass, GpuProbeReport, GpuTier};
use crate::drivers::x86::gpu_support::display::scanout::ScanoutBackendId;
use crate::drivers::x86::gpu_support::drivers::simplefb;
use crate::drivers::x86::gpu_support::errors::GpuError;
use crate::drivers::x86::gpu_support::transport::mmio::MmioRegion;

// ---------------------------------------------------------------------------
// NV_PMC — Master Control registers
// Source: envytools (rnndb/pmc.xml, MIT license)
// ---------------------------------------------------------------------------

/// NV_PMC_BOOT_0 — chip identification register (NV50+).
/// Bits 31:20 = architecture family, bits 11:0 = chip revision.
const REG_NV_PMC_BOOT_0: usize = 0x0000_0000;

/// NV_PMC_ENABLE — engine enable bitfield.
const REG_NV_PMC_ENABLE: usize = 0x0000_0200;

// ---------------------------------------------------------------------------
// NV_PDISP — Display Engine registers (NV50+)
// ---------------------------------------------------------------------------

/// NV_PDISP_SOR0_STATUS — SOR0 head attach status.
const REG_NV_PDISP_SOR0_STATUS: usize = 0x0061_C004;

// ---------------------------------------------------------------------------
// NVIDIA chip-family identification
// ---------------------------------------------------------------------------

/// GPU architecture extracted from NV_PMC_BOOT_0 bits [31:20].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvArch {
    Nv50,    // G80–GT2xx
    Fermi,   // GF1xx
    Kepler,  // GK1xx / GK2xx
    Maxwell, // GM1xx / GM2xx
    Pascal,  // GP1xx
    Volta,   // GV1xx
    Turing,  // TU1xx
    Ampere,  // GA1xx
    Ada,     // AD1xx
    Unknown(u32),
}

impl NvArch {
    pub fn from_boot0(boot0: u32) -> Self {
        let arch = (boot0 >> 20) & 0xFFF;
        match arch {
            0x050..=0x068 => NvArch::Nv50,
            0x0C0..=0x0CF => NvArch::Fermi,
            0x0E0..=0x0EF => NvArch::Kepler,
            0x110..=0x12F => NvArch::Maxwell,
            0x130..=0x13F => NvArch::Pascal,
            0x140..=0x14F => NvArch::Volta,
            0x160..=0x16F => NvArch::Turing,
            0x170..=0x17F => NvArch::Ampere,
            0x190..=0x19F => NvArch::Ada,
            v => NvArch::Unknown(v),
        }
    }

    pub fn is_known_display_capable(&self) -> bool {
        !matches!(self, NvArch::Unknown(_))
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

pub fn supports(report: &GpuProbeReport) -> bool {
    report.class == GpuClass::NvidiaFamily
}

/// Read NV_PMC_BOOT_0 to identify the NVIDIA architecture family.
pub fn read_architecture(bar0_base: usize) -> Option<NvArch> {
    let region = MmioRegion::new(bar0_base, 0x1000);
    match unsafe { region.read_u32(REG_NV_PMC_BOOT_0) } {
        None | Some(0) | Some(0xFFFF_FFFF) => None,
        Some(boot0) => Some(NvArch::from_boot0(boot0)),
    }
}

/// Check that NV_PMC_ENABLE has the display bit set (bit 30 on NV50+).
pub fn display_engine_enabled(bar0_base: usize) -> bool {
    let region = MmioRegion::new(bar0_base, 0x1000);
    match unsafe { region.read_u32(REG_NV_PMC_ENABLE) } {
        Some(v) => (v & (1 << 30)) != 0,
        None => false,
    }
}

/// Probe NVIDIA display engine from a pre-parsed `GpuProbeReport`.
///
/// If BAR0 is MMIO-accessible, NV_PMC_BOOT_0 returns a known architecture,
/// and the display engine enable bit is set, upgrades to Scanout via simplefb.
pub fn probe_display(report: &GpuProbeReport, _mb2_ptr: u32) -> GpuProbeReport {
    let bar0 = report
        .bars
        .iter()
        .flatten()
        .find(|b| b.index == 0 && b.is_mmio);

    let arch = bar0
        .filter(|b| b.base > 0)
        .and_then(|b| read_architecture(b.base as usize));

    let disp_enabled = bar0
        .filter(|b| b.base > 0)
        .map(|b| display_engine_enabled(b.base as usize))
        .unwrap_or(false);

    match arch {
        Some(a) if a.is_known_display_capable() && disp_enabled => {
            crate::serial_println!(
                "[NVIDIA GPU] arch={:?} display-enabled — routing to simplefb",
                a
            );
            GpuProbeReport {
                class: GpuClass::NvidiaFamily,
                tier: GpuTier::Scanout,
                caps: GpuCapabilities::scanout(),
                backend: ScanoutBackendId::SimpleFramebuffer,
                ..(*report)
            }
        }
        Some(a) => {
            crate::serial_println!("[NVIDIA GPU] arch={:?} display not enabled — ProbeOnly", a);
            *report
        }
        None => {
            crate::serial_println!("[NVIDIA GPU] BOOT_0 unreadable — ProbeOnly");
            *report
        }
    }
}

/// Activate NVIDIA family scanout via simplefb.
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
