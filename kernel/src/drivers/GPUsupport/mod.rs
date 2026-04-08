/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Oreulius universal GPU substrate.
//!
//! This subsystem provides a tiered GPU model that is safe on unknown hardware
//! and progressively richer on standardized or plugin-backed devices:
//!
//! - Tier 0: safe probe only
//! - Tier 1: scanout / compositor backend
//! - Tier 2: normalized transfer path
//! - Tier 3: normalized compute path
//! - Tier 4: optimized vendor-family acceleration
//!
//! The kernel does not attempt unsafe brandless MMIO command inference.
//! Unknown devices receive the highest safe tier Oreulius can actually prove.

#![allow(dead_code)]

pub mod backend;
pub mod caps;
pub mod core;
pub mod display;
pub mod drivers;
pub mod engines;
pub mod errors;
pub mod firmware;
pub mod memory;
pub mod probe;
pub mod registry;
pub mod security;
pub mod telemetry;
pub mod topology;
pub mod transport;

#[cfg(test)]
pub mod tests;

pub use caps::{GpuCapabilities, GpuEngineMask};
pub use core::{GpuClass, GpuProbeReport, GpuTier};
pub use display::scanout::{
    active_present_target, with_active_scanout, PresentTarget, ScanoutBackendId, ScanoutDevice,
};
pub use drivers::simplefb::{with_framebuffer, GpuFramebuffer, VesaMode, GPU_FB};
pub use engines::packets::{CommandPacket, ComputePacket, TransferPacket};
pub use errors::GpuError;
pub use memory::bo::BufferObject;
pub use registry::{active_backend, active_probe_report, gpu_registry};
pub use transport::fence::GpuFence;

use ::core::cmp::Ordering;

fn backend_priority(backend: ScanoutBackendId) -> u8 {
    match backend {
        ScanoutBackendId::VirtioGpu => 0,
        ScanoutBackendId::Qxl => 1,
        ScanoutBackendId::Bochs => 2,
        ScanoutBackendId::SimpleFramebuffer => 3,
        ScanoutBackendId::None => 4,
    }
}

fn report_cmp(a: &GpuProbeReport, b: &GpuProbeReport) -> Ordering {
    let tier_cmp = b.tier.rank().cmp(&a.tier.rank());
    if tier_cmp != Ordering::Equal {
        return tier_cmp;
    }
    backend_priority(a.backend).cmp(&backend_priority(b.backend))
}

fn best_probe_report(reports: &[Option<GpuProbeReport>]) -> Option<GpuProbeReport> {
    let mut best = None;
    for report in reports.iter().flatten() {
        match best {
            None => best = Some(*report),
            Some(current) if report_cmp(report, &current).is_lt() => best = Some(*report),
            _ => {}
        }
    }
    best
}

fn activate_report(report: GpuProbeReport, mb2_ptr: u32) -> Result<(), GpuError> {
    match report.backend {
        ScanoutBackendId::VirtioGpu => drivers::virtio_gpu::activate(mb2_ptr),
        ScanoutBackendId::Qxl => drivers::qxl::activate(mb2_ptr),
        ScanoutBackendId::Bochs => drivers::bochs::activate(mb2_ptr),
        ScanoutBackendId::SimpleFramebuffer => drivers::simplefb::activate(mb2_ptr).map(|_| ()),
        ScanoutBackendId::None => {
            *GPU_FB.lock() = None;
            Ok(())
        }
    }
}

/// Initialise the universal GPU substrate.
///
/// This performs safe probe, picks the highest-priority supported backend,
/// activates it, and registers the resulting device for the compositor.
pub fn init(mb2_ptr: u32) {
    registry::clear();

    let reports = probe::probe_all(mb2_ptr);
    for report in reports.iter().flatten() {
        let _ = registry::register(*report);
    }

    if let Some(best) = best_probe_report(&reports) {
        if let Err(err) = activate_report(best, mb2_ptr) {
            crate::serial_println!("[GPU] activation failed: {:?}", err);
            *GPU_FB.lock() = None;
            registry::set_active_backend(ScanoutBackendId::None);
            return;
        }
        registry::set_active(best);
        crate::serial_println!(
            "[GPU] active class={:?} tier={:?} backend={:?}",
            best.class,
            best.tier,
            best.backend
        );
        return;
    }

    crate::serial_println!("[GPU] no supported scanout backend detected");
    *GPU_FB.lock() = None;
    registry::set_active_backend(ScanoutBackendId::None);
}

/// Active screen dimensions as reported by the selected scanout backend.
pub fn active_dimensions() -> (u32, u32) {
    let target = active_present_target();
    (target.width, target.height)
}
