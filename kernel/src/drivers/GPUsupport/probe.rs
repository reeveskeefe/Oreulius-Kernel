/*!
 * Safe PCI/framebuffer GPU probing.
 */

use crate::pci::{PciDevice, PciScanner};

use super::caps::GpuCapabilities;
use super::core::{GpuBarInfo, GpuClass, GpuProbeReport, GpuTier};
use super::display::scanout::ScanoutBackendId;
use super::drivers::{amd, intel, nvidia, simplefb};

pub const MAX_PROBE_REPORTS: usize = 8;

fn classify_device(dev: PciDevice) -> (GpuClass, GpuTier, GpuCapabilities, ScanoutBackendId, bool) {
    match (dev.vendor_id, dev.device_id) {
        (0x1AF4, 0x1050) | (0x1AF4, 0x1005) => (
            GpuClass::VirtioGpu,
            GpuTier::Scanout,
            GpuCapabilities::scanout(),
            ScanoutBackendId::VirtioGpu,
            false,
        ),
        (0x1B36, 0x0100) => (
            GpuClass::Qxl,
            GpuTier::Scanout,
            GpuCapabilities::scanout(),
            ScanoutBackendId::Qxl,
            false,
        ),
        (0x1234, 0x1111) | (0x15AD, 0x0405) => (
            GpuClass::Bochs,
            GpuTier::Scanout,
            GpuCapabilities::scanout(),
            ScanoutBackendId::Bochs,
            false,
        ),
        (0x8086, _) => (
            GpuClass::IntelFamily,
            GpuTier::ProbeOnly,
            GpuCapabilities::probe_only(),
            ScanoutBackendId::None,
            false,
        ),
        (0x1002, _) | (0x1022, _) => (
            GpuClass::AmdFamily,
            GpuTier::ProbeOnly,
            GpuCapabilities::probe_only(),
            ScanoutBackendId::None,
            true,
        ),
        (0x10DE, _) => (
            GpuClass::NvidiaFamily,
            GpuTier::ProbeOnly,
            GpuCapabilities::probe_only(),
            ScanoutBackendId::None,
            true,
        ),
        _ => (
            GpuClass::UnknownDisplay,
            GpuTier::ProbeOnly,
            GpuCapabilities::probe_only(),
            ScanoutBackendId::None,
            false,
        ),
    }
}

fn bars_for_device(dev: &PciDevice) -> [Option<GpuBarInfo>; 6] {
    let mut bars = [None, None, None, None, None, None];
    for idx in 0..6u8 {
        let raw = unsafe { dev.read_bar(idx) };
        if raw == 0 || raw == 0xFFFF_FFFF {
            continue;
        }
        let is_mmio = raw & 0x1 == 0;
        let is_64bit = is_mmio && ((raw >> 1) & 0x3) == 0x2;
        let prefetchable = is_mmio && (raw & 0x8) != 0;
        let base = if is_mmio { (raw & !0xFu32) as u64 } else { (raw & !0x3u32) as u64 };
        bars[idx as usize] = Some(GpuBarInfo {
            index: idx,
            base,
            size_hint: 0,
            is_mmio,
            is_64bit,
            prefetchable,
        });
    }
    bars
}

pub fn probe_pci_device(dev: PciDevice, mb2_ptr: u32) -> GpuProbeReport {
    let (class, tier, caps, backend, firmware_required) = classify_device(dev);
    let base_report = GpuProbeReport {
        pci: Some(dev),
        class,
        tier,
        caps,
        irq_line: dev.interrupt_line,
        bars: bars_for_device(&dev),
        backend,
        firmware_required,
    };
    // Give vendor-specific drivers a chance to upgrade the tier to Scanout
    // based on live register reads (e.g. pipe-active, CRTC-enabled).
    match base_report.class {
        GpuClass::IntelFamily   => intel::probe_display(&base_report, mb2_ptr),
        GpuClass::AmdFamily     => amd::probe_display(&base_report, mb2_ptr),
        GpuClass::NvidiaFamily  => nvidia::probe_display(&base_report, mb2_ptr),
        _                       => base_report,
    }
}

pub fn probe_all(mb2_ptr: u32) -> [Option<GpuProbeReport>; MAX_PROBE_REPORTS] {
    let mut out = [None, None, None, None, None, None, None, None];
    let mut count = 0usize;

    if unsafe { simplefb::detect_mb2_framebuffer(mb2_ptr) }.is_some() {
        out[count] = Some(GpuProbeReport::framebuffer(
            GpuTier::Scanout,
            GpuCapabilities::scanout(),
            ScanoutBackendId::SimpleFramebuffer,
        ));
        count += 1;
    }

    let mut scanner = PciScanner::new();
    scanner.scan();
    for dev in scanner.find_all_display_devices().iter().flatten() {
        if count >= MAX_PROBE_REPORTS {
            break;
        }
        out[count] = Some(probe_pci_device(*dev, mb2_ptr));
        count += 1;
    }

    if count == 0 {
        out[0] = Some(GpuProbeReport::framebuffer(
            GpuTier::Scanout,
            GpuCapabilities::scanout(),
            ScanoutBackendId::SimpleFramebuffer,
        ));
    }

    out
}

