/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * Global GPU registry and active backend selection.
 */

use spin::Mutex;

use super::core::GpuProbeReport;
use super::display::scanout::ScanoutBackendId;

pub const MAX_GPU_DEVICES: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct RegisteredGpu {
    pub report: GpuProbeReport,
    pub active: bool,
}

pub struct GpuRegistry {
    devices: [Option<RegisteredGpu>; MAX_GPU_DEVICES],
    len: usize,
    active: Option<usize>,
    active_backend: ScanoutBackendId,
}

impl GpuRegistry {
    pub const fn new() -> Self {
        GpuRegistry {
            devices: [None, None, None, None, None, None, None, None],
            len: 0,
            active: None,
            active_backend: ScanoutBackendId::None,
        }
    }

    pub fn clear(&mut self) {
        self.devices = [None, None, None, None, None, None, None, None];
        self.len = 0;
        self.active = None;
        self.active_backend = ScanoutBackendId::None;
    }

    pub fn register(&mut self, report: GpuProbeReport) -> Option<usize> {
        if self.len >= MAX_GPU_DEVICES {
            return None;
        }
        let idx = self.len;
        self.devices[idx] = Some(RegisteredGpu {
            report,
            active: false,
        });
        self.len += 1;
        Some(idx)
    }

    pub fn set_active(&mut self, report: GpuProbeReport) {
        self.active_backend = report.backend;
        self.active = None;
        for idx in 0..self.len {
            if let Some(mut entry) = self.devices[idx] {
                let matches =
                    entry.report.class == report.class && entry.report.backend == report.backend;
                entry.active = matches;
                self.devices[idx] = Some(entry);
                if matches {
                    self.active = Some(idx);
                }
            }
        }
    }

    pub fn set_active_backend(&mut self, backend: ScanoutBackendId) {
        self.active_backend = backend;
    }

    pub fn active_report(&self) -> Option<GpuProbeReport> {
        self.active
            .and_then(|idx| self.devices[idx].map(|entry| entry.report))
    }

    pub const fn active_backend(&self) -> ScanoutBackendId {
        self.active_backend
    }
}

pub static GPU_REGISTRY: Mutex<GpuRegistry> = Mutex::new(GpuRegistry::new());

pub fn gpu_registry() -> spin::MutexGuard<'static, GpuRegistry> {
    GPU_REGISTRY.lock()
}

pub fn clear() {
    GPU_REGISTRY.lock().clear();
}

pub fn register(report: GpuProbeReport) -> Option<usize> {
    GPU_REGISTRY.lock().register(report)
}

pub fn set_active(report: GpuProbeReport) {
    GPU_REGISTRY.lock().set_active(report);
}

pub fn set_active_backend(backend: ScanoutBackendId) {
    GPU_REGISTRY.lock().set_active_backend(backend);
}

pub fn active_probe_report() -> Option<GpuProbeReport> {
    GPU_REGISTRY.lock().active_report()
}

pub fn active_backend() -> ScanoutBackendId {
    GPU_REGISTRY.lock().active_backend()
}
