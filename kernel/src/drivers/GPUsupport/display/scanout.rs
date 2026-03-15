/*!
 * Compositor-facing scanout abstraction.
 */

use super::super::drivers::{bochs, qxl, simplefb, virtio_gpu};
use super::super::registry;

pub trait ScanoutDevice {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8);
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8);
    fn flush(&self);
    fn width(&self) -> u32;
    fn height(&self) -> u32;
    fn is_available(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanoutBackendId {
    None,
    SimpleFramebuffer,
    Bochs,
    Qxl,
    VirtioGpu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentTarget {
    pub width: u32,
    pub height: u32,
    pub backend: ScanoutBackendId,
}

struct NullScanout;
struct SimpleFbScanout;
struct BochsScanout;
struct QxlScanout;
struct VirtioGpuScanout;

impl ScanoutDevice for NullScanout {
    fn put_pixel(&self, _x: u32, _y: u32, _r: u8, _g: u8, _b: u8) {}
    fn fill_rect(&self, _x: u32, _y: u32, _w: u32, _h: u32, _r: u8, _g: u8, _b: u8) {}
    fn flush(&self) {}
    fn width(&self) -> u32 { 0 }
    fn height(&self) -> u32 { 0 }
    fn is_available(&self) -> bool { false }
}

impl ScanoutDevice for SimpleFbScanout {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        simplefb::put_pixel(x, y, r, g, b);
    }
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        simplefb::fill_rect(x, y, w, h, r, g, b);
    }
    fn flush(&self) { simplefb::flush(); }
    fn width(&self) -> u32 { simplefb::dimensions().0 }
    fn height(&self) -> u32 { simplefb::dimensions().1 }
    fn is_available(&self) -> bool { simplefb::is_available() }
}

impl ScanoutDevice for BochsScanout {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) { bochs::put_pixel(x, y, r, g, b); }
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        bochs::fill_rect(x, y, w, h, r, g, b);
    }
    fn flush(&self) { bochs::flush(); }
    fn width(&self) -> u32 { bochs::dimensions().0 }
    fn height(&self) -> u32 { bochs::dimensions().1 }
    fn is_available(&self) -> bool { bochs::is_available() }
}

impl ScanoutDevice for QxlScanout {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) { qxl::put_pixel(x, y, r, g, b); }
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        qxl::fill_rect(x, y, w, h, r, g, b);
    }
    fn flush(&self) { qxl::flush(); }
    fn width(&self) -> u32 { qxl::dimensions().0 }
    fn height(&self) -> u32 { qxl::dimensions().1 }
    fn is_available(&self) -> bool { qxl::is_available() }
}

impl ScanoutDevice for VirtioGpuScanout {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        virtio_gpu::put_pixel(x, y, r, g, b);
    }
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        virtio_gpu::fill_rect(x, y, w, h, r, g, b);
    }
    fn flush(&self) { virtio_gpu::flush(); }
    fn width(&self) -> u32 { virtio_gpu::dimensions().0 }
    fn height(&self) -> u32 { virtio_gpu::dimensions().1 }
    fn is_available(&self) -> bool { virtio_gpu::is_available() }
}

static NULL_SCANOUT: NullScanout = NullScanout;
static SIMPLEFB_SCANOUT: SimpleFbScanout = SimpleFbScanout;
static BOCHS_SCANOUT: BochsScanout = BochsScanout;
static QXL_SCANOUT: QxlScanout = QxlScanout;
static VIRTIO_GPU_SCANOUT: VirtioGpuScanout = VirtioGpuScanout;

pub fn with_backend<F: FnOnce(&dyn ScanoutDevice)>(backend: ScanoutBackendId, f: F) {
    match backend {
        ScanoutBackendId::None => f(&NULL_SCANOUT),
        ScanoutBackendId::SimpleFramebuffer => f(&SIMPLEFB_SCANOUT),
        ScanoutBackendId::Bochs => f(&BOCHS_SCANOUT),
        ScanoutBackendId::Qxl => f(&QXL_SCANOUT),
        ScanoutBackendId::VirtioGpu => f(&VIRTIO_GPU_SCANOUT),
    }
}

pub fn with_active_scanout<F: FnOnce(&dyn ScanoutDevice)>(f: F) {
    with_backend(registry::active_backend(), f);
}

pub fn active_present_target() -> PresentTarget {
    let mut width = 0;
    let mut height = 0;
    let backend = registry::active_backend();
    with_backend(backend, |scanout| {
        width = scanout.width();
        height = scanout.height();
    });
    PresentTarget { width, height, backend }
}

