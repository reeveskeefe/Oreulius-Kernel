/*!
 * Generic framebuffer / simple scanout backend.
 */

use spin::Mutex;

use crate::drivers::x86::framebuffer;
use crate::drivers::x86::gpu_support::errors::GpuError;

#[derive(Clone, Copy, Debug, Default)]
pub struct VesaMode {
    pub mode_number: u16,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub pitch: u32,
    pub phys_addr: u64,
}

impl VesaMode {
    pub fn framebuffer_bytes(&self) -> usize {
        (self.pitch as usize) * (self.height as usize)
    }
}

#[repr(C, packed)]
struct Mb2TagHeader {
    tag_type: u32,
    size: u32,
}

#[repr(C, packed)]
struct Mb2FramebufferTag {
    tag_type: u32,
    size: u32,
    addr: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u8,
    fb_type: u8,
    _reserved: u16,
}

const MB2_TAG_TYPE_FRAMEBUFFER: u32 = 8;
const MB2_TAG_TYPE_END: u32 = 0;

pub unsafe fn detect_mb2_framebuffer(mb2_ptr: u32) -> Option<VesaMode> {
    if mb2_ptr == 0 {
        return None;
    }
    let total_size = core::ptr::read_volatile(mb2_ptr as *const u32) as usize;
    let mut offset = 8usize;
    while offset < total_size {
        let tag = &*((mb2_ptr as usize + offset) as *const Mb2TagHeader);
        match tag.tag_type {
            MB2_TAG_TYPE_END => break,
            MB2_TAG_TYPE_FRAMEBUFFER => {
                let fb = &*((mb2_ptr as usize + offset) as *const Mb2FramebufferTag);
                if fb.fb_type == 2 || fb.fb_type == 0 {
                    return Some(VesaMode {
                        mode_number: 0,
                        width: fb.width,
                        height: fb.height,
                        bpp: fb.bpp,
                        pitch: fb.pitch,
                        phys_addr: fb.addr,
                    });
                }
            }
            _ => {}
        }
        offset += (tag.size as usize + 7) & !7;
    }
    None
}

const SHADOW_BUF_MAX: usize = 1920 * 1080 * 4;

#[repr(C, align(4096))]
struct ShadowBuf {
    data: [u8; SHADOW_BUF_MAX],
}

static mut SHADOW_BUF: ShadowBuf = ShadowBuf {
    data: [0u8; SHADOW_BUF_MAX],
};

pub struct GpuFramebuffer {
    #[allow(dead_code)]
    front_phys: u64,
    front_ptr: *mut u8,
    shadow_ptr: *mut u8,
    pub mode: VesaMode,
    pub double_buffer: bool,
}

unsafe impl Send for GpuFramebuffer {}
unsafe impl Sync for GpuFramebuffer {}

impl GpuFramebuffer {
    fn new(mode: VesaMode, double_buffer: bool) -> Self {
        GpuFramebuffer {
            front_phys: mode.phys_addr,
            front_ptr: mode.phys_addr as *mut u8,
            shadow_ptr: unsafe { SHADOW_BUF.data.as_mut_ptr() },
            mode,
            double_buffer,
        }
    }

    #[inline]
    pub fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }
        let offset = (y * self.mode.pitch + x * (self.mode.bpp as u32 / 8)) as usize;
        let dst = if self.double_buffer {
            self.shadow_ptr
        } else {
            self.front_ptr
        };
        unsafe {
            match self.mode.bpp {
                32 => {
                    let px: u32 =
                        (0xFFu32 << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
                    core::ptr::write_volatile((dst as usize + offset) as *mut u32, px);
                }
                24 => {
                    core::ptr::write_volatile((dst as usize + offset) as *mut u8, b);
                    core::ptr::write_volatile((dst as usize + offset + 1) as *mut u8, g);
                    core::ptr::write_volatile((dst as usize + offset + 2) as *mut u8, r);
                }
                16 => {
                    let px: u16 =
                        ((r as u16 & 0xF8) << 8) | ((g as u16 & 0xFC) << 3) | (b as u16 >> 3);
                    core::ptr::write_volatile((dst as usize + offset) as *mut u16, px);
                }
                _ => {}
            }
        }
    }

    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let x_end = core::cmp::min(x + w, self.mode.width);
        let y_end = core::cmp::min(y + h, self.mode.height);
        for py in y..y_end {
            for px in x..x_end {
                self.put_pixel(px, py, r, g, b);
            }
        }
    }

    pub fn clear(&self) {
        let bytes = self.mode.framebuffer_bytes();
        let dst = if self.double_buffer {
            self.shadow_ptr
        } else {
            self.front_ptr
        };
        unsafe {
            core::ptr::write_bytes(dst, 0, core::cmp::min(bytes, SHADOW_BUF_MAX));
        }
    }

    pub fn swap_buffers(&self) {
        if !self.double_buffer {
            return;
        }
        let bytes = core::cmp::min(self.mode.framebuffer_bytes(), SHADOW_BUF_MAX);
        unsafe {
            core::ptr::copy_nonoverlapping(self.shadow_ptr, self.front_ptr, bytes);
        }
    }

    pub fn flush_row(&self, y: u32) {
        if !self.double_buffer || y >= self.mode.height {
            return;
        }
        let row_bytes = self.mode.pitch as usize;
        let offset = (y * self.mode.pitch) as usize;
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.shadow_ptr.add(offset),
                self.front_ptr.add(offset),
                row_bytes,
            );
        }
    }

    pub fn width(&self) -> u32 {
        self.mode.width
    }
    pub fn height(&self) -> u32 {
        self.mode.height
    }
}

pub static GPU_FB: Mutex<Option<GpuFramebuffer>> = Mutex::new(None);

fn fallback_mode() -> VesaMode {
    VesaMode {
        mode_number: 0,
        width: 1024,
        height: 768,
        bpp: 32,
        pitch: 1024 * 4,
        phys_addr: 0xFD00_0000,
    }
}

fn try_pci_framebuffer() -> Option<VesaMode> {
    let mut scanner = crate::drivers::x86::pci::PciScanner::new();
    scanner.scan();
    framebuffer::register_pci_devices(scanner.devices());

    let display_devices = {
        let guard = framebuffer::DISPLAY.lock();
        guard.devices
    };

    if !framebuffer::init_from_pci(&display_devices) {
        return None;
    }

    let guard = framebuffer::DISPLAY.lock();
    let fb = guard.framebuffer.as_ref()?;
    Some(VesaMode {
        mode_number: 0,
        width: fb.info.width,
        height: fb.info.height,
        bpp: fb.info.bpp as u8,
        pitch: fb.info.pitch,
        phys_addr: fb.info.base as u64,
    })
}

pub fn activate(mb2_ptr: u32) -> Result<VesaMode, GpuError> {
    let mode = unsafe { detect_mb2_framebuffer(mb2_ptr) }
        .filter(|m| m.phys_addr != 0)
        .map(|mode| {
            framebuffer::init_from_address(
                mode.phys_addr as usize,
                mode.width,
                mode.height,
                mode.pitch,
                mode.bpp as u32,
            );
            mode
        })
        .or_else(try_pci_framebuffer)
        .unwrap_or_else(|| {
            let mode = fallback_mode();
            framebuffer::init_from_address(
                mode.phys_addr as usize,
                mode.width,
                mode.height,
                mode.pitch,
                mode.bpp as u32,
            );
            mode
        });

    // Identity-map the physical framebuffer region so that swap_buffers() can
    // write to front_ptr without triggering a page fault.  The kernel page
    // tables only cover low RAM by default; the Bochs/VBE LFB lives at
    // 0xFD000000 which is well above that range.
    //
    // On x86 (i686) the legacy paging module owns the active page tables via
    // KERNEL_ADDRESS_SPACE.  On x86_64 the MMU module owns the live CR3 and
    // KERNEL_ADDRESS_SPACE is always None, so we call the x86_64-specific
    // map_mmio_identity_range shim instead.
    let fb_phys = mode.phys_addr as usize;
    let fb_size = mode.framebuffer_bytes();
    if fb_phys != 0 && fb_size != 0 {
        #[cfg(target_arch = "x86_64")]
        {
            crate::arch::mmu::map_mmio_identity_range(fb_phys, fb_size);
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let mut guard = crate::fs::paging::KERNEL_ADDRESS_SPACE.lock();
            if let Some(space) = guard.as_mut() {
                let _ = space.map_mmio_range(fb_phys, fb_size);
            }
        }
    }

    let fb = GpuFramebuffer::new(mode, true);
    fb.clear();
    *GPU_FB.lock() = Some(fb);
    Ok(mode)
}

pub fn with_framebuffer<F: FnOnce(&GpuFramebuffer)>(f: F) {
    if let Some(fb) = GPU_FB.lock().as_ref() {
        f(fb);
    }
}

pub fn put_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
    with_framebuffer(|fb| fb.put_pixel(x, y, r, g, b));
}

pub fn fill_rect(x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
    with_framebuffer(|fb| fb.fill_rect(x, y, w, h, r, g, b));
}

pub fn flush() {
    with_framebuffer(|fb| fb.swap_buffers());
}

pub fn dimensions() -> (u32, u32) {
    let lock = GPU_FB.lock();
    lock.as_ref()
        .map(|fb| (fb.width(), fb.height()))
        .unwrap_or((0, 0))
}

pub fn is_available() -> bool {
    GPU_FB.lock().is_some()
}
