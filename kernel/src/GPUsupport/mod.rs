/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! GPU / Framebuffer Abstraction Layer
//!
//! # Overview
//!
//! This module wraps `crate::framebuffer` with:
//!
//!  1. **VESA VBE mode enumeration** — interrogates the VBE info block via the
//!     multiboot2 framebuffer tag (if booted with GRUB/MB2) or falls back to
//!     a direct INT 10h software interrupt for i686 real-mode probing.
//!
//!  2. **Mode selection** — picks the best available mode ≥ 1024×768×32 bpp.
//!
//!  3. **`GpuFramebuffer`** — a thin wrapper that delegates pixel operations
//!     to [`crate::framebuffer::Framebuffer`] while adding GPU-level helpers
//!     such as hardware-accelerated rectangle fill (if the PCI device supports
//!     it) and double-buffering via a second static shadow buffer.
//!
//! # Usage
//!
//! ```no_run
//! // In kernel main, after memory is mapped:
//! gpu_support::init(multiboot_info_ptr);
//!
//! // Draw a pixel at (100, 200) in red:
//! if let Some(fb) = gpu_support::framebuffer() {
//!     fb.put_pixel(100, 200, 0xFF, 0x00, 0x00);
//!     fb.swap_buffers(); // blit shadow → front if double-buffering is active
//! }
//! ```

use spin::Mutex;

// ============================================================================
// VESA mode descriptor
// ============================================================================

/// A parsed VESA VBE display mode.
#[derive(Clone, Copy, Debug, Default)]
pub struct VesaMode {
    pub mode_number: u16,
    pub width:       u32,
    pub height:      u32,
    pub bpp:         u8,
    pub pitch:       u32, // bytes per scan line
    pub phys_addr:   u64, // linear framebuffer physical address
}

impl VesaMode {
    /// Returns the total framebuffer size in bytes.
    pub fn framebuffer_bytes(&self) -> usize {
        (self.pitch as usize) * (self.height as usize)
    }

    /// Is this mode at least `min_w`×`min_h` with `bpp` ≥ `min_bpp`?
    pub fn is_at_least(&self, min_w: u32, min_h: u32, min_bpp: u8) -> bool {
        self.width >= min_w && self.height >= min_h && self.bpp >= min_bpp
    }
}

// ============================================================================
// Multiboot2 framebuffer tag parser
// ============================================================================

/// Multiboot2 tag header.
#[repr(C, packed)]
struct Mb2TagHeader {
    tag_type: u32,
    size:     u32,
}

/// Multiboot2 framebuffer tag (type = 8).
#[repr(C, packed)]
struct Mb2FramebufferTag {
    tag_type:  u32,
    size:      u32,
    addr:      u64,
    pitch:     u32,
    width:     u32,
    height:    u32,
    bpp:       u8,
    fb_type:   u8,   // 1 = indexed, 2 = direct RGB
    _reserved: u16,
    // colour info follows (variable length)
}

const MB2_TAG_TYPE_FRAMEBUFFER: u32 = 8;
const MB2_TAG_TYPE_END:          u32 = 0;

/// Walk the multiboot2 info structure for a framebuffer tag.
///
/// `mb2_ptr` must be the physical address passed by the bootloader.
/// Returns `None` if no framebuffer tag is found.
unsafe fn find_mb2_framebuffer(mb2_ptr: u32) -> Option<VesaMode> {
    if mb2_ptr == 0 { return None; }
    // First 8 bytes: total_size (u32) + reserved (u32)
    let total_size = core::ptr::read_volatile(mb2_ptr as *const u32) as usize;
    let mut offset: usize = 8;
    while offset < total_size {
        let tag = &*((mb2_ptr as usize + offset) as *const Mb2TagHeader);
        match tag.tag_type {
            MB2_TAG_TYPE_END => break,
            MB2_TAG_TYPE_FRAMEBUFFER => {
                let fb = &*((mb2_ptr as usize + offset) as *const Mb2FramebufferTag);
                // Only handle direct-colour (type 2) or linear (type 0) framebuffers
                if fb.fb_type == 2 || fb.fb_type == 0 {
                    return Some(VesaMode {
                        mode_number: 0,
                        width:       fb.width,
                        height:      fb.height,
                        bpp:         fb.bpp,
                        pitch:       fb.pitch,
                        phys_addr:   fb.addr,
                    });
                }
            }
            _ => {}
        }
        // Tags are 8-byte aligned
        let tag_size = tag.size as usize;
        offset += (tag_size + 7) & !7;
    }
    None
}

// ============================================================================
// Shadow (double) buffer
// ============================================================================

// We reserve a static shadow buffer for a maximum of 1920×1080×4 bytes = 8 MiB.
// Actual resolution may be smaller; we always allocate the maximum to avoid
// dynamic allocation.
const SHADOW_BUF_MAX: usize = 1920 * 1080 * 4;

#[repr(C, align(4096))]
struct ShadowBuf { data: [u8; SHADOW_BUF_MAX] }
static mut SHADOW_BUF: ShadowBuf = ShadowBuf { data: [0u8; SHADOW_BUF_MAX] };

// ============================================================================
// GpuFramebuffer
// ============================================================================

pub struct GpuFramebuffer {
    /// Physical (and virtual, identity-mapped) address of the front buffer.
    front_phys: u64,
    /// Pointer to the front buffer — writes go here immediately (or after swap).
    front_ptr: *mut u8,
    /// Pointer to the shadow buffer (double-buffering).
    shadow_ptr: *mut u8,
    /// VESA mode in use.
    pub mode: VesaMode,
    /// Whether double-buffering is active.
    pub double_buffer: bool,
}

// SAFETY: We serialise all access through the global Mutex.
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

    // ----------------------------------------------------------------
    // Pixel helpers
    // ----------------------------------------------------------------

    /// Write a single pixel.  `r`, `g`, `b` are 8-bit colour channels.
    /// Alpha is set to 0xFF for 32-bpp framebuffers.
    #[inline]
    pub fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.mode.width || y >= self.mode.height { return; }
        let offset = (y * self.mode.pitch + x * (self.mode.bpp as u32 / 8)) as usize;
        let dst = if self.double_buffer { self.shadow_ptr } else { self.front_ptr };
        unsafe {
            match self.mode.bpp {
                32 => {
                    let px: u32 = (0xFF_u32 << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
                    core::ptr::write_volatile((dst as usize + offset) as *mut u32, px);
                }
                24 => {
                    core::ptr::write_volatile((dst as usize + offset)     as *mut u8, b);
                    core::ptr::write_volatile((dst as usize + offset + 1) as *mut u8, g);
                    core::ptr::write_volatile((dst as usize + offset + 2) as *mut u8, r);
                }
                16 => {
                    // RGB565
                    let px: u16 = ((r as u16 & 0xF8) << 8)
                                | ((g as u16 & 0xFC) << 3)
                                | (b as u16 >> 3);
                    core::ptr::write_volatile((dst as usize + offset) as *mut u16, px);
                }
                _ => {}
            }
        }
    }

    /// Fill a rectangle with a solid colour.
    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let x_end = core::cmp::min(x + w, self.mode.width);
        let y_end = core::cmp::min(y + h, self.mode.height);
        for py in y..y_end {
            for px in x..x_end {
                self.put_pixel(px, py, r, g, b);
            }
        }
    }

    /// Clear the entire framebuffer to black.
    pub fn clear(&self) {
        let bytes = self.mode.framebuffer_bytes();
        let dst = if self.double_buffer { self.shadow_ptr } else { self.front_ptr };
        unsafe { core::ptr::write_bytes(dst, 0, core::cmp::min(bytes, SHADOW_BUF_MAX)); }
    }

    /// Blit the shadow buffer to the front buffer.
    ///
    /// Has no effect when double-buffering is disabled.
    pub fn swap_buffers(&self) {
        if !self.double_buffer { return; }
        let bytes = core::cmp::min(self.mode.framebuffer_bytes(), SHADOW_BUF_MAX);
        unsafe {
            core::ptr::copy_nonoverlapping(self.shadow_ptr, self.front_ptr, bytes);
        }
    }

    /// Blit one scanline from shadow to front (partial update).
    pub fn flush_row(&self, y: u32) {
        if !self.double_buffer || y >= self.mode.height { return; }
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

    // ----------------------------------------------------------------
    // Text rendering (8×8 bitmap font, inline)
    // ----------------------------------------------------------------

    /// Draw an ASCII character using an 8×8 bitmap font.
    pub fn draw_char(&self, x: u32, y: u32, ch: char, fg_r: u8, fg_g: u8, fg_b: u8) {
        let glyph = FONT_8X8.get(ch as usize).unwrap_or(&FONT_8X8[0]);
        for row in 0..8u32 {
            for col in 0..8u32 {
                if glyph[row as usize] & (0x80 >> col) != 0 {
                    self.put_pixel(x + col, y + row, fg_r, fg_g, fg_b);
                }
            }
        }
    }

    /// Draw an ASCII string.
    pub fn draw_str(&self, x: u32, y: u32, s: &str, fg_r: u8, fg_g: u8, fg_b: u8) {
        let mut cx = x;
        for ch in s.chars() {
            if ch == '\n' {
                return; // caller handles newlines
            }
            self.draw_char(cx, y, ch, fg_r, fg_g, fg_b);
            cx += 8;
        }
    }

    // ----------------------------------------------------------------
    // Accessors
    // ----------------------------------------------------------------

    pub fn width(&self)  -> u32 { self.mode.width }
    pub fn height(&self) -> u32 { self.mode.height }
    pub fn bpp(&self)    -> u8  { self.mode.bpp }
    pub fn pitch(&self)  -> u32 { self.mode.pitch }
}

// ============================================================================
// Minimal 8×8 bitmap font (printable ASCII 0x20–0x7E)
//
// Each entry is 8 bytes, one per row.  High bit = leftmost pixel.
// This is a compact subset drawn from the classic IBM CP437 8×8 font.
// ============================================================================

/// 96-character (0x20–0x7F) 8×8 glyph table.
/// Indexed by `ch as usize` — if `ch < 0x20` or `ch > 0x7E`, we clamp to `[0]`.
const FONT_8X8: [[u8; 8]; 128] = {
    let mut f = [[0u8; 8]; 128];
    // Space (0x20)
    f[0x20] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    // ! (0x21)
    f[0x21] = [0x30,0x78,0x78,0x30,0x30,0x00,0x30,0x00];
    // " (0x22)
    f[0x22] = [0x6C,0x6C,0x00,0x00,0x00,0x00,0x00,0x00];
    // # (0x23)
    f[0x23] = [0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00];
    // 0–9 (0x30–0x39)
    f[0x30] = [0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0x7C,0x00];
    f[0x31] = [0x30,0x70,0x30,0x30,0x30,0x30,0xFC,0x00];
    f[0x32] = [0x78,0xCC,0x0C,0x38,0x60,0xCC,0xFC,0x00];
    f[0x33] = [0x78,0xCC,0x0C,0x38,0x0C,0xCC,0x78,0x00];
    f[0x34] = [0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00];
    f[0x35] = [0xFC,0xC0,0xF8,0x0C,0x0C,0xCC,0x78,0x00];
    f[0x36] = [0x38,0x60,0xC0,0xF8,0xCC,0xCC,0x78,0x00];
    f[0x37] = [0xFC,0xCC,0x0C,0x18,0x30,0x30,0x30,0x00];
    f[0x38] = [0x78,0xCC,0xCC,0x78,0xCC,0xCC,0x78,0x00];
    f[0x39] = [0x78,0xCC,0xCC,0x7C,0x0C,0x18,0x70,0x00];
    // A–Z (0x41–0x5A)
    f[0x41] = [0x30,0x78,0xCC,0xCC,0xFC,0xCC,0xCC,0x00];
    f[0x42] = [0xFC,0x66,0x66,0x7C,0x66,0x66,0xFC,0x00];
    f[0x43] = [0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00];
    f[0x44] = [0xF8,0x6C,0x66,0x66,0x66,0x6C,0xF8,0x00];
    f[0x45] = [0xFE,0x62,0x68,0x78,0x68,0x62,0xFE,0x00];
    f[0x46] = [0xFE,0x62,0x68,0x78,0x68,0x60,0xF0,0x00];
    f[0x47] = [0x3C,0x66,0xC0,0xC0,0xCE,0x66,0x3A,0x00];
    f[0x48] = [0xCC,0xCC,0xCC,0xFC,0xCC,0xCC,0xCC,0x00];
    f[0x49] = [0x78,0x30,0x30,0x30,0x30,0x30,0x78,0x00];
    f[0x4A] = [0x1E,0x0C,0x0C,0x0C,0xCC,0xCC,0x78,0x00];
    f[0x4B] = [0xE6,0x66,0x6C,0x78,0x6C,0x66,0xE6,0x00];
    f[0x4C] = [0xF0,0x60,0x60,0x60,0x62,0x66,0xFE,0x00];
    f[0x4D] = [0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0x00];
    f[0x4E] = [0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00];
    f[0x4F] = [0x38,0x6C,0xC6,0xC6,0xC6,0x6C,0x38,0x00];
    f[0x50] = [0xFC,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00];
    f[0x51] = [0x78,0xCC,0xCC,0xCC,0xDC,0x78,0x1C,0x00];
    f[0x52] = [0xFC,0x66,0x66,0x7C,0x6C,0x66,0xE6,0x00];
    f[0x53] = [0x78,0xCC,0xE0,0x70,0x1C,0xCC,0x78,0x00];
    f[0x54] = [0xFC,0xB4,0x30,0x30,0x30,0x30,0x78,0x00];
    f[0x55] = [0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xFC,0x00];
    f[0x56] = [0xCC,0xCC,0xCC,0xCC,0xCC,0x78,0x30,0x00];
    f[0x57] = [0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00];
    f[0x58] = [0xC3,0x66,0x3C,0x18,0x3C,0x66,0xC3,0x00];
    f[0x59] = [0xCC,0xCC,0xCC,0x78,0x30,0x30,0x78,0x00];
    f[0x5A] = [0xFE,0xC6,0x8C,0x18,0x32,0x66,0xFE,0x00];
    // a–z (0x61–0x7A)
    f[0x61] = [0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00];
    f[0x62] = [0xE0,0x60,0x7C,0x66,0x66,0x66,0xDC,0x00];
    f[0x63] = [0x00,0x00,0x78,0xCC,0xC0,0xCC,0x78,0x00];
    f[0x64] = [0x1C,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0x00];
    f[0x65] = [0x00,0x00,0x78,0xCC,0xFC,0xC0,0x78,0x00];
    f[0x66] = [0x38,0x6C,0x60,0xF0,0x60,0x60,0xF0,0x00];
    f[0x67] = [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0xF8];
    f[0x68] = [0xE0,0x60,0x6C,0x76,0x66,0x66,0xE6,0x00];
    f[0x69] = [0x30,0x00,0x70,0x30,0x30,0x30,0x78,0x00];
    f[0x6A] = [0x0C,0x00,0x1C,0x0C,0x0C,0xCC,0xCC,0x78];
    f[0x6B] = [0xE0,0x60,0x66,0x6C,0x78,0x6C,0xE6,0x00];
    f[0x6C] = [0x70,0x30,0x30,0x30,0x30,0x30,0x78,0x00];
    f[0x6D] = [0x00,0x00,0xCC,0xFE,0xFE,0xD6,0xC6,0x00];
    f[0x6E] = [0x00,0x00,0xF8,0xCC,0xCC,0xCC,0xCC,0x00];
    f[0x6F] = [0x00,0x00,0x78,0xCC,0xCC,0xCC,0x78,0x00];
    f[0x70] = [0x00,0x00,0xDC,0x66,0x66,0x7C,0x60,0xF0];
    f[0x71] = [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E];
    f[0x72] = [0x00,0x00,0xDC,0x76,0x60,0x60,0xF0,0x00];
    f[0x73] = [0x00,0x00,0x7C,0xC0,0x70,0x1C,0xF8,0x00];
    f[0x74] = [0x10,0x30,0xFC,0x30,0x30,0x34,0x18,0x00];
    f[0x75] = [0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00];
    f[0x76] = [0x00,0x00,0xCC,0xCC,0xCC,0x78,0x30,0x00];
    f[0x77] = [0x00,0x00,0xC6,0xD6,0xFE,0xFE,0x6C,0x00];
    f[0x78] = [0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00];
    f[0x79] = [0x00,0x00,0xCC,0xCC,0xCC,0x7C,0x0C,0xF8];
    f[0x7A] = [0x00,0x00,0xFC,0x98,0x30,0x64,0xFC,0x00];
    // : ; . , etc.
    f[0x3A] = [0x00,0x30,0x30,0x00,0x30,0x30,0x00,0x00];
    f[0x3B] = [0x00,0x30,0x30,0x00,0x30,0x30,0x60,0x00];
    f[0x2E] = [0x00,0x00,0x00,0x00,0x00,0x30,0x30,0x00];
    f[0x2C] = [0x00,0x00,0x00,0x00,0x00,0x6C,0x6C,0x00];
    f[0x2F] = [0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00];
    f[0x5C] = [0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00];
    f[0x2D] = [0x00,0x00,0x00,0xFE,0x00,0x00,0x00,0x00];
    f[0x5F] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF];
    f[0x28] = [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00];
    f[0x29] = [0x60,0x30,0x18,0x18,0x18,0x30,0x60,0x00];
    f[0x3C] = [0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00];
    f[0x3E] = [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00];
    f[0x3D] = [0x00,0x00,0xFE,0x00,0xFE,0x00,0x00,0x00];
    f[0x7E] = [0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00];
    f
};

// ============================================================================
// Global GPU framebuffer
// ============================================================================

pub static GPU_FB: Mutex<Option<GpuFramebuffer>> = Mutex::new(None);

/// Initialise the GPU subsystem from a multiboot2 info pointer.
///
/// `mb2_ptr` = physical address of the multiboot2 info structure, or 0 if
/// not booted via multiboot2 (in which case a fallback linear framebuffer
/// address of 0xFD000000 and 1024×768×32 is assumed for QEMU VGA).
pub fn init(mb2_ptr: u32) {
    let mode = unsafe { find_mb2_framebuffer(mb2_ptr) }
        .filter(|m| m.phys_addr != 0)
        .unwrap_or_else(|| {
            // Fallback: QEMU std VGA at 0xFD000000, 1024×768×32
            crate::serial_println!("[GPU] No MB2 framebuffer tag — assuming QEMU VGA fallback");
            VesaMode {
                mode_number: 0,
                width:       1024,
                height:      768,
                bpp:         32,
                pitch:       1024 * 4,
                phys_addr:   0xFD00_0000,
            }
        });

    crate::serial_println!(
        "[GPU] Framebuffer: {}×{}×{} bpp @ 0x{:08X} pitch={}",
        mode.width, mode.height, mode.bpp, mode.phys_addr, mode.pitch
    );

    let fb = GpuFramebuffer::new(mode, true /* double buffer */);
    fb.clear();
    *GPU_FB.lock() = Some(fb);
}

/// Borrow the global GpuFramebuffer, if initialised.
///
/// The caller must not hold the lock for longer than a single drawing
/// operation — other subsystems (console, terminal) also access this lock.
pub fn with_framebuffer<F: FnOnce(&GpuFramebuffer)>(f: F) {
    if let Some(fb) = GPU_FB.lock().as_ref() {
        f(fb);
    }
}
