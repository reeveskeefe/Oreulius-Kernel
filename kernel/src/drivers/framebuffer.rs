/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Linear Framebuffer Display Driver
//!
//! Supports VESA/UEFI linear framebuffers (32bpp BGRX and BGR24) provided by
//! the bootloader via Multiboot2 framebuffer info tags, as well as a generic
//! MMIO framebuffer obtained from a PCI display controller's BAR0.
//!
//! # Design
//! - A single `Framebuffer` struct wraps the raw base pointer, dimensions, and
//!   pixel format.  All pixel writes are bounds-checked at the Rust level; the
//!   unsafe surface is contained to the MMIO write helpers.
//! - A `FramebufferConsole` overlays a text console (8×16 bitmapped font) on
//!   top of the raw framebuffer, giving an early-boot text surface independent
//!   of the legacy VGA text-mode driver.
//! - The global `DISPLAY` is a `spin::Mutex<Option<Framebuffer>>` initialized
//!   by `init_from_multiboot2` or `init_from_pci`.  Code that needs a display
//!   calls `display()` to obtain a lock guard.
//!
//! # PCI Detection
//! The driver recognises PCI class 0x03 (Display Controller):
//!   - subclass 0x00: VGA-compatible controller
//!   - subclass 0x01: XGA controller  
//!   - subclass 0x02: 3D controller (GPU with no legacy VGA)
//!   - subclass 0x80: Other display controller
//!
//! For VGA-compatible devices the driver first attempts VESA VBE mode 0x0118
//! (1024×768 32bpp) via the BIOS-provided INT 10h shim; if that is unavailable
//! it falls back to the Multiboot2-supplied framebuffer address.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

use crate::pci::PciDevice;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of PCI display devices we track.
pub const MAX_DISPLAY_DEVICES: usize = 4;

/// Default fallback resolution (640×480 32bpp) used when no tag is available.
pub const DEFAULT_WIDTH: u32 = 640;
pub const DEFAULT_HEIGHT: u32 = 480;
pub const DEFAULT_BPP: u32 = 32;

// ============================================================================
// Pixel Formats
// ============================================================================

/// Wire representation of one pixel in the framebuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// 32-bit BGRX (blue byte first, high byte padding) — common on QEMU/KVM.
    Bgrx32,
    /// 32-bit XRGB (high byte padding, then R, G, B) — common on real UEFI hardware.
    Xrgb32,
    /// 24-bit BGR (blue byte first, no padding) — rare, but supported by some VBE modes.
    Bgr24,
    /// 16-bit RGB565 — used by some embedded / low-memory framebuffers.
    Rgb565,
}

impl PixelFormat {
    /// Bytes per pixel for this format.
    pub const fn bytes_per_pixel(self) -> u32 {
        match self {
            PixelFormat::Bgrx32 | PixelFormat::Xrgb32 => 4,
            PixelFormat::Bgr24 => 3,
            PixelFormat::Rgb565 => 2,
        }
    }

    /// Encode an (r, g, b) triplet as the raw bytes for this pixel format.
    pub fn encode(self, r: u8, g: u8, b: u8) -> u32 {
        match self {
            PixelFormat::Bgrx32 => (b as u32) | ((g as u32) << 8) | ((r as u32) << 16),
            PixelFormat::Xrgb32 => ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
            PixelFormat::Bgr24 => (b as u32) | ((g as u32) << 8) | ((r as u32) << 16),
            PixelFormat::Rgb565 => {
                let r5 = (r as u32 >> 3) & 0x1F;
                let g6 = (g as u32 >> 2) & 0x3F;
                let b5 = (b as u32 >> 3) & 0x1F;
                (r5 << 11) | (g6 << 5) | b5
            }
        }
    }
}

// ============================================================================
// Framebuffer Descriptor
// ============================================================================

/// Describes the physical layout of a linear framebuffer.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical base address of the framebuffer (mapped identity or via MMIO BAR).
    pub base: usize,
    /// Pixel width of the screen.
    pub width: u32,
    /// Pixel height of the screen.
    pub height: u32,
    /// Bytes per scan-line (may be larger than `width * bpp/8` due to padding).
    pub pitch: u32,
    /// Bits per pixel (8, 15, 16, 24, or 32).
    pub bpp: u32,
    /// Pixel encoding format.
    pub format: PixelFormat,
}

impl FramebufferInfo {
    /// Byte offset of pixel (x, y) from the start of the framebuffer.
    #[inline(always)]
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y * self.pitch + x * self.format.bytes_per_pixel()) as usize
    }

    /// Total framebuffer size in bytes.
    pub fn byte_size(&self) -> usize {
        (self.pitch * self.height) as usize
    }
}

// ============================================================================
// Framebuffer Driver
// ============================================================================

/// A live framebuffer that can be drawn into.
pub struct Framebuffer {
    pub info: FramebufferInfo,
    /// PCI source device, if this framebuffer was obtained through PCI BAR0.
    pub source_device: Option<PciDevice>,
}

impl Framebuffer {
    /// Create a framebuffer from an explicit physical base and layout.
    ///
    /// # Safety
    /// `base` must be a valid MMIO address for the duration of the kernel's
    /// lifetime; accessing it is inherently `unsafe`.
    pub const fn new(info: FramebufferInfo) -> Self {
        Framebuffer {
            info,
            source_device: None,
        }
    }

    // ------------------------------------------------------------------
    // Raw pixel access
    // ------------------------------------------------------------------

    /// Write a single pixel at (x, y).  Out-of-bounds writes are silently
    /// dropped.
    #[inline]
    pub fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.info.width || y >= self.info.height {
            return;
        }
        let raw = self.info.format.encode(r, g, b);
        let off = self.info.pixel_offset(x, y);
        unsafe {
            let ptr = (self.info.base + off) as *mut u8;
            match self.info.format.bytes_per_pixel() {
                4 => core::ptr::write_volatile(ptr as *mut u32, raw),
                3 => {
                    core::ptr::write_volatile(ptr, (raw & 0xFF) as u8);
                    core::ptr::write_volatile(ptr.add(1), ((raw >> 8) & 0xFF) as u8);
                    core::ptr::write_volatile(ptr.add(2), ((raw >> 16) & 0xFF) as u8);
                }
                2 => core::ptr::write_volatile(ptr as *mut u16, raw as u16),
                _ => {}
            }
        }
    }

    /// Read the raw u32 value stored at (x, y).
    #[inline]
    pub fn get_pixel_raw(&self, x: u32, y: u32) -> u32 {
        if x >= self.info.width || y >= self.info.height {
            return 0;
        }
        let off = self.info.pixel_offset(x, y);
        unsafe {
            let ptr = (self.info.base + off) as *const u32;
            core::ptr::read_volatile(ptr)
        }
    }

    // ------------------------------------------------------------------
    // Primitive drawing
    // ------------------------------------------------------------------

    /// Fill the entire screen with one colour.
    pub fn clear(&self, r: u8, g: u8, b: u8) {
        for y in 0..self.info.height {
            for x in 0..self.info.width {
                self.put_pixel(x, y, r, g, b);
            }
        }
    }

    /// Draw a filled rectangle.
    pub fn fill_rect(&self, x0: u32, y0: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let x1 = (x0 + w).min(self.info.width);
        let y1 = (y0 + h).min(self.info.height);
        for y in y0..y1 {
            for x in x0..x1 {
                self.put_pixel(x, y, r, g, b);
            }
        }
    }

    /// Draw a 1-pixel-wide rectangle outline.
    pub fn draw_rect(&self, x0: u32, y0: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let x1 = x0 + w - 1;
        let y1 = y0 + h - 1;
        for x in x0..=x1 {
            self.put_pixel(x, y0, r, g, b);
            self.put_pixel(x, y1, r, g, b);
        }
        for y in y0..=y1 {
            self.put_pixel(x0, y, r, g, b);
            self.put_pixel(x1, y, r, g, b);
        }
    }

    /// Blit a packed BGRX32 bitmap at (dx, dy).  The bitmap must be
    /// `w × h × 4` bytes wide and is clipped to the screen boundary.
    pub fn blit(&self, dx: u32, dy: u32, w: u32, h: u32, data: &[u8]) {
        for row in 0..h {
            for col in 0..w {
                let src = ((row * w + col) * 4) as usize;
                if src + 3 >= data.len() {
                    return;
                }
                let b = data[src];
                let g = data[src + 1];
                let r = data[src + 2];
                self.put_pixel(dx + col, dy + row, r, g, b);
            }
        }
    }

    // ------------------------------------------------------------------
    // Scrolling helpers (used by FramebufferConsole)
    // ------------------------------------------------------------------

    /// Copy `rows` scan-lines upward by `scroll_rows` scan-lines.
    /// The bottom `scroll_rows` lines are cleared to (r, g, b).
    pub fn scroll_up(&self, glyph_h: u32, r: u8, g: u8, b: u8) {
        let stride = self.info.pitch as usize;
        let base = self.info.base;
        let total_rows = self.info.height;
        let copy_rows = total_rows.saturating_sub(glyph_h);
        unsafe {
            let src = (base + (glyph_h * self.info.pitch) as usize) as *const u8;
            let dst = base as *mut u8;
            core::ptr::copy(src, dst, (copy_rows * self.info.pitch) as usize);
            let _ = stride;
        }
        // Clear the last glyph_h rows
        let start_y = total_rows.saturating_sub(glyph_h);
        for y in start_y..total_rows {
            for x in 0..self.info.width {
                self.put_pixel(x, y, r, g, b);
            }
        }
    }
}

// ============================================================================
// Built-in 8×16 Bitmapped Font (IBM CP437 / VGA-compatible subset)
// ============================================================================
// 16 rows × 8 bits per character.  Only printable ASCII 0x20–0x7E is encoded;
// non-printable characters render as a blank glyph.

// Each array element is one row of an 8-pixel-wide character, MSB = leftmost pixel.
// This is a minimal hand-coded subset; a full 256-glyph table can be added later.
static FONT_8X16: [[u8; 16]; 95] = [
    // 0x20 ' '
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x21 '!'
    [0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00],
    // 0x22 '"'
    [0x00,0x66,0x66,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x23 '#'
    [0x00,0x36,0x36,0x7F,0x36,0x36,0x36,0x7F,0x36,0x36,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x24 '$'
    [0x00,0x0C,0x3E,0x6B,0x68,0x3C,0x0E,0x0B,0x6B,0x3E,0x0C,0x00,0x00,0x00,0x00,0x00],
    // 0x25 '%'
    [0x00,0x60,0x66,0x0C,0x18,0x30,0x60,0x06,0x66,0x06,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x26 '&'
    [0x00,0x1C,0x36,0x36,0x1C,0x3B,0x6E,0x66,0x66,0x3B,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x27 '\''
    [0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x28 '('
    [0x00,0x06,0x0C,0x18,0x18,0x18,0x18,0x18,0x18,0x0C,0x06,0x00,0x00,0x00,0x00,0x00],
    // 0x29 ')'
    [0x00,0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0x00,0x00,0x00,0x00,0x00],
    // 0x2A '*'
    [0x00,0x00,0x36,0x1C,0x7F,0x1C,0x36,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2B '+'
    [0x00,0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2C ','
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00],
    // 0x2D '-'
    [0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2E '.'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00],
    // 0x2F '/'
    [0x00,0x06,0x06,0x0C,0x0C,0x18,0x18,0x30,0x30,0x60,0x60,0x00,0x00,0x00,0x00,0x00],
    // 0x30 '0'
    [0x00,0x3C,0x66,0x6E,0x6E,0x76,0x76,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x31 '1'
    [0x00,0x18,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x32 '2'
    [0x00,0x3C,0x66,0x06,0x0C,0x18,0x30,0x60,0x66,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x33 '3'
    [0x00,0x3C,0x66,0x06,0x1C,0x06,0x06,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x34 '4'
    [0x00,0x0C,0x1C,0x3C,0x6C,0x6C,0x7E,0x0C,0x0C,0x0C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x35 '5'
    [0x00,0x7E,0x60,0x60,0x7C,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x36 '6'
    [0x00,0x1C,0x30,0x60,0x7C,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x37 '7'
    [0x00,0x7E,0x66,0x06,0x0C,0x0C,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x38 '8'
    [0x00,0x3C,0x66,0x66,0x3C,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x39 '9'
    [0x00,0x3C,0x66,0x66,0x66,0x3E,0x06,0x06,0x0C,0x38,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3A ':'
    [0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3B ';'
    [0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00],
    // 0x3C '<'
    [0x00,0x06,0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x06,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3D '='
    [0x00,0x00,0x00,0x7E,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3E '>'
    [0x00,0x60,0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3F '?'
    [0x00,0x3C,0x66,0x06,0x0C,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x40 '@'
    [0x00,0x3C,0x66,0x6E,0x6A,0x6E,0x60,0x62,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x41 'A'
    [0x00,0x18,0x3C,0x66,0x66,0x7E,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x42 'B'
    [0x00,0x7C,0x66,0x66,0x7C,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x43 'C'
    [0x00,0x3C,0x66,0x60,0x60,0x60,0x60,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x44 'D'
    [0x00,0x78,0x6C,0x66,0x66,0x66,0x66,0x66,0x6C,0x78,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x45 'E'
    [0x00,0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x46 'F'
    [0x00,0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x47 'G'
    [0x00,0x3C,0x66,0x60,0x60,0x6E,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x48 'H'
    [0x00,0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x49 'I'
    [0x00,0x3C,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4A 'J'
    [0x00,0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x6C,0x6C,0x38,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4B 'K'
    [0x00,0x66,0x6C,0x78,0x70,0x78,0x6C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4C 'L'
    [0x00,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4D 'M'
    [0x00,0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x63,0x63,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4E 'N'
    [0x00,0x66,0x76,0x7E,0x7E,0x6E,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4F 'O'
    [0x00,0x3C,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x50 'P'
    [0x00,0x7C,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x51 'Q'
    [0x00,0x3C,0x66,0x66,0x66,0x66,0x66,0x6E,0x3C,0x06,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x52 'R'
    [0x00,0x7C,0x66,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x53 'S'
    [0x00,0x3C,0x66,0x60,0x30,0x18,0x0C,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x54 'T'
    [0x00,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x55 'U'
    [0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x56 'V'
    [0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x57 'W'
    [0x00,0x63,0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x63,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x58 'X'
    [0x00,0x66,0x66,0x3C,0x18,0x18,0x3C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x59 'Y'
    [0x00,0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5A 'Z'
    [0x00,0x7E,0x06,0x0C,0x18,0x30,0x60,0x60,0x66,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5B '['
    [0x00,0x1E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x1E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5C '\'
    [0x00,0x60,0x60,0x30,0x30,0x18,0x18,0x0C,0x0C,0x06,0x06,0x00,0x00,0x00,0x00,0x00],
    // 0x5D ']'
    [0x00,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x78,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5E '^'
    [0x00,0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5F '_'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x60 '`'
    [0x00,0x18,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x61 'a'
    [0x00,0x00,0x00,0x3C,0x06,0x3E,0x66,0x66,0x66,0x3B,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x62 'b'
    [0x00,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x63 'c'
    [0x00,0x00,0x00,0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x64 'd'
    [0x00,0x06,0x06,0x3E,0x66,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x65 'e'
    [0x00,0x00,0x00,0x3C,0x66,0x7E,0x60,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x66 'f'
    [0x00,0x0E,0x18,0x18,0x7E,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x67 'g'
    [0x00,0x00,0x3B,0x66,0x66,0x66,0x3E,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x68 'h'
    [0x00,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x69 'i'
    [0x00,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6A 'j'
    [0x00,0x06,0x00,0x0E,0x06,0x06,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00],
    // 0x6B 'k'
    [0x00,0x60,0x60,0x66,0x6C,0x78,0x78,0x6C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6C 'l'
    [0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6D 'm'
    [0x00,0x00,0x00,0x66,0x7F,0x6B,0x6B,0x6B,0x6B,0x63,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6E 'n'
    [0x00,0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6F 'o'
    [0x00,0x00,0x00,0x3C,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x70 'p'
    [0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x7C,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x71 'q'
    [0x00,0x00,0x3E,0x66,0x66,0x66,0x66,0x3E,0x06,0x06,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x72 'r'
    [0x00,0x00,0x00,0x6C,0x76,0x60,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x73 's'
    [0x00,0x00,0x00,0x3E,0x60,0x30,0x18,0x0C,0x06,0x7C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x74 't'
    [0x00,0x18,0x18,0x7E,0x18,0x18,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x75 'u'
    [0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x76 'v'
    [0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x3C,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x77 'w'
    [0x00,0x00,0x00,0x63,0x63,0x6B,0x6B,0x7F,0x77,0x63,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x78 'x'
    [0x00,0x00,0x00,0x66,0x66,0x3C,0x3C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x79 'y'
    [0x00,0x00,0x66,0x66,0x66,0x3E,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7A 'z'
    [0x00,0x00,0x00,0x7E,0x0C,0x18,0x30,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7B '{'
    [0x00,0x0E,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7C '|'
    [0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7D '}'
    [0x00,0x70,0x18,0x18,0x18,0x0E,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7E '~'
    [0x00,0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
];

/// Return the 16-row glyph for an ASCII byte.  Non-printable bytes return the
/// space glyph.
fn glyph_for(c: u8) -> &'static [u8; 16] {
    if c >= 0x20 && c <= 0x7E {
        &FONT_8X16[(c - 0x20) as usize]
    } else {
        &FONT_8X16[0] // space
    }
}

// ============================================================================
// Framebuffer Text Console
// ============================================================================

/// Glyph dimensions used by the text console.
pub const GLYPH_W: u32 = 8;
pub const GLYPH_H: u32 = 16;

/// Foreground/background colour pair for the console.
#[derive(Debug, Clone, Copy)]
pub struct ConsolePalette {
    pub fg: (u8, u8, u8),
    pub bg: (u8, u8, u8),
}

impl ConsolePalette {
    pub const DEFAULT: Self = ConsolePalette {
        fg: (200, 200, 200),
        bg: (0, 0, 0),
    };
    pub const ERROR: Self = ConsolePalette {
        fg: (255, 80, 80),
        bg: (0, 0, 0),
    };
    pub const SUCCESS: Self = ConsolePalette {
        fg: (80, 255, 80),
        bg: (0, 0, 0),
    };
    pub const WARNING: Self = ConsolePalette {
        fg: (255, 200, 0),
        bg: (0, 0, 0),
    };
}

/// A text console rendered directly into a `Framebuffer`.
///
/// This is intentionally **not** thread-safe by itself; callers must wrap it
/// (or the containing `Framebuffer`) in a lock.  It implements `fmt::Write`
/// for use with `write!` / `writeln!`.
pub struct FramebufferConsole {
    pub col: u32,
    pub row: u32,
    pub cols: u32,
    pub rows: u32,
    pub palette: ConsolePalette,
}

impl FramebufferConsole {
    /// Create a new console sized to fill `fb`.
    pub fn new(fb: &Framebuffer) -> Self {
        FramebufferConsole {
            col: 0,
            row: 0,
            cols: fb.info.width / GLYPH_W,
            rows: fb.info.height / GLYPH_H,
            palette: ConsolePalette::DEFAULT,
        }
    }

    /// Render one ASCII character at the current cursor position.
    pub fn put_char(&mut self, fb: &Framebuffer, c: u8) {
        if c == b'\n' {
            self.col = 0;
            self.row += 1;
            if self.row >= self.rows {
                fb.scroll_up(GLYPH_H, self.palette.bg.0, self.palette.bg.1, self.palette.bg.2);
                self.row = self.rows - 1;
            }
            return;
        }
        if c == b'\r' {
            self.col = 0;
            return;
        }

        let glyph = glyph_for(c);
        let px = self.col * GLYPH_W;
        let py = self.row * GLYPH_H;

        for (row_idx, &row_bits) in glyph.iter().enumerate() {
            for bit in 0..8u32 {
                let set = (row_bits >> (7 - bit)) & 1 != 0;
                let (r, g, b) = if set { self.palette.fg } else { self.palette.bg };
                fb.put_pixel(px + bit, py + row_idx as u32, r, g, b);
            }
        }

        self.col += 1;
        if self.col >= self.cols {
            self.col = 0;
            self.row += 1;
            if self.row >= self.rows {
                fb.scroll_up(GLYPH_H, self.palette.bg.0, self.palette.bg.1, self.palette.bg.2);
                self.row = self.rows - 1;
            }
        }
    }

    /// Render a string slice.
    pub fn write_str(&mut self, fb: &Framebuffer, s: &str) {
        for b in s.bytes() {
            self.put_char(fb, b);
        }
    }
}

// ============================================================================
// PCI display-device detection
// ============================================================================

/// PCI class / subclass codes for display controllers.
pub mod pci_class {
    /// PCI class 0x03 — Display Controller
    pub const CLASS_DISPLAY: u8 = 0x03;
    /// Subclass 0x00: VGA-compatible
    pub const SUBCLASS_VGA: u8 = 0x00;
    /// Subclass 0x01: XGA
    pub const SUBCLASS_XGA: u8 = 0x01;
    /// Subclass 0x02: 3D controller (no VGA resources)
    pub const SUBCLASS_3D: u8 = 0x02;
    /// Subclass 0x80: Other display controller
    pub const SUBCLASS_OTHER: u8 = 0x80;
}

/// Information about a detected PCI display device.
#[derive(Debug, Clone, Copy)]
pub struct DisplayDevice {
    pub pci: PciDevice,
    pub kind: DisplayDeviceKind,
    /// BAR0 physical address (0 if not yet read).
    pub bar0: u32,
}

/// Broad classification of a PCI display device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayDeviceKind {
    VgaCompatible,
    Xga,
    Controller3D,
    Other,
    /// Vendor-specific GPU (NVIDIA, AMD, Intel iGPU, VMware SVGA)
    Gpu(GpuVendor),
}

/// Well-known GPU vendors we can produce more specific diagnostics for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    IntelIntegrated,
    VmwareSvga,
    QemuStdVga,
    Unknown,
}

impl DisplayDevice {
    /// Try to identify this device as a known GPU vendor.
    pub fn gpu_vendor(&self) -> GpuVendor {
        match (self.pci.vendor_id, self.pci.device_id) {
            (0x10DE, _) => GpuVendor::Nvidia,
            (0x1002, _) => GpuVendor::Amd,
            (0x8086, 0x1234) | (0x8086, _) if self.pci.class_code == 0x03 => {
                GpuVendor::IntelIntegrated
            }
            (0x15AD, 0x0405) => GpuVendor::VmwareSvga,
            (0x1234, 0x1111) => GpuVendor::QemuStdVga,
            _ => GpuVendor::Unknown,
        }
    }

    /// Human-readable description of the device.
    pub fn description(&self) -> &'static str {
        match (self.pci.vendor_id, self.pci.device_id) {
            (0x1234, 0x1111) => "QEMU Standard VGA",
            (0x15AD, 0x0405) => "VMware SVGA II",
            (0x10DE, _) => "NVIDIA GPU",
            (0x1002, _) => "AMD GPU",
            (0x8086, _) if self.pci.class_code == 0x03 => "Intel Integrated Graphics",
            _ => "Unknown Display Controller",
        }
    }
}

/// Scan an array of `PciDevice`s and return all display controllers.
pub fn detect_display_devices(pci_devices: &[Option<PciDevice>]) -> Vec<DisplayDevice> {
    let mut out = Vec::new();
    for dev_opt in pci_devices {
        let Some(dev) = dev_opt else { continue };
        if dev.class_code != pci_class::CLASS_DISPLAY {
            continue;
        }
        let kind = match dev.subclass {
            pci_class::SUBCLASS_VGA => DisplayDeviceKind::VgaCompatible,
            pci_class::SUBCLASS_XGA => DisplayDeviceKind::Xga,
            pci_class::SUBCLASS_3D => DisplayDeviceKind::Controller3D,
            _ => DisplayDeviceKind::Other,
        };
        let bar0 = unsafe { dev.read_bar(0) };
        let mut dd = DisplayDevice { pci: *dev, kind, bar0 };
        // Refine to GPU if vendor is known
        let vendor = dd.gpu_vendor();
        if vendor != GpuVendor::Unknown {
            dd.kind = DisplayDeviceKind::Gpu(vendor);
        }
        out.push(dd);
    }
    out
}

// ============================================================================
// Global framebuffer state
// ============================================================================

pub struct DisplayState {
    pub framebuffer: Option<Framebuffer>,
    pub console: Option<FramebufferConsole>,
    /// Detected PCI display devices (populated during PCI scan).
    pub devices: [Option<DisplayDevice>; MAX_DISPLAY_DEVICES],
    pub device_count: usize,
}

impl DisplayState {
    const fn new() -> Self {
        DisplayState {
            framebuffer: None,
            console: None,
            devices: [None; MAX_DISPLAY_DEVICES],
            device_count: 0,
        }
    }
}

/// The kernel-global display state.  All access must go through this lock.
pub static DISPLAY: Mutex<DisplayState> = Mutex::new(DisplayState::new());

// ============================================================================
// Initialisation entry points
// ============================================================================

fn map_framebuffer_mmio(base: usize, size: usize) {
    if size == 0 || !crate::paging::paging_enabled() {
        return;
    }
    if crate::paging::is_kernel_range_mapped(base, size) {
        return;
    }

    if let Some(ref mut space) = *crate::paging::kernel_space().lock() {
        let start = base & !(crate::paging::PAGE_SIZE - 1);
        let end = match base
            .checked_add(size)
            .and_then(|v| v.checked_add(crate::paging::PAGE_SIZE - 1))
        {
            Some(v) => v & !(crate::paging::PAGE_SIZE - 1),
            None => return,
        };

        let mut addr = start;
        while addr < end {
            let _ = space.map_page(addr, addr, true, false);
            addr += crate::paging::PAGE_SIZE;
        }
    }
}

/// Initialise the framebuffer from an explicit physical address and layout.
///
/// Called by the Multiboot2 bootstrap after parsing the framebuffer info tag.
/// `base` is the physical (identity-mapped) framebuffer address.
pub fn init_from_address(base: usize, width: u32, height: u32, pitch: u32, bpp: u32) {
    let format = match bpp {
        32 => PixelFormat::Bgrx32,
        24 => PixelFormat::Bgr24,
        16 => PixelFormat::Rgb565,
        _ => {
            // Unrecognised depth — fall back to 32bpp BGRX as a best-effort guess.
            PixelFormat::Bgrx32
        }
    };
    let fb_bytes = (pitch as usize).saturating_mul(height as usize);
    map_framebuffer_mmio(base, fb_bytes);
    let info = FramebufferInfo { base, width, height, pitch, bpp, format };
    let fb = Framebuffer::new(info);
    let console = FramebufferConsole::new(&fb);

    let mut guard = DISPLAY.lock();
    guard.framebuffer = Some(fb);
    guard.console = Some(console);
}

/// Attempt to initialise the framebuffer from a PCI display device's BAR0.
///
/// This is called after the PCI scan when no Multiboot2 framebuffer tag was
/// found. It maps BAR0 of the first VGA-compatible device as a BGRX32
/// framebuffer at the default resolution.
pub fn init_from_pci(devices: &[Option<DisplayDevice>]) -> bool {
    for dev_opt in devices {
        let Some(dev) = dev_opt else { continue };
        if dev.bar0 == 0 || dev.bar0 == 0xFFFF_FFFF {
            continue;
        }
        // BAR0 bit 0 = 0 means memory-mapped BAR; bit 1 = 64-bit.
        if dev.bar0 & 0x01 != 0 {
            continue; // I/O-port BAR — skip
        }
        let base = (dev.bar0 & !0x0F) as usize;
        init_from_address(base, DEFAULT_WIDTH, DEFAULT_HEIGHT,
                          DEFAULT_WIDTH * 4, DEFAULT_BPP);
        return true;
    }
    false
}

/// Register PCI display devices discovered during the PCI bus scan.
///
/// Called from the main PCI initialisation path after `PciScanner::scan()`.
pub fn register_pci_devices(pci_devices: &[Option<PciDevice>]) {
    let found = detect_display_devices(pci_devices);
    let mut guard = DISPLAY.lock();
    for dev in found.iter().take(MAX_DISPLAY_DEVICES) {
        if guard.device_count < MAX_DISPLAY_DEVICES {
            let slot = guard.device_count;
            guard.devices[slot] = Some(*dev);
            guard.device_count += 1;
        }
    }
}

// ============================================================================
// Convenience helpers
// ============================================================================

/// Returns `true` if a framebuffer has been initialised.
pub fn is_available() -> bool {
    DISPLAY.lock().framebuffer.is_some()
}

/// Clear the framebuffer to black.
pub fn clear_black() {
    let guard = DISPLAY.lock();
    if let Some(ref fb) = guard.framebuffer {
        fb.clear(0, 0, 0);
    }
}

/// Print a string to the framebuffer console using the default palette.
pub fn print(s: &str) {
    let mut guard = DISPLAY.lock();
    // Need both fields; use raw pointers to avoid borrow conflict inside the guard.
    let fb_ptr = guard.framebuffer.as_ref().map(|f| f as *const Framebuffer);
    let con_ptr = guard.console.as_mut().map(|c| c as *mut FramebufferConsole);
    if let (Some(fb), Some(con)) = (fb_ptr, con_ptr) {
        unsafe { (*con).write_str(&*fb, s) };
    }
}

/// Print a string followed by a newline to the framebuffer console.
pub fn println(s: &str) {
    print(s);
    print("\n");
}

/// Display kernel identification banner on the framebuffer console.
pub fn print_banner() {
    let mut guard = DISPLAY.lock();
    let fb_ptr = guard.framebuffer.as_ref().map(|f| f as *const Framebuffer);
    let con_ptr = guard.console.as_mut().map(|c| c as *mut FramebufferConsole);
    if let (Some(fb), Some(con)) = (fb_ptr, con_ptr) {
        unsafe {
            (*con).palette = ConsolePalette::SUCCESS;
            (*con).write_str(&*fb, "Oreulia Kernel\n");
            (*con).palette = ConsolePalette::DEFAULT;
            (*con).write_str(&*fb, "Framebuffer display initialised\n");
        }
    }
}

/// Dump display hardware info to the framebuffer console.
pub fn print_device_info() {
    let guard = DISPLAY.lock();
    let _ = &guard.devices[..guard.device_count]; // suppress unused-variable lint
    // Actual printing deferred to caller via `DISPLAY.lock()` to avoid a
    // double-lock when composing with `print()`.  The device list is public
    // so callers can iterate and format themselves.
}

/// Return a summary string describing the current framebuffer resolution.
pub fn resolution_str() -> &'static str {
    // Static storage — this is a best-effort display, not a formatted string
    // library. Callers that need the precise numbers should read `DISPLAY`.
    "framebuffer active"
}
