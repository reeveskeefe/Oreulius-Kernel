//! Framebuffer display backend.
//!
//! Implements `DisplayBackend` by delegating to the active GPU scanout
//! backend. On platforms where no scanout is available all operations become
//! no-ops.

#![allow(dead_code)]

use super::backend::DisplayBackend;

#[cfg(not(target_arch = "aarch64"))]
use crate::gpu_support;

// ---------------------------------------------------------------------------
// FbBackend
// ---------------------------------------------------------------------------

/// Framebuffer-backed display backend.
pub struct FbBackend {
    width: u32,
    height: u32,
    available: bool,
}

impl FbBackend {
    /// Construct the backend.  `width` and `height` are the screen dimensions
    /// reported by the framebuffer driver (or 0 if unavailable).
    pub const fn new(width: u32, height: u32) -> Self {
        let available = width > 0 && height > 0;
        FbBackend {
            width,
            height,
            available,
        }
    }

    /// Update the screen size (e.g. after a mode change).
    pub fn set_size(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
        self.available = width > 0 && height > 0;
    }
}

impl DisplayBackend for FbBackend {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if !self.available {
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.put_pixel(x, y, r, g, b));
    }

    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        if !self.available {
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.fill_rect(x, y, w, h, r, g, b));
    }

    fn flush(&self) {
        if !self.available {
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.flush());
    }

    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn is_available(&self) -> bool {
        self.available
    }
}
