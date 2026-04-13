/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Framebuffer display backend.
//!
//! Implements `DisplayBackend` by delegating to the active GPU scanout
//! backend. On platforms where no scanout is available all operations become
//! no-ops.

#![allow(dead_code)]

use super::backend::DisplayBackend;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

#[cfg(not(target_arch = "aarch64"))]
use crate::drivers::x86::gpu_support;

static SHADOW_PUT_PIXEL_CALLS: AtomicUsize = AtomicUsize::new(0);
static SHADOW_FILL_RECT_CALLS: AtomicUsize = AtomicUsize::new(0);
static SHADOW_FLUSH_CALLS: AtomicUsize = AtomicUsize::new(0);
static SHADOW_LAST_PIXEL: Mutex<u64> = Mutex::new(0);
static SHADOW_LAST_RECT: Mutex<u64> = Mutex::new(0);

#[inline]
fn record_shadow_pixel(x: u32, y: u32, r: u8, g: u8, b: u8) {
    SHADOW_PUT_PIXEL_CALLS.fetch_add(1, Ordering::Relaxed);
    *SHADOW_LAST_PIXEL.lock() = ((x as u64) << 32)
        | ((y as u64) << 16)
        | ((r as u64) << 8)
        | ((g as u64) << 4)
        | (b as u64);
}

#[inline]
fn record_shadow_rect(x: u32, y: u32, w: u32, h: u32) {
    SHADOW_FILL_RECT_CALLS.fetch_add(1, Ordering::Relaxed);
    *SHADOW_LAST_RECT.lock() =
        ((x as u64) << 48) | ((y as u64) << 32) | ((w as u64) << 16) | (h as u64);
}

#[inline]
fn record_shadow_flush() {
    SHADOW_FLUSH_CALLS.fetch_add(1, Ordering::Relaxed);
}

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
            record_shadow_pixel(x, y, r, g, b);
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.put_pixel(x, y, r, g, b));
        #[cfg(target_arch = "aarch64")]
        record_shadow_pixel(x, y, r, g, b);
    }

    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        if !self.available {
            let _ = (r, g, b);
            record_shadow_rect(x, y, w, h);
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.fill_rect(x, y, w, h, r, g, b));
        #[cfg(target_arch = "aarch64")]
        {
            let _ = (r, g, b);
            record_shadow_rect(x, y, w, h);
        }
    }

    fn flush(&self) {
        if !self.available {
            record_shadow_flush();
            return;
        }
        #[cfg(not(target_arch = "aarch64"))]
        gpu_support::with_active_scanout(|scanout| scanout.flush());
        #[cfg(target_arch = "aarch64")]
        record_shadow_flush();
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
