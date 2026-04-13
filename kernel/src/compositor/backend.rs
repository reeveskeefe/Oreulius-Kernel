/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Display backend abstraction.
//!
//! Provides a hardware-independent interface that the compositor uses to push
//! pixels to the screen.  The real implementation (`FbBackend`) delegates to
//! the GPU/framebuffer driver.  A `NoopBackend` exists for headless / test
//! environments where no display hardware is present.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Low-level display output interface.
///
/// All coordinates are in screen pixels.  Color components are 0–255.
pub trait DisplayBackend {
    /// Write a single pixel.
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8);

    /// Fill a rectangle with a solid color.
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8);

    /// Flush (swap buffers / signal VSYNC) after a frame is complete.
    fn flush(&self);

    /// Screen width in pixels.
    fn width(&self) -> u32;

    /// Screen height in pixels.
    fn height(&self) -> u32;

    /// True if the backend has real hardware behind it.
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// No-op backend (headless / fallback)
// ---------------------------------------------------------------------------

/// A display backend that does nothing.  Used when no framebuffer is
/// available (e.g. early boot or CI).
pub struct NoopBackend {
    width: u32,
    height: u32,
}

impl NoopBackend {
    pub const fn new(width: u32, height: u32) -> Self {
        NoopBackend { width, height }
    }
}

impl DisplayBackend for NoopBackend {
    #[inline]
    fn put_pixel(&self, _x: u32, _y: u32, _r: u8, _g: u8, _b: u8) {}

    #[inline]
    fn fill_rect(&self, _x: u32, _y: u32, _w: u32, _h: u32, _r: u8, _g: u8, _b: u8) {}

    #[inline]
    fn flush(&self) {}

    #[inline]
    fn width(&self) -> u32 {
        self.width
    }

    #[inline]
    fn height(&self) -> u32 {
        self.height
    }

    #[inline]
    fn is_available(&self) -> bool {
        false
    }
}
