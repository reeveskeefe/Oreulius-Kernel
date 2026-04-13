/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Compositor policy enforcement.
//!
//! Centralises all quota and bounds checks so that the main service dispatch
//! loop stays readable.  Every check returns `Ok(())` or a typed
//! `CompositorError` that can be forwarded straight back to the client.

#![allow(dead_code)]

use super::protocol::CompositorError;

/// Hard limits enforced per-session.
pub const MAX_WINDOWS_PER_SESSION: usize = 8;
pub const MAX_SURFACES_PER_SESSION: usize = 8;

/// Maximum surface / window dimensions (pixels).
pub const MAX_WINDOW_WIDTH: u32 = 1920;
pub const MAX_WINDOW_HEIGHT: u32 = 1080;

/// Minimum sensible size (avoids zero-area allocation attempts).
pub const MIN_WINDOW_WIDTH: u32 = 1;
pub const MIN_WINDOW_HEIGHT: u32 = 1;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

pub struct CompositorPolicy;

impl CompositorPolicy {
    pub const fn new() -> Self {
        CompositorPolicy
    }

    // ------------------------------------------------------------------
    // Window creation
    // ------------------------------------------------------------------

    /// Check that a session may create another window.
    pub fn check_create_window(
        &self,
        current_window_count: usize,
        w: u32,
        h: u32,
    ) -> Result<(), CompositorError> {
        if current_window_count >= MAX_WINDOWS_PER_SESSION {
            return Err(CompositorError::QuotaExceeded);
        }
        self.check_window_size(w, h)
    }

    /// Check that (width, height) are within allowed bounds.
    pub fn check_window_size(&self, w: u32, h: u32) -> Result<(), CompositorError> {
        if w < MIN_WINDOW_WIDTH || h < MIN_WINDOW_HEIGHT {
            return Err(CompositorError::InvalidSize);
        }
        if w > MAX_WINDOW_WIDTH || h > MAX_WINDOW_HEIGHT {
            return Err(CompositorError::InvalidSize);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Surface creation
    // ------------------------------------------------------------------

    /// Check that a session may create another surface and that its size is
    /// within policy limits.
    pub fn check_surface_size(
        &self,
        current_surface_count: usize,
        w: u32,
        h: u32,
    ) -> Result<(), CompositorError> {
        if current_surface_count >= MAX_SURFACES_PER_SESSION {
            return Err(CompositorError::QuotaExceeded);
        }
        if w == 0 || h == 0 {
            return Err(CompositorError::InvalidSize);
        }
        if w > MAX_WINDOW_WIDTH || h > MAX_WINDOW_HEIGHT {
            return Err(CompositorError::InvalidSize);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Position / z-order
    // ------------------------------------------------------------------

    /// Clamp a window position so that at least a 1-pixel strip remains on
    /// screen (prevents windows from being entirely off-screen).
    pub fn clamp_position(
        &self,
        x: i32,
        y: i32,
        w: u32,
        h: u32,
        screen_w: u32,
        screen_h: u32,
    ) -> (i32, i32) {
        let max_x = screen_w as i32 - 1;
        let max_y = screen_h as i32 - 1;
        let min_x = -(w as i32) + 1;
        let min_y = -(h as i32) + 1;
        (x.max(min_x).min(max_x), y.max(min_y).min(max_y))
    }

    // ------------------------------------------------------------------
    // Input subscription
    // ------------------------------------------------------------------

    /// Check that a session is allowed to subscribe to input events.
    /// Currently always true; hook here for future sandboxing.
    pub fn check_input_subscription(&self) -> Result<(), CompositorError> {
        Ok(())
    }
}
