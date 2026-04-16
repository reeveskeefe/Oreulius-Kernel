// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


//! Compositor present pass.
//!
//! `present_frame` iterates all live windows in z-order (bottom to top),
//! alpha-blends their surface pixels into each scanline, then writes the
//! result to the display backend.
//!
//! Only the bounding box of all accumulated damage rectangles is re-rendered,
//! keeping the cost proportional to how much actually changed each frame.

#![allow(dead_code)]

use super::backend::DisplayBackend;
use super::damage::{DamageAccumulator, DamageRect};
use super::surface::SurfacePool;
use super::window::WindowTable;

// ---------------------------------------------------------------------------
// Alpha blending
// ---------------------------------------------------------------------------

/// Porter-Duff `src-over` blend of `src` on top of `dst`.
/// Both colours are packed ARGB (A in bits 31–24).
#[inline(always)]
pub fn alpha_blend(dst: u32, src: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 0xFF {
        return src; // fully opaque fast path
    }
    if sa == 0 {
        return dst; // fully transparent fast path
    }
    let da = (dst >> 24) & 0xFF;
    let inv_sa = 255 - sa;

    let out_a = sa + ((da * inv_sa + 127) / 255);

    let blend_chan = |s: u32, d: u32| -> u32 { (s * sa + d * inv_sa + 127) / 255 };

    let r = blend_chan((src >> 16) & 0xFF, (dst >> 16) & 0xFF);
    let g = blend_chan((src >> 8) & 0xFF, (dst >> 8) & 0xFF);
    let b = blend_chan(src & 0xFF, dst & 0xFF);

    (out_a << 24) | (r << 16) | (g << 8) | b
}

// ---------------------------------------------------------------------------
// Present pass
// ---------------------------------------------------------------------------

/// Scanline scratch buffer width. Wider damage rects are processed in chunks.
const MAX_SCAN_WIDTH: usize = super::policy::MAX_WINDOW_WIDTH as usize;

/// Composit all dirty regions onto the display backend.
///
/// After this call the caller should invoke `damage.clear()` and
/// `windows.clear_dirty_all()`.
pub fn present_frame(
    damage: &DamageAccumulator,
    windows: &WindowTable,
    surfaces: &SurfacePool,
    backend: &dyn DisplayBackend,
) {
    if !damage.is_dirty() {
        return;
    }
    if !backend.is_available() {
        return;
    }

    // Build a z-sorted window list.
    let mut sorted_ids = [super::protocol::WindowId(0); super::window::MAX_WINDOWS];
    let count = windows.sorted_ids(&mut sorted_ids);
    let sorted = &sorted_ids[..count];

    // Re-render each damage rectangle.
    for rect in damage.rects() {
        present_rect(rect, sorted, windows, surfaces, backend);
    }
}

/// Render one damage rectangle by compositing all overlapping windows onto
/// the backend, one scanline at a time.
fn present_rect(
    rect: DamageRect,
    sorted_ids: &[super::protocol::WindowId],
    windows: &WindowTable,
    surfaces: &SurfacePool,
    backend: &dyn DisplayBackend,
) {
    // Scratch scanline buffer — ARGB.
    let mut scanline = [0u32; MAX_SCAN_WIDTH];

    let x0 = rect.x;
    let y0 = rect.y;
    let x1 = (rect.x + rect.w).min(backend.width());
    let y1 = (rect.y + rect.h).min(backend.height());

    if x1 <= x0 || y1 <= y0 {
        return;
    }
    for chunk_x0 in (x0..x1).step_by(MAX_SCAN_WIDTH.max(1)) {
        let chunk_x1 = (chunk_x0 + MAX_SCAN_WIDTH as u32).min(x1);
        let scan_len = (chunk_x1 - chunk_x0) as usize;

        for sy in y0..y1 {
            for px in &mut scanline[..scan_len] {
                *px = 0xFF00_0000;
            }

            for &wid in sorted_ids {
                let Some(win) = windows.find(wid) else {
                    continue;
                };
                let Some(surf) = surfaces.get(win.surface_idx) else {
                    continue;
                };

                if !surf.alive {
                    continue;
                }

                let win_y = sy as i32 - win.y;
                if win_y < 0 || win_y >= win.height as i32 {
                    continue;
                }

                for sx_screen in chunk_x0..chunk_x1 {
                    let sx = sx_screen as i32 - win.x;
                    if sx < 0 || sx >= win.width as i32 {
                        continue;
                    }

                    let argb = surf.get_pixel(sx as u32, win_y as u32);
                    let slot = (sx_screen - chunk_x0) as usize;
                    scanline[slot] = alpha_blend(scanline[slot], argb);
                }
            }

            for i in 0..scan_len {
                let argb = scanline[i];
                let r = ((argb >> 16) & 0xFF) as u8;
                let g = ((argb >> 8) & 0xFF) as u8;
                let b = (argb & 0xFF) as u8;
                backend.put_pixel(chunk_x0 + i as u32, sy, r, g, b);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::present_frame;
    use crate::compositor::backend::DisplayBackend;
    use crate::compositor::damage::DamageAccumulator;
    use crate::compositor::surface::SurfacePool;
    use crate::compositor::window::WindowTable;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend {
        width: u32,
        height: u32,
        pixels: AtomicUsize,
    }

    impl CountingBackend {
        const fn new(width: u32, height: u32) -> Self {
            CountingBackend {
                width,
                height,
                pixels: AtomicUsize::new(0),
            }
        }
    }

    impl DisplayBackend for CountingBackend {
        fn put_pixel(&self, _x: u32, _y: u32, _r: u8, _g: u8, _b: u8) {
            self.pixels.fetch_add(1, Ordering::Relaxed);
        }

        fn fill_rect(&self, _x: u32, _y: u32, _w: u32, _h: u32, _r: u8, _g: u8, _b: u8) {}

        fn flush(&self) {}

        fn width(&self) -> u32 {
            self.width
        }

        fn height(&self) -> u32 {
            self.height
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    #[test]
    fn present_frame_handles_backends_wider_than_scanline_chunk() {
        let backend = CountingBackend::new(2560, 1);
        let windows = WindowTable::new();
        let surfaces = SurfacePool::new();
        let mut damage = DamageAccumulator::new(2560, 1);
        damage.add_region(0, 0, 2560, 1);

        present_frame(&damage, &windows, &surfaces, &backend);

        assert_eq!(backend.pixels.load(Ordering::Relaxed), 2560);
    }
}
