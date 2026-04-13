/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Oreulius Compositor / Window Manager
//!
//! A lightweight compositing window manager for the Oreulius kernel.
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────┐
//! │                   COMPOSITOR                       │
//! │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────────────┐  │
//! │  │Layer0│  │Layer1│  │Layer2│  │ WallpaperLayer│  │
//! │  │(z=0) │  │(z=1) │  │(z=2) │  │   (z=255)    │  │
//! │  └──────┘  └──────┘  └──────┘  └──────────────┘  │
//! │                   ↓ composite()                    │
//! │  ┌─────────────────────────────────────────────┐  │
//! │  │          GpuFramebuffer (shadow buf)         │  │
//! │  └─────────────────────────────────────────────┘  │
//! └────────────────────────────────────────────────────┘
//! ```
//!
//! Each `Layer` corresponds to one window (or the desktop background).
//! Layers are sorted by `z_order` and painted back-to-front into a shadow
//! buffer, then flushed to the physical framebuffer via `swap_buffers()`.
//!
//! ## Pixel format
//!
//! All layer pixel buffers use **ARGB8888** (32 bits per pixel, high byte =
//! alpha). The compositor alpha-blends layers: `alpha = 255` is fully opaque,
//! `alpha = 0` is fully transparent.
//!
//! ## Thread safety
//!
//! The global `COMPOSITOR` is wrapped in a `Mutex`.  WASM host functions and
//! kernel subsystems access it via `compositor()`.
//!
//! ## WASM host functions
//!
//! | ID | Name                          | Signature                              |
//! |----|-------------------------------|----------------------------------------|
//! | 28 | `compositor_create_window`    | `(x,y,w,h: i32) -> i32` (window_id)   |
//! | 29 | `compositor_destroy_window`   | `(window_id: i32) -> i32`              |
//! | 30 | `compositor_set_pixel`        | `(wid,x,y,argb: i32) -> ()`            |
//! | 31 | `compositor_fill_rect`        | `(wid,x,y,w,h,argb: i32) -> ()`        |
//! | 32 | `compositor_flush`            | `(wid: i32) -> ()`                     |
//! | 33 | `compositor_move_window`      | `(wid,x,y: i32) -> ()`                 |
//! | 34 | `compositor_set_z_order`      | `(wid,z: i32) -> ()`                   |
//! | 35 | `compositor_get_width`        | `(wid: i32) -> i32`                    |
//! | 36 | `compositor_get_height`       | `(wid: i32) -> i32`                    |
//! | 37 | `compositor_draw_text`        | `(wid,x,y,ptr,len,argb: i32) -> i32`  |

#![allow(dead_code)]

use spin::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously open windows.
pub const MAX_LAYERS: usize = 16;

/// Maximum width of a single window in pixels.
pub const MAX_WINDOW_WIDTH: u32 = 1920;

/// Maximum height of a single window in pixels.
pub const MAX_WINDOW_HEIGHT: u32 = 1080;

/// Maximum total pixels in a single window's pixel buffer.
/// This is only used as a cap — actual allocation is dynamic via the JIT arena.
pub const MAX_WINDOW_PIXELS: usize = 1024 * 768;

/// Opaque background colour (black by default).
pub const BACKGROUND_ARGB: u32 = 0xFF00_0000;

/// Default foreground text colour (white).
pub const TEXT_FG_ARGB: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Pixel buffer storage
// ---------------------------------------------------------------------------
//
// Each window's pixel buffer is dynamically allocated from the kernel JIT
// arena so that the compositor's static footprint is minimal.  A slot table
// records which buffer pages are in use.

/// Bytes per pixel (ARGB8888).
const BPP: usize = 4;

/// Metadata for one allocated pixel buffer.
#[derive(Clone, Copy)]
struct PixelBufMeta {
    /// Base pointer to ARGB pixels (JIT arena page-aligned).
    ptr: *mut u32,
    /// Number of 4096-byte pages allocated.
    pages: usize,
    /// Whether this slot is in use.
    claimed: bool,
}

impl PixelBufMeta {
    const fn empty() -> Self {
        PixelBufMeta {
            ptr: core::ptr::null_mut(),
            pages: 0,
            claimed: false,
        }
    }
}

// SAFETY: access is serialised by PIXEL_POOL Mutex.
unsafe impl Send for PixelBufMeta {}

struct PixelBufPool {
    slots: [PixelBufMeta; MAX_LAYERS],
}

impl PixelBufPool {
    const fn new() -> Self {
        const EMPTY_SLOT: PixelBufMeta = PixelBufMeta::empty();
        PixelBufPool {
            slots: [EMPTY_SLOT; MAX_LAYERS],
        }
    }

    /// Allocate pixel storage for `w × h` pixels.  Returns slot index or None.
    fn claim(&mut self, w: u32, h: u32) -> Option<usize> {
        let pixels = (w as usize).saturating_mul(h as usize);
        let bytes = pixels.saturating_mul(BPP);
        let page_size = crate::fs::paging::PAGE_SIZE;
        let pages = (bytes + page_size - 1) / page_size;

        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.claimed {
                continue;
            }
            // Try to reuse existing allocation if it's large enough.
            let needs_alloc = slot.ptr.is_null() || slot.pages < pages;
            if needs_alloc {
                // Release old allocation if any.
                if !slot.ptr.is_null() && slot.pages > 0 {
                    // JIT arena is bump-allocated; we cannot free individual
                    // pages, but we zero the region and mark unclaimed.
                    unsafe {
                        core::ptr::write_bytes(slot.ptr as *mut u8, 0, slot.pages * page_size);
                    }
                }
                let base = crate::memory::jit_allocate_pages(pages).unwrap_or(0) as *mut u32;
                if base.is_null() {
                    return None;
                }
                unsafe {
                    core::ptr::write_bytes(base as *mut u8, 0, pages * page_size);
                }
                slot.ptr = base;
                slot.pages = pages;
            } else {
                // Zero the reused buffer.
                unsafe {
                    core::ptr::write_bytes(slot.ptr as *mut u8, 0, slot.pages * page_size);
                }
            }
            slot.claimed = true;
            return Some(i);
        }
        None
    }

    /// Release a slot (mark unclaimed; memory stays allocated for reuse).
    fn release(&mut self, idx: usize) {
        if idx < MAX_LAYERS {
            self.slots[idx].claimed = false;
        }
    }

    /// Get a pixel from slot `idx` at (x, y) with row stride `w`.
    fn get_pixel(&self, idx: usize, x: u32, y: u32, w: u32) -> u32 {
        if idx >= MAX_LAYERS {
            return 0;
        }
        let slot = &self.slots[idx];
        if slot.ptr.is_null() {
            return 0;
        }
        let offset = (y as usize)
            .wrapping_mul(w as usize)
            .wrapping_add(x as usize);
        let max_pixels = slot.pages * crate::fs::paging::PAGE_SIZE / BPP;
        if offset >= max_pixels {
            return 0;
        }
        unsafe { *slot.ptr.add(offset) }
    }

    /// Set a pixel in slot `idx` at (x, y) with row stride `w`.
    fn set_pixel(&mut self, idx: usize, x: u32, y: u32, w: u32, argb: u32) {
        if idx >= MAX_LAYERS {
            return;
        }
        let slot = &mut self.slots[idx];
        if slot.ptr.is_null() {
            return;
        }
        let offset = (y as usize)
            .wrapping_mul(w as usize)
            .wrapping_add(x as usize);
        let max_pixels = slot.pages * crate::fs::paging::PAGE_SIZE / BPP;
        if offset < max_pixels {
            unsafe {
                *slot.ptr.add(offset) = argb;
            }
        }
    }
}

/// Global pixel buffer pool — allocations come from the kernel JIT arena.
static PIXEL_POOL: Mutex<PixelBufPool> = Mutex::new(PixelBufPool::new());

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

/// A composited window layer.
#[derive(Clone, Copy, Debug)]
pub struct Layer {
    /// Unique window ID (never 0 for a live layer).
    pub window_id: u32,
    /// Top-left corner of the window on the desktop.
    pub x: i32,
    pub y: i32,
    /// Window dimensions in pixels.
    pub width: u32,
    pub height: u32,
    /// Paint order (0 = bottom/background, 255 = topmost).
    pub z_order: u8,
    /// Whether this layer has unsaved changes since last composite.
    pub dirty: bool,
    /// Index into the `PixelBufPool`.
    pixel_buf_idx: usize,
    /// Whether this layer is in use.
    pub alive: bool,
}

impl Layer {
    fn new(window_id: u32, x: i32, y: i32, w: u32, h: u32, z: u8, buf_idx: usize) -> Self {
        Layer {
            window_id,
            x,
            y,
            width: w,
            height: h,
            z_order: z,
            dirty: true,
            pixel_buf_idx: buf_idx,
            alive: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Alpha blend helper
// ---------------------------------------------------------------------------

/// Alpha-blend `src` (ARGB) over `dst` (ARGB) using the source alpha channel.
#[inline]
fn alpha_blend(dst: u32, src: u32) -> u32 {
    let sa = (src >> 24) & 0xFF;
    if sa == 0xFF {
        return src; // fast path: fully opaque
    }
    if sa == 0x00 {
        return dst; // fast path: fully transparent
    }
    let sr = (src >> 16) & 0xFF;
    let sg = (src >> 8) & 0xFF;
    let sb = src & 0xFF;
    let dr = (dst >> 16) & 0xFF;
    let dg = (dst >> 8) & 0xFF;
    let db = dst & 0xFF;
    let inv_sa = 255 - sa;
    let r = ((sr * sa + dr * inv_sa) / 255) & 0xFF;
    let g = ((sg * sa + dg * inv_sa) / 255) & 0xFF;
    let b = ((sb * sa + db * inv_sa) / 255) & 0xFF;
    0xFF00_0000 | (r << 16) | (g << 8) | b
}

// ---------------------------------------------------------------------------
// Compositor
// ---------------------------------------------------------------------------

/// The Oreulius compositor / window manager.
pub struct Compositor {
    /// The layer table (up to `MAX_LAYERS` entries).
    layers: [Option<Layer>; MAX_LAYERS],
    /// Whether any layer has been modified since the last full composite.
    pub dirty: bool,
    /// Monotonic window ID counter.
    next_window_id: u32,
    /// Sort scratch buffer (layer indices sorted by z_order).
    sort_buf: [usize; MAX_LAYERS],
    sort_len: usize,
    /// Desktop resolution (set from the framebuffer on init).
    pub screen_width: u32,
    pub screen_height: u32,
}

impl Compositor {
    pub const fn new() -> Self {
        Compositor {
            layers: [None; MAX_LAYERS],
            dirty: false,
            next_window_id: 1,
            sort_buf: [0usize; MAX_LAYERS],
            sort_len: 0,
            screen_width: 1024,
            screen_height: 768,
        }
    }

    /// Initialise or update the desktop resolution.
    pub fn set_resolution(&mut self, w: u32, h: u32) {
        self.screen_width = w;
        self.screen_height = h;
    }

    // -----------------------------------------------------------------------
    // Window lifecycle
    // -----------------------------------------------------------------------

    /// Create a new window layer.  Returns the window ID, or 0 on failure.
    pub fn create_window(&mut self, x: i32, y: i32, w: u32, h: u32) -> u32 {
        if w == 0 || h == 0 || w > MAX_WINDOW_WIDTH || h > MAX_WINDOW_HEIGHT {
            return 0;
        }
        // Claim a pixel buffer.
        let buf_idx = match PIXEL_POOL.lock().claim(w, h) {
            Some(i) => i,
            None => return 0,
        };
        // Find an empty layer slot.
        let slot = match self.layers.iter().position(|l| l.is_none()) {
            Some(i) => i,
            None => {
                PIXEL_POOL.lock().release(buf_idx);
                return 0;
            }
        };
        let wid = self.next_window_id;
        self.next_window_id = self.next_window_id.wrapping_add(1);
        if self.next_window_id == 0 {
            self.next_window_id = 1;
        }
        let z = slot as u8; // default z = slot index
        self.layers[slot] = Some(Layer::new(wid, x, y, w, h, z, buf_idx));
        self.dirty = true;
        wid
    }

    /// Destroy a window.  Returns true if found.
    pub fn destroy_window(&mut self, window_id: u32) -> bool {
        for slot in self.layers.iter_mut() {
            if let Some(ref layer) = *slot {
                if layer.window_id == window_id {
                    let buf_idx = layer.pixel_buf_idx;
                    PIXEL_POOL.lock().release(buf_idx);
                    *slot = None;
                    self.dirty = true;
                    return true;
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Pixel operations
    // -----------------------------------------------------------------------

    /// Set a single pixel in a window.
    pub fn set_pixel(&mut self, window_id: u32, x: u32, y: u32, argb: u32) {
        if let Some(layer) = self.find_layer_mut(window_id) {
            if x < layer.width && y < layer.height {
                let w = layer.width;
                let buf_idx = layer.pixel_buf_idx;
                layer.dirty = true;
                PIXEL_POOL.lock().set_pixel(buf_idx, x, y, w, argb);
                self.dirty = true;
            }
        }
    }

    /// Fill a rectangle in a window with a solid colour.
    pub fn fill_rect(&mut self, window_id: u32, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        if let Some(layer) = self.find_layer_mut(window_id) {
            let lw = layer.width;
            let lh = layer.height;
            let buf_idx = layer.pixel_buf_idx;
            let x1 = x.min(lw);
            let y1 = y.min(lh);
            let x2 = (x.saturating_add(w)).min(lw);
            let y2 = (y.saturating_add(h)).min(lh);
            layer.dirty = true;
            let mut pool = PIXEL_POOL.lock();
            for py in y1..y2 {
                for px in x1..x2 {
                    pool.set_pixel(buf_idx, px, py, lw, argb);
                }
            }
            self.dirty = true;
        }
    }

    /// Draw an ARGB row slice from a source buffer into a window at (x, y).
    /// `src` must be exactly `w` u32 values wide.
    pub fn blit_row(&mut self, window_id: u32, x: u32, y: u32, src: &[u32]) {
        if let Some(layer) = self.find_layer_mut(window_id) {
            if y >= layer.height {
                return;
            }
            let lw = layer.width;
            let buf_idx = layer.pixel_buf_idx;
            let copy_w = (src.len() as u32).min(lw.saturating_sub(x));
            layer.dirty = true;
            let mut pool = PIXEL_POOL.lock();
            for i in 0..copy_w as usize {
                pool.set_pixel(buf_idx, x + i as u32, y, lw, src[i]);
            }
            self.dirty = true;
        }
    }

    /// Draw text into a window using the built-in 8×8 bitmap font.
    /// Returns the number of characters drawn.
    pub fn draw_text(&mut self, window_id: u32, x: u32, y: u32, text: &str, fg_argb: u32) -> u32 {
        let (lw, lh, buf_idx) = match self.find_layer_ref(window_id) {
            Some(l) => (l.width, l.height, l.pixel_buf_idx),
            None => return 0,
        };
        let mut drawn = 0u32;
        let mut cx = x;
        let mut pool = PIXEL_POOL.lock();
        for ch in text.chars() {
            if cx + 8 > lw {
                break;
            }
            let glyph = FONT_8X8.get_glyph(ch);
            for row in 0..8u32 {
                if y + row >= lh {
                    break;
                }
                let bits = glyph[row as usize];
                for col in 0u32..8 {
                    if bits & (0x80 >> col) != 0 {
                        pool.set_pixel(buf_idx, cx + col, y + row, lw, fg_argb);
                    }
                }
            }
            cx += 8;
            drawn += 1;
        }
        // Mark dirty.
        if let Some(layer) = self.find_layer_mut(window_id) {
            layer.dirty = true;
        }
        self.dirty = true;
        drawn
    }

    // -----------------------------------------------------------------------
    // Window management
    // -----------------------------------------------------------------------

    /// Move a window to a new position.
    pub fn move_window(&mut self, window_id: u32, x: i32, y: i32) {
        if let Some(layer) = self.find_layer_mut(window_id) {
            layer.x = x;
            layer.y = y;
            layer.dirty = true;
            self.dirty = true;
        }
    }

    /// Set a window's paint order (z_order).
    pub fn set_z_order(&mut self, window_id: u32, z: u8) {
        if let Some(layer) = self.find_layer_mut(window_id) {
            layer.z_order = z;
            layer.dirty = true;
            self.dirty = true;
        }
    }

    /// Return the dimensions of a window.
    pub fn window_size(&self, window_id: u32) -> Option<(u32, u32)> {
        self.find_layer_ref(window_id).map(|l| (l.width, l.height))
    }

    /// Raise a window to the top (gives it z_order = 255, others unchanged).
    pub fn raise_window(&mut self, window_id: u32) {
        self.set_z_order(window_id, 255);
    }

    /// Lower a window to the bottom.
    pub fn lower_window(&mut self, window_id: u32) {
        self.set_z_order(window_id, 0);
    }

    // -----------------------------------------------------------------------
    // Compositing
    // -----------------------------------------------------------------------

    /// Paint all dirty layers into the framebuffer.
    ///
    /// If `force` is false, this is a no-op when no layer has changed.
    pub fn composite(&mut self, fb: &crate::drivers::x86::gpu_support::GpuFramebuffer, force: bool) {
        if !self.dirty && !force {
            return;
        }
        // Build the sorted draw order (insertion sort — MAX_LAYERS ≤ 16).
        self.rebuild_sort_buf();

        let sw = self.screen_width;
        let sh = self.screen_height;

        // Paint each scanline.
        for py in 0..sh {
            for px in 0..sw {
                let mut pixel: u32 = BACKGROUND_ARGB;
                // Iterate layers from bottom to top.
                let pool = PIXEL_POOL.lock();
                for &slot_idx in &self.sort_buf[..self.sort_len] {
                    if let Some(ref layer) = self.layers[slot_idx] {
                        // Transform screen coord → layer-local coord.
                        let lx = px as i32 - layer.x;
                        let ly = py as i32 - layer.y;
                        if lx < 0 || ly < 0 {
                            continue;
                        }
                        let lx = lx as u32;
                        let ly = ly as u32;
                        if lx >= layer.width || ly >= layer.height {
                            continue;
                        }
                        let src = pool.get_pixel(layer.pixel_buf_idx, lx, ly, layer.width);
                        pixel = alpha_blend(pixel, src);
                    }
                }
                drop(pool);
                // Write to framebuffer.
                let r = ((pixel >> 16) & 0xFF) as u8;
                let g = ((pixel >> 8) & 0xFF) as u8;
                let b = (pixel & 0xFF) as u8;
                fb.put_pixel(px, py, r, g, b);
            }
        }

        // Mark all layers clean.
        for slot in self.layers.iter_mut().flatten() {
            slot.dirty = false;
        }
        self.dirty = false;
    }

    /// Composite only the dirty region of a single window (fast path).
    pub fn flush_window(&mut self, window_id: u32, fb: &crate::drivers::x86::gpu_support::GpuFramebuffer) {
        let (wx, wy, ww, wh, buf_idx) = match self.find_layer_ref(window_id) {
            Some(l) if l.dirty => (l.x, l.y, l.width, l.height, l.pixel_buf_idx),
            _ => return,
        };

        let sw = self.screen_width as i32;
        let sh = self.screen_height as i32;

        let x0 = wx.max(0) as u32;
        let y0 = wy.max(0) as u32;
        let x1 = ((wx + ww as i32).min(sw)) as u32;
        let y1 = ((wy + wh as i32).min(sh)) as u32;

        let pool = PIXEL_POOL.lock();
        for py in y0..y1 {
            for px in x0..x1 {
                let lx = (px as i32 - wx) as u32;
                let ly = (py as i32 - wy) as u32;
                let argb = pool.get_pixel(buf_idx, lx, ly, ww);
                let r = ((argb >> 16) & 0xFF) as u8;
                let g = ((argb >> 8) & 0xFF) as u8;
                let b = (argb & 0xFF) as u8;
                fb.put_pixel(px, py, r, g, b);
            }
        }
        drop(pool);

        if let Some(layer) = self.find_layer_mut(window_id) {
            layer.dirty = false;
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_layer_mut(&mut self, window_id: u32) -> Option<&mut Layer> {
        for slot in self.layers.iter_mut() {
            if let Some(ref mut layer) = slot {
                if layer.window_id == window_id {
                    return Some(layer);
                }
            }
        }
        None
    }

    fn find_layer_ref(&self, window_id: u32) -> Option<&Layer> {
        for slot in &self.layers {
            if let Some(ref layer) = slot {
                if layer.window_id == window_id {
                    return Some(layer);
                }
            }
        }
        None
    }

    /// Rebuild the sorted draw-order buffer (insertion sort by z_order).
    fn rebuild_sort_buf(&mut self) {
        self.sort_len = 0;
        for (i, slot) in self.layers.iter().enumerate() {
            if slot.is_some() {
                self.sort_buf[self.sort_len] = i;
                self.sort_len += 1;
            }
        }
        // Insertion sort by z_order (ascending = bottom first).
        let sb = &mut self.sort_buf[..self.sort_len];
        let layers = &self.layers;
        for i in 1..sb.len() {
            let key = sb[i];
            let key_z = layers[key].as_ref().map(|l| l.z_order).unwrap_or(0);
            let mut j = i;
            while j > 0 {
                let prev_z = layers[sb[j - 1]].as_ref().map(|l| l.z_order).unwrap_or(0);
                if prev_z <= key_z {
                    break;
                }
                sb[j] = sb[j - 1];
                j -= 1;
            }
            sb[j] = key;
        }
    }

    /// Return the window ID at screen position (px, py), or 0 if none.
    /// Hits the topmost (highest z_order) window that contains the point.
    pub fn hit_test(&self, px: i32, py: i32) -> u32 {
        // Walk sorted buf in reverse (topmost first).
        let mut best_wid = 0u32;
        let mut best_z = 0i32;
        for slot in &self.layers {
            if let Some(ref layer) = slot {
                let lx = px - layer.x;
                let ly = py - layer.y;
                if lx >= 0 && ly >= 0 && (lx as u32) < layer.width && (ly as u32) < layer.height {
                    if layer.z_order as i32 >= best_z {
                        best_z = layer.z_order as i32;
                        best_wid = layer.window_id;
                    }
                }
            }
        }
        best_wid
    }

    /// Return a snapshot list of all live windows for the task bar.
    pub fn list_windows(&self, out: &mut [(u32, i32, i32, u32, u32)]) -> usize {
        let mut n = 0;
        for slot in &self.layers {
            if let Some(ref l) = slot {
                if n >= out.len() {
                    break;
                }
                out[n] = (l.window_id, l.x, l.y, l.width, l.height);
                n += 1;
            }
        }
        n
    }

    /// Total number of live windows.
    pub fn window_count(&self) -> usize {
        self.layers.iter().filter(|l| l.is_some()).count()
    }
}

// ---------------------------------------------------------------------------
// Global compositor instance
// ---------------------------------------------------------------------------

pub static COMPOSITOR: Mutex<Compositor> = Mutex::new(Compositor::new());

/// Access the global compositor.
pub fn compositor() -> spin::MutexGuard<'static, Compositor> {
    COMPOSITOR.lock()
}

/// Initialise the compositor with the current framebuffer resolution.
/// Call this once after `gpu_support::init()`.
pub fn init(w: u32, h: u32) {
    let mut comp = COMPOSITOR.lock();
    comp.set_resolution(w, h);
    crate::serial_println!("[COMPOSITOR] Initialised {}×{}", w, h);
}

// ---------------------------------------------------------------------------
// 8×8 Bitmap Font
// ---------------------------------------------------------------------------
//
// A minimal built-in bitmap font covering printable ASCII (0x20–0x7E).
// Each character is an 8-byte array: one byte per scanline, MSB = leftmost
// pixel.  Based on the classic IBM PC Code Page 437 8×8 font.

struct Font8x8;

impl Font8x8 {
    /// Return the 8-row glyph bitmap for a character.  Falls back to a
    /// default block glyph for characters outside the supported range.
    fn get_glyph(&self, ch: char) -> [u8; 8] {
        let idx = ch as usize;
        if idx >= 0x20 && idx <= 0x7E {
            FONT_DATA[idx - 0x20]
        } else {
            // Unknown: solid 6×6 box
            [0x00, 0x7E, 0x42, 0x42, 0x42, 0x7E, 0x00, 0x00]
        }
    }
}

const FONT_8X8: Font8x8 = Font8x8;

// ---------------------------------------------------------------------------
// Font data (printable ASCII 0x20–0x7E)
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const FONT_DATA: [[u8; 8]; 95] = [
    // 0x20 ' '
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x21 '!'
    [0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00],
    // 0x22 '"'
    [0x6C,0x6C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x23 '#'
    [0x6C,0x6C,0xFE,0x6C,0xFE,0x6C,0x6C,0x00],
    // 0x24 '$'
    [0x18,0x7E,0xC0,0x7C,0x06,0xFC,0x18,0x00],
    // 0x25 '%'
    [0x00,0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00],
    // 0x26 '&'
    [0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00],
    // 0x27 '\''
    [0x30,0x30,0x60,0x00,0x00,0x00,0x00,0x00],
    // 0x28 '('
    [0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00],
    // 0x29 ')'
    [0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00],
    // 0x2A '*'
    [0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00],
    // 0x2B '+'
    [0x00,0x30,0x30,0xFC,0x30,0x30,0x00,0x00],
    // 0x2C ','
    [0x00,0x00,0x00,0x00,0x00,0x30,0x30,0x60],
    // 0x2D '-'
    [0x00,0x00,0x00,0xFC,0x00,0x00,0x00,0x00],
    // 0x2E '.'
    [0x00,0x00,0x00,0x00,0x00,0x30,0x30,0x00],
    // 0x2F '/'
    [0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00],
    // 0x30 '0'
    [0x7C,0xC6,0xCE,0xDE,0xF6,0xE6,0x7C,0x00],
    // 0x31 '1'
    [0x30,0x70,0x30,0x30,0x30,0x30,0xFC,0x00],
    // 0x32 '2'
    [0x78,0xCC,0x0C,0x38,0x60,0xCC,0xFC,0x00],
    // 0x33 '3'
    [0x78,0xCC,0x0C,0x38,0x0C,0xCC,0x78,0x00],
    // 0x34 '4'
    [0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00],
    // 0x35 '5'
    [0xFC,0xC0,0xF8,0x0C,0x0C,0xCC,0x78,0x00],
    // 0x36 '6'
    [0x38,0x60,0xC0,0xF8,0xCC,0xCC,0x78,0x00],
    // 0x37 '7'
    [0xFC,0xCC,0x0C,0x18,0x30,0x30,0x30,0x00],
    // 0x38 '8'
    [0x78,0xCC,0xCC,0x78,0xCC,0xCC,0x78,0x00],
    // 0x39 '9'
    [0x78,0xCC,0xCC,0x7C,0x0C,0x18,0x70,0x00],
    // 0x3A ':'
    [0x00,0x30,0x30,0x00,0x00,0x30,0x30,0x00],
    // 0x3B ';'
    [0x00,0x30,0x30,0x00,0x00,0x30,0x30,0x60],
    // 0x3C '<'
    [0x18,0x30,0x60,0xC0,0x60,0x30,0x18,0x00],
    // 0x3D '='
    [0x00,0x00,0xFC,0x00,0x00,0xFC,0x00,0x00],
    // 0x3E '>'
    [0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00],
    // 0x3F '?'
    [0x78,0xCC,0x0C,0x18,0x30,0x00,0x30,0x00],
    // 0x40 '@'
    [0x7C,0xC6,0xDE,0xDE,0xDE,0xC0,0x78,0x00],
    // 0x41 'A'
    [0x30,0x78,0xCC,0xCC,0xFC,0xCC,0xCC,0x00],
    // 0x42 'B'
    [0xFC,0x66,0x66,0x7C,0x66,0x66,0xFC,0x00],
    // 0x43 'C'
    [0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00],
    // 0x44 'D'
    [0xF8,0x6C,0x66,0x66,0x66,0x6C,0xF8,0x00],
    // 0x45 'E'
    [0xFE,0x62,0x68,0x78,0x68,0x62,0xFE,0x00],
    // 0x46 'F'
    [0xFE,0x62,0x68,0x78,0x68,0x60,0xF0,0x00],
    // 0x47 'G'
    [0x3C,0x66,0xC0,0xC0,0xCE,0x66,0x3A,0x00],
    // 0x48 'H'
    [0xCC,0xCC,0xCC,0xFC,0xCC,0xCC,0xCC,0x00],
    // 0x49 'I'
    [0x78,0x30,0x30,0x30,0x30,0x30,0x78,0x00],
    // 0x4A 'J'
    [0x1E,0x0C,0x0C,0x0C,0xCC,0xCC,0x78,0x00],
    // 0x4B 'K'
    [0xE6,0x66,0x6C,0x78,0x6C,0x66,0xE6,0x00],
    // 0x4C 'L'
    [0xF0,0x60,0x60,0x60,0x62,0x66,0xFE,0x00],
    // 0x4D 'M'
    [0xC6,0xEE,0xFE,0xFE,0xD6,0xC6,0xC6,0x00],
    // 0x4E 'N'
    [0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00],
    // 0x4F 'O'
    [0x38,0x6C,0xC6,0xC6,0xC6,0x6C,0x38,0x00],
    // 0x50 'P'
    [0xFC,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00],
    // 0x51 'Q'
    [0x78,0xCC,0xCC,0xCC,0xDC,0x78,0x1C,0x00],
    // 0x52 'R'
    [0xFC,0x66,0x66,0x7C,0x6C,0x66,0xE6,0x00],
    // 0x53 'S'
    [0x78,0xCC,0xE0,0x78,0x1C,0xCC,0x78,0x00],
    // 0x54 'T'
    [0xFC,0xB4,0x30,0x30,0x30,0x30,0x78,0x00],
    // 0x55 'U'
    [0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xFC,0x00],
    // 0x56 'V'
    [0xCC,0xCC,0xCC,0xCC,0xCC,0x78,0x30,0x00],
    // 0x57 'W'
    [0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00],
    // 0x58 'X'
    [0xC6,0xC6,0x6C,0x38,0x38,0x6C,0xC6,0x00],
    // 0x59 'Y'
    [0xCC,0xCC,0xCC,0x78,0x30,0x30,0x78,0x00],
    // 0x5A 'Z'
    [0xFE,0xC6,0x8C,0x18,0x32,0x66,0xFE,0x00],
    // 0x5B '['
    [0x78,0x60,0x60,0x60,0x60,0x60,0x78,0x00],
    // 0x5C '\\'
    [0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00],
    // 0x5D ']'
    [0x78,0x18,0x18,0x18,0x18,0x18,0x78,0x00],
    // 0x5E '^'
    [0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00],
    // 0x5F '_'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF],
    // 0x60 '`'
    [0x30,0x30,0x18,0x00,0x00,0x00,0x00,0x00],
    // 0x61 'a'
    [0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00],
    // 0x62 'b'
    [0xE0,0x60,0x60,0x7C,0x66,0x66,0xDC,0x00],
    // 0x63 'c'
    [0x00,0x00,0x78,0xCC,0xC0,0xCC,0x78,0x00],
    // 0x64 'd'
    [0x1C,0x0C,0x0C,0x7C,0xCC,0xCC,0x76,0x00],
    // 0x65 'e'
    [0x00,0x00,0x78,0xCC,0xFC,0xC0,0x78,0x00],
    // 0x66 'f'
    [0x38,0x6C,0x60,0xF0,0x60,0x60,0xF0,0x00],
    // 0x67 'g'
    [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0xF8],
    // 0x68 'h'
    [0xE0,0x60,0x6C,0x76,0x66,0x66,0xE6,0x00],
    // 0x69 'i'
    [0x30,0x00,0x70,0x30,0x30,0x30,0x78,0x00],
    // 0x6A 'j'
    [0x0C,0x00,0x0C,0x0C,0x0C,0xCC,0xCC,0x78],
    // 0x6B 'k'
    [0xE0,0x60,0x66,0x6C,0x78,0x6C,0xE6,0x00],
    // 0x6C 'l'
    [0x70,0x30,0x30,0x30,0x30,0x30,0x78,0x00],
    // 0x6D 'm'
    [0x00,0x00,0xCC,0xFE,0xFE,0xD6,0xC6,0x00],
    // 0x6E 'n'
    [0x00,0x00,0xF8,0xCC,0xCC,0xCC,0xCC,0x00],
    // 0x6F 'o'
    [0x00,0x00,0x78,0xCC,0xCC,0xCC,0x78,0x00],
    // 0x70 'p'
    [0x00,0x00,0xDC,0x66,0x66,0x7C,0x60,0xF0],
    // 0x71 'q'
    [0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E],
    // 0x72 'r'
    [0x00,0x00,0xDC,0x76,0x66,0x60,0xF0,0x00],
    // 0x73 's'
    [0x00,0x00,0x7C,0xC0,0x78,0x0C,0xF8,0x00],
    // 0x74 't'
    [0x10,0x30,0x7C,0x30,0x30,0x34,0x18,0x00],
    // 0x75 'u'
    [0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00],
    // 0x76 'v'
    [0x00,0x00,0xCC,0xCC,0xCC,0x78,0x30,0x00],
    // 0x77 'w'
    [0x00,0x00,0xC6,0xD6,0xFE,0xFE,0x6C,0x00],
    // 0x78 'x'
    [0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00],
    // 0x79 'y'
    [0x00,0x00,0xCC,0xCC,0xCC,0x7C,0x0C,0xF8],
    // 0x7A 'z'
    [0x00,0x00,0xFC,0x98,0x30,0x64,0xFC,0x00],
    // 0x7B '{'
    [0x1C,0x30,0x30,0xE0,0x30,0x30,0x1C,0x00],
    // 0x7C '|'
    [0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00],
    // 0x7D '}'
    [0xE0,0x30,0x30,0x1C,0x30,0x30,0xE0,0x00],
    // 0x7E '~'
    [0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00],
];
