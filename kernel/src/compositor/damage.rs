//! Damage accumulator for the compositor.
//!
//! Tracks which regions of the screen have changed since the last present.
//! The compositor adds a window's bounding box to the accumulator whenever
//! it receives a `CommitSurface` request or when a window moves/resizes.
//! At present time the union of all dirty rectangles is flushed to the
//! display backend.

#![allow(dead_code)]

/// Maximum number of individual damage rectangles we track before falling
/// back to a single full-screen bounding box.
pub const MAX_DAMAGE_RECTS: usize = 32;

/// An axis-aligned dirty rectangle in screen coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DamageRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl DamageRect {
    pub const fn new(x: u32, y: u32, w: u32, h: u32) -> Self {
        DamageRect { x, y, w, h }
    }

    /// Return the bounding-box union of two rectangles.
    pub fn union(self, other: DamageRect) -> DamageRect {
        let x1 = self.x.min(other.x);
        let y1 = self.y.min(other.y);
        let x2 = (self.x + self.w).max(other.x + other.w);
        let y2 = (self.y + self.h).max(other.y + other.h);
        DamageRect {
            x: x1,
            y: y1,
            w: x2.saturating_sub(x1),
            h: y2.saturating_sub(y1),
        }
    }

    /// True if the rectangle covers zero area.
    pub fn is_empty(&self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Clip to screen bounds (width × height).
    pub fn clip_to(self, screen_w: u32, screen_h: u32) -> DamageRect {
        let x = self.x.min(screen_w);
        let y = self.y.min(screen_h);
        let w = (self.w).min(screen_w.saturating_sub(x));
        let h = (self.h).min(screen_h.saturating_sub(y));
        DamageRect { x, y, w, h }
    }
}

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

pub struct DamageAccumulator {
    rects: [DamageRect; MAX_DAMAGE_RECTS],
    count: usize,
    /// When the individual-rect array overflows we merge everything into a
    /// single full-screen bounding box to avoid missing damage.
    overflowed: bool,
    screen_w: u32,
    screen_h: u32,
}

impl DamageAccumulator {
    pub const fn new(screen_w: u32, screen_h: u32) -> Self {
        DamageAccumulator {
            rects: [DamageRect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            }; MAX_DAMAGE_RECTS],
            count: 0,
            overflowed: false,
            screen_w,
            screen_h,
        }
    }

    /// Add a damage rectangle.
    pub fn add(&mut self, rect: DamageRect) {
        if rect.is_empty() {
            return;
        }
        if self.overflowed {
            return; // full-screen damage already pending
        }
        // Check whether the new rect is already covered by an existing one
        // (cheap early-out to avoid growing the list unnecessarily).
        for existing in &self.rects[..self.count] {
            if rect.x >= existing.x
                && rect.y >= existing.y
                && rect.x + rect.w <= existing.x + existing.w
                && rect.y + rect.h <= existing.y + existing.h
            {
                return; // already covered
            }
        }
        if self.count < MAX_DAMAGE_RECTS {
            self.rects[self.count] = rect;
            self.count += 1;
        } else {
            self.overflowed = true;
        }
    }

    /// Add damage for the full bounding box of a screen region.
    pub fn add_region(&mut self, x: i32, y: i32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let cx = (x.max(0)) as u32;
        let cy = (y.max(0)) as u32;
        let rect = DamageRect::new(cx, cy, w, h).clip_to(self.screen_w, self.screen_h);
        self.add(rect);
    }

    /// True if there is any pending damage.
    pub fn is_dirty(&self) -> bool {
        self.overflowed || self.count > 0
    }

    /// Compute the single bounding-box union over all damage rects.
    /// Returns None if there is no damage.
    pub fn bounding_box(&self) -> Option<DamageRect> {
        if self.overflowed {
            // Full screen.
            return Some(DamageRect::new(0, 0, self.screen_w, self.screen_h));
        }
        if self.count == 0 {
            return None;
        }
        let mut bb = self.rects[0];
        for r in &self.rects[1..self.count] {
            bb = bb.union(*r);
        }
        Some(bb)
    }

    /// Iterate all damage rects (including full-screen fallback when overflowed).
    pub fn rects(&self) -> DamageIter<'_> {
        if self.overflowed {
            DamageIter::FullScreen {
                rect: DamageRect::new(0, 0, self.screen_w, self.screen_h),
                done: false,
            }
        } else {
            DamageIter::Rects {
                slice: &self.rects[..self.count],
                pos: 0,
            }
        }
    }

    /// Clear all damage (call after present).
    pub fn clear(&mut self) {
        self.count = 0;
        self.overflowed = false;
    }

    /// Resize the screen (e.g. on mode change).
    pub fn set_screen_size(&mut self, w: u32, h: u32) {
        self.screen_w = w;
        self.screen_h = h;
        // After a resize everything must be redrawn.
        self.overflowed = true;
    }
}

// ---------------------------------------------------------------------------
// Iterator
// ---------------------------------------------------------------------------

pub enum DamageIter<'a> {
    Rects { slice: &'a [DamageRect], pos: usize },
    FullScreen { rect: DamageRect, done: bool },
}

impl<'a> Iterator for DamageIter<'a> {
    type Item = DamageRect;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            DamageIter::Rects { slice, pos } => {
                if *pos < slice.len() {
                    let r = slice[*pos];
                    *pos += 1;
                    Some(r)
                } else {
                    None
                }
            }
            DamageIter::FullScreen { rect, done } => {
                if *done {
                    None
                } else {
                    *done = true;
                    Some(*rect)
                }
            }
        }
    }
}
