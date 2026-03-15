//! Window metadata and z-ordered window table.
//!
//! A `WindowMeta` record stores position, size, z-order and the backing
//! surface index.  The `WindowTable` keeps an array of optional slots and
//! provides hit-testing and z-sorted iteration for the compositor.

#![allow(dead_code)]

use super::protocol::WindowId;

pub const MAX_WINDOWS: usize = 64;

/// Metadata for one on-screen window.
#[derive(Clone, Copy)]
pub struct WindowMeta {
    pub id: WindowId,
    /// Index into SessionTable of the owning session.
    pub session_idx: usize,
    /// Top-left position in screen coordinates.
    pub x: i32,
    pub y: i32,
    /// Dimensions in pixels.
    pub width: u32,
    pub height: u32,
    /// Painting order: higher = on top.
    pub z_order: i32,
    /// Index into SurfacePool for this window's pixel buffer.
    pub surface_idx: usize,
    /// True if the surface has uncommitted damage since last present.
    pub dirty: bool,
    /// Whether this slot is in use.
    pub alive: bool,
}

impl WindowMeta {
    pub const fn empty() -> Self {
        WindowMeta {
            id: WindowId(0),
            session_idx: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            z_order: 0,
            surface_idx: 0,
            dirty: false,
            alive: false,
        }
    }

    /// Axis-aligned bounding box test.
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && py >= self.y
            && px < self.x + self.width as i32
            && py < self.y + self.height as i32
    }
}

// ---------------------------------------------------------------------------
// Window table
// ---------------------------------------------------------------------------

pub struct WindowTable {
    slots: [Option<WindowMeta>; MAX_WINDOWS],
    /// Monotonic ID counter.
    next_id: u32,
}

impl WindowTable {
    pub const fn new() -> Self {
        WindowTable {
            slots: [None; MAX_WINDOWS],
            next_id: 1,
        }
    }

    /// Allocate a new window.  Returns the window ID on success.
    pub fn create(
        &mut self,
        session_idx: usize,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        surface_idx: usize,
    ) -> Option<WindowId> {
        let id = WindowId(self.next_id);
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(WindowMeta {
                    id,
                    session_idx,
                    x,
                    y,
                    width,
                    height,
                    z_order: 0,
                    surface_idx,
                    dirty: true,
                    alive: true,
                });
                self.next_id = self.next_id.wrapping_add(1).max(1);
                return Some(id);
            }
        }
        None
    }

    /// Destroy a window by ID, freeing its slot.
    pub fn destroy(&mut self, id: WindowId) -> bool {
        for slot in self.slots.iter_mut() {
            if matches!(slot, Some(w) if w.id == id) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Find a window by ID (immutable).
    pub fn find(&self, id: WindowId) -> Option<&WindowMeta> {
        self.slots.iter().find_map(|s| match s {
            Some(w) if w.id == id => Some(w),
            _ => None,
        })
    }

    /// Find a window by ID (mutable).
    pub fn find_mut(&mut self, id: WindowId) -> Option<&mut WindowMeta> {
        self.slots.iter_mut().find_map(|s| match s {
            Some(w) if w.id == id => Some(w),
            _ => None,
        })
    }

    /// Move a window to screen coordinates (x, y).
    pub fn move_to(&mut self, id: WindowId, x: i32, y: i32) -> bool {
        match self.find_mut(id) {
            Some(w) => {
                w.x = x;
                w.y = y;
                w.dirty = true;
                true
            }
            None => false,
        }
    }

    /// Resize a window.  The caller must allocate a new surface externally.
    pub fn resize(&mut self, id: WindowId, width: u32, height: u32, new_surface_idx: usize) -> bool {
        match self.find_mut(id) {
            Some(w) => {
                w.width = width;
                w.height = height;
                w.surface_idx = new_surface_idx;
                w.dirty = true;
                true
            }
            None => false,
        }
    }

    /// Set z-order for a window.
    pub fn set_z_order(&mut self, id: WindowId, z: i32) {
        if let Some(w) = self.find_mut(id) {
            w.z_order = z;
        }
    }

    /// Raise a window to the top (z-order above all others).
    pub fn raise(&mut self, id: WindowId) {
        let max_z = self
            .slots
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|w| w.z_order)
            .max()
            .unwrap_or(0);
        if let Some(w) = self.find_mut(id) {
            w.z_order = max_z + 1;
        }
    }

    /// Lower a window to the bottom (z-order below all others).
    pub fn lower(&mut self, id: WindowId) {
        let min_z = self
            .slots
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|w| w.z_order)
            .min()
            .unwrap_or(0);
        if let Some(w) = self.find_mut(id) {
            w.z_order = min_z - 1;
        }
    }

    /// Hit-test: return the top-most window at screen position (px, py).
    pub fn hit_test(&self, px: i32, py: i32) -> Option<WindowId> {
        let mut best: Option<(i32, WindowId)> = None;
        for slot in self.slots.iter().filter_map(|s| s.as_ref()) {
            if slot.contains(px, py) {
                let better = match best {
                    None => true,
                    Some((bz, _)) => slot.z_order > bz,
                };
                if better {
                    best = Some((slot.z_order, slot.id));
                }
            }
        }
        best.map(|(_, id)| id)
    }

    /// Fill `out` with window IDs sorted by z-order (bottom to top).
    /// Returns the number of windows written.
    pub fn sorted_ids(&self, out: &mut [WindowId]) -> usize {
        // Collect live windows.
        let mut buf = [WindowId(0); MAX_WINDOWS];
        let mut count = 0usize;
        for slot in self.slots.iter().filter_map(|s| s.as_ref()) {
            if count < MAX_WINDOWS {
                buf[count] = slot.id;
                count += 1;
            }
        }
        let live = &mut buf[..count];

        // Insertion-sort by z_order ascending (bottom first).
        for i in 1..live.len() {
            let key = live[i];
            let key_z = self.find(key).map(|w| w.z_order).unwrap_or(0);
            let mut j = i;
            while j > 0 {
                let cmp_z = self.find(live[j - 1]).map(|w| w.z_order).unwrap_or(0);
                if cmp_z > key_z {
                    live[j] = live[j - 1];
                    j -= 1;
                } else {
                    break;
                }
            }
            live[j] = key;
        }

        let n = count.min(out.len());
        out[..n].copy_from_slice(&live[..n]);
        n
    }

    /// Mark a window as dirty (has uncommitted damage).
    pub fn mark_dirty(&mut self, id: WindowId) {
        if let Some(w) = self.find_mut(id) {
            w.dirty = true;
        }
    }

    /// Returns true if any window has pending damage.
    pub fn any_dirty(&self) -> bool {
        self.slots.iter().filter_map(|s| s.as_ref()).any(|w| w.dirty)
    }

    /// Clear dirty flag on all windows (called after a full present).
    pub fn clear_dirty_all(&mut self) {
        for slot in self.slots.iter_mut().filter_map(|s| s.as_mut()) {
            slot.dirty = false;
        }
    }

    /// Return the number of windows owned by a session.
    pub fn count_for_session(&self, session_idx: usize) -> usize {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|w| w.session_idx == session_idx)
            .count()
    }
}
