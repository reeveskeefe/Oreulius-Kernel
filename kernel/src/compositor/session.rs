//! Compositor sessions — one session per GUI client process.
//!
//! A `CompositorSession` tracks:
//! - the owning process ID
//! - all window IDs belonging to that process
//! - the session capability token
//! - per-session quotas (max windows, max surface bytes)
//! - whether input is subscribed

#![allow(dead_code)]

use super::protocol::{CompositorCap, SessionId, WindowId};
use crate::ipc::ProcessId;

/// Maximum windows per session.
pub const MAX_WINDOWS_PER_SESSION: usize = 8;

/// Maximum number of concurrent sessions.
pub const MAX_SESSIONS: usize = 16;

/// Per-process compositor session.
#[derive(Clone)]
pub struct CompositorSession {
    /// Which process owns this session.
    pub pid: ProcessId,
    /// Session ID (matches the slot index + 1).
    pub id: SessionId,
    /// Capability token this session must present.
    pub cap: CompositorCap,
    /// Input subscription capability.
    pub input_cap: CompositorCap,
    /// Window IDs owned by this session (up to MAX_WINDOWS_PER_SESSION).
    pub windows: [Option<WindowId>; MAX_WINDOWS_PER_SESSION],
    pub window_count: usize,
    /// Whether this session has subscribed to input events.
    pub input_subscribed: bool,
    /// Whether this slot is in use.
    pub alive: bool,
}

impl CompositorSession {
    pub const fn empty() -> Self {
        CompositorSession {
            pid: ProcessId(0),
            id: SessionId(0),
            cap: CompositorCap(0),
            input_cap: CompositorCap(0),
            windows: [None; MAX_WINDOWS_PER_SESSION],
            window_count: 0,
            input_subscribed: false,
            alive: false,
        }
    }

    /// Add a window to this session.  Returns false if quota is full.
    pub fn add_window(&mut self, wid: WindowId) -> bool {
        if self.window_count >= MAX_WINDOWS_PER_SESSION {
            return false;
        }
        for slot in self.windows.iter_mut() {
            if slot.is_none() {
                *slot = Some(wid);
                self.window_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove a window from this session.
    pub fn remove_window(&mut self, wid: WindowId) {
        for slot in self.windows.iter_mut() {
            if *slot == Some(wid) {
                *slot = None;
                if self.window_count > 0 {
                    self.window_count -= 1;
                }
                return;
            }
        }
    }

    /// Check that a session capability matches.
    pub fn check_cap(&self, cap: CompositorCap) -> bool {
        self.alive && self.cap.is_valid() && self.cap == cap
    }

    /// Check that an input capability matches.
    pub fn check_input_cap(&self, cap: CompositorCap) -> bool {
        self.alive && self.input_cap.is_valid() && self.input_cap == cap
    }
}

// ---------------------------------------------------------------------------
// Session table
// ---------------------------------------------------------------------------

pub struct SessionTable {
    slots: [CompositorSession; MAX_SESSIONS],
    /// Monotonic counter for capability token generation.
    cap_counter: u64,
}

impl SessionTable {
    pub const fn new() -> Self {
        const EMPTY: CompositorSession = CompositorSession::empty();
        SessionTable {
            slots: [EMPTY; MAX_SESSIONS],
            cap_counter: 1,
        }
    }

    /// Create a new session for `pid`.  Returns the session slot index or None.
    pub fn open(&mut self, pid: ProcessId) -> Option<usize> {
        // Find a free slot before we borrow self again for cap generation.
        let slot_idx = self.slots.iter().position(|s| !s.alive)?;
        let id = SessionId((slot_idx + 1) as u32);
        // Generate capabilities before borrowing the slot mutably.
        let cap = self.next_cap();
        let input_cap = self.next_cap();
        self.slots[slot_idx] = CompositorSession {
            pid,
            id,
            cap,
            input_cap,
            windows: [None; MAX_WINDOWS_PER_SESSION],
            window_count: 0,
            input_subscribed: false,
            alive: true,
        };
        Some(slot_idx)
    }

    /// Close a session by slot index.
    pub fn close(&mut self, idx: usize) {
        if idx < MAX_SESSIONS {
            self.slots[idx] = CompositorSession::empty();
        }
    }

    /// Find a session by `SessionId`.
    pub fn find(&self, id: SessionId) -> Option<usize> {
        let idx = id.0.checked_sub(1)? as usize;
        if idx < MAX_SESSIONS && self.slots[idx].alive && self.slots[idx].id == id {
            Some(idx)
        } else {
            None
        }
    }

    /// Get a reference to a session by slot index.
    pub fn get(&self, idx: usize) -> Option<&CompositorSession> {
        if idx < MAX_SESSIONS && self.slots[idx].alive {
            Some(&self.slots[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to a session by slot index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut CompositorSession> {
        if idx < MAX_SESSIONS && self.slots[idx].alive {
            Some(&mut self.slots[idx])
        } else {
            None
        }
    }

    /// Find the session that owns `pid`.
    pub fn find_by_pid(&self, pid: ProcessId) -> Option<usize> {
        self.slots.iter().position(|s| s.alive && s.pid == pid)
    }

    fn next_cap(&mut self) -> CompositorCap {
        let v = self.cap_counter;
        self.cap_counter = self.cap_counter.wrapping_add(1).max(1);
        CompositorCap(v ^ 0xCAFE_BABE_DEAD_0000)
    }
}
