//! Capability registry for the compositor.
//!
//! Each surface, window, session and input-subscription is gated by an
//! opaque `CompositorCap` token.  Tokens are issued when a resource is
//! created and must be presented on every subsequent operation that touches
//! that resource.  Tokens are revoked when the resource is destroyed or the
//! owning session closes.
//!
//! All state fits in a fixed-size array — no heap allocation.

#![allow(dead_code)]

use super::protocol::CompositorCap;

pub const MAX_CAPS: usize = 256;

/// The kind of resource a capability grants access to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapKind {
    /// Authorises IPC commands for one compositor session.
    Session,
    /// Authorises create/destroy/move/resize for one window.
    WindowManage,
    /// Authorises pixel writes and `CommitSurface` for one surface.
    SurfaceWrite,
    /// Authorises `SubscribeInput` / reading input events.
    InputSubscribe,
}

/// One entry in the capability table.
#[derive(Clone, Copy)]
struct CapEntry {
    token: CompositorCap,
    kind: CapKind,
    /// Which slot in the SessionTable this cap belongs to.
    session_idx: usize,
    /// ID of the resource (window ID raw value, surface index, etc.).
    resource_id: u64,
    alive: bool,
}

impl CapEntry {
    const fn empty() -> Self {
        CapEntry {
            token: CompositorCap(0),
            kind: CapKind::Session,
            session_idx: 0,
            resource_id: 0,
            alive: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct CompositorCapRegistry {
    entries: [CapEntry; MAX_CAPS],
    /// Monotonic counter for unique token generation.
    counter: u64,
}

impl CompositorCapRegistry {
    pub const fn new() -> Self {
        CompositorCapRegistry {
            entries: [CapEntry::empty(); MAX_CAPS],
            counter: 0x0000_0001_0000_0001,
        }
    }

    // ------------------------------------------------------------------
    // Issue
    // ------------------------------------------------------------------

    /// Issue a new capability token.  Returns `CompositorCap(0)` if the
    /// table is full (should never happen in practice).
    pub fn issue(&mut self, kind: CapKind, session_idx: usize, resource_id: u64) -> CompositorCap {
        // Find the first free slot index.
        let slot_idx = self.entries.iter().position(|e| !e.alive);
        if let Some(idx) = slot_idx {
            // Generate the token before we mutably borrow the entry.
            let token = self.next_token(kind);
            self.entries[idx] = CapEntry {
                token,
                kind,
                session_idx,
                resource_id,
                alive: true,
            };
            return token;
        }
        CompositorCap(0) // table full
    }

    // ------------------------------------------------------------------
    // Validate
    // ------------------------------------------------------------------

    /// Validate a token of a specific kind.
    /// Returns `(session_idx, resource_id)` on success.
    pub fn validate(&self, cap: CompositorCap, kind: CapKind) -> Option<(usize, u64)> {
        if !cap.is_valid() {
            return None;
        }
        for entry in &self.entries {
            if entry.alive && entry.token == cap && entry.kind == kind {
                return Some((entry.session_idx, entry.resource_id));
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Revoke
    // ------------------------------------------------------------------

    /// Revoke a single capability.
    pub fn revoke(&mut self, cap: CompositorCap) {
        for entry in self.entries.iter_mut() {
            if entry.alive && entry.token == cap {
                *entry = CapEntry::empty();
                return;
            }
        }
    }

    /// Revoke all capabilities belonging to a session (cascade on close).
    pub fn revoke_session(&mut self, session_idx: usize) {
        for entry in self.entries.iter_mut() {
            if entry.alive && entry.session_idx == session_idx {
                *entry = CapEntry::empty();
            }
        }
    }

    /// Revoke all capabilities for a specific resource.
    pub fn revoke_resource(&mut self, kind: CapKind, session_idx: usize, resource_id: u64) {
        for entry in self.entries.iter_mut() {
            if entry.alive
                && entry.kind == kind
                && entry.session_idx == session_idx
                && entry.resource_id == resource_id
            {
                *entry = CapEntry::empty();
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn next_token(&mut self, kind: CapKind) -> CompositorCap {
        let salt: u64 = match kind {
            CapKind::Session => 0xAAAA_0000_0000_0001,
            CapKind::WindowManage => 0xBBBB_0000_0000_0002,
            CapKind::SurfaceWrite => 0xCCCC_0000_0000_0003,
            CapKind::InputSubscribe => 0xDDDD_0000_0000_0004,
        };
        let v = self.counter ^ salt;
        // Advance counter: simple LCG to spread values.
        self.counter = self
            .counter
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        CompositorCap(v)
    }
}
