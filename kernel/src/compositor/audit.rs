//! Compositor audit log.
//!
//! Records significant compositor events for post-hoc inspection (debugging,
//! security, telemetry).  The log is a fixed-size ring buffer; once full the
//! oldest entry is overwritten.  All writes are O(1) with no allocation.

#![allow(dead_code)]

pub const AUDIT_LOG_SIZE: usize = 128;

/// Category of event being logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditKind {
    SessionOpened = 0,
    SessionClosed = 1,
    WindowCreated = 2,
    WindowDestroyed = 3,
    SurfaceAllocated = 4,
    SurfaceFreed = 5,
    SurfaceCommit = 6,
    InputRouted = 7,
    FocusChanged = 8,
    PolicyViolation = 9,
    PresentComplete = 10,
    CapIssued = 11,
    CapRevoked = 12,
}

/// One audit record.
#[derive(Clone, Copy)]
pub struct AuditEntry {
    pub kind: AuditKind,
    /// Slot index in the SessionTable (-1 if not session-specific).
    pub session_idx: i32,
    /// Additional detail (window ID, surface index, etc.).
    pub detail: u64,
    /// Nanosecond timestamp from the kernel monotonic clock if available,
    /// otherwise a monotonic event counter.
    pub timestamp: u64,
}

impl AuditEntry {
    pub const fn empty() -> Self {
        AuditEntry {
            kind: AuditKind::SessionOpened,
            session_idx: -1,
            detail: 0,
            timestamp: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Ring buffer
// ---------------------------------------------------------------------------

pub struct AuditLog {
    entries: [AuditEntry; AUDIT_LOG_SIZE],
    /// Index of the next slot to write.
    write: usize,
    /// Total entries ever written (monotonic counter used as timestamps when
    /// no clock is available).
    total: u64,
}

impl AuditLog {
    pub const fn new() -> Self {
        AuditLog {
            entries: [AuditEntry::empty(); AUDIT_LOG_SIZE],
            write: 0,
            total: 0,
        }
    }

    // ------------------------------------------------------------------
    // Recording
    // ------------------------------------------------------------------

    /// Record an event for the given session.
    pub fn record(&mut self, kind: AuditKind, session_idx: i32, detail: u64) {
        let entry = AuditEntry {
            kind,
            session_idx,
            detail,
            timestamp: self.total,
        };
        self.entries[self.write] = entry;
        self.write = (self.write + 1) % AUDIT_LOG_SIZE;
        self.total = self.total.wrapping_add(1);
    }

    /// Convenience: record without a specific session or detail.
    pub fn record_simple(&mut self, kind: AuditKind) {
        self.record(kind, -1, 0);
    }

    // ------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------

    /// Copy the most recent `out.len()` entries (newest-first) into `out`.
    /// Returns the number of entries actually written.
    pub fn drain_recent(&self, out: &mut [AuditEntry]) -> usize {
        if self.total == 0 || out.is_empty() {
            return 0;
        }
        let available = (self.total as usize).min(AUDIT_LOG_SIZE);
        let n = available.min(out.len());
        // Walk backwards from the last written slot.
        let mut read = if self.write == 0 {
            AUDIT_LOG_SIZE - 1
        } else {
            self.write - 1
        };
        for i in 0..n {
            out[i] = self.entries[read];
            read = if read == 0 {
                AUDIT_LOG_SIZE - 1
            } else {
                read - 1
            };
        }
        n
    }

    /// Total events ever recorded (monotonic counter).
    pub fn total_events(&self) -> u64 {
        self.total
    }
}
