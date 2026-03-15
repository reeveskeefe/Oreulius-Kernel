//! Browser backend audit log.
//!
//! Identical pattern to `compositor/audit.rs`: a fixed-size ring buffer of
//! `AuditEntry` records stamped with a monotonic sequence counter.
//! No heap allocation required.

#![allow(dead_code)]

use super::types::{BrowserSessionId, RequestId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const AUDIT_LOG_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// AuditKind
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuditKind {
    SessionOpened      = 0,
    SessionClosed      = 1,
    NavigateStart      = 2,
    NavigateCommit     = 3,
    FetchStart         = 4,
    FetchComplete      = 5,
    PolicyBlocked      = 6,
    TlsEstablished     = 7,
    TlsFailed          = 8,
    DownloadOffered    = 9,
    DownloadComplete   = 10,
    CookieSet          = 11,
    CacheHit           = 12,
    CacheMiss          = 13,
    RequestAborted     = 14,
    RedirectFollowed   = 15,
    ContentFiltered    = 16,
    InternalError      = 17,
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// A single audit log entry.  Fits in a cache line (64 bytes).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct AuditEntry {
    /// Monotonic sequence number (wraps at u32::MAX).
    pub seq:      u32,
    /// Which session this event belongs to (0 = kernel / no session).
    pub session:  BrowserSessionId,
    /// Which request triggered the event (0 = not applicable).
    pub request:  RequestId,
    pub kind:     AuditKind,
    /// Free-form 32-byte annotation (ASCII, zero-padded).
    pub note:     [u8; 32],
    /// Spare byte for alignment.
    _pad:         [u8; 13],
}

impl AuditEntry {
    pub const EMPTY: Self = Self {
        seq:     0,
        session: BrowserSessionId(0),
        request: RequestId(0),
        kind:    AuditKind::InternalError,
        note:    [0u8; 32],
        _pad:    [0u8; 13],
    };

    /// Build an entry with a short ASCII annotation.
    pub fn new(
        seq:     u32,
        session: BrowserSessionId,
        request: RequestId,
        kind:    AuditKind,
        note:    &[u8],
    ) -> Self {
        let mut entry = Self::EMPTY;
        entry.seq     = seq;
        entry.session = session;
        entry.request = request;
        entry.kind    = kind;
        let len = note.len().min(32);
        entry.note[..len].copy_from_slice(&note[..len]);
        entry
    }
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

pub struct AuditLog {
    ring:  [AuditEntry; AUDIT_LOG_SIZE],
    head:  usize,
    seq:   u32,
}

impl AuditLog {
    pub const fn new() -> Self {
        Self {
            ring: [AuditEntry::EMPTY; AUDIT_LOG_SIZE],
            head: 0,
            seq:  0,
        }
    }

    /// Append an entry, overwriting the oldest if the ring is full.
    pub fn push(
        &mut self,
        session: BrowserSessionId,
        request: RequestId,
        kind:    AuditKind,
        note:    &[u8],
    ) {
        let seq  = self.seq;
        self.seq = self.seq.wrapping_add(1);
        self.ring[self.head] = AuditEntry::new(seq, session, request, kind, note);
        self.head = (self.head + 1) % AUDIT_LOG_SIZE;
    }

    /// Convenience helpers — each maps to one `AuditKind` variant.

    pub fn session_opened(&mut self, s: BrowserSessionId) {
        self.push(s, RequestId(0), AuditKind::SessionOpened, b"");
    }

    pub fn session_closed(&mut self, s: BrowserSessionId) {
        self.push(s, RequestId(0), AuditKind::SessionClosed, b"");
    }

    pub fn navigate_start(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::NavigateStart, b"");
    }

    pub fn navigate_commit(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::NavigateCommit, b"");
    }

    pub fn fetch_start(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::FetchStart, b"");
    }

    pub fn fetch_complete(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::FetchComplete, b"");
    }

    pub fn policy_blocked(&mut self, s: BrowserSessionId, r: RequestId, reason: &[u8]) {
        self.push(s, r, AuditKind::PolicyBlocked, reason);
    }

    pub fn tls_established(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::TlsEstablished, b"");
    }

    pub fn tls_failed(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::TlsFailed, b"");
    }

    pub fn download_offered(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::DownloadOffered, b"");
    }

    pub fn download_complete(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::DownloadComplete, b"");
    }

    pub fn cookie_set(&mut self, s: BrowserSessionId, host: &[u8]) {
        self.push(s, RequestId(0), AuditKind::CookieSet, host);
    }

    pub fn cache_hit(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::CacheHit, b"");
    }

    pub fn cache_miss(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::CacheMiss, b"");
    }

    pub fn request_aborted(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::RequestAborted, b"");
    }

    pub fn redirect_followed(&mut self, s: BrowserSessionId, r: RequestId, to: &[u8]) {
        self.push(s, r, AuditKind::RedirectFollowed, to);
    }

    pub fn content_filtered(&mut self, s: BrowserSessionId, r: RequestId) {
        self.push(s, r, AuditKind::ContentFiltered, b"");
    }

    pub fn internal_error(&mut self, s: BrowserSessionId, r: RequestId, msg: &[u8]) {
        self.push(s, r, AuditKind::InternalError, msg);
    }

    // -----------------------------------------------------------------------
    // Iteration
    // -----------------------------------------------------------------------

    /// Iterate entries in insertion order (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &AuditEntry> {
        let start = self.head;
        let ring  = &self.ring;
        (0..AUDIT_LOG_SIZE).map(move |i| &ring[(start + i) % AUDIT_LOG_SIZE])
    }

    /// Drain entries newer than `after_seq` (exclusive).
    /// Calls `f` for each qualifying entry in order.
    pub fn drain_since<F: FnMut(&AuditEntry)>(&self, after_seq: u32, mut f: F) {
        for e in self.iter() {
            if e.seq != 0 && e.seq > after_seq {
                f(e);
            }
        }
    }
}
