//! Browser session: navigation history and per-session state.

#![allow(dead_code)]

use super::audit::AuditLog;
use super::cache::ResponseCache;
use super::cookie_jar::CookieJar;
use super::downloads::DownloadManager;
use super::origin::{OriginPolicy, OriginTable};
use super::policy::PolicyProfile;
use super::protocol::{BrowserError, BrowserEvent, BrowserRequest, BrowserResponse};
use super::storage::StorageTable;
use super::types::{BrowserCap, BrowserSessionId, DownloadId, HttpMethod, RequestId, Url, URL_MAX};
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum open browser sessions.
pub const MAX_BROWSER_SESSIONS: usize = 8;

/// Navigation history depth per session.
pub const NAV_HISTORY_DEPTH: usize = 32;

/// Maximum events queued in a session's outbox.
pub const EVENT_QUEUE_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// NavigationEntry
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct NavigationEntry {
    pub url: [u8; URL_MAX],
    pub url_len: usize,
    pub active: bool,
}

impl NavigationEntry {
    pub const EMPTY: Self = Self {
        url: [0; URL_MAX],
        url_len: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// BrowserSession
// ---------------------------------------------------------------------------

pub struct BrowserSession {
    pub id: BrowserSessionId,
    pub pid: ProcessId,
    pub cap: BrowserCap,
    pub policy: PolicyProfile,
    /// Input-event subscription flag.
    pub subscribed: bool,
    pub alive: bool,

    // Navigation history ring.
    nav_history: [NavigationEntry; NAV_HISTORY_DEPTH],
    nav_head: usize,
    nav_count: usize,

    // Pending events outbox.
    event_queue: [Option<BrowserEvent>; EVENT_QUEUE_DEPTH],
    eq_head: usize,
    eq_tail: usize,
    eq_count: usize,

    // Active request counter.
    pub next_request_id: u32,
}

impl BrowserSession {
    pub const fn empty() -> Self {
        Self {
            id: BrowserSessionId(0),
            pid: ProcessId(0),
            cap: BrowserCap(0),
            policy: PolicyProfile::DEFAULT,
            subscribed: false,
            alive: false,
            nav_history: [NavigationEntry::EMPTY; NAV_HISTORY_DEPTH],
            nav_head: 0,
            nav_count: 0,
            event_queue: [None; EVENT_QUEUE_DEPTH],
            eq_head: 0,
            eq_tail: 0,
            eq_count: 0,
            next_request_id: 1,
        }
    }

    /// Allocate the next `RequestId` for this session.
    pub fn alloc_request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_request_id);
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        id
    }

    /// Navigation ring head (next write index).
    pub fn nav_head(&self) -> usize {
        self.nav_head
    }

    /// Number of valid navigation entries (≤ `NAV_HISTORY_DEPTH`).
    pub fn nav_count(&self) -> usize {
        self.nav_count
    }

    /// Access a navigation entry by ring slot index.
    pub fn nav_entry(&self, i: usize) -> Option<&NavigationEntry> {
        if i < NAV_HISTORY_DEPTH {
            Some(&self.nav_history[i])
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Navigation history
    // -----------------------------------------------------------------------

    /// Push a URL onto the navigation history ring.
    pub fn push_nav(&mut self, url: &Url) {
        let entry = &mut self.nav_history[self.nav_head % NAV_HISTORY_DEPTH];
        // Reconstruct the URL string: scheme://host[:port]/path[?query]
        let mut buf = [0u8; URL_MAX];
        let mut pos = 0usize;
        let scheme_str = url.scheme.as_str().as_bytes();
        let sc = scheme_str.len().min(URL_MAX - pos);
        buf[pos..pos + sc].copy_from_slice(&scheme_str[..sc]);
        pos += sc;
        if pos + 3 < URL_MAX {
            buf[pos..pos + 3].copy_from_slice(b"://");
            pos += 3;
        }
        let hc = url.host_len.min(URL_MAX - pos);
        buf[pos..pos + hc].copy_from_slice(&url.host[..hc]);
        pos += hc;
        if url.port != url.scheme.default_port() && pos + 7 < URL_MAX {
            buf[pos] = b':';
            pos += 1;
            let mut num = [0u8; 6];
            let nl = write_u16_buf(&mut num, url.port);
            let nc = nl.min(URL_MAX - pos);
            buf[pos..pos + nc].copy_from_slice(&num[..nc]);
            pos += nc;
        }
        let pc = url.path_len.min(URL_MAX - pos);
        buf[pos..pos + pc].copy_from_slice(&url.path[..pc]);
        pos += pc;
        if url.query_len > 0 && pos + 1 + url.query_len < URL_MAX {
            buf[pos] = b'?';
            pos += 1;
            let qc = url.query_len.min(URL_MAX - pos);
            buf[pos..pos + qc].copy_from_slice(&url.query[..qc]);
            pos += qc;
        }
        let len = pos.min(URL_MAX);
        entry.url[..len].copy_from_slice(&buf[..len]);
        entry.url_len = len;
        entry.active = true;
        self.nav_head = (self.nav_head + 1) % NAV_HISTORY_DEPTH;
        if self.nav_count < NAV_HISTORY_DEPTH {
            self.nav_count += 1;
        }
    }

    /// Return the most recent navigation URL, if any.
    pub fn current_url(&self) -> Option<&[u8]> {
        if self.nav_count == 0 {
            return None;
        }
        let idx = self.nav_head.wrapping_sub(1) % NAV_HISTORY_DEPTH;
        let e = &self.nav_history[idx];
        if e.active {
            Some(&e.url[..e.url_len])
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Event queue
    // -----------------------------------------------------------------------

    /// Enqueue an event.  Drops the event if the queue is full.
    pub fn enqueue(&mut self, ev: BrowserEvent) {
        if self.eq_count >= EVENT_QUEUE_DEPTH {
            return;
        }
        self.event_queue[self.eq_tail] = Some(ev);
        self.eq_tail = (self.eq_tail + 1) % EVENT_QUEUE_DEPTH;
        self.eq_count += 1;
    }

    /// Drain up to `max` events into `out`.  Returns count drained.
    pub fn drain_events(&mut self, out: &mut [Option<BrowserEvent>; 8]) -> usize {
        let n = self.eq_count.min(8);
        for i in 0..n {
            out[i] = self.event_queue[self.eq_head].take();
            self.eq_head = (self.eq_head + 1) % EVENT_QUEUE_DEPTH;
        }
        self.eq_count -= n;
        n
    }
}

// ---------------------------------------------------------------------------
// SessionTable
// ---------------------------------------------------------------------------

pub struct SessionTable {
    slots: [BrowserSession; MAX_BROWSER_SESSIONS],
    cap_seed: u64,
}

impl SessionTable {
    pub const fn new() -> Self {
        const EMPTY: BrowserSession = BrowserSession::empty();
        Self {
            slots: [EMPTY; MAX_BROWSER_SESSIONS],
            cap_seed: 0xDEAD_BEEF_1234_5678,
        }
    }

    fn next_cap(&mut self) -> BrowserCap {
        // LCG — same pattern as compositor/capability.rs.
        let x = self.cap_seed;
        self.cap_seed = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        BrowserCap(self.cap_seed | 1)
    }

    /// Open a new session for `pid`.  Returns slot index or `None`.
    pub fn open(&mut self, pid: ProcessId) -> Option<usize> {
        let slot = self.slots.iter().position(|s| !s.alive)?;
        let id = BrowserSessionId((slot + 1) as u32);
        let cap = self.next_cap();
        self.slots[slot] = BrowserSession::empty();
        self.slots[slot].id = id;
        self.slots[slot].pid = pid;
        self.slots[slot].cap = cap;
        self.slots[slot].alive = true;
        Some(slot)
    }

    /// Close a session by slot index.
    pub fn close(&mut self, idx: usize) {
        if idx < MAX_BROWSER_SESSIONS {
            self.slots[idx] = BrowserSession::empty();
        }
    }

    /// Find by `BrowserSessionId`.
    pub fn find(&self, id: BrowserSessionId) -> Option<usize> {
        let idx = id.0.checked_sub(1)? as usize;
        if idx < MAX_BROWSER_SESSIONS && self.slots[idx].alive && self.slots[idx].id == id {
            Some(idx)
        } else {
            None
        }
    }

    pub fn get(&self, idx: usize) -> Option<&BrowserSession> {
        if idx < MAX_BROWSER_SESSIONS && self.slots[idx].alive {
            Some(&self.slots[idx])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut BrowserSession> {
        if idx < MAX_BROWSER_SESSIONS && self.slots[idx].alive {
            Some(&mut self.slots[idx])
        } else {
            None
        }
    }

    pub fn restore(
        &mut self,
        idx: usize,
        id: BrowserSessionId,
        pid: ProcessId,
        cap: BrowserCap,
    ) -> bool {
        if idx >= MAX_BROWSER_SESSIONS {
            return false;
        }
        self.slots[idx] = BrowserSession::empty();
        self.slots[idx].id = id;
        self.slots[idx].pid = pid;
        self.slots[idx].cap = cap;
        self.slots[idx].policy = PolicyProfile::DEFAULT;
        self.slots[idx].alive = true;
        true
    }

    /// Restore navigation history and `next_request_id` for an already-live
    /// session at `idx`.  No-op if `idx` is out of range or slot is not alive.
    pub fn restore_nav(
        &mut self,
        idx: usize,
        next_request_id: u32,
        nav_head: usize,
        nav_count: usize,
        entries: &[(usize, [u8; URL_MAX])],
    ) {
        if idx >= MAX_BROWSER_SESSIONS || !self.slots[idx].alive {
            return;
        }
        let s = &mut self.slots[idx];
        s.next_request_id = next_request_id.max(1);
        s.nav_head = nav_head % NAV_HISTORY_DEPTH;
        s.nav_count = nav_count.min(NAV_HISTORY_DEPTH);
        for (i, (url_len, url)) in entries.iter().enumerate() {
            if i >= NAV_HISTORY_DEPTH {
                break;
            }
            s.nav_history[i].url = *url;
            s.nav_history[i].url_len = (*url_len).min(URL_MAX);
            s.nav_history[i].active = *url_len > 0;
        }
    }

    pub fn find_by_pid(&self, pid: ProcessId) -> Option<usize> {
        self.slots.iter().position(|s| s.alive && s.pid == pid)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a u16 decimal to a fixed buffer, return number of bytes written.
fn write_u16_buf(out: &mut [u8; 6], v: u16) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 6];
    let mut n = v as u32;
    let mut i = 5usize;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i -= 1;
    }
    let start = i + 1;
    let len = 6 - start;
    out[..len].copy_from_slice(&tmp[start..]);
    len
}
