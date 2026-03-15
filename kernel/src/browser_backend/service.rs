//! Browser backend service — global singleton and request dispatcher.
//!
//! `BrowserBackendService` owns all browser subsystems:
//!   - `SessionTable`   — client browser sessions
//!   - `OriginTable`    — per-session origin policy
//!   - `CookieJar`      — per-origin cookies
//!   - `ResponseCache`  — HTTP response cache
//!   - `DownloadManager`— pending download jobs
//!   - `StorageTable`   — per-session VFS storage
//!   - `AuditLog`       — event history ring buffer
//!
//! Public API:
//!   - `init()`                  — called once at boot
//!   - `handle_request(req) → BrowserResponse` — process one IPC message

#![allow(dead_code)]

use spin::Mutex;

use super::audit::{AuditKind, AuditLog};
use super::cache::ResponseCache;
use super::content_filter::{ContentFilter, SniffResult};
use super::cookie_jar::CookieJar;
use super::downloads::DownloadManager;
use super::fetch::{fetch_request, FetchContext, FetchOutcome};
use super::origin::{OriginCheckResult, OriginPolicy, OriginTable};
use super::policy::BrowserPolicy;
use super::protocol::{
    BrowserError, BrowserEvent, BrowserRequest, BrowserResponse,
    PolicyBlockReason, TlsHandshakeResult, BODY_CHUNK_MAX,
};
use super::session::{BrowserSession, SessionTable, MAX_BROWSER_SESSIONS};
use super::storage::StorageTable;
use super::temporal;
use super::types::{
    BrowserCap, BrowserSessionId, DownloadId, HttpMethod, Origin,
    RequestId, Scheme, Url, URL_MAX,
};
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

pub static BROWSER_SERVICE: Mutex<BrowserBackendService> =
    Mutex::new(BrowserBackendService::new());

// ---------------------------------------------------------------------------
// Service struct
// ---------------------------------------------------------------------------

pub struct BrowserBackendService {
    sessions:  SessionTable,
    origins:   OriginTable,
    cookies:   CookieJar,
    cache:     ResponseCache,
    downloads: DownloadManager,
    storage:   StorageTable,
    audit:     AuditLog,
    /// Monotonic epoch counter (incremented by each `tick()` call).
    epoch:     u64,
    initialised: bool,
}

impl BrowserBackendService {
    pub const fn new() -> Self {
        Self {
            sessions:  SessionTable::new(),
            origins:   OriginTable::new(),
            cookies:   CookieJar::new(),
            cache:     ResponseCache::new(),
            downloads: DownloadManager::new(),
            storage:   StorageTable::new(),
            audit:     AuditLog::new(),
            epoch:     0,
            initialised: false,
        }
    }

    // -----------------------------------------------------------------------
    // Init / tick
    // -----------------------------------------------------------------------

    pub fn init(&mut self) {
        if self.initialised { return; }
        self.initialised = true;
    }

    /// Advance the epoch counter.  Called by the kernel timer tick.
    pub fn tick(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    // -----------------------------------------------------------------------
    // Request dispatch
    // -----------------------------------------------------------------------

    pub fn handle_request(&mut self, req: BrowserRequest) -> BrowserResponse {
        match req {
            BrowserRequest::OpenSession { pid, .. } => {
                self.do_open_session(pid)
            }
            BrowserRequest::CloseSession { session, cap } => {
                self.do_close_session(session, cap)
            }
            BrowserRequest::Navigate {
                session, cap, url, url_len, method, body, body_len, redirect,
            } => {
                self.do_navigate(session, cap, &url[..url_len], method, &body[..body_len])
            }
            BrowserRequest::Subscribe { session, cap } => {
                self.do_subscribe(session, cap)
            }
            BrowserRequest::Unsubscribe { session, cap } => {
                self.do_unsubscribe(session, cap)
            }
            BrowserRequest::AbortRequest { session, cap, request_id } => {
                self.do_abort(session, cap, request_id)
            }
            BrowserRequest::AcceptDownload { session, cap, download_id, dest_path, dest_len } => {
                self.do_accept_download(session, cap, download_id, &dest_path[..dest_len])
            }
            BrowserRequest::RejectDownload { session, cap, download_id } => {
                self.do_reject_download(session, cap, download_id)
            }
            BrowserRequest::PollEvents { session, cap } => {
                self.do_poll_events(session, cap)
            }
        }
    }

    // -----------------------------------------------------------------------
    // OpenSession
    // -----------------------------------------------------------------------

    fn do_open_session(&mut self, pid: ProcessId) -> BrowserResponse {
        // Limit one session per PID.
        if self.sessions.find_by_pid(pid).is_some() {
            return BrowserResponse::Error(BrowserError::SessionQuotaExceeded);
        }
        let idx = match self.sessions.open(pid) {
            Some(i) => i,
            None    => return BrowserResponse::Error(BrowserError::SessionQuotaExceeded),
        };
        let s   = self.sessions.get(idx).unwrap();
        let id  = s.id;
        let cap = s.cap;

        // Register in origin table (open policy by default).
        self.origins.register(id, OriginPolicy::open(Origin::OPAQUE));
        // Ensure VFS storage directory.
        self.storage.register(id);

        self.audit.session_opened(id);
        BrowserResponse::SessionGranted { session: id, cap }
    }

    // -----------------------------------------------------------------------
    // CloseSession
    // -----------------------------------------------------------------------

    fn do_close_session(
        &mut self,
        session: BrowserSessionId,
        cap:     BrowserCap,
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None    => return BrowserResponse::Error(BrowserError::InvalidSession),
        };
        self.sessions.close(idx);
        self.origins.unregister(session);
        self.cookies.purge_session(session);
        self.cache.purge_session(session);
        self.downloads.purge_session(session);
        self.storage.unregister(session);
        self.audit.session_closed(session);
        BrowserResponse::Ok
    }

    // -----------------------------------------------------------------------
    // Navigate
    // -----------------------------------------------------------------------

    fn do_navigate(
        &mut self,
        session:  BrowserSessionId,
        cap:      BrowserCap,
        url_raw:  &[u8],
        method:   HttpMethod,
        body:     &[u8],
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None    => return BrowserResponse::Error(BrowserError::InvalidSession),
        };

        // Parse URL.
        let url = match Url::parse(url_raw) {
            Some(u) => u,
            None    => return BrowserResponse::Error(BrowserError::InvalidUrl),
        };

        // Scheme check.
        let policy_checker = BrowserPolicy;
        if policy_checker.check_scheme(url.scheme).is_some() {
            return BrowserResponse::Error(BrowserError::UnsupportedScheme);
        }

        // Origin check.
        match self.origins.check_navigation(session, &url) {
            OriginCheckResult::Allowed => {}
            _                          => {
                self.audit.policy_blocked(
                    session,
                    RequestId(0),
                    b"origin-blocked",
                );
                return BrowserResponse::Error(BrowserError::InternalError);
            }
        }

        // Allocate request ID.
        let request_id = {
            let s = self.sessions.get_mut(idx).unwrap();
            s.alloc_request_id()
        };

        // Cache lookup.
        if method == HttpMethod::Get {
            if let Some(cache_idx) = self.cache.lookup(session, &url, self.epoch) {
                // Cache hit — emit headers + body from cache.
                let s = self.sessions.get_mut(idx).unwrap();
                let entry = &self.cache.entries[cache_idx];
                let status = entry.status;
                let mime   = entry.mime;
                let body_len = entry.body_len;
                let body_off = entry.body_offset;

                let mut body_chunk = [0u8; BODY_CHUNK_MAX];
                let read = self.cache.read_body(cache_idx, &mut body_chunk);
                s.enqueue(BrowserEvent::Headers {
                    request_id,
                    status,
                    mime,
                    content_length: Some(body_len as u64),
                    headers:     [super::protocol::ResponseHeader::empty(); 32],
                    header_count: 0,
                });
                if read > 0 {
                    s.enqueue(BrowserEvent::BodyChunk {
                        request_id,
                        data: body_chunk,
                        data_len: read,
                        is_last: true,
                    });
                }
                s.enqueue(BrowserEvent::Complete { request_id });
                self.audit.cache_hit(session, request_id);
                return BrowserResponse::RequestAccepted { request_id };
            }
        }
        self.audit.cache_miss(session, request_id);

        // Kick off the fetch.
        self.audit.navigate_start(session, request_id);

        let profile = {
            let s = self.sessions.get(idx).unwrap();
            s.policy
        };

        let mut events: [Option<BrowserEvent>; 64] = [None; 64];
        let mut event_count = 0usize;

        let outcome = fetch_request(
            &FetchContext {
                session,
                request: request_id,
                url: &url,
                method,
                body,
                profile: &profile,
            },
            &mut events,
            &mut event_count,
        );

        // Enqueue all fetch events.
        {
            let s = self.sessions.get_mut(idx).unwrap();
            for i in 0..event_count {
                if let Some(ev) = events[i].take() {
                    s.enqueue(ev);
                }
            }
        }

        match outcome {
            FetchOutcome::Complete => {
                self.audit.fetch_complete(session, request_id);
                // Update top origin on successful navigation.
                self.origins.update_top_origin(session, Origin::from_url(&url));
                let s = self.sessions.get_mut(idx).unwrap();
                s.push_nav(&url);
            }
            FetchOutcome::PolicyBlocked(reason) => {
                self.audit.policy_blocked(session, request_id, b"policy-blocked");
            }
            FetchOutcome::Error(kind) => {
                self.audit.internal_error(session, request_id, b"fetch-error");
            }
            FetchOutcome::Redirect { status, location, location_len } => {
                // Redirect is surfaced as an event; the client re-issues Navigate.
                let s = self.sessions.get_mut(idx).unwrap();
                // Reconstruct "from" URL from the Url struct fields.
                let mut from = [0u8; URL_MAX];
                let mut fpos = 0usize;
                let sstr = url.scheme.as_str().as_bytes();
                let sc = sstr.len().min(URL_MAX - fpos);
                from[fpos..fpos+sc].copy_from_slice(&sstr[..sc]); fpos += sc;
                if fpos + 3 < URL_MAX { from[fpos..fpos+3].copy_from_slice(b"://"); fpos += 3; }
                let hc = url.host_len.min(URL_MAX - fpos);
                from[fpos..fpos+hc].copy_from_slice(&url.host[..hc]); fpos += hc;
                let pc = url.path_len.min(URL_MAX - fpos);
                from[fpos..fpos+pc].copy_from_slice(&url.path[..pc]); fpos += pc;
                let fl = fpos;
                let mut to = [0u8; URL_MAX];
                let tl = location_len.min(URL_MAX);
                to[..tl].copy_from_slice(&location[..tl]);
                s.enqueue(BrowserEvent::Redirect {
                    request_id,
                    from_url: from,
                    from_url_len: fl,
                    to_url: to,
                    to_url_len: tl,
                    status: crate::browser_backend::types::StatusCode(status),
                });
            }
        }

        BrowserResponse::RequestAccepted { request_id }
    }

    // -----------------------------------------------------------------------
    // Subscribe / Unsubscribe
    // -----------------------------------------------------------------------

    fn do_subscribe(&mut self, session: BrowserSessionId, cap: BrowserCap) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        if let Some(idx) = self.sessions.find(session) {
            self.sessions.get_mut(idx).unwrap().subscribed = true;
            BrowserResponse::Subscribed
        } else {
            BrowserResponse::Error(BrowserError::InvalidSession)
        }
    }

    fn do_unsubscribe(&mut self, session: BrowserSessionId, cap: BrowserCap) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        if let Some(idx) = self.sessions.find(session) {
            self.sessions.get_mut(idx).unwrap().subscribed = false;
            BrowserResponse::Ok
        } else {
            BrowserResponse::Error(BrowserError::InvalidSession)
        }
    }

    // -----------------------------------------------------------------------
    // Abort
    // -----------------------------------------------------------------------

    fn do_abort(
        &mut self,
        session:    BrowserSessionId,
        cap:        BrowserCap,
        request_id: RequestId,
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        self.audit.request_aborted(session, request_id);
        // Transport-level abort is best-effort; the session will see no more
        // events for this request_id after `AbortRequest`.
        BrowserResponse::Ok
    }

    // -----------------------------------------------------------------------
    // AcceptDownload / RejectDownload
    // -----------------------------------------------------------------------

    fn do_accept_download(
        &mut self,
        session:     BrowserSessionId,
        cap:         BrowserCap,
        download_id: DownloadId,
        dest_path:   &[u8],
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        if self.downloads.accept(download_id, session, dest_path) {
            BrowserResponse::Ok
        } else {
            BrowserResponse::Error(BrowserError::InvalidDownload)
        }
    }

    fn do_reject_download(
        &mut self,
        session:     BrowserSessionId,
        cap:         BrowserCap,
        download_id: DownloadId,
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        if self.downloads.reject(download_id, session) {
            BrowserResponse::Ok
        } else {
            BrowserResponse::Error(BrowserError::InvalidDownload)
        }
    }

    // -----------------------------------------------------------------------
    // PollEvents
    // -----------------------------------------------------------------------

    fn do_poll_events(
        &mut self,
        session: BrowserSessionId,
        cap:     BrowserCap,
    ) -> BrowserResponse {
        if !self.verify_cap(session, cap) {
            return BrowserResponse::Error(BrowserError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None    => return BrowserResponse::Error(BrowserError::InvalidSession),
        };
        let mut events = [None; 8];
        let count = self.sessions.get_mut(idx).unwrap().drain_events(&mut events);
        BrowserResponse::Events { events, count }
    }

    // -----------------------------------------------------------------------
    // Capability verification
    // -----------------------------------------------------------------------

    fn verify_cap(&self, session: BrowserSessionId, cap: BrowserCap) -> bool {
        match self.sessions.find(session) {
            Some(idx) => self.sessions.get(idx)
                .map(|s| s.cap == cap && cap.is_valid())
                .unwrap_or(false),
            None      => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Module-level public API
// ---------------------------------------------------------------------------

/// Called once at kernel boot.
pub fn init() {
    BROWSER_SERVICE.lock().init();
}

/// Called on every kernel timer tick.
pub fn tick() {
    BROWSER_SERVICE.lock().tick();
}

/// Dispatch a single IPC request.
pub fn handle_request(req: BrowserRequest) -> BrowserResponse {
    BROWSER_SERVICE.lock().handle_request(req)
}
