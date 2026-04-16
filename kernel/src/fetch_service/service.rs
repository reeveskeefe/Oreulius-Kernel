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


//! Browser backend service — global singleton and request dispatcher.
//!
//! `FetchServiceService` owns all browser subsystems:
//!   - `SessionTable`   — client fetch sessions
//!   - `OriginTable`    — per-session origin policy
//!   - `CookieJar`      — per-origin cookies
//!   - `ResponseCache`  — HTTP response cache
//!   - `DownloadManager`— pending download jobs
//!   - `StorageTable`   — per-session VFS storage
//!   - `AuditLog`       — event history ring buffer
//!
//! Public API:
//!   - `init()`                  — called once at boot
//!   - `handle_request(req) → FetchResponse` — process one IPC message

#![allow(dead_code)]

use spin::Mutex;

use super::audit::{AuditKind, AuditLog};
use super::cache::ResponseCache;
use super::content_filter::{ContentFilter, SniffResult};
use super::cookie_jar::CookieJar;
use super::downloads::DownloadManager;
use super::fetch::{fetch_request, FetchContext, FetchOutcome};
use super::origin::{OriginCheckResult, OriginPolicy, OriginTable};
use super::policy::FetchPolicy;
use super::protocol::{
    FetchError, FetchEvent, FetchRequest, FetchResponse, FetchErrorKind, PolicyBlockReason,
    TlsHandshakeResult, BODY_CHUNK_MAX, ERROR_MSG_MAX,
};
use super::session::{BrowserSession, SessionTable, MAX_BROWSER_SESSIONS};
use super::storage::StorageTable;
use super::temporal;
use super::types::{
    Cap, SessionId, DownloadId, HttpMethod, Origin, RedirectPolicy, RequestId,
    Scheme, Url, URL_MAX,
};
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

pub static BROWSER_SERVICE: Mutex<FetchServiceService> = Mutex::new(FetchServiceService::new());

// ---------------------------------------------------------------------------
// Service struct
// ---------------------------------------------------------------------------

pub struct FetchServiceService {
    sessions: SessionTable,
    origins: OriginTable,
    cookies: CookieJar,
    cache: ResponseCache,
    downloads: DownloadManager,
    storage: StorageTable,
    audit: AuditLog,
    /// Monotonic epoch counter (incremented by each `tick()` call).
    epoch: u64,
    initialised: bool,
}

fn policy_reason_bytes(reason: PolicyBlockReason) -> &'static [u8] {
    match reason {
        PolicyBlockReason::MixedContent => b"mixed-content",
        PolicyBlockReason::OriginNotAllowed => b"origin-not-allowed",
        PolicyBlockReason::SchemeNotAllowed => b"scheme-not-allowed",
        PolicyBlockReason::Filtered => b"filtered",
        PolicyBlockReason::TlsCertificateError => b"tls-certificate-error",
    }
}

fn fetch_error_kind_bytes(kind: FetchErrorKind) -> &'static [u8] {
    match kind {
        FetchErrorKind::DnsFailure => b"dns-failure",
        FetchErrorKind::ConnectionFailed => b"connection-failed",
        FetchErrorKind::TlsHandshakeFailed => b"tls-handshake-failed",
        FetchErrorKind::ConnectionReset => b"connection-reset",
        FetchErrorKind::ProtocolError => b"protocol-error",
        FetchErrorKind::TooManyRedirects => b"too-many-redirects",
        FetchErrorKind::Aborted => b"aborted",
        FetchErrorKind::InternalError => b"internal-error",
    }
}

impl FetchServiceService {
    pub const fn new() -> Self {
        Self {
            sessions: SessionTable::new(),
            origins: OriginTable::new(),
            cookies: CookieJar::new(),
            cache: ResponseCache::new(),
            downloads: DownloadManager::new(),
            storage: StorageTable::new(),
            audit: AuditLog::new(),
            epoch: 0,
            initialised: false,
        }
    }

    // -----------------------------------------------------------------------
    // Init / tick
    // -----------------------------------------------------------------------

    pub fn init(&mut self) {
        if self.initialised {
            return;
        }
        self.initialised = true;
    }

    /// Advance the epoch counter.  Called by the kernel timer tick.
    pub fn tick(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    // -----------------------------------------------------------------------
    // Request dispatch
    // -----------------------------------------------------------------------

    pub fn handle_request(&mut self, req: FetchRequest) -> FetchResponse {
        match req {
            FetchRequest::OpenSession { pid, .. } => self.do_open_session(pid),
            FetchRequest::CloseSession { session, cap } => self.do_close_session(session, cap),
            FetchRequest::Navigate {
                session,
                cap,
                url,
                url_len,
                method,
                body,
                body_len,
                redirect,
            } => self.do_navigate(
                session,
                cap,
                &url[..url_len],
                method,
                &body[..body_len],
                redirect,
            ),
            FetchRequest::Subscribe { session, cap } => self.do_subscribe(session, cap),
            FetchRequest::Unsubscribe { session, cap } => self.do_unsubscribe(session, cap),
            FetchRequest::AbortRequest {
                session,
                cap,
                request_id,
            } => self.do_abort(session, cap, request_id),
            FetchRequest::AcceptDownload {
                session,
                cap,
                download_id,
                dest_path,
                dest_len,
            } => self.do_accept_download(session, cap, download_id, &dest_path[..dest_len]),
            FetchRequest::RejectDownload {
                session,
                cap,
                download_id,
            } => self.do_reject_download(session, cap, download_id),
            FetchRequest::PollEvents { session, cap } => self.do_poll_events(session, cap),
        }
    }

    // -----------------------------------------------------------------------
    // OpenSession
    // -----------------------------------------------------------------------

    fn do_open_session(&mut self, pid: ProcessId) -> FetchResponse {
        // Limit one session per PID.
        if self.sessions.find_by_pid(pid).is_some() {
            return FetchResponse::Error(FetchError::SessionQuotaExceeded);
        }
        let idx = match self.sessions.open(pid) {
            Some(i) => i,
            None => return FetchResponse::Error(FetchError::SessionQuotaExceeded),
        };
        let s = self.sessions.get(idx).unwrap();
        let id = s.id;
        let cap = s.cap;

        // Register in origin table (open policy by default).
        self.origins
            .register(id, OriginPolicy::open(Origin::OPAQUE));
        // Ensure VFS storage directory.
        self.storage.register(id);

        self.audit.session_opened(id);
        FetchResponse::SessionGranted { session: id, cap }
    }

    // -----------------------------------------------------------------------
    // CloseSession
    // -----------------------------------------------------------------------

    fn do_close_session(&mut self, session: SessionId, cap: Cap) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return FetchResponse::Error(FetchError::InvalidSession),
        };
        self.sessions.close(idx);
        self.origins.unregister(session);
        self.cookies.purge_session(session);
        self.cache.purge_session(session);
        self.downloads.purge_session(session);
        self.storage.unregister(session);
        self.audit.session_closed(session);
        FetchResponse::Ok
    }

    // -----------------------------------------------------------------------
    // Navigate
    // -----------------------------------------------------------------------

    fn do_navigate(
        &mut self,
        session: SessionId,
        cap: Cap,
        url_raw: &[u8],
        method: HttpMethod,
        body: &[u8],
        redirect: RedirectPolicy,
    ) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return FetchResponse::Error(FetchError::InvalidSession),
        };

        // Parse URL.
        let url = match Url::parse(url_raw) {
            Some(u) => u,
            None => return FetchResponse::Error(FetchError::InvalidUrl),
        };

        // Scheme check.
        let policy_checker = FetchPolicy;
        if policy_checker.check_scheme(url.scheme).is_some() {
            return FetchResponse::Error(FetchError::UnsupportedScheme);
        }

        // Origin check.
        match self.origins.check_navigation(session, &url) {
            OriginCheckResult::Allowed => {}
            _ => {
                self.audit
                    .policy_blocked(session, RequestId(0), b"origin-blocked");
                return FetchResponse::Error(FetchError::InternalError);
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
                let mime = entry.mime;
                let body_len = entry.body_len;
                let body_off = entry.body_offset;

                let mut body_chunk = [0u8; BODY_CHUNK_MAX];
                let read = self.cache.read_body(cache_idx, &mut body_chunk);
                let is_last = read >= body_len
                    && body_off.saturating_add(read) <= super::cache::CACHE_BODY_POOL;
                s.enqueue(FetchEvent::Headers {
                    request_id,
                    status,
                    mime,
                    content_length: Some(body_len as u64),
                    headers: [super::protocol::ResponseHeader::empty(); 32],
                    header_count: 0,
                });
                if read > 0 {
                    s.enqueue(FetchEvent::BodyChunk {
                        request_id,
                        data: body_chunk,
                        data_len: read,
                        is_last,
                    });
                }
                s.enqueue(FetchEvent::Complete { request_id });
                self.audit.cache_hit(session, request_id);
                return FetchResponse::RequestAccepted { request_id };
            }
        }
        self.audit.cache_miss(session, request_id);

        // Kick off the fetch.
        self.audit.navigate_start(session, request_id);

        let profile = {
            let s = self.sessions.get(idx).unwrap();
            let mut profile = s.policy;
            profile.max_redirects = core::cmp::min(profile.max_redirects, redirect.max_redirects);
            profile
        };

        let mut events: [Option<FetchEvent>; 64] = [None; 64];
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
                self.origins
                    .update_top_origin(session, Origin::from_url(&url));
                let s = self.sessions.get_mut(idx).unwrap();
                s.push_nav(&url);
            }
            FetchOutcome::PolicyBlocked(reason) => {
                self.audit
                    .policy_blocked(session, request_id, policy_reason_bytes(reason));
            }
            FetchOutcome::Error(kind) => {
                self.audit
                    .internal_error(session, request_id, fetch_error_kind_bytes(kind));
            }
            FetchOutcome::Redirect {
                status,
                location,
                location_len,
            } => {
                let s = self.sessions.get_mut(idx).unwrap();
                if redirect.max_redirects == 0 {
                    let mut message = [0u8; ERROR_MSG_MAX];
                    let msg = b"redirects disabled by policy";
                    let msg_len = msg.len().min(ERROR_MSG_MAX);
                    message[..msg_len].copy_from_slice(&msg[..msg_len]);
                    s.enqueue(FetchEvent::FetchError {
                        request_id,
                        kind: FetchErrorKind::TooManyRedirects,
                        message,
                        msg_len,
                    });
                    self.audit
                        .internal_error(session, request_id, b"redirect-disabled");
                    return FetchResponse::RequestAccepted { request_id };
                }
                if !redirect.follow_cross_origin {
                    if let Some(target_url) = Url::parse(&location[..location_len]) {
                        let from_origin = Origin::from_url(&url);
                        let to_origin = Origin::from_url(&target_url);
                        if !from_origin.same_origin(&to_origin) {
                            s.enqueue(FetchEvent::PolicyBlocked {
                                request_id,
                                reason: PolicyBlockReason::OriginNotAllowed,
                            });
                            self.audit.policy_blocked(
                                session,
                                request_id,
                                b"redirect-cross-origin",
                            );
                            return FetchResponse::RequestAccepted { request_id };
                        }
                    }
                }
                self.audit
                    .redirect_followed(session, request_id, &location[..location_len]);
                // Reconstruct "from" URL from the Url struct fields.
                let mut from = [0u8; URL_MAX];
                let mut fpos = 0usize;
                let sstr = url.scheme.as_str().as_bytes();
                let sc = sstr.len().min(URL_MAX - fpos);
                from[fpos..fpos + sc].copy_from_slice(&sstr[..sc]);
                fpos += sc;
                if fpos + 3 < URL_MAX {
                    from[fpos..fpos + 3].copy_from_slice(b"://");
                    fpos += 3;
                }
                let hc = url.host_len.min(URL_MAX - fpos);
                from[fpos..fpos + hc].copy_from_slice(&url.host[..hc]);
                fpos += hc;
                let pc = url.path_len.min(URL_MAX - fpos);
                from[fpos..fpos + pc].copy_from_slice(&url.path[..pc]);
                fpos += pc;
                let fl = fpos;
                let mut to = [0u8; URL_MAX];
                let tl = location_len.min(URL_MAX);
                to[..tl].copy_from_slice(&location[..tl]);
                s.enqueue(FetchEvent::Redirect {
                    request_id,
                    from_url: from,
                    from_url_len: fl,
                    to_url: to,
                    to_url_len: tl,
                    status: crate::fetch_service::types::StatusCode(status),
                });
            }
        }

        FetchResponse::RequestAccepted { request_id }
    }

    // -----------------------------------------------------------------------
    // Subscribe / Unsubscribe
    // -----------------------------------------------------------------------

    fn do_subscribe(&mut self, session: SessionId, cap: Cap) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        if let Some(idx) = self.sessions.find(session) {
            self.sessions.get_mut(idx).unwrap().subscribed = true;
            FetchResponse::Subscribed
        } else {
            FetchResponse::Error(FetchError::InvalidSession)
        }
    }

    fn do_unsubscribe(&mut self, session: SessionId, cap: Cap) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        if let Some(idx) = self.sessions.find(session) {
            self.sessions.get_mut(idx).unwrap().subscribed = false;
            FetchResponse::Ok
        } else {
            FetchResponse::Error(FetchError::InvalidSession)
        }
    }

    // -----------------------------------------------------------------------
    // Abort
    // -----------------------------------------------------------------------

    fn do_abort(
        &mut self,
        session: SessionId,
        cap: Cap,
        request_id: RequestId,
    ) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        self.audit.request_aborted(session, request_id);
        // Transport-level abort is best-effort; the session will see no more
        // events for this request_id after `AbortRequest`.
        FetchResponse::Ok
    }

    // -----------------------------------------------------------------------
    // AcceptDownload / RejectDownload
    // -----------------------------------------------------------------------

    fn do_accept_download(
        &mut self,
        session: SessionId,
        cap: Cap,
        download_id: DownloadId,
        dest_path: &[u8],
    ) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        if self.downloads.accept(download_id, session, dest_path) {
            FetchResponse::Ok
        } else {
            FetchResponse::Error(FetchError::InvalidDownload)
        }
    }

    fn do_reject_download(
        &mut self,
        session: SessionId,
        cap: Cap,
        download_id: DownloadId,
    ) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        if self.downloads.reject(download_id, session) {
            FetchResponse::Ok
        } else {
            FetchResponse::Error(FetchError::InvalidDownload)
        }
    }

    // -----------------------------------------------------------------------
    // PollEvents
    // -----------------------------------------------------------------------

    fn do_poll_events(&mut self, session: SessionId, cap: Cap) -> FetchResponse {
        if !self.verify_cap(session, cap) {
            return FetchResponse::Error(FetchError::InvalidCapability);
        }
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return FetchResponse::Error(FetchError::InvalidSession),
        };
        let mut events = [None; 8];
        let count = self
            .sessions
            .get_mut(idx)
            .unwrap()
            .drain_events(&mut events);
        FetchResponse::Events { events, count }
    }

    // -----------------------------------------------------------------------
    // Capability verification
    // -----------------------------------------------------------------------

    fn verify_cap(&self, session: SessionId, cap: Cap) -> bool {
        match self.sessions.find(session) {
            Some(idx) => self
                .sessions
                .get(idx)
                .map(|s| s.cap == cap && cap.is_valid())
                .unwrap_or(false),
            None => false,
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
pub fn handle_request(req: FetchRequest) -> FetchResponse {
    BROWSER_SERVICE.lock().handle_request(req)
}
