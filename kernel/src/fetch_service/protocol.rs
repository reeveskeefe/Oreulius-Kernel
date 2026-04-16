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


//! IPC protocol between the fetch service kernel service and frontend clients.
//!
//! Clients communicate over the kernel IPC service layer by sending
//! `FetchRequest` values and receiving `FetchResponse` / `FetchEvent`
//! values back.  All types are fixed-size and heap-free.

#![allow(dead_code)]

use super::types::{
    Cap, SessionId, DownloadId, HttpMethod, MimeType, RedirectPolicy, RequestId,
    StatusCode, Url, URL_MAX,
};
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Request envelope
// ---------------------------------------------------------------------------

/// Every request from a frontend client to the fetch service.
pub enum FetchRequest {
    /// Open a new fetch session (one per tab / navigation context).
    /// The caller supplies its own PID for capability bookkeeping.
    OpenSession {
        pid: ProcessId,
        /// Human-readable profile name (e.g. b"default\0…").
        profile: [u8; 32],
    },

    /// Close a session and revoke all its capabilities.
    CloseSession {
        session: SessionId,
        cap: Cap,
    },

    /// Navigate the session to a URL (starts a fetch, streams events back).
    Navigate {
        session: SessionId,
        cap: Cap,
        url: [u8; URL_MAX],
        url_len: usize,
        method: HttpMethod,
        /// Request body (POST/PUT).  Ignored for GET/HEAD.
        body: [u8; 4096],
        body_len: usize,
        redirect: RedirectPolicy,
    },

    /// Subscribe to events for a session (returns an event-channel capability).
    Subscribe {
        session: SessionId,
        cap: Cap,
    },

    /// Unsubscribe from events.
    Unsubscribe {
        session: SessionId,
        cap: Cap,
    },

    /// Abort an in-flight request.
    AbortRequest {
        session: SessionId,
        cap: Cap,
        request_id: RequestId,
    },

    /// Accept or reject a download offered via `FetchEvent::DownloadOffered`.
    AcceptDownload {
        session: SessionId,
        cap: Cap,
        download_id: DownloadId,
        /// VFS path for the output file (capability-gated write).
        dest_path: [u8; 256],
        dest_len: usize,
    },

    RejectDownload {
        session: SessionId,
        cap: Cap,
        download_id: DownloadId,
    },

    /// Poll for pending events (non-blocking).
    PollEvents {
        session: SessionId,
        cap: Cap,
    },
}

// ---------------------------------------------------------------------------
// Response envelope
// ---------------------------------------------------------------------------

/// Synchronous response to a `FetchRequest`.
pub enum FetchResponse {
    /// Session was opened successfully.
    SessionGranted {
        session: SessionId,
        cap: Cap,
    },

    /// A `Navigate` was accepted; `request_id` identifies the in-flight fetch.
    RequestAccepted { request_id: RequestId },

    /// Subscribe accepted; events will be delivered via poll or push.
    Subscribed,

    /// Generic success for commands that don't return data.
    Ok,

    /// Error response.
    Error(FetchError),

    /// One or more pending events (up to 8 per poll).
    Events {
        events: [Option<FetchEvent>; 8],
        count: usize,
    },
}

// ---------------------------------------------------------------------------
// Event stream
// ---------------------------------------------------------------------------

pub const HEADER_VALUE_MAX: usize = 256;
pub const HEADER_NAME_MAX: usize = 64;
pub const MAX_RESPONSE_HEADERS: usize = 32;
pub const BODY_CHUNK_MAX: usize = 4096;
pub const ERROR_MSG_MAX: usize = 128;

/// A single HTTP response header.
#[derive(Clone, Copy)]
pub struct ResponseHeader {
    pub name: [u8; HEADER_NAME_MAX],
    pub name_len: usize,
    pub value: [u8; HEADER_VALUE_MAX],
    pub value_len: usize,
}

impl ResponseHeader {
    pub const fn empty() -> Self {
        ResponseHeader {
            name: [0; HEADER_NAME_MAX],
            name_len: 0,
            value: [0; HEADER_VALUE_MAX],
            value_len: 0,
        }
    }
}

/// TLS handshake outcome delivered with `FetchEvent::TlsState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandshakeResult {
    /// TLS 1.3 established; the connection is secure.
    Established,
    /// Handshake failed (certificate error, timeout, etc.).
    Failed,
    /// Connection is plaintext (HTTP, not HTTPS).
    Plaintext,
}

/// Events streamed to subscribed clients.
#[derive(Clone, Copy)]
pub enum FetchEvent {
    /// Response headers received.  Emitted once per redirect and once for
    /// the final response.
    Headers {
        request_id: RequestId,
        status: StatusCode,
        mime: MimeType,
        content_length: Option<u64>,
        headers: [ResponseHeader; MAX_RESPONSE_HEADERS],
        header_count: usize,
    },

    /// A chunk of the response body.  May fire many times for large resources.
    BodyChunk {
        request_id: RequestId,
        data: [u8; BODY_CHUNK_MAX],
        data_len: usize,
        /// True when this is the last chunk.
        is_last: bool,
    },

    /// The server issued a redirect.  Emitted before following it.
    Redirect {
        request_id: RequestId,
        from_url: [u8; URL_MAX],
        from_url_len: usize,
        to_url: [u8; URL_MAX],
        to_url_len: usize,
        status: StatusCode,
    },

    /// A request was blocked by policy (CSP-like, mixed-content, allowlist).
    PolicyBlocked {
        request_id: RequestId,
        reason: PolicyBlockReason,
    },

    /// TLS handshake result for the current navigation.
    TlsState {
        request_id: RequestId,
        result: TlsHandshakeResult,
    },

    /// A response with a `Content-Disposition: attachment` or binary MIME
    /// type was received and needs user approval before writing to disk.
    DownloadOffered {
        request_id: RequestId,
        download_id: DownloadId,
        filename: [u8; 256],
        filename_len: usize,
        mime: MimeType,
        size_hint: Option<u64>,
    },

    /// A download job completed.
    DownloadComplete {
        download_id: DownloadId,
        bytes_written: u64,
    },

    /// The request completed without error.
    Complete { request_id: RequestId },

    /// The request failed.
    FetchError {
        request_id: RequestId,
        kind: FetchErrorKind,
        message: [u8; ERROR_MSG_MAX],
        msg_len: usize,
    },
}

/// Reason a request was blocked by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBlockReason {
    /// Mixed content: HTTPS page loading HTTP resource.
    MixedContent,
    /// Origin not on session allowlist.
    OriginNotAllowed,
    /// Scheme not permitted (e.g. `file://`).
    SchemeNotAllowed,
    /// The URL matched a known malicious/ad pattern.
    Filtered,
    /// Certificate verification failed.
    TlsCertificateError,
}

/// Why a fetch failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchErrorKind {
    /// DNS resolution failed.
    DnsFailure,
    /// TCP connection refused or timed out.
    ConnectionFailed,
    /// TLS handshake failed.
    TlsHandshakeFailed,
    /// Server closed connection before a complete response.
    ConnectionReset,
    /// Response parse error (e.g. invalid status line).
    ProtocolError,
    /// Exceeded the redirect limit.
    TooManyRedirects,
    /// Request was aborted by the client.
    Aborted,
    /// Internal kernel error.
    InternalError,
}

// ---------------------------------------------------------------------------
// Error variants
// ---------------------------------------------------------------------------

/// Errors returned synchronously in `FetchResponse::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The session ID does not exist.
    InvalidSession,
    /// The capability token is invalid or revoked.
    InvalidCapability,
    /// Too many sessions are already open.
    SessionQuotaExceeded,
    /// Too many concurrent requests.
    RequestQuotaExceeded,
    /// The URL could not be parsed.
    InvalidUrl,
    /// The scheme is not supported.
    UnsupportedScheme,
    /// The download ID is unknown.
    InvalidDownload,
    /// The VFS path could not be written.
    StorageError,
    /// Internal error.
    InternalError,
}
