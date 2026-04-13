/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Browser backend kernel module.
//!
//! This module implements the in-kernel layer of the Oreulius browser stack:
//!
//! - **Network I/O**: DNS, TCP, TLS (transport.rs)
//! - **HTTP/1.1**: request builder + streaming response parser (fetch.rs)
//! - **Session management**: navigation history, event queues (session.rs)
//! - **Origin model**: same-origin enforcement, per-session allowlists (origin.rs)
//! - **Cookie storage**: SameSite/Secure/HttpOnly enforcement (cookie_jar.rs)
//! - **Response cache**: ETag/Last-Modified validation, TTL eviction (cache.rs)
//! - **Content filter**: MIME sniffing guardrails, attachment classification (content_filter.rs)
//! - **Download manager**: capability-gated download jobs (downloads.rs)
//! - **Per-origin storage**: VFS-backed per-session key/value store (storage.rs)
//! - **Security policy**: mixed-content blocking, denylist, redirect limits (policy.rs)
//! - **Audit log**: ring-buffer event history (audit.rs)
//! - **Temporal**: snapshot/restore stubs (temporal.rs)
//!
//! **Explicitly out-of-kernel**:
//! HTML/CSS/JS parsers, layout engine, rendering pipeline, font rasterisation,
//! DOM, CSSOM, JavaScript engine — these all live in the userspace renderer
//! process and are fed raw byte streams by this module.

#![allow(unused_imports)]

pub mod audit;
pub mod cache;
pub mod content_filter;
pub mod cookie_jar;
pub mod downloads;
pub mod fetch;
pub mod headers;
pub mod origin;
pub mod policy;
pub mod protocol;
pub mod service;
pub mod session;
pub mod storage;
pub mod temporal;
pub mod transport;
pub mod types;

// ---------------------------------------------------------------------------
// Public re-exports for callers in the kernel
// ---------------------------------------------------------------------------

pub use protocol::{
    BrowserError, BrowserEvent, BrowserRequest, BrowserResponse, FetchErrorKind, PolicyBlockReason,
    ResponseHeader, TlsHandshakeResult,
};
pub use types::{
    BrowserCap, BrowserSessionId, DownloadId, HttpMethod, MimeType, Origin, RequestId, Scheme,
    StatusCode, Url,
};

// ---------------------------------------------------------------------------
// Module lifecycle
// ---------------------------------------------------------------------------

/// Initialise the browser backend.  Called once at kernel boot.
pub fn init() {
    service::init();
}

/// Advance the internal epoch counter.  Called by the kernel timer tick.
pub fn tick() {
    service::tick();
}

/// Dispatch a single IPC request from a frontend client.
pub fn handle_request(req: BrowserRequest) -> BrowserResponse {
    service::handle_request(req)
}
