//! Browser backend security policy enforcement.
//!
//! `BrowserPolicy` is a zero-copy, stateless checker.  All state lives in
//! `session.rs`; policy only inspects values passed to it and returns
//! a verdict.

#![allow(dead_code)]

use super::protocol::PolicyBlockReason;
use super::types::{Scheme, Url};

// ---------------------------------------------------------------------------
// Tunable limits
// ---------------------------------------------------------------------------

/// Maximum response body that will be buffered for a single request (bytes).
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum number of redirect hops before we abort.
pub const MAX_REDIRECTS: u8 = 10;

/// Minimum content-length for a download-offer prompt (bytes).
pub const DOWNLOAD_PROMPT_THRESHOLD: u64 = 1024 * 1024; // 1 MiB

// ---------------------------------------------------------------------------
// Allowed URL schemes
// ---------------------------------------------------------------------------

/// Schemes the browser backend will actually fetch.
/// All others are blocked with `SchemeNotAllowed`.
pub const ALLOWED_SCHEMES: &[Scheme] = &[Scheme::Http, Scheme::Https];

// ---------------------------------------------------------------------------
// BrowserPolicy
// ---------------------------------------------------------------------------

/// Stateless policy checker.
pub struct BrowserPolicy;

impl BrowserPolicy {
    // -----------------------------------------------------------------------
    // Scheme check
    // -----------------------------------------------------------------------

    /// Returns `None` if the scheme is allowed, or a reason if it is blocked.
    pub fn check_scheme(&self, scheme: Scheme) -> Option<PolicyBlockReason> {
        if ALLOWED_SCHEMES.contains(&scheme) {
            None
        } else {
            Some(PolicyBlockReason::SchemeNotAllowed)
        }
    }

    // -----------------------------------------------------------------------
    // Mixed-content check
    // -----------------------------------------------------------------------

    /// Block a plaintext (`http`) subresource on a secure (`https`) page.
    ///
    /// Top-level navigations from HTTPS → HTTP are *not* blocked here —
    /// that is handled by the redirect policy.
    pub fn check_mixed_content(
        &self,
        page_scheme:     Scheme,
        resource_scheme: Scheme,
        is_subresource:  bool,
    ) -> Option<PolicyBlockReason> {
        if is_subresource
            && page_scheme    == Scheme::Https
            && resource_scheme == Scheme::Http
        {
            Some(PolicyBlockReason::MixedContent)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Redirect validation
    // -----------------------------------------------------------------------

    /// Validate a single redirect hop.
    ///
    /// - Blocks HTTP→HTTPS downgrade (HTTPS → HTTP is an active downgrade).
    /// - Blocks `data:`, `blob:`, and other non-http(s) redirect targets.
    /// - Enforces `max_redirects` counter.
    pub fn check_redirect(
        &self,
        from_scheme:   Scheme,
        to_url:        &Url,
        redirect_count: u8,
    ) -> Option<PolicyBlockReason> {
        if redirect_count >= MAX_REDIRECTS {
            // caller maps this to FetchErrorKind::TooManyRedirects
            return Some(PolicyBlockReason::SchemeNotAllowed);
        }
        // Disallow redirecting to opaque schemes.
        if let Some(reason) = self.check_scheme(to_url.scheme) {
            return Some(reason);
        }
        // Actively downgrading a secure origin to plaintext is blocked.
        if from_scheme == Scheme::Https && to_url.scheme == Scheme::Http {
            return Some(PolicyBlockReason::MixedContent);
        }
        None
    }

    // -----------------------------------------------------------------------
    // Response body size
    // -----------------------------------------------------------------------

    /// Returns `true` if the declared `content_length` exceeds the hard limit.
    pub fn body_too_large(&self, content_length: Option<u64>) -> bool {
        match content_length {
            Some(n) => n > MAX_BODY_BYTES as u64,
            None    => false, // streaming — enforce lazily in fetch.rs
        }
    }

    /// Returns `true` if the response should be treated as a download offer
    /// rather than an inline body (either the MIME type is binary, or the
    /// content-length is large).
    pub fn should_offer_download(
        &self,
        is_attachment:  bool,
        content_length: Option<u64>,
    ) -> bool {
        if is_attachment { return true; }
        match content_length {
            Some(n) => n >= DOWNLOAD_PROMPT_THRESHOLD,
            None    => false,
        }
    }

    // -----------------------------------------------------------------------
    // TLS certificate errors
    // -----------------------------------------------------------------------

    /// Block a request because its TLS handshake failed.
    pub fn check_tls_handshake_failed(&self, secure: bool) -> Option<PolicyBlockReason> {
        if secure {
            Some(PolicyBlockReason::TlsCertificateError)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Origin-based filtering
    // -----------------------------------------------------------------------

    /// A final-stage host denylist check.
    ///
    /// `denylist` is a slice of lowercase ASCII hostnames.  Returns
    /// `Some(OriginNotAllowed)` if the request host is found.
    pub fn check_denylist(
        &self,
        host:     &[u8],
        host_len: usize,
        denylist: &[[u8; 253]],
    ) -> Option<PolicyBlockReason> {
        let h = &host[..host_len];
        for entry in denylist {
            let entry_len = entry.iter().position(|&b| b == 0).unwrap_or(253);
            if entry[..entry_len].eq_ignore_ascii_case(h) {
                return Some(PolicyBlockReason::OriginNotAllowed);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// PolicyProfile
// ---------------------------------------------------------------------------

/// A per-session collection of policy settings.
///
/// Stored in `BrowserSession`; consulted by `fetch.rs` on every request.
#[derive(Copy, Clone, Debug)]
pub struct PolicyProfile {
    pub allow_mixed_content: bool,
    pub max_redirects:       u8,
    pub max_body_bytes:      usize,
    /// Compact denylist — zero-terminated ASCII hostnames.
    pub denylist:            [[u8; 253]; 8],
    pub denylist_len:        usize,
}

impl PolicyProfile {
    pub const DEFAULT: Self = Self {
        allow_mixed_content: false,
        max_redirects:       MAX_REDIRECTS,
        max_body_bytes:      MAX_BODY_BYTES,
        denylist:            [[0u8; 253]; 8],
        denylist_len:        0,
    };

    /// Add a hostname to the denylist.  No-op if full.
    pub fn add_denylist(&mut self, host: &[u8]) {
        if self.denylist_len >= 8 { return; }
        let len = host.len().min(253);
        let mut entry = [0u8; 253];
        for (i, &b) in host[..len].iter().enumerate() {
            entry[i] = b.to_ascii_lowercase();
        }
        self.denylist[self.denylist_len] = entry;
        self.denylist_len += 1;
    }
}
