/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Per-origin cookie storage with SameSite / Secure / HttpOnly enforcement.
//!
//! Cookies are stored in a fixed-size flat array; each entry is bounded to
//! `COOKIE_NAME_MAX` + `COOKIE_VALUE_MAX` bytes.  No heap allocation.

#![allow(dead_code)]

use super::types::{BrowserSessionId, Origin, Scheme};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COOKIE_NAME_MAX: usize = 128;
pub const COOKIE_VALUE_MAX: usize = 4096;
pub const MAX_COOKIES: usize = 128;

// ---------------------------------------------------------------------------
// SameSite
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

// ---------------------------------------------------------------------------
// CookieEntry
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct CookieEntry {
    pub name: [u8; COOKIE_NAME_MAX],
    pub name_len: usize,
    pub value: [u8; COOKIE_VALUE_MAX],
    pub value_len: usize,
    /// Domain scope (lowercase, leading dot stripped).
    pub domain: [u8; 253],
    pub domain_len: usize,
    /// Path scope.
    pub path: [u8; 256],
    pub path_len: usize,
    pub session: BrowserSessionId,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    /// Absolute expiry epoch (0 = session cookie).
    pub expires: u64,
    pub active: bool,
}

impl CookieEntry {
    pub const EMPTY: Self = Self {
        name: [0; COOKIE_NAME_MAX],
        name_len: 0,
        value: [0; COOKIE_VALUE_MAX],
        value_len: 0,
        domain: [0; 253],
        domain_len: 0,
        path: [0; 256],
        path_len: 0,
        session: BrowserSessionId(0),
        http_only: false,
        secure: false,
        same_site: SameSite::Lax,
        expires: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// SetCookieDirectives
// ---------------------------------------------------------------------------

/// Parsed attributes from a `Set-Cookie` header value.
#[derive(Clone, Copy)]
pub struct SetCookieDirectives {
    pub domain: [u8; 253],
    pub domain_len: usize,
    pub path: [u8; 256],
    pub path_len: usize,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<SameSite>,
    pub max_age: Option<i64>,
}

impl Default for SetCookieDirectives {
    fn default() -> Self {
        Self {
            domain: [0u8; 253],
            domain_len: 0,
            path: [0u8; 256],
            path_len: 0,
            http_only: false,
            secure: false,
            same_site: None,
            max_age: None,
        }
    }
}

/// Parse the attributes half of a `Set-Cookie` value (the part after ';').
pub fn parse_set_cookie_attrs(attrs: &[u8], out: &mut SetCookieDirectives) {
    let mut pos = 0usize;
    while pos < attrs.len() {
        // Find next ';'.
        let end = attrs[pos..]
            .iter()
            .position(|&b| b == b';')
            .map(|e| e + pos)
            .unwrap_or(attrs.len());
        let attr = trim_ascii(&attrs[pos..end]);
        pos = end + 1; // skip ';'

        if attr.is_empty() {
            continue;
        }

        // Split on '='.
        if let Some(eq) = attr.iter().position(|&b| b == b'=') {
            let key = trim_ascii(&attr[..eq]);
            let val = trim_ascii(&attr[eq + 1..]);
            if key.eq_ignore_ascii_case(b"domain") {
                // Strip leading dot.
                let v = if !val.is_empty() && val[0] == b'.' {
                    &val[1..]
                } else {
                    val
                };
                let len = v.len().min(253);
                out.domain[..len].copy_from_slice(&v[..len]);
                out.domain_len = len;
            } else if key.eq_ignore_ascii_case(b"path") {
                let len = val.len().min(256);
                out.path[..len].copy_from_slice(&val[..len]);
                out.path_len = len;
            } else if key.eq_ignore_ascii_case(b"samesite") {
                out.same_site = Some(if val.eq_ignore_ascii_case(b"strict") {
                    SameSite::Strict
                } else if val.eq_ignore_ascii_case(b"none") {
                    SameSite::None
                } else {
                    SameSite::Lax
                });
            } else if key.eq_ignore_ascii_case(b"max-age") {
                out.max_age = parse_i64(val);
            }
        } else {
            // Flag attributes.
            if attr.eq_ignore_ascii_case(b"httponly") {
                out.http_only = true;
            } else if attr.eq_ignore_ascii_case(b"secure") {
                out.secure = true;
            }
        }
    }
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &s[start..end]
}

fn parse_i64(b: &[u8]) -> Option<i64> {
    let b = trim_ascii(b);
    if b.is_empty() {
        return None;
    }
    let (neg, b) = if b[0] == b'-' {
        (true, &b[1..])
    } else {
        (false, b)
    };
    let mut v = 0i64;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.saturating_mul(10).saturating_add((c - b'0') as i64);
    }
    Some(if neg { -v } else { v })
}

// ---------------------------------------------------------------------------
// CookieJar
// ---------------------------------------------------------------------------

pub struct CookieJar {
    entries: [CookieEntry; MAX_COOKIES],
    count: usize,
}

impl CookieJar {
    pub const fn new() -> Self {
        Self {
            entries: [CookieEntry::EMPTY; MAX_COOKIES],
            count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Store a cookie
    // -----------------------------------------------------------------------

    /// Store a cookie from a `Set-Cookie` header.
    ///
    /// `name` and `value` come from the `cookie_pair` half.
    /// `attrs` come from `parse_set_cookie_attrs`.
    /// `request_scheme` is the scheme of the URL that received the response.
    /// `request_host` is the normalized hostname.
    pub fn set(
        &mut self,
        session: BrowserSessionId,
        name: &[u8],
        value: &[u8],
        attrs: &SetCookieDirectives,
        request_scheme: Scheme,
        request_host: &[u8],
        current_epoch: u64,
    ) -> bool {
        // Secure cookies must only arrive over HTTPS.
        if attrs.secure && request_scheme != Scheme::Https {
            return false;
        }

        // If `Domain` attribute is absent, scope to request host.
        let (dom, dom_len) = if attrs.domain_len > 0 {
            (attrs.domain, attrs.domain_len)
        } else {
            let mut d = [0u8; 253];
            let len = request_host.len().min(253);
            d[..len].copy_from_slice(&request_host[..len]);
            (d, len)
        };

        // Compute expiry.
        let expires = match attrs.max_age {
            Some(age) if age > 0 => current_epoch.saturating_add(age as u64),
            Some(age) if age <= 0 => {
                // Delete the cookie.
                self.delete(session, name, &dom[..dom_len]);
                return true;
            }
            _ => 0, // session cookie
        };

        let name_len = name.len().min(COOKIE_NAME_MAX);
        let value_len = value.len().min(COOKIE_VALUE_MAX);
        let path_len = attrs.path_len.min(256);

        // Update existing entry first.
        for e in &mut self.entries {
            if e.active
                && e.session == session
                && e.name[..e.name_len] == name[..name_len]
                && e.domain[..e.domain_len] == dom[..dom_len]
            {
                e.value[..value_len].copy_from_slice(&value[..value_len]);
                e.value_len = value_len;
                e.http_only = attrs.http_only;
                e.secure = attrs.secure;
                e.same_site = attrs.same_site.unwrap_or(SameSite::Lax);
                e.expires = expires;
                e.path_len = path_len;
                if path_len > 0 {
                    e.path[..path_len].copy_from_slice(&attrs.path[..path_len]);
                }
                return true;
            }
        }

        // Insert new entry.
        if self.count >= MAX_COOKIES {
            return false;
        }
        for e in &mut self.entries {
            if !e.active {
                e.session = session;
                e.name_len = name_len;
                e.name[..name_len].copy_from_slice(&name[..name_len]);
                e.value_len = value_len;
                e.value[..value_len].copy_from_slice(&value[..value_len]);
                e.domain = dom;
                e.domain_len = dom_len;
                e.path_len = path_len;
                if path_len > 0 {
                    e.path[..path_len].copy_from_slice(&attrs.path[..path_len]);
                }
                e.http_only = attrs.http_only;
                e.secure = attrs.secure;
                e.same_site = attrs.same_site.unwrap_or(SameSite::Lax);
                e.expires = expires;
                e.active = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Build Cookie header value
    // -----------------------------------------------------------------------

    /// Write a `Cookie:` header value into `out` for the given request
    /// context.  Returns the number of bytes written.
    ///
    /// - `request_scheme`:  used for `Secure` enforcement
    /// - `request_host`:    domain-scope matching
    /// - `request_path`:    path-scope matching
    /// - `current_epoch`:   for expiry eviction
    /// - `is_cross_site`:   for SameSite enforcement
    pub fn build_cookie_header(
        &mut self,
        session: BrowserSessionId,
        out: &mut [u8],
        request_scheme: Scheme,
        request_host: &[u8],
        request_path: &[u8],
        current_epoch: u64,
        is_cross_site: bool,
    ) -> usize {
        let mut w = 0usize;
        let mut first = true;

        for e in &mut self.entries {
            if !e.active || e.session != session {
                continue;
            }

            // Expired?
            if e.expires != 0 && current_epoch > e.expires {
                e.active = false;
                self.count = self.count.saturating_sub(1);
                continue;
            }

            // Secure flag.
            if e.secure && request_scheme != Scheme::Https {
                continue;
            }

            // SameSite.
            if is_cross_site {
                match e.same_site {
                    SameSite::Strict => continue,
                    SameSite::Lax => {} // allowed on cross-site top-level nav
                    SameSite::None if e.secure => {}
                    SameSite::None => continue,
                }
            }

            // Domain matching.
            if !domain_matches(request_host, &e.domain[..e.domain_len]) {
                continue;
            }

            // Path matching.
            if e.path_len > 0 && !path_matches(request_path, &e.path[..e.path_len]) {
                continue;
            }

            // Write "name=value" pair.
            if !first {
                if w + 2 > out.len() {
                    break;
                }
                out[w] = b';';
                out[w + 1] = b' ';
                w += 2;
            }
            first = false;

            let pair_needed = e.name_len + 1 + e.value_len;
            if w + pair_needed > out.len() {
                break;
            }
            out[w..w + e.name_len].copy_from_slice(&e.name[..e.name_len]);
            w += e.name_len;
            out[w] = b'=';
            w += 1;
            out[w..w + e.value_len].copy_from_slice(&e.value[..e.value_len]);
            w += e.value_len;
        }
        w
    }

    // -----------------------------------------------------------------------
    // Delete / evict
    // -----------------------------------------------------------------------

    pub fn delete(&mut self, session: BrowserSessionId, name: &[u8], domain: &[u8]) {
        for e in &mut self.entries {
            if e.active
                && e.session == session
                && e.name[..e.name_len].eq_ignore_ascii_case(name)
                && e.domain[..e.domain_len].eq_ignore_ascii_case(domain)
            {
                e.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Remove all cookies belonging to `session`.
    pub fn purge_session(&mut self, session: BrowserSessionId) {
        for e in &mut self.entries {
            if e.active && e.session == session {
                e.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Directly insert a `CookieEntry` from a snapshot without applying any
    /// policy checks.  Used only by `temporal::restore`.  Returns `false` if
    /// the jar is full.
    pub fn restore_entry(&mut self, entry: CookieEntry) -> bool {
        if self.count >= MAX_COOKIES {
            return false;
        }
        for slot in &mut self.entries {
            if !slot.active {
                *slot = entry;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Iterate over all active cookie entries.  Used by `temporal::snapshot`.
    pub fn entries_iter(&self) -> impl Iterator<Item = &CookieEntry> {
        self.entries.iter().filter(|e| e.active)
    }
}

// ---------------------------------------------------------------------------
// Domain / path matching helpers
// ---------------------------------------------------------------------------

fn domain_matches(request_host: &[u8], cookie_domain: &[u8]) -> bool {
    // Exact match.
    if request_host.eq_ignore_ascii_case(cookie_domain) {
        return true;
    }
    // Suffix match: request_host ends with ".cookie_domain".
    if cookie_domain.len() < request_host.len() {
        let off = request_host.len() - cookie_domain.len();
        if request_host[off - 1] == b'.' && request_host[off..].eq_ignore_ascii_case(cookie_domain)
        {
            return true;
        }
    }
    false
}

fn path_matches(request_path: &[u8], cookie_path: &[u8]) -> bool {
    if cookie_path == b"/" {
        return true;
    }
    if request_path.starts_with(cookie_path) {
        let after = request_path.len() > cookie_path.len();
        if !after {
            return true;
        }
        return request_path[cookie_path.len()] == b'/';
    }
    false
}
