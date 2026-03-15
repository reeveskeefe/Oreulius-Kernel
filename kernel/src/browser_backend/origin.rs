//! Origin model: same-origin enforcement and per-session allowlists.
//!
//! Every navigation or subresource request passes through `OriginTable` before
//! `fetch` is allowed to open a connection.  The table is checked in O(n)
//! over a small fixed array; no heap allocation is needed.

#![allow(dead_code)]

use super::types::{BrowserSessionId, Origin, Scheme, Url};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of per-session origin allowlist entries.
pub const MAX_ORIGIN_ALLOWLIST: usize = 32;

/// Maximum number of per-session site-isolation records.
pub const MAX_SESSION_ORIGINS: usize = 16;

// ---------------------------------------------------------------------------
// OriginPolicy
// ---------------------------------------------------------------------------

/// The top-level origin of a browser session (i.e. the page origin).
///
/// A session may only embed cross-origin resources if they satisfy its policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OriginPolicy {
    /// The page origin.
    pub top_origin: Origin,
    /// How many cross-origin navigations are permitted.
    pub allow_cross_origin: bool,
    /// Allowlisted origins — subresource loads to non-listed origins are
    /// blocked regardless of `allow_cross_origin`.
    pub allowlist:      [Origin; MAX_ORIGIN_ALLOWLIST],
    pub allowlist_len:  usize,
}

impl OriginPolicy {
    /// An open policy (no allowlist restriction, cross-origin allowed).
    pub const fn open(top_origin: Origin) -> Self {
        Self {
            top_origin,
            allow_cross_origin: true,
            allowlist: [Origin::OPAQUE; MAX_ORIGIN_ALLOWLIST],
            allowlist_len: 0,
        }
    }

    /// A strict same-origin policy (no cross-origin requests at all).
    pub const fn same_origin_only(top_origin: Origin) -> Self {
        Self {
            top_origin,
            allow_cross_origin: false,
            allowlist: [Origin::OPAQUE; MAX_ORIGIN_ALLOWLIST],
            allowlist_len: 0,
        }
    }

    /// Add an origin to the allowlist.  No-op if full.
    pub fn add_allowlist(&mut self, o: Origin) {
        if self.allowlist_len < MAX_ORIGIN_ALLOWLIST {
            self.allowlist[self.allowlist_len] = o;
            self.allowlist_len += 1;
        }
    }

    fn in_allowlist(&self, o: &Origin) -> bool {
        self.allowlist[..self.allowlist_len]
            .iter()
            .any(|a| a.same_origin(o))
    }
}

// ---------------------------------------------------------------------------
// Cross-origin classification
// ---------------------------------------------------------------------------

/// Classification of a request relative to its context origin.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OriginClassification {
    SameOrigin,
    SameSite,
    CrossOrigin,
    Opaque,
}

/// Classify `target` relative to `context`.
pub fn classify(context: &Origin, target: &Origin) -> OriginClassification {
    if context.is_opaque() || target.is_opaque() {
        return OriginClassification::Opaque;
    }
    if context.same_origin(target) {
        return OriginClassification::SameOrigin;
    }
    if same_site(context, target) {
        return OriginClassification::SameSite;
    }
    OriginClassification::CrossOrigin
}

/// Two origins are "same-site" when their registrable domain matches
/// regardless of port.  We approximate this as: same scheme + same host
/// (the last two hostname labels).
fn same_site(a: &Origin, b: &Origin) -> bool {
    if a.scheme != b.scheme { return false; }
    let a_host = &a.host[..a.host_len];
    let b_host = &b.host[..b.host_len];
    registrable_domain(a_host) == registrable_domain(b_host)
}

/// Return the slice corresponding to the last two dot-separated labels.
fn registrable_domain(host: &[u8]) -> &[u8] {
    let dots: [usize; 2] = {
        let mut positions = [usize::MAX; 2];
        let mut found = 0;
        // Scan right-to-left looking for dots.
        let mut i = host.len();
        while i > 0 && found < 2 {
            i -= 1;
            if host[i] == b'.' {
                positions[found] = i;
                found += 1;
            }
        }
        positions
    };
    // If we found at least one dot, start after the second-to-last dot.
    if dots[1] != usize::MAX {
        &host[dots[1] + 1..]
    } else if dots[0] != usize::MAX {
        &host[dots[0] + 1..]
    } else {
        host
    }
}

// ---------------------------------------------------------------------------
// Navigation / subresource checks
// ---------------------------------------------------------------------------

/// Result of an origin check.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OriginCheckResult {
    /// Request is permitted.
    Allowed,
    /// Request is blocked because the origin is not in the allowlist.
    BlockedByAllowlist,
    /// Request is blocked because cross-origin is disabled.
    BlockedCrossOrigin,
    /// Request is blocked because the target is opaque.
    BlockedOpaque,
}

/// Check whether a top-level navigation to `target_url` is allowed.
pub fn check_navigation(policy: &OriginPolicy, target_url: &Url) -> OriginCheckResult {
    let target_origin = Origin::from_url(target_url);
    check_origin(policy, &target_origin, /* is_top_level */ true)
}

/// Check whether a subresource (image, script, XHR, …) load from
/// `resource_url` is allowed given `policy`.
pub fn check_subresource(policy: &OriginPolicy, resource_url: &Url) -> OriginCheckResult {
    let target_origin = Origin::from_url(resource_url);
    check_origin(policy, &target_origin, /* is_top_level */ false)
}

fn check_origin(
    policy: &OriginPolicy,
    target: &Origin,
    is_top_level: bool,
) -> OriginCheckResult {
    if target.is_opaque() {
        return OriginCheckResult::BlockedOpaque;
    }
    if policy.top_origin.same_origin(target) {
        return OriginCheckResult::Allowed;
    }
    // Cross-origin path.
    if !policy.allow_cross_origin && !is_top_level {
        return OriginCheckResult::BlockedCrossOrigin;
    }
    if policy.allowlist_len > 0 && !policy.in_allowlist(target) {
        return OriginCheckResult::BlockedByAllowlist;
    }
    OriginCheckResult::Allowed
}

// ---------------------------------------------------------------------------
// OriginTable — per-kernel site-isolation map
// ---------------------------------------------------------------------------

/// A small global table mapping `BrowserSessionId` → `OriginPolicy`.
///
/// The kernel service (`service.rs`) holds one instance; checked on every
/// `Navigate` and subresource dispatch.
pub struct OriginTable {
    entries:  [OriginEntry; MAX_SESSION_ORIGINS],
    count:    usize,
}

#[derive(Copy, Clone)]
struct OriginEntry {
    session: BrowserSessionId,
    policy:  OriginPolicy,
    active:  bool,
}

impl OriginEntry {
    const EMPTY: Self = Self {
        session: BrowserSessionId(0),
        policy:  OriginPolicy::same_origin_only(Origin::OPAQUE),
        active:  false,
    };
}

impl OriginTable {
    pub const fn new() -> Self {
        Self {
            entries: [OriginEntry::EMPTY; MAX_SESSION_ORIGINS],
            count: 0,
        }
    }

    /// Register a new session with an initial policy.
    /// Returns `false` if the table is full.
    pub fn register(&mut self, session: BrowserSessionId, policy: OriginPolicy) -> bool {
        if self.count >= MAX_SESSION_ORIGINS { return false; }
        // Reuse a free slot first.
        for e in &mut self.entries {
            if !e.active {
                e.session = session;
                e.policy  = policy;
                e.active  = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Remove a session's entry.
    pub fn unregister(&mut self, session: BrowserSessionId) {
        for e in &mut self.entries {
            if e.active && e.session == session {
                e.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Update the top-level origin for `session` (called on navigation commit).
    pub fn update_top_origin(&mut self, session: BrowserSessionId, origin: Origin) {
        for e in &mut self.entries {
            if e.active && e.session == session {
                e.policy.top_origin = origin;
                return;
            }
        }
    }

    /// Look up the policy for a session.
    pub fn policy(&self, session: BrowserSessionId) -> Option<&OriginPolicy> {
        for e in &self.entries {
            if e.active && e.session == session {
                return Some(&e.policy);
            }
        }
        None
    }

    /// Check a navigation for `session`.
    pub fn check_navigation(
        &self,
        session:    BrowserSessionId,
        target_url: &Url,
    ) -> OriginCheckResult {
        match self.policy(session) {
            Some(p) => check_navigation(p, target_url),
            None    => OriginCheckResult::Allowed, // session not yet registered
        }
    }

    /// Check a subresource for `session`.
    pub fn check_subresource(
        &self,
        session:      BrowserSessionId,
        resource_url: &Url,
    ) -> OriginCheckResult {
        match self.policy(session) {
            Some(p) => check_subresource(p, resource_url),
            None    => OriginCheckResult::Allowed,
        }
    }
}
