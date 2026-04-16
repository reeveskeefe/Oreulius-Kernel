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


//! HTTP response cache with ETag / Last-Modified validation and TTL eviction.
//!
//! The cache stores up to `MAX_CACHE_ENTRIES` fixed-size records.
//! Body data is stored in a flat ring buffer (`CACHE_BODY_POOL`).
//! No heap allocation.

#![allow(dead_code)]

use super::types::{BrowserSessionId, MimeType, StatusCode, Url};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of cached responses.
pub const MAX_CACHE_ENTRIES: usize = 32;

/// Total body storage pool in bytes (shared across all entries).
pub const CACHE_BODY_POOL: usize = 2 * 1024 * 1024; // 2 MiB

/// Maximum body size for a single cached entry.
pub const MAX_CACHED_BODY: usize = 256 * 1024; // 256 KiB

// ---------------------------------------------------------------------------
// CacheEntry metadata
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct CacheEntry {
    /// Which session owns this cached response.
    pub session: BrowserSessionId,
    /// URL key (host + path + query, fixed arrays from Url).
    pub url_digest: [u8; 512],
    pub url_digest_len: usize,
    /// HTTP status of the cached response.
    pub status: StatusCode,
    /// MIME type.
    pub mime: MimeType,
    /// ETag value (if any).
    pub etag: [u8; 128],
    pub etag_len: usize,
    /// Last-Modified value (if any).
    pub last_modified: [u8; 64],
    pub lm_len: usize,
    /// Cache-Control max-age in seconds (0 = revalidate always).
    pub max_age: u32,
    /// Epoch at which the entry was stored.
    pub stored_at: u64,
    /// Offset into `POOL` for the body bytes.
    pub body_offset: usize,
    /// Length of body in pool.
    pub body_len: usize,
    pub active: bool,
}

impl CacheEntry {
    pub const EMPTY: Self = Self {
        session: BrowserSessionId(0),
        url_digest: [0; 512],
        url_digest_len: 0,
        status: StatusCode(0),
        mime: MimeType::from_bytes(b"application/octet-stream"),
        etag: [0; 128],
        etag_len: 0,
        last_modified: [0; 64],
        lm_len: 0,
        max_age: 0,
        stored_at: 0,
        body_offset: 0,
        body_len: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// ResponseCache
// ---------------------------------------------------------------------------

pub struct ResponseCache {
    pub entries: [CacheEntry; MAX_CACHE_ENTRIES],
    pool: [u8; CACHE_BODY_POOL],
    pool_write: usize, // next write offset (ring)
    count: usize,
}

impl ResponseCache {
    pub const fn new() -> Self {
        Self {
            entries: [CacheEntry::EMPTY; MAX_CACHE_ENTRIES],
            pool: [0u8; CACHE_BODY_POOL],
            pool_write: 0,
            count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // URL digest
    // -----------------------------------------------------------------------

    /// Compute a compact key from the URL (scheme + host + path + query).
    fn url_digest(url: &Url) -> ([u8; 512], usize) {
        let mut d = [0u8; 512];
        let mut pos = 0usize;
        let scheme_str = url.scheme.as_str().as_bytes();
        let copy = scheme_str.len().min(512 - pos);
        d[pos..pos + copy].copy_from_slice(&scheme_str[..copy]);
        pos += copy;
        if pos < 512 {
            d[pos] = b':';
            pos += 1;
        }
        let host_copy = url.host_len.min(512 - pos);
        d[pos..pos + host_copy].copy_from_slice(&url.host[..host_copy]);
        pos += host_copy;
        if url.port != 0 && pos + 6 < 512 {
            d[pos] = b':';
            pos += 1;
            let mut tmp = [0u8; 6];
            let nlen = write_u16(&mut tmp, url.port);
            d[pos..pos + nlen].copy_from_slice(&tmp[..nlen]);
            pos += nlen;
        }
        let path_copy = url.path_len.min(512 - pos);
        d[pos..pos + path_copy].copy_from_slice(&url.path[..path_copy]);
        pos += path_copy;
        if url.query_len > 0 && pos + 1 + url.query_len < 512 {
            d[pos] = b'?';
            pos += 1;
            let q_copy = url.query_len.min(512 - pos);
            d[pos..pos + q_copy].copy_from_slice(&url.query[..q_copy]);
            pos += q_copy;
        }
        (d, pos)
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Find a fresh cache entry for `url` within `session`.
    ///
    /// Returns the index of the matching entry, or `None` on miss / stale.
    pub fn lookup(
        &self,
        session: BrowserSessionId,
        url: &Url,
        current_epoch: u64,
    ) -> Option<usize> {
        let (digest, digest_len) = Self::url_digest(url);
        for (i, e) in self.entries.iter().enumerate() {
            if !e.active {
                continue;
            }
            if e.session != session {
                continue;
            }
            if e.url_digest_len != digest_len {
                continue;
            }
            if e.url_digest[..digest_len] != digest[..digest_len] {
                continue;
            }
            // TTL check.
            if e.max_age > 0 {
                let age = current_epoch.saturating_sub(e.stored_at);
                if age > e.max_age as u64 {
                    continue;
                }
            }
            return Some(i);
        }
        None
    }

    /// Read cached body bytes for entry at `idx` into `out`.
    /// Returns bytes written.
    pub fn read_body(&self, idx: usize, out: &mut [u8]) -> usize {
        let e = &self.entries[idx];
        if !e.active || e.body_len == 0 {
            return 0;
        }
        let copy = e.body_len.min(out.len());
        out[..copy].copy_from_slice(&self.pool[e.body_offset..e.body_offset + copy]);
        copy
    }

    // -----------------------------------------------------------------------
    // Validation headers
    // -----------------------------------------------------------------------

    /// Write `If-None-Match` value for entry `idx` into `out`.
    /// Returns bytes written, or 0 if no ETag.
    pub fn etag_value(&self, idx: usize, out: &mut [u8; 128]) -> usize {
        let e = &self.entries[idx];
        if !e.active || e.etag_len == 0 {
            return 0;
        }
        let len = e.etag_len.min(128);
        out[..len].copy_from_slice(&e.etag[..len]);
        len
    }

    /// Write `If-Modified-Since` value into `out`.
    pub fn last_modified_value(&self, idx: usize, out: &mut [u8; 64]) -> usize {
        let e = &self.entries[idx];
        if !e.active || e.lm_len == 0 {
            return 0;
        }
        let len = e.lm_len.min(64);
        out[..len].copy_from_slice(&e.last_modified[..len]);
        len
    }

    // -----------------------------------------------------------------------
    // Store
    // -----------------------------------------------------------------------

    /// Store a completed response.  Returns the slot index on success.
    ///
    /// `body` must be <= `MAX_CACHED_BODY`.  Only cacheable status codes
    /// (200, 203, 300, 301, 410) are accepted.
    pub fn store(
        &mut self,
        session: BrowserSessionId,
        url: &Url,
        status: StatusCode,
        mime: MimeType,
        body: &[u8],
        etag: Option<&[u8]>,
        last_modified: Option<&[u8]>,
        max_age: u32,
        current_epoch: u64,
    ) -> Option<usize> {
        if !is_cacheable(status) {
            return None;
        }
        if body.len() > MAX_CACHED_BODY {
            return None;
        }

        // Evict any existing entry for this URL.
        let (digest, digest_len) = Self::url_digest(url);
        for e in &mut self.entries {
            if e.active
                && e.session == session
                && e.url_digest_len == digest_len
                && e.url_digest[..digest_len] == digest[..digest_len]
            {
                e.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }

        // Find a free slot.
        let slot = self.find_free_slot()?;

        // Allocate pool space.
        let body_offset = self.alloc_pool(body.len())?;
        self.pool[body_offset..body_offset + body.len()].copy_from_slice(body);

        // Fill entry.
        let e = &mut self.entries[slot];
        e.session = session;
        e.url_digest = digest;
        e.url_digest_len = digest_len;
        e.status = status;
        e.mime = mime;
        e.max_age = max_age;
        e.stored_at = current_epoch;
        e.body_offset = body_offset;
        e.body_len = body.len();
        e.active = true;

        if let Some(t) = etag {
            let len = t.len().min(128);
            e.etag[..len].copy_from_slice(&t[..len]);
            e.etag_len = len;
        }
        if let Some(lm) = last_modified {
            let len = lm.len().min(64);
            e.last_modified[..len].copy_from_slice(&lm[..len]);
            e.lm_len = len;
        }

        self.count += 1;
        Some(slot)
    }

    // -----------------------------------------------------------------------
    // Invalidate
    // -----------------------------------------------------------------------

    /// Remove all entries for `session` (e.g., on session close).
    pub fn purge_session(&mut self, session: BrowserSessionId) {
        for e in &mut self.entries {
            if e.active && e.session == session {
                e.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_free_slot(&mut self) -> Option<usize> {
        // First look for a genuinely empty slot.
        for (i, e) in self.entries.iter().enumerate() {
            if !e.active {
                return Some(i);
            }
        }
        // Evict oldest entry.
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.stored_at)
            .map(|(i, _)| i)?;
        self.entries[oldest].active = false;
        self.count = self.count.saturating_sub(1);
        Some(oldest)
    }

    /// Ring-buffer allocate `size` bytes in the pool.
    fn alloc_pool(&mut self, size: usize) -> Option<usize> {
        if size > CACHE_BODY_POOL {
            return None;
        }
        let offset = if self.pool_write + size <= CACHE_BODY_POOL {
            self.pool_write
        } else {
            // Wrap around — invalidate any entries that overlap.
            let start = 0;
            let end = size;
            for e in &mut self.entries {
                if !e.active {
                    continue;
                }
                let e_end = e.body_offset + e.body_len;
                if e.body_offset < end && e_end > start {
                    e.active = false;
                    self.count = self.count.saturating_sub(1);
                }
            }
            0
        };
        self.pool_write = (offset + size) % CACHE_BODY_POOL;
        if self.pool_write == 0 && size > 0 {
            self.pool_write = size;
        }
        Some(offset)
    }
}

fn is_cacheable(s: StatusCode) -> bool {
    matches!(s.0, 200 | 203 | 300 | 301 | 410)
}

fn write_u16(buf: &mut [u8; 6], mut v: u16) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 6];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}
