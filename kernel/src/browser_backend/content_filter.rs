/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Content filtering: MIME sniffing guardrails and
//! attachment-vs-inline classification.
//!
//! The kernel never executes HTML/CSS/JS; it needs only to decide:
//!   - Is this response safe to relay as a body stream to the renderer?
//!   - Should the response be forced into a download?

#![allow(dead_code)]

use super::types::MimeType;

// ---------------------------------------------------------------------------
// Known-safe inline MIME types (the renderer may display these)
// ---------------------------------------------------------------------------

/// Whitelist of MIME type prefixes that may be relayed inline.
const INLINE_SAFE: &[&[u8]] = &[
    b"text/html",
    b"text/plain",
    b"text/xml",
    b"application/xhtml+xml",
    b"application/xml",
    b"image/",
    b"audio/",
    b"video/",
    b"application/json",
    b"application/javascript",
    b"text/css",
    b"text/javascript",
    b"font/",
    b"application/pdf",
];

/// MIME types that must always be treated as downloads (never inline).
const FORCE_DOWNLOAD: &[&[u8]] = &[
    b"application/octet-stream",
    b"application/x-msdownload",
    b"application/x-executable",
    b"application/x-sharedlib",
    b"application/x-elf",
    b"application/x-mach-binary",
    b"application/x-msdos-program",
    b"application/vnd.ms-cab-compressed",
    b"application/zip",
    b"application/x-tar",
    b"application/gzip",
    b"application/x-bzip2",
    b"application/x-xz",
    b"application/x-7z-compressed",
    b"application/x-rar-compressed",
];

// ---------------------------------------------------------------------------
// SniffResult
// ---------------------------------------------------------------------------

/// Classification returned by `classify_response`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SniffResult {
    /// Relay the body inline to the renderer.
    Inline,
    /// Offer the body as a file download.
    Download,
    /// Block the response entirely (e.g., dangerous content).
    Block,
}

// ---------------------------------------------------------------------------
// ContentFilter
// ---------------------------------------------------------------------------

pub struct ContentFilter;

impl ContentFilter {
    /// Classify a response given its declared MIME type and
    /// `Content-Disposition` header.
    ///
    /// `is_attachment` should be `true` when the response includes
    /// `Content-Disposition: attachment`.
    /// `sniff_bytes` may be the first few bytes of the body for MIME
    /// sniffing (pass an empty slice to skip sniffing).
    pub fn classify(
        &self,
        declared_mime: &MimeType,
        is_attachment: bool,
        sniff_bytes: &[u8],
    ) -> SniffResult {
        // Explicit attachment → always a download.
        if is_attachment {
            return SniffResult::Download;
        }

        let mime_raw = declared_mime.as_bytes();

        // Force-download list check.
        if prefix_match(mime_raw, FORCE_DOWNLOAD) {
            return SniffResult::Download;
        }

        // Inline safe list check.
        if prefix_match(mime_raw, INLINE_SAFE) {
            return SniffResult::Inline;
        }

        // Unknown MIME — attempt signature sniff.
        if !sniff_bytes.is_empty() {
            match sniff_mime_signature(sniff_bytes) {
                SniffedMime::Executable => return SniffResult::Download,
                SniffedMime::Archive => return SniffResult::Download,
                SniffedMime::Image => return SniffResult::Inline,
                SniffedMime::Html => return SniffResult::Inline,
                SniffedMime::Unknown => {}
            }
        }

        // Default for truly unknown types: safe-download.
        SniffResult::Download
    }

    /// Normalise a `Content-Disposition` value and return `true` if the
    /// disposition type is `attachment`.
    pub fn is_attachment(&self, content_disposition: &[u8]) -> bool {
        let trimmed = trim_ascii(content_disposition);
        // Split on ';'.
        let disp_type_end = trimmed
            .iter()
            .position(|&b| b == b';')
            .unwrap_or(trimmed.len());
        let disp_type = trim_ascii(&trimmed[..disp_type_end]);
        disp_type.eq_ignore_ascii_case(b"attachment")
    }

    /// Extract the suggested filename from a `Content-Disposition` header
    /// into `out`.  Returns the number of bytes written.
    pub fn extract_filename(&self, content_disposition: &[u8], out: &mut [u8; 256]) -> usize {
        // Look for filename= or filename*= attribute.
        let mut pos = 0usize;
        while pos < content_disposition.len() {
            // Skip to next ';' or start.
            let start = content_disposition[pos..]
                .iter()
                .position(|&b| b == b';')
                .map(|p| p + pos + 1)
                .unwrap_or(content_disposition.len());
            if start >= content_disposition.len() {
                break;
            }
            pos = start;

            let seg_end = content_disposition[pos..]
                .iter()
                .position(|&b| b == b';')
                .map(|p| p + pos)
                .unwrap_or(content_disposition.len());
            let seg = trim_ascii(&content_disposition[pos..seg_end]);
            pos = seg_end;

            if let Some(eq) = seg.iter().position(|&b| b == b'=') {
                let key = trim_ascii(&seg[..eq]);
                let val = trim_ascii(&seg[eq + 1..]);
                if key.eq_ignore_ascii_case(b"filename") || key.eq_ignore_ascii_case(b"filename*") {
                    let val = strip_quotes(val);
                    let len = val.len().min(256);
                    out[..len].copy_from_slice(&val[..len]);
                    return len;
                }
            }
        }
        0
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prefix_match(mime: &[u8], list: &[&[u8]]) -> bool {
    for &prefix in list {
        if mime.len() >= prefix.len() && mime[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return true;
        }
    }
    false
}

enum SniffedMime {
    Executable,
    Archive,
    Image,
    Html,
    Unknown,
}

fn sniff_mime_signature(b: &[u8]) -> SniffedMime {
    if b.len() >= 4 && &b[..4] == b"\x7fELF" {
        return SniffedMime::Executable;
    }
    if b.len() >= 2 && ((&b[..2] == b"MZ") || (&b[..2] == b"ZM")) {
        return SniffedMime::Executable;
    }
    if b.len() >= 4 && &b[..4] == b"PK\x03\x04" {
        return SniffedMime::Archive;
    }
    if b.len() >= 6 && b.starts_with(b"GIF89a") {
        return SniffedMime::Image;
    }
    if b.len() >= 6 && b.starts_with(b"GIF87a") {
        return SniffedMime::Image;
    }
    if b.len() >= 4 && &b[..4] == b"\x89PNG" {
        return SniffedMime::Image;
    }
    if b.len() >= 2 && &b[..2] == b"\xff\xd8" {
        return SniffedMime::Image;
    } // JPEG
    if b.len() >= 5 {
        let lower = to_lower5(b);
        if &lower == b"<html" || &lower == b"<!doc" {
            return SniffedMime::Html;
        }
    }
    SniffedMime::Unknown
}

fn to_lower5(b: &[u8]) -> [u8; 5] {
    let mut out = [0u8; 5];
    for i in 0..5 {
        out[i] = b[i].to_ascii_lowercase();
    }
    out
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

fn strip_quotes(s: &[u8]) -> &[u8] {
    if s.len() >= 2 && s[0] == b'"' && s[s.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}
