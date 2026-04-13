/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! HTTP header parsing and normalization.
//!
//! All parsing is zero-allocation, operating on slices of bytes.
//! The public surface intentionally avoids `alloc` so the module is safe
//! at every privilege level.

#![allow(dead_code)]

use super::protocol::{ResponseHeader, HEADER_NAME_MAX, HEADER_VALUE_MAX, MAX_RESPONSE_HEADERS};
use super::types::MimeType;

// ---------------------------------------------------------------------------
// Raw header block parser
// ---------------------------------------------------------------------------

/// Parse a raw HTTP/1.1 response header block into a fixed array.
///
/// `block` should be the bytes between the status line and the blank line
/// (`\r\n\r\n`), **not** including the status line itself.
///
/// Returns the number of headers successfully parsed (up to
/// `MAX_RESPONSE_HEADERS`).
pub fn parse_headers(block: &[u8], out: &mut [ResponseHeader; MAX_RESPONSE_HEADERS]) -> usize {
    let mut count = 0usize;
    let mut pos = 0usize;

    while pos < block.len() && count < MAX_RESPONSE_HEADERS {
        // Find end of this line.
        let line_end = find_crlf(block, pos).unwrap_or(block.len());
        let line = &block[pos..line_end];

        // Advance past the CRLF.
        pos = line_end + 2;

        // An empty line signals end of headers.
        if line.is_empty() {
            break;
        }

        // Split on the first ':'.
        let colon = match line.iter().position(|&b| b == b':') {
            Some(c) => c,
            None => continue, // malformed line — skip
        };

        let raw_name = &line[..colon];
        let raw_value = skip_ows(&line[colon + 1..]);

        // Validate name: only token characters allowed (RFC 7230 §3.2.6).
        if !raw_name.iter().all(|&b| is_token_char(b)) {
            continue;
        }

        let name_len = raw_name.len().min(HEADER_NAME_MAX);
        let value_len = raw_value.len().min(HEADER_VALUE_MAX);

        let mut hdr = ResponseHeader::empty();
        // Canonicalize to lowercase for case-insensitive comparison.
        for (i, &b) in raw_name[..name_len].iter().enumerate() {
            hdr.name[i] = b.to_ascii_lowercase();
        }
        hdr.name_len = name_len;
        hdr.value[..value_len].copy_from_slice(&raw_value[..value_len]);
        hdr.value_len = value_len;

        out[count] = hdr;
        count += 1;
    }

    count
}

/// Find the first `\r\n` at or after `start` in `buf`.
fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Skip optional whitespace (OWS = *( SP / HTAB )) at the front of a slice.
fn skip_ows(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    // Also strip trailing OWS.
    let mut j = s.len();
    while j > i && (s[j - 1] == b' ' || s[j - 1] == b'\t') {
        j -= 1;
    }
    &s[i..j]
}

/// RFC 7230 token character predicate.
fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
            | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

// ---------------------------------------------------------------------------
// Header lookup helpers
// ---------------------------------------------------------------------------

/// Find the value of a header by lowercase name.  Returns `None` if absent.
pub fn get_header<'a>(
    headers: &'a [ResponseHeader],
    count: usize,
    name: &[u8],
) -> Option<&'a [u8]> {
    for h in &headers[..count] {
        if h.name[..h.name_len].eq_ignore_ascii_case(name) {
            return Some(&h.value[..h.value_len]);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Status-line parsing
// ---------------------------------------------------------------------------

/// Parse an HTTP/1.x status line, e.g. `HTTP/1.1 200 OK\r\n`.
///
/// Returns `(status_code, header_block_start)` where `header_block_start`
/// is the byte offset of the first header line in `response_bytes`.
/// `status_code` is 0 on parse failure.
pub fn parse_status_line(response_bytes: &[u8]) -> (u16, usize) {
    // Must start with "HTTP/1."
    if response_bytes.len() < 12 || !response_bytes.starts_with(b"HTTP/1.") {
        return (0, 0);
    }
    // Find first \r\n
    let line_end = match find_crlf(response_bytes, 0) {
        Some(e) => e,
        None => return (0, 0),
    };
    let line = &response_bytes[..line_end];

    // Status code starts at offset 9 (after "HTTP/1.x ")
    if line.len() < 12 {
        return (0, 0);
    }
    let code = parse_3digit(&line[9..12]);
    (code, line_end + 2) // skip the \r\n
}

fn parse_3digit(b: &[u8]) -> u16 {
    if b.len() < 3 {
        return 0;
    }
    if !b[0].is_ascii_digit() || !b[1].is_ascii_digit() || !b[2].is_ascii_digit() {
        return 0;
    }
    (b[0] - b'0') as u16 * 100 + (b[1] - b'0') as u16 * 10 + (b[2] - b'0') as u16
}

// ---------------------------------------------------------------------------
// Content-Type parsing
// ---------------------------------------------------------------------------

/// Extract the MIME type from a `Content-Type` value.
///
/// Strips any parameters (e.g. `; charset=utf-8`).
pub fn parse_content_type(value: &[u8]) -> MimeType {
    let end = value.iter().position(|&b| b == b';').unwrap_or(value.len());
    let raw = skip_ows(&value[..end]);
    MimeType::from_bytes(raw)
}

// ---------------------------------------------------------------------------
// Content-Length parsing
// ---------------------------------------------------------------------------

/// Parse the `Content-Length` header value to a u64.
pub fn parse_content_length(value: &[u8]) -> Option<u64> {
    let trimmed = skip_ows(value);
    if trimmed.is_empty() || trimmed.len() > 20 {
        return None;
    }
    let mut v = 0u64;
    for &b in trimmed {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u64);
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// Location (redirect) parsing
// ---------------------------------------------------------------------------

/// Extract the redirect target from a `Location` header value.
/// Returns a slice of `out` containing the normalized URL, or `None`.
pub fn parse_location<'a>(value: &[u8], out: &'a mut [u8; 2048]) -> Option<&'a [u8]> {
    let trimmed = skip_ows(value);
    if trimmed.is_empty() {
        return None;
    }
    let len = trimmed.len().min(2048);
    out[..len].copy_from_slice(&trimmed[..len]);
    Some(&out[..len])
}

// ---------------------------------------------------------------------------
// Set-Cookie extraction
// ---------------------------------------------------------------------------

/// Extract the raw cookie string from a `Set-Cookie` header value.
/// Returns the attribute portion as a separate slice for parsing by
/// `cookie_jar`.
pub fn parse_set_cookie(value: &[u8]) -> (&[u8], &[u8]) {
    // "name=value; attr1; attr2"
    let semi = value.iter().position(|&b| b == b';').unwrap_or(value.len());
    let cookie_pair = skip_ows(&value[..semi]);
    let attrs = if semi < value.len() {
        &value[semi + 1..]
    } else {
        &[]
    };
    (cookie_pair, attrs)
}

// ---------------------------------------------------------------------------
// Transfer-Encoding detection
// ---------------------------------------------------------------------------

pub fn is_chunked_transfer(headers: &[ResponseHeader], count: usize) -> bool {
    if let Some(te) = get_header(headers, count, b"transfer-encoding") {
        return te.eq_ignore_ascii_case(b"chunked")
            || te
                .windows(b"chunked".len())
                .any(|w| w.eq_ignore_ascii_case(b"chunked"));
    }
    false
}

// ---------------------------------------------------------------------------
// Chunked body decoder
// ---------------------------------------------------------------------------

/// Decode one HTTP/1.1 chunked body from `src` into `dst`.
///
/// Returns `(bytes_written, bytes_consumed, done)`.
/// `done` is true when the terminal zero-length chunk has been seen.
pub fn decode_chunked(src: &[u8], dst: &mut [u8]) -> (usize, usize, bool) {
    let mut rpos = 0usize; // read cursor in src
    let mut wpos = 0usize; // write cursor in dst

    loop {
        // Read chunk-size line.
        let line_end = match find_crlf(src, rpos) {
            Some(e) => e,
            None => break,
        };
        let size_hex = &src[rpos..line_end];
        let size = parse_hex_usize(size_hex);
        rpos = line_end + 2; // skip \r\n

        if size == 0 {
            // Terminal chunk — skip trailing CRLF if present.
            if rpos + 1 < src.len() && src[rpos] == b'\r' && src[rpos + 1] == b'\n' {
                rpos += 2;
            }
            return (wpos, rpos, true);
        }

        // Copy chunk data.
        let available = src.len().saturating_sub(rpos);
        if available < size {
            break;
        } // incomplete chunk — wait for more data

        let copy = size.min(dst.len() - wpos);
        dst[wpos..wpos + copy].copy_from_slice(&src[rpos..rpos + copy]);
        wpos += copy;
        rpos += size;

        // Skip trailing \r\n after chunk data.
        if rpos + 1 < src.len() && src[rpos] == b'\r' && src[rpos + 1] == b'\n' {
            rpos += 2;
        }
    }

    (wpos, rpos, false)
}

fn parse_hex_usize(b: &[u8]) -> usize {
    // Only read the actual hex digits; ignore chunk extensions after ';'.
    let b = b
        .iter()
        .position(|&c| c == b';')
        .map(|p| &b[..p])
        .unwrap_or(b);
    let mut v = 0usize;
    for &c in b {
        let digit = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'f' => (c - b'a') as usize + 10,
            b'A'..=b'F' => (c - b'A') as usize + 10,
            _ => return v,
        };
        v = v.saturating_mul(16).saturating_add(digit);
    }
    v
}
