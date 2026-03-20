//! High-level fetch pipeline.
//!
//! `fetch_request` drives the full DNS → connect → TLS → HTTP/1.1 → stream
//! pipeline for a single request.  It emits `BrowserEvent`s into a
//! fixed-size output array rather than allocating.

#![allow(dead_code)]

use super::headers::{
    decode_chunked, is_chunked_transfer, parse_content_length, parse_content_type, parse_headers,
    parse_location, parse_status_line,
};
use super::policy::{BrowserPolicy, PolicyProfile};
use super::protocol::{
    BrowserError, BrowserEvent, FetchErrorKind, PolicyBlockReason, ResponseHeader,
    TlsHandshakeResult, BODY_CHUNK_MAX, MAX_RESPONSE_HEADERS,
};
use super::transport::{TransportError, TransportHandle};
use super::types::{BrowserSessionId, HttpMethod, MimeType, RequestId, Scheme, StatusCode, Url};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the raw receive buffer used while reading the HTTP response.
const RECV_BUF: usize = 8192;

/// Maximum header block size we will buffer before giving up.
const MAX_HEADER_BLOCK: usize = 16384;

// ---------------------------------------------------------------------------
// FetchContext
// ---------------------------------------------------------------------------

/// Everything needed to execute one HTTP request.
pub struct FetchContext<'a> {
    pub session: BrowserSessionId,
    pub request: RequestId,
    pub url: &'a Url,
    pub method: HttpMethod,
    pub body: &'a [u8],
    pub profile: &'a PolicyProfile,
}

// ---------------------------------------------------------------------------
// FetchResult
// ---------------------------------------------------------------------------

/// Outcome of a single `fetch_request` call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FetchOutcome {
    /// Response fully received (events contain Headers + Body chunks + Complete).
    Complete,
    /// A redirect was encountered — caller should re-issue with new URL.
    Redirect {
        status: u16,
        /// Destination URL as raw bytes (null-terminated inside the fixed array).
        location: [u8; 2048],
        location_len: usize,
    },
    /// A policy rule blocked the request before or during fetch.
    PolicyBlocked(PolicyBlockReason),
    /// Network or protocol error.
    Error(FetchErrorKind),
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Execute one HTTP request and write events into `events[..event_count]`.
///
/// Up to `MAX_EVENTS` events may be written.  Body chunks are flushed
/// eagerly — each `BodyChunk` event corresponds to one `BODY_CHUNK_MAX`
/// read.  The caller should call this in a loop for redirects, updating
/// the URL on each iteration.
pub fn fetch_request<const MAX_EVENTS: usize>(
    ctx: &FetchContext<'_>,
    events: &mut [Option<BrowserEvent>; MAX_EVENTS],
    event_count: &mut usize,
) -> FetchOutcome {
    let policy = BrowserPolicy;

    // -----------------------------------------------------------------------
    // Scheme check
    // -----------------------------------------------------------------------
    if let Some(reason) = policy.check_scheme(ctx.url.scheme) {
        push_policy_blocked(events, event_count, ctx.request, reason);
        return FetchOutcome::PolicyBlocked(reason);
    }

    // -----------------------------------------------------------------------
    // Mixed-content check (subresource is always false at top-level fetch)
    // -----------------------------------------------------------------------
    // (The caller in session.rs passes whether this is a subresource;
    //  here we conservatively assume it is not top-level when HTTP is used
    //  on a known HTTPS session — that enforcement happens at origin.rs.
    //  transport.rs is agnostic.)

    // -----------------------------------------------------------------------
    // Connect
    // -----------------------------------------------------------------------
    let host = &ctx.url.host[..ctx.url.host_len];
    let port = if ctx.url.port != 0 {
        ctx.url.port
    } else {
        ctx.url.scheme.default_port()
    };

    let mut transport = match TransportHandle::connect(ctx.url.scheme, host, port) {
        Ok(t) => t,
        Err(TransportError::DnsFailure) => {
            push_fetch_error(
                events,
                event_count,
                ctx.request,
                FetchErrorKind::DnsFailure,
                b"DNS resolution failed",
            );
            return FetchOutcome::Error(FetchErrorKind::DnsFailure);
        }
        Err(TransportError::TlsAllocFailed) | Err(TransportError::TlsHandshakeFailed) => {
            // Emit TlsState event + FetchError.
            push_tls_state(events, event_count, ctx.request, TlsHandshakeResult::Failed);
            push_fetch_error(
                events,
                event_count,
                ctx.request,
                FetchErrorKind::TlsHandshakeFailed,
                b"TLS handshake failed",
            );
            return FetchOutcome::Error(FetchErrorKind::TlsHandshakeFailed);
        }
        Err(_) => {
            push_fetch_error(
                events,
                event_count,
                ctx.request,
                FetchErrorKind::ConnectionFailed,
                b"Connection failed",
            );
            return FetchOutcome::Error(FetchErrorKind::ConnectionFailed);
        }
    };

    // TLS established event.
    if ctx.url.scheme == Scheme::Https {
        push_tls_state(
            events,
            event_count,
            ctx.request,
            TlsHandshakeResult::Established,
        );
    } else {
        push_tls_state(
            events,
            event_count,
            ctx.request,
            TlsHandshakeResult::Plaintext,
        );
    }

    // -----------------------------------------------------------------------
    // Build host header
    // -----------------------------------------------------------------------
    let mut host_hdr = [0u8; 270]; // host (253) + ":" + port (5) + NUL
    let host_hdr_len = build_host_header(&mut host_hdr, host, port, ctx.url.scheme);

    // -----------------------------------------------------------------------
    // Build path + query
    // -----------------------------------------------------------------------
    let mut path_buf = [0u8; 1024 + 512 + 1];
    let path_len = build_path(&mut path_buf, ctx.url);

    // -----------------------------------------------------------------------
    // Send request
    // -----------------------------------------------------------------------
    let method_str = ctx.method.as_str();
    if let Err(_) = transport.send_http_request(
        method_str.as_bytes(),
        &path_buf[..path_len],
        &host_hdr[..host_hdr_len],
        ctx.body,
    ) {
        transport.close();
        push_fetch_error(
            events,
            event_count,
            ctx.request,
            FetchErrorKind::ConnectionFailed,
            b"Send failed",
        );
        return FetchOutcome::Error(FetchErrorKind::ConnectionFailed);
    }

    // -----------------------------------------------------------------------
    // Read raw response into header-block buffer
    // -----------------------------------------------------------------------
    let mut raw = [0u8; MAX_HEADER_BLOCK];
    let raw_len = read_until_headers(&mut transport, &mut raw);
    if raw_len == 0 {
        transport.close();
        push_fetch_error(
            events,
            event_count,
            ctx.request,
            FetchErrorKind::ProtocolError,
            b"No response",
        );
        return FetchOutcome::Error(FetchErrorKind::ProtocolError);
    }

    // -----------------------------------------------------------------------
    // Parse status line
    // -----------------------------------------------------------------------
    let (status_code, header_start) = parse_status_line(&raw[..raw_len]);
    if status_code == 0 {
        transport.close();
        push_fetch_error(
            events,
            event_count,
            ctx.request,
            FetchErrorKind::ProtocolError,
            b"Bad status line",
        );
        return FetchOutcome::Error(FetchErrorKind::ProtocolError);
    }

    // -----------------------------------------------------------------------
    // Parse headers
    // -----------------------------------------------------------------------
    let mut headers = [ResponseHeader::empty(); MAX_RESPONSE_HEADERS];
    let header_count = if header_start < raw_len {
        // Find end of header block (\r\n\r\n).
        let block_end = find_header_end(&raw[header_start..raw_len])
            .map(|e| e + header_start)
            .unwrap_or(raw_len);
        parse_headers(&raw[header_start..block_end], &mut headers)
    } else {
        0
    };

    // -----------------------------------------------------------------------
    // Extract key header values
    // -----------------------------------------------------------------------
    use super::headers::{get_header, parse_content_length as pcl};

    let content_length = get_header(&headers, header_count, b"content-length").and_then(pcl);
    let mime = get_header(&headers, header_count, b"content-type")
        .map(parse_content_type)
        .unwrap_or(MimeType::from_bytes(b"application/octet-stream"));
    let is_chunked = is_chunked_transfer(&headers, header_count);

    // -----------------------------------------------------------------------
    // Redirect?
    // -----------------------------------------------------------------------
    let sc = StatusCode(status_code);
    if sc.is_redirect() {
        if let Some(loc_raw) = get_header(&headers, header_count, b"location") {
            let mut loc_buf = [0u8; 2048];
            if let Some(loc) = parse_location(loc_raw, &mut loc_buf) {
                let loc_len = loc.len();
                transport.close();
                return FetchOutcome::Redirect {
                    status: status_code,
                    location: loc_buf,
                    location_len: loc_len,
                };
            }
        }
    }

    // -----------------------------------------------------------------------
    // Content-Disposition: attachment → download offer (handled by fetch.rs
    // caller, not here — just emit headers event and let service.rs decide)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Emit Headers event
    // -----------------------------------------------------------------------
    push_headers(
        events,
        event_count,
        ctx.request,
        status_code,
        mime,
        content_length,
        &headers,
        header_count,
    );

    // -----------------------------------------------------------------------
    // Stream body
    // -----------------------------------------------------------------------
    let outcome = stream_body(
        &mut transport,
        events,
        event_count,
        ctx.request,
        is_chunked,
        content_length,
    );

    transport.close();

    match outcome {
        Ok(()) => FetchOutcome::Complete,
        Err(kind) => {
            push_fetch_error(events, event_count, ctx.request, kind, b"Body read error");
            FetchOutcome::Error(kind)
        }
    }
}

// ---------------------------------------------------------------------------
// Body streaming
// ---------------------------------------------------------------------------

fn stream_body<const N: usize>(
    transport: &mut TransportHandle,
    events: &mut [Option<BrowserEvent>; N],
    event_count: &mut usize,
    request: RequestId,
    is_chunked: bool,
    content_length: Option<u64>,
) -> Result<(), FetchErrorKind> {
    let mut recv_buf = [0u8; RECV_BUF];
    let mut chunk_buf = [0u8; BODY_CHUNK_MAX];
    let mut total_received: u64 = 0;
    let expected = content_length.unwrap_or(u64::MAX);

    if is_chunked {
        // Chunked transfer decoding loop.
        let mut leftover = [0u8; RECV_BUF * 2];
        let mut leftover_len = 0usize;
        loop {
            let n = transport
                .read_raw(&mut recv_buf)
                .map_err(|_| FetchErrorKind::ConnectionReset)?;
            if n == 0 {
                break;
            }

            // Append to leftover.
            let copy = n.min(leftover.len() - leftover_len);
            leftover[leftover_len..leftover_len + copy].copy_from_slice(&recv_buf[..copy]);
            leftover_len += copy;

            // Decode as many chunks as possible.
            let (decoded, consumed, done) =
                decode_chunked(&leftover[..leftover_len], &mut chunk_buf);

            if decoded > 0 {
                let is_last = done;
                push_body_chunk(events, event_count, request, &chunk_buf[..decoded], is_last);
                total_received += decoded as u64;
            }

            // Compact leftover.
            leftover_len -= consumed;
            leftover.copy_within(consumed..consumed + leftover_len, 0);

            if done {
                break;
            }
        }
    } else {
        // Identity (or unknown) body.
        loop {
            if total_received >= expected {
                break;
            }
            let remaining = (expected - total_received).min(RECV_BUF as u64) as usize;
            let n = transport
                .read_raw(&mut recv_buf[..remaining])
                .map_err(|_| FetchErrorKind::ConnectionReset)?;
            if n == 0 {
                break;
            }
            // Relay in BODY_CHUNK_MAX-sized pieces.
            let mut off = 0;
            while off < n {
                let piece_len = (n - off).min(BODY_CHUNK_MAX);
                let is_last = total_received + (off + piece_len) as u64 >= expected;
                push_body_chunk(
                    events,
                    event_count,
                    request,
                    &recv_buf[off..off + piece_len],
                    is_last,
                );
                off += piece_len;
            }
            total_received += n as u64;
        }
    }

    push_complete(events, event_count, request);
    Ok(())
}

// ---------------------------------------------------------------------------
// Read until \r\n\r\n (header boundary)
// ---------------------------------------------------------------------------

fn read_until_headers(transport: &mut TransportHandle, buf: &mut [u8; MAX_HEADER_BLOCK]) -> usize {
    let mut total = 0usize;
    let mut recv = [0u8; 256];
    loop {
        let n = match transport.read_raw(&mut recv) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let copy = n.min(MAX_HEADER_BLOCK - total);
        buf[total..total + copy].copy_from_slice(&recv[..copy]);
        total += copy;
        // Check for double CRLF.
        if find_header_end(&buf[..total]).is_some() {
            break;
        }
        if total >= MAX_HEADER_BLOCK {
            break;
        }
    }
    total
}

/// Find the offset of the first `\r\n\r\n` in `buf`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..buf.len() - 3 {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Path + query builder
// ---------------------------------------------------------------------------

fn build_path(out: &mut [u8; 1024 + 512 + 1], url: &Url) -> usize {
    let mut w = 0usize;
    let path_len = url.path_len;
    let path = &url.path[..path_len];
    if path_len == 0 {
        out[0] = b'/';
        w = 1;
    } else {
        out[..path_len].copy_from_slice(path);
        w = path_len;
    }
    if url.query_len > 0 && w + 1 + url.query_len <= out.len() {
        out[w] = b'?';
        w += 1;
        out[w..w + url.query_len].copy_from_slice(&url.query[..url.query_len]);
        w += url.query_len;
    }
    w
}

fn build_host_header(out: &mut [u8; 270], host: &[u8], port: u16, scheme: Scheme) -> usize {
    let host_len = host.len().min(253);
    out[..host_len].copy_from_slice(&host[..host_len]);
    let mut w = host_len;
    // Omit default port.
    let default = scheme.default_port();
    if port != default && port != 0 {
        out[w] = b':';
        w += 1;
        let mut num = [0u8; 6];
        let nlen = write_u16(&mut num, port);
        out[w..w + nlen].copy_from_slice(&num[..nlen]);
        w += nlen;
    }
    w
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

// ---------------------------------------------------------------------------
// Event push helpers
// ---------------------------------------------------------------------------

fn push<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    e: BrowserEvent,
) {
    if *count < N {
        events[*count] = Some(e);
        *count += 1;
    }
}

fn push_policy_blocked<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
    reason: PolicyBlockReason,
) {
    push(
        events,
        count,
        BrowserEvent::PolicyBlocked {
            request_id: req,
            reason,
        },
    );
}

fn push_tls_state<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
    result: TlsHandshakeResult,
) {
    push(
        events,
        count,
        BrowserEvent::TlsState {
            request_id: req,
            result,
        },
    );
}

fn push_fetch_error<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
    kind: FetchErrorKind,
    message: &[u8],
) {
    let mut msg = [0u8; 128];
    let len = message.len().min(128);
    msg[..len].copy_from_slice(&message[..len]);
    push(
        events,
        count,
        BrowserEvent::FetchError {
            request_id: req,
            kind,
            message: msg,
            msg_len: len,
        },
    );
}

fn push_headers<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
    status: u16,
    mime: MimeType,
    content_length: Option<u64>,
    headers: &[ResponseHeader; MAX_RESPONSE_HEADERS],
    header_count: usize,
) {
    push(
        events,
        count,
        BrowserEvent::Headers {
            request_id: req,
            status: StatusCode(status),
            mime,
            content_length,
            headers: *headers,
            header_count,
        },
    );
}

fn push_body_chunk<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
    data: &[u8],
    is_last: bool,
) {
    let mut buf = [0u8; BODY_CHUNK_MAX];
    let len = data.len().min(BODY_CHUNK_MAX);
    buf[..len].copy_from_slice(&data[..len]);
    push(
        events,
        count,
        BrowserEvent::BodyChunk {
            request_id: req,
            data: buf,
            data_len: len,
            is_last,
        },
    );
}

fn push_complete<const N: usize>(
    events: &mut [Option<BrowserEvent>; N],
    count: &mut usize,
    req: RequestId,
) {
    push(events, count, BrowserEvent::Complete { request_id: req });
}
