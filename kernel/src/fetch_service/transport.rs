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


//! Transport layer: wraps the TLS session pool and provides a minimal
//! HTTP/1.1 request builder + streaming response reader.
//!
//! # Design
//! - HTTPS → drive `crate::net::tls::{alloc_session, session_mut, free_session, tick_all}`
//! - HTTP  → drive `crate::net::net_reactor::{tcp_connect, tcp_send, tcp_recv, tcp_close}`
//!
//! No heap allocation.  All staging buffers live on the stack or in the
//! caller-supplied slices.

#![allow(dead_code)]

use crate::net::net_reactor;
use crate::net::netstack::Ipv4Addr;
use crate::net::tls;

use super::types::Scheme;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the internal send scratch buffer (one HTTP/1.1 request line).
const REQ_BUF: usize = 4096;

/// Maximum number of spin-ticks while waiting for TCP to deliver data.
const MAX_TICKS: usize = 512;

/// Sentinel for an unused TCP connection handle.
const NO_TCP_CONN: u16 = u16::MAX;

/// Sentinel for an unused TLS session handle.
const NO_TLS_HANDLE: i32 = -1;

// ---------------------------------------------------------------------------
// TransportError
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    DnsFailure,
    TcpConnectFailed,
    TlsAllocFailed,
    TlsHandshakeFailed,
    SendFailed,
    RecvFailed,
    Timeout,
    InvalidState,
}

// ---------------------------------------------------------------------------
// TransportHandle
// ---------------------------------------------------------------------------

/// Owning handle to either a TLS session (HTTPS) or a plain TCP connection
/// (HTTP).  Drop-equivalent is `close()`; callers **must** call `close()`
/// explicitly because there is no `Drop` in `no_std` without alloc.
pub struct TransportHandle {
    scheme: Scheme,
    tls_handle: i32, // valid when scheme == Https
    tcp_conn: u16,   // valid when scheme == Http
    /// Resolved server IP — kept for reconnect on redirect.
    pub server_ip: [u8; 4],
}

impl TransportHandle {
    #[inline]
    fn has_tls_session(&self) -> bool {
        self.tls_handle != NO_TLS_HANDLE
    }

    #[inline]
    fn has_tcp_connection(&self) -> bool {
        self.tcp_conn != NO_TCP_CONN
    }

    #[inline]
    fn validate_active_state(&self) -> Result<(), TransportError> {
        match self.scheme {
            Scheme::Https if self.has_tls_session() && !self.has_tcp_connection() => Ok(()),
            Scheme::Http if self.has_tcp_connection() && !self.has_tls_session() => Ok(()),
            _ => Err(TransportError::InvalidState),
        }
    }

    /// Connect to `host:port`, resolving the hostname via the net reactor.
    ///
    /// For HTTPS the TLS handshake is driven to completion (blocking via
    /// `tick_all`).
    pub fn connect(scheme: Scheme, host: &[u8], port: u16) -> Result<Self, TransportError> {
        // DNS resolution via net_reactor.
        let host_str = core::str::from_utf8(host)
            .unwrap_or("")
            .trim_end_matches('\0');
        let ip: Ipv4Addr =
            net_reactor::dns_resolve(host_str).map_err(|_| TransportError::DnsFailure)?;
        let ip_bytes: [u8; 4] = ip.0;

        match scheme {
            Scheme::Https => Self::connect_tls(host, port, ip_bytes),
            Scheme::Http => Self::connect_tcp(port, ip_bytes),
            _ => Err(TransportError::InvalidState),
        }
    }

    fn connect_tls(host: &[u8], port: u16, ip: [u8; 4]) -> Result<Self, TransportError> {
        let handle = tls::alloc_session(host, port, ip);
        if handle < 0 {
            return Err(TransportError::TlsAllocFailed);
        }

        // Drive the handshake.
        for _ in 0..MAX_TICKS {
            tls::tick_all();
            match tls::session_mut(handle) {
                None => return Err(TransportError::TlsHandshakeFailed),
                Some(s) => {
                    if s.handshake_done() {
                        break;
                    }
                    // Error state: bail.
                    if !s.error_str().is_empty() {
                        tls::free_session(handle);
                        return Err(TransportError::TlsHandshakeFailed);
                    }
                }
            }
        }
        // Verify we actually finished.
        match tls::session_mut(handle) {
            Some(s) if s.handshake_done() => {}
            _ => {
                tls::free_session(handle);
                return Err(TransportError::TlsHandshakeFailed);
            }
        }
        Ok(Self {
            scheme: Scheme::Https,
            tls_handle: handle,
            tcp_conn: NO_TCP_CONN,
            server_ip: ip,
        })
    }

    fn connect_tcp(port: u16, ip: [u8; 4]) -> Result<Self, TransportError> {
        let remote = Ipv4Addr(ip);
        let conn_id =
            net_reactor::tcp_connect(remote, port).map_err(|_| TransportError::TcpConnectFailed)?;
        Ok(Self {
            scheme: Scheme::Http,
            tls_handle: NO_TLS_HANDLE,
            tcp_conn: conn_id,
            server_ip: ip,
        })
    }

    // -----------------------------------------------------------------------
    // HTTP/1.1 request builder
    // -----------------------------------------------------------------------

    /// Build and send a complete HTTP/1.1 request.
    ///
    /// `path` should include query string if any.  `host_hdr` is the
    /// `Host:` header value (usually `hostname` or `hostname:port`).
    /// `body` may be empty.
    pub fn send_http_request(
        &mut self,
        method: &[u8],
        path: &[u8],
        host_hdr: &[u8],
        body: &[u8],
    ) -> Result<(), TransportError> {
        let mut buf = [0u8; REQ_BUF];
        let len = Self::build_request(&mut buf, method, path, host_hdr, body)?;
        self.send_all(&buf[..len])?;
        if !body.is_empty() {
            self.send_all(body)?;
        }
        Ok(())
    }

    /// Write HTTP/1.1 request headers into `buf`.  Returns the number of
    /// bytes written, or `TransportError::SendFailed` if the buffer is too
    /// small.
    fn build_request(
        buf: &mut [u8; REQ_BUF],
        method: &[u8],
        path: &[u8],
        host_hdr: &[u8],
        body: &[u8],
    ) -> Result<usize, TransportError> {
        let mut w = BufWriter::new(buf);
        w.write(method)?;
        w.write(b" ")?;
        w.write(path)?;
        w.write(b" HTTP/1.1\r\nHost: ")?;
        w.write(host_hdr)?;
        w.write(b"\r\nConnection: close\r\nAccept: */*\r\n")?;
        if !body.is_empty() {
            w.write(b"Content-Length: ")?;
            let mut num_buf = [0u8; 20];
            let n = write_u64(&mut num_buf, body.len() as u64);
            w.write(&num_buf[..n])?;
            w.write(b"\r\n")?;
        }
        w.write(b"\r\n")?;
        Ok(w.pos)
    }

    // -----------------------------------------------------------------------
    // Streaming response reader
    // -----------------------------------------------------------------------

    /// Read raw bytes into `out`, returning how many bytes arrived.
    /// Returns `Ok(0)` on graceful EOF.
    pub fn read_raw(&mut self, out: &mut [u8]) -> Result<usize, TransportError> {
        self.validate_active_state()?;
        match self.scheme {
            Scheme::Https => {
                let s = tls::session_mut(self.tls_handle).ok_or(TransportError::InvalidState)?;
                // Drive TLS state machine briefly before reading.
                s.tick();
                let n = s.read(out);
                Ok(n)
            }
            Scheme::Http => {
                net_reactor::tcp_recv(self.tcp_conn, out).map_err(|_| TransportError::RecvFailed)
            }
            _ => Err(TransportError::InvalidState),
        }
    }

    /// Block-read until `out` is full or EOF/error.
    /// Returns `(bytes_read, eof)`.
    pub fn read_exact_or_eof(&mut self, out: &mut [u8]) -> Result<(usize, bool), TransportError> {
        let mut total = 0usize;
        let mut ticks = 0usize;
        while total < out.len() {
            let n = self.read_raw(&mut out[total..])?;
            if n == 0 {
                ticks += 1;
                if ticks > MAX_TICKS {
                    return Ok((total, true));
                }
                if self.scheme == Scheme::Https {
                    tls::tick_all();
                }
                continue;
            }
            ticks = 0;
            total += n;
        }
        Ok((total, total < out.len()))
    }

    // -----------------------------------------------------------------------
    // Close
    // -----------------------------------------------------------------------

    /// Release all kernel resources.  Must be called before discarding the
    /// handle.
    pub fn close(&mut self) {
        if self.has_tls_session() {
            if let Some(s) = tls::session_mut(self.tls_handle) {
                s.close();
            }
            tls::free_session(self.tls_handle);
            self.tls_handle = NO_TLS_HANDLE;
        }
        if self.has_tcp_connection() {
            let _ = net_reactor::tcp_close(self.tcp_conn);
            self.tcp_conn = NO_TCP_CONN;
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn send_all(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut sent = 0usize;
        while sent < data.len() {
            let n = self.send_chunk(&data[sent..])?;
            if n == 0 {
                return Err(TransportError::SendFailed);
            }
            sent += n;
        }
        Ok(())
    }

    fn send_chunk(&mut self, data: &[u8]) -> Result<usize, TransportError> {
        self.validate_active_state()?;
        match self.scheme {
            Scheme::Https => {
                let s = tls::session_mut(self.tls_handle).ok_or(TransportError::InvalidState)?;
                Ok(s.write(data))
            }
            Scheme::Http => {
                net_reactor::tcp_send(self.tcp_conn, data).map_err(|_| TransportError::SendFailed)
            }
            _ => Err(TransportError::InvalidState),
        }
    }
}

// ---------------------------------------------------------------------------
// BufWriter — write into a fixed array, returning an error if full
// ---------------------------------------------------------------------------

struct BufWriter<'a> {
    buf: &'a mut [u8; REQ_BUF],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8; REQ_BUF]) -> Self {
        Self { buf, pos: 0 }
    }

    fn write(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if self.pos + data.len() > REQ_BUF {
            return Err(TransportError::SendFailed);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// u64 → ASCII decimal
// ---------------------------------------------------------------------------

fn write_u64(buf: &mut [u8; 20], mut v: u64) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
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
