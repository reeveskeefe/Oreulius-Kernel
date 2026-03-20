//! Core types for the browser backend subsystem.
//!
//! All types in this module are `no_std`-compatible, heap-free, and use
//! fixed-size arrays for all variable-length data.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// ID Newtypes
// ---------------------------------------------------------------------------

/// Identifies an active browser session (one per tab/navigation context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserSessionId(pub u32);

/// Identifies a single in-flight or completed fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub u32);

/// Opaque capability token issued to a client when a session is opened.
/// The token is a 64-bit MAC — clients cannot forge or guess it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserCap(pub u64);

impl BrowserCap {
    pub const INVALID: BrowserCap = BrowserCap(0);
    pub fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// Identifies a download job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadId(pub u32);

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

pub const URL_MAX: usize = 2048;
pub const HOST_MAX: usize = 253;
pub const PATH_MAX: usize = 1024;
pub const QUERY_MAX: usize = 512;

/// Scheme of a parsed URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Unknown,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
            Scheme::Unknown => 0,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Unknown => "",
        }
    }
    pub fn is_secure(self) -> bool {
        matches!(self, Scheme::Https)
    }
}

/// A parsed URL, represented as fixed-size byte arrays.
///
/// All length fields shadow the corresponding array: only bytes `[..len]`
/// are valid.
#[derive(Clone, Copy)]
pub struct Url {
    pub scheme: Scheme,
    pub host: [u8; HOST_MAX],
    pub host_len: usize,
    pub port: u16,
    pub path: [u8; PATH_MAX],
    pub path_len: usize,
    pub query: [u8; QUERY_MAX],
    pub query_len: usize,
}

impl Url {
    pub const fn empty() -> Self {
        Url {
            scheme: Scheme::Unknown,
            host: [0; HOST_MAX],
            host_len: 0,
            port: 0,
            path: [0; PATH_MAX],
            path_len: 0,
            query: [0; QUERY_MAX],
            query_len: 0,
        }
    }

    /// Parse a URL from a raw byte string.  Returns `None` on parse failure.
    ///
    /// Supported forms:
    ///   `http://host[:port][/path[?query]]`
    ///   `https://host[:port][/path[?query]]`
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let mut url = Url::empty();

        // --- Scheme ---
        let (scheme, rest) = if raw.starts_with(b"https://") {
            (Scheme::Https, &raw[8..])
        } else if raw.starts_with(b"http://") {
            (Scheme::Http, &raw[7..])
        } else {
            return None;
        };
        url.scheme = scheme;

        // --- Authority: host[:port] ---
        let path_start = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        let authority = &rest[..path_start];
        let path_and_query = &rest[path_start..];

        let (host_bytes, port) = if let Some(colon) = authority.iter().rposition(|&b| b == b':') {
            let port_bytes = &authority[colon + 1..];
            let p = parse_decimal_u16(port_bytes).unwrap_or(scheme.default_port());
            (&authority[..colon], p)
        } else {
            (authority, scheme.default_port())
        };

        if host_bytes.is_empty() || host_bytes.len() > HOST_MAX {
            return None;
        }
        url.host[..host_bytes.len()].copy_from_slice(host_bytes);
        url.host_len = host_bytes.len();
        url.port = port;

        // --- Path ---
        let (path_bytes, query_bytes) =
            if let Some(q) = path_and_query.iter().position(|&b| b == b'?') {
                (&path_and_query[..q], &path_and_query[q + 1..])
            } else {
                (path_and_query, &b""[..])
            };

        let path_effective = if path_bytes.is_empty() {
            b"/" as &[u8]
        } else {
            path_bytes
        };
        let plen = path_effective.len().min(PATH_MAX);
        url.path[..plen].copy_from_slice(&path_effective[..plen]);
        url.path_len = plen;

        let qlen = query_bytes.len().min(QUERY_MAX);
        url.query[..qlen].copy_from_slice(&query_bytes[..qlen]);
        url.query_len = qlen;

        Some(url)
    }

    pub fn host_str(&self) -> &[u8] {
        &self.host[..self.host_len]
    }
    pub fn path_str(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
    pub fn query_str(&self) -> &[u8] {
        &self.query[..self.query_len]
    }
}

fn parse_decimal_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() || bytes.len() > 5 {
        return None;
    }
    let mut v = 0u32;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        v = v * 10 + (b - b'0') as u32;
    }
    if v > 65535 {
        return None;
    }
    Some(v as u16)
}

// ---------------------------------------------------------------------------
// Origin
// ---------------------------------------------------------------------------

/// An origin is `scheme + host + port`, the unit of web security isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub scheme: Scheme,
    pub host: [u8; HOST_MAX],
    pub host_len: usize,
    pub port: u16,
}

impl Origin {
    pub const OPAQUE: Origin = Origin {
        scheme: Scheme::Unknown,
        host: [0; HOST_MAX],
        host_len: 0,
        port: 0,
    };

    pub fn from_url(url: &Url) -> Self {
        Origin {
            scheme: url.scheme,
            host: url.host,
            host_len: url.host_len,
            port: url.port,
        }
    }

    pub fn is_opaque(&self) -> bool {
        self.scheme == Scheme::Unknown
    }

    pub fn same_origin(&self, other: &Origin) -> bool {
        self.scheme == other.scheme
            && self.port == other.port
            && self.host[..self.host_len] == other.host[..other.host_len]
    }
}

// ---------------------------------------------------------------------------
// HTTP Method
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Options,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Head => "HEAD",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
        }
    }
    pub fn has_body(self) -> bool {
        matches!(self, HttpMethod::Post | HttpMethod::Put)
    }
}

// ---------------------------------------------------------------------------
// MIME type
// ---------------------------------------------------------------------------

pub const MIME_MAX: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MimeType {
    pub bytes: [u8; MIME_MAX],
    pub len: usize,
}

impl MimeType {
    pub const fn empty() -> Self {
        MimeType {
            bytes: [0; MIME_MAX],
            len: 0,
        }
    }

    pub const fn from_bytes(b: &[u8]) -> Self {
        let l = if b.len() < MIME_MAX {
            b.len()
        } else {
            MIME_MAX
        };
        let mut bytes = [0u8; MIME_MAX];
        let mut i = 0;
        while i < l {
            bytes[i] = b[i];
            i += 1;
        }
        MimeType { bytes, len: l }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn is_text(&self) -> bool {
        self.as_bytes().starts_with(b"text/")
    }
    pub fn is_html(&self) -> bool {
        self.as_bytes() == b"text/html" || self.as_bytes().starts_with(b"text/html;")
    }
    pub fn is_json(&self) -> bool {
        self.as_bytes() == b"application/json" || self.as_bytes().starts_with(b"application/json;")
    }
    pub fn is_binary(&self) -> bool {
        self.as_bytes() == b"application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// Redirect policy
// ---------------------------------------------------------------------------

/// Controls how many HTTP redirects the fetch pipeline follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectPolicy {
    pub max_redirects: u8,
    pub follow_cross_origin: bool,
}

impl RedirectPolicy {
    pub const DEFAULT: RedirectPolicy = RedirectPolicy {
        max_redirects: 10,
        follow_cross_origin: true,
    };
    pub const NO_FOLLOW: RedirectPolicy = RedirectPolicy {
        max_redirects: 0,
        follow_cross_origin: false,
    };
}

// ---------------------------------------------------------------------------
// Fetch result metadata
// ---------------------------------------------------------------------------

/// HTTP status code wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }
    pub fn is_redirect(self) -> bool {
        self.0 == 301 || self.0 == 302 || self.0 == 303 || self.0 == 307 || self.0 == 308
    }
    pub fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }
    pub fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }
}
