//! Temporal snapshot / restore for the browser backend.
//!
//! Persists session identity, navigation history, cookies and download jobs
//! across kernel lifecycle events (suspend/resume, soft-reboot).
//!
//! ## Snapshot v2 wire layout
//!
//! ```text
//! Header (24 bytes):
//!   0-3:   magic  = 0x4252_5357  ('BRSW')
//!   4-7:   version = 2 (u32 LE)
//!   8-11:  session_count  (u32 LE)
//!   12-15: cookie_count   (u32 LE)
//!   16-19: download_count (u32 LE)
//!   20-23: reserved
//!
//! SESSION records (variable length, session_count of them):
//!   0-3:  session_id       (u32 LE)
//!   4-7:  pid              (u32 LE)
//!   8-15: cap              (u64 LE)
//!   16:   alive            (u8)
//!   17-20: next_request_id (u32 LE)
//!   21:   nav_head         (u8)
//!   22:   nav_count        (u8)
//!   For i in 0..NAV_HISTORY_DEPTH entries:
//!     0-1: url_len (u16 LE, 0 = inactive slot)
//!     2..: url bytes (url_len bytes)
//!
//! COOKIE records (variable length, cookie_count of them):
//!   0-3:  session_id (u32 LE)
//!   4-11: expires    (u64 LE)
//!   12:   flags      (u8: bit0=http_only, bit1=secure, bit2-3=same_site)
//!   13:   name_len   (u8, max 128)
//!   14-15: value_len (u16 LE, max 4096)
//!   16:   domain_len (u8, max 253)
//!   17:   path_len   (u8, truncated at 255)
//!   18..: name, value, domain, path (variable)
//!
//! DOWNLOAD records (variable length, download_count of them):
//!   0-3:   id           (u32 LE)
//!   4-7:   session_id   (u32 LE)
//!   8:     state        (u8: Pending=0, Active=1, Complete=2, Rejected=3, Error=4)
//!   9:     filename_len (u8, max 255)
//!   10:    mime_len     (u8, max 128)
//!   11-18: size_hint    (u64 LE)
//!   19-26: bytes_written(u64 LE)
//!   27..:  filename     (filename_len bytes)
//!          then dest_path_len (u8)
//!          then dest_path     (dest_path_len bytes)
//!          then mime          (mime_len bytes)
//! ```

#![allow(dead_code)]

use super::cookie_jar::{CookieEntry, CookieJar, SameSite};
use super::downloads::{DownloadJob, DownloadManager, DownloadState};
use super::session::{SessionTable, NAV_HISTORY_DEPTH};
use super::types::{
    BrowserCap, BrowserSessionId, DownloadId, MimeType, RequestId, MIME_MAX, URL_MAX,
};
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SNAPSHOT_MAGIC: u32 = 0x4252_5357;
pub const SNAPSHOT_VERSION: u32 = 2;
pub const HEADER_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// Internal write/read helpers
// ---------------------------------------------------------------------------

#[inline]
fn write_u16(out: &mut [u8], pos: &mut usize, v: u16) {
    out[*pos] = v as u8;
    out[*pos + 1] = (v >> 8) as u8;
    *pos += 2;
}

#[inline]
fn write_u32(out: &mut [u8], pos: &mut usize, v: u32) {
    let b = v.to_le_bytes();
    out[*pos..*pos + 4].copy_from_slice(&b);
    *pos += 4;
}

#[inline]
fn write_u64(out: &mut [u8], pos: &mut usize, v: u64) {
    let b = v.to_le_bytes();
    out[*pos..*pos + 8].copy_from_slice(&b);
    *pos += 8;
}

#[inline]
fn write_u8(out: &mut [u8], pos: &mut usize, v: u8) {
    out[*pos] = v;
    *pos += 1;
}

#[inline]
fn write_bytes(out: &mut [u8], pos: &mut usize, src: &[u8]) {
    out[*pos..*pos + src.len()].copy_from_slice(src);
    *pos += src.len();
}

#[inline]
fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= buf.len() {
        return None;
    }
    let v = buf[*pos];
    *pos += 1;
    Some(v)
}

#[inline]
fn read_u16(buf: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > buf.len() {
        return None;
    }
    let v = u16::from_le_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Some(v)
}

#[inline]
fn read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > buf.len() {
        return None;
    }
    let v = u32::from_le_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Some(v)
}

#[inline]
fn read_u64(buf: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > buf.len() {
        return None;
    }
    let v = u64::from_le_bytes([
        buf[*pos],
        buf[*pos + 1],
        buf[*pos + 2],
        buf[*pos + 3],
        buf[*pos + 4],
        buf[*pos + 5],
        buf[*pos + 6],
        buf[*pos + 7],
    ]);
    *pos += 8;
    Some(v)
}

/// Read `len` bytes from `buf` at `pos` into `dst[..len]`.
/// Returns `false` (and leaves `pos`/`dst` unchanged on failure) if bounds
/// would be exceeded.
#[inline]
fn read_bytes(buf: &[u8], pos: &mut usize, dst: &mut [u8], len: usize) -> bool {
    if len > dst.len() || *pos + len > buf.len() {
        return false;
    }
    dst[..len].copy_from_slice(&buf[*pos..*pos + len]);
    *pos += len;
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Serialise full browser state into `out`.
///
/// Includes session identity, navigation history, cookies and active download
/// jobs.  `ResponseCache` body data and VFS-backed `StorageTable` entries are
/// excluded (the former is too large; the latter is already persistent).
///
/// Returns the number of bytes written, or 0 if `out` is too small.
pub fn snapshot(
    sessions: &SessionTable,
    cookies: &CookieJar,
    downloads: &DownloadManager,
    out: &mut [u8],
) -> usize {
    use super::session::MAX_BROWSER_SESSIONS;

    // We write into `out` starting at `pos`.  If at any point we would
    // overflow, we abort and return 0 so the caller knows the buffer needs
    // to be larger.
    if out.len() < HEADER_SIZE {
        return 0;
    }

    let mut pos = HEADER_SIZE; // reserve header, fill at end

    // ------------------------------------------------------------------
    // SESSION records
    // ------------------------------------------------------------------
    let mut session_count = 0u32;
    for i in 0..MAX_BROWSER_SESSIONS {
        let s = match sessions.get(i) {
            Some(s) => s,
            None => continue,
        };

        // Fixed per-session header: id(4)+pid(4)+cap(8)+alive(1)+next_req_id(4)
        //                           +nav_head(1)+nav_count(1) = 23 bytes
        if pos + 23 > out.len() {
            return 0;
        }
        write_u32(out, &mut pos, s.id.0);
        write_u32(out, &mut pos, s.pid.0);
        write_u64(out, &mut pos, s.cap.0);
        write_u8(out, &mut pos, 1u8); // alive
        write_u32(out, &mut pos, s.next_request_id);
        write_u8(out, &mut pos, (s.nav_head() % NAV_HISTORY_DEPTH) as u8);
        write_u8(out, &mut pos, s.nav_count().min(NAV_HISTORY_DEPTH) as u8);

        // Nav entries: always write NAV_HISTORY_DEPTH slots so restore can
        // index them directly by ring position.
        for i in 0..NAV_HISTORY_DEPTH {
            let e = s.nav_entry(i).unwrap(); // always Some — i < NAV_HISTORY_DEPTH
            let url_len = if e.active { e.url_len.min(URL_MAX) } else { 0 };
            if pos + 2 + url_len > out.len() {
                return 0;
            }
            write_u16(out, &mut pos, url_len as u16);
            if url_len > 0 {
                write_bytes(out, &mut pos, &e.url[..url_len]);
            }
        }

        session_count += 1;
    }

    // ------------------------------------------------------------------
    // COOKIE records
    // ------------------------------------------------------------------
    let mut cookie_count = 0u32;
    for entry in cookies.entries_iter() {
        // flags: bit0=http_only, bit1=secure, bit2-3=same_site(0=Lax,1=Strict,2=None)
        let ss_bits: u8 = match entry.same_site {
            SameSite::Lax => 0,
            SameSite::Strict => 1,
            SameSite::None => 2,
        };
        let flags = (entry.http_only as u8)
            | ((entry.secure as u8) << 1)
            | (ss_bits << 2);

        let name_len = entry.name_len.min(128) as u8;
        let value_len = entry.value_len.min(4096) as u16;
        let domain_len = entry.domain_len.min(253) as u8;
        let path_len = entry.path_len.min(255) as u8;

        let rec_size = 18
            + name_len as usize
            + value_len as usize
            + domain_len as usize
            + path_len as usize;
        if pos + rec_size > out.len() {
            return 0;
        }

        write_u32(out, &mut pos, entry.session.0);
        write_u64(out, &mut pos, entry.expires);
        write_u8(out, &mut pos, flags);
        write_u8(out, &mut pos, name_len);
        write_u16(out, &mut pos, value_len);
        write_u8(out, &mut pos, domain_len);
        write_u8(out, &mut pos, path_len);
        write_bytes(out, &mut pos, &entry.name[..name_len as usize]);
        write_bytes(out, &mut pos, &entry.value[..value_len as usize]);
        write_bytes(out, &mut pos, &entry.domain[..domain_len as usize]);
        write_bytes(out, &mut pos, &entry.path[..path_len as usize]);

        cookie_count += 1;
    }

    // ------------------------------------------------------------------
    // DOWNLOAD records
    // ------------------------------------------------------------------
    let mut download_count = 0u32;
    for job in downloads.jobs_iter() {
        let state_byte: u8 = match job.state {
            DownloadState::Pending => 0,
            DownloadState::Active => 1,
            DownloadState::Complete => 2,
            DownloadState::Rejected => 3,
            DownloadState::Error => 4,
        };
        let filename_len = job.filename_len.min(255) as u8;
        let mime_len = job.mime.len.min(MIME_MAX) as u8;
        let dest_path_len = job.dest_path_len.min(255) as u8;

        // Fixed: id(4)+session(4)+state(1)+filename_len(1)+mime_len(1)
        //        +size_hint(8)+bytes_written(8) = 27 bytes
        // Variable: filename + dest_path_len(1) + dest_path + mime
        let rec_size = 27
            + filename_len as usize
            + 1
            + dest_path_len as usize
            + mime_len as usize;
        if pos + rec_size > out.len() {
            return 0;
        }

        write_u32(out, &mut pos, job.id.0);
        write_u32(out, &mut pos, job.session.0);
        write_u8(out, &mut pos, state_byte);
        write_u8(out, &mut pos, filename_len);
        write_u8(out, &mut pos, mime_len);
        write_u64(out, &mut pos, job.size_hint);
        write_u64(out, &mut pos, job.bytes_written);
        write_bytes(out, &mut pos, &job.filename[..filename_len as usize]);
        write_u8(out, &mut pos, dest_path_len);
        write_bytes(out, &mut pos, &job.dest_path[..dest_path_len as usize]);
        write_bytes(out, &mut pos, &job.mime.bytes[..mime_len as usize]);

        download_count += 1;
    }

    // ------------------------------------------------------------------
    // Write header now that we know all counts
    // ------------------------------------------------------------------
    let mut hpos = 0usize;
    write_u32(out, &mut hpos, SNAPSHOT_MAGIC);
    write_u32(out, &mut hpos, SNAPSHOT_VERSION);
    write_u32(out, &mut hpos, session_count);
    write_u32(out, &mut hpos, cookie_count);
    write_u32(out, &mut hpos, download_count);
    write_u32(out, &mut hpos, 0u32); // reserved

    pos
}

/// Validate the header of a snapshot payload.
///
/// Returns `true` if the payload looks like a valid v2 browser-backend
/// snapshot; does not restore any state.
pub fn validate_snapshot(payload: &[u8]) -> bool {
    if payload.len() < HEADER_SIZE {
        return false;
    }
    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let version = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    magic == SNAPSHOT_MAGIC && version == SNAPSHOT_VERSION
}

/// Restore full browser state from a snapshot.
///
/// Restores session identities, navigation history, cookies, and download
/// jobs.  `ResponseCache` and `StorageTable` are intentionally excluded.
///
/// Returns the number of sessions successfully restored, or 0 on format error.
pub fn restore(
    sessions: &mut SessionTable,
    cookies: &mut CookieJar,
    downloads: &mut DownloadManager,
    payload: &[u8],
) -> usize {
    use super::session::MAX_BROWSER_SESSIONS;

    if !validate_snapshot(payload) {
        return 0;
    }

    let mut pos = 4usize; // skip magic (already validated)
    let _version = match read_u32(payload, &mut pos) {
        Some(v) => v,
        None => return 0,
    };
    let session_count = match read_u32(payload, &mut pos) {
        Some(v) => v as usize,
        None => return 0,
    };
    let cookie_count = match read_u32(payload, &mut pos) {
        Some(v) => v as usize,
        None => return 0,
    };
    let download_count = match read_u32(payload, &mut pos) {
        Some(v) => v as usize,
        None => return 0,
    };
    let _reserved = read_u32(payload, &mut pos); // skip reserved field

    // ------------------------------------------------------------------
    // SESSION records
    // ------------------------------------------------------------------
    let mut restored = 0usize;
    for _ in 0..session_count.min(MAX_BROWSER_SESSIONS) {
        let session_id = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let pid = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let cap = match read_u64(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let alive = match read_u8(payload, &mut pos) {
            Some(v) => v != 0,
            None => break,
        };
        let next_request_id = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let nav_head = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let nav_count = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };

        // Read NAV_HISTORY_DEPTH nav entries (always written, even inactive).
        let mut nav_entries: [(usize, [u8; URL_MAX]); NAV_HISTORY_DEPTH] =
            [(0, [0u8; URL_MAX]); NAV_HISTORY_DEPTH];
        let mut nav_ok = true;
        for nav_entry in nav_entries.iter_mut() {
            let url_len = match read_u16(payload, &mut pos) {
                Some(v) => v as usize,
                None => {
                    nav_ok = false;
                    break;
                }
            };
            let url_len = url_len.min(URL_MAX);
            if url_len > 0 {
                if !read_bytes(payload, &mut pos, &mut nav_entry.1, url_len) {
                    nav_ok = false;
                    break;
                }
                nav_entry.0 = url_len;
            }
        }
        if !nav_ok {
            break;
        }

        if alive {
            let idx = match session_id
                .checked_sub(1)
                .map(|v| v as usize)
                .filter(|i| *i < MAX_BROWSER_SESSIONS)
            {
                Some(i) => i,
                None => continue,
            };
            if sessions.restore(
                idx,
                BrowserSessionId(session_id),
                ProcessId(pid),
                BrowserCap(cap),
            ) {
                sessions.restore_nav(
                    idx,
                    next_request_id,
                    nav_head,
                    nav_count,
                    &nav_entries,
                );
                restored += 1;
            }
        }
    }

    // ------------------------------------------------------------------
    // COOKIE records
    // ------------------------------------------------------------------
    for _ in 0..cookie_count {
        let session_id = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let expires = match read_u64(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let flags = match read_u8(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let name_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let value_len = match read_u16(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let domain_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let path_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };

        // Bounds-check lengths before reading variable data.
        if name_len > 128 || value_len > 4096 || domain_len > 253 || path_len > 256 {
            break;
        }

        let mut entry = CookieEntry::EMPTY;
        if !read_bytes(payload, &mut pos, &mut entry.name, name_len) {
            break;
        }
        entry.name_len = name_len;
        if !read_bytes(payload, &mut pos, &mut entry.value, value_len) {
            break;
        }
        entry.value_len = value_len;
        if !read_bytes(payload, &mut pos, &mut entry.domain, domain_len) {
            break;
        }
        entry.domain_len = domain_len;
        if !read_bytes(payload, &mut pos, &mut entry.path[..], path_len) {
            break;
        }
        entry.path_len = path_len;

        entry.session = BrowserSessionId(session_id);
        entry.expires = expires;
        entry.http_only = (flags & 0x01) != 0;
        entry.secure = (flags & 0x02) != 0;
        entry.same_site = match (flags >> 2) & 0x03 {
            1 => SameSite::Strict,
            2 => SameSite::None,
            _ => SameSite::Lax,
        };
        entry.active = true;

        cookies.restore_entry(entry);
    }

    // ------------------------------------------------------------------
    // DOWNLOAD records
    // ------------------------------------------------------------------
    for _ in 0..download_count {
        let id = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let session_id = match read_u32(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let state_byte = match read_u8(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let filename_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let mime_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        let size_hint = match read_u64(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };
        let bytes_written = match read_u64(payload, &mut pos) {
            Some(v) => v,
            None => break,
        };

        if filename_len > 255 || mime_len > MIME_MAX {
            break;
        }

        let mut job = DownloadJob::EMPTY;
        if !read_bytes(payload, &mut pos, &mut job.filename, filename_len) {
            break;
        }
        job.filename_len = filename_len;

        let dest_path_len = match read_u8(payload, &mut pos) {
            Some(v) => v as usize,
            None => break,
        };
        if dest_path_len > 255 {
            break;
        }
        if !read_bytes(payload, &mut pos, &mut job.dest_path, dest_path_len) {
            break;
        }
        job.dest_path_len = dest_path_len;

        let mut mime_bytes = [0u8; MIME_MAX];
        if !read_bytes(payload, &mut pos, &mut mime_bytes, mime_len) {
            break;
        }
        job.mime = MimeType::from_bytes(&mime_bytes[..mime_len]);

        job.id = DownloadId(id);
        job.session = BrowserSessionId(session_id);
        job.size_hint = size_hint;
        job.bytes_written = bytes_written;
        job.state = match state_byte {
            0 => DownloadState::Pending,
            1 => DownloadState::Active,
            2 => DownloadState::Complete,
            3 => DownloadState::Rejected,
            _ => DownloadState::Error,
        };
        job.request = RequestId(0); // request context is not meaningful after restore
        job.active = true;

        downloads.restore_job(job);
    }

    restored
}
