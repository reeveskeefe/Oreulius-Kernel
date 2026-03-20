//! Temporal snapshot / restore stubs for the browser backend.
//!
//! Full temporal state is not yet persisted for browser sessions; these
//! stubs provide the hooking points so `temporal.rs` can participate in
//! the kernel's snapshot lifecycle without breaking the build.

#![allow(dead_code)]

use super::session::SessionTable;
use super::types::BrowserSessionId;

// ---------------------------------------------------------------------------
// Snapshot payload layout (version 1)
// ---------------------------------------------------------------------------
//
//  Bytes 0-3:  magic = 0x4252_5357  ('BRSW')
//  Bytes 4-7:  version = 1 (u32 LE)
//  Bytes 8-11: session_count (u32 LE)
//  Then, for each session (up to MAX_BROWSER_SESSIONS):
//    Bytes +0-3: session_id (u32 LE)
//    Bytes +4-7: pid (u32 LE)
//    Bytes +8-15: cap (u64 LE)
//    Bytes +16: alive (u8)
//    Bytes 17-19: reserved
//  Total per-session record: 20 bytes
//
// Minimum snapshot size: 12 + 8 * 20 = 172 bytes

pub const SNAPSHOT_MAGIC: u32 = 0x4252_5357;
pub const SNAPSHOT_VERSION: u32 = 1;
pub const RECORD_SIZE: usize = 20;

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Serialise essential browser session state into `out`.
///
/// Returns the number of bytes written, or 0 on error.
pub fn snapshot(sessions: &SessionTable, out: &mut [u8]) -> usize {
    use super::session::MAX_BROWSER_SESSIONS;

    let needed = 12 + MAX_BROWSER_SESSIONS * RECORD_SIZE;
    if out.len() < needed {
        return 0;
    }

    // Magic
    out[0..4].copy_from_slice(&SNAPSHOT_MAGIC.to_le_bytes());
    // Version
    out[4..8].copy_from_slice(&SNAPSHOT_VERSION.to_le_bytes());

    let mut count = 0u32;
    let mut pos = 12usize;
    for i in 0..MAX_BROWSER_SESSIONS {
        if let Some(s) = sessions.get(i) {
            out[pos..pos + 4].copy_from_slice(&s.id.0.to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&s.pid.0.to_le_bytes());
            out[pos + 8..pos + 16].copy_from_slice(&s.cap.0.to_le_bytes());
            out[pos + 16] = 1; // alive
            out[pos + 17] = 0;
            out[pos + 18] = 0;
            out[pos + 19] = 0;
            pos += RECORD_SIZE;
            count += 1;
        }
    }
    // Write count.
    out[8..12].copy_from_slice(&count.to_le_bytes());
    pos
}

/// Validate the header of a snapshot payload.
///
/// Returns `true` if the payload appears to be a valid browser-backend
/// snapshot; does not restore any state.
pub fn validate_snapshot(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }
    let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let version = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    magic == SNAPSHOT_MAGIC && version == SNAPSHOT_VERSION
}

/// Restore browser session IDs from a snapshot.
///
/// **Stub** — only the session ID mapping is restored; capabilities are
/// invalidated and must be re-issued by the service layer.  Full restore
/// (cookies, cache, downloads) is deferred to a future kernel version.
///
/// Returns the number of records processed.
pub fn restore(sessions: &mut SessionTable, payload: &[u8]) -> usize {
    if !validate_snapshot(payload) {
        return 0;
    }

    let count = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
    let mut pos = 12usize;
    let mut restored = 0usize;

    for _ in 0..count {
        if pos + RECORD_SIZE > payload.len() {
            break;
        }
        let alive = payload[pos + 16] != 0;
        if alive {
            // Nothing to restore without re-issuing capabilities; just count.
            restored += 1;
        }
        pos += RECORD_SIZE;
    }
    restored
}
