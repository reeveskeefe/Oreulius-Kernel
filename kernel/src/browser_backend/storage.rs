//! Per-origin persistent storage slots backed by the kernel VFS.
//!
//! Each session gets a private directory under `/browser/<session_id>/`.
//! Files within it are addressed by a short key (ASCII filename).
//! All path construction uses only fixed arrays; no heap allocation.

#![allow(dead_code)]

use crate::fs::vfs;

use super::types::BrowserSessionId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Root directory for all browser storage.
pub const STORAGE_ROOT: &str = "/browser";

/// Maximum length of a storage key (used as filename).
pub const KEY_MAX: usize = 64;

/// Maximum bytes that may be written in a single `write` call.
pub const VALUE_MAX: usize = 64 * 1024; // 64 KiB

// ---------------------------------------------------------------------------
// StorageError
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    PathTooLong,
    KeyInvalid,
    WriteFailed,
    ReadFailed,
    NotFound,
    VfsError,
}

// ---------------------------------------------------------------------------
// OriginStorage
// ---------------------------------------------------------------------------

/// Thin wrapper that scopes VFS operations to a session's storage directory.
#[derive(Clone)]
pub struct OriginStorage {
    /// Pre-built base path: `/browser/<session_id>/` (null-terminated ASCII).
    base: [u8; 64],
    base_len: usize,
}

impl OriginStorage {
    /// Create a new `OriginStorage` view for `session`.
    ///
    /// Does **not** create the directory — call `ensure_dir()` first.
    pub fn new(session: BrowserSessionId) -> Self {
        let mut base = [0u8; 64];
        let len = build_base_path(&mut base, session);
        Self { base, base_len: len }
    }

    /// Ensure the session's storage directory exists in the VFS.
    pub fn ensure_dir(&self) -> Result<(), StorageError> {
        let path = self.base_str().ok_or(StorageError::PathTooLong)?;
        // mkdir is idempotent if the dir already exists (returns Ok).
        vfs::mkdir(path).map_err(|_| StorageError::VfsError)
    }

    /// Write `value` to key `key` within the session's storage.
    ///
    /// Overwrites any existing file with the same key.
    pub fn write(
        &self,
        key:   &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        validate_key(key)?;
        let path = self.key_path(key)?;
        let path_str = core::str::from_utf8(&path[..self.key_path_len(key)])
            .map_err(|_| StorageError::PathTooLong)?;
        vfs::write_path(path_str, value)
            .map(|_| ())
            .map_err(|_| StorageError::WriteFailed)
    }

    /// Read key `key` into `out`.  Returns bytes read.
    pub fn read(
        &self,
        key: &[u8],
        out: &mut [u8],
    ) -> Result<usize, StorageError> {
        validate_key(key)?;
        let path = self.key_path(key)?;
        let path_str = core::str::from_utf8(&path[..self.key_path_len(key)])
            .map_err(|_| StorageError::PathTooLong)?;
        vfs::read_path(path_str, out).map_err(|e| {
            if e.contains("not found") || e.contains("No such") {
                StorageError::NotFound
            } else {
                StorageError::ReadFailed
            }
        })
    }

    /// Delete the file at `key`.
    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        validate_key(key)?;
        let path = self.key_path(key)?;
        let path_str = core::str::from_utf8(&path[..self.key_path_len(key)])
            .map_err(|_| StorageError::PathTooLong)?;
        vfs::unlink(path_str).map_err(|_| StorageError::VfsError)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn base_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.base[..self.base_len]).ok()
    }

    /// Build the full VFS path for a key into a stack buffer.
    fn key_path(&self, key: &[u8]) -> Result<[u8; 128], StorageError> {
        let mut buf = [0u8; 128];
        let kl = key.len();
        if self.base_len + kl + 1 > 128 {
            return Err(StorageError::PathTooLong);
        }
        buf[..self.base_len].copy_from_slice(&self.base[..self.base_len]);
        buf[self.base_len..self.base_len + kl].copy_from_slice(key);
        // null-terminate
        buf[self.base_len + kl] = 0;
        Ok(buf)
    }

    fn key_path_len(&self, key: &[u8]) -> usize {
        self.base_len + key.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_base_path(buf: &mut [u8; 64], session: BrowserSessionId) -> usize {
    // "/browser/<decimal>/"
    let prefix    = b"/browser/";
    let prefix_len = prefix.len();
    buf[..prefix_len].copy_from_slice(prefix);
    let mut pos = prefix_len;
    let mut id  = session.0;
    let mut tmp = [0u8; 10];
    let mut tlen = 0usize;
    if id == 0 {
        tmp[0] = b'0';
        tlen   = 1;
    } else {
        while id > 0 {
            tmp[tlen] = b'0' + (id % 10) as u8;
            id /= 10;
            tlen += 1;
        }
    }
    for i in 0..tlen {
        if pos < 63 { buf[pos] = tmp[tlen - 1 - i]; pos += 1; }
    }
    if pos < 63 { buf[pos] = b'/'; pos += 1; }
    pos
}

fn validate_key(key: &[u8]) -> Result<(), StorageError> {
    if key.is_empty() || key.len() > KEY_MAX {
        return Err(StorageError::KeyInvalid);
    }
    // Allow only printable ASCII excluding path separators.
    for &b in key {
        if b < 0x20 || b == b'/' || b == b'\\' || b == 0x7f {
            return Err(StorageError::KeyInvalid);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// StorageTable — per-session OriginStorage registry
// ---------------------------------------------------------------------------

/// A small fixed-size table mapping `BrowserSessionId` → `OriginStorage`.
///
/// The kernel service holds one instance; storage views are allocated lazily.
pub struct StorageTable {
    entries:  [StorageEntry; 16],
    count:    usize,
}

#[derive(Clone)]
struct StorageEntry {
    session: BrowserSessionId,
    storage: OriginStorage,
    active:  bool,
}

impl StorageEntry {
    const EMPTY: Self = Self {
        session: BrowserSessionId(0),
        storage: OriginStorage { base: [0; 64], base_len: 0 },
        active:  false,
    };
}

impl StorageTable {
    pub const fn new() -> Self {
        Self {
            entries: [StorageEntry::EMPTY; 16],
            count:   0,
        }
    }

    /// Register a session and ensure its storage directory exists.
    pub fn register(&mut self, session: BrowserSessionId) -> bool {
        if self.count >= 16 { return false; }
        for e in &mut self.entries {
            if !e.active {
                let storage = OriginStorage::new(session);
                let _ = storage.ensure_dir();
                e.session = session;
                e.storage = storage;
                e.active  = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Remove a session's storage entry (does **not** delete VFS files).
    pub fn unregister(&mut self, session: BrowserSessionId) {
        for e in &mut self.entries {
            if e.active && e.session == session {
                e.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Get the `OriginStorage` for a session.
    pub fn storage(&self, session: BrowserSessionId) -> Option<&OriginStorage> {
        for e in &self.entries {
            if e.active && e.session == session {
                return Some(&e.storage);
            }
        }
        None
    }
}
