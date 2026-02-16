/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

//! Temporal Objects (versioned kernel state for files).
//!
//! This module maintains per-path immutable version chains with Merkle metadata,
//! enabling snapshot/history/read-at-version/rollback semantics.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

use crate::temporal_asm;

pub const MAX_TEMPORAL_OBJECTS: usize = 128;
pub const MAX_VERSIONS_PER_OBJECT: usize = 64;
pub const MAX_TEMPORAL_VERSION_BYTES: usize = 256 * 1024;
pub const MAX_TEMPORAL_CAPTURE_BYTES: usize = crate::vfs::MAX_VFS_FILE_SIZE;
pub const MERKLE_CHUNK_BYTES: usize = 64;
pub const TEMPORAL_HASH_SEED: u32 = 0x811C9DC5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TemporalOperation {
    Snapshot = 1,
    Write = 2,
    Rollback = 3,
}

impl TemporalOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            TemporalOperation::Snapshot => "snapshot",
            TemporalOperation::Write => "write",
            TemporalOperation::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TemporalVersionMeta {
    pub version_id: u64,
    pub parent_version_id: Option<u64>,
    pub rollback_from_version_id: Option<u64>,
    pub branch_id: u32,
    pub tick: u64,
    pub data_len: usize,
    pub leaf_count: u32,
    pub content_hash: u32,
    pub merkle_root: u32,
    pub operation: TemporalOperation,
}

#[derive(Clone, Debug)]
struct TemporalVersionEntry {
    meta: TemporalVersionMeta,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct TemporalObjectHistory {
    path: String,
    versions: Vec<TemporalVersionEntry>,
    head_version_id: Option<u64>,
    active_branch_id: u32,
    next_branch_id: u32,
}

impl TemporalObjectHistory {
    fn new(path: String) -> Self {
        Self {
            path,
            versions: Vec::new(),
            head_version_id: None,
            active_branch_id: 0,
            next_branch_id: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalError {
    InvalidPath,
    ObjectLimit,
    VersionLimit,
    PayloadTooLarge,
    ObjectNotFound,
    VersionNotFound,
    VfsReadFailed,
    VfsWriteFailed,
}

impl TemporalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TemporalError::InvalidPath => "invalid path",
            TemporalError::ObjectLimit => "temporal object limit reached",
            TemporalError::VersionLimit => "version limit reached for object",
            TemporalError::PayloadTooLarge => "payload exceeds temporal version byte limit",
            TemporalError::ObjectNotFound => "temporal object not found",
            TemporalError::VersionNotFound => "version not found",
            TemporalError::VfsReadFailed => "failed to read path from VFS",
            TemporalError::VfsWriteFailed => "failed to write path to VFS",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TemporalStats {
    pub objects: usize,
    pub versions: usize,
    pub bytes: usize,
    pub active_branches: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct TemporalRollbackResult {
    pub new_version_id: u64,
    pub branch_id: u32,
    pub restored_len: usize,
}

struct TemporalService {
    objects: Vec<TemporalObjectHistory>,
    next_version_id: u64,
}

impl TemporalService {
    const fn new() -> Self {
        Self {
            objects: Vec::new(),
            next_version_id: 1,
        }
    }

    fn find_object_index(&self, path: &str) -> Option<usize> {
        self.objects.iter().position(|obj| obj.path == path)
    }

    fn ensure_object_index(&mut self, path: &str) -> Result<usize, TemporalError> {
        if let Some(index) = self.find_object_index(path) {
            return Ok(index);
        }

        if self.objects.len() >= MAX_TEMPORAL_OBJECTS {
            return Err(TemporalError::ObjectLimit);
        }

        self.objects.push(TemporalObjectHistory::new(path.to_string()));
        Ok(self.objects.len().saturating_sub(1))
    }

    fn record_version_locked(
        &mut self,
        path: &str,
        payload: &[u8],
        operation: TemporalOperation,
    ) -> Result<u64, TemporalError> {
        if payload.len() > MAX_TEMPORAL_VERSION_BYTES {
            return Err(TemporalError::PayloadTooLarge);
        }

        let index = self.ensure_object_index(path)?;
        let object = self
            .objects
            .get_mut(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        if object.versions.len() >= MAX_VERSIONS_PER_OBJECT {
            return Err(TemporalError::VersionLimit);
        }

        let version_id = self.next_version_id;
        self.next_version_id = self.next_version_id.saturating_add(1);

        let (content_hash, merkle_root, leaf_count) = compute_version_hashes(payload);
        let mut data = Vec::new();
        data.resize(payload.len(), 0);
        temporal_asm::copy_bytes(&mut data, payload);

        let meta = TemporalVersionMeta {
            version_id,
            parent_version_id: object.head_version_id,
            rollback_from_version_id: None,
            branch_id: object.active_branch_id,
            tick: crate::pit::get_ticks(),
            data_len: data.len(),
            leaf_count,
            content_hash,
            merkle_root,
            operation,
        };

        object.versions.push(TemporalVersionEntry { meta, payload: data });
        object.head_version_id = Some(version_id);

        Ok(version_id)
    }

    fn get_head_version_id(&self, path: &str) -> Result<Option<u64>, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        Ok(self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?
            .head_version_id)
    }

    fn mark_latest_rollback_locked(
        &mut self,
        path: &str,
        rollback_from: u64,
        previous_head: Option<u64>,
    ) -> Result<TemporalRollbackResult, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;

        let object = self
            .objects
            .get_mut(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let latest = object
            .versions
            .last_mut()
            .ok_or(TemporalError::VersionNotFound)?;

        latest.meta.operation = TemporalOperation::Rollback;
        latest.meta.rollback_from_version_id = Some(rollback_from);

        if previous_head.is_some() && previous_head != Some(rollback_from) {
            let new_branch = object.next_branch_id;
            object.active_branch_id = new_branch;
            object.next_branch_id = object.next_branch_id.saturating_add(1);
            latest.meta.branch_id = new_branch;
        } else {
            latest.meta.branch_id = object.active_branch_id;
        }

        Ok(TemporalRollbackResult {
            new_version_id: latest.meta.version_id,
            branch_id: latest.meta.branch_id,
            restored_len: latest.meta.data_len,
        })
    }

    fn read_version_payload_locked(&self, path: &str, version_id: u64) -> Result<Vec<u8>, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;

        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let entry = object
            .versions
            .iter()
            .find(|entry| entry.meta.version_id == version_id)
            .ok_or(TemporalError::VersionNotFound)?;

        Ok(entry.payload.clone())
    }

    fn latest_meta_locked(&self, path: &str) -> Result<TemporalVersionMeta, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;

        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let latest = object
            .versions
            .last()
            .ok_or(TemporalError::VersionNotFound)?;

        Ok(latest.meta.clone())
    }

    fn list_version_metas_locked(&self, path: &str) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;

        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let mut out = Vec::with_capacity(object.versions.len());
        for entry in &object.versions {
            out.push(entry.meta.clone());
        }

        Ok(out)
    }

    fn history_window_locked(
        &self,
        path: &str,
        start_from_newest: usize,
        max_entries: usize,
    ) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        if max_entries == 0 || start_from_newest >= object.versions.len() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        out.reserve(max_entries);

        let mut consumed = 0usize;
        while consumed < max_entries {
            let newest_offset = start_from_newest.saturating_add(consumed);
            if newest_offset >= object.versions.len() {
                break;
            }
            let idx = object
                .versions
                .len()
                .saturating_sub(1)
                .saturating_sub(newest_offset);
            out.push(object.versions[idx].meta.clone());
            consumed = consumed.saturating_add(1);
        }

        Ok(out)
    }

    fn stats_locked(&self) -> TemporalStats {
        let mut stats = TemporalStats::default();
        stats.objects = self.objects.len();

        for object in &self.objects {
            stats.versions = stats.versions.saturating_add(object.versions.len());
            stats.active_branches = stats
                .active_branches
                .saturating_add((object.active_branch_id as usize).saturating_add(1));
            for entry in &object.versions {
                stats.bytes = stats.bytes.saturating_add(entry.meta.data_len);
            }
        }

        stats
    }
}

static TEMPORAL: Mutex<TemporalService> = Mutex::new(TemporalService::new());

fn normalize_path(path: &str) -> Result<String, TemporalError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(TemporalError::InvalidPath);
    }

    if trimmed.starts_with('/') {
        Ok(trimmed.to_string())
    } else {
        let mut normalized = String::from("/");
        normalized.push_str(trimmed);
        Ok(normalized)
    }
}

fn compute_version_hashes(payload: &[u8]) -> (u32, u32, u32) {
    let content_hash = temporal_asm::fnv1a32(payload, TEMPORAL_HASH_SEED);

    if payload.is_empty() {
        let root = temporal_asm::hash_pair(content_hash, TEMPORAL_HASH_SEED ^ 0xA5A5_5A5A);
        return (content_hash, root, 1);
    }

    let mut leaves: Vec<u32> = Vec::with_capacity((payload.len() + MERKLE_CHUNK_BYTES - 1) / MERKLE_CHUNK_BYTES);
    for (chunk_index, chunk) in payload.chunks(MERKLE_CHUNK_BYTES).enumerate() {
        let seed = TEMPORAL_HASH_SEED ^ ((chunk_index as u32).wrapping_mul(0x9E37_79B1));
        leaves.push(temporal_asm::fnv1a32(chunk, seed));
    }

    let leaf_count = leaves.len() as u32;
    let merkle_root = temporal_asm::merkle_root(&mut leaves);
    (content_hash, merkle_root, leaf_count)
}

pub fn init() {
    // Statically initialized.
}

pub fn record_write(path: &str, payload: &[u8]) -> Result<u64, TemporalError> {
    let normalized = normalize_path(path)?;
    TEMPORAL
        .lock()
        .record_version_locked(&normalized, payload, TemporalOperation::Write)
}

pub fn snapshot_path(path: &str) -> Result<u64, TemporalError> {
    let normalized = normalize_path(path)?;

    let mut read_buf = Vec::new();
    read_buf.resize(MAX_TEMPORAL_CAPTURE_BYTES, 0);

    let read = crate::vfs::read_path(&normalized, &mut read_buf).map_err(|_| TemporalError::VfsReadFailed)?;
    read_buf.truncate(read);

    TEMPORAL
        .lock()
        .record_version_locked(&normalized, &read_buf, TemporalOperation::Snapshot)
}

pub fn read_version(path: &str, version_id: u64) -> Result<Vec<u8>, TemporalError> {
    let normalized = normalize_path(path)?;
    TEMPORAL
        .lock()
        .read_version_payload_locked(&normalized, version_id)
}

pub fn list_versions(path: &str) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
    let normalized = normalize_path(path)?;
    TEMPORAL.lock().list_version_metas_locked(&normalized)
}

pub fn latest_version(path: &str) -> Result<TemporalVersionMeta, TemporalError> {
    let normalized = normalize_path(path)?;
    TEMPORAL.lock().latest_meta_locked(&normalized)
}

pub fn history_window(
    path: &str,
    start_from_newest: usize,
    max_entries: usize,
) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
    let normalized = normalize_path(path)?;
    TEMPORAL
        .lock()
        .history_window_locked(&normalized, start_from_newest, max_entries)
}

pub fn rollback_path(path: &str, rollback_to_version_id: u64) -> Result<TemporalRollbackResult, TemporalError> {
    let normalized = normalize_path(path)?;

    let (payload, previous_head) = {
        let service = TEMPORAL.lock();
        let payload = service.read_version_payload_locked(&normalized, rollback_to_version_id)?;
        let previous_head = service.get_head_version_id(&normalized)?;
        (payload, previous_head)
    };

    crate::vfs::write_path(&normalized, &payload).map_err(|_| TemporalError::VfsWriteFailed)?;

    TEMPORAL
        .lock()
        .mark_latest_rollback_locked(&normalized, rollback_to_version_id, previous_head)
}

pub fn stats() -> TemporalStats {
    TEMPORAL.lock().stats_locked()
}

pub fn vfs_fd_capture_self_check() -> Result<(), &'static str> {
    let pid = crate::process::process_manager()
        .spawn("temporal-fd-selfcheck", None)
        .map_err(|_| "spawn failed")?;

    const PATH: &str = "/temporal-fd-selfcheck";
    let result = (|| -> Result<(), &'static str> {
        crate::vfs::write_path(PATH, b"seed").map_err(|_| "seed write failed")?;

        let before = list_versions(PATH)
            .map_err(|_| "history unavailable before fd write")?
            .len();

        let flags = crate::vfs::OpenFlags::READ | crate::vfs::OpenFlags::WRITE;
        let fd = crate::vfs::open_for_pid(pid, PATH, flags).map_err(|_| "open_for_pid failed")?;
        let write_res = crate::vfs::write_fd(pid, fd, b"x").map_err(|_| "write_fd failed");
        let _ = crate::vfs::close_fd(pid, fd);
        write_res?;

        let history = list_versions(PATH).map_err(|_| "history unavailable after fd write")?;
        if history.len() <= before {
            return Err("fd write did not produce a temporal version");
        }

        let latest = history
            .last()
            .ok_or("missing latest temporal entry after fd write")?;
        if latest.operation != TemporalOperation::Write {
            return Err("latest temporal entry after fd write is not a write");
        }

        let payload = read_version(PATH, latest.version_id)
            .map_err(|_| "unable to read fd-captured temporal payload")?;
        if payload.is_empty() || payload[0] != b'x' {
            return Err("fd-captured payload mismatch");
        }

        Ok(())
    })();

    let _ = crate::process::process_manager().terminate(pid);
    result
}
