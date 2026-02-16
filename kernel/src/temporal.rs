/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

//! Temporal Objects (versioned kernel state for files, sockets, and channels).
//!
//! This module maintains immutable version chains keyed by object path, with
//! Merkle metadata for integrity and replay-oriented auditing.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, Once};

use crate::temporal_asm;

pub const MAX_TEMPORAL_OBJECTS: usize = 128;
pub const MAX_VERSIONS_PER_OBJECT: usize = 64;
pub const MAX_TEMPORAL_VERSION_BYTES: usize = 256 * 1024;
pub const MAX_TEMPORAL_CAPTURE_BYTES: usize = crate::vfs::MAX_VFS_FILE_SIZE;
pub const MERKLE_CHUNK_BYTES: usize = 64;
pub const TEMPORAL_HASH_SEED: u32 = 0x811C9DC5;
pub const TEMPORAL_OBJECT_ENCODING_V1: u8 = 1;
pub const TEMPORAL_SOCKET_OBJECT_TCP_CONN: u8 = 1;
pub const TEMPORAL_SOCKET_OBJECT_TCP_LISTENER: u8 = 2;
pub const TEMPORAL_CHANNEL_OBJECT: u8 = 3;
pub const TEMPORAL_PROCESS_OBJECT: u8 = 4;
pub const TEMPORAL_CAPABILITY_OBJECT: u8 = 5;
pub const TEMPORAL_REGISTRY_OBJECT: u8 = 6;
pub const TEMPORAL_CONSOLE_OBJECT: u8 = 7;
pub const TEMPORAL_SECURITY_OBJECT: u8 = 8;
pub const TEMPORAL_CAPNET_OBJECT: u8 = 9;
pub const TEMPORAL_WASM_SERVICE_POINTER_OBJECT: u8 = 10;
pub const TEMPORAL_NETWORK_CONFIG_OBJECT: u8 = 11;
pub const TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT: u8 = 12;
pub const TEMPORAL_SCHEDULER_OBJECT: u8 = 13;
pub const TEMPORAL_REPLAY_MANAGER_OBJECT: u8 = 14;
pub const TEMPORAL_NETWORK_LEGACY_OBJECT: u8 = 15;
pub const TEMPORAL_WIFI_OBJECT: u8 = 16;
pub const TEMPORAL_ENCLAVE_OBJECT: u8 = 17;
pub const TEMPORAL_SOCKET_EVENT_LISTEN: u8 = 1;
pub const TEMPORAL_SOCKET_EVENT_ACCEPT: u8 = 2;
pub const TEMPORAL_SOCKET_EVENT_CONNECT: u8 = 3;
pub const TEMPORAL_SOCKET_EVENT_SEND: u8 = 4;
pub const TEMPORAL_SOCKET_EVENT_RECV: u8 = 5;
pub const TEMPORAL_SOCKET_EVENT_CLOSE: u8 = 6;
pub const TEMPORAL_SOCKET_EVENT_STATE: u8 = 7;
pub const TEMPORAL_CHANNEL_EVENT_SEND: u8 = 1;
pub const TEMPORAL_CHANNEL_EVENT_RECV: u8 = 2;
pub const TEMPORAL_CHANNEL_EVENT_CLOSE: u8 = 3;
pub const TEMPORAL_PROCESS_EVENT_SPAWN: u8 = 1;
pub const TEMPORAL_PROCESS_EVENT_TERMINATE: u8 = 2;
pub const TEMPORAL_CAPABILITY_EVENT_GRANT: u8 = 1;
pub const TEMPORAL_CAPABILITY_EVENT_REVOKE: u8 = 2;
pub const TEMPORAL_REGISTRY_EVENT_REGISTER: u8 = 1;
pub const TEMPORAL_REGISTRY_EVENT_UNREGISTER: u8 = 2;
pub const TEMPORAL_CONSOLE_EVENT_CREATE: u8 = 1;
pub const TEMPORAL_CONSOLE_EVENT_STATE: u8 = 2;
pub const TEMPORAL_SECURITY_EVENT_INTENT_POLICY: u8 = 1;
pub const TEMPORAL_CAPNET_EVENT_STATE: u8 = 1;
pub const TEMPORAL_WASM_SERVICE_POINTER_EVENT_STATE: u8 = 1;
pub const TEMPORAL_NETWORK_CONFIG_EVENT_STATE: u8 = 1;
pub const TEMPORAL_WASM_SYSCALL_MODULE_TABLE_EVENT_STATE: u8 = 1;
pub const TEMPORAL_SCHEDULER_EVENT_STATE: u8 = 1;
pub const TEMPORAL_REPLAY_MANAGER_EVENT_STATE: u8 = 1;
pub const TEMPORAL_NETWORK_LEGACY_EVENT_STATE: u8 = 1;
pub const TEMPORAL_WIFI_EVENT_STATE: u8 = 1;
pub const TEMPORAL_ENCLAVE_EVENT_STATE: u8 = 1;
pub const TEMPORAL_SOCKET_PAYLOAD_PREVIEW_BYTES: usize = 192;
const TEMPORAL_PERSIST_MAGIC: u32 = 0x5450_5354; // "TPST"
const TEMPORAL_PERSIST_VERSION: u16 = 2;
const TEMPORAL_PERSIST_VERSION_V1: u16 = 1;
const TEMPORAL_PERSIST_SENTINEL_U64: u64 = u64::MAX;
const DEFAULT_BRANCH_NAME: &str = "main";
const MAX_BRANCHES_PER_OBJECT: usize = 32;
const MAX_BRANCH_NAME_BYTES: usize = 48;
const MAX_TEMPORAL_ADAPTERS: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TemporalOperation {
    Snapshot = 1,
    Write = 2,
    Rollback = 3,
    Merge = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalRestoreMode {
    Rollback,
    Checkout,
    Merge,
}

impl TemporalOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            TemporalOperation::Snapshot => "snapshot",
            TemporalOperation::Write => "write",
            TemporalOperation::Rollback => "rollback",
            TemporalOperation::Merge => "merge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalMergeStrategy {
    FastForwardOnly,
    Ours,
    Theirs,
}

#[derive(Clone, Copy, Debug)]
pub struct TemporalMergeResult {
    pub fast_forward: bool,
    pub new_version_id: Option<u64>,
    pub target_branch_id: u32,
    pub source_branch_id: u32,
    pub target_head_before: Option<u64>,
    pub target_head_after: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TemporalBranchInfo {
    pub branch_id: u32,
    pub name: String,
    pub head_version_id: Option<u64>,
    pub active: bool,
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
struct TemporalBranchHead {
    branch_id: u32,
    name: String,
    head_version_id: Option<u64>,
}

#[derive(Clone, Debug)]
struct TemporalObjectHistory {
    path: String,
    versions: Vec<TemporalVersionEntry>,
    head_version_id: Option<u64>,
    active_branch_id: u32,
    next_branch_id: u32,
    branches: Vec<TemporalBranchHead>,
}

impl TemporalObjectHistory {
    fn new(path: String) -> Self {
        let mut branches = Vec::new();
        branches.push(TemporalBranchHead {
            branch_id: 0,
            name: String::from(DEFAULT_BRANCH_NAME),
            head_version_id: None,
        });
        Self {
            path,
            versions: Vec::new(),
            head_version_id: None,
            active_branch_id: 0,
            next_branch_id: 1,
            branches,
        }
    }

    fn find_branch_index_by_id(&self, branch_id: u32) -> Option<usize> {
        self.branches.iter().position(|b| b.branch_id == branch_id)
    }

    fn find_branch_index_by_name(&self, name: &str) -> Option<usize> {
        self.branches.iter().position(|b| b.name == name)
    }

    fn active_branch_index(&self) -> Option<usize> {
        self.find_branch_index_by_id(self.active_branch_id)
    }

    fn active_branch_head(&self) -> Option<u64> {
        self.active_branch_index()
            .and_then(|idx| self.branches.get(idx))
            .and_then(|b| b.head_version_id)
    }

    fn active_branch_name(&self) -> Option<&str> {
        self.active_branch_index()
            .and_then(|idx| self.branches.get(idx))
            .map(|b| b.name.as_str())
    }

    fn update_branch_head_by_id(&mut self, branch_id: u32, head: Option<u64>) -> bool {
        if let Some(idx) = self.find_branch_index_by_id(branch_id) {
            if let Some(branch) = self.branches.get_mut(idx) {
                branch.head_version_id = head;
                return true;
            }
        }
        false
    }

    fn ensure_branch_slot(&self) -> Result<(), TemporalError> {
        if self.branches.len() >= MAX_BRANCHES_PER_OBJECT {
            return Err(TemporalError::BranchLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporalError {
    InvalidPath,
    ObjectLimit,
    VersionLimit,
    BranchLimit,
    PayloadTooLarge,
    ObjectNotFound,
    VersionNotFound,
    BranchNotFound,
    BranchAlreadyExists,
    InvalidBranchName,
    MergeConflict,
    VfsReadFailed,
    VfsWriteFailed,
    AdapterRegistryFull,
    AdapterApplyFailed,
}

impl TemporalError {
    pub fn as_str(&self) -> &'static str {
        match self {
            TemporalError::InvalidPath => "invalid path",
            TemporalError::ObjectLimit => "temporal object limit reached",
            TemporalError::VersionLimit => "version limit reached for object",
            TemporalError::BranchLimit => "branch limit reached for object",
            TemporalError::PayloadTooLarge => "payload exceeds temporal version byte limit",
            TemporalError::ObjectNotFound => "temporal object not found",
            TemporalError::VersionNotFound => "version not found",
            TemporalError::BranchNotFound => "branch not found",
            TemporalError::BranchAlreadyExists => "branch already exists",
            TemporalError::InvalidBranchName => "invalid branch name",
            TemporalError::MergeConflict => "merge conflict",
            TemporalError::VfsReadFailed => "failed to read path from VFS",
            TemporalError::VfsWriteFailed => "failed to write path to VFS",
            TemporalError::AdapterRegistryFull => "temporal adapter registry full",
            TemporalError::AdapterApplyFailed => "temporal object apply failed",
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

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum TemporalAuditAction {
    Snapshot = 1,
    Write = 2,
    Rollback = 3,
    BranchCreate = 4,
    BranchCheckout = 5,
    Merge = 6,
    ReadVersion = 7,
    ListVersions = 8,
    LatestVersion = 9,
    HistoryWindow = 10,
    ListBranches = 11,
    Recover = 12,
}

#[derive(Clone, Copy)]
struct TemporalRetentionPolicy {
    max_persist_bytes: usize,
    max_versions_per_object: usize,
}

impl TemporalRetentionPolicy {
    const fn default() -> Self {
        Self {
            // Persistence snapshot payload is capped by `persistence::MAX_SNAPSHOT_SIZE`.
            max_persist_bytes: crate::persistence::MAX_SNAPSHOT_SIZE,
            // Keep a meaningful history by default, but bounded for durability.
            max_versions_per_object: 64,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TemporalLineHunk {
    base_start: usize,
    base_end: usize,
    other_start: usize,
    other_end: usize,
}

struct TemporalService {
    objects: Vec<TemporalObjectHistory>,
    next_version_id: u64,
    retention: TemporalRetentionPolicy,
}

impl TemporalService {
    const fn new() -> Self {
        Self {
            objects: Vec::new(),
            next_version_id: 1,
            retention: TemporalRetentionPolicy::default(),
        }
    }

    fn estimate_persist_size_locked(&self) -> usize {
        // Must match `encode_persistent_state_locked` encoding layout.
        let mut size = 24usize; // global header
        for object in &self.objects {
            size = size.saturating_add(28).saturating_add(object.path.len());
            for branch in &object.branches {
                size = size.saturating_add(16).saturating_add(branch.name.len());
            }
            for entry in &object.versions {
                size = size
                    .saturating_add(56)
                    .saturating_add(entry.payload.len());
            }
        }
        size
    }

    fn object_pinned_version_ids(object: &TemporalObjectHistory) -> Vec<u64> {
        let mut pinned = Vec::new();
        if let Some(id) = object.head_version_id {
            pinned.push(id);
        }
        for branch in &object.branches {
            if let Some(id) = branch.head_version_id {
                pinned.push(id);
            }
        }
        pinned
    }

    fn clear_one_inactive_branch_head(object: &mut TemporalObjectHistory) -> bool {
        let active = object.active_branch_id;
        let head = object.head_version_id;
        let active_head = object.active_branch_head();
        let mut best_idx: Option<usize> = None;
        let mut best_tick = u64::MAX;

        for (idx, branch) in object.branches.iter().enumerate() {
            if branch.branch_id == active {
                continue;
            }
            let head_id = match branch.head_version_id {
                Some(v) => v,
                None => continue,
            };
            if Some(head_id) == head || Some(head_id) == active_head {
                continue;
            }
            let tick = object
                .versions
                .iter()
                .find(|e| e.meta.version_id == head_id)
                .map(|e| e.meta.tick)
                .unwrap_or(0);
            if tick < best_tick {
                best_tick = tick;
                best_idx = Some(idx);
            }
        }

        if let Some(idx) = best_idx {
            if let Some(branch) = object.branches.get_mut(idx) {
                branch.head_version_id = None;
                return true;
            }
        }
        false
    }

    fn remove_version_rewire_locked(object: &mut TemporalObjectHistory, remove_idx: usize) -> bool {
        if remove_idx >= object.versions.len() {
            return false;
        }

        let removed_meta = object.versions[remove_idx].meta.clone();
        let removed_id = removed_meta.version_id;
        let replacement_parent = removed_meta.parent_version_id;
        let replacement_rollback = removed_meta.rollback_from_version_id.or(replacement_parent);

        for entry in object.versions.iter_mut() {
            if entry.meta.parent_version_id == Some(removed_id) {
                entry.meta.parent_version_id = replacement_parent;
            }
            if entry.meta.rollback_from_version_id == Some(removed_id) {
                entry.meta.rollback_from_version_id = replacement_rollback;
            }
        }

        if object.head_version_id == Some(removed_id) {
            object.head_version_id = replacement_parent;
        }
        for branch in object.branches.iter_mut() {
            if branch.head_version_id == Some(removed_id) {
                branch.head_version_id = replacement_parent;
            }
        }

        object.versions.remove(remove_idx);
        true
    }

    fn apply_retention_for_persistence_locked(&mut self) {
        let max_bytes = self
            .retention
            .max_persist_bytes
            .min(crate::persistence::MAX_SNAPSHOT_SIZE);
        let max_versions_per_object = self
            .retention
            .max_versions_per_object
            .min(MAX_VERSIONS_PER_OBJECT)
            .max(1);

        // First, cap history per object by count, preserving pinned heads when possible.
        for object in &mut self.objects {
            while object.versions.len() > max_versions_per_object {
                let pinned = Self::object_pinned_version_ids(object);
                let mut remove_idx = None;
                for (idx, entry) in object.versions.iter().enumerate() {
                    if !pinned.iter().any(|v| *v == entry.meta.version_id) {
                        remove_idx = Some(idx);
                        break;
                    }
                }
                match remove_idx {
                    Some(idx) => {
                        let _ = Self::remove_version_rewire_locked(object, idx);
                    }
                    None => {
                        if !Self::clear_one_inactive_branch_head(object) {
                            break;
                        }
                    }
                }
            }
        }

        // Then, enforce global persistence budget. Drop oldest unpinned versions first; if we
        // cannot find any, clear inactive branch heads to unpin more history.
        let mut guard = 0usize;
        while self.estimate_persist_size_locked() > max_bytes && guard < 100_000 {
            guard = guard.saturating_add(1);

            let mut best_obj: Option<usize> = None;
            let mut best_ver: Option<usize> = None;
            let mut best_tick = u64::MAX;

            for (oi, object) in self.objects.iter().enumerate() {
                let pinned = Self::object_pinned_version_ids(object);
                for (vi, entry) in object.versions.iter().enumerate() {
                    if pinned.iter().any(|v| *v == entry.meta.version_id) {
                        continue;
                    }
                    if entry.meta.tick < best_tick {
                        best_tick = entry.meta.tick;
                        best_obj = Some(oi);
                        best_ver = Some(vi);
                    }
                }
            }

            if let (Some(oi), Some(vi)) = (best_obj, best_ver) {
                if let Some(object) = self.objects.get_mut(oi) {
                    if vi < object.versions.len() {
                        let _ = Self::remove_version_rewire_locked(object, vi);
                        continue;
                    }
                }
            }

            // No removable versions. Try unpinning an inactive branch head somewhere.
            let mut unpinned = false;
            for object in &mut self.objects {
                if Self::clear_one_inactive_branch_head(object) {
                    unpinned = true;
                    break;
                }
            }
            if !unpinned {
                break;
            }
        }

        // Last-resort compaction: if we still exceed the budget, squash each object down to its
        // active head (or latest), clearing inactive branch heads.
        if self.estimate_persist_size_locked() > max_bytes {
            for object in &mut self.objects {
                let keep_id = object
                    .active_branch_head()
                    .or(object.head_version_id)
                    .or_else(|| object.versions.last().map(|v| v.meta.version_id));
                if let Some(keep_id) = keep_id {
                    object.versions.retain(|v| v.meta.version_id == keep_id);
                    object.head_version_id = Some(keep_id);
                    for branch in &mut object.branches {
                        if branch.branch_id == object.active_branch_id {
                            branch.head_version_id = Some(keep_id);
                        } else {
                            branch.head_version_id = None;
                        }
                    }
                } else {
                    object.versions.clear();
                    object.head_version_id = None;
                    for branch in &mut object.branches {
                        branch.head_version_id = None;
                    }
                }
            }
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

        let parent_version_id = object.active_branch_head();

        let (content_hash, merkle_root, leaf_count) = compute_version_hashes(payload);
        let mut data = Vec::new();
        data.resize(payload.len(), 0);
        temporal_asm::copy_bytes(&mut data, payload);

        let meta = TemporalVersionMeta {
            version_id,
            parent_version_id,
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
        let _ = object.update_branch_head_by_id(object.active_branch_id, Some(version_id));

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

        let latest_index = object
            .versions
            .len()
            .checked_sub(1)
            .ok_or(TemporalError::VersionNotFound)?;
        let latest_version_id = {
            let latest = object
                .versions
                .get_mut(latest_index)
                .ok_or(TemporalError::VersionNotFound)?;
            latest.meta.operation = TemporalOperation::Rollback;
            latest.meta.rollback_from_version_id = Some(rollback_from);
            latest.meta.version_id
        };
        let mut branch_id = object.active_branch_id;

        if previous_head.is_some() && previous_head != Some(rollback_from) {
            object.ensure_branch_slot()?;
            let new_branch = object.next_branch_id;
            object.next_branch_id = object.next_branch_id.saturating_add(1);
            let mut auto_name = String::from("rollback-");
            auto_name.push_str(&new_branch.to_string());
            object.branches.push(TemporalBranchHead {
                branch_id: new_branch,
                name: auto_name,
                head_version_id: Some(latest_version_id),
            });
            object.active_branch_id = new_branch;
            branch_id = new_branch;
        }

        {
            let latest = object
                .versions
                .get_mut(latest_index)
                .ok_or(TemporalError::VersionNotFound)?;
            latest.meta.branch_id = branch_id;
        }

        let _ = object.update_branch_head_by_id(branch_id, Some(latest_version_id));
        object.head_version_id = Some(latest_version_id);
        let restored_len = object
            .versions
            .get(latest_index)
            .map(|entry| entry.meta.data_len)
            .unwrap_or(0);

        Ok(TemporalRollbackResult {
            new_version_id: latest_version_id,
            branch_id,
            restored_len,
        })
    }

    fn find_version_index_locked(
        object: &TemporalObjectHistory,
        version_id: u64,
    ) -> Option<usize> {
        object
            .versions
            .iter()
            .position(|entry| entry.meta.version_id == version_id)
    }

    fn version_payload_locked(
        object: &TemporalObjectHistory,
        version_id: u64,
    ) -> Option<&[u8]> {
        let idx = Self::find_version_index_locked(object, version_id)?;
        Some(object.versions.get(idx)?.payload.as_slice())
    }

    fn create_branch_locked(
        &mut self,
        path: &str,
        branch_name: &str,
        from_version_id: Option<u64>,
    ) -> Result<u32, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get_mut(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        if !is_valid_branch_name(branch_name) {
            return Err(TemporalError::InvalidBranchName);
        }
        if object.find_branch_index_by_name(branch_name).is_some() {
            return Err(TemporalError::BranchAlreadyExists);
        }
        object.ensure_branch_slot()?;

        let base_head = match from_version_id {
            Some(id) => {
                if Self::find_version_index_locked(object, id).is_none() {
                    return Err(TemporalError::VersionNotFound);
                }
                Some(id)
            }
            None => object.active_branch_head(),
        };

        let branch_id = object.next_branch_id;
        object.next_branch_id = object.next_branch_id.saturating_add(1);
        object.branches.push(TemporalBranchHead {
            branch_id,
            name: branch_name.to_string(),
            head_version_id: base_head,
        });
        Ok(branch_id)
    }

    fn checkout_branch_locked(
        &mut self,
        path: &str,
        branch_name: &str,
    ) -> Result<(u32, Option<u64>, Option<Vec<u8>>), TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get_mut(index)
            .ok_or(TemporalError::ObjectNotFound)?;
        let branch_idx = object
            .find_branch_index_by_name(branch_name)
            .ok_or(TemporalError::BranchNotFound)?;
        let branch = object
            .branches
            .get(branch_idx)
            .ok_or(TemporalError::BranchNotFound)?;
        object.active_branch_id = branch.branch_id;
        object.head_version_id = branch.head_version_id;
        let payload = match branch.head_version_id {
            Some(version_id) => Self::version_payload_locked(object, version_id).map(|p| p.to_vec()),
            None => None,
        };
        Ok((branch.branch_id, branch.head_version_id, payload))
    }

    fn list_branches_locked(
        &self,
        path: &str,
    ) -> Result<Vec<TemporalBranchInfo>, TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let mut out = Vec::new();
        out.reserve(object.branches.len());
        for branch in &object.branches {
            out.push(TemporalBranchInfo {
                branch_id: branch.branch_id,
                name: branch.name.clone(),
                head_version_id: branch.head_version_id,
                active: branch.branch_id == object.active_branch_id,
            });
        }
        Ok(out)
    }

    fn branch_state_locked(
        &self,
        path: &str,
        branch_name: &str,
    ) -> Result<(u32, Option<u64>), TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get(index)
            .ok_or(TemporalError::ObjectNotFound)?;
        let branch_idx = object
            .find_branch_index_by_name(branch_name)
            .ok_or(TemporalError::BranchNotFound)?;
        let branch = object
            .branches
            .get(branch_idx)
            .ok_or(TemporalError::BranchNotFound)?;
        Ok((branch.branch_id, branch.head_version_id))
    }

    fn is_ancestor_locked(object: &TemporalObjectHistory, ancestor: u64, descendant: u64) -> bool {
        if ancestor == descendant {
            return true;
        }
        let mut stack = Vec::new();
        stack.push(descendant);
        let mut visited: Vec<u64> = Vec::new();

        while let Some(current) = stack.pop() {
            if current == ancestor {
                return true;
            }
            if visited.iter().any(|v| *v == current) {
                continue;
            }
            visited.push(current);

            let idx = match Self::find_version_index_locked(object, current) {
                Some(v) => v,
                None => continue,
            };
            let entry = match object.versions.get(idx) {
                Some(v) => v,
                None => continue,
            };
            if let Some(parent) = entry.meta.parent_version_id {
                stack.push(parent);
            }
            if let Some(extra) = entry.meta.rollback_from_version_id {
                stack.push(extra);
            }
        }
        false
    }

    fn common_ancestor_parent_chain_locked(
        object: &TemporalObjectHistory,
        a: u64,
        b: u64,
    ) -> Option<u64> {
        if a == b {
            return Some(a);
        }

        let mut a_chain: Vec<u64> = Vec::new();
        let mut current = Some(a);
        let mut guard = 0usize;
        while let Some(id) = current {
            a_chain.push(id);
            guard = guard.saturating_add(1);
            if guard > MAX_VERSIONS_PER_OBJECT.saturating_add(4) {
                break;
            }
            current = Self::find_version_index_locked(object, id)
                .and_then(|idx| object.versions.get(idx))
                .and_then(|entry| entry.meta.parent_version_id);
        }

        let mut current = Some(b);
        let mut guard = 0usize;
        while let Some(id) = current {
            if a_chain.iter().any(|v| *v == id) {
                return Some(id);
            }
            guard = guard.saturating_add(1);
            if guard > MAX_VERSIONS_PER_OBJECT.saturating_add(4) {
                break;
            }
            current = Self::find_version_index_locked(object, id)
                .and_then(|idx| object.versions.get(idx))
                .and_then(|entry| entry.meta.parent_version_id);
        }

        None
    }

    fn diff_span(base: &[u8], other: &[u8]) -> (usize, usize, usize) {
        let mut start = 0usize;
        while start < base.len() && start < other.len() {
            if base[start] != other[start] {
                break;
            }
            start = start.saturating_add(1);
        }

        let mut base_end = base.len();
        let mut other_end = other.len();
        while base_end > start && other_end > start {
            if base[base_end - 1] != other[other_end - 1] {
                break;
            }
            base_end = base_end.saturating_sub(1);
            other_end = other_end.saturating_sub(1);
        }

        (start, base_end, other_end)
    }

    fn try_three_way_span_merge(
        base: &[u8],
        ours: &[u8],
        theirs: &[u8],
    ) -> Option<Vec<u8>> {
        let (s1, be1, oe1) = Self::diff_span(base, ours);
        let (s2, be2, oe2) = Self::diff_span(base, theirs);

        // Non-overlapping edits (relative to base) can be merged deterministically.
        if be1 <= s2 {
            let mut out = Vec::new();
            out.extend_from_slice(&base[..s1]);
            out.extend_from_slice(&ours[s1..oe1]);
            out.extend_from_slice(&base[be1..s2]);
            out.extend_from_slice(&theirs[s2..oe2]);
            out.extend_from_slice(&base[be2..]);
            return Some(out);
        }
        if be2 <= s1 {
            let mut out = Vec::new();
            out.extend_from_slice(&base[..s2]);
            out.extend_from_slice(&theirs[s2..oe2]);
            out.extend_from_slice(&base[be2..s1]);
            out.extend_from_slice(&ours[s1..oe1]);
            out.extend_from_slice(&base[be1..]);
            return Some(out);
        }

        None
    }

    fn split_lines_inclusive<'a>(s: &'a str, max_lines: usize) -> Option<Vec<&'a str>> {
        let mut lines = Vec::new();
        if s.is_empty() {
            return Some(lines);
        }

        let bytes = s.as_bytes();
        let mut start = 0usize;
        for (idx, b) in bytes.iter().enumerate() {
            if *b == b'\n' {
                let end = idx.saturating_add(1);
                if end <= s.len() && start <= end {
                    lines.push(&s[start..end]);
                }
                start = end;
                if lines.len() > max_lines {
                    return None;
                }
            }
        }

        if start < s.len() {
            lines.push(&s[start..]);
            if lines.len() > max_lines {
                return None;
            }
        }

        Some(lines)
    }

    fn diff_lines_to_hunks(
        base_lines: &[&str],
        other_lines: &[&str],
    ) -> Option<Vec<TemporalLineHunk>> {
        let n = base_lines.len();
        let m = other_lines.len();

        // Keep CPU/memory bounded. This is a kernel merge helper, not a full diff engine.
        const MAX_LINES: usize = 256;
        if n > MAX_LINES || m > MAX_LINES {
            return None;
        }

        let cols = m.saturating_add(1);
        let rows = n.saturating_add(1);
        let mut dp: Vec<u16> = Vec::new();
        dp.resize(rows.saturating_mul(cols), 0);

        let mut i = n;
        while i > 0 {
            i = i.saturating_sub(1);
            let mut j = m;
            while j > 0 {
                j = j.saturating_sub(1);
                let idx = i.saturating_mul(cols).saturating_add(j);
                let down = dp[(i + 1).saturating_mul(cols).saturating_add(j)];
                let right = dp[i.saturating_mul(cols).saturating_add(j + 1)];
                dp[idx] = if base_lines[i] == other_lines[j] {
                    dp[(i + 1).saturating_mul(cols).saturating_add(j + 1)].saturating_add(1)
                } else if down >= right {
                    down
                } else {
                    right
                };
            }
        }

        let mut hunks: Vec<TemporalLineHunk> = Vec::new();
        let mut bi = 0usize;
        let mut oi = 0usize;
        while bi < n || oi < m {
            if bi < n && oi < m && base_lines[bi] == other_lines[oi] {
                bi = bi.saturating_add(1);
                oi = oi.saturating_add(1);
                continue;
            }

            let base_start = bi;
            let other_start = oi;

            while bi < n || oi < m {
                if bi < n && oi < m && base_lines[bi] == other_lines[oi] {
                    break;
                }

                if bi == n {
                    oi = oi.saturating_add(1);
                    continue;
                }
                if oi == m {
                    bi = bi.saturating_add(1);
                    continue;
                }

                let down = dp[(bi + 1).saturating_mul(cols).saturating_add(oi)];
                let right = dp[bi.saturating_mul(cols).saturating_add(oi + 1)];
                if down >= right {
                    bi = bi.saturating_add(1);
                } else {
                    oi = oi.saturating_add(1);
                }
            }

            let base_end = bi;
            let other_end = oi;
            if base_start != base_end || other_start != other_end {
                hunks.push(TemporalLineHunk {
                    base_start,
                    base_end,
                    other_start,
                    other_end,
                });
            }
        }

        Some(hunks)
    }

    fn hunk_overlaps_region(h: &TemporalLineHunk, region_start: usize, region_end: usize) -> bool {
        if region_start == region_end {
            // Point-region: used for pure insertions. Any edit that crosses this point overlaps.
            if h.base_start == h.base_end {
                return h.base_start == region_start;
            }
            return h.base_start <= region_start && h.base_end > region_start;
        }

        if h.base_start == h.base_end {
            // Insertions overlap iff they are inside [start, end).
            return h.base_start >= region_start && h.base_start < region_end;
        }

        h.base_start < region_end && h.base_end > region_start
    }

    fn append_line_range_bytes(out: &mut Vec<u8>, lines: &[&str], start: usize, end: usize) {
        let mut i = start;
        while i < end && i < lines.len() {
            out.extend_from_slice(lines[i].as_bytes());
            i = i.saturating_add(1);
        }
    }

    fn apply_line_hunks_range_bytes(
        base_lines: &[&str],
        other_lines: &[&str],
        hunks: &[TemporalLineHunk],
        region_start: usize,
        region_end: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut base_pos = region_start;

        for h in hunks {
            if h.base_start < region_start || h.base_start > region_end {
                continue;
            }
            if h.base_end > region_end {
                break;
            }

            Self::append_line_range_bytes(&mut out, base_lines, base_pos, h.base_start);
            Self::append_line_range_bytes(&mut out, other_lines, h.other_start, h.other_end);
            base_pos = h.base_end;
        }

        Self::append_line_range_bytes(&mut out, base_lines, base_pos, region_end);
        out
    }

    fn try_three_way_line_merge(base: &[u8], ours: &[u8], theirs: &[u8]) -> Option<Vec<u8>> {
        // Only attempt diff3-style merge for reasonably small UTF-8 payloads.
        let base_str = core::str::from_utf8(base).ok()?;
        let ours_str = core::str::from_utf8(ours).ok()?;
        let theirs_str = core::str::from_utf8(theirs).ok()?;

        const MAX_LINES: usize = 256;
        let base_lines = Self::split_lines_inclusive(base_str, MAX_LINES)?;
        let ours_lines = Self::split_lines_inclusive(ours_str, MAX_LINES)?;
        let theirs_lines = Self::split_lines_inclusive(theirs_str, MAX_LINES)?;

        let ours_hunks = Self::diff_lines_to_hunks(&base_lines, &ours_lines)?;
        let theirs_hunks = Self::diff_lines_to_hunks(&base_lines, &theirs_lines)?;

        let base_len = base_lines.len();
        let mut out: Vec<u8> = Vec::new();
        let mut base_pos = 0usize;
        let mut o_idx = 0usize;
        let mut t_idx = 0usize;

        loop {
            let next_o = ours_hunks.get(o_idx).map(|h| h.base_start).unwrap_or(usize::MAX);
            let next_t = theirs_hunks
                .get(t_idx)
                .map(|h| h.base_start)
                .unwrap_or(usize::MAX);
            let next_start = if next_o < next_t { next_o } else { next_t };

            if next_start == usize::MAX {
                Self::append_line_range_bytes(&mut out, &base_lines, base_pos, base_len);
                break;
            }

            if base_pos < next_start {
                Self::append_line_range_bytes(&mut out, &base_lines, base_pos, next_start);
            }

            let region_start = next_start;
            let mut region_end = region_start;
            if let Some(h) = ours_hunks.get(o_idx) {
                if h.base_start == region_start {
                    region_end = region_end.max(h.base_end);
                }
            }
            if let Some(h) = theirs_hunks.get(t_idx) {
                if h.base_start == region_start {
                    region_end = region_end.max(h.base_end);
                }
            }

            // Expand the region to include all overlapping edits from either side.
            let mut changed = true;
            while changed {
                changed = false;

                let mut k = o_idx;
                while let Some(h) = ours_hunks.get(k) {
                    if region_start < region_end && h.base_start >= region_end {
                        break;
                    }
                    if region_start == region_end && h.base_start > region_start {
                        break;
                    }
                    if Self::hunk_overlaps_region(h, region_start, region_end) {
                        let new_end = region_end.max(h.base_end);
                        if new_end != region_end {
                            region_end = new_end;
                            changed = true;
                        }
                    }
                    k = k.saturating_add(1);
                }

                let mut k = t_idx;
                while let Some(h) = theirs_hunks.get(k) {
                    if region_start < region_end && h.base_start >= region_end {
                        break;
                    }
                    if region_start == region_end && h.base_start > region_start {
                        break;
                    }
                    if Self::hunk_overlaps_region(h, region_start, region_end) {
                        let new_end = region_end.max(h.base_end);
                        if new_end != region_end {
                            region_end = new_end;
                            changed = true;
                        }
                    }
                    k = k.saturating_add(1);
                }
            }

            // Gather hunks for this region.
            let o_start = o_idx;
            while let Some(h) = ours_hunks.get(o_idx) {
                if region_start == region_end {
                    if h.base_start != region_start {
                        break;
                    }
                } else if h.base_start >= region_end {
                    break;
                }
                o_idx = o_idx.saturating_add(1);
            }
            let o_end = o_idx;

            let t_start = t_idx;
            while let Some(h) = theirs_hunks.get(t_idx) {
                if region_start == region_end {
                    if h.base_start != region_start {
                        break;
                    }
                } else if h.base_start >= region_end {
                    break;
                }
                t_idx = t_idx.saturating_add(1);
            }
            let t_end = t_idx;

            let mut base_bytes = Vec::new();
            Self::append_line_range_bytes(&mut base_bytes, &base_lines, region_start, region_end);
            let ours_bytes = Self::apply_line_hunks_range_bytes(
                &base_lines,
                &ours_lines,
                &ours_hunks[o_start..o_end],
                region_start,
                region_end,
            );
            let theirs_bytes = Self::apply_line_hunks_range_bytes(
                &base_lines,
                &theirs_lines,
                &theirs_hunks[t_start..t_end],
                region_start,
                region_end,
            );

            if ours_bytes == theirs_bytes {
                out.extend_from_slice(&ours_bytes);
            } else if ours_bytes == base_bytes {
                out.extend_from_slice(&theirs_bytes);
            } else if theirs_bytes == base_bytes {
                out.extend_from_slice(&ours_bytes);
            } else {
                return None;
            }

            base_pos = region_end;
        }

        Some(out)
    }

    fn merge_branch_locked(
        &mut self,
        path: &str,
        source_branch_name: &str,
        target_branch_name: Option<&str>,
        strategy: TemporalMergeStrategy,
    ) -> Result<(TemporalMergeResult, Option<Vec<u8>>), TemporalError> {
        let index = self
            .find_object_index(path)
            .ok_or(TemporalError::ObjectNotFound)?;
        let object = self
            .objects
            .get_mut(index)
            .ok_or(TemporalError::ObjectNotFound)?;

        let source_idx = object
            .find_branch_index_by_name(source_branch_name)
            .ok_or(TemporalError::BranchNotFound)?;
        let target_idx = if let Some(name) = target_branch_name {
            object
                .find_branch_index_by_name(name)
                .ok_or(TemporalError::BranchNotFound)?
        } else {
            object.active_branch_index().ok_or(TemporalError::BranchNotFound)?
        };
        if source_idx == target_idx {
            return Err(TemporalError::MergeConflict);
        }

        let source_branch = object
            .branches
            .get(source_idx)
            .ok_or(TemporalError::BranchNotFound)?
            .clone();
        let target_branch = object
            .branches
            .get(target_idx)
            .ok_or(TemporalError::BranchNotFound)?
            .clone();
        let source_head = source_branch.head_version_id;
        let target_head = target_branch.head_version_id;
        let target_is_active = object.active_branch_id == target_branch.branch_id;

        if source_head.is_none() {
            return Ok((
                TemporalMergeResult {
                    fast_forward: true,
                    new_version_id: None,
                    target_branch_id: target_branch.branch_id,
                    source_branch_id: source_branch.branch_id,
                    target_head_before: target_head,
                    target_head_after: target_head,
                },
                None,
            ));
        }
        let source_head_id = source_head.unwrap_or(0);

        if target_head.is_none()
            || Self::is_ancestor_locked(object, target_head.unwrap_or(0), source_head_id)
        {
            let _ = object.update_branch_head_by_id(target_branch.branch_id, Some(source_head_id));
            if object.active_branch_id == target_branch.branch_id {
                object.head_version_id = Some(source_head_id);
            }
            let payload = if target_is_active {
                Self::version_payload_locked(object, source_head_id).map(|p| p.to_vec())
            } else {
                None
            };
            return Ok((
                TemporalMergeResult {
                    fast_forward: true,
                    new_version_id: None,
                    target_branch_id: target_branch.branch_id,
                    source_branch_id: source_branch.branch_id,
                    target_head_before: target_head,
                    target_head_after: Some(source_head_id),
                },
                payload,
            ));
        }

        if Self::is_ancestor_locked(object, source_head_id, target_head.unwrap_or(0)) {
            return Ok((
                TemporalMergeResult {
                    fast_forward: true,
                    new_version_id: None,
                    target_branch_id: target_branch.branch_id,
                    source_branch_id: source_branch.branch_id,
                    target_head_before: target_head,
                    target_head_after: target_head,
                },
                None,
            ));
        }

        if matches!(strategy, TemporalMergeStrategy::FastForwardOnly) {
            return Err(TemporalError::MergeConflict);
        }

        if object.versions.len() >= MAX_VERSIONS_PER_OBJECT {
            return Err(TemporalError::VersionLimit);
        }

        let ours_head_id = target_head.ok_or(TemporalError::VersionNotFound)?;
        let ours = Self::version_payload_locked(object, ours_head_id)
            .ok_or(TemporalError::VersionNotFound)?;
        let theirs = Self::version_payload_locked(object, source_head_id)
            .ok_or(TemporalError::VersionNotFound)?;

        let base_id = Self::common_ancestor_parent_chain_locked(object, ours_head_id, source_head_id);
        let base = base_id.and_then(|id| Self::version_payload_locked(object, id));

        let mut merged: Option<Vec<u8>> = None;
        if ours == theirs {
            merged = Some(ours.to_vec());
        } else if let Some(base) = base {
            if ours == base {
                merged = Some(theirs.to_vec());
            } else if theirs == base {
                merged = Some(ours.to_vec());
            } else {
                merged = Self::try_three_way_span_merge(base, ours, theirs);
                if merged.is_none() {
                    merged = Self::try_three_way_line_merge(base, ours, theirs);
                }
            }
        }

        let payload = match merged {
            Some(v) => v,
            None => match strategy {
                TemporalMergeStrategy::Theirs => theirs.to_vec(),
                TemporalMergeStrategy::Ours | TemporalMergeStrategy::FastForwardOnly => ours.to_vec(),
            },
        };

        let version_id = self.next_version_id;
        self.next_version_id = self.next_version_id.saturating_add(1);
        let (content_hash, merkle_root, leaf_count) = compute_version_hashes(&payload);
        let meta = TemporalVersionMeta {
            version_id,
            parent_version_id: target_head,
            rollback_from_version_id: Some(source_head_id),
            branch_id: target_branch.branch_id,
            tick: crate::pit::get_ticks(),
            data_len: payload.len(),
            leaf_count,
            content_hash,
            merkle_root,
            operation: TemporalOperation::Merge,
        };
        object.versions.push(TemporalVersionEntry { meta, payload: payload.clone() });
        let _ = object.update_branch_head_by_id(target_branch.branch_id, Some(version_id));
        if object.active_branch_id == target_branch.branch_id {
            object.head_version_id = Some(version_id);
        }

        Ok((
            TemporalMergeResult {
                fast_forward: false,
                new_version_id: Some(version_id),
                target_branch_id: target_branch.branch_id,
                source_branch_id: source_branch.branch_id,
                    target_head_before: target_head,
                    target_head_after: Some(version_id),
                },
            if target_is_active { Some(payload) } else { None },
        ))
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
                .saturating_add(object.branches.len());
            for entry in &object.versions {
                stats.bytes = stats.bytes.saturating_add(entry.meta.data_len);
            }
        }

        stats
    }

    fn encode_persistent_state_locked(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.reserve(256);
        append_u32(&mut out, TEMPORAL_PERSIST_MAGIC);
        append_u16(&mut out, TEMPORAL_PERSIST_VERSION);
        append_u16(&mut out, 0);
        append_u64(&mut out, self.next_version_id);
        append_u32(&mut out, self.objects.len() as u32);
        append_u32(&mut out, 0);

        for object in &self.objects {
            let path = object.path.as_bytes();
            if path.len() > u16::MAX as usize
                || object.versions.len() > u16::MAX as usize
                || object.branches.len() > u16::MAX as usize
            {
                return None;
            }

            append_u16(&mut out, path.len() as u16);
            append_u16(&mut out, object.versions.len() as u16);
            append_u16(&mut out, object.branches.len() as u16);
            append_u16(&mut out, 0);
            append_u64(
                &mut out,
                object
                    .head_version_id
                    .unwrap_or(TEMPORAL_PERSIST_SENTINEL_U64),
            );
            append_u32(&mut out, object.active_branch_id);
            append_u32(&mut out, object.next_branch_id);
            append_u32(&mut out, 0);
            out.extend_from_slice(path);

            for branch in &object.branches {
                let name = branch.name.as_bytes();
                if name.len() > u16::MAX as usize {
                    return None;
                }
                append_u32(&mut out, branch.branch_id);
                append_u64(
                    &mut out,
                    branch
                        .head_version_id
                        .unwrap_or(TEMPORAL_PERSIST_SENTINEL_U64),
                );
                append_u16(&mut out, name.len() as u16);
                append_u16(&mut out, 0);
                out.extend_from_slice(name);
            }

            for entry in &object.versions {
                let meta = &entry.meta;
                if entry.payload.len() > u32::MAX as usize {
                    return None;
                }
                append_u64(&mut out, meta.version_id);
                append_u64(
                    &mut out,
                    meta.parent_version_id
                        .unwrap_or(TEMPORAL_PERSIST_SENTINEL_U64),
                );
                append_u64(
                    &mut out,
                    meta.rollback_from_version_id
                        .unwrap_or(TEMPORAL_PERSIST_SENTINEL_U64),
                );
                append_u32(&mut out, meta.branch_id);
                append_u64(&mut out, meta.tick);
                append_u32(&mut out, meta.data_len as u32);
                append_u32(&mut out, meta.leaf_count);
                append_u32(&mut out, meta.content_hash);
                append_u32(&mut out, meta.merkle_root);
                out.push(meta.operation as u8);
                out.extend_from_slice(&[0u8; 3]);
                out.extend_from_slice(&entry.payload);
            }
        }

        Some(out)
    }

    fn decode_persistent_state(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let magic = read_u32(data, 0)?;
        let version = read_u16(data, 4)?;
        if magic != TEMPORAL_PERSIST_MAGIC {
            return None;
        }
        if version == TEMPORAL_PERSIST_VERSION_V1 {
            return Self::decode_persistent_state_v1(data);
        }
        if version != TEMPORAL_PERSIST_VERSION {
            return None;
        }

        let mut cursor = 8usize;
        let mut next_version_id = read_u64(data, cursor)?;
        cursor = cursor.saturating_add(8);
        let object_count = read_u32(data, cursor)? as usize;
        cursor = cursor.saturating_add(4);
        cursor = cursor.saturating_add(4); // reserved

        if object_count > MAX_TEMPORAL_OBJECTS {
            return None;
        }

        let mut service = TemporalService::new();
        service.objects.clear();
        service.next_version_id = next_version_id.max(1);

        let mut observed_max_version = 0u64;

        for _ in 0..object_count {
            let path_len = read_u16(data, cursor)? as usize;
            cursor = cursor.saturating_add(2);
            let version_count = read_u16(data, cursor)? as usize;
            cursor = cursor.saturating_add(2);
            let branch_count = read_u16(data, cursor)? as usize;
            cursor = cursor.saturating_add(2);
            cursor = cursor.saturating_add(2); // reserved
            let head_raw = read_u64(data, cursor)?;
            cursor = cursor.saturating_add(8);
            let active_branch_id = read_u32(data, cursor)?;
            cursor = cursor.saturating_add(4);
            let next_branch_id = read_u32(data, cursor)?;
            cursor = cursor.saturating_add(4);
            cursor = cursor.saturating_add(4); // reserved

            if version_count > MAX_VERSIONS_PER_OBJECT {
                return None;
            }
            if branch_count > MAX_BRANCHES_PER_OBJECT {
                return None;
            }
            if cursor.saturating_add(path_len) > data.len() {
                return None;
            }
            let path = core::str::from_utf8(&data[cursor..cursor + path_len])
                .ok()?
                .to_string();
            cursor = cursor.saturating_add(path_len);

            let mut object = TemporalObjectHistory::new(path);
            object.active_branch_id = active_branch_id;
            object.next_branch_id = next_branch_id.max(active_branch_id.saturating_add(1));
            object.head_version_id = if head_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                None
            } else {
                Some(head_raw)
            };
            object.branches.clear();
            object.branches.reserve(branch_count.max(1));
            object.versions.clear();
            object.versions.reserve(version_count);

            for _ in 0..branch_count {
                let branch_id = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let head_raw = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let name_len = read_u16(data, cursor)? as usize;
                cursor = cursor.saturating_add(2);
                cursor = cursor.saturating_add(2); // reserved
                if cursor.saturating_add(name_len) > data.len() {
                    return None;
                }
                let name = core::str::from_utf8(&data[cursor..cursor + name_len]).ok()?.to_string();
                cursor = cursor.saturating_add(name_len);
                object.branches.push(TemporalBranchHead {
                    branch_id,
                    name,
                    head_version_id: if head_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                        None
                    } else {
                        Some(head_raw)
                    },
                });
            }

            for _ in 0..version_count {
                let version_id = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let parent_raw = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let rollback_raw = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let branch_id = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let tick = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let data_len = read_u32(data, cursor)? as usize;
                cursor = cursor.saturating_add(4);
                let leaf_count = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let content_hash = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let merkle_root = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                if cursor >= data.len() {
                    return None;
                }
                let op = op_from_u8(data[cursor])?;
                cursor = cursor.saturating_add(4); // op + reserved

                if data_len > MAX_TEMPORAL_VERSION_BYTES {
                    return None;
                }
                if cursor.saturating_add(data_len) > data.len() {
                    return None;
                }
                let mut payload = Vec::new();
                payload.resize(data_len, 0);
                if data_len > 0 {
                    payload.copy_from_slice(&data[cursor..cursor + data_len]);
                }
                cursor = cursor.saturating_add(data_len);

                observed_max_version = observed_max_version.max(version_id);

                let meta = TemporalVersionMeta {
                    version_id,
                    parent_version_id: if parent_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                        None
                    } else {
                        Some(parent_raw)
                    },
                    rollback_from_version_id: if rollback_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                        None
                    } else {
                        Some(rollback_raw)
                    },
                    branch_id,
                    tick,
                    data_len,
                    leaf_count,
                    content_hash,
                    merkle_root,
                    operation: op,
                };
                object.versions.push(TemporalVersionEntry { meta, payload });
            }

            if object.branches.is_empty() {
                object.branches.push(TemporalBranchHead {
                    branch_id: 0,
                    name: String::from(DEFAULT_BRANCH_NAME),
                    head_version_id: object.head_version_id,
                });
                object.active_branch_id = 0;
            }

            if object.head_version_id.is_none() && !object.versions.is_empty() {
                object.head_version_id = Some(object.versions.last()?.meta.version_id);
            }
            if object.find_branch_index_by_id(object.active_branch_id).is_none() {
                object.active_branch_id = object.branches.get(0)?.branch_id;
            }
            if object.next_branch_id <= object.active_branch_id {
                object.next_branch_id = object.active_branch_id.saturating_add(1);
            }
            for branch in &object.branches {
                if object.next_branch_id <= branch.branch_id {
                    object.next_branch_id = branch.branch_id.saturating_add(1);
                }
            }
            service.objects.push(object);
        }

        if cursor > data.len() {
            return None;
        }
        if next_version_id <= observed_max_version {
            next_version_id = observed_max_version.saturating_add(1);
        }
        service.next_version_id = next_version_id.max(1);
        Some(service)
    }

    fn decode_persistent_state_v1(data: &[u8]) -> Option<Self> {
        let mut cursor = 8usize;
        let mut next_version_id = read_u64(data, cursor)?;
        cursor = cursor.saturating_add(8);
        let object_count = read_u32(data, cursor)? as usize;
        cursor = cursor.saturating_add(4);
        cursor = cursor.saturating_add(4); // reserved

        if object_count > MAX_TEMPORAL_OBJECTS {
            return None;
        }

        let mut service = TemporalService::new();
        service.objects.clear();
        service.next_version_id = next_version_id.max(1);
        let mut observed_max_version = 0u64;

        for _ in 0..object_count {
            let path_len = read_u16(data, cursor)? as usize;
            cursor = cursor.saturating_add(2);
            let version_count = read_u16(data, cursor)? as usize;
            cursor = cursor.saturating_add(2);
            let head_raw = read_u64(data, cursor)?;
            cursor = cursor.saturating_add(8);
            let active_branch_id = read_u32(data, cursor)?;
            cursor = cursor.saturating_add(4);
            let next_branch_id = read_u32(data, cursor)?;
            cursor = cursor.saturating_add(4);
            cursor = cursor.saturating_add(4); // reserved

            if version_count > MAX_VERSIONS_PER_OBJECT {
                return None;
            }
            if cursor.saturating_add(path_len) > data.len() {
                return None;
            }
            let path = core::str::from_utf8(&data[cursor..cursor + path_len])
                .ok()?
                .to_string();
            cursor = cursor.saturating_add(path_len);

            let mut object = TemporalObjectHistory::new(path);
            object.active_branch_id = active_branch_id;
            object.next_branch_id = next_branch_id.max(active_branch_id.saturating_add(1));
            object.head_version_id = if head_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                None
            } else {
                Some(head_raw)
            };
            object.versions.clear();
            object.versions.reserve(version_count);

            let mut branch_ids: Vec<u32> = Vec::new();
            branch_ids.push(0);
            if active_branch_id != 0 {
                branch_ids.push(active_branch_id);
            }

            for _ in 0..version_count {
                let version_id = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let parent_raw = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let rollback_raw = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let branch_id = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let tick = read_u64(data, cursor)?;
                cursor = cursor.saturating_add(8);
                let data_len = read_u32(data, cursor)? as usize;
                cursor = cursor.saturating_add(4);
                let leaf_count = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let content_hash = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                let merkle_root = read_u32(data, cursor)?;
                cursor = cursor.saturating_add(4);
                if cursor >= data.len() {
                    return None;
                }
                let op = op_from_u8(data[cursor])?;
                cursor = cursor.saturating_add(4);
                if data_len > MAX_TEMPORAL_VERSION_BYTES || cursor.saturating_add(data_len) > data.len() {
                    return None;
                }
                let mut payload = Vec::new();
                payload.resize(data_len, 0);
                if data_len > 0 {
                    payload.copy_from_slice(&data[cursor..cursor + data_len]);
                }
                cursor = cursor.saturating_add(data_len);

                if !branch_ids.iter().any(|id| *id == branch_id) {
                    branch_ids.push(branch_id);
                }
                observed_max_version = observed_max_version.max(version_id);
                let meta = TemporalVersionMeta {
                    version_id,
                    parent_version_id: if parent_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                        None
                    } else {
                        Some(parent_raw)
                    },
                    rollback_from_version_id: if rollback_raw == TEMPORAL_PERSIST_SENTINEL_U64 {
                        None
                    } else {
                        Some(rollback_raw)
                    },
                    branch_id,
                    tick,
                    data_len,
                    leaf_count,
                    content_hash,
                    merkle_root,
                    operation: op,
                };
                object.versions.push(TemporalVersionEntry { meta, payload });
            }

            object.branches.clear();
            for branch_id in branch_ids {
                let head = object
                    .versions
                    .iter()
                    .rev()
                    .find(|entry| entry.meta.branch_id == branch_id)
                    .map(|entry| entry.meta.version_id);
                let name = if branch_id == 0 {
                    String::from(DEFAULT_BRANCH_NAME)
                } else {
                    let mut n = String::from("legacy-");
                    n.push_str(&branch_id.to_string());
                    n
                };
                object.branches.push(TemporalBranchHead {
                    branch_id,
                    name,
                    head_version_id: head,
                });
            }
            if object.find_branch_index_by_id(object.active_branch_id).is_none() {
                object.active_branch_id = 0;
            }
            if object.head_version_id.is_none() {
                object.head_version_id = object.active_branch_head();
            }
            if object.next_branch_id <= object.active_branch_id {
                object.next_branch_id = object.active_branch_id.saturating_add(1);
            }
            for branch in &object.branches {
                if object.next_branch_id <= branch.branch_id {
                    object.next_branch_id = branch.branch_id.saturating_add(1);
                }
            }
            service.objects.push(object);
        }

        if cursor > data.len() {
            return None;
        }
        if next_version_id <= observed_max_version {
            next_version_id = observed_max_version.saturating_add(1);
        }
        service.next_version_id = next_version_id.max(1);
        Some(service)
    }
}

static TEMPORAL: Mutex<TemporalService> = Mutex::new(TemporalService::new());
pub type TemporalObjectAdapterFn =
    fn(path: &str, payload: &[u8], mode: TemporalRestoreMode) -> Result<(), &'static str>;

#[derive(Clone, Copy)]
struct TemporalObjectAdapter {
    prefix: &'static str,
    apply: TemporalObjectAdapterFn,
}

static TEMPORAL_OBJECT_ADAPTERS: Mutex<[Option<TemporalObjectAdapter>; MAX_TEMPORAL_ADAPTERS]> =
    Mutex::new([None; MAX_TEMPORAL_ADAPTERS]);
static TEMPORAL_OBJECT_ADAPTERS_INIT: Once<()> = Once::new();
static TEMPORAL_REPLAY_DEPTH: AtomicUsize = AtomicUsize::new(0);

struct TemporalReplayGuard;

impl TemporalReplayGuard {
    fn new() -> Self {
        TEMPORAL_REPLAY_DEPTH.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for TemporalReplayGuard {
    fn drop(&mut self) {
        TEMPORAL_REPLAY_DEPTH.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn is_replay_active() -> bool {
    TEMPORAL_REPLAY_DEPTH.load(Ordering::Relaxed) > 0
}

fn parse_object_id_from_key(path: &str, prefix: &str) -> Option<u32> {
    if !path.starts_with(prefix) {
        return None;
    }
    path[prefix.len()..].parse::<u32>().ok()
}

fn parse_object_id_u64_from_key(path: &str, prefix: &str) -> Option<u64> {
    if !path.starts_with(prefix) {
        return None;
    }
    path[prefix.len()..].parse::<u64>().ok()
}

fn parse_capability_key(path: &str) -> Option<(u32, u8, u64)> {
    let prefix = "/capability/";
    if !path.starts_with(prefix) {
        return None;
    }
    let mut parts = path[prefix.len()..].split('/');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let cap_type = parts.next()?.parse::<u8>().ok()?;
    let object_id = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((pid, cap_type, object_id))
}

fn parse_registry_key(path: &str) -> Option<(u32, u32)> {
    let prefix = "/registry/service/";
    if !path.starts_with(prefix) {
        return None;
    }
    let mut parts = path[prefix.len()..].split('/');
    let service_type = parts.next()?.parse::<u32>().ok()?;
    let namespace = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((service_type, namespace))
}

fn temporal_apply_vfs_file_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    match crate::vfs::temporal_try_apply_backend_payload(path, payload) {
        Ok(true) => Ok(()),
        Ok(false) => crate::vfs::write_path_untracked(path, payload).map(|_| ()),
        Err(e) => Err(e),
    }
}

fn temporal_apply_tcp_listener_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 20 {
        return Err("temporal tcp listener payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_SOCKET_OBJECT_TCP_LISTENER {
        return Err("temporal tcp listener payload type mismatch");
    }
    let listener_id = read_u32(payload, 4).ok_or("temporal tcp listener payload missing id")?;
    let key_id = parse_object_id_from_key(path, "/socket/tcp/listener/")
        .ok_or("temporal tcp listener key parse failed")?;
    if listener_id != key_id {
        return Err("temporal tcp listener payload/key mismatch");
    }
    let port = read_u16(payload, 8).ok_or("temporal tcp listener payload missing port")?;
    let event = payload[2];
    crate::net_reactor::temporal_apply_tcp_listener_event(listener_id, port, event)
}

fn temporal_apply_tcp_conn_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 32 {
        return Err("temporal tcp connection payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_SOCKET_OBJECT_TCP_CONN {
        return Err("temporal tcp connection payload type mismatch");
    }
    let conn_id = read_u32(payload, 4).ok_or("temporal tcp connection payload missing id")?;
    let key_id = parse_object_id_from_key(path, "/socket/tcp/conn/")
        .ok_or("temporal tcp connection key parse failed")?;
    if conn_id != key_id {
        return Err("temporal tcp connection payload/key mismatch");
    }

    let event = payload[2];
    let state = payload[3];
    let local_ip = [payload[8], payload[9], payload[10], payload[11]];
    let local_port = read_u16(payload, 12).ok_or("temporal tcp connection missing local port")?;
    let remote_ip = [payload[14], payload[15], payload[16], payload[17]];
    let remote_port = read_u16(payload, 18).ok_or("temporal tcp connection missing remote port")?;

    let (aux, preview) = if event == TEMPORAL_SOCKET_EVENT_SEND || event == TEMPORAL_SOCKET_EVENT_RECV {
        if payload.len() < 36 {
            return Err("temporal tcp data payload malformed");
        }
        let preview_len = read_u16(payload, 24).ok_or("temporal tcp data preview missing")? as usize;
        let preview_start = 36usize;
        if preview_start > payload.len() {
            return Err("temporal tcp data preview offset invalid");
        }
        let preview_end = core::cmp::min(preview_start.saturating_add(preview_len), payload.len());
        let payload_len = read_u32(payload, 20).unwrap_or(0);
        (payload_len, &payload[preview_start..preview_end])
    } else {
        (read_u32(payload, 20).unwrap_or(0), &payload[0..0])
    };

    crate::net_reactor::temporal_apply_tcp_connection_event(
        conn_id,
        state,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        event,
        aux,
        preview,
    )
}

fn temporal_apply_ipc_channel_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 28 {
        return Err("temporal ipc channel payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_CHANNEL_OBJECT {
        return Err("temporal ipc channel payload type mismatch");
    }
    let channel_id = read_u32(payload, 4).ok_or("temporal ipc channel payload missing id")?;
    let key_id = parse_object_id_from_key(path, "/ipc/channel/")
        .ok_or("temporal ipc channel key parse failed")?;
    if channel_id != key_id {
        return Err("temporal ipc channel payload/key mismatch");
    }
    crate::ipc::temporal_apply_channel_payload(payload)
}

fn temporal_apply_process_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 16 {
        return Err("temporal process payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_PROCESS_OBJECT {
        return Err("temporal process payload type mismatch");
    }
    let event = payload[2];
    let pid = read_u32(payload, 4).ok_or("temporal process payload missing pid")?;
    let key_pid =
        parse_object_id_from_key(path, "/process/").ok_or("temporal process key parse failed")?;
    if pid != key_pid {
        return Err("temporal process payload/key mismatch");
    }
    let parent_pid = read_u32(payload, 8).ok_or("temporal process payload missing parent")?;
    let name_len = read_u16(payload, 12).ok_or("temporal process payload missing name length")? as usize;
    let name_start = 16usize;
    let name_end = name_start.saturating_add(name_len);
    if name_end > payload.len() {
        return Err("temporal process payload truncated");
    }
    crate::process::temporal_apply_process_event(pid, parent_pid, event, &payload[name_start..name_end])
}

fn temporal_apply_capability_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 32 {
        return Err("temporal capability payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_CAPABILITY_OBJECT {
        return Err("temporal capability payload type mismatch");
    }
    let (key_pid, key_cap_type, key_object_id) =
        parse_capability_key(path).ok_or("temporal capability key parse failed")?;
    let event = payload[2];
    let pid = read_u32(payload, 4).ok_or("temporal capability payload missing pid")?;
    let cap_type = payload[8];
    let object_id = read_u64(payload, 12).ok_or("temporal capability payload missing object id")?;
    if pid != key_pid || cap_type != key_cap_type || object_id != key_object_id {
        return Err("temporal capability payload/key mismatch");
    }
    let rights = read_u32(payload, 20).ok_or("temporal capability payload missing rights")?;
    let origin_pid = read_u32(payload, 24).ok_or("temporal capability payload missing origin")?;
    let cap_id_hint = read_u32(payload, 28).ok_or("temporal capability payload missing cap id")?;
    crate::capability::temporal_apply_capability_event(
        pid,
        cap_type,
        object_id,
        rights,
        origin_pid,
        event,
        cap_id_hint,
    )
}

fn temporal_apply_registry_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 32 {
        return Err("temporal registry payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_REGISTRY_OBJECT {
        return Err("temporal registry payload type mismatch");
    }
    let (key_service_type, key_namespace) =
        parse_registry_key(path).ok_or("temporal registry key parse failed")?;
    let event = payload[2];
    let service_type = read_u32(payload, 4).ok_or("temporal registry payload missing service type")?;
    let namespace = read_u32(payload, 8).ok_or("temporal registry payload missing namespace")?;
    if service_type != key_service_type || namespace != key_namespace {
        return Err("temporal registry payload/key mismatch");
    }
    let channel_id = read_u32(payload, 12).ok_or("temporal registry payload missing channel")?;
    let provider_pid = read_u32(payload, 16).ok_or("temporal registry payload missing provider")?;
    let version = read_u32(payload, 20).ok_or("temporal registry payload missing version")?;
    let max_connections =
        read_u32(payload, 24).ok_or("temporal registry payload missing max connections")?;
    let active_connections =
        read_u32(payload, 28).ok_or("temporal registry payload missing active connections")?;
    crate::registry::temporal_apply_service_event(
        service_type,
        namespace,
        channel_id,
        provider_pid,
        version,
        max_connections,
        active_connections,
        event,
    )
}

fn temporal_apply_console_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if payload.len() < 32 {
        return Err("temporal console payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_CONSOLE_OBJECT {
        return Err("temporal console payload type mismatch");
    }
    let object_id = read_u64(payload, 4).ok_or("temporal console payload missing object id")?;
    let key_id = parse_object_id_u64_from_key(path, "/console/object/")
        .ok_or("temporal console key parse failed")?;
    if object_id != key_id {
        return Err("temporal console payload/key mismatch");
    }
    let event = payload[2];
    let owner_pid = read_u32(payload, 12).ok_or("temporal console payload missing owner")?;
    let write_count = read_u64(payload, 16).ok_or("temporal console payload missing write count")?;
    let read_count = read_u64(payload, 24).ok_or("temporal console payload missing read count")?;
    crate::console_service::temporal_apply_console_event(
        object_id,
        owner_pid,
        write_count,
        read_count,
        event,
    )
}

fn temporal_apply_security_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/security/intent/policy" {
        return Err("temporal security key mismatch");
    }
    if payload.len() < 36 {
        return Err("temporal security payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_SECURITY_OBJECT {
        return Err("temporal security payload type mismatch");
    }
    if payload[2] != TEMPORAL_SECURITY_EVENT_INTENT_POLICY {
        return Err("temporal security event unsupported");
    }
    let policy = crate::intent_graph::IntentPolicy {
        window_seconds: read_u64(payload, 4).ok_or("temporal security payload missing window")?,
        alert_score: read_u32(payload, 12).ok_or("temporal security payload missing alert score")?,
        restrict_score: read_u32(payload, 16)
            .ok_or("temporal security payload missing restrict score")?,
        isolate_restrictions: read_u16(payload, 20)
            .ok_or("temporal security payload missing isolate restrictions")?,
        terminate_restrictions: read_u16(payload, 22)
            .ok_or("temporal security payload missing terminate restrictions")?,
        restrict_base_seconds: read_u16(payload, 24)
            .ok_or("temporal security payload missing restrict base seconds")?,
        restrict_max_seconds: read_u16(payload, 26)
            .ok_or("temporal security payload missing restrict max seconds")?,
        isolate_extension_seconds: read_u16(payload, 28)
            .ok_or("temporal security payload missing isolate extension")?,
        severity_step_score: read_u16(payload, 30)
            .ok_or("temporal security payload missing severity step")?,
        alert_cooldown_ms: read_u16(payload, 32)
            .ok_or("temporal security payload missing alert cooldown")?,
        restrict_cooldown_ms: read_u16(payload, 34)
            .ok_or("temporal security payload missing restrict cooldown")?,
    };
    crate::security::temporal_apply_intent_policy(policy)
}

fn temporal_apply_capnet_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/capnet/state" {
        return Err("temporal capnet key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal capnet payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_CAPNET_OBJECT {
        return Err("temporal capnet payload type mismatch");
    }
    if payload[2] != TEMPORAL_CAPNET_EVENT_STATE {
        return Err("temporal capnet event unsupported");
    }
    crate::capnet::temporal_apply_state_payload(payload)
}

fn temporal_apply_wasm_service_pointer_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/wasm/service-pointers" {
        return Err("temporal wasm key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal wasm payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != TEMPORAL_WASM_SERVICE_POINTER_OBJECT
    {
        return Err("temporal wasm payload type mismatch");
    }
    if payload[2] != TEMPORAL_WASM_SERVICE_POINTER_EVENT_STATE {
        return Err("temporal wasm event unsupported");
    }
    crate::wasm::temporal_apply_service_pointer_registry_payload(payload)
}

fn temporal_apply_network_config_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/network/config" {
        return Err("temporal network key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal network payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_NETWORK_CONFIG_OBJECT {
        return Err("temporal network payload type mismatch");
    }
    if payload[2] != TEMPORAL_NETWORK_CONFIG_EVENT_STATE {
        return Err("temporal network event unsupported");
    }
    crate::net_reactor::temporal_apply_network_config_payload(payload)
}

fn temporal_apply_wasm_syscall_module_table_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/wasm/syscall-modules" {
        return Err("temporal wasm syscall key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal wasm syscall payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT
    {
        return Err("temporal wasm syscall payload type mismatch");
    }
    if payload[2] != TEMPORAL_WASM_SYSCALL_MODULE_TABLE_EVENT_STATE {
        return Err("temporal wasm syscall event unsupported");
    }
    crate::wasm::temporal_apply_syscall_module_table_payload(payload)
}

fn temporal_apply_scheduler_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/scheduler/state" {
        return Err("temporal scheduler key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal scheduler payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_SCHEDULER_OBJECT {
        return Err("temporal scheduler payload type mismatch");
    }
    if payload[2] != TEMPORAL_SCHEDULER_EVENT_STATE {
        return Err("temporal scheduler event unsupported");
    }
    crate::quantum_scheduler::temporal_apply_scheduler_payload(payload)
}

fn temporal_apply_replay_manager_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/replay/state" {
        return Err("temporal replay key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal replay payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_REPLAY_MANAGER_OBJECT {
        return Err("temporal replay payload type mismatch");
    }
    if payload[2] != TEMPORAL_REPLAY_MANAGER_EVENT_STATE {
        return Err("temporal replay event unsupported");
    }
    crate::replay::temporal_apply_replay_manager_payload(payload)
}

fn temporal_apply_network_legacy_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/network/legacy/state" {
        return Err("temporal legacy network key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal legacy network payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_NETWORK_LEGACY_OBJECT {
        return Err("temporal legacy network payload type mismatch");
    }
    if payload[2] != TEMPORAL_NETWORK_LEGACY_EVENT_STATE {
        return Err("temporal legacy network event unsupported");
    }
    crate::net::temporal_apply_network_service_payload(payload)
}

fn temporal_apply_wifi_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/wifi/state" {
        return Err("temporal wifi key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal wifi payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_WIFI_OBJECT {
        return Err("temporal wifi payload type mismatch");
    }
    if payload[2] != TEMPORAL_WIFI_EVENT_STATE {
        return Err("temporal wifi event unsupported");
    }
    crate::wifi::temporal_apply_wifi_driver_payload(payload)
}

fn temporal_apply_enclave_payload(
    path: &str,
    payload: &[u8],
    _mode: TemporalRestoreMode,
) -> Result<(), &'static str> {
    if path != "/enclave/state" {
        return Err("temporal enclave key mismatch");
    }
    if payload.len() < 4 {
        return Err("temporal enclave payload too short");
    }
    if payload[0] != TEMPORAL_OBJECT_ENCODING_V1 || payload[1] != TEMPORAL_ENCLAVE_OBJECT {
        return Err("temporal enclave payload type mismatch");
    }
    if payload[2] != TEMPORAL_ENCLAVE_EVENT_STATE {
        return Err("temporal enclave event unsupported");
    }
    crate::enclave::temporal_apply_enclave_state_payload(payload)
}

fn register_object_adapter_internal(
    prefix: &'static str,
    apply: TemporalObjectAdapterFn,
) -> Result<(), TemporalError> {
    if prefix.is_empty() || !prefix.starts_with('/') {
        return Err(TemporalError::InvalidPath);
    }
    let mut adapters = TEMPORAL_OBJECT_ADAPTERS.lock();

    let mut i = 0usize;
    while i < adapters.len() {
        if let Some(existing) = adapters[i] {
            if existing.prefix == prefix {
                adapters[i] = Some(TemporalObjectAdapter { prefix, apply });
                return Ok(());
            }
        }
        i += 1;
    }

    let mut i = 0usize;
    while i < adapters.len() {
        if adapters[i].is_none() {
            adapters[i] = Some(TemporalObjectAdapter { prefix, apply });
            return Ok(());
        }
        i += 1;
    }

    Err(TemporalError::AdapterRegistryFull)
}

fn ensure_object_adapters_initialized() {
    TEMPORAL_OBJECT_ADAPTERS_INIT.call_once(|| {
        let _ = register_object_adapter_internal("/", temporal_apply_vfs_file_payload);
        let _ = register_object_adapter_internal(
            "/socket/tcp/listener/",
            temporal_apply_tcp_listener_payload,
        );
        let _ = register_object_adapter_internal("/socket/tcp/conn/", temporal_apply_tcp_conn_payload);
        let _ = register_object_adapter_internal("/ipc/channel/", temporal_apply_ipc_channel_payload);
        let _ = register_object_adapter_internal("/process/", temporal_apply_process_payload);
        let _ = register_object_adapter_internal("/capability/", temporal_apply_capability_payload);
        let _ = register_object_adapter_internal("/registry/service/", temporal_apply_registry_payload);
        let _ = register_object_adapter_internal("/console/object/", temporal_apply_console_payload);
        let _ = register_object_adapter_internal("/security/intent/policy", temporal_apply_security_payload);
        let _ = register_object_adapter_internal("/capnet/state", temporal_apply_capnet_payload);
        let _ = register_object_adapter_internal(
            "/wasm/service-pointers",
            temporal_apply_wasm_service_pointer_payload,
        );
        let _ = register_object_adapter_internal("/network/config", temporal_apply_network_config_payload);
        let _ = register_object_adapter_internal(
            "/wasm/syscall-modules",
            temporal_apply_wasm_syscall_module_table_payload,
        );
        let _ = register_object_adapter_internal("/scheduler/state", temporal_apply_scheduler_payload);
        let _ = register_object_adapter_internal("/replay/state", temporal_apply_replay_manager_payload);
        let _ = register_object_adapter_internal(
            "/network/legacy/state",
            temporal_apply_network_legacy_payload,
        );
        let _ = register_object_adapter_internal("/wifi/state", temporal_apply_wifi_payload);
        let _ = register_object_adapter_internal("/enclave/state", temporal_apply_enclave_payload);
    });
}

pub fn register_object_adapter(
    prefix: &'static str,
    apply: TemporalObjectAdapterFn,
) -> Result<(), TemporalError> {
    ensure_object_adapters_initialized();
    register_object_adapter_internal(prefix, apply)
}

fn find_object_adapter(path: &str) -> Option<TemporalObjectAdapter> {
    ensure_object_adapters_initialized();
    let adapters = TEMPORAL_OBJECT_ADAPTERS.lock();
    let mut best: Option<TemporalObjectAdapter> = None;
    let mut best_len = 0usize;

    let mut i = 0usize;
    while i < adapters.len() {
        if let Some(adapter) = adapters[i] {
            let prefix_len = adapter.prefix.len();
            if prefix_len >= best_len && path.starts_with(adapter.prefix) {
                best = Some(adapter);
                best_len = prefix_len;
            }
        }
        i += 1;
    }
    best
}

fn apply_temporal_payload_to_object(
    path: &str,
    payload: &[u8],
    mode: TemporalRestoreMode,
) -> Result<(), TemporalError> {
    let adapter = find_object_adapter(path).ok_or(TemporalError::AdapterApplyFailed)?;
    let _replay_guard = TemporalReplayGuard::new();
    (adapter.apply)(path, payload, mode).map_err(|_| TemporalError::AdapterApplyFailed)
}

fn temporal_current_pid() -> crate::ipc::ProcessId {
    crate::process::current_pid().unwrap_or(crate::ipc::ProcessId(0))
}

fn temporal_object_hint(path: &str) -> u64 {
    crate::security::hash_data(path.as_bytes())
}

fn temporal_audit_context(action: TemporalAuditAction, object_hint: u64, success: bool) -> u64 {
    let mut context = ((action as u64) << 56) | (object_hint & 0x00FF_FFFF_FFFF_FFFF);
    if success {
        context |= 1u64 << 55;
    }
    context
}

fn emit_temporal_audit(
    action: TemporalAuditAction,
    path: &str,
    cap_id: u32,
    success: bool,
    write_intent: bool,
) {
    let pid = temporal_current_pid();
    let object_hint = temporal_object_hint(path);
    let security = crate::security::security();
    if write_intent {
        security.intent_fs_write(pid, object_hint);
    } else {
        security.intent_fs_read(pid, object_hint);
    }
    security.log_event(
        crate::security::AuditEntry::new(crate::security::SecurityEvent::TemporalOperation, pid, cap_id)
            .with_context(temporal_audit_context(action, object_hint, success)),
    );
}

fn audit_action_for_operation(operation: TemporalOperation) -> TemporalAuditAction {
    match operation {
        TemporalOperation::Snapshot => TemporalAuditAction::Snapshot,
        TemporalOperation::Write => TemporalAuditAction::Write,
        TemporalOperation::Rollback => TemporalAuditAction::Rollback,
        TemporalOperation::Merge => TemporalAuditAction::Merge,
    }
}

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

fn append_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    if offset.saturating_add(8) > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

fn op_from_u8(value: u8) -> Option<TemporalOperation> {
    match value {
        1 => Some(TemporalOperation::Snapshot),
        2 => Some(TemporalOperation::Write),
        3 => Some(TemporalOperation::Rollback),
        4 => Some(TemporalOperation::Merge),
        _ => None,
    }
}

fn is_valid_branch_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_BRANCH_NAME_BYTES {
        return false;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
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

fn temporal_store_cap() -> crate::persistence::StoreCapability {
    crate::persistence::StoreCapability::new(
        0x544D_5054, // "TMPT"
        crate::persistence::StoreRights::all(),
    )
}

fn persist_state_snapshot() {
    let encoded = {
        let mut service = TEMPORAL.lock();
        service.apply_retention_for_persistence_locked();
        match service.encode_persistent_state_locked() {
            Some(data) => data,
            None => return,
        }
    };

    let cap = temporal_store_cap();
    let mut persistence = crate::persistence::persistence().lock();
    let last_offset = persistence.log_stats().0;
    let _ = persistence.write_temporal_snapshot(&cap, &encoded, last_offset);
}

pub fn init() {
    ensure_object_adapters_initialized();
    let _ = recover_from_persistence();
}

pub fn recover_from_persistence() -> Result<(), &'static str> {
    const RECOVER_PATH: &str = "/temporal/persistence";
    let cap = temporal_store_cap();
    let snapshot = {
        let persistence = crate::persistence::persistence().lock();
        match persistence.read_temporal_snapshot(&cap) {
            Ok((data, _offset)) => data.to_vec(),
            Err(_) => {
                emit_temporal_audit(TemporalAuditAction::Recover, RECOVER_PATH, 0, false, true);
                return Err("temporal persistence read denied");
            }
        }
    };
    if snapshot.is_empty() {
        emit_temporal_audit(TemporalAuditAction::Recover, RECOVER_PATH, 0, true, true);
        return Ok(());
    }

    let recovered = match TemporalService::decode_persistent_state(&snapshot) {
        Some(service) => service,
        None => {
            emit_temporal_audit(TemporalAuditAction::Recover, RECOVER_PATH, 0, false, true);
            return Err("temporal snapshot decode failed");
        }
    };
    let recovered_objects = recovered.objects.len() as u32;
    let mut service = TEMPORAL.lock();
    if service.objects.is_empty() {
        *service = recovered;
    }
    emit_temporal_audit(
        TemporalAuditAction::Recover,
        RECOVER_PATH,
        recovered_objects,
        true,
        true,
    );
    Ok(())
}

pub fn tcp_socket_object_key(socket_id: u32) -> String {
    alloc::format!("/socket/tcp/conn/{}", socket_id)
}

pub fn tcp_listener_object_key(listener_id: u32) -> String {
    alloc::format!("/socket/tcp/listener/{}", listener_id)
}

pub fn ipc_channel_object_key(channel_id: u32) -> String {
    alloc::format!("/ipc/channel/{}", channel_id)
}

pub fn process_object_key(pid: u32) -> String {
    alloc::format!("/process/{}", pid)
}

pub fn capability_object_key(pid: u32, cap_type_raw: u8, object_id: u64) -> String {
    alloc::format!("/capability/{}/{}/{}", pid, cap_type_raw, object_id)
}

pub fn registry_service_object_key(service_type_raw: u32, namespace_raw: u32) -> String {
    alloc::format!("/registry/service/{}/{}", service_type_raw, namespace_raw)
}

pub fn console_object_key(object_id: u64) -> String {
    alloc::format!("/console/object/{}", object_id)
}

pub fn security_intent_policy_object_key() -> &'static str {
    "/security/intent/policy"
}

pub fn capnet_state_object_key() -> &'static str {
    "/capnet/state"
}

pub fn wasm_service_pointer_object_key() -> &'static str {
    "/wasm/service-pointers"
}

pub fn network_config_object_key() -> &'static str {
    "/network/config"
}

pub fn wasm_syscall_module_table_object_key() -> &'static str {
    "/wasm/syscall-modules"
}

pub fn scheduler_state_object_key() -> &'static str {
    "/scheduler/state"
}

pub fn replay_state_object_key() -> &'static str {
    "/replay/state"
}

pub fn network_legacy_state_object_key() -> &'static str {
    "/network/legacy/state"
}

pub fn wifi_state_object_key() -> &'static str {
    "/wifi/state"
}

pub fn enclave_state_object_key() -> &'static str {
    "/enclave/state"
}

pub fn record_object_event(
    object_key: &str,
    operation: TemporalOperation,
    payload: &[u8],
) -> Result<u64, TemporalError> {
    if is_replay_active() {
        return Ok(0);
    }
    let action = audit_action_for_operation(operation);
    let normalized = match normalize_path(object_key) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(action, object_key, 0, false, true);
            return Err(e);
        }
    };
    let version_id = {
        let mut service = TEMPORAL.lock();
        match service.record_version_locked(&normalized, payload, operation) {
            Ok(version_id) => version_id,
            Err(e) => {
                emit_temporal_audit(action, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };
    emit_temporal_audit(action, &normalized, version_id as u32, true, true);
    persist_state_snapshot();
    Ok(version_id)
}

pub fn record_object_write(object_key: &str, payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_event(object_key, TemporalOperation::Write, payload)
}

pub fn record_object_snapshot(object_key: &str, payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_event(object_key, TemporalOperation::Snapshot, payload)
}

pub fn record_tcp_socket_listener_event(
    listener_id: u32,
    port: u16,
    event: u8,
) -> Result<u64, TemporalError> {
    let key = tcp_listener_object_key(listener_id);
    let mut payload = Vec::new();
    payload.reserve(20);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_SOCKET_OBJECT_TCP_LISTENER);
    payload.push(event);
    payload.push(0);
    append_u32(&mut payload, listener_id);
    append_u16(&mut payload, port);
    append_u16(&mut payload, 0);
    append_u64(&mut payload, crate::pit::get_ticks());
    record_object_write(&key, &payload)
}

pub fn record_tcp_socket_state_event(
    socket_id: u32,
    state: u8,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    event: u8,
    aux: u32,
) -> Result<u64, TemporalError> {
    let key = tcp_socket_object_key(socket_id);
    let mut payload = Vec::new();
    payload.reserve(32);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_SOCKET_OBJECT_TCP_CONN);
    payload.push(event);
    payload.push(state);
    append_u32(&mut payload, socket_id);
    payload.extend_from_slice(&local_ip);
    append_u16(&mut payload, local_port);
    payload.extend_from_slice(&remote_ip);
    append_u16(&mut payload, remote_port);
    append_u32(&mut payload, aux);
    append_u64(&mut payload, crate::pit::get_ticks());
    record_object_write(&key, &payload)
}

pub fn record_tcp_socket_data_event(
    socket_id: u32,
    state: u8,
    local_ip: [u8; 4],
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    event: u8,
    data: &[u8],
) -> Result<u64, TemporalError> {
    let key = tcp_socket_object_key(socket_id);
    let preview_len = core::cmp::min(data.len(), TEMPORAL_SOCKET_PAYLOAD_PREVIEW_BYTES);
    let mut payload = Vec::new();
    payload.reserve(40usize.saturating_add(preview_len));
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_SOCKET_OBJECT_TCP_CONN);
    payload.push(event);
    payload.push(state);
    append_u32(&mut payload, socket_id);
    payload.extend_from_slice(&local_ip);
    append_u16(&mut payload, local_port);
    payload.extend_from_slice(&remote_ip);
    append_u16(&mut payload, remote_port);
    append_u32(&mut payload, data.len() as u32);
    append_u16(&mut payload, preview_len as u16);
    append_u16(&mut payload, 0);
    append_u64(&mut payload, crate::pit::get_ticks());
    payload.extend_from_slice(&data[..preview_len]);
    record_object_write(&key, &payload)
}

pub fn record_ipc_channel_event(
    channel_id: u32,
    event: u8,
    process_id: u32,
    payload_len: usize,
    caps_len: usize,
    queue_depth: usize,
) -> Result<u64, TemporalError> {
    let key = ipc_channel_object_key(channel_id);
    let mut payload = Vec::new();
    payload.reserve(32);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_CHANNEL_OBJECT);
    payload.push(event);
    payload.push(0);
    append_u32(&mut payload, channel_id);
    append_u32(&mut payload, process_id);
    append_u32(&mut payload, payload_len as u32);
    append_u16(&mut payload, caps_len as u16);
    append_u16(&mut payload, queue_depth as u16);
    append_u64(&mut payload, crate::pit::get_ticks());
    record_object_write(&key, &payload)
}

pub fn record_process_event(
    pid: u32,
    parent_pid: Option<u32>,
    event: u8,
    name: &str,
) -> Result<u64, TemporalError> {
    let key = process_object_key(pid);
    let name_bytes = name.as_bytes();
    let capped_len = core::cmp::min(name_bytes.len(), u16::MAX as usize);
    let mut payload = Vec::new();
    payload.reserve(16usize.saturating_add(capped_len));
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_PROCESS_OBJECT);
    payload.push(event);
    payload.push(0);
    append_u32(&mut payload, pid);
    append_u32(&mut payload, parent_pid.unwrap_or(u32::MAX));
    append_u16(&mut payload, capped_len as u16);
    payload.push(0);
    payload.push(0);
    payload.extend_from_slice(&name_bytes[..capped_len]);
    record_object_write(&key, &payload)
}

pub fn record_capability_event(
    pid: u32,
    cap_type_raw: u8,
    object_id: u64,
    rights: u32,
    origin_pid: u32,
    event: u8,
    cap_id_hint: u32,
) -> Result<u64, TemporalError> {
    let key = capability_object_key(pid, cap_type_raw, object_id);
    let mut payload = Vec::new();
    payload.reserve(32);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_CAPABILITY_OBJECT);
    payload.push(event);
    payload.push(0);
    append_u32(&mut payload, pid);
    payload.push(cap_type_raw);
    payload.push(0);
    payload.push(0);
    payload.push(0);
    append_u64(&mut payload, object_id);
    append_u32(&mut payload, rights);
    append_u32(&mut payload, origin_pid);
    append_u32(&mut payload, cap_id_hint);
    record_object_write(&key, &payload)
}

#[allow(clippy::too_many_arguments)]
pub fn record_registry_service_event(
    service_type_raw: u32,
    namespace_raw: u32,
    channel_id: u32,
    provider_pid: u32,
    version: u32,
    max_connections: u32,
    active_connections: u32,
    event: u8,
) -> Result<u64, TemporalError> {
    let key = registry_service_object_key(service_type_raw, namespace_raw);
    let mut payload = Vec::new();
    payload.reserve(32);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_REGISTRY_OBJECT);
    payload.push(event);
    payload.push(0);
    append_u32(&mut payload, service_type_raw);
    append_u32(&mut payload, namespace_raw);
    append_u32(&mut payload, channel_id);
    append_u32(&mut payload, provider_pid);
    append_u32(&mut payload, version);
    append_u32(&mut payload, max_connections);
    append_u32(&mut payload, active_connections);
    record_object_write(&key, &payload)
}

pub fn record_console_event(
    object_id: u64,
    owner_pid: u32,
    write_count: u64,
    read_count: u64,
    event: u8,
) -> Result<u64, TemporalError> {
    let key = console_object_key(object_id);
    let mut payload = Vec::new();
    payload.reserve(32);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_CONSOLE_OBJECT);
    payload.push(event);
    payload.push(0);
    append_u64(&mut payload, object_id);
    append_u32(&mut payload, owner_pid);
    append_u64(&mut payload, write_count);
    append_u64(&mut payload, read_count);
    record_object_write(&key, &payload)
}

pub fn record_intent_policy_event(policy: &crate::intent_graph::IntentPolicy) -> Result<u64, TemporalError> {
    let mut payload = Vec::new();
    payload.reserve(36);
    payload.push(TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(TEMPORAL_SECURITY_OBJECT);
    payload.push(TEMPORAL_SECURITY_EVENT_INTENT_POLICY);
    payload.push(0);
    append_u64(&mut payload, policy.window_seconds);
    append_u32(&mut payload, policy.alert_score);
    append_u32(&mut payload, policy.restrict_score);
    append_u16(&mut payload, policy.isolate_restrictions);
    append_u16(&mut payload, policy.terminate_restrictions);
    append_u16(&mut payload, policy.restrict_base_seconds);
    append_u16(&mut payload, policy.restrict_max_seconds);
    append_u16(&mut payload, policy.isolate_extension_seconds);
    append_u16(&mut payload, policy.severity_step_score);
    append_u16(&mut payload, policy.alert_cooldown_ms);
    append_u16(&mut payload, policy.restrict_cooldown_ms);
    record_object_write(security_intent_policy_object_key(), &payload)
}

pub fn record_capnet_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(capnet_state_object_key(), payload)
}

pub fn record_wasm_service_pointer_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(wasm_service_pointer_object_key(), payload)
}

pub fn record_network_config_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(network_config_object_key(), payload)
}

pub fn record_wasm_syscall_module_table_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(wasm_syscall_module_table_object_key(), payload)
}

pub fn record_scheduler_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(scheduler_state_object_key(), payload)
}

pub fn record_replay_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(replay_state_object_key(), payload)
}

pub fn record_network_legacy_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(network_legacy_state_object_key(), payload)
}

pub fn record_wifi_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(wifi_state_object_key(), payload)
}

pub fn record_enclave_state_event(payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(enclave_state_object_key(), payload)
}

pub fn record_write(path: &str, payload: &[u8]) -> Result<u64, TemporalError> {
    record_object_write(path, payload)
}

pub fn snapshot_path(path: &str) -> Result<u64, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::Snapshot, path, 0, false, true);
            return Err(e);
        }
    };

    let mut read_buf = Vec::new();
    read_buf.resize(MAX_TEMPORAL_CAPTURE_BYTES, 0);

    let read = match crate::vfs::read_path(&normalized, &mut read_buf) {
        Ok(read) => read,
        Err(_) => {
            emit_temporal_audit(TemporalAuditAction::Snapshot, &normalized, 0, false, true);
            return Err(TemporalError::VfsReadFailed);
        }
    };
    read_buf.truncate(read);

    let version_id = {
        let mut service = TEMPORAL.lock();
        match service.record_version_locked(&normalized, &read_buf, TemporalOperation::Snapshot) {
            Ok(version_id) => version_id,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::Snapshot, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };
    emit_temporal_audit(
        TemporalAuditAction::Snapshot,
        &normalized,
        version_id as u32,
        true,
        true,
    );
    persist_state_snapshot();
    Ok(version_id)
}

pub fn read_version(path: &str, version_id: u64) -> Result<Vec<u8>, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ReadVersion, path, 0, false, false);
            return Err(e);
        }
    };
    let result = TEMPORAL
        .lock()
        .read_version_payload_locked(&normalized, version_id);
    match result {
        Ok(payload) => {
            emit_temporal_audit(
                TemporalAuditAction::ReadVersion,
                &normalized,
                version_id as u32,
                true,
                false,
            );
            Ok(payload)
        }
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ReadVersion, &normalized, 0, false, false);
            Err(e)
        }
    }
}

pub fn list_versions(path: &str) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ListVersions, path, 0, false, false);
            return Err(e);
        }
    };
    let result = TEMPORAL.lock().list_version_metas_locked(&normalized);
    match result {
        Ok(history) => {
            emit_temporal_audit(
                TemporalAuditAction::ListVersions,
                &normalized,
                history.len() as u32,
                true,
                false,
            );
            Ok(history)
        }
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ListVersions, &normalized, 0, false, false);
            Err(e)
        }
    }
}

pub fn latest_version(path: &str) -> Result<TemporalVersionMeta, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::LatestVersion, path, 0, false, false);
            return Err(e);
        }
    };
    let result = TEMPORAL.lock().latest_meta_locked(&normalized);
    match result {
        Ok(meta) => {
            emit_temporal_audit(
                TemporalAuditAction::LatestVersion,
                &normalized,
                meta.version_id as u32,
                true,
                false,
            );
            Ok(meta)
        }
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::LatestVersion, &normalized, 0, false, false);
            Err(e)
        }
    }
}

pub fn history_window(
    path: &str,
    start_from_newest: usize,
    max_entries: usize,
) -> Result<Vec<TemporalVersionMeta>, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::HistoryWindow, path, 0, false, false);
            return Err(e);
        }
    };
    let result = TEMPORAL
        .lock()
        .history_window_locked(&normalized, start_from_newest, max_entries);
    match result {
        Ok(history) => {
            emit_temporal_audit(
                TemporalAuditAction::HistoryWindow,
                &normalized,
                history.len() as u32,
                true,
                false,
            );
            Ok(history)
        }
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::HistoryWindow, &normalized, 0, false, false);
            Err(e)
        }
    }
}

pub fn rollback_path(path: &str, rollback_to_version_id: u64) -> Result<TemporalRollbackResult, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::Rollback, path, 0, false, true);
            return Err(e);
        }
    };

    let (payload, previous_head) = {
        let service = TEMPORAL.lock();
        let payload = match service.read_version_payload_locked(&normalized, rollback_to_version_id) {
            Ok(payload) => payload,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::Rollback, &normalized, 0, false, true);
                return Err(e);
            }
        };
        let previous_head = match service.get_head_version_id(&normalized) {
            Ok(head) => head,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::Rollback, &normalized, 0, false, true);
                return Err(e);
            }
        };
        (payload, previous_head)
    };

    if apply_temporal_payload_to_object(&normalized, &payload, TemporalRestoreMode::Rollback).is_err()
    {
        emit_temporal_audit(TemporalAuditAction::Rollback, &normalized, 0, false, true);
        return Err(TemporalError::AdapterApplyFailed);
    }

    let result = {
        let mut service = TEMPORAL.lock();
        match service.mark_latest_rollback_locked(&normalized, rollback_to_version_id, previous_head) {
            Ok(result) => result,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::Rollback, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };
    emit_temporal_audit(
        TemporalAuditAction::Rollback,
        &normalized,
        result.new_version_id as u32,
        true,
        true,
    );
    persist_state_snapshot();
    Ok(result)
}

pub fn create_branch(
    path: &str,
    branch_name: &str,
    from_version_id: Option<u64>,
) -> Result<u32, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::BranchCreate, path, 0, false, true);
            return Err(e);
        }
    };
    let branch_id = {
        let mut service = TEMPORAL.lock();
        match service.create_branch_locked(&normalized, branch_name, from_version_id) {
            Ok(branch_id) => branch_id,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::BranchCreate, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };
    emit_temporal_audit(
        TemporalAuditAction::BranchCreate,
        &normalized,
        branch_id,
        true,
        true,
    );
    persist_state_snapshot();
    Ok(branch_id)
}

pub fn list_branches(path: &str) -> Result<Vec<TemporalBranchInfo>, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ListBranches, path, 0, false, false);
            return Err(e);
        }
    };
    let result = TEMPORAL.lock().list_branches_locked(&normalized);
    match result {
        Ok(branches) => {
            emit_temporal_audit(
                TemporalAuditAction::ListBranches,
                &normalized,
                branches.len() as u32,
                true,
                false,
            );
            Ok(branches)
        }
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::ListBranches, &normalized, 0, false, false);
            Err(e)
        }
    }
}

pub fn checkout_branch(path: &str, branch_name: &str) -> Result<(u32, Option<u64>), TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::BranchCheckout, path, 0, false, true);
            return Err(e);
        }
    };
    let (branch_id, head_version_id, payload) = {
        let mut service = TEMPORAL.lock();
        match service.checkout_branch_locked(&normalized, branch_name) {
            Ok(v) => v,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::BranchCheckout, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };

    if let Some(data) = payload {
        if apply_temporal_payload_to_object(&normalized, &data, TemporalRestoreMode::Checkout).is_err()
        {
            emit_temporal_audit(TemporalAuditAction::BranchCheckout, &normalized, 0, false, true);
            return Err(TemporalError::AdapterApplyFailed);
        }
    }

    emit_temporal_audit(
        TemporalAuditAction::BranchCheckout,
        &normalized,
        branch_id,
        true,
        true,
    );
    persist_state_snapshot();
    Ok((branch_id, head_version_id))
}

pub fn merge_branch(
    path: &str,
    source_branch_name: &str,
    target_branch_name: Option<&str>,
    strategy: TemporalMergeStrategy,
) -> Result<TemporalMergeResult, TemporalError> {
    let normalized = match normalize_path(path) {
        Ok(path) => path,
        Err(e) => {
            emit_temporal_audit(TemporalAuditAction::Merge, path, 0, false, true);
            return Err(e);
        }
    };
    let (result, payload) = {
        let mut service = TEMPORAL.lock();
        match service.merge_branch_locked(&normalized, source_branch_name, target_branch_name, strategy) {
            Ok(v) => v,
            Err(e) => {
                emit_temporal_audit(TemporalAuditAction::Merge, &normalized, 0, false, true);
                return Err(e);
            }
        }
    };

    if let Some(data) = payload {
        if apply_temporal_payload_to_object(&normalized, &data, TemporalRestoreMode::Merge).is_err()
        {
            emit_temporal_audit(TemporalAuditAction::Merge, &normalized, 0, false, true);
            return Err(TemporalError::AdapterApplyFailed);
        }
    }

    let merge_cap_id = result.new_version_id.unwrap_or(result.target_branch_id as u64) as u32;
    emit_temporal_audit(
        TemporalAuditAction::Merge,
        &normalized,
        merge_cap_id,
        true,
        true,
    );
    persist_state_snapshot();
    Ok(result)
}

pub fn stats() -> TemporalStats {
    TEMPORAL.lock().stats_locked()
}

pub fn retention_policy() -> (usize, usize) {
    let svc = TEMPORAL.lock();
    (svc.retention.max_versions_per_object, svc.retention.max_persist_bytes)
}

pub fn set_retention_policy(max_versions_per_object: usize, max_persist_bytes: usize) -> (usize, usize) {
    let mut svc = TEMPORAL.lock();
    svc.retention.max_versions_per_object =
        max_versions_per_object.clamp(1, MAX_VERSIONS_PER_OBJECT);
    svc.retention.max_persist_bytes = max_persist_bytes
        .clamp(256, crate::persistence::MAX_SNAPSHOT_SIZE);
    (svc.retention.max_versions_per_object, svc.retention.max_persist_bytes)
}

pub fn reset_retention_policy() -> (usize, usize) {
    let mut svc = TEMPORAL.lock();
    svc.retention = TemporalRetentionPolicy::default();
    (svc.retention.max_versions_per_object, svc.retention.max_persist_bytes)
}

pub fn gc_for_persistence_budget() -> (usize, usize) {
    let mut svc = TEMPORAL.lock();
    let before = svc.estimate_persist_size_locked();
    svc.apply_retention_for_persistence_locked();
    let after = svc.estimate_persist_size_locked();
    (before, after)
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

pub fn object_scope_self_check() -> Result<(), &'static str> {
    let seed = (crate::pit::get_ticks() & 0xFFFF) as u32;
    let socket_id = 0x5100_0000u32 | seed;
    let listener_id = 0x2900_0000u32 | seed;
    let channel_id = 0x3300_0000u32 | seed;
    const LOCAL_IP: [u8; 4] = [10, 1, 0, 2];
    const REMOTE_IP: [u8; 4] = [10, 1, 0, 9];

    record_tcp_socket_listener_event(
        listener_id,
        8080,
        TEMPORAL_SOCKET_EVENT_LISTEN,
    )
    .map_err(|_| "temporal object self-check: listener record failed")?;
    record_tcp_socket_state_event(
        socket_id,
        4, // established
        LOCAL_IP,
        50001,
        REMOTE_IP,
        443,
        TEMPORAL_SOCKET_EVENT_CONNECT,
        0,
    )
    .map_err(|_| "temporal object self-check: socket state record failed")?;
    record_tcp_socket_data_event(
        socket_id,
        4,
        LOCAL_IP,
        50001,
        REMOTE_IP,
        443,
        TEMPORAL_SOCKET_EVENT_SEND,
        b"GET / HTTP/1.1",
    )
    .map_err(|_| "temporal object self-check: socket data record failed")?;
    record_ipc_channel_event(
        channel_id,
        TEMPORAL_CHANNEL_EVENT_SEND,
        91,
        64,
        1,
        1,
    )
    .map_err(|_| "temporal object self-check: channel record failed")?;

    let socket_key = tcp_socket_object_key(socket_id);
    let socket_history = list_versions(&socket_key)
        .map_err(|_| "temporal object self-check: socket history missing")?;
    if socket_history.len() < 2 {
        return Err("temporal object self-check: socket history too short");
    }
    let socket_latest = latest_version(&socket_key)
        .map_err(|_| "temporal object self-check: latest socket version missing")?;
    let socket_payload = read_version(&socket_key, socket_latest.version_id)
        .map_err(|_| "temporal object self-check: latest socket payload unreadable")?;
    if socket_payload.len() < 32 {
        return Err("temporal object self-check: socket payload too short");
    }

    let listener_key = tcp_listener_object_key(listener_id);
    let listener_latest = latest_version(&listener_key)
        .map_err(|_| "temporal object self-check: listener history missing")?;
    if listener_latest.operation != TemporalOperation::Write {
        return Err("temporal object self-check: listener op mismatch");
    }

    let channel_key = ipc_channel_object_key(channel_id);
    let channel_latest = latest_version(&channel_key)
        .map_err(|_| "temporal object self-check: channel history missing")?;
    let channel_payload = read_version(&channel_key, channel_latest.version_id)
        .map_err(|_| "temporal object self-check: channel payload unreadable")?;
    if channel_payload.len() < 24 {
        return Err("temporal object self-check: channel payload too short");
    }

    let proc_id = 0x4400_0000u32 | seed;
    record_process_event(proc_id, Some(1), TEMPORAL_PROCESS_EVENT_SPAWN, "temporal-selfcheck")
        .map_err(|_| "temporal object self-check: process record failed")?;
    let proc_key = process_object_key(proc_id);
    let proc_latest = latest_version(&proc_key)
        .map_err(|_| "temporal object self-check: process history missing")?;
    let proc_payload = read_version(&proc_key, proc_latest.version_id)
        .map_err(|_| "temporal object self-check: process payload unreadable")?;
    if proc_payload.len() < 16 {
        return Err("temporal object self-check: process payload too short");
    }

    let cap_object = 0x55AA_1100u64 | (seed as u64);
    record_capability_event(
        1,
        crate::capability::CapabilityType::Console as u8,
        cap_object,
        crate::capability::Rights::CONSOLE_WRITE,
        0,
        TEMPORAL_CAPABILITY_EVENT_GRANT,
        7,
    )
    .map_err(|_| "temporal object self-check: capability record failed")?;
    let cap_key =
        capability_object_key(1, crate::capability::CapabilityType::Console as u8, cap_object);
    let cap_latest = latest_version(&cap_key)
        .map_err(|_| "temporal object self-check: capability history missing")?;
    let cap_payload = read_version(&cap_key, cap_latest.version_id)
        .map_err(|_| "temporal object self-check: capability payload unreadable")?;
    if cap_payload.len() < 32 {
        return Err("temporal object self-check: capability payload too short");
    }

    record_registry_service_event(
        crate::registry::ServiceType::Temporal.as_u32(),
        crate::registry::ServiceNamespace::Production.as_u32(),
        10,
        1,
        1,
        8,
        0,
        TEMPORAL_REGISTRY_EVENT_REGISTER,
    )
    .map_err(|_| "temporal object self-check: registry record failed")?;
    let reg_key = registry_service_object_key(
        crate::registry::ServiceType::Temporal.as_u32(),
        crate::registry::ServiceNamespace::Production.as_u32(),
    );
    let reg_latest = latest_version(&reg_key)
        .map_err(|_| "temporal object self-check: registry history missing")?;
    let reg_payload = read_version(&reg_key, reg_latest.version_id)
        .map_err(|_| "temporal object self-check: registry payload unreadable")?;
    if reg_payload.len() < 32 {
        return Err("temporal object self-check: registry payload too short");
    }

    let console_object = 0x6600_0000u64 | (seed as u64);
    record_console_event(
        console_object,
        0,
        12,
        0,
        TEMPORAL_CONSOLE_EVENT_CREATE,
    )
    .map_err(|_| "temporal object self-check: console record failed")?;
    let console_key = console_object_key(console_object);
    let console_latest = latest_version(&console_key)
        .map_err(|_| "temporal object self-check: console history missing")?;
    let console_payload = read_version(&console_key, console_latest.version_id)
        .map_err(|_| "temporal object self-check: console payload unreadable")?;
    if console_payload.len() < 32 {
        return Err("temporal object self-check: console payload too short");
    }

    record_intent_policy_event(&crate::intent_graph::IntentPolicy::baseline())
        .map_err(|_| "temporal object self-check: security policy record failed")?;
    let sec_latest = latest_version(security_intent_policy_object_key())
        .map_err(|_| "temporal object self-check: security policy history missing")?;
    let sec_payload = read_version(security_intent_policy_object_key(), sec_latest.version_id)
        .map_err(|_| "temporal object self-check: security payload unreadable")?;
    if sec_payload.len() < 36 {
        return Err("temporal object self-check: security payload too short");
    }

    let capnet_payload = [
        TEMPORAL_OBJECT_ENCODING_V1,
        TEMPORAL_CAPNET_OBJECT,
        TEMPORAL_CAPNET_EVENT_STATE,
        0,
    ];
    record_capnet_state_event(&capnet_payload)
        .map_err(|_| "temporal object self-check: capnet record failed")?;
    let capnet_latest = latest_version(capnet_state_object_key())
        .map_err(|_| "temporal object self-check: capnet history missing")?;
    let capnet_read = read_version(capnet_state_object_key(), capnet_latest.version_id)
        .map_err(|_| "temporal object self-check: capnet payload unreadable")?;
    if capnet_read.len() < 4 {
        return Err("temporal object self-check: capnet payload too short");
    }

    let wasm_payload = [
        TEMPORAL_OBJECT_ENCODING_V1,
        TEMPORAL_WASM_SERVICE_POINTER_OBJECT,
        TEMPORAL_WASM_SERVICE_POINTER_EVENT_STATE,
        0,
    ];
    record_wasm_service_pointer_event(&wasm_payload)
        .map_err(|_| "temporal object self-check: wasm service pointer record failed")?;
    let wasm_latest = latest_version(wasm_service_pointer_object_key())
        .map_err(|_| "temporal object self-check: wasm service pointer history missing")?;
    let wasm_read = read_version(wasm_service_pointer_object_key(), wasm_latest.version_id)
        .map_err(|_| "temporal object self-check: wasm service pointer payload unreadable")?;
    if wasm_read.len() < 4 {
        return Err("temporal object self-check: wasm service pointer payload too short");
    }

    let network_payload = [
        TEMPORAL_OBJECT_ENCODING_V1,
        TEMPORAL_NETWORK_CONFIG_OBJECT,
        TEMPORAL_NETWORK_CONFIG_EVENT_STATE,
        0,
    ];
    record_network_config_event(&network_payload)
        .map_err(|_| "temporal object self-check: network config record failed")?;
    let network_latest = latest_version(network_config_object_key())
        .map_err(|_| "temporal object self-check: network config history missing")?;
    let network_read = read_version(network_config_object_key(), network_latest.version_id)
        .map_err(|_| "temporal object self-check: network config payload unreadable")?;
    if network_read.len() < 4 {
        return Err("temporal object self-check: network config payload too short");
    }

    let wasm_syscall_payload = [
        TEMPORAL_OBJECT_ENCODING_V1,
        TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT,
        TEMPORAL_WASM_SYSCALL_MODULE_TABLE_EVENT_STATE,
        0,
    ];
    record_wasm_syscall_module_table_event(&wasm_syscall_payload)
        .map_err(|_| "temporal object self-check: wasm syscall module record failed")?;
    let wasm_syscall_latest = latest_version(wasm_syscall_module_table_object_key())
        .map_err(|_| "temporal object self-check: wasm syscall module history missing")?;
    let wasm_syscall_read =
        read_version(wasm_syscall_module_table_object_key(), wasm_syscall_latest.version_id)
            .map_err(|_| "temporal object self-check: wasm syscall module payload unreadable")?;
    if wasm_syscall_read.len() < 4 {
        return Err("temporal object self-check: wasm syscall module payload too short");
    }

    let scheduler_payload = [
        TEMPORAL_OBJECT_ENCODING_V1,
        TEMPORAL_SCHEDULER_OBJECT,
        TEMPORAL_SCHEDULER_EVENT_STATE,
        0,
    ];
    record_scheduler_state_event(&scheduler_payload)
        .map_err(|_| "temporal object self-check: scheduler record failed")?;
    let scheduler_latest = latest_version(scheduler_state_object_key())
        .map_err(|_| "temporal object self-check: scheduler history missing")?;
    let scheduler_read = read_version(scheduler_state_object_key(), scheduler_latest.version_id)
        .map_err(|_| "temporal object self-check: scheduler payload unreadable")?;
    if scheduler_read.len() < 4 {
        return Err("temporal object self-check: scheduler payload too short");
    }

    crate::replay::start_record(0, 0x5450_4C59, 0)
        .map_err(|_| "temporal object self-check: replay start_record failed")?;
    let replay_latest = latest_version(replay_state_object_key())
        .map_err(|_| "temporal object self-check: replay history missing")?;
    let replay_read = read_version(replay_state_object_key(), replay_latest.version_id)
        .map_err(|_| "temporal object self-check: replay payload unreadable")?;
    if replay_read.len() < 8 {
        return Err("temporal object self-check: replay payload too short");
    }
    rollback_path(replay_state_object_key(), replay_latest.version_id)
        .map_err(|_| "temporal object self-check: replay rollback failed")?;
    crate::replay::clear(0);

    let mut legacy_network_payload = [0u8; 32];
    legacy_network_payload[0] = TEMPORAL_OBJECT_ENCODING_V1;
    legacy_network_payload[1] = TEMPORAL_NETWORK_LEGACY_OBJECT;
    legacy_network_payload[2] = TEMPORAL_NETWORK_LEGACY_EVENT_STATE;
    legacy_network_payload[3] = 1; // schema v1
    legacy_network_payload[24..28].copy_from_slice(&1u32.to_le_bytes());
    record_network_legacy_state_event(&legacy_network_payload)
        .map_err(|_| "temporal object self-check: legacy network record failed")?;
    let legacy_latest = latest_version(network_legacy_state_object_key())
        .map_err(|_| "temporal object self-check: legacy network history missing")?;
    rollback_path(network_legacy_state_object_key(), legacy_latest.version_id)
        .map_err(|_| "temporal object self-check: legacy network rollback failed")?;

    let mut wifi_payload = [0u8; 84];
    wifi_payload[0] = TEMPORAL_OBJECT_ENCODING_V1;
    wifi_payload[1] = TEMPORAL_WIFI_OBJECT;
    wifi_payload[2] = TEMPORAL_WIFI_EVENT_STATE;
    wifi_payload[3] = 1; // schema v1
    wifi_payload[4] = 0; // no pci device
    wifi_payload[5] = 0; // disabled
    wifi_payload[6] = 0; // WifiState::Disabled
    wifi_payload[7] = 0; // ip not assigned
    wifi_payload[39] = 0; // WifiSecurity::Open
    // scan_count at offset 16 remains 0, connection network is zeroed and valid for ssid_len=0
    record_wifi_state_event(&wifi_payload)
        .map_err(|_| "temporal object self-check: wifi record failed")?;
    let wifi_latest = latest_version(wifi_state_object_key())
        .map_err(|_| "temporal object self-check: wifi history missing")?;
    rollback_path(wifi_state_object_key(), wifi_latest.version_id)
        .map_err(|_| "temporal object self-check: wifi rollback failed")?;

    crate::enclave::set_remote_attestation_policy(crate::enclave::RemoteAttestationPolicy::Audit);
    let enclave_latest = latest_version(enclave_state_object_key())
        .map_err(|_| "temporal object self-check: enclave history missing")?;
    let enclave_read = read_version(enclave_state_object_key(), enclave_latest.version_id)
        .map_err(|_| "temporal object self-check: enclave payload unreadable")?;
    if enclave_read.len() < 4 {
        return Err("temporal object self-check: enclave payload too short");
    }
    rollback_path(enclave_state_object_key(), enclave_latest.version_id)
        .map_err(|_| "temporal object self-check: enclave rollback failed")?;
    crate::enclave::set_remote_attestation_policy(crate::enclave::RemoteAttestationPolicy::Enforce);

    Ok(())
}

pub fn persistence_recovery_self_check() -> Result<(), &'static str> {
    const PATH: &str = "/temporal-persist-selfcheck";
    const PAYLOAD: &[u8] = b"temporal-persist-recovery";

    let backup = {
        let mut service = TEMPORAL.lock();
        service.apply_retention_for_persistence_locked();
        service
            .encode_persistent_state_locked()
            .ok_or("temporal persistence self-check backup encode failed")?
    };

    let result = (|| -> Result<(), &'static str> {
        record_object_snapshot(PATH, PAYLOAD)
            .map_err(|_| "temporal persistence self-check snapshot write failed")?;
        let expected = latest_version(PATH)
            .map_err(|_| "temporal persistence self-check latest lookup failed")?
            .version_id;

        let cap = temporal_store_cap();
        {
            let persistence = crate::persistence::persistence().lock();
            let (snap, _) = persistence
                .read_temporal_snapshot(&cap)
                .map_err(|_| "temporal persistence self-check read failed")?;
            if snap.is_empty() {
                return Err("temporal persistence self-check snapshot empty");
            }
            if TemporalService::decode_persistent_state(snap).is_none() {
                return Err("temporal persistence self-check snapshot decode failed");
            }
        }

        {
            let mut service = TEMPORAL.lock();
            *service = TemporalService::new();
        }

        recover_from_persistence()?;
        let recovered = latest_version(PATH)
            .map_err(|_| "temporal persistence self-check post-recover latest missing")?
            .version_id;
        if recovered != expected {
            return Err("temporal persistence self-check recovered version mismatch");
        }
        Ok(())
    })();

    {
        let mut service = TEMPORAL.lock();
        if backup.is_empty() {
            *service = TemporalService::new();
        } else {
            *service = TemporalService::decode_persistent_state(&backup)
                .ok_or("temporal persistence self-check backup decode failed")?;
        }
    }
    persist_state_snapshot();

    result
}

pub fn branch_merge_self_check() -> Result<(), &'static str> {
    const PATH: &str = "/temporal-branch-selfcheck";
    const BASE: &[u8] = b"temporal-branch-base";
    const MAIN_UPDATE: &[u8] = b"temporal-branch-main-update";
    const BRANCH_NAME: &str = "feature";

    crate::vfs::write_path(PATH, BASE).map_err(|_| "branch self-check seed write failed")?;
    let seed_version = snapshot_path(PATH).map_err(|_| "branch self-check seed snapshot failed")?;
    let _ = seed_version;

    let branch_id =
        create_branch(PATH, BRANCH_NAME, None).map_err(|_| "branch self-check create failed")?;
    crate::vfs::write_path(PATH, MAIN_UPDATE).map_err(|_| "branch self-check main write failed")?;
    let main_head = latest_version(PATH)
        .map_err(|_| "branch self-check latest lookup failed")?
        .version_id;

    let merge = merge_branch(
        PATH,
        DEFAULT_BRANCH_NAME,
        Some(BRANCH_NAME),
        TemporalMergeStrategy::FastForwardOnly,
    )
    .map_err(|_| "branch self-check merge failed")?;
    if !merge.fast_forward {
        return Err("branch self-check expected fast-forward merge");
    }
    if merge.target_branch_id != branch_id {
        return Err("branch self-check merge target branch mismatch");
    }

    let (_checked_out_branch, head) =
        checkout_branch(PATH, BRANCH_NAME).map_err(|_| "branch self-check checkout failed")?;
    if head != Some(main_head) {
        return Err("branch self-check checkout head mismatch");
    }

    let mut read_buf = Vec::new();
    read_buf.resize(MAIN_UPDATE.len().saturating_add(32), 0);
    let read = crate::vfs::read_path(PATH, &mut read_buf).map_err(|_| "branch self-check read failed")?;
    read_buf.truncate(read);
    if read_buf.as_slice() != MAIN_UPDATE {
        return Err("branch self-check payload mismatch");
    }

    let branches = list_branches(PATH).map_err(|_| "branch self-check list failed")?;
    if branches.len() < 2 {
        return Err("branch self-check expected at least two branches");
    }
    let mut found_feature = false;
    for branch in branches {
        if branch.name == BRANCH_NAME {
            found_feature = true;
            if !branch.active {
                return Err("branch self-check branch not active after checkout");
            }
            if branch.head_version_id != Some(main_head) {
                return Err("branch self-check branch head mismatch");
            }
            break;
        }
    }
    if !found_feature {
        return Err("branch self-check feature branch missing");
    }

    Ok(())
}

pub fn audit_emission_self_check() -> Result<(), &'static str> {
    use crate::security::SecurityEvent;

    const PATH: &str = "/temporal-audit-selfcheck";
    const PAYLOAD: &[u8] = b"temporal-audit-signal";

    let before_total = crate::security::security().get_audit_stats().0;

    crate::vfs::write_path(PATH, PAYLOAD).map_err(|_| "temporal audit self-check seed write failed")?;
    snapshot_path(PATH).map_err(|_| "temporal audit self-check snapshot failed")?;
    let _ = latest_version(PATH).map_err(|_| "temporal audit self-check latest query failed")?;
    let _ = list_versions(PATH).map_err(|_| "temporal audit self-check list query failed")?;

    let after_total = crate::security::security().get_audit_stats().0;
    if after_total <= before_total {
        return Err("temporal audit self-check did not increase audit total");
    }

    let events = crate::security::security().get_recent_events(32);
    let mut saw_temporal_event = false;
    for entry in events.iter().flatten() {
        if entry.event == SecurityEvent::TemporalOperation {
            saw_temporal_event = true;
            break;
        }
    }
    if !saw_temporal_event {
        return Err("temporal audit self-check did not observe temporal audit event");
    }

    Ok(())
}
