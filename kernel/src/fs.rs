/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Oreulia Filesystem
//!
//! A persistence-first, capability-gated filesystem service providing durable
//! storage without ambient paths or global namespaces.
//!
//! v1 shifts the in-kernel service away from fixed compile-time arrays and
//! toward dynamic storage, runtime observability, and policy-driven limits.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use spin::{Mutex, Once};

/// IPC capability transfer only carries a short prefix inline.
pub const IPC_KEY_PREFIX_BYTES: usize = 16;
/// Number of u32 words used to transport the inline key prefix.
pub const IPC_KEY_PREFIX_WORDS: usize = IPC_KEY_PREFIX_BYTES / core::mem::size_of::<u32>();

// ============================================================================
// Core Types
// ============================================================================

/// A file key (string identifier)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileKey {
    text: Box<str>,
}

impl FileKey {
    /// Create a new file key from a string slice.
    pub fn new(s: &str) -> Result<Self, FilesystemError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(FilesystemError::InvalidKey);
        }

        Ok(FileKey {
            text: trimmed.to_string().into_boxed_str(),
        })
    }

    /// Build a key directly from owned text.
    pub fn from_string(text: String) -> Result<Self, FilesystemError> {
        if text.trim().is_empty() {
            return Err(FilesystemError::InvalidKey);
        }

        Ok(FileKey {
            text: text.into_boxed_str(),
        })
    }

    /// Get the key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Get the key as raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// Check if this key is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Length of the key in bytes.
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Pack key prefix into u32 array for IPC transfer.
    pub fn pack_prefix(&self) -> [u32; IPC_KEY_PREFIX_WORDS] {
        let mut result = [0u32; IPC_KEY_PREFIX_WORDS];
        let len = self.len().min(IPC_KEY_PREFIX_BYTES);
        for i in 0..len {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            result[word_idx] |= (self.as_bytes()[i] as u32) << (byte_idx * 8);
        }
        result
    }

    /// Unpack key prefix from u32 array (IPC transfer).
    pub fn unpack_prefix(
        data: [u32; IPC_KEY_PREFIX_WORDS],
        len: usize,
    ) -> Result<Self, FilesystemError> {
        if len > IPC_KEY_PREFIX_BYTES {
            return Err(FilesystemError::KeyTooLong);
        }

        let mut bytes = Vec::with_capacity(len);
        for i in 0..len {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            bytes.push(((data[word_idx] >> (byte_idx * 8)) & 0xFF) as u8);
        }

        let text = String::from_utf8(bytes).map_err(|_| FilesystemError::InvalidKey)?;
        FileKey::from_string(text)
    }
}

impl fmt::Display for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Relative access temperature based on observed activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTemperature {
    Cold,
    Warm,
    Hot,
}

/// File metadata.
#[derive(Debug, Clone, Copy)]
pub struct FileMetadata {
    /// Size in bytes.
    pub size: usize,
    /// Creation timestamp.
    pub created: u64,
    /// Last modified timestamp.
    pub modified: u64,
    /// Last accessed timestamp.
    pub accessed: u64,
    /// Number of successful reads.
    pub read_count: u64,
    /// Number of successful writes.
    pub write_count: u64,
    /// Rolling hotness score used for adaptive reporting.
    pub hot_score: u64,
}

/// A file object in the filesystem.
#[derive(Clone)]
pub struct File {
    /// The file's key.
    pub key: FileKey,
    /// File data.
    pub data: Vec<u8>,
    /// File metadata.
    pub metadata: FileMetadata,
}

impl File {
    /// Create a new empty file with the given key.
    pub fn new(key: FileKey, tick: u64) -> Self {
        File {
            key,
            data: Vec::new(),
            metadata: FileMetadata {
                size: 0,
                created: tick,
                modified: tick,
                accessed: tick,
                read_count: 0,
                write_count: 0,
                hot_score: 0,
            },
        }
    }

    fn decay_hot_score(current: u64, delta: u64) -> u64 {
        current
            .saturating_mul(7)
            .saturating_div(8)
            .saturating_add(delta)
    }

    /// Write data to the file.
    pub fn write(&mut self, data: &[u8], tick: u64) {
        self.data.clear();
        self.data.extend_from_slice(data);
        self.metadata.size = self.data.len();
        self.metadata.modified = tick;
        self.metadata.accessed = tick;
        self.metadata.write_count = self.metadata.write_count.saturating_add(1);
        let write_weight = data.len().max(1) as u64;
        self.metadata.hot_score = Self::decay_hot_score(self.metadata.hot_score, write_weight);
    }

    /// Read the file data.
    pub fn read(&mut self, tick: u64) -> &[u8] {
        self.metadata.accessed = tick;
        self.metadata.read_count = self.metadata.read_count.saturating_add(1);
        self.metadata.hot_score = Self::decay_hot_score(self.metadata.hot_score, 1);
        &self.data
    }

    /// Classify the file relative to the current average hotness.
    pub fn temperature(&self, average_hot_score: u64) -> AccessTemperature {
        if self.metadata.hot_score == 0 {
            AccessTemperature::Cold
        } else if self.metadata.hot_score > average_hot_score.saturating_mul(2).max(1) {
            AccessTemperature::Hot
        } else if self.metadata.hot_score >= average_hot_score.max(1) {
            AccessTemperature::Warm
        } else {
            AccessTemperature::Cold
        }
    }
}

// ============================================================================
// Capability Types
// ============================================================================

/// Filesystem capability rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemRights {
    bits: u32,
}

impl FilesystemRights {
    pub const NONE: u32 = 0;
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const DELETE: u32 = 1 << 2;
    pub const LIST: u32 = 1 << 3;
    pub const ALL: u32 = Self::READ | Self::WRITE | Self::DELETE | Self::LIST;

    /// Create a new rights set.
    pub const fn new(bits: u32) -> Self {
        FilesystemRights { bits }
    }

    /// Check if a right is present.
    pub const fn has(&self, right: u32) -> bool {
        (self.bits & right) != 0
    }

    /// Attenuate (reduce) rights.
    pub const fn attenuate(&self, rights: u32) -> Self {
        FilesystemRights {
            bits: self.bits & rights,
        }
    }

    /// Read-only rights.
    pub const fn read_only() -> Self {
        FilesystemRights { bits: Self::READ }
    }

    /// Read-write rights.
    pub const fn read_write() -> Self {
        FilesystemRights {
            bits: Self::READ | Self::WRITE,
        }
    }

    /// Full rights.
    pub const fn all() -> Self {
        FilesystemRights { bits: Self::ALL }
    }
}

/// Optional quota carried by a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemQuota {
    pub max_total_bytes: Option<usize>,
    pub max_file_count: Option<usize>,
    pub max_single_file_bytes: Option<usize>,
}

impl FilesystemQuota {
    pub const fn unlimited() -> Self {
        FilesystemQuota {
            max_total_bytes: None,
            max_file_count: None,
            max_single_file_bytes: None,
        }
    }

    pub const fn bounded(
        max_total_bytes: Option<usize>,
        max_file_count: Option<usize>,
        max_single_file_bytes: Option<usize>,
    ) -> Self {
        FilesystemQuota {
            max_total_bytes,
            max_file_count,
            max_single_file_bytes,
        }
    }
}

/// A capability to access the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemCapability {
    /// Capability ID (index into capability table).
    pub cap_id: u32,
    /// Rights granted by this capability.
    pub rights: FilesystemRights,
    /// Optional key prefix filter (for scoped access).
    pub key_prefix: Option<FileKey>,
    /// Optional resource budget associated with the capability.
    pub quota: Option<FilesystemQuota>,
}

impl FilesystemCapability {
    /// Create a new filesystem capability.
    pub fn new(cap_id: u32, rights: FilesystemRights) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: None,
            quota: None,
        }
    }

    /// Create a capability with an explicit quota.
    pub fn with_quota(cap_id: u32, rights: FilesystemRights, quota: FilesystemQuota) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: None,
            quota: Some(quota),
        }
    }

    /// Create a scoped capability (only access keys with prefix).
    pub fn scoped(cap_id: u32, rights: FilesystemRights, prefix: FileKey) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: Some(prefix),
            quota: None,
        }
    }

    /// Create a scoped capability with an explicit quota.
    pub fn scoped_with_quota(
        cap_id: u32,
        rights: FilesystemRights,
        prefix: FileKey,
        quota: FilesystemQuota,
    ) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: Some(prefix),
            quota: Some(quota),
        }
    }

    /// Check if this capability allows access to a key.
    pub fn can_access(&self, key: &FileKey) -> bool {
        if let Some(prefix) = &self.key_prefix {
            key.as_str().starts_with(prefix.as_str())
        } else {
            true
        }
    }

    /// Attenuate this capability.
    pub fn attenuate(&self, rights: FilesystemRights) -> Self {
        FilesystemCapability {
            cap_id: self.cap_id,
            rights: self.rights.attenuate(rights.bits),
            key_prefix: self.key_prefix.clone(),
            quota: self.quota,
        }
    }

    /// Attach or replace a quota.
    pub fn with_quota_limit(mut self, quota: FilesystemQuota) -> Self {
        self.quota = Some(quota);
        self
    }

    /// Convert to IPC capability for transfer.
    pub fn to_ipc_capability(&self) -> crate::ipc::Capability {
        use crate::ipc::{Capability, CapabilityType};

        let mut cap = Capability::with_type(
            self.cap_id,
            0, // object_id - filesystem is global service
            self.rights.bits,
            CapabilityType::Filesystem,
        );

        if let Some(prefix) = &self.key_prefix {
            cap.extra = prefix.pack_prefix();
            cap.object_id = prefix.len() as u32;
        }

        // IPC v0 transports rights and prefix only; quota stays local to the sender.
        cap.sign();
        cap
    }

    /// Create from IPC capability.
    pub fn from_ipc_capability(cap: &crate::ipc::Capability) -> Result<Self, FilesystemError> {
        use crate::ipc::CapabilityType;

        if cap.cap_type != CapabilityType::Filesystem {
            return Err(FilesystemError::InvalidOperation);
        }
        if !cap.verify() {
            return Err(FilesystemError::InvalidOperation);
        }

        let rights = FilesystemRights::new(cap.rights);
        let key_prefix = if cap.object_id > 0 {
            Some(FileKey::unpack_prefix(cap.extra, cap.object_id as usize)?)
        } else {
            None
        };

        Ok(FilesystemCapability {
            cap_id: cap.cap_id,
            rights,
            key_prefix,
            quota: None,
        })
    }
}

// ============================================================================
// Message Protocol
// ============================================================================

/// Filesystem request message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Read,
    Write,
    Delete,
    List,
}

/// A filesystem request message.
pub struct Request {
    pub req_type: RequestType,
    pub key: Option<FileKey>,
    pub data: Vec<u8>,
    pub capability: FilesystemCapability,
}

impl Request {
    /// Create a read request.
    pub fn read(key: FileKey, capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::Read,
            key: Some(key),
            data: Vec::new(),
            capability,
        }
    }

    /// Create a write request.
    pub fn write(
        key: FileKey,
        data: &[u8],
        capability: FilesystemCapability,
    ) -> Result<Self, FilesystemError> {
        Ok(Request {
            req_type: RequestType::Write,
            key: Some(key),
            data: data.to_vec(),
            capability,
        })
    }

    /// Create a delete request.
    pub fn delete(key: FileKey, capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::Delete,
            key: Some(key),
            data: Vec::new(),
            capability,
        }
    }

    /// Create a list request.
    pub fn list(capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::List,
            key: None,
            data: Vec::new(),
            capability,
        }
    }
}

/// Response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Ok,
    Error(FilesystemError),
}

/// A filesystem response message.
pub struct Response {
    pub status: ResponseStatus,
    pub data: Vec<u8>,
    pub detail: Option<String>,
}

impl Response {
    /// Create a success response.
    pub fn ok(data: &[u8]) -> Self {
        Response {
            status: ResponseStatus::Ok,
            data: data.to_vec(),
            detail: None,
        }
    }

    /// Create a success response from owned data without another copy.
    pub fn ok_owned(data: Vec<u8>) -> Self {
        Response {
            status: ResponseStatus::Ok,
            data,
            detail: None,
        }
    }

    /// Create a success response with contextual detail.
    pub fn ok_with_detail(data: &[u8], detail: impl Into<String>) -> Self {
        Response {
            status: ResponseStatus::Ok,
            data: data.to_vec(),
            detail: Some(detail.into()),
        }
    }

    /// Create an error response.
    pub fn error(error: FilesystemError) -> Self {
        Response {
            status: ResponseStatus::Error(error),
            data: Vec::new(),
            detail: None,
        }
    }

    /// Create an error response with contextual detail.
    pub fn error_with_detail(error: FilesystemError, detail: impl Into<String>) -> Self {
        Response {
            status: ResponseStatus::Error(error),
            data: Vec::new(),
            detail: Some(detail.into()),
        }
    }

    /// Get response data.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    /// Optional detail for debugging and richer feedback.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Filesystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemError {
    /// File not found.
    NotFound,
    /// File already exists.
    AlreadyExists,
    /// File exceeds the caller's allowed budget.
    FileTooLarge,
    /// Inline IPC key prefix length was invalid.
    KeyTooLong,
    /// Invalid key.
    InvalidKey,
    /// Permission denied (capability check failed).
    PermissionDenied,
    /// Quota would be exceeded by the requested operation.
    QuotaExceeded,
    /// Backend metadata was internally inconsistent.
    CorruptedMetadata,
    /// Invalid operation.
    InvalidOperation,
    /// Reserved compatibility error for bounded backends.
    FilesystemFull,
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FilesystemError::NotFound => write!(f, "File not found"),
            FilesystemError::AlreadyExists => write!(f, "File already exists"),
            FilesystemError::FileTooLarge => write!(f, "File exceeds allowed size"),
            FilesystemError::KeyTooLong => write!(f, "Inline key prefix too long for IPC"),
            FilesystemError::InvalidKey => write!(f, "Invalid key"),
            FilesystemError::PermissionDenied => write!(f, "Permission denied"),
            FilesystemError::QuotaExceeded => write!(f, "Capability quota exceeded"),
            FilesystemError::CorruptedMetadata => write!(f, "Corrupted filesystem metadata"),
            FilesystemError::InvalidOperation => write!(f, "Invalid operation"),
            FilesystemError::FilesystemFull => write!(f, "Filesystem full"),
        }
    }
}

// ============================================================================
// Observability
// ============================================================================

/// Filesystem operation kinds tracked by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemOperation {
    Read,
    WriteCreate,
    WriteUpdate,
    Delete,
    List,
    PermissionDenied,
    NotFound,
    QuotaDenied,
    Repair,
}

/// Latest event emitted by the filesystem service.
#[derive(Debug, Clone)]
pub struct FilesystemEvent {
    pub sequence: u64,
    pub tick: u64,
    pub operation: FilesystemOperation,
    pub key: Option<FileKey>,
    pub bytes: usize,
    pub detail: Option<String>,
}

/// Aggregate filesystem metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilesystemMetrics {
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub lists: u64,
    pub creates: u64,
    pub updates: u64,
    pub permission_denials: u64,
    pub quota_denials: u64,
    pub not_found: u64,
    pub repairs: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub net_bytes_added: i64,
    pub bytes_deleted: u64,
    pub last_tick: u64,
}

impl FilesystemMetrics {
    pub fn total_operations(&self) -> u64 {
        self.reads
            .saturating_add(self.writes)
            .saturating_add(self.deletes)
            .saturating_add(self.lists)
            .saturating_add(self.permission_denials)
            .saturating_add(self.quota_denials)
            .saturating_add(self.not_found)
            .saturating_add(self.repairs)
    }
}

/// Retention policy for in-memory observability data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemRetentionPolicy {
    /// Maximum number of retained filesystem events.
    ///
    /// `None` disables trimming and allows unbounded growth.
    pub max_event_log_entries: Option<usize>,
}

impl FilesystemRetentionPolicy {
    /// Leave the event log unbounded.
    pub const fn unbounded() -> Self {
        FilesystemRetentionPolicy {
            max_event_log_entries: None,
        }
    }

    /// Retain at most `max_event_log_entries` events.
    pub const fn bounded(max_event_log_entries: usize) -> Self {
        FilesystemRetentionPolicy {
            max_event_log_entries: Some(max_event_log_entries),
        }
    }

    /// Default retention budget: one page of event headers.
    ///
    /// This keeps the default bounded without reintroducing an arbitrary
    /// compile-time event count.
    pub fn page_sized_default() -> Self {
        let entry_size = core::mem::size_of::<FilesystemEvent>().max(1);
        let page_budget = crate::paging::PAGE_SIZE / entry_size;
        FilesystemRetentionPolicy::bounded(page_budget.max(1))
    }
}

impl Default for FilesystemRetentionPolicy {
    fn default() -> Self {
        Self::page_sized_default()
    }
}

/// Snapshot of filesystem state.
#[derive(Debug, Clone)]
pub struct FilesystemHealth {
    pub file_count: usize,
    pub total_bytes: usize,
    pub average_file_size: usize,
    pub hottest_key: Option<FileKey>,
    pub hottest_score: u64,
    pub hot_files: usize,
    pub warm_files: usize,
    pub cold_files: usize,
    pub hot_bytes: usize,
    pub warm_bytes: usize,
    pub cold_bytes: usize,
    pub average_hot_score: u64,
    pub total_operations: u64,
    pub permission_denials: u64,
    pub quota_denials: u64,
    pub not_found: u64,
    pub event_log_len: usize,
    pub event_log_capacity: Option<usize>,
    pub last_event: Option<FilesystemEvent>,
    pub last_error: Option<FilesystemEvent>,
}

/// Scrub pass result.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilesystemScrubReport {
    pub files_scanned: usize,
    pub issues_found: usize,
    pub repaired_files: usize,
    pub bytes_recounted: usize,
}

// ============================================================================
// Storage Backend (RAM-backed)
// ============================================================================

struct WriteOutcome {
    created: bool,
    previous_size: usize,
    new_size: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct StorageThermalProfile {
    hot_files: usize,
    warm_files: usize,
    cold_files: usize,
    hot_bytes: usize,
    warm_bytes: usize,
    cold_bytes: usize,
    average_hot_score: u64,
}

/// RAM-backed storage for the filesystem.
struct RamStorage {
    files: BTreeMap<FileKey, File>,
    total_bytes: usize,
}

impl RamStorage {
    /// Create a new empty RAM storage.
    fn new() -> Self {
        RamStorage {
            files: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    /// Check if a file exists.
    fn contains(&self, key: &FileKey) -> bool {
        self.files.contains_key(key)
    }

    /// Read a file and update its access metadata.
    fn read(&mut self, key: &FileKey, tick: u64) -> Option<Vec<u8>> {
        self.files.get_mut(key).map(|file| file.read(tick).to_vec())
    }

    /// Upsert file contents.
    fn write(&mut self, key: &FileKey, data: &[u8], tick: u64) -> WriteOutcome {
        if let Some(file) = self.files.get_mut(key) {
            let previous_size = file.metadata.size;
            file.write(data, tick);
            self.total_bytes = self.total_bytes + file.metadata.size - previous_size;
            WriteOutcome {
                created: false,
                previous_size,
                new_size: file.metadata.size,
            }
        } else {
            let mut file = File::new(key.clone(), tick);
            file.write(data, tick);
            let new_size = file.metadata.size;
            self.total_bytes = self.total_bytes.saturating_add(new_size);
            self.files.insert(key.clone(), file);
            WriteOutcome {
                created: true,
                previous_size: 0,
                new_size,
            }
        }
    }

    /// Remove a file by key.
    fn remove(&mut self, key: &FileKey) -> Result<File, FilesystemError> {
        let removed = self.files.remove(key).ok_or(FilesystemError::NotFound)?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.metadata.size);
        Ok(removed)
    }

    /// List all file keys, optionally filtered by a prefix.
    fn list_keys(&self, prefix: Option<&FileKey>) -> Vec<FileKey> {
        self.files
            .keys()
            .filter(|key| {
                prefix
                    .map(|prefix_key| key.as_str().starts_with(prefix_key.as_str()))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Current number of files.
    fn count(&self) -> usize {
        self.files.len()
    }

    /// Current bytes stored.
    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Size for a given key if present.
    fn file_size(&self, key: &FileKey) -> Option<usize> {
        self.files.get(key).map(|file| file.metadata.size)
    }

    /// Scrub metadata and repair simple size mismatches.
    fn scrub_and_repair(&mut self) -> FilesystemScrubReport {
        let mut report = FilesystemScrubReport::default();
        let mut recomputed_total = 0usize;

        for file in self.files.values_mut() {
            report.files_scanned += 1;
            recomputed_total = recomputed_total.saturating_add(file.data.len());
            if file.metadata.size != file.data.len() {
                report.issues_found += 1;
                report.repaired_files += 1;
                file.metadata.size = file.data.len();
            }
        }

        if recomputed_total != self.total_bytes {
            report.issues_found += 1;
            report.bytes_recounted = recomputed_total;
            self.total_bytes = recomputed_total;
        }

        report
    }

    fn average_hot_score(&self) -> u64 {
        if self.files.is_empty() {
            return 0;
        }

        let total: u64 = self
            .files
            .values()
            .map(|file| file.metadata.hot_score)
            .sum();
        total / self.files.len() as u64
    }

    fn hottest_entry(&self) -> Option<(FileKey, u64)> {
        self.files
            .values()
            .max_by_key(|file| file.metadata.hot_score)
            .map(|file| (file.key.clone(), file.metadata.hot_score))
    }

    fn thermal_profile(&self) -> StorageThermalProfile {
        let average = self.average_hot_score();
        let mut profile = StorageThermalProfile {
            average_hot_score: average,
            ..StorageThermalProfile::default()
        };

        for file in self.files.values() {
            match file.temperature(average) {
                AccessTemperature::Cold => {
                    profile.cold_files += 1;
                    profile.cold_bytes = profile.cold_bytes.saturating_add(file.metadata.size);
                }
                AccessTemperature::Warm => {
                    profile.warm_files += 1;
                    profile.warm_bytes = profile.warm_bytes.saturating_add(file.metadata.size);
                }
                AccessTemperature::Hot => {
                    profile.hot_files += 1;
                    profile.hot_bytes = profile.hot_bytes.saturating_add(file.metadata.size);
                }
            }
        }

        profile
    }
}

// ============================================================================
// Filesystem Service
// ============================================================================

struct FilesystemState {
    storage: RamStorage,
    metrics: FilesystemMetrics,
    next_sequence: u64,
    retention_policy: FilesystemRetentionPolicy,
    event_log: VecDeque<FilesystemEvent>,
    last_event: Option<FilesystemEvent>,
    last_error: Option<FilesystemEvent>,
}

impl FilesystemState {
    fn new() -> Self {
        FilesystemState {
            storage: RamStorage::new(),
            metrics: FilesystemMetrics::default(),
            next_sequence: 1,
            retention_policy: FilesystemRetentionPolicy::default(),
            event_log: VecDeque::new(),
            last_event: None,
            last_error: None,
        }
    }

    fn trim_event_log(&mut self) {
        let Some(max_entries) = self.retention_policy.max_event_log_entries else {
            return;
        };

        while self.event_log.len() > max_entries {
            self.event_log.pop_front();
        }
    }

    fn record_event(
        &mut self,
        tick: u64,
        operation: FilesystemOperation,
        key: Option<&FileKey>,
        bytes: usize,
        detail: Option<String>,
    ) {
        let event = FilesystemEvent {
            sequence: self.next_sequence,
            tick,
            operation,
            key: key.cloned(),
            bytes,
            detail,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.event_log.push_back(event.clone());
        self.trim_event_log();
        self.last_event = Some(event.clone());
        match operation {
            FilesystemOperation::PermissionDenied
            | FilesystemOperation::NotFound
            | FilesystemOperation::QuotaDenied => {
                self.last_error = Some(event);
            }
            _ => {}
        }
    }

    fn note_permission_denied(&mut self, tick: u64, key: Option<&FileKey>, detail: &str) {
        self.metrics.permission_denials = self.metrics.permission_denials.saturating_add(1);
        self.metrics.last_tick = tick;
        self.record_event(
            tick,
            FilesystemOperation::PermissionDenied,
            key,
            0,
            Some(detail.to_string()),
        );
    }

    fn note_quota_denied(&mut self, tick: u64, key: Option<&FileKey>, detail: &str) {
        self.metrics.quota_denials = self.metrics.quota_denials.saturating_add(1);
        self.metrics.last_tick = tick;
        self.record_event(
            tick,
            FilesystemOperation::QuotaDenied,
            key,
            0,
            Some(detail.to_string()),
        );
    }

    fn note_not_found(&mut self, tick: u64, key: &FileKey) {
        self.metrics.not_found = self.metrics.not_found.saturating_add(1);
        self.metrics.last_tick = tick;
        self.record_event(
            tick,
            FilesystemOperation::NotFound,
            Some(key),
            0,
            Some("missing file".to_string()),
        );
    }
}

/// The main filesystem service.
pub struct FilesystemService {
    state: Mutex<FilesystemState>,
    root_capability: FilesystemCapability,
}

impl FilesystemService {
    /// Create a new filesystem service.
    pub fn new() -> Self {
        FilesystemService {
            state: Mutex::new(FilesystemState::new()),
            root_capability: FilesystemCapability {
                cap_id: 0,
                rights: FilesystemRights::all(),
                key_prefix: None,
                quota: None,
            },
        }
    }

    fn current_tick() -> u64 {
        crate::pit::try_get_ticks().unwrap_or(0)
    }

    /// Check if a capability grants the required rights for an operation.
    fn check_permission(
        &self,
        capability: &FilesystemCapability,
        key: &FileKey,
        required_right: u32,
    ) -> Result<(), FilesystemError> {
        if !capability.rights.has(required_right) {
            return Err(FilesystemError::PermissionDenied);
        }

        if !capability.can_access(key) {
            return Err(FilesystemError::PermissionDenied);
        }

        Ok(())
    }

    fn check_quota(
        &self,
        storage: &RamStorage,
        capability: &FilesystemCapability,
        key: &FileKey,
        new_len: usize,
    ) -> Result<(), FilesystemError> {
        let Some(quota) = capability.quota else {
            return Ok(());
        };

        if let Some(limit) = quota.max_single_file_bytes {
            if new_len > limit {
                return Err(FilesystemError::FileTooLarge);
            }
        }

        let existing_size = storage.file_size(key).unwrap_or(0);
        if let Some(limit) = quota.max_total_bytes {
            let projected_total = storage
                .total_bytes()
                .saturating_sub(existing_size)
                .saturating_add(new_len);
            if projected_total > limit {
                return Err(FilesystemError::QuotaExceeded);
            }
        }

        if let Some(limit) = quota.max_file_count {
            let projected_count = storage.count() + usize::from(!storage.contains(key));
            if projected_count > limit {
                return Err(FilesystemError::QuotaExceeded);
            }
        }

        Ok(())
    }

    /// Handle a read request.
    pub fn handle_read(&self, key: &FileKey, capability: &FilesystemCapability) -> Response {
        let tick = Self::current_tick();
        let mut state = self.state.lock();

        if let Err(e) = self.check_permission(capability, key, FilesystemRights::READ) {
            state.note_permission_denied(tick, Some(key), "read denied");
            return Response::error_with_detail(e, format!("read denied for key '{}'", key));
        }

        match state.storage.read(key, tick) {
            Some(data) => {
                state.metrics.reads = state.metrics.reads.saturating_add(1);
                state.metrics.bytes_read =
                    state.metrics.bytes_read.saturating_add(data.len() as u64);
                state.metrics.last_tick = tick;
                state.record_event(tick, FilesystemOperation::Read, Some(key), data.len(), None);
                Response::ok_owned(data)
            }
            None => {
                state.note_not_found(tick, key);
                Response::error_with_detail(
                    FilesystemError::NotFound,
                    format!("read missing key '{}'", key),
                )
            }
        }
    }

    /// Handle a write request (create or update).
    pub fn handle_write(
        &self,
        key: &FileKey,
        data: &[u8],
        capability: &FilesystemCapability,
    ) -> Response {
        let tick = Self::current_tick();
        let mut state = self.state.lock();

        if let Err(e) = self.check_permission(capability, key, FilesystemRights::WRITE) {
            state.note_permission_denied(tick, Some(key), "write denied");
            return Response::error_with_detail(e, format!("write denied for key '{}'", key));
        }

        if let Err(e) = self.check_quota(&state.storage, capability, key, data.len()) {
            state.note_quota_denied(tick, Some(key), "write quota denied");
            return Response::error_with_detail(
                e,
                format!("write of {} bytes denied for key '{}'", data.len(), key),
            );
        }

        let outcome = state.storage.write(key, data, tick);
        state.metrics.writes = state.metrics.writes.saturating_add(1);
        state.metrics.bytes_written = state
            .metrics
            .bytes_written
            .saturating_add(data.len() as u64);
        state.metrics.net_bytes_added = state
            .metrics
            .net_bytes_added
            .saturating_add(outcome.new_size as i64 - outcome.previous_size as i64);
        state.metrics.last_tick = tick;
        if outcome.created {
            state.metrics.creates = state.metrics.creates.saturating_add(1);
            state.record_event(
                tick,
                FilesystemOperation::WriteCreate,
                Some(key),
                outcome.new_size,
                Some(format!("created file ({} bytes)", outcome.new_size)),
            );
        } else {
            state.metrics.updates = state.metrics.updates.saturating_add(1);
            state.record_event(
                tick,
                FilesystemOperation::WriteUpdate,
                Some(key),
                outcome.new_size,
                Some(format!(
                    "updated file ({} -> {} bytes)",
                    outcome.previous_size, outcome.new_size
                )),
            );
        }

        Response::ok_with_detail(
            &[],
            format!(
                "write accepted for '{}' (logical={} bytes, stored={} bytes)",
                key,
                data.len(),
                outcome.new_size
            ),
        )
    }

    /// Handle a delete request.
    pub fn handle_delete(&self, key: &FileKey, capability: &FilesystemCapability) -> Response {
        let tick = Self::current_tick();
        let mut state = self.state.lock();

        if let Err(e) = self.check_permission(capability, key, FilesystemRights::DELETE) {
            state.note_permission_denied(tick, Some(key), "delete denied");
            return Response::error_with_detail(e, format!("delete denied for key '{}'", key));
        }

        match state.storage.remove(key) {
            Ok(file) => {
                state.metrics.deletes = state.metrics.deletes.saturating_add(1);
                state.metrics.bytes_deleted = state
                    .metrics
                    .bytes_deleted
                    .saturating_add(file.metadata.size as u64);
                state.metrics.last_tick = tick;
                state.record_event(
                    tick,
                    FilesystemOperation::Delete,
                    Some(key),
                    file.metadata.size,
                    Some("deleted file".to_string()),
                );
                Response::ok_with_detail(
                    &[],
                    format!("deleted '{}' ({} bytes removed)", key, file.metadata.size),
                )
            }
            Err(e) => {
                state.note_not_found(tick, key);
                Response::error_with_detail(e, format!("delete missing key '{}'", key))
            }
        }
    }

    /// Handle a list request.
    pub fn handle_list(&self, capability: &FilesystemCapability) -> Response {
        let tick = Self::current_tick();
        let mut state = self.state.lock();

        if !capability.rights.has(FilesystemRights::LIST) {
            state.note_permission_denied(tick, capability.key_prefix.as_ref(), "list denied");
            return Response::error_with_detail(
                FilesystemError::PermissionDenied,
                "list denied by capability rights",
            );
        }

        let keys = state.storage.list_keys(capability.key_prefix.as_ref());
        let mut result = Vec::new();
        for key in &keys {
            result.extend_from_slice(key.as_bytes());
            result.push(b'\n');
        }

        state.metrics.lists = state.metrics.lists.saturating_add(1);
        state.metrics.last_tick = tick;
        state.record_event(
            tick,
            FilesystemOperation::List,
            capability.key_prefix.as_ref(),
            result.len(),
            Some(format!("listed {} keys", keys.len())),
        );

        Response::ok_owned(result)
    }

    /// Process a filesystem request.
    pub fn handle_request(&self, request: Request) -> Response {
        match request.req_type {
            RequestType::Read => match request.key.as_ref() {
                Some(key) => self.handle_read(key, &request.capability),
                None => Response::error(FilesystemError::InvalidOperation),
            },
            RequestType::Write => match request.key.as_ref() {
                Some(key) => self.handle_write(key, &request.data, &request.capability),
                None => Response::error(FilesystemError::InvalidOperation),
            },
            RequestType::Delete => match request.key.as_ref() {
                Some(key) => self.handle_delete(key, &request.capability),
                None => Response::error(FilesystemError::InvalidOperation),
            },
            RequestType::List => self.handle_list(&request.capability),
        }
    }

    /// Create a new capability for this filesystem.
    pub fn create_capability(
        &self,
        cap_id: u32,
        rights: FilesystemRights,
        key_prefix: Option<FileKey>,
    ) -> FilesystemCapability {
        if let Some(prefix) = key_prefix {
            FilesystemCapability::scoped(cap_id, rights, prefix)
        } else {
            FilesystemCapability::new(cap_id, rights)
        }
    }

    /// Create a new quota-limited capability for this filesystem.
    pub fn create_capability_with_quota(
        &self,
        cap_id: u32,
        rights: FilesystemRights,
        key_prefix: Option<FileKey>,
        quota: FilesystemQuota,
    ) -> FilesystemCapability {
        if let Some(prefix) = key_prefix {
            FilesystemCapability::scoped_with_quota(cap_id, rights, prefix, quota)
        } else {
            FilesystemCapability::with_quota(cap_id, rights, quota)
        }
    }

    /// Root capability held by the service.
    pub fn root_capability(&self) -> FilesystemCapability {
        self.root_capability.clone()
    }

    /// Lightweight compatibility stats: file count and total bytes.
    pub fn stats(&self) -> (usize, usize) {
        let state = self.state.lock();
        (state.storage.count(), state.storage.total_bytes())
    }

    /// Full metrics snapshot.
    pub fn metrics(&self) -> FilesystemMetrics {
        self.state.lock().metrics
    }

    /// Current observability retention policy.
    pub fn retention_policy(&self) -> FilesystemRetentionPolicy {
        self.state.lock().retention_policy
    }

    /// Update the observability retention policy and immediately trim to fit.
    pub fn set_retention_policy(&self, retention_policy: FilesystemRetentionPolicy) {
        let mut state = self.state.lock();
        state.retention_policy = retention_policy;
        state.trim_event_log();
    }

    /// Convenience helper for configuring only the event log capacity.
    pub fn set_event_log_capacity(&self, max_event_log_entries: Option<usize>) {
        self.set_retention_policy(FilesystemRetentionPolicy {
            max_event_log_entries,
        });
    }

    /// Health snapshot.
    pub fn health(&self) -> FilesystemHealth {
        let state = self.state.lock();
        let profile = state.storage.thermal_profile();
        let hottest = state.storage.hottest_entry();
        let file_count = state.storage.count();

        FilesystemHealth {
            file_count,
            total_bytes: state.storage.total_bytes(),
            average_file_size: if file_count == 0 {
                0
            } else {
                state.storage.total_bytes() / file_count
            },
            hottest_key: hottest.as_ref().map(|(key, _)| key.clone()),
            hottest_score: hottest.map(|(_, score)| score).unwrap_or(0),
            hot_files: profile.hot_files,
            warm_files: profile.warm_files,
            cold_files: profile.cold_files,
            hot_bytes: profile.hot_bytes,
            warm_bytes: profile.warm_bytes,
            cold_bytes: profile.cold_bytes,
            average_hot_score: profile.average_hot_score,
            total_operations: state.metrics.total_operations(),
            permission_denials: state.metrics.permission_denials,
            quota_denials: state.metrics.quota_denials,
            not_found: state.metrics.not_found,
            event_log_len: state.event_log.len(),
            event_log_capacity: state.retention_policy.max_event_log_entries,
            last_event: state.last_event.clone(),
            last_error: state.last_error.clone(),
        }
    }

    /// Return up to `limit` most recent events, oldest to newest.
    pub fn recent_events(&self, limit: usize) -> Vec<FilesystemEvent> {
        let state = self.state.lock();
        let start = state.event_log.len().saturating_sub(limit);
        state.event_log.iter().skip(start).cloned().collect()
    }

    /// Validate metadata consistency and repair simple accounting drift.
    pub fn scrub_and_repair(&self) -> FilesystemScrubReport {
        let tick = Self::current_tick();
        let mut state = self.state.lock();
        let report = state.storage.scrub_and_repair();
        if report.issues_found > 0 {
            state.metrics.repairs = state.metrics.repairs.saturating_add(1);
            state.metrics.last_tick = tick;
            state.record_event(
                tick,
                FilesystemOperation::Repair,
                None,
                report.bytes_recounted,
                Some(format!(
                    "scrub repaired {} files and found {} issues",
                    report.repaired_files, report.issues_found
                )),
            );
        }
        report
    }
}

// ============================================================================
// Global Filesystem Instance
// ============================================================================

/// Global filesystem service instance.
static FILESYSTEM: Once<FilesystemService> = Once::new();

/// Get a reference to the global filesystem.
pub fn filesystem() -> &'static FilesystemService {
    if let Some(fs) = FILESYSTEM.get() {
        fs
    } else {
        FILESYSTEM.call_once(FilesystemService::new)
    }
}

/// Initialize the filesystem service.
pub fn init() {
    let _ = FILESYSTEM.call_once(FilesystemService::new);
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Open a file (syscall wrapper).
pub fn open(path: &str) -> Result<usize, &'static str> {
    let _ = FileKey::new(path).map_err(|_| "Invalid path")?;
    crate::vfs::open_for_current(
        path,
        crate::vfs::OpenFlags::READ | crate::vfs::OpenFlags::WRITE | crate::vfs::OpenFlags::CREATE,
    )
}

/// Read from file (syscall wrapper).
pub fn read(fd: usize, buffer: &mut [u8]) -> Result<usize, &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::read_fd(pid, fd, buffer)
}

/// Write to file (syscall wrapper).
pub fn write(fd: usize, data: &[u8]) -> Result<usize, &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::write_fd(pid, fd, data)
}

/// Close file (syscall wrapper).
pub fn close(fd: usize) -> Result<(), &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::close_fd(pid, fd)
}

/// Delete file (syscall wrapper).
pub fn delete(path: &str) -> Result<(), &'static str> {
    let _ = FileKey::new(path).map_err(|_| "Invalid path")?;
    crate::vfs::unlink(path)
}

/// List directory contents (syscall wrapper).
pub fn list_dir(path: &str, buffer: &mut [u8]) -> Result<usize, &'static str> {
    crate::vfs::list_dir(path, buffer)
}

// ============================================================================
// Kernel-internal convenience shims used by WASI layer
// ============================================================================

/// Read file contents by key, returning a heap-allocated copy.
/// Returns `None` if the file does not exist or cannot be read.
pub fn kernel_read_bytes(key: &FileKey) -> Option<Vec<u8>> {
    let fs = filesystem();
    // Use cap_id=0 (kernel-internal) with all rights to bypass capability check.
    let cap = fs.create_capability(0u32, FilesystemRights::read_only(), None);
    let req = Request::read(key.clone(), cap);
    let resp = fs.handle_request(req);
    if resp.status == ResponseStatus::Ok {
        Some(resp.data)
    } else {
        None
    }
}

/// Write data to a file by key.  Creates the file if it does not exist.
pub fn kernel_write_bytes(key: &FileKey, data: &[u8]) {
    let fs = filesystem();
    let cap = fs.create_capability(0u32, FilesystemRights::read_write(), None);
    if let Ok(req) = Request::write(key.clone(), data, cap) {
        let _ = fs.handle_request(req);
    }
}

/// Delete a file by key.  Silently ignores errors.
pub fn kernel_delete(key: &FileKey) {
    let fs = filesystem();
    let cap = fs.create_capability(0u32, FilesystemRights::all(), None);
    let req = Request::delete(key.clone(), cap);
    let _ = fs.handle_request(req);
}

/// Read a file by key and return its contents as a static byte slice.
/// Returns an empty slice if the file does not exist.
/// The data is leaked from a heap allocation — only use for small, long-lived
/// kernel assets (e.g., WASI pre-opened read-only files).
pub fn kernel_read_static(key: &FileKey) -> &'static [u8] {
    match kernel_read_bytes(key) {
        Some(v) => {
            let boxed = v.into_boxed_slice();
            let leaked: &'static [u8] = Box::leak(boxed);
            leaked
        }
        None => &[],
    }
}

// ============================================================================
// Tests & Examples
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_key_creation() {
        let key = FileKey::new("test.txt").unwrap();
        assert_eq!(key.as_str(), "test.txt");

        assert!(FileKey::new("").is_err());
        assert!(FileKey::new("   ").is_err());

        let long_key = "a".repeat(4096);
        assert_eq!(FileKey::new(&long_key).unwrap().len(), 4096);
    }

    #[test]
    fn test_capability_rights() {
        let rights = FilesystemRights::all();
        assert!(rights.has(FilesystemRights::READ));
        assert!(rights.has(FilesystemRights::WRITE));
        assert!(rights.has(FilesystemRights::DELETE));

        let read_only = rights.attenuate(FilesystemRights::READ);
        assert!(read_only.has(FilesystemRights::READ));
        assert!(!read_only.has(FilesystemRights::WRITE));
    }

    #[test]
    fn test_dynamic_storage_and_health() {
        let fs = FilesystemService::new();
        let cap = fs.create_capability(1, FilesystemRights::all(), None);
        let key = FileKey::new("config/app.json").unwrap();

        let req = Request::write(key.clone(), b"hello world", cap.clone()).unwrap();
        assert_eq!(fs.handle_request(req).status, ResponseStatus::Ok);
        assert_eq!(
            fs.handle_request(Request::read(key.clone(), cap.clone()))
                .status,
            ResponseStatus::Ok
        );

        let health = fs.health();
        assert_eq!(health.file_count, 1);
        assert_eq!(health.total_bytes, 11);
        assert!(health.total_operations >= 2);
        assert_eq!(
            health.event_log_capacity,
            fs.retention_policy().max_event_log_entries
        );
    }

    #[test]
    fn test_event_log_retention_policy_trims() {
        let fs = FilesystemService::new();
        fs.set_event_log_capacity(Some(2));
        let cap = fs.create_capability(1, FilesystemRights::all(), None);

        let key_a = FileKey::new("a").unwrap();
        let key_b = FileKey::new("b").unwrap();
        let key_c = FileKey::new("c").unwrap();

        assert_eq!(
            fs.handle_request(Request::write(key_a, b"one", cap.clone()).unwrap())
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(
            fs.handle_request(Request::write(key_b, b"two", cap.clone()).unwrap())
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(
            fs.handle_request(Request::write(key_c, b"three", cap).unwrap())
                .status,
            ResponseStatus::Ok
        );

        let events = fs.recent_events(8);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].key.as_ref().unwrap().as_str(), "b");
        assert_eq!(events[1].key.as_ref().unwrap().as_str(), "c");
    }
}
