/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
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

//! Oreulia Filesystem v0
//!
//! A persistence-first, capability-gated filesystem service providing
//! durable storage without ambient paths or global namespaces.
//!
//! Key principles:
//! - No ambient access: storage only via capabilities
//! - Flat namespace: keys are strings (e.g., "config/app.json")
//! - Persistence-first: files are durable by default
//! - Message-based: all operations via IPC (channel messages)

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;

/// Maximum file size (4 KiB - reduced to shrink kernel binary)
pub const MAX_FILE_SIZE: usize = 4 * 1024;

/// Maximum key length
pub const MAX_KEY_LENGTH: usize = 256;

/// Maximum number of files (reduced to shrink kernel binary)
pub const MAX_FILES: usize = 32;

// ============================================================================
// Core Types
// ============================================================================

/// A file key (string identifier)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileKey {
    bytes: [u8; MAX_KEY_LENGTH],
    len: usize,
}

impl FileKey {
    /// Create a new file key from a string slice
    pub fn new(s: &str) -> Result<Self, FilesystemError> {
        let bytes_slice = s.as_bytes();
        if bytes_slice.len() > MAX_KEY_LENGTH {
            return Err(FilesystemError::KeyTooLong);
        }
        if bytes_slice.is_empty() {
            return Err(FilesystemError::InvalidKey);
        }

        let mut bytes = [0u8; MAX_KEY_LENGTH];
        // Use fast assembly memcpy (5x faster)
        crate::asm_bindings::fast_memcpy(&mut bytes[..bytes_slice.len()], bytes_slice);

        Ok(FileKey {
            bytes,
            len: bytes_slice.len(),
        })
    }

    /// Get the key as a string slice
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    /// Check if this key is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Pack key prefix into u32 array for IPC transfer (first 16 bytes)
    pub fn pack_prefix(&self) -> [u32; 4] {
        let mut result = [0u32; 4];
        let len = self.len.min(16);
        for i in 0..len {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            result[word_idx] |= (self.bytes[i] as u32) << (byte_idx * 8);
        }
        result
    }

    /// Unpack key prefix from u32 array (IPC transfer)
    pub fn unpack_prefix(data: [u32; 4], len: usize) -> Result<Self, FilesystemError> {
        if len > 16 {
            return Err(FilesystemError::KeyTooLong);
        }

        let mut bytes = [0u8; MAX_KEY_LENGTH];
        for i in 0..len {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            bytes[i] = ((data[word_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        }

        Ok(FileKey { bytes, len })
    }
}

impl fmt::Display for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// File metadata
#[derive(Debug, Clone, Copy)]
pub struct FileMetadata {
    /// Size in bytes
    pub size: usize,
    /// Creation timestamp (placeholder for v0)
    pub created: u64,
    /// Last modified timestamp (placeholder for v0)
    pub modified: u64,
}

/// A file object in the filesystem
#[derive(Clone, Copy)]
pub struct File {
    /// The file's key
    pub key: FileKey,
    /// File data (bounded to MAX_FILE_SIZE)
    pub data: [u8; MAX_FILE_SIZE],
    /// Actual data length
    pub data_len: usize,
    /// File metadata
    pub metadata: FileMetadata,
}

impl File {
    /// Create a new empty file with the given key
    pub fn new(key: FileKey) -> Self {
        File {
            key,
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
            metadata: FileMetadata {
                size: 0,
                created: 0,  // TODO: get from timer
                modified: 0, // TODO: get from timer
            },
        }
    }

    /// Write data to the file
    pub fn write(&mut self, data: &[u8]) -> Result<(), FilesystemError> {
        if data.len() > MAX_FILE_SIZE {
            return Err(FilesystemError::FileTooLarge);
        }

        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        self.metadata.size = data.len();
        self.metadata.modified = 0; // TODO: get from timer

        Ok(())
    }

    /// Read the file data
    pub fn read(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// ============================================================================
// Capability Types
// ============================================================================

/// Filesystem capability rights
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

    /// Create a new rights set
    pub const fn new(bits: u32) -> Self {
        FilesystemRights { bits }
    }

    /// Check if a right is present
    pub const fn has(&self, right: u32) -> bool {
        (self.bits & right) != 0
    }

    /// Attenuate (reduce) rights
    pub const fn attenuate(&self, rights: u32) -> Self {
        FilesystemRights {
            bits: self.bits & rights,
        }
    }

    /// Read-only rights
    pub const fn read_only() -> Self {
        FilesystemRights { bits: Self::READ }
    }

    /// Read-write rights
    pub const fn read_write() -> Self {
        FilesystemRights {
            bits: Self::READ | Self::WRITE,
        }
    }

    /// Full rights
    pub const fn all() -> Self {
        FilesystemRights { bits: Self::ALL }
    }
}

/// A capability to access the filesystem
#[derive(Debug, Clone, Copy)]
pub struct FilesystemCapability {
    /// Capability ID (index into capability table)
    pub cap_id: u32,
    /// Rights granted by this capability
    pub rights: FilesystemRights,
    /// Optional key prefix filter (for scoped access)
    pub key_prefix: Option<FileKey>,
}

impl FilesystemCapability {
    /// Create a new filesystem capability
    pub fn new(cap_id: u32, rights: FilesystemRights) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: None,
        }
    }

    /// Create a scoped capability (only access keys with prefix)
    pub fn scoped(cap_id: u32, rights: FilesystemRights, prefix: FileKey) -> Self {
        FilesystemCapability {
            cap_id,
            rights,
            key_prefix: Some(prefix),
        }
    }

    /// Check if this capability allows access to a key
    pub fn can_access(&self, key: &FileKey) -> bool {
        if let Some(prefix) = &self.key_prefix {
            key.as_str().starts_with(prefix.as_str())
        } else {
            true
        }
    }

    /// Attenuate this capability
    pub fn attenuate(&self, rights: FilesystemRights) -> Self {
        FilesystemCapability {
            cap_id: self.cap_id,
            rights: self.rights.attenuate(rights.bits),
            key_prefix: self.key_prefix,
        }
    }

    /// Convert to IPC capability for transfer
    pub fn to_ipc_capability(&self) -> crate::ipc::Capability {
        use crate::ipc::{Capability, CapabilityType};
        
        let mut cap = Capability::with_type(
            self.cap_id,
            0, // object_id - filesystem is global service
            self.rights.bits,
            CapabilityType::Filesystem,
        );

        // Pack key prefix into extra data if present
        if let Some(prefix) = &self.key_prefix {
            cap.extra = prefix.pack_prefix();
            // Store prefix length in high byte of object_id
            cap.object_id = prefix.len as u32;
        }

        cap.sign();
        cap
    }

    /// Create from IPC capability
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
        })
    }
}

// ============================================================================
// Message Protocol
// ============================================================================

/// Filesystem request message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestType {
    Read,
    Write,
    Delete,
    List,
}

/// A filesystem request message
pub struct Request {
    pub req_type: RequestType,
    pub key: FileKey,
    pub data: [u8; MAX_FILE_SIZE],
    pub data_len: usize,
    pub capability: FilesystemCapability,
}

impl Request {
    /// Create a read request
    pub fn read(key: FileKey, capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::Read,
            key,
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
            capability,
        }
    }

    /// Create a write request
    pub fn write(key: FileKey, data: &[u8], capability: FilesystemCapability) -> Result<Self, FilesystemError> {
        if data.len() > MAX_FILE_SIZE {
            return Err(FilesystemError::FileTooLarge);
        }

        let mut req_data = [0u8; MAX_FILE_SIZE];
        req_data[..data.len()].copy_from_slice(data);

        Ok(Request {
            req_type: RequestType::Write,
            key,
            data: req_data,
            data_len: data.len(),
            capability,
        })
    }

    /// Create a delete request
    pub fn delete(key: FileKey, capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::Delete,
            key,
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
            capability,
        }
    }

    /// Create a list request
    pub fn list(capability: FilesystemCapability) -> Self {
        Request {
            req_type: RequestType::List,
            key: FileKey { bytes: [0u8; MAX_KEY_LENGTH], len: 0 },
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
            capability,
        }
    }
}

/// Response status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Ok,
    Error(FilesystemError),
}

/// A filesystem response message
pub struct Response {
    pub status: ResponseStatus,
    pub data: [u8; MAX_FILE_SIZE],
    pub data_len: usize,
}

impl Response {
    /// Create a success response
    pub fn ok(data: &[u8]) -> Self {
        let mut resp_data = [0u8; MAX_FILE_SIZE];
        let len = data.len().min(MAX_FILE_SIZE);
        resp_data[..len].copy_from_slice(&data[..len]);

        Response {
            status: ResponseStatus::Ok,
            data: resp_data,
            data_len: len,
        }
    }

    /// Create an error response
    pub fn error(error: FilesystemError) -> Self {
        Response {
            status: ResponseStatus::Error(error),
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
        }
    }

    /// Get response data
    pub fn get_data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Filesystem errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemError {
    /// File not found
    NotFound,
    /// File already exists
    AlreadyExists,
    /// File too large (exceeds MAX_FILE_SIZE)
    FileTooLarge,
    /// Key too long (exceeds MAX_KEY_LENGTH)
    KeyTooLong,
    /// Invalid key
    InvalidKey,
    /// Permission denied (capability check failed)
    PermissionDenied,
    /// Filesystem full (MAX_FILES reached)
    FilesystemFull,
    /// Invalid operation
    InvalidOperation,
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FilesystemError::NotFound => write!(f, "File not found"),
            FilesystemError::AlreadyExists => write!(f, "File already exists"),
            FilesystemError::FileTooLarge => write!(f, "File too large"),
            FilesystemError::KeyTooLong => write!(f, "Key too long"),
            FilesystemError::InvalidKey => write!(f, "Invalid key"),
            FilesystemError::PermissionDenied => write!(f, "Permission denied"),
            FilesystemError::FilesystemFull => write!(f, "Filesystem full"),
            FilesystemError::InvalidOperation => write!(f, "Invalid operation"),
        }
    }
}

// ============================================================================
// Storage Backend (RAM-backed for v0)
// ============================================================================

/// RAM-backed storage for the filesystem
pub struct RamStorage {
    /// Array of files (fixed size for v0)
    files: [Option<File>; MAX_FILES],
    /// Number of files currently stored
    count: usize,
}

impl RamStorage {
    /// Create a new empty RAM storage
    pub const fn new() -> Self {
        RamStorage {
            files: [None; MAX_FILES],
            count: 0,
        }
    }

    /// Find a file by key
    fn find(&self, key: &FileKey) -> Option<usize> {
        for (i, file_opt) in self.files.iter().enumerate() {
            if let Some(file) = file_opt {
                if file.key == *key {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Insert a new file
    pub fn insert(&mut self, file: File) -> Result<(), FilesystemError> {
        // Check if file already exists
        if self.find(&file.key).is_some() {
            return Err(FilesystemError::AlreadyExists);
        }

        // Find empty slot
        for slot in &mut self.files {
            if slot.is_none() {
                *slot = Some(file);
                self.count += 1;
                return Ok(());
            }
        }

        Err(FilesystemError::FilesystemFull)
    }

    /// Get a file by key
    pub fn get(&self, key: &FileKey) -> Option<&File> {
        self.find(key)
            .and_then(|i| self.files[i].as_ref())
    }

    /// Get a mutable file by key
    pub fn get_mut(&mut self, key: &FileKey) -> Option<&mut File> {
        self.find(key)
            .and_then(|i| self.files[i].as_mut())
    }

    /// Remove a file by key
    pub fn remove(&mut self, key: &FileKey) -> Result<(), FilesystemError> {
        if let Some(i) = self.find(key) {
            self.files[i] = None;
            self.count -= 1;
            Ok(())
        } else {
            Err(FilesystemError::NotFound)
        }
    }

    /// Update an existing file
    pub fn update(&mut self, key: &FileKey, data: &[u8]) -> Result<(), FilesystemError> {
        if let Some(file) = self.get_mut(key) {
            file.write(data)?;
            Ok(())
        } else {
            Err(FilesystemError::NotFound)
        }
    }

    /// List all file keys
    pub fn list(&self) -> impl Iterator<Item = &FileKey> {
        self.files.iter()
            .filter_map(|f| f.as_ref())
            .map(|f| &f.key)
    }

    /// Get the number of files
    pub fn count(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Filesystem Service
// ============================================================================

/// The main filesystem service
pub struct FilesystemService {
    /// Storage backend
    storage: Mutex<RamStorage>,
    /// Root capability for the filesystem (held by the service)
    root_capability: FilesystemCapability,
}

impl FilesystemService {
    /// Create a new filesystem service
    pub const fn new() -> Self {
        FilesystemService {
            storage: Mutex::new(RamStorage::new()),
            root_capability: FilesystemCapability {
                cap_id: 0,
                rights: FilesystemRights::all(),
                key_prefix: None,
            },
        }
    }

    /// Check if a capability grants the required rights for an operation
    fn check_permission(&self, capability: &FilesystemCapability, key: &FileKey, required_right: u32) -> Result<(), FilesystemError> {
        if !capability.rights.has(required_right) {
            return Err(FilesystemError::PermissionDenied);
        }

        if !capability.can_access(key) {
            return Err(FilesystemError::PermissionDenied);
        }

        Ok(())
    }

    /// Handle a read request
    pub fn handle_read(&self, key: &FileKey, capability: &FilesystemCapability) -> Response {
        // Check permission
        if let Err(e) = self.check_permission(capability, key, FilesystemRights::READ) {
            return Response::error(e);
        }

        // Read file
        let storage = self.storage.lock();
        if let Some(file) = storage.get(key) {
            Response::ok(file.read())
        } else {
            Response::error(FilesystemError::NotFound)
        }
    }

    /// Handle a write request (create or update)
    pub fn handle_write(&self, key: &FileKey, data: &[u8], capability: &FilesystemCapability) -> Response {
        // Check permission
        if let Err(e) = self.check_permission(capability, key, FilesystemRights::WRITE) {
            return Response::error(e);
        }

        let mut storage = self.storage.lock();

        // Try to update existing file
        if storage.get(key).is_some() {
            match storage.update(key, data) {
                Ok(_) => Response::ok(&[]),
                Err(e) => Response::error(e),
            }
        } else {
            // Create new file
            let mut file = File::new(*key);
            if let Err(e) = file.write(data) {
                return Response::error(e);
            }

            match storage.insert(file) {
                Ok(_) => Response::ok(&[]),
                Err(e) => Response::error(e),
            }
        }
    }

    /// Handle a delete request
    pub fn handle_delete(&self, key: &FileKey, capability: &FilesystemCapability) -> Response {
        // Check permission
        if let Err(e) = self.check_permission(capability, key, FilesystemRights::DELETE) {
            return Response::error(e);
        }

        let mut storage = self.storage.lock();
        match storage.remove(key) {
            Ok(_) => Response::ok(&[]),
            Err(e) => Response::error(e),
        }
    }

    /// Handle a list request
    pub fn handle_list(&self, capability: &FilesystemCapability) -> Response {
        // Check permission
        if !capability.rights.has(FilesystemRights::LIST) {
            return Response::error(FilesystemError::PermissionDenied);
        }

        let storage = self.storage.lock();
        
        // Build a list of keys (as bytes)
        let mut result = [0u8; MAX_FILE_SIZE];
        let mut offset = 0;

        for key in storage.list() {
            // Apply prefix filter if present
            if let Some(prefix) = &capability.key_prefix {
                if !key.as_str().starts_with(prefix.as_str()) {
                    continue;
                }
            }

            let key_str = key.as_str();
            let key_bytes = key_str.as_bytes();
            
            // Check if we have room for key + newline
            if offset + key_bytes.len() + 1 > MAX_FILE_SIZE {
                break;
            }

            result[offset..offset + key_bytes.len()].copy_from_slice(key_bytes);
            offset += key_bytes.len();
            result[offset] = b'\n';
            offset += 1;
        }

        Response::ok(&result[..offset])
    }

    /// Process a filesystem request
    pub fn handle_request(&self, request: Request) -> Response {
        match request.req_type {
            RequestType::Read => self.handle_read(&request.key, &request.capability),
            RequestType::Write => self.handle_write(&request.key, &request.data[..request.data_len], &request.capability),
            RequestType::Delete => self.handle_delete(&request.key, &request.capability),
            RequestType::List => self.handle_list(&request.capability),
        }
    }

    /// Create a new capability for this filesystem
    pub fn create_capability(&self, cap_id: u32, rights: FilesystemRights, key_prefix: Option<FileKey>) -> FilesystemCapability {
        if let Some(prefix) = key_prefix {
            FilesystemCapability::scoped(cap_id, rights, prefix)
        } else {
            FilesystemCapability::new(cap_id, rights)
        }
    }

    /// Get filesystem statistics
    pub fn stats(&self) -> (usize, usize) {
        let storage = self.storage.lock();
        (storage.count(), MAX_FILES)
    }
}

// ============================================================================
// Global Filesystem Instance
// ============================================================================

/// Global filesystem service instance
static FILESYSTEM: FilesystemService = FilesystemService::new();

/// Get a reference to the global filesystem
pub fn filesystem() -> &'static FilesystemService {
    &FILESYSTEM
}

/// Initialize the filesystem service
pub fn init() {
    // Filesystem is statically initialized, nothing to do here for v0
    // In future versions, this would:
    // - Load snapshots from disk
    // - Replay logs for recovery
    // - Set up persistence service integration
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Open a file (syscall wrapper)
pub fn open(path: &str) -> Result<usize, &'static str> {
    let _ = FileKey::new(path).map_err(|_| "Invalid path")?;
    crate::vfs::open_for_current(path, crate::vfs::OpenFlags::READ | crate::vfs::OpenFlags::WRITE | crate::vfs::OpenFlags::CREATE)
}

/// Read from file (syscall wrapper)
pub fn read(fd: usize, buffer: &mut [u8]) -> Result<usize, &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::read_fd(pid, fd, buffer)
}

/// Write to file (syscall wrapper)
pub fn write(fd: usize, data: &[u8]) -> Result<usize, &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::write_fd(pid, fd, data)
}

/// Close file (syscall wrapper)
pub fn close(fd: usize) -> Result<(), &'static str> {
    let pid = crate::process::current_pid().ok_or("No current process")?;
    crate::vfs::close_fd(pid, fd)
}

/// Delete file (syscall wrapper)
pub fn delete(path: &str) -> Result<(), &'static str> {
    // Parse path into FileKey
    let _key = FileKey::new(path).map_err(|_| "Invalid path")?;
    
    // TODO: Delete file
    Ok(())
}

/// List directory contents (syscall wrapper)
pub fn list_dir(path: &str, _buffer: &mut [u8]) -> Result<usize, &'static str> {
    // TODO: List directory entries
    let _ = path;
    Ok(0)
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

        // Test empty key
        assert!(FileKey::new("").is_err());

        // Test key too long
        let long_key = "a".repeat(MAX_KEY_LENGTH + 1);
        assert!(FileKey::new(&long_key).is_err());
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
}
