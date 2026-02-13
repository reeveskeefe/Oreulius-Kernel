//! Oreulia Capability Security - Enhanced Authority Model
//!
//! This module implements Oreulia's capability-based security model as specified
//! in docs/oreulia-capabilities.md and docs/oreulia-vision.md
//!
//! Key principles:
//! - NO AMBIENT AUTHORITY: All access requires explicit capabilities
//! - UNFORGEABLE REFERENCES: Capabilities cannot be invented by tasks
//! - TRANSFERABLE: Capabilities can be sent over IPC channels
//! - ATTENUATABLE: Capabilities can be reduced to fewer rights
//! - AUDITABLE: All capability operations are tracked
//!
//! This differentiates Oreulia from POSIX/Unix/Linux/NT kernels which rely on:
//! - Global namespaces (filesystem paths, network ports)
//! - Ambient authority (current user, process groups)
//! - Discretionary access control (file permissions)

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
pub use crate::ipc::ProcessId;  // Re-export for syscall module
use crate::ipc::ChannelId;
use crate::security::{self, SecurityEvent, AuditEntry};

// ============================================================================
// Capability Types and Rights
// ============================================================================

/// Capability type taxonomy (aligned with oreulia-capabilities.md)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CapabilityType {
    // Kernel-level capabilities
    Channel = 0,
    Task = 1,
    Spawner = 2,
    
    // System service capabilities
    Console = 10,
    Clock = 11,
    Store = 12,
    Filesystem = 13,
    
    // Future: Network, Device, etc.
    Reserved = 255,
}

/// Rights bitflags for capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights {
    bits: u32,
}

impl Rights {
    // Channel rights
    pub const CHANNEL_SEND: u32 = 1 << 0;
    pub const CHANNEL_RECEIVE: u32 = 1 << 1;
    pub const CHANNEL_CLONE_SENDER: u32 = 1 << 2;
    pub const CHANNEL_CREATE: u32 = 1 << 3;
    
    // Task rights
    pub const TASK_SIGNAL: u32 = 1 << 4;
    pub const TASK_JOIN: u32 = 1 << 5;
    
    // Spawner rights
    pub const SPAWNER_SPAWN: u32 = 1 << 6;
    
    // Console rights
    pub const CONSOLE_WRITE: u32 = 1 << 7;
    pub const CONSOLE_READ: u32 = 1 << 8;
    
    // Clock rights
    pub const CLOCK_READ_MONOTONIC: u32 = 1 << 9;
    
    // Store rights
    pub const STORE_APPEND_LOG: u32 = 1 << 10;
    pub const STORE_READ_LOG: u32 = 1 << 11;
    pub const STORE_WRITE_SNAPSHOT: u32 = 1 << 12;
    pub const STORE_READ_SNAPSHOT: u32 = 1 << 13;
    
    // Filesystem rights
    pub const FS_READ: u32 = 1 << 14;
    pub const FS_WRITE: u32 = 1 << 15;
    pub const FS_DELETE: u32 = 1 << 16;
    pub const FS_LIST: u32 = 1 << 17;
    
    pub const NONE: u32 = 0;
    pub const ALL: u32 = 0xFFFFFFFF;
    
    pub const fn new(bits: u32) -> Self {
        Rights { bits }
    }
    
    pub const fn contains(&self, right: u32) -> bool {
        (self.bits & right) == right
    }
    
    pub const fn is_subset_of(&self, other: &Rights) -> bool {
        (self.bits & !other.bits) == 0
    }
    
    pub fn attenuate(&self, mask: u32) -> Self {
        Rights { bits: self.bits & mask }
    }
}

// ============================================================================
// Capability Structure
// ============================================================================

/// A capability grants authority to perform operations on an object
#[derive(Debug, Clone, Copy)]
pub struct OreuliaCapability {
    /// Capability ID (local to task)
    pub cap_id: u32,
    /// Kernel object ID (unforgeable)
    pub object_id: u64,
    /// Type of capability
    pub cap_type: CapabilityType,
    /// Rights bitset
    pub rights: Rights,
    /// Origin tracking (for auditing)
    pub origin: ProcessId,
    /// Grant timestamp (logical time)
    pub granted_at: u64,
    /// Optional label for debugging
    pub label_hash: u32,
}

impl OreuliaCapability {
    pub fn new(
        cap_id: u32,
        object_id: u64,
        cap_type: CapabilityType,
        rights: Rights,
        origin: ProcessId,
    ) -> Self {
        OreuliaCapability {
            cap_id,
            object_id,
            cap_type,
            rights,
            origin,
            granted_at: crate::pit::get_ticks() as u64,
            label_hash: 0,
        }
    }
    
    /// Attenuate capability to fewer rights (subset principle)
    pub fn attenuate(&self, new_rights: Rights) -> Result<Self, CapabilityError> {
        if !new_rights.is_subset_of(&self.rights) {
            return Err(CapabilityError::InvalidAttenuation);
        }
        
        let mut attenuated = *self;
        attenuated.rights = new_rights;
        Ok(attenuated)
    }
    
    /// Check if this capability grants a specific right
    pub fn has_right(&self, right: u32) -> bool {
        self.rights.contains(right)
    }
    
    /// Verify capability is valid for an operation
    pub fn verify(&self, required_type: CapabilityType, required_right: u32) -> Result<(), CapabilityError> {
        if self.cap_type != required_type {
            return Err(CapabilityError::TypeMismatch);
        }
        
        if !self.has_right(required_right) {
            return Err(CapabilityError::InsufficientRights);
        }
        
        Ok(())
    }
}

// ============================================================================
// Per-Task Capability Table
// ============================================================================

const MAX_CAPABILITIES: usize = 256;

/// Per-task capability table (unforgeable capability storage)
pub struct CapabilityTable {
    entries: [Option<OreuliaCapability>; MAX_CAPABILITIES],
    next_cap_id: u32,
    owner: ProcessId,
}

impl CapabilityTable {
    pub const fn new(owner: ProcessId) -> Self {
        CapabilityTable {
            entries: [None; MAX_CAPABILITIES],
            next_cap_id: 1, // 0 is reserved as invalid
            owner,
        }
    }
    
    /// Install a capability (creation or transfer)
    pub fn install(&mut self, cap: OreuliaCapability) -> Result<u32, CapabilityError> {
        // Find empty slot
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if entry.is_none() {
                let cap_id = idx as u32; // Simplified ID allocation
                let mut installed = cap;
                installed.cap_id = cap_id;
                *entry = Some(installed);
                
                // Audit capability installation
                security::security().log_event(
                    AuditEntry::new(SecurityEvent::CapabilityCreated, self.owner, cap_id)
                        .with_context(cap.object_id)
                );
                
                return Ok(cap_id);
            }
        }
        
        Err(CapabilityError::TableFull)
    }
    
    /// Lookup capability by cap_id
    pub fn lookup(&self, cap_id: u32) -> Result<&OreuliaCapability, CapabilityError> {
        self.entries
            .iter()
            .find(|e| e.as_ref().map_or(false, |c| c.cap_id == cap_id))
            .and_then(|e| e.as_ref())
            .ok_or(CapabilityError::InvalidCapability)
    }
    
    /// Remove capability (for transfer or revocation)
    pub fn remove(&mut self, cap_id: u32) -> Result<OreuliaCapability, CapabilityError> {
        for entry in self.entries.iter_mut() {
            if let Some(cap) = entry {
                if cap.cap_id == cap_id {
                    let removed = *cap;
                    *entry = None;
                    
                    // Audit capability removal
                    security::security().log_event(
                        AuditEntry::new(SecurityEvent::CapabilityRevoked, self.owner, cap_id)
                    );
                    
                    return Ok(removed);
                }
            }
        }
        
        Err(CapabilityError::InvalidCapability)
    }
    
    /// Attenuate an existing capability
    pub fn attenuate(&mut self, cap_id: u32, new_rights: Rights) -> Result<u32, CapabilityError> {
        let original = self.lookup(cap_id)?;
        let attenuated = original.attenuate(new_rights)?;
        
        self.install(attenuated)
    }
    
    /// Count capabilities by type
    pub fn count_by_type(&self, cap_type: CapabilityType) -> usize {
        self.entries
            .iter()
            .filter(|e| e.as_ref().map_or(false, |c| c.cap_type == cap_type))
            .count()
    }
    
    /// Get all capabilities (for auditing)
    pub fn list_all(&self) -> impl Iterator<Item = &OreuliaCapability> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }
    
    /// Create channel capability from ChannelId
    pub fn create_channel_capability(&mut self, channel: ChannelId, rights: Rights, origin: ProcessId) -> Result<u32, CapabilityError> {
        let cap = OreuliaCapability::new(
            0,
            channel.0 as u64, // Use channel ID as object ID
            CapabilityType::Channel,
            rights,
            origin,
        );
        self.install(cap)
    }
}

// ============================================================================
// Capability Manager (Global)
// ============================================================================

const MAX_TASKS: usize = 64;

/// Global capability manager
#[repr(align(64))]
pub struct CapabilityManager {
    tables: Mutex<[Option<alloc::boxed::Box<CapabilityTable>>; MAX_TASKS]>,
    next_object_id: Mutex<u64>,
}

impl CapabilityManager {
    pub const fn new() -> Self {
        CapabilityManager {
            tables: Mutex::new([None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None,
                               None, None, None, None, None, None, None, None]),
            next_object_id: Mutex::new(1),
        }
    }
    
    /// Initialize capability table for a task
    pub fn init_task(&self, pid: ProcessId) {
        let mut tables = self.tables.lock();
        if (pid.0 as usize) < MAX_TASKS {
            tables[pid.0 as usize] = Some(alloc::boxed::Box::new(CapabilityTable::new(pid)));
        }
    }
    
    /// Create a new object and return its ID
    pub fn create_object(&self) -> u64 {
        let mut next = self.next_object_id.lock();
        let id = *next;
        *next += 1;
        id
    }
    
    /// Grant a capability to a task
    pub fn grant_capability(
        &self,
        pid: ProcessId,
        object_id: u64,
        cap_type: CapabilityType,
        rights: Rights,
        origin: ProcessId,
    ) -> Result<u32, CapabilityError> {
        let mut tables = self.tables.lock();
        
        if let Some(table) = tables[pid.0 as usize].as_mut() {
            let cap = OreuliaCapability::new(0, object_id, cap_type, rights, origin);
            table.install(cap)
        } else {
            Err(CapabilityError::TaskNotFound)
        }
    }
    
    /// Transfer capability from one task to another
    pub fn transfer_capability(
        &self,
        from_pid: ProcessId,
        to_pid: ProcessId,
        cap_id: u32,
    ) -> Result<u32, CapabilityError> {
        let mut tables = self.tables.lock();
        
        // Remove from source
        let cap = if let Some(from_table) = tables[from_pid.0 as usize].as_mut() {
            from_table.remove(cap_id)?
        } else {
            return Err(CapabilityError::TaskNotFound);
        };
        
        // Install in destination
        if let Some(to_table) = tables[to_pid.0 as usize].as_mut() {
            let new_cap_id = to_table.install(cap)?;
            
            // Audit transfer
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityTransferred, from_pid, cap_id)
                    .with_context(to_pid.0 as u64)
            );
            
            Ok(new_cap_id)
        } else {
            Err(CapabilityError::TaskNotFound)
        }
    }
    
    /// Verify capability and return object ID if valid
    pub fn verify_and_get_object(
        &self,
        pid: ProcessId,
        cap_id: u32,
        required_type: CapabilityType,
        required_right: u32,
    ) -> Result<u64, CapabilityError> {
        let tables = self.tables.lock();
        
        if let Some(table) = tables[pid.0 as usize].as_ref() {
            let cap = table.lookup(cap_id)?;
            cap.verify(required_type, required_right)?;
            
            // Audit capability use
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityUsed, pid, cap_id)
                    .with_context(cap.object_id)
            );
            
            Ok(cap.object_id)
        } else {
            Err(CapabilityError::TaskNotFound)
        }
    }
    
    /// Attenuate a capability
    pub fn attenuate_capability(
        &self,
        pid: ProcessId,
        cap_id: u32,
        new_rights: Rights,
    ) -> Result<u32, CapabilityError> {
        let mut tables = self.tables.lock();
        
        if let Some(table) = tables[pid.0 as usize].as_mut() {
            table.attenuate(cap_id, new_rights)
        } else {
            Err(CapabilityError::TaskNotFound)
        }
    }
    
    /// Get capability statistics for auditing
    pub fn get_statistics(&self, pid: ProcessId) -> (usize, usize, usize) {
        let tables = self.tables.lock();
        
        if let Some(table) = tables[pid.0 as usize].as_ref() {
            let total = table.list_all().count();
            let channels = table.count_by_type(CapabilityType::Channel);
            let services = table.count_by_type(CapabilityType::Console) 
                + table.count_by_type(CapabilityType::Clock)
                + table.count_by_type(CapabilityType::Store)
                + table.count_by_type(CapabilityType::Filesystem);
            
            (total, channels, services)
        } else {
            (0, 0, 0)
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidCapability,
    InsufficientRights,
    TypeMismatch,
    InvalidAttenuation,
    TableFull,
    TaskNotFound,
}

impl CapabilityError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityError::InvalidCapability => "Invalid capability",
            CapabilityError::InsufficientRights => "Insufficient rights",
            CapabilityError::TypeMismatch => "Capability type mismatch",
            CapabilityError::InvalidAttenuation => "Invalid attenuation (not a subset)",
            CapabilityError::TableFull => "Capability table full",
            CapabilityError::TaskNotFound => "Task not found",
        }
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static CAPABILITY_MANAGER: CapabilityManager = CapabilityManager::new();

pub fn capability_manager() -> &'static CapabilityManager {
    &CAPABILITY_MANAGER
}

pub fn init() {
    // Initialize capability manager (already done via static initialization)
    // Create initial capabilities for kernel process
    let kernel_pid = ProcessId::new(0);
    CAPABILITY_MANAGER.init_task(kernel_pid);
}

/// Check if a process has a specific capability (syscall helper)
pub fn check_capability(
    pid: ProcessId,
    object_id: u64,
    cap_type: CapabilityType,
    required_rights: Rights,
) -> bool {
    // Allow all operations from kernel (PID 0)
    if pid.0 == 0 {
        return true;
    }
    
    // Rate limit check via SecurityManager
    if security::security().validate_capability(pid, required_rights.bits, required_rights.bits).is_err() {
        return false;
    }
    
    // Look up capability in process capability table
    let tables = CAPABILITY_MANAGER.tables.lock();
    
    if let Some(table) = tables[pid.0 as usize].as_ref() {
        // Iterate through all capabilities to find matching one
        for entry in &table.entries {
            if let Some(cap) = entry {
                // Check capability type matches
                if cap.cap_type != cap_type {
                    continue;
                }
                
                // Check object_id matches (or is wildcard 0 for non-object-specific capabilities)
                if object_id != 0 && cap.object_id != 0 && cap.object_id != object_id {
                    continue;
                }
                
                // Check if capability has required rights
                if !cap.rights.is_subset_of(&Rights::new(cap.rights.bits | required_rights.bits)) {
                    continue;
                }
                
                if cap.has_right(required_rights.bits) {
                    // Audit successful capability use
                    security::security().log_event(
                        AuditEntry::new(SecurityEvent::CapabilityUsed, pid, cap.cap_id)
                            .with_context(cap.object_id)
                    );
                    return true;
                }
            }
        }
    }
    
    // No matching capability found
    false
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Revoke a capability (syscall wrapper)
impl CapabilityManager {
    pub fn revoke_capability(&self, _pid: ProcessId, _cap_id: u32) -> Result<(), &'static str> {
        // TODO: Implement capability revocation via capability table
        // For now, just return success
        Ok(())
    }
    
    /// Query capability information (syscall wrapper)
    pub fn query_capability(&self, _pid: ProcessId, _cap_id: u32) -> Result<(u32, u64), &'static str> {
        // TODO: Look up capability and return (type, object_id)
        // For now, just return dummy data
        Ok((0, 0))
    }
}
