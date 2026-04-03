/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Oreulius Capability Security - Enhanced Authority Model
//!
//! This module implements Oreulius's capability-based security model as specified
//! in docs/capability/oreulius-capabilities.md and docs/project/oreulius-vision.md
//!
//! Key principles:
//! - NO AMBIENT AUTHORITY: All access requires explicit capabilities
//! - UNFORGEABLE REFERENCES: Capabilities cannot be invented by tasks
//! - TRANSFERABLE: Capabilities can be sent over IPC channels
//! - ATTENUATABLE: Capabilities can be reduced to fewer rights
//! - AUDITABLE: All capability operations are tracked
//!
//! This differentiates Oreulius from POSIX/Unix/Linux/NT kernels which rely on:
//! - Global namespaces (filesystem paths, network ports)
//! - Ambient authority (current user, process groups)
//! - Discretionary access control (file permissions)

#![allow(dead_code)]

pub mod cap_graph;

pub use crate::ipc::ProcessId; // Re-export for syscall module
use crate::ipc::{ChannelCapability, ChannelId, ChannelRights};
use crate::security::{self, AuditEntry, SecurityEvent};
use core::fmt;
use spin::Mutex;

// ============================================================================
// Capability Types and Rights
// ============================================================================

/// Capability type taxonomy (aligned with oreulius-capabilities.md)
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
    ServicePointer = 14,
    /// Cross-language polyglot service link capability.
    /// Issued by `polyglot_link` (host syscall 105); carries audit metadata
    /// about the source and destination language tags.
    CrossLanguage = 15,

    // Future: Network, Device, etc.
    Reserved = 255,
}

impl CapabilityType {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(CapabilityType::Channel),
            1 => Some(CapabilityType::Task),
            2 => Some(CapabilityType::Spawner),
            10 => Some(CapabilityType::Console),
            11 => Some(CapabilityType::Clock),
            12 => Some(CapabilityType::Store),
            13 => Some(CapabilityType::Filesystem),
            14 => Some(CapabilityType::ServicePointer),
            15 => Some(CapabilityType::CrossLanguage),
            _ => None,
        }
    }
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

    // Service-pointer rights
    pub const SERVICE_INVOKE: u32 = 1 << 18;
    pub const SERVICE_DELEGATE: u32 = 1 << 19;
    pub const SERVICE_INTROSPECT: u32 = 1 << 20;

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
        Rights {
            bits: self.bits & mask,
        }
    }

    pub const fn bits(&self) -> u32 {
        self.bits
    }
}

// ============================================================================
// Capability Structure
// ============================================================================

/// A capability grants authority to perform operations on an object
#[derive(Debug, Clone, Copy)]
pub struct OreuliusCapability {
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
    /// Cryptographic token (SipHash-2-4 MAC)
    pub token: u64,
    /// Provenance: the cap_id of the capability this was delegated/derived from
    /// (Def A.28 provenance chain).  `None` for root capabilities created
    /// directly by the kernel.  Used by `cap_graph::build_chain` to walk the
    /// full ancestry of a capability token.
    pub parent_cap_id: Option<u32>,
}

impl OreuliusCapability {
    pub fn new(
        cap_id: u32,
        object_id: u64,
        cap_type: CapabilityType,
        rights: Rights,
        origin: ProcessId,
    ) -> Self {
        OreuliusCapability {
            cap_id,
            object_id,
            cap_type,
            rights,
            origin,
            granted_at: crate::pit::get_ticks() as u64,
            label_hash: 0,
            token: 0,
            parent_cap_id: None,
        }
    }

    /// Attenuate capability to fewer rights (subset principle)
    pub fn attenuate(&self, new_rights: Rights) -> Result<Self, CapabilityError> {
        if !new_rights.is_subset_of(&self.rights) {
            return Err(CapabilityError::InvalidAttenuation);
        }

        let mut attenuated = *self;
        attenuated.rights = new_rights;
        // Record provenance: the attenuated cap derives from this one.
        attenuated.parent_cap_id = Some(self.cap_id);
        Ok(attenuated)
    }

    /// Check if this capability grants a specific right
    pub fn has_right(&self, right: u32) -> bool {
        self.rights.contains(right)
    }

    /// Verify capability is valid for an operation
    pub fn verify(
        &self,
        required_type: CapabilityType,
        required_right: u32,
    ) -> Result<(), CapabilityError> {
        if self.cap_type != required_type {
            return Err(CapabilityError::TypeMismatch);
        }

        if !self.has_right(required_right) {
            return Err(CapabilityError::InsufficientRights);
        }

        Ok(())
    }

    pub fn sign(&mut self, owner: ProcessId) {
        let payload = self.token_payload(owner);
        self.token = security::security().cap_token_sign(&payload);
    }

    /// Create a `CrossLanguage` capability for a polyglot service link.
    /// The `object_id` identifies the target `ServicePointer` entry;
    /// `lang_tag` is the destination language (stored in `label_hash`
    /// lower byte for cheap audit reads without deserializing).
    #[cfg(not(target_arch = "aarch64"))]
    pub fn new_polyglot_link(
        origin: ProcessId,
        object_id: u64,
        lang_tag: crate::wasm::LanguageTag,
    ) -> Self {
        let mut cap = OreuliusCapability::new(
            0,
            object_id,
            CapabilityType::CrossLanguage,
            Rights {
                bits: Rights::SERVICE_INVOKE,
            },
            origin,
        );
        cap.label_hash = lang_tag as u32;
        cap.sign(origin);
        cap
    }

    pub fn verify_token(&self, owner: ProcessId) -> bool {
        let payload = self.token_payload(owner);
        security::security().cap_token_verify(&payload, self.token)
    }

    fn token_payload(&self, owner: ProcessId) -> [u8; 48] {
        const TOKEN_CONTEXT: u32 = 0x4B43_4150; // "KCAP"
        let mut buf = [0u8; 48];
        let mut offset = 0usize;
        write_u32(&mut buf, &mut offset, TOKEN_CONTEXT);
        write_u32(&mut buf, &mut offset, owner.0);
        write_u32(&mut buf, &mut offset, self.cap_id);
        write_u64(&mut buf, &mut offset, self.object_id);
        write_u32(&mut buf, &mut offset, self.cap_type as u32);
        write_u32(&mut buf, &mut offset, self.rights.bits);
        write_u32(&mut buf, &mut offset, self.origin.0);
        write_u64(&mut buf, &mut offset, self.granted_at);
        write_u32(&mut buf, &mut offset, self.label_hash);
        write_u32(&mut buf, &mut offset, 0);
        buf
    }
}

#[derive(Clone, Copy)]
struct CapabilityAccessRequest {
    object_id: u64,
    required_type: CapabilityType,
    required_right: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoteLeaseDecision {
    NotMapped,
    Allow,
    Deny,
}

fn verify_capability_access(
    owner: ProcessId,
    cap: &OreuliusCapability,
    req: CapabilityAccessRequest,
) -> Result<(), CapabilityError> {
    if !cap.verify_token(owner) {
        return Err(CapabilityError::InvalidCapability);
    }
    if cap.cap_type != req.required_type {
        return Err(CapabilityError::TypeMismatch);
    }
    if req.object_id != 0 && cap.object_id != 0 && cap.object_id != req.object_id {
        return Err(CapabilityError::InvalidCapability);
    }
    if !cap.has_right(req.required_right) {
        return Err(CapabilityError::InsufficientRights);
    }
    Ok(())
}

fn check_remote_capability_access(
    pid: ProcessId,
    object_id: u64,
    required_type: CapabilityType,
    required_rights: Rights,
) -> bool {
    let now = crate::pit::get_ticks() as u64;
    let mut leases = CAPABILITY_MANAGER.remote_leases.lock();

    for entry in leases.iter_mut() {
        if let Some(lease) = entry.as_mut() {
            if !lease.active || lease.revoked {
                continue;
            }
            // Owner-bound leases should be enforced through mapped local table entries.
            if lease.mapped_cap_id != 0 {
                continue;
            }
            if !lease.owner_any && lease.owner_pid != pid {
                continue;
            }
            if lease.cap_type != required_type {
                continue;
            }
            if object_id != 0 && lease.object_id != 0 && lease.object_id != object_id {
                continue;
            }
            if now < lease.not_before || now > lease.expires_at {
                lease.active = false;
                lease.revoked = true;
                lease.mapped_cap_id = 0;
                continue;
            }
            if !lease.rights.contains(required_rights.bits) {
                continue;
            }
            if lease.enforce_use_budget {
                if lease.uses_remaining == 0 {
                    continue;
                }
                lease.uses_remaining = lease.uses_remaining.saturating_sub(1);
            }

            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityUsed, pid, lease.mapped_cap_id)
                    .with_context(lease.object_id),
            );
            return true;
        }
    }

    false
}

fn evaluate_mapped_remote_capability(
    pid: ProcessId,
    mapped_cap_id: u32,
    object_id: u64,
    required_type: CapabilityType,
    required_rights: Rights,
) -> RemoteLeaseDecision {
    let now = crate::pit::get_ticks() as u64;
    let mut leases = CAPABILITY_MANAGER.remote_leases.lock();

    for entry in leases.iter_mut() {
        let lease = match entry.as_mut() {
            Some(lease) => lease,
            None => continue,
        };
        if lease.mapped_cap_id != mapped_cap_id {
            continue;
        }
        if !lease.owner_any && lease.owner_pid != pid {
            continue;
        }
        if !lease.active || lease.revoked {
            return RemoteLeaseDecision::Deny;
        }
        if lease.cap_type != required_type {
            return RemoteLeaseDecision::Deny;
        }
        if object_id != 0 && lease.object_id != 0 && lease.object_id != object_id {
            return RemoteLeaseDecision::Deny;
        }
        if now < lease.not_before || now > lease.expires_at {
            lease.active = false;
            lease.revoked = true;
            lease.mapped_cap_id = 0;
            return RemoteLeaseDecision::Deny;
        }
        if !lease.rights.contains(required_rights.bits) {
            return RemoteLeaseDecision::Deny;
        }
        if lease.enforce_use_budget {
            if lease.uses_remaining == 0 {
                return RemoteLeaseDecision::Deny;
            }
            lease.uses_remaining = lease.uses_remaining.saturating_sub(1);
        }

        security::security().log_event(
            AuditEntry::new(SecurityEvent::CapabilityUsed, pid, mapped_cap_id)
                .with_context(lease.object_id),
        );
        return RemoteLeaseDecision::Allow;
    }

    RemoteLeaseDecision::NotMapped
}

fn write_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 4].copy_from_slice(&bytes);
    *offset += 4;
}

fn write_u64(buf: &mut [u8], offset: &mut usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 8].copy_from_slice(&bytes);
    *offset += 8;
}

// ============================================================================
// Per-Task Capability Table
// ============================================================================

const MAX_CAPABILITIES: usize = 256;
const MAX_REMOTE_LEASES: usize = 128;
const MAX_QUARANTINED_CAPS: usize = 256;

/// Remote capability lease created from a validated CapNet token.
#[derive(Debug, Clone, Copy)]
pub struct RemoteCapabilityLease {
    pub active: bool,
    pub token_id: u64,
    pub mapped_cap_id: u32,
    pub owner_pid: ProcessId,
    pub owner_any: bool,
    pub issuer_device_id: u64,
    pub measurement_hash: u64,
    pub session_id: u32,
    pub object_id: u64,
    pub cap_type: CapabilityType,
    pub rights: Rights,
    pub not_before: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub enforce_use_budget: bool,
    pub uses_remaining: u16,
}

impl RemoteCapabilityLease {
    const fn empty() -> Self {
        RemoteCapabilityLease {
            active: false,
            token_id: 0,
            mapped_cap_id: 0,
            owner_pid: ProcessId(0),
            owner_any: false,
            issuer_device_id: 0,
            measurement_hash: 0,
            session_id: 0,
            object_id: 0,
            cap_type: CapabilityType::Reserved,
            rights: Rights::new(Rights::NONE),
            not_before: 0,
            expires_at: 0,
            revoked: false,
            enforce_use_budget: false,
            uses_remaining: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct QuarantinedCapability {
    owner_pid: ProcessId,
    cap: OreuliusCapability,
    restore_at_tick: u64,
}

/// Per-task capability table (unforgeable capability storage)
pub struct CapabilityTable {
    entries: [Option<OreuliusCapability>; MAX_CAPABILITIES],
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

    #[inline]
    const fn cap_id_to_index(cap_id: u32) -> Result<usize, CapabilityError> {
        if cap_id == 0 {
            return Err(CapabilityError::InvalidCapability);
        }
        let idx = cap_id as usize;
        if idx >= MAX_CAPABILITIES {
            return Err(CapabilityError::InvalidCapability);
        }
        Ok(idx)
    }

    #[inline]
    const fn next_search_start_from(cap_id: u32) -> u32 {
        if cap_id == 0 || cap_id as usize >= MAX_CAPABILITIES - 1 {
            1
        } else {
            cap_id + 1
        }
    }

    fn alloc_slot(&mut self) -> Result<u32, CapabilityError> {
        let start = if self.next_cap_id == 0 || self.next_cap_id as usize >= MAX_CAPABILITIES {
            1
        } else {
            self.next_cap_id
        };

        let mut cap_id = start;
        let mut scanned = 0usize;
        while scanned < (MAX_CAPABILITIES - 1) {
            let idx = cap_id as usize;
            if self.entries[idx].is_none() {
                self.next_cap_id = Self::next_search_start_from(cap_id);
                return Ok(cap_id);
            }

            cap_id = Self::next_search_start_from(cap_id);
            scanned += 1;
        }

        Err(CapabilityError::TableFull)
    }

    fn store_installed_at(
        &mut self,
        cap_id: u32,
        cap: OreuliusCapability,
    ) -> Result<u32, CapabilityError> {
        let idx = Self::cap_id_to_index(cap_id)?;
        let mut installed = cap;
        installed.cap_id = cap_id;
        installed.granted_at = crate::pit::get_ticks() as u64;
        installed.sign(self.owner);
        self.entries[idx] = Some(installed);

        security::security().log_event(
            AuditEntry::new(SecurityEvent::CapabilityCreated, self.owner, cap_id)
                .with_context(installed.object_id),
        );

        Ok(cap_id)
    }

    /// Install a capability (creation or transfer)
    pub fn install(&mut self, cap: OreuliusCapability) -> Result<u32, CapabilityError> {
        let cap_id = self.alloc_slot()?;
        self.store_installed_at(cap_id, cap)
    }

    /// Install a capability at a fixed cap_id, replacing any existing entry.
    /// Used for mapped remote leases so lease ID and table slot stay aligned.
    pub fn install_or_replace(
        &mut self,
        preferred_cap_id: Option<u32>,
        cap: OreuliusCapability,
    ) -> Result<u32, CapabilityError> {
        if let Some(cap_id) = preferred_cap_id {
            if Self::cap_id_to_index(cap_id).is_ok() {
                self.next_cap_id = Self::next_search_start_from(cap_id);
                return self.store_installed_at(cap_id, cap);
            }
        }
        self.install(cap)
    }

    /// Lookup capability by cap_id
    pub fn lookup(&self, cap_id: u32) -> Result<&OreuliusCapability, CapabilityError> {
        let idx = Self::cap_id_to_index(cap_id)?;
        if let Some(cap) = self.entries[idx].as_ref() {
            if cap.cap_id != cap_id || !cap.verify_token(self.owner) {
                security::security().log_event(AuditEntry::new(
                    SecurityEvent::InvalidCapability,
                    self.owner,
                    cap_id,
                ));
                return Err(CapabilityError::InvalidCapability);
            }
            return Ok(cap);
        }
        Err(CapabilityError::InvalidCapability)
    }

    /// Remove capability (for transfer or revocation)
    pub fn remove(&mut self, cap_id: u32) -> Result<OreuliusCapability, CapabilityError> {
        let idx = Self::cap_id_to_index(cap_id)?;
        if let Some(cap) = self.entries[idx] {
            if cap.cap_id != cap_id || !cap.verify_token(self.owner) {
                security::security().log_event(AuditEntry::new(
                    SecurityEvent::InvalidCapability,
                    self.owner,
                    cap_id,
                ));
                return Err(CapabilityError::InvalidCapability);
            }

            self.entries[idx] = None;
            self.next_cap_id = cap_id;

            security::security().log_event(AuditEntry::new(
                SecurityEvent::CapabilityRevoked,
                self.owner,
                cap_id,
            ));

            return Ok(cap);
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
    pub fn list_all(&self) -> impl Iterator<Item = &OreuliusCapability> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }

    /// Create channel capability from ChannelId
    pub fn create_channel_capability(
        &mut self,
        channel: ChannelId,
        rights: Rights,
        origin: ProcessId,
    ) -> Result<u32, CapabilityError> {
        let cap = OreuliusCapability::new(
            0,
            channel.0 as u64, // Use channel ID as object ID
            CapabilityType::Channel,
            rights,
            origin,
        );
        self.install(cap)
    }

    /// Revoke all capabilities matching type and rights mask.
    ///
    /// `rights_mask == 0` means revoke all capabilities of `cap_type`.
    pub fn revoke_matching(&mut self, cap_type: CapabilityType, rights_mask: u32) -> usize {
        let mut revoke_ids = [0u32; MAX_CAPABILITIES];
        let mut revoke_count = 0usize;

        for entry in self.entries.iter() {
            let cap = match entry {
                Some(cap) => cap,
                None => continue,
            };
            if cap.cap_type != cap_type {
                continue;
            }
            if rights_mask != 0 && (cap.rights.bits & rights_mask) == 0 {
                continue;
            }
            if revoke_count < revoke_ids.len() {
                revoke_ids[revoke_count] = cap.cap_id;
                revoke_count += 1;
            }
        }

        let mut revoked = 0usize;
        let mut i = 0usize;
        while i < revoke_count {
            if self.remove(revoke_ids[i]).is_ok() {
                revoked += 1;
            }
            i += 1;
        }
        revoked
    }

    /// Revoke every capability in the table.
    pub fn revoke_all(&mut self) -> usize {
        let mut revoke_ids = [0u32; MAX_CAPABILITIES];
        let mut revoke_count = 0usize;

        for entry in self.entries.iter() {
            if let Some(cap) = entry {
                if revoke_count < revoke_ids.len() {
                    revoke_ids[revoke_count] = cap.cap_id;
                    revoke_count += 1;
                }
            }
        }

        let mut revoked = 0usize;
        let mut i = 0usize;
        while i < revoke_count {
            if self.remove(revoke_ids[i]).is_ok() {
                revoked += 1;
            }
            i += 1;
        }
        revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cap(object_id: u64) -> OreuliusCapability {
        OreuliusCapability::new(
            0,
            object_id,
            CapabilityType::Channel,
            Rights::new(Rights::CHANNEL_SEND),
            ProcessId::new(1),
        )
    }

    #[test]
    fn capability_table_never_allocates_cap_id_zero() {
        let mut table = CapabilityTable::new(ProcessId::new(1));
        let cap_id = table.install(test_cap(0x10)).unwrap();
        assert_eq!(cap_id, 1);
    }

    #[test]
    fn capability_table_lookup_and_remove_are_slot_indexed() {
        let mut table = CapabilityTable::new(ProcessId::new(2));
        let cap_id = table.install(test_cap(0x20)).unwrap();
        let looked_up = table.lookup(cap_id).unwrap();
        assert_eq!(looked_up.cap_id, cap_id);
        assert_eq!(looked_up.object_id, 0x20);

        let removed = table.remove(cap_id).unwrap();
        assert_eq!(removed.cap_id, cap_id);
        assert!(matches!(
            table.lookup(cap_id),
            Err(CapabilityError::InvalidCapability)
        ));
    }

    #[test]
    fn capability_table_reuses_freed_slot_after_removal() {
        let mut table = CapabilityTable::new(ProcessId::new(3));
        let first = table.install(test_cap(0x30)).unwrap();
        let second = table.install(test_cap(0x31)).unwrap();
        assert_eq!(first, 1);
        assert_eq!(second, 2);

        let _ = table.remove(first).unwrap();
        let reused = table.install(test_cap(0x32)).unwrap();
        assert_eq!(reused, first);
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
    remote_leases: Mutex<[Option<RemoteCapabilityLease>; MAX_REMOTE_LEASES]>,
    quarantined_caps: Mutex<[Option<QuarantinedCapability>; MAX_QUARANTINED_CAPS]>,
    next_remote_cap_id: Mutex<u32>,
}

impl CapabilityManager {
    pub const fn new() -> Self {
        CapabilityManager {
            tables: Mutex::new([
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ]),
            next_object_id: Mutex::new(1),
            remote_leases: Mutex::new([None; MAX_REMOTE_LEASES]),
            quarantined_caps: Mutex::new([None; MAX_QUARANTINED_CAPS]),
            next_remote_cap_id: Mutex::new(1),
        }
    }

    /// Initialize capability table for a task
    pub fn init_task(&self, pid: ProcessId) {
        let mut tables = self.tables.lock();
        if (pid.0 as usize) < MAX_TASKS {
            tables[pid.0 as usize] = Some(alloc::boxed::Box::new(CapabilityTable::new(pid)));
        }
    }

    /// Clone a task capability table into a new owner PID, re-signing each
    /// capability token for the child task while preserving the slot layout.
    pub fn clone_task_capabilities(
        &self,
        parent_pid: ProcessId,
        child_pid: ProcessId,
    ) -> Result<usize, &'static str> {
        let parent_idx = parent_pid.0 as usize;
        let child_idx = child_pid.0 as usize;
        if parent_idx >= MAX_TASKS || child_idx >= MAX_TASKS {
            return Err("Task not found");
        }

        let mut tables = self.tables.lock();
        let parent_table = tables[parent_idx].as_ref().ok_or("Task not found")?;
        let mut child_table = CapabilityTable::new(child_pid);
        let mut cloned = 0usize;

        let mut idx = 0usize;
        while idx < parent_table.entries.len() {
            if let Some(mut cap) = parent_table.entries[idx] {
                cap.sign(child_pid);
                child_table.entries[idx] = Some(cap);
                cloned = cloned.saturating_add(1);
            }
            idx += 1;
        }

        tables[child_idx] = Some(alloc::boxed::Box::new(child_table));
        Ok(cloned)
    }

    /// Tear down capability state for a task and revoke owner-bound remote leases.
    pub fn deinit_task(&self, pid: ProcessId) {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return;
        }

        let mut tables = self.tables.lock();
        if let Some(table) = tables[idx].as_mut() {
            let revoked_local = table.revoke_all();
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityRevoked, pid, 0)
                    .with_context(revoked_local as u64),
            );
        }
        tables[idx] = None;

        let mut quarantined = self.quarantined_caps.lock();
        for entry in quarantined.iter_mut() {
            let remove = match entry.as_ref() {
                Some(cap) => cap.owner_pid == pid,
                None => false,
            };
            if remove {
                *entry = None;
            }
        }

        let mut leases = self.remote_leases.lock();
        for entry in leases.iter_mut() {
            let remove = match entry.as_ref() {
                Some(lease) => !lease.owner_any && lease.owner_pid == pid,
                None => false,
            };
            if !remove {
                continue;
            }
            let token_id = match entry.as_ref() {
                Some(lease) => lease.token_id,
                None => 0,
            };
            *entry = None;
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityRevoked, pid, 0).with_context(token_id),
            );
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
            let cap = OreuliusCapability::new(0, object_id, cap_type, rights, origin);
            let cap_id = table.install(cap)?;
            if !crate::temporal::is_replay_active() {
                let _ = crate::temporal::record_capability_event(
                    pid.0,
                    cap_type as u8,
                    object_id,
                    rights.bits(),
                    origin.0,
                    crate::temporal::TEMPORAL_CAPABILITY_EVENT_GRANT,
                    cap_id,
                );
            }
            // Notify kernel observers about the capability grant.
            #[cfg(not(target_arch = "aarch64"))]
            let payload = [
                pid.0.to_le_bytes()[0],
                pid.0.to_le_bytes()[1],
                pid.0.to_le_bytes()[2],
                pid.0.to_le_bytes()[3],
                cap_type as u8,
                0,
                0,
                0,
            ];
            #[cfg(not(target_arch = "aarch64"))]
            crate::wasm::observer_notify(crate::wasm::observer_events::CAPABILITY_OP, &payload);
            Ok(cap_id)
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

        // Capability graph: check invariants before completing the transfer.
        self::cap_graph::check_invariants(
            from_pid.0,
            cap_id,
            to_pid.0,
            cap.rights.bits(),
            cap.rights.bits(),
        )
        .map_err(|_| CapabilityError::SecurityViolation)?;

        // Install in destination
        if let Some(to_table) = tables[to_pid.0 as usize].as_mut() {
            // Stamp provenance: the new cap in the destination derives from cap_id.
            let mut delegated_cap = cap;
            delegated_cap.parent_cap_id = Some(cap_id);
            let new_cap_id = to_table.install(delegated_cap)?;

            // Record the delegation edge.
            let _ = self::cap_graph::record_delegation(
                from_pid.0,
                cap_id,
                to_pid.0,
                new_cap_id,
                cap.rights.bits(),
            );
            crate::serial_println!(
                "[cap_graph] delegation recorded: pid={} cap={} -> pid={} cap={}",
                from_pid.0,
                cap_id,
                to_pid.0,
                new_cap_id
            );

            // Audit transfer
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityTransferred, from_pid, cap_id)
                    .with_context(to_pid.0 as u64),
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
            verify_capability_access(
                table.owner,
                cap,
                CapabilityAccessRequest {
                    object_id: 0,
                    required_type,
                    required_right,
                },
            )?;

            // Audit capability use
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityUsed, pid, cap_id)
                    .with_context(cap.object_id),
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
                + table.count_by_type(CapabilityType::Filesystem)
                + table.count_by_type(CapabilityType::ServicePointer);

            (total, channels, services)
        } else {
            (0, 0, 0)
        }
    }

    fn quarantine_insert(
        quarantined: &mut [Option<QuarantinedCapability>; MAX_QUARANTINED_CAPS],
        owner_pid: ProcessId,
        cap: OreuliusCapability,
        restore_at_tick: u64,
    ) -> bool {
        let mut slot_idx = None;
        let mut i = 0usize;
        while i < quarantined.len() {
            match quarantined[i] {
                Some(existing)
                    if existing.owner_pid == owner_pid && existing.cap.cap_id == cap.cap_id =>
                {
                    slot_idx = Some(i);
                    break;
                }
                None if slot_idx.is_none() => {
                    slot_idx = Some(i);
                }
                _ => {}
            }
            i += 1;
        }

        let idx = match slot_idx {
            Some(idx) => idx,
            None => return false,
        };
        quarantined[idx] = Some(QuarantinedCapability {
            owner_pid,
            cap,
            restore_at_tick,
        });
        true
    }

    fn restore_quarantined_inner(
        tables: &mut [Option<alloc::boxed::Box<CapabilityTable>>; MAX_TASKS],
        quarantined: &mut [Option<QuarantinedCapability>; MAX_QUARANTINED_CAPS],
        pid: ProcessId,
        now: u64,
        force: bool,
    ) -> usize {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return 0;
        }

        let table = match tables[idx].as_mut() {
            Some(table) => table,
            None => {
                for entry in quarantined.iter_mut() {
                    let should_drop = match entry.as_ref() {
                        Some(q) => q.owner_pid == pid,
                        None => false,
                    };
                    if should_drop {
                        *entry = None;
                    }
                }
                return 0;
            }
        };

        let mut restored = 0usize;
        for entry in quarantined.iter_mut() {
            let q = match *entry {
                Some(q) => q,
                None => continue,
            };
            if q.owner_pid != pid {
                continue;
            }
            if !force && now < q.restore_at_tick {
                continue;
            }

            let slot = q.cap.cap_id as usize;
            if slot >= MAX_CAPABILITIES {
                *entry = None;
                continue;
            }

            // Never clobber a currently occupied slot; prefer preserving current authority.
            if table.entries[slot].is_some() {
                continue;
            }

            if table.install_or_replace(Some(q.cap.cap_id), q.cap).is_ok() {
                *entry = None;
                restored = restored.saturating_add(1);
            }
        }

        restored
    }

    /// Restore quarantined capabilities for a process whose quarantine timer expired.
    pub fn restore_quarantined_capabilities(&self, pid: ProcessId) -> usize {
        let now = crate::pit::get_ticks() as u64;
        let mut tables = self.tables.lock();
        let mut quarantined = self.quarantined_caps.lock();
        Self::restore_quarantined_inner(&mut tables, &mut quarantined, pid, now, false)
    }

    /// Force-restore all quarantined capabilities for a process, regardless of timer.
    pub fn force_restore_quarantined_capabilities(&self, pid: ProcessId) -> usize {
        let now = crate::pit::get_ticks() as u64;
        let mut tables = self.tables.lock();
        let mut quarantined = self.quarantined_caps.lock();
        Self::restore_quarantined_inner(&mut tables, &mut quarantined, pid, now, true)
    }

    /// Predictively revoke matching local capabilities and remote leases.
    pub fn predictive_revoke_capabilities(
        &self,
        pid: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
        restore_at_tick: u64,
    ) -> usize {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return 0;
        }

        let now = crate::pit::get_ticks() as u64;
        let hz = (crate::pit::get_frequency() as u64).max(1);
        let min_restore_at = now.saturating_add(hz);
        let restore_at_tick = if restore_at_tick > min_restore_at {
            restore_at_tick
        } else {
            min_restore_at
        };

        let mut revoked = 0usize;
        let mut tables = self.tables.lock();
        let mut quarantined = self.quarantined_caps.lock();
        if let Some(table) = tables[idx].as_mut() {
            let mut revoke_ids = [0u32; MAX_CAPABILITIES];
            let mut revoke_count = 0usize;

            for entry in table.entries.iter() {
                let cap = match entry {
                    Some(cap) => cap,
                    None => continue,
                };
                if cap.cap_type != cap_type {
                    continue;
                }
                if rights_mask != 0 && (cap.rights.bits & rights_mask) == 0 {
                    continue;
                }
                if revoke_count < revoke_ids.len() {
                    revoke_ids[revoke_count] = cap.cap_id;
                    revoke_count += 1;
                }
            }

            let mut i = 0usize;
            while i < revoke_count {
                if let Ok(cap) = table.remove(revoke_ids[i]) {
                    let _ = Self::quarantine_insert(&mut quarantined, pid, cap, restore_at_tick);
                    revoked = revoked.saturating_add(1);
                }
                i += 1;
            }
        }

        let mut leases = self.remote_leases.lock();
        for entry in leases.iter_mut() {
            let should_revoke = match entry.as_ref() {
                Some(lease) => {
                    !lease.owner_any
                        && lease.owner_pid == pid
                        && lease.cap_type == cap_type
                        && (rights_mask == 0 || (lease.rights.bits & rights_mask) != 0)
                }
                None => false,
            };
            if !should_revoke {
                continue;
            }

            let (mapped_cap_id, token_id) = match entry.as_ref() {
                Some(lease) => (lease.mapped_cap_id, lease.token_id),
                None => continue,
            };

            if mapped_cap_id != 0 {
                self.remove_remote_cap_mapping(&mut tables, pid, mapped_cap_id);
            }
            *entry = None;
            revoked = revoked.saturating_add(1);
            security::security().log_event(
                AuditEntry::new(SecurityEvent::CapabilityRevoked, pid, mapped_cap_id)
                    .with_context(token_id),
            );
        }

        revoked
    }

    fn alloc_remote_cap_id(&self) -> u32 {
        let mut next = self.next_remote_cap_id.lock();
        let id = (*next).max(1);
        *next = (*next).wrapping_add(1).max(1);
        id
    }

    fn install_remote_cap_mapping(
        &self,
        tables: &mut [Option<alloc::boxed::Box<CapabilityTable>>; MAX_TASKS],
        owner_pid: ProcessId,
        object_id: u64,
        cap_type: CapabilityType,
        rights: Rights,
        preferred_cap_id: Option<u32>,
    ) -> Result<u32, CapabilityError> {
        let idx = owner_pid.0 as usize;
        if idx >= MAX_TASKS {
            return Err(CapabilityError::TaskNotFound);
        }
        let table = tables[idx].as_mut().ok_or(CapabilityError::TaskNotFound)?;
        let cap = OreuliusCapability::new(0, object_id, cap_type, rights, owner_pid);
        table.install_or_replace(preferred_cap_id, cap)
    }

    fn remove_remote_cap_mapping(
        &self,
        tables: &mut [Option<alloc::boxed::Box<CapabilityTable>>; MAX_TASKS],
        owner_pid: ProcessId,
        mapped_cap_id: u32,
    ) {
        if mapped_cap_id == 0 {
            return;
        }
        let idx = owner_pid.0 as usize;
        if idx >= MAX_TASKS {
            return;
        }
        if let Some(table) = tables[idx].as_mut() {
            let _ = table.remove(mapped_cap_id);
        }
    }

    /// Install or update a remote capability lease from a verified CapNet token.
    pub fn install_remote_lease(
        &self,
        owner_pid: ProcessId,
        owner_any: bool,
        token_id: u64,
        issuer_device_id: u64,
        measurement_hash: u64,
        session_id: u32,
        object_id: u64,
        cap_type: CapabilityType,
        rights: Rights,
        not_before: u64,
        expires_at: u64,
        enforce_use_budget: bool,
        uses_remaining: u16,
    ) -> Result<u32, CapabilityError> {
        let mut tables = self.tables.lock();
        let mut leases = self.remote_leases.lock();
        let now = crate::pit::get_ticks() as u64;

        for entry in leases.iter_mut() {
            let should_reclaim = match entry.as_ref() {
                Some(lease) => {
                    !lease.active
                        || lease.revoked
                        || (lease.expires_at != 0 && now > lease.expires_at)
                        || (lease.enforce_use_budget && lease.uses_remaining == 0)
                }
                None => false,
            };
            if !should_reclaim {
                continue;
            }

            let (stale_owner_pid, stale_owner_any, stale_mapped_cap_id) = match entry.as_ref() {
                Some(lease) => (lease.owner_pid, lease.owner_any, lease.mapped_cap_id),
                None => continue,
            };
            if !stale_owner_any && stale_mapped_cap_id != 0 {
                self.remove_remote_cap_mapping(&mut tables, stale_owner_pid, stale_mapped_cap_id);
            }
            *entry = None;
        }

        let mut existing_idx = None;
        for i in 0..leases.len() {
            if let Some(lease) = leases[i].as_ref() {
                if lease.token_id == token_id {
                    existing_idx = Some(i);
                    break;
                }
            }
        }

        let previous = existing_idx.and_then(|idx| leases[idx]);
        let preferred_cap_id = if !owner_any {
            if let Some(prev) = previous {
                if !prev.owner_any && prev.owner_pid == owner_pid && prev.mapped_cap_id != 0 {
                    Some(prev.mapped_cap_id)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mapped_cap_id = if owner_any {
            0
        } else {
            self.install_remote_cap_mapping(
                &mut tables,
                owner_pid,
                object_id,
                cap_type,
                rights,
                preferred_cap_id,
            )?
        };

        if let Some(idx) = existing_idx {
            if let Some(lease) = leases[idx].as_mut() {
                lease.active = true;
                lease.token_id = token_id;
                lease.mapped_cap_id = mapped_cap_id;
                lease.owner_pid = owner_pid;
                lease.owner_any = owner_any;
                lease.issuer_device_id = issuer_device_id;
                lease.measurement_hash = measurement_hash;
                lease.session_id = session_id;
                lease.object_id = object_id;
                lease.cap_type = cap_type;
                lease.rights = rights;
                lease.not_before = not_before;
                lease.expires_at = expires_at;
                lease.revoked = false;
                lease.enforce_use_budget = enforce_use_budget;
                lease.uses_remaining = uses_remaining;
            }
        } else {
            let mut inserted = false;
            for entry in leases.iter_mut() {
                if entry.is_none() {
                    *entry = Some(RemoteCapabilityLease {
                        active: true,
                        token_id,
                        mapped_cap_id,
                        owner_pid,
                        owner_any,
                        issuer_device_id,
                        measurement_hash,
                        session_id,
                        object_id,
                        cap_type,
                        rights,
                        not_before,
                        expires_at,
                        revoked: false,
                        enforce_use_budget,
                        uses_remaining,
                    });
                    inserted = true;
                    break;
                }
            }

            if !inserted {
                if !owner_any {
                    self.remove_remote_cap_mapping(&mut tables, owner_pid, mapped_cap_id);
                }
                return Err(CapabilityError::TableFull);
            }
        }

        if let Some(prev) = previous {
            let same_mapping = !owner_any
                && !prev.owner_any
                && prev.owner_pid == owner_pid
                && prev.mapped_cap_id == mapped_cap_id;
            if prev.mapped_cap_id != 0 && !same_mapping {
                self.remove_remote_cap_mapping(&mut tables, prev.owner_pid, prev.mapped_cap_id);
            }
        }

        security::security().log_event(
            AuditEntry::new(SecurityEvent::CapabilityCreated, owner_pid, mapped_cap_id)
                .with_context(token_id),
        );
        Ok(mapped_cap_id)
    }

    /// Revoke a remote capability lease by token id.
    pub fn revoke_remote_lease_by_token(&self, token_id: u64) -> bool {
        let mut tables = self.tables.lock();
        let mut leases = self.remote_leases.lock();
        for entry in leases.iter_mut() {
            if let Some(lease) = entry.as_mut() {
                if lease.token_id == token_id {
                    let owner_pid = lease.owner_pid;
                    let mapped_cap_id = lease.mapped_cap_id;
                    if !lease.owner_any {
                        self.remove_remote_cap_mapping(&mut tables, owner_pid, mapped_cap_id);
                    }
                    *entry = None;
                    security::security().log_event(
                        AuditEntry::new(SecurityEvent::CapabilityRevoked, owner_pid, mapped_cap_id)
                            .with_context(token_id),
                    );
                    return true;
                }
            }
        }
        false
    }

    pub fn remote_lease_snapshots(&self) -> [Option<RemoteCapabilityLease>; MAX_REMOTE_LEASES] {
        let leases = self.remote_leases.lock();
        *leases
    }

    /// Clear all remote leases and any local mappings they installed.
    ///
    /// This is used by deterministic self-tests/fuzzing so stale owner-bound
    /// leases from earlier iterations do not bleed into later checks.
    pub fn clear_remote_leases_for_testing(&self) {
        let mut caps_to_remove = [(ProcessId(0), 0u32); MAX_REMOTE_LEASES];
        let mut remove_count = 0;

        {
            let mut leases = self.remote_leases.lock();
            for entry in leases.iter_mut() {
                let lease = match entry.take() {
                    Some(lease) => lease,
                    None => continue,
                };
                if !lease.owner_any && lease.mapped_cap_id != 0 {
                    caps_to_remove[remove_count] = (lease.owner_pid, lease.mapped_cap_id);
                    remove_count += 1;
                }
            }
        }

        {
            let mut tables = self.tables.lock();
            let mut i = 0;
            while i < remove_count {
                let (pid, cap_id) = caps_to_remove[i];
                self.remove_remote_cap_mapping(&mut tables, pid, cap_id);
                i += 1;
            }
        }

        *self.next_remote_cap_id.lock() = 1;
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
    /// Delegation graph invariant violated (cycle or rights escalation).
    SecurityViolation,
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
            CapabilityError::SecurityViolation => "Capability graph security violation",
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

pub fn temporal_apply_capability_event(
    pid_raw: u32,
    cap_type_raw: u8,
    object_id: u64,
    rights_bits: u32,
    origin_pid_raw: u32,
    event: u8,
    cap_id_hint: u32,
) -> Result<(), &'static str> {
    let pid = ProcessId(pid_raw);
    let origin = ProcessId(origin_pid_raw);
    let cap_type = CapabilityType::from_raw(cap_type_raw).ok_or("Invalid capability type")?;

    match event {
        crate::temporal::TEMPORAL_CAPABILITY_EVENT_GRANT => capability_manager()
            .grant_capability(pid, object_id, cap_type, Rights::new(rights_bits), origin)
            .map(|_| ())
            .map_err(|e| e.as_str()),
        crate::temporal::TEMPORAL_CAPABILITY_EVENT_REVOKE => {
            if cap_id_hint != 0 {
                let _ = capability_manager().revoke_capability(pid, cap_id_hint);
            }
            let _ = capability_manager().revoke_matching_for_pid(pid, cap_type, object_id);
            Ok(())
        }
        _ => Err("Unsupported capability temporal event"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAccess {
    Send,
    Receive,
    Close,
}

/// Resolve a process-owned channel capability into an IPC channel capability token.
///
/// This binds IPC operations to real capability table entries instead of temporary
/// placeholder rights.
pub fn resolve_channel_capability(
    pid: ProcessId,
    channel_id: ChannelId,
    access: ChannelAccess,
) -> Result<ChannelCapability, &'static str> {
    if pid.0 == 0 {
        return Ok(ChannelCapability::new(
            0,
            channel_id,
            ChannelRights::all(),
            pid,
        ));
    }

    let required_right = match access {
        ChannelAccess::Send => Rights::CHANNEL_SEND,
        ChannelAccess::Receive => Rights::CHANNEL_RECEIVE,
        ChannelAccess::Close => Rights::CHANNEL_SEND | Rights::CHANNEL_RECEIVE,
    };

    // Run full capability/security policy check once (includes predictive revocation,
    // rate limiting, local+remote capability validation, and audit logging).
    if !check_capability(
        pid,
        channel_id.0 as u64,
        CapabilityType::Channel,
        Rights::new(required_right),
    ) {
        return Err("No channel capability");
    }

    let tables = CAPABILITY_MANAGER.tables.lock();
    if let Some(table) = tables[pid.0 as usize].as_ref() {
        for entry in &table.entries {
            let cap = match entry {
                Some(cap) => cap,
                None => continue,
            };
            if cap.cap_type != CapabilityType::Channel {
                continue;
            }
            if cap.object_id != 0 && cap.object_id != channel_id.0 as u64 {
                continue;
            }
            if !cap.verify_token(table.owner) {
                security::security().log_event(
                    AuditEntry::new(SecurityEvent::InvalidCapability, pid, cap.cap_id)
                        .with_context(cap.object_id),
                );
                continue;
            }
            if !cap.has_right(required_right) {
                continue;
            }

            let mut rights_bits = 0u32;
            if cap.has_right(Rights::CHANNEL_SEND) {
                rights_bits |= ChannelRights::SEND;
            }
            if cap.has_right(Rights::CHANNEL_RECEIVE) {
                rights_bits |= ChannelRights::RECEIVE;
            }
            if (rights_bits & (ChannelRights::SEND | ChannelRights::RECEIVE))
                == (ChannelRights::SEND | ChannelRights::RECEIVE)
            {
                rights_bits |= ChannelRights::CLOSE;
            }

            let rights = ChannelRights::new(rights_bits);
            let allow = match access {
                ChannelAccess::Send => rights.has(ChannelRights::SEND),
                ChannelAccess::Receive => rights.has(ChannelRights::RECEIVE),
                ChannelAccess::Close => rights.has(ChannelRights::CLOSE),
            };
            if !allow {
                continue;
            }

            return Ok(ChannelCapability::new(cap.cap_id, channel_id, rights, pid));
        }
    }

    // Authorized via remote lease without local mapping; return an ephemeral cap.
    let rights = match access {
        ChannelAccess::Send => ChannelRights::send_only(),
        ChannelAccess::Receive => ChannelRights::receive_only(),
        ChannelAccess::Close => ChannelRights::full(),
    };
    Ok(ChannelCapability::new(0, channel_id, rights, pid))
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

    // Opportunistically restore quarantined capabilities whose cooldown expired.
    let _ = CAPABILITY_MANAGER.restore_quarantined_capabilities(pid);

    let sec = security::security();
    sec.intent_capability_probe(pid, cap_type, required_rights.bits, object_id);

    if sec.is_predictively_restricted(pid, cap_type, required_rights.bits) {
        let restore_at = sec.restriction_until_tick(pid);
        let revoked = CAPABILITY_MANAGER.predictive_revoke_capabilities(
            pid,
            cap_type,
            required_rights.bits,
            restore_at,
        );
        sec.intent_capability_denied(pid, cap_type, required_rights.bits, object_id);
        sec.log_event(
            AuditEntry::new(SecurityEvent::CapabilityRevoked, pid, 0).with_context(revoked as u64),
        );
        sec.log_event(
            AuditEntry::new(SecurityEvent::PermissionDenied, pid, 0).with_context(object_id),
        );
        return false;
    }

    // Rate limit check via SecurityManager
    if sec
        .validate_capability(pid, required_rights.bits, required_rights.bits)
        .is_err()
    {
        sec.intent_capability_denied(pid, cap_type, required_rights.bits, object_id);
        return false;
    }

    // Look up capability in process capability table
    let tables = CAPABILITY_MANAGER.tables.lock();

    if let Some(table) = tables[pid.0 as usize].as_ref() {
        // Iterate through all capabilities to find matching one
        for entry in &table.entries {
            if let Some(cap) = entry {
                let access = verify_capability_access(
                    table.owner,
                    cap,
                    CapabilityAccessRequest {
                        object_id,
                        required_type: cap_type,
                        required_right: required_rights.bits,
                    },
                );
                if access.is_ok() {
                    match evaluate_mapped_remote_capability(
                        pid,
                        cap.cap_id,
                        object_id,
                        cap_type,
                        required_rights,
                    ) {
                        RemoteLeaseDecision::Allow => return true,
                        RemoteLeaseDecision::Deny => {
                            sec.intent_invalid_capability(
                                pid,
                                cap_type,
                                required_rights.bits,
                                cap.object_id,
                            );
                            sec.log_event(
                                AuditEntry::new(SecurityEvent::InvalidCapability, pid, cap.cap_id)
                                    .with_context(cap.object_id),
                            );
                            continue;
                        }
                        RemoteLeaseDecision::NotMapped => {
                            // Audit successful capability use
                            sec.log_event(
                                AuditEntry::new(SecurityEvent::CapabilityUsed, pid, cap.cap_id)
                                    .with_context(cap.object_id),
                            );
                            return true;
                        }
                    }
                }
                if matches!(access, Err(CapabilityError::InvalidCapability)) {
                    sec.intent_invalid_capability(
                        pid,
                        cap_type,
                        required_rights.bits,
                        cap.object_id,
                    );
                    sec.log_event(
                        AuditEntry::new(SecurityEvent::InvalidCapability, pid, cap.cap_id)
                            .with_context(cap.object_id),
                    );
                }
            }
        }
    }

    // Fallback to active remote leases installed from validated CapNet tokens.
    if check_remote_capability_access(pid, object_id, cap_type, required_rights) {
        return true;
    }

    // No matching local capability or remote lease found
    sec.intent_capability_denied(pid, cap_type, required_rights.bits, object_id);
    sec.log_event(AuditEntry::new(SecurityEvent::PermissionDenied, pid, 0).with_context(object_id));
    false
}

fn capability_type_from_capnet(cap_type: u8) -> Option<CapabilityType> {
    CapabilityType::from_raw(cap_type)
}

/// Install/update a remote capability lease from a verified CapNet token.
///
/// `context == 0` in the token means "any local process"; non-zero binds to a PID.
pub fn install_remote_lease_from_capnet_token(
    token: &crate::capnet::CapabilityTokenV1,
) -> Result<u32, &'static str> {
    let cap_type = capability_type_from_capnet(token.cap_type).ok_or("Unsupported cap type")?;
    let owner_any = token.context == 0;
    let owner_pid = if owner_any {
        ProcessId(0)
    } else {
        ProcessId(token.context)
    };
    let enforce_use_budget =
        (token.constraints_flags & crate::capnet::CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE) != 0;
    let uses_remaining = if enforce_use_budget {
        token.max_uses
    } else {
        0
    };

    CAPABILITY_MANAGER
        .install_remote_lease(
            owner_pid,
            owner_any,
            token.token_id(),
            token.issuer_device_id,
            token.measurement_hash,
            token.session_id,
            token.object_id,
            cap_type,
            Rights::new(token.rights),
            token.not_before,
            token.expires_at,
            enforce_use_budget,
            uses_remaining,
        )
        .map_err(|e| e.as_str())
}

pub fn revoke_remote_lease_by_token(token_id: u64) -> bool {
    CAPABILITY_MANAGER.revoke_remote_lease_by_token(token_id)
}

pub fn clear_remote_leases_for_testing() {
    CAPABILITY_MANAGER.clear_remote_leases_for_testing();
}

pub fn formal_capability_self_check() -> Result<(), &'static str> {
    let owner = ProcessId::new(42);
    let mut cap = OreuliusCapability::new(
        7,
        0xABCD,
        CapabilityType::Channel,
        Rights::new(Rights::CHANNEL_SEND | Rights::CHANNEL_RECEIVE),
        owner,
    );
    cap.sign(owner);

    // Proof obligation 1: Valid token + required rights/type/object must pass.
    verify_capability_access(
        owner,
        &cap,
        CapabilityAccessRequest {
            object_id: 0xABCD,
            required_type: CapabilityType::Channel,
            required_right: Rights::CHANNEL_SEND,
        },
    )
    .map_err(|_| "Formal capability self-check denied valid capability")?;

    // Proof obligation 2: Wrong right must fail.
    if verify_capability_access(
        owner,
        &cap,
        CapabilityAccessRequest {
            object_id: 0xABCD,
            required_type: CapabilityType::Channel,
            required_right: Rights::CHANNEL_CREATE,
        },
    )
    .is_ok()
    {
        return Err("Formal capability self-check accepted insufficient rights");
    }

    // Proof obligation 3: Wrong type must fail.
    if verify_capability_access(
        owner,
        &cap,
        CapabilityAccessRequest {
            object_id: 0xABCD,
            required_type: CapabilityType::Filesystem,
            required_right: Rights::CHANNEL_SEND,
        },
    )
    .is_ok()
    {
        return Err("Formal capability self-check accepted wrong type");
    }

    // Proof obligation 4: Token tampering must be detected.
    let mut forged = cap;
    forged.token ^= 0x1;
    if verify_capability_access(
        owner,
        &forged,
        CapabilityAccessRequest {
            object_id: 0xABCD,
            required_type: CapabilityType::Channel,
            required_right: Rights::CHANNEL_SEND,
        },
    )
    .is_ok()
    {
        return Err("Formal capability self-check failed token tamper detection");
    }

    // Proof obligation 5: Attenuation subset law holds.
    let attenuated = cap
        .attenuate(Rights::new(Rights::CHANNEL_SEND))
        .map_err(|_| "Formal capability self-check attenuation rejected valid subset")?;
    if !attenuated.has_right(Rights::CHANNEL_SEND) || attenuated.has_right(Rights::CHANNEL_RECEIVE)
    {
        return Err("Formal capability self-check attenuation produced invalid rights set");
    }
    if cap
        .attenuate(Rights::new(Rights::CHANNEL_SEND | Rights::CHANNEL_CREATE))
        .is_ok()
    {
        return Err("Formal capability self-check accepted non-subset attenuation");
    }

    Ok(())
}

// ============================================================================
// Syscall Wrapper Functions
// ============================================================================

/// Revoke a capability (syscall wrapper)
impl CapabilityManager {
    pub fn revoke_capability(&self, pid: ProcessId, cap_id: u32) -> Result<(), &'static str> {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return Err("Task not found");
        }

        let mut tables = self.tables.lock();
        let table = tables[idx].as_mut().ok_or("Task not found")?;
        let cap = *table.lookup(cap_id).map_err(|e| e.as_str())?;
        table.remove(cap_id).map_err(|e| e.as_str())?;
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_capability_event(
                pid.0,
                cap.cap_type as u8,
                cap.object_id,
                cap.rights.bits(),
                cap.origin.0,
                crate::temporal::TEMPORAL_CAPABILITY_EVENT_REVOKE,
                cap_id,
            );
        }
        // Capability graph: prune all delegation edges involving this cap.
        self::cap_graph::prune_edges_for(pid.0, cap_id);

        // Notify kernel observers about the capability revocation.
        #[cfg(not(target_arch = "aarch64"))]
        let payload = [
            pid.0.to_le_bytes()[0],
            pid.0.to_le_bytes()[1],
            pid.0.to_le_bytes()[2],
            pid.0.to_le_bytes()[3],
            cap.cap_type as u8,
            1,
            0,
            0, // 1 = revoke
        ];
        #[cfg(not(target_arch = "aarch64"))]
        crate::wasm::observer_notify(crate::wasm::observer_events::CAPABILITY_OP, &payload);
        Ok(())
    }

    /// Revoke all capabilities for a specific PID — used by the Math Daemon
    /// cross-PID revocation path (PMA §6.2 / syscall 43).
    pub fn revoke_all_capabilities(&self, pid: ProcessId) -> Result<(), &'static str> {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return Err("Task not found");
        }
        let mut tables = self.tables.lock();
        let table = tables[idx].as_mut().ok_or("Task not found")?;
        table.revoke_all();
        Ok(())
    }

    /// Revoke all capabilities for a specific PID (infallible convenience wrapper).
    pub fn revoke_all_for_pid(&self, pid: ProcessId) {
        let _ = self.revoke_all_capabilities(pid);
    }

    /// Snapshot the capability set for `pid` as a fixed-size array.
    ///
    /// Returns up to `MAX_CAPABILITIES` entries as `Option<OreuliusCapability>`.
    /// The array length matches `MAX_CAPABILITIES`; unused slots are `None`.
    pub fn list_capabilities_for_pid(
        &self,
        pid: ProcessId,
    ) -> [Option<OreuliusCapability>; MAX_CAPABILITIES] {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return [None; MAX_CAPABILITIES];
        }
        let tables = self.tables.lock();
        match tables[idx].as_ref() {
            None => [None; MAX_CAPABILITIES],
            Some(table) => {
                let mut out = [None; MAX_CAPABILITIES];
                let mut k = 0usize;
                for entry in table.entries.iter() {
                    if k >= MAX_CAPABILITIES {
                        break;
                    }
                    if entry.is_some() {
                        out[k] = *entry;
                        k += 1;
                    }
                }
                out
            }
        }
    }

    /// Query capability information (syscall wrapper)
    pub fn query_capability(
        &self,
        pid: ProcessId,
        cap_id: u32,
    ) -> Result<(u32, u64), &'static str> {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return Err("Task not found");
        }

        let tables = self.tables.lock();
        let table = tables[idx].as_ref().ok_or("Task not found")?;
        let cap = table.lookup(cap_id).map_err(|e| e.as_str())?;
        Ok((cap.cap_type as u32, cap.object_id))
    }

    /// Revoke all capabilities referencing a specific object/type pair across all tasks.
    pub fn revoke_object_capabilities(&self, cap_type: CapabilityType, object_id: u64) -> usize {
        let mut tables = self.tables.lock();
        let mut revoked = 0usize;

        for slot in tables.iter_mut() {
            let table = match slot.as_mut() {
                Some(t) => t,
                None => continue,
            };

            let mut revoke_ids = [0u32; MAX_CAPABILITIES];
            let mut revoke_count = 0usize;
            for entry in table.entries.iter() {
                let cap = match entry {
                    Some(c) => c,
                    None => continue,
                };
                if cap.cap_type != cap_type || cap.object_id != object_id {
                    continue;
                }
                if revoke_count < revoke_ids.len() {
                    revoke_ids[revoke_count] = cap.cap_id;
                    revoke_count += 1;
                }
            }

            let mut i = 0usize;
            while i < revoke_count {
                if table.remove(revoke_ids[i]).is_ok() {
                    revoked = revoked.saturating_add(1);
                }
                i += 1;
            }
        }
        revoked
    }

    pub fn revoke_matching_for_pid(
        &self,
        pid: ProcessId,
        cap_type: CapabilityType,
        object_id: u64,
    ) -> usize {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return 0;
        }

        let mut tables = self.tables.lock();
        let table = match tables[idx].as_mut() {
            Some(t) => t,
            None => return 0,
        };

        let mut revoke_ids = [0u32; MAX_CAPABILITIES];
        let mut revoke_count = 0usize;
        for entry in table.entries.iter() {
            let cap = match entry {
                Some(c) => c,
                None => continue,
            };
            if cap.cap_type != cap_type || cap.object_id != object_id {
                continue;
            }
            if revoke_count < revoke_ids.len() {
                revoke_ids[revoke_count] = cap.cap_id;
                revoke_count += 1;
            }
        }

        let mut revoked = 0usize;
        let mut i = 0usize;
        while i < revoke_count {
            if table.remove(revoke_ids[i]).is_ok() {
                revoked = revoked.saturating_add(1);
            }
            i += 1;
        }
        revoked
    }

    /// Return full capability metadata for kernel mediation paths.
    pub fn get_capability(
        &self,
        pid: ProcessId,
        cap_id: u32,
    ) -> Result<OreuliusCapability, &'static str> {
        let idx = pid.0 as usize;
        if idx >= MAX_TASKS {
            return Err("Task not found");
        }

        let tables = self.tables.lock();
        let table = tables[idx].as_ref().ok_or("Task not found")?;
        let cap = table.lookup(cap_id).map_err(|e| e.as_str())?;
        Ok(*cap)
    }
}

fn ipc_cap_type_for(cap_type: CapabilityType) -> crate::ipc::CapabilityType {
    match cap_type {
        CapabilityType::Channel => crate::ipc::CapabilityType::Channel,
        CapabilityType::Filesystem => crate::ipc::CapabilityType::Filesystem,
        CapabilityType::Store => crate::ipc::CapabilityType::Store,
        CapabilityType::ServicePointer => crate::ipc::CapabilityType::ServicePointer,
        _ => crate::ipc::CapabilityType::Generic,
    }
}

fn cap_type_from_ipc(
    cap_type: crate::ipc::CapabilityType,
    extra_words: [u32; 4],
) -> Option<CapabilityType> {
    match cap_type {
        crate::ipc::CapabilityType::Channel => Some(CapabilityType::Channel),
        crate::ipc::CapabilityType::Filesystem => Some(CapabilityType::Filesystem),
        crate::ipc::CapabilityType::Store => Some(CapabilityType::Store),
        crate::ipc::CapabilityType::ServicePointer => Some(CapabilityType::ServicePointer),
        crate::ipc::CapabilityType::Generic => CapabilityType::from_raw(extra_words[3] as u8),
    }
}

/// Export a local capability as an authenticated IPC capability attachment.
pub fn export_capability_to_ipc(
    owner: ProcessId,
    cap_id: u32,
) -> Result<crate::ipc::Capability, &'static str> {
    let cap = capability_manager().get_capability(owner, cap_id)?;

    if cap.cap_type == CapabilityType::ServicePointer && !cap.has_right(Rights::SERVICE_DELEGATE) {
        return Err("Service pointer requires delegate right for transfer");
    }

    let mut out = crate::ipc::Capability::with_type(
        cap.cap_id,
        cap.object_id,
        cap.rights,
        ipc_cap_type_for(cap.cap_type),
    )
    .with_owner(cap.origin)
    .with_validity(cap.granted_at, 0)
    .with_flags(cap.cap_type as u32);
    out.extra[3] = cap.cap_type as u32;
    out.sign();
    Ok(out)
}

/// Import an IPC-attached capability into a process capability table.
pub fn import_capability_from_ipc(
    owner: ProcessId,
    cap: &crate::ipc::Capability,
    source: ProcessId,
) -> Result<u32, &'static str> {
    if !cap.verify() {
        return Err("Invalid IPC capability token");
    }

    let cap_type =
        cap_type_from_ipc(cap.cap_type, cap.extra).ok_or("Unsupported IPC capability type")?;
    let object_id = cap.object_id;

    #[cfg(not(target_arch = "aarch64"))]
    if cap_type == CapabilityType::ServicePointer && !crate::wasm::service_pointer_exists(object_id)
    {
        return Err("Unknown service pointer object");
    }

    capability_manager()
        .grant_capability(owner, object_id, cap_type, cap.rights, source)
        .map_err(|e| e.as_str())
}
