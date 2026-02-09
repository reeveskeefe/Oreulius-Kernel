//! Oreulia Security Module
//!
//! Comprehensive security infrastructure for capability-based OS
//!
//! Features:
//! - Capability audit logging and validation
//! - Cryptographic primitives (hashing, random generation)
//! - Resource quotas and rate limiting
//! - Security policy enforcement
//! - Integrity checking

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
use crate::ipc::ProcessId;

// ============================================================================
// Security Constants
// ============================================================================

/// Maximum audit log entries
pub const MAX_AUDIT_ENTRIES: usize = 1024;

/// Maximum security violations before process termination
pub const MAX_VIOLATIONS_PER_PROCESS: u32 = 10;

/// Rate limit: operations per second
pub const RATE_LIMIT_OPS_PER_SEC: u32 = 1000;

/// Maximum capability lifetime in milliseconds (0 = unlimited)
pub const MAX_CAPABILITY_LIFETIME_MS: u64 = 0;

// ============================================================================
// Audit Log
// ============================================================================

/// Security event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    /// Capability created
    CapabilityCreated,
    /// Capability transferred
    CapabilityTransferred,
    /// Capability used
    CapabilityUsed,
    /// Capability revoked
    CapabilityRevoked,
    /// Permission denied
    PermissionDenied,
    /// Resource quota exceeded
    QuotaExceeded,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Invalid capability access
    InvalidCapability,
    /// Integrity check failed
    IntegrityCheckFailed,
    /// Process spawned
    ProcessSpawned,
    /// Process terminated
    ProcessTerminated,
}

impl SecurityEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityEvent::CapabilityCreated => "CapCreated",
            SecurityEvent::CapabilityTransferred => "CapTransferred",
            SecurityEvent::CapabilityUsed => "CapUsed",
            SecurityEvent::CapabilityRevoked => "CapRevoked",
            SecurityEvent::PermissionDenied => "PermDenied",
            SecurityEvent::QuotaExceeded => "QuotaExceeded",
            SecurityEvent::RateLimitExceeded => "RateLimitExceeded",
            SecurityEvent::InvalidCapability => "InvalidCap",
            SecurityEvent::IntegrityCheckFailed => "IntegrityFailed",
            SecurityEvent::ProcessSpawned => "ProcSpawned",
            SecurityEvent::ProcessTerminated => "ProcTerminated",
        }
    }
}

/// Audit log entry
#[derive(Clone, Copy)]
pub struct AuditEntry {
    /// Event type
    pub event: SecurityEvent,
    /// Process involved
    pub process_id: ProcessId,
    /// Capability ID (if applicable)
    pub cap_id: u32,
    /// Timestamp (ticks)
    pub timestamp: u64,
    /// Additional context data
    pub context: u64,
}

impl AuditEntry {
    pub fn new(event: SecurityEvent, process_id: ProcessId, cap_id: u32) -> Self {
        AuditEntry {
            event,
            process_id,
            cap_id,
            timestamp: 0, // crate::pit::get_ticks() as u64, // DISABLED FOR DEBUGGING HANG
            context: 0,
        }
    }

    pub fn with_context(mut self, context: u64) -> Self {
        self.context = context;
        self
    }
}

/// Audit log
pub struct AuditLog {
    entries: [Option<AuditEntry>; MAX_AUDIT_ENTRIES],
    count: usize,
    next_index: usize,
}

impl AuditLog {
    pub const fn new() -> Self {
        AuditLog {
            entries: [None; MAX_AUDIT_ENTRIES],
            count: 0,
            next_index: 0,
        }
    }

    /// Log a security event
    pub fn log(&mut self, entry: AuditEntry) {
        self.entries[self.next_index] = Some(entry);
        self.next_index = (self.next_index + 1) % MAX_AUDIT_ENTRIES;
        if self.count < MAX_AUDIT_ENTRIES {
            self.count += 1;
        }
    }

    /// Get recent entries (up to limit)
    pub fn recent(&self, limit: usize) -> impl Iterator<Item = &AuditEntry> {
        let count = self.count.min(limit);
        let start = if self.next_index >= count {
            self.next_index - count
        } else {
            MAX_AUDIT_ENTRIES + self.next_index - count
        };

        (0..count).filter_map(move |i| {
            let idx = (start + i) % MAX_AUDIT_ENTRIES;
            self.entries[idx].as_ref()
        })
    }

    /// Count events by type
    pub fn count_events(&self, event_type: SecurityEvent) -> usize {
        self.entries
            .iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.event == event_type)
            .count()
    }

    /// Get total event count
    pub fn total_count(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Capability Validation
// ============================================================================

/// Capability validator
pub struct CapabilityValidator {
    /// Violation counts per process
    violations: [(ProcessId, u32); 64],
    violation_count: usize,
}

impl CapabilityValidator {
    pub const fn new() -> Self {
        CapabilityValidator {
            violations: [(ProcessId(0), 0); 64],
            violation_count: 0,
        }
    }

    /// Validate capability rights
    pub fn validate_rights(&mut self, process: ProcessId, required: u32, actual: u32) -> Result<(), SecurityError> {
        if (actual & required) != required {
            self.record_violation(process);
            return Err(SecurityError::InsufficientRights);
        }
        Ok(())
    }

    /// Check if capability is expired (if lifetime tracking enabled)
    pub fn is_expired(&self, _cap_id: u32, _created_at: u64) -> bool {
        // v0: No expiration
        if MAX_CAPABILITY_LIFETIME_MS == 0 {
            return false;
        }

        // Future: check timestamp + lifetime
        false
    }

    /// Record security violation
    fn record_violation(&mut self, process: ProcessId) {
        // Find or add process
        for i in 0..self.violation_count {
            if self.violations[i].0 == process {
                self.violations[i].1 += 1;
                return;
            }
        }

        if self.violation_count < self.violations.len() {
            self.violations[self.violation_count] = (process, 1);
            self.violation_count += 1;
        }
    }

    /// Get violation count for process
    pub fn get_violations(&self, process: ProcessId) -> u32 {
        self.violations
            .iter()
            .take(self.violation_count)
            .find(|(pid, _)| *pid == process)
            .map(|(_, count)| *count)
            .unwrap_or(0)
    }

    /// Check if process should be terminated
    pub fn should_terminate(&self, process: ProcessId) -> bool {
        self.get_violations(process) >= MAX_VIOLATIONS_PER_PROCESS
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limiter per process
pub struct RateLimiter {
    /// Tokens per process (token bucket algorithm)
    tokens: [(ProcessId, u32, u64); 64],
    count: usize,
}

impl RateLimiter {
    pub const fn new() -> Self {
        RateLimiter {
            tokens: [(ProcessId(0), 0, 0); 64],
            count: 0,
        }
    }

    /// Check if operation is allowed (token bucket)
    pub fn allow(&mut self, process: ProcessId) -> bool {
        let now = crate::pit::get_ticks() as u64;

        // Find process bucket
        for i in 0..self.count {
            if self.tokens[i].0 == process {
                let (_, tokens, last_refill) = &mut self.tokens[i];

                // Refill tokens based on time elapsed
                let elapsed_ms = (now - *last_refill) * 10; // 100 Hz = 10ms per tick
                let refill_amount = ((elapsed_ms * RATE_LIMIT_OPS_PER_SEC as u64) / 1000) as u32;

                if refill_amount > 0 {
                    *tokens = (*tokens + refill_amount).min(RATE_LIMIT_OPS_PER_SEC);
                    *last_refill = now;
                }

                // Check if tokens available
                if *tokens > 0 {
                    *tokens -= 1;
                    return true;
                }
                return false;
            }
        }

        // New process - add bucket
        if self.count < self.tokens.len() {
            self.tokens[self.count] = (process, RATE_LIMIT_OPS_PER_SEC - 1, now);
            self.count += 1;
            return true;
        }

        false
    }

    /// Get remaining tokens for process
    pub fn remaining(&self, process: ProcessId) -> u32 {
        self.tokens
            .iter()
            .take(self.count)
            .find(|(pid, _, _)| *pid == process)
            .map(|(_, tokens, _)| *tokens)
            .unwrap_or(0)
    }
}

// ============================================================================
// Resource Quotas
// ============================================================================

/// Resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Memory,
    Capabilities,
    Channels,
    WasmInstances,
    FileHandles,
}

/// Resource quota entry
#[derive(Clone, Copy)]
pub struct ResourceQuota {
    pub resource: ResourceType,
    pub limit: usize,
    pub used: usize,
}

/// Per-process resource tracking
pub struct ResourceTracker {
    /// Quotas per process
    quotas: [(ProcessId, [ResourceQuota; 5]); 32],
    count: usize,
}

impl ResourceTracker {
    pub const fn new() -> Self {
        ResourceTracker {
            quotas: [(ProcessId(0), [ResourceQuota::empty(); 5]); 32],
            count: 0,
        }
    }

    /// Initialize quotas for process
    pub fn init_process(&mut self, process: ProcessId) {
        if self.count >= self.quotas.len() {
            return;
        }

        self.quotas[self.count] = (
            process,
            [
                ResourceQuota::new(ResourceType::Memory, 1024 * 1024), // 1 MB
                ResourceQuota::new(ResourceType::Capabilities, 128),
                ResourceQuota::new(ResourceType::Channels, 32),
                ResourceQuota::new(ResourceType::WasmInstances, 4),
                ResourceQuota::new(ResourceType::FileHandles, 64),
            ],
        );
        self.count += 1;
    }

    /// Check if allocation is allowed
    pub fn check_allocation(&mut self, process: ProcessId, resource: ResourceType, amount: usize) -> Result<(), SecurityError> {
        for i in 0..self.count {
            if self.quotas[i].0 == process {
                let quota = &mut self.quotas[i].1[resource as usize];
                if quota.used + amount > quota.limit {
                    return Err(SecurityError::QuotaExceeded);
                }
                quota.used += amount;
                return Ok(());
            }
        }
        Err(SecurityError::ProcessNotFound)
    }

    /// Release resources
    pub fn release(&mut self, process: ProcessId, resource: ResourceType, amount: usize) {
        for i in 0..self.count {
            if self.quotas[i].0 == process {
                let quota = &mut self.quotas[i].1[resource as usize];
                quota.used = quota.used.saturating_sub(amount);
                return;
            }
        }
    }

    /// Get resource usage
    pub fn get_usage(&self, process: ProcessId, resource: ResourceType) -> (usize, usize) {
        for i in 0..self.count {
            if self.quotas[i].0 == process {
                let quota = &self.quotas[i].1[resource as usize];
                return (quota.used, quota.limit);
            }
        }
        (0, 0)
    }
}

impl ResourceQuota {
    pub const fn new(resource: ResourceType, limit: usize) -> Self {
        ResourceQuota {
            resource,
            limit,
            used: 0,
        }
    }

    pub const fn empty() -> Self {
        ResourceQuota {
            resource: ResourceType::Memory,
            limit: 0,
            used: 0,
        }
    }
}

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Simple PRNG for secure random generation (xorshift64)
pub struct SecureRandom {
    state: u64,
}

impl SecureRandom {
    pub const fn new(seed: u64) -> Self {
        SecureRandom { state: seed }
    }

    /// Generate next random u64
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate random u32
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}

/// Cryptographic hash (SHA-256 placeholder - using FNV for v0)
pub fn hash_data(data: &[u8]) -> u64 {
    // Use assembly-optimized FNV-1a hash (returns u32, cast to u64)
    crate::asm_bindings::hash_data(data) as u64
}

/// Verify data integrity
pub fn verify_integrity(data: &[u8], expected_hash: u64) -> bool {
    hash_data(data) == expected_hash
}

// ============================================================================
// Security Manager
// ============================================================================

/// Global security manager
#[repr(align(64))]
pub struct SecurityManager {
    audit_log: Mutex<AuditLog>,
    validator: Mutex<CapabilityValidator>,
    rate_limiter: Mutex<RateLimiter>,
    resource_tracker: Mutex<ResourceTracker>,
    random: Mutex<SecureRandom>,
}

impl SecurityManager {
    pub const fn new() -> Self {
        SecurityManager {
            audit_log: Mutex::new(AuditLog::new()),
            validator: Mutex::new(CapabilityValidator::new()),
            rate_limiter: Mutex::new(RateLimiter::new()),
            resource_tracker: Mutex::new(ResourceTracker::new()),
            random: Mutex::new(SecureRandom::new(0x1234567890ABCDEF)),
        }
    }

    /// Log security event
    pub fn log_event(&self, entry: AuditEntry) {
        if let Some(mut log) = self.audit_log.try_lock() {
            log.log(entry);
        }
    }

    /// Validate capability operation
    pub fn validate_capability(&self, process: ProcessId, required_rights: u32, actual_rights: u32) -> Result<(), SecurityError> {
        // Check rate limit
        if !self.rate_limiter.lock().allow(process) {
            self.log_event(
                AuditEntry::new(SecurityEvent::RateLimitExceeded, process, 0)
            );
            return Err(SecurityError::RateLimitExceeded);
        }

        // Validate rights
        let result = self.validator.lock().validate_rights(process, required_rights, actual_rights);

        if result.is_err() {
            self.log_event(
                AuditEntry::new(SecurityEvent::PermissionDenied, process, 0)
            );
        }

        result
    }

    /// Check resource allocation
    pub fn check_resource(&self, process: ProcessId, resource: ResourceType, amount: usize) -> Result<(), SecurityError> {
        let result = self.resource_tracker.lock().check_allocation(process, resource, amount);

        if result.is_err() {
            self.log_event(
                AuditEntry::new(SecurityEvent::QuotaExceeded, process, 0)
                    .with_context(resource as u64)
            );
        }

        result
    }

    /// Release resource
    pub fn release_resource(&self, process: ProcessId, resource: ResourceType, amount: usize) {
        self.resource_tracker.lock().release(process, resource, amount);
    }

    /// Initialize process security context
    pub fn init_process(&self, process: ProcessId) {
        self.resource_tracker.lock().init_process(process);
        self.log_event(
            AuditEntry::new(SecurityEvent::ProcessSpawned, process, 0)
        );
    }

    /// Generate secure random bytes
    pub fn random_bytes(&self, buf: &mut [u8]) {
        self.random.lock().fill_bytes(buf);
    }

    /// Generate random u32
    pub fn random_u32(&self) -> u32 {
        self.random.lock().next_u32()
    }

    /// Get audit statistics
    pub fn get_audit_stats(&self) -> (usize, usize, usize) {
        let log = self.audit_log.lock();
        let total = log.total_count();
        let denied = log.count_events(SecurityEvent::PermissionDenied);
        let quota = log.count_events(SecurityEvent::QuotaExceeded);
        (total, denied, quota)
    }

    /// Get recent audit entries (returns up to 32 entries)
    pub fn get_recent_events(&self, limit: usize) -> [Option<AuditEntry>; 32] {
        let mut result = [None; 32];
        let actual_limit = limit.min(32);
        let mut idx = 0;
        
        for entry in self.audit_log.lock().recent(actual_limit) {
            if idx < 32 {
                result[idx] = Some(*entry);
                idx += 1;
            }
        }
        
        result
    }

    /// Check if process should be terminated
    pub fn should_terminate_process(&self, process: ProcessId) -> bool {
        self.validator.lock().should_terminate(process)
    }
}

// ============================================================================
// Security Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    InsufficientRights,
    QuotaExceeded,
    RateLimitExceeded,
    InvalidCapability,
    IntegrityCheckFailed,
    ProcessNotFound,
}

impl SecurityError {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityError::InsufficientRights => "Insufficient rights",
            SecurityError::QuotaExceeded => "Resource quota exceeded",
            SecurityError::RateLimitExceeded => "Rate limit exceeded",
            SecurityError::InvalidCapability => "Invalid capability",
            SecurityError::IntegrityCheckFailed => "Integrity check failed",
            SecurityError::ProcessNotFound => "Process not found",
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// Global Security Instance
// ============================================================================

static SECURITY: SecurityManager = SecurityManager::new();

/// Get global security manager
pub fn security() -> &'static SecurityManager {
    &SECURITY
}

/// Initialize security subsystem
pub fn init() {
    // Seed random number generator
    let seed = 0xDEADBEEF; 
    
    // Try lock
    if let Some(mut random) = SECURITY.random.try_lock() {
         random.state ^= seed;
    }
}
