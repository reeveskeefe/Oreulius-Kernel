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
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::capability::CapabilityType;
use crate::intent_graph::{
    IntentDecision, IntentGraph, IntentGraphStats, IntentPolicy, IntentPolicyError,
    IntentProcessSnapshot, IntentSignal,
};
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

/// Sliding anomaly window width (seconds).
pub const ANOMALY_WINDOW_SECONDS: u64 = 10;
/// Alert threshold for anomaly score.
pub const ANOMALY_ALERT_SCORE: u32 = 64;
/// Critical threshold for anomaly score.
pub const ANOMALY_CRITICAL_SCORE: u32 = 160;
/// Number of per-second buckets used for anomaly accounting.
const ANOMALY_BUCKETS: usize = 32;

pub use crate::intent_graph::{
    INTENT_ALERT_SCORE, INTENT_ISOLATE_RESTRICTIONS, INTENT_RESTRICT_SCORE,
    INTENT_TERMINATE_RESTRICTIONS, INTENT_WINDOW_SECONDS,
};

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
    /// Runtime anomaly score crossed threshold
    AnomalyDetected,
    /// Syscall observed at boundary
    SyscallObserved,
    /// Process spawned
    ProcessSpawned,
    /// Process terminated
    ProcessTerminated,
    /// Temporal object operation observed
    TemporalOperation,
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
            SecurityEvent::AnomalyDetected => "Anomaly",
            SecurityEvent::SyscallObserved => "Syscall",
            SecurityEvent::ProcessSpawned => "ProcSpawned",
            SecurityEvent::ProcessTerminated => "ProcTerminated",
            SecurityEvent::TemporalOperation => "TemporalOp",
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
// Runtime Anomaly Detection
// ============================================================================

#[derive(Clone, Copy)]
struct AnomalyBucket {
    epoch_sec: u64,
    denied: u16,
    quota: u16,
    rate: u16,
    invalid: u16,
    integrity: u16,
}

impl AnomalyBucket {
    const fn empty() -> Self {
        Self {
            epoch_sec: 0,
            denied: 0,
            quota: 0,
            rate: 0,
            invalid: 0,
            integrity: 0,
        }
    }

    fn reset(&mut self, epoch_sec: u64) {
        self.epoch_sec = epoch_sec;
        self.denied = 0;
        self.quota = 0;
        self.rate = 0;
        self.invalid = 0;
        self.integrity = 0;
    }
}

#[derive(Clone, Copy)]
pub struct AnomalyStats {
    pub alerts_total: u32,
    pub critical_total: u32,
    pub last_score: u32,
    pub max_score: u32,
    pub recent_denied: u32,
    pub recent_quota: u32,
    pub recent_rate: u32,
    pub recent_invalid: u32,
    pub recent_integrity: u32,
}

pub struct AnomalyDetector {
    buckets: [AnomalyBucket; ANOMALY_BUCKETS],
    alerts_total: u32,
    critical_total: u32,
    last_alert_tick: u64,
    last_score: u32,
    max_score: u32,
}

impl AnomalyDetector {
    pub const fn new() -> Self {
        Self {
            buckets: [AnomalyBucket::empty(); ANOMALY_BUCKETS],
            alerts_total: 0,
            critical_total: 0,
            last_alert_tick: 0,
            last_score: 0,
            max_score: 0,
        }
    }

    fn epoch_sec(now_ticks: u64) -> u64 {
        let hz = crate::pit::get_frequency() as u64;
        if hz == 0 {
            now_ticks
        } else {
            now_ticks / hz
        }
    }

    fn bucket_mut(&mut self, epoch_sec: u64) -> &mut AnomalyBucket {
        let idx = (epoch_sec as usize) % ANOMALY_BUCKETS;
        if self.buckets[idx].epoch_sec != epoch_sec {
            self.buckets[idx].reset(epoch_sec);
        }
        &mut self.buckets[idx]
    }

    fn score_window(&self, epoch_sec: u64) -> (u32, u32, u32, u32, u32, u32) {
        let window_start = epoch_sec.saturating_sub(ANOMALY_WINDOW_SECONDS.saturating_sub(1));
        let mut denied = 0u32;
        let mut quota = 0u32;
        let mut rate = 0u32;
        let mut invalid = 0u32;
        let mut integrity = 0u32;
        let mut i = 0usize;
        while i < self.buckets.len() {
            let b = self.buckets[i];
            if b.epoch_sec >= window_start && b.epoch_sec <= epoch_sec {
                denied = denied.saturating_add(b.denied as u32);
                quota = quota.saturating_add(b.quota as u32);
                rate = rate.saturating_add(b.rate as u32);
                invalid = invalid.saturating_add(b.invalid as u32);
                integrity = integrity.saturating_add(b.integrity as u32);
            }
            i += 1;
        }
        // Weighted score tuned for noisy-but-benign operation under fuzzing.
        let score = denied
            .saturating_mul(2)
            .saturating_add(quota.saturating_mul(2))
            .saturating_add(rate)
            .saturating_add(invalid.saturating_mul(4))
            .saturating_add(integrity.saturating_mul(16));
        (score, denied, quota, rate, invalid, integrity)
    }

    pub fn record(&mut self, event: SecurityEvent, now_ticks: u64) -> Option<u32> {
        let epoch = Self::epoch_sec(now_ticks);
        let bucket = self.bucket_mut(epoch);
        match event {
            SecurityEvent::PermissionDenied => {
                bucket.denied = bucket.denied.saturating_add(1);
            }
            SecurityEvent::QuotaExceeded => {
                bucket.quota = bucket.quota.saturating_add(1);
            }
            SecurityEvent::RateLimitExceeded => {
                bucket.rate = bucket.rate.saturating_add(1);
            }
            SecurityEvent::InvalidCapability => {
                bucket.invalid = bucket.invalid.saturating_add(1);
            }
            SecurityEvent::IntegrityCheckFailed => {
                bucket.integrity = bucket.integrity.saturating_add(1);
            }
            _ => {}
        }

        let (score, ..) = self.score_window(epoch);
        self.last_score = score;
        if score > self.max_score {
            self.max_score = score;
        }

        if score < ANOMALY_ALERT_SCORE {
            return None;
        }
        let min_gap = (crate::pit::get_frequency() as u64).max(1);
        if self.last_alert_tick != 0 && now_ticks.saturating_sub(self.last_alert_tick) < min_gap {
            return None;
        }
        self.last_alert_tick = now_ticks;
        self.alerts_total = self.alerts_total.saturating_add(1);
        if score >= ANOMALY_CRITICAL_SCORE {
            self.critical_total = self.critical_total.saturating_add(1);
        }
        Some(score)
    }

    pub fn snapshot(&self, now_ticks: u64) -> AnomalyStats {
        let epoch = Self::epoch_sec(now_ticks);
        let (_, denied, quota, rate, invalid, integrity) = self.score_window(epoch);
        AnomalyStats {
            alerts_total: self.alerts_total,
            critical_total: self.critical_total,
            last_score: self.last_score,
            max_score: self.max_score,
            recent_denied: denied,
            recent_quota: quota,
            recent_rate: rate,
            recent_invalid: invalid,
            recent_integrity: integrity,
        }
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

    /// Remove stored violation state for a process.
    pub fn clear_process(&mut self, process: ProcessId) {
        let mut i = 0usize;
        while i < self.violation_count {
            if self.violations[i].0 == process {
                let last = self.violation_count.saturating_sub(1);
                self.violations[i] = self.violations[last];
                self.violations[last] = (ProcessId(0), 0);
                self.violation_count = last;
                return;
            }
            i += 1;
        }
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

    /// Remove rate limiting state for a process.
    pub fn remove_process(&mut self, process: ProcessId) {
        let mut i = 0usize;
        while i < self.count {
            if self.tokens[i].0 == process {
                let last = self.count.saturating_sub(1);
                self.tokens[i] = self.tokens[last];
                self.tokens[last] = (ProcessId(0), 0, 0);
                self.count = last;
                return;
            }
            i += 1;
        }
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

    /// Remove all resource quota state for a process.
    pub fn remove_process(&mut self, process: ProcessId) {
        let mut i = 0usize;
        while i < self.count {
            if self.quotas[i].0 == process {
                let last = self.count.saturating_sub(1);
                self.quotas[i] = self.quotas[last];
                self.quotas[last] = (ProcessId(0), [ResourceQuota::empty(); 5]);
                self.count = last;
                return;
            }
            i += 1;
        }
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
    anomaly_detector: Mutex<AnomalyDetector>,
    intent_graph: Mutex<IntentGraph>,
    validator: Mutex<CapabilityValidator>,
    rate_limiter: Mutex<RateLimiter>,
    rate_limit_enabled: AtomicBool,
    resource_tracker: Mutex<ResourceTracker>,
    random: Mutex<SecureRandom>,
    cap_token_key: Mutex<[u64; 2]>,
}

impl SecurityManager {
    pub const fn new() -> Self {
        SecurityManager {
            audit_log: Mutex::new(AuditLog::new()),
            anomaly_detector: Mutex::new(AnomalyDetector::new()),
            intent_graph: Mutex::new(IntentGraph::new()),
            validator: Mutex::new(CapabilityValidator::new()),
            rate_limiter: Mutex::new(RateLimiter::new()),
            rate_limit_enabled: AtomicBool::new(true),
            resource_tracker: Mutex::new(ResourceTracker::new()),
            random: Mutex::new(SecureRandom::new(0x1234567890ABCDEF)),
            cap_token_key: Mutex::new([0xA5A5_A5A5_5A5A_5A5A, 0x5A5A_5A5A_A5A5_A5A5]),
        }
    }

    /// Enable/disable rate limiting (used by fuzz harness).
    pub fn set_rate_limit_enabled(&self, enabled: bool) {
        self.rate_limit_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn rate_limit_enabled(&self) -> bool {
        self.rate_limit_enabled.load(Ordering::SeqCst)
    }

    /// Log security event
    pub fn log_event(&self, entry: AuditEntry) {
        let now = crate::pit::get_ticks();
        let anomaly_score = self.anomaly_detector.lock().record(entry.event, now);
        if let Some(mut log) = self.audit_log.try_lock() {
            let mut stamped = entry;
            stamped.timestamp = now;
            log.log(stamped);
            if let Some(score) = anomaly_score {
                let mut anomaly = AuditEntry::new(
                    SecurityEvent::AnomalyDetected,
                    entry.process_id,
                    entry.cap_id,
                )
                .with_context(score as u64);
                anomaly.timestamp = now;
                log.log(anomaly);
            }
        }
    }

    fn record_intent_signal(&self, process: ProcessId, signal: IntentSignal) {
        let now = crate::pit::get_ticks();
        let decision = {
            let mut graph = self.intent_graph.lock();
            graph.record(process, signal, now)
        };

        match decision {
            IntentDecision::Allow => {}
            IntentDecision::Alert(score) => {
                self.log_event(
                    AuditEntry::new(SecurityEvent::AnomalyDetected, process, 0)
                        .with_context(score as u64),
                );
            }
            IntentDecision::Restrict(score) => {
                let context = ((score as u64) << 40)
                    | ((signal.cap_type as u64) << 32)
                    | signal.rights_mask as u64;
                self.log_event(
                    AuditEntry::new(SecurityEvent::CapabilityRevoked, process, 0)
                        .with_context(context),
                );
            }
        }
    }

    pub fn intent_capability_probe(
        &self,
        process: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) {
        self.record_intent_signal(
            process,
            IntentSignal::capability_probe(cap_type, rights_mask, object_hint),
        );
    }

    pub fn intent_capability_denied(
        &self,
        process: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) {
        self.record_intent_signal(
            process,
            IntentSignal::capability_denied(cap_type, rights_mask, object_hint),
        );
    }

    pub fn intent_invalid_capability(
        &self,
        process: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) {
        self.record_intent_signal(
            process,
            IntentSignal::invalid_capability(cap_type, rights_mask, object_hint),
        );
    }

    pub fn intent_ipc_send(&self, process: ProcessId, channel_id: u64) {
        self.record_intent_signal(process, IntentSignal::ipc_send(channel_id));
    }

    pub fn intent_ipc_recv(&self, process: ProcessId, channel_id: u64) {
        self.record_intent_signal(process, IntentSignal::ipc_recv(channel_id));
    }

    pub fn intent_wasm_call(&self, process: ProcessId, host_fn: u64) {
        self.record_intent_signal(process, IntentSignal::wasm_call(host_fn));
    }

    pub fn intent_syscall(
        &self,
        process: ProcessId,
        syscall_no: u32,
        cap_type: CapabilityType,
        rights_mask: u32,
    ) {
        self.record_intent_signal(
            process,
            IntentSignal::syscall(syscall_no as u64, cap_type, rights_mask),
        );
    }

    pub fn intent_fs_read(&self, process: ProcessId, object_hint: u64) {
        self.record_intent_signal(process, IntentSignal::fs_read(object_hint));
    }

    pub fn intent_fs_write(&self, process: ProcessId, object_hint: u64) {
        self.record_intent_signal(process, IntentSignal::fs_write(object_hint));
    }

    pub fn is_predictively_restricted(
        &self,
        process: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
    ) -> bool {
        let now = crate::pit::get_ticks();
        self.intent_graph
            .lock()
            .is_restricted(process, cap_type, rights_mask, now)
    }

    pub fn get_intent_graph_stats(&self) -> IntentGraphStats {
        let now = crate::pit::get_ticks();
        self.intent_graph.lock().stats(now)
    }

    pub fn get_intent_policy(&self) -> IntentPolicy {
        self.intent_graph.lock().policy()
    }

    pub fn set_intent_policy(&self, policy: IntentPolicy) -> Result<(), IntentPolicyError> {
        self.intent_graph.lock().set_policy(policy)?;
        if !crate::temporal::is_replay_active() {
            let _ = crate::temporal::record_intent_policy_event(&policy);
        }
        Ok(())
    }

    pub fn reset_intent_policy(&self) {
        self.intent_graph.lock().reset_policy();
    }

    pub fn get_intent_process_snapshot(&self, process: ProcessId) -> Option<IntentProcessSnapshot> {
        let now = crate::pit::get_ticks();
        self.intent_graph.lock().process_snapshot(process, now)
    }

    pub fn clear_intent_restriction(&self, process: ProcessId) -> bool {
        let now = crate::pit::get_ticks();
        self.intent_graph.lock().clear_restriction(process, now)
    }

    /// Get current predictive restriction expiry tick for a process (0 if none).
    pub fn restriction_until_tick(&self, process: ProcessId) -> u64 {
        let now = crate::pit::get_ticks();
        self.intent_graph
            .lock()
            .process_snapshot(process, now)
            .map(|s| s.restriction_until_tick)
            .unwrap_or(0)
    }

    /// Consume a pending intent-based termination recommendation for process.
    pub fn take_intent_termination_recommendation(&self, process: ProcessId) -> bool {
        self.intent_graph
            .lock()
            .take_termination_recommendation(process)
    }

    fn hash_syscall_args(args: [u32; 5]) -> u32 {
        let mut h = 0x811C_9DC5u32;
        let mut i = 0usize;
        while i < args.len() {
            h ^= args[i];
            h = h.rotate_left(5).wrapping_mul(0x0100_0193);
            i += 1;
        }
        h
    }

    fn syscall_required_access(syscall_no: u32, args: [u32; 5]) -> Option<(CapabilityType, u32)> {
        match syscall_no {
            10 => Some((CapabilityType::Channel, crate::capability::Rights::CHANNEL_CREATE)),
            11 => Some((CapabilityType::Channel, crate::capability::Rights::CHANNEL_SEND)),
            12 => Some((CapabilityType::Channel, crate::capability::Rights::CHANNEL_RECEIVE)),
            13 => Some((
                CapabilityType::Channel,
                crate::capability::Rights::CHANNEL_SEND | crate::capability::Rights::CHANNEL_RECEIVE,
            )),
            14 => Some((CapabilityType::Channel, crate::capability::Rights::CHANNEL_SEND)),
            15 => Some((CapabilityType::Channel, crate::capability::Rights::CHANNEL_RECEIVE)),
            20 => {
                let flags = args[1];
                let mut rights = 0u32;
                if (flags & 0x01) != 0 {
                    rights |= crate::capability::Rights::FS_READ;
                }
                if (flags & 0x02) != 0 || (flags & 0x04) != 0 {
                    rights |= crate::capability::Rights::FS_WRITE;
                }
                if rights == 0 {
                    rights = crate::capability::Rights::FS_READ;
                }
                Some((CapabilityType::Filesystem, rights))
            }
            21 => Some((CapabilityType::Filesystem, crate::capability::Rights::FS_READ)),
            22 => Some((CapabilityType::Filesystem, crate::capability::Rights::FS_WRITE)),
            23 => Some((
                CapabilityType::Filesystem,
                crate::capability::Rights::FS_READ | crate::capability::Rights::FS_WRITE,
            )),
            24 => Some((CapabilityType::Filesystem, crate::capability::Rights::FS_DELETE)),
            25 => Some((CapabilityType::Filesystem, crate::capability::Rights::FS_LIST)),
            50 => Some((CapabilityType::Console, crate::capability::Rights::CONSOLE_WRITE)),
            51 => Some((CapabilityType::Console, crate::capability::Rights::CONSOLE_READ)),
            62 => Some((
                CapabilityType::ServicePointer,
                crate::capability::Rights::SERVICE_INVOKE,
            )),
            63 => Some((
                CapabilityType::ServicePointer,
                crate::capability::Rights::SERVICE_INVOKE,
            )),
            64 => Some((
                CapabilityType::ServicePointer,
                crate::capability::Rights::SERVICE_INTROSPECT,
            )),
            _ => None,
        }
    }

    /// Audit syscall ingress and feed intent graph.
    pub fn audit_syscall(&self, process: ProcessId, syscall_no: u32, args: [u32; 5]) {
        let args_hash = Self::hash_syscall_args(args);
        let context = ((syscall_no as u64) << 32) | args_hash as u64;
        self.log_event(
            AuditEntry::new(SecurityEvent::SyscallObserved, process, 0).with_context(context),
        );

        let (cap_type, rights) = Self::syscall_required_access(syscall_no, args)
            .unwrap_or((CapabilityType::Reserved, 0));
        self.intent_syscall(process, syscall_no, cap_type, rights);
    }

    /// Policy gate for syscall-level predictive revocation.
    pub fn syscall_policy_blocked(&self, process: ProcessId, syscall_no: u32, args: [u32; 5]) -> bool {
        let (cap_type, rights) = match Self::syscall_required_access(syscall_no, args) {
            Some(v) => v,
            None => return false,
        };
        if rights == 0 {
            return false;
        }

        if self.is_predictively_restricted(process, cap_type, rights) {
            self.intent_capability_denied(process, cap_type, rights, syscall_no as u64);
            self.log_event(
                AuditEntry::new(SecurityEvent::PermissionDenied, process, 0)
                    .with_context(syscall_no as u64),
            );
            return true;
        }
        false
    }

    /// Validate capability operation
    pub fn validate_capability(&self, process: ProcessId, required_rights: u32, actual_rights: u32) -> Result<(), SecurityError> {
        // Check rate limit
        if self.rate_limit_enabled.load(Ordering::SeqCst) {
            if !self.rate_limiter.lock().allow(process) {
                self.log_event(
                    AuditEntry::new(SecurityEvent::RateLimitExceeded, process, 0)
                );
                return Err(SecurityError::RateLimitExceeded);
            }
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
        self.intent_graph.lock().init_process(process);
        self.log_event(
            AuditEntry::new(SecurityEvent::ProcessSpawned, process, 0)
        );
    }

    /// Tear down process security context and transient detector state.
    pub fn terminate_process(&self, process: ProcessId) {
        self.resource_tracker.lock().remove_process(process);
        self.rate_limiter.lock().remove_process(process);
        self.validator.lock().clear_process(process);
        self.intent_graph.lock().deinit_process(process);
        self.log_event(
            AuditEntry::new(SecurityEvent::ProcessTerminated, process, 0)
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

    /// Sign a capability token payload using a per-boot secret key.
    pub fn cap_token_sign(&self, data: &[u8]) -> u64 {
        let key = self.cap_token_key.lock();
        siphash24(key[0], key[1], data)
    }

    /// Verify a capability token payload against a provided token.
    pub fn cap_token_verify(&self, data: &[u8], token: u64) -> bool {
        self.cap_token_sign(data) == token
    }

    /// Sign a token payload with an explicit key pair.
    /// Used by CapNet peer-session keyed verification.
    pub fn cap_token_sign_with_key(&self, k0: u64, k1: u64, data: &[u8]) -> u64 {
        siphash24(k0, k1, data)
    }

    /// Verify a token payload against an explicit key pair.
    pub fn cap_token_verify_with_key(&self, k0: u64, k1: u64, data: &[u8], token: u64) -> bool {
        self.cap_token_sign_with_key(k0, k1, data) == token
    }

    /// Derive a CapNet peer session keypair from handshake material.
    ///
    /// Note:
    /// - This expands material via the per-boot secret and is appropriate for
    ///   same-kernel or pre-shared-secret flows.
    /// - Cross-device deployments should feed a shared secret negotiated via
    ///   attestation/exchange and then call `cap_token_sign_with_key`.
    pub fn capnet_derive_session_key(
        &self,
        peer_device_id: u64,
        nonce_a: u64,
        nonce_b: u64,
        measurement_hash: u64,
        key_epoch: u32,
    ) -> [u64; 2] {
        const CONTEXT: u32 = 0x3154_5043; // "CPT1"

        let lo = core::cmp::min(nonce_a, nonce_b);
        let hi = core::cmp::max(nonce_a, nonce_b);

        let mut payload = [0u8; 40];
        payload[0..4].copy_from_slice(&CONTEXT.to_le_bytes());
        payload[4..12].copy_from_slice(&peer_device_id.to_le_bytes());
        payload[12..20].copy_from_slice(&lo.to_le_bytes());
        payload[20..28].copy_from_slice(&hi.to_le_bytes());
        payload[28..36].copy_from_slice(&measurement_hash.to_le_bytes());
        payload[36..40].copy_from_slice(&key_epoch.to_le_bytes());

        let mut p0 = [0u8; 48];
        p0[0..40].copy_from_slice(&payload);
        p0[40..48].copy_from_slice(&0u64.to_le_bytes());

        let mut p1 = [0u8; 48];
        p1[0..40].copy_from_slice(&payload);
        p1[40..48].copy_from_slice(&1u64.to_le_bytes());

        [self.cap_token_sign(&p0), self.cap_token_sign(&p1)]
    }

    /// Derive a CapNet peer session keypair from an explicit shared secret.
    ///
    /// This is the cross-device path used after remote attestation establishes
    /// a verifier trust relationship and both sides share `shared_secret`.
    pub fn capnet_derive_session_key_with_secret(
        &self,
        shared_secret: u64,
        peer_device_id: u64,
        nonce_a: u64,
        nonce_b: u64,
        measurement_hash: u64,
        key_epoch: u32,
    ) -> [u64; 2] {
        const CONTEXT: u32 = 0x3254_5043; // "CPT2"

        let lo = core::cmp::min(nonce_a, nonce_b);
        let hi = core::cmp::max(nonce_a, nonce_b);

        let mut payload = [0u8; 48];
        payload[0..4].copy_from_slice(&CONTEXT.to_le_bytes());
        payload[4..12].copy_from_slice(&peer_device_id.to_le_bytes());
        payload[12..20].copy_from_slice(&lo.to_le_bytes());
        payload[20..28].copy_from_slice(&hi.to_le_bytes());
        payload[28..36].copy_from_slice(&measurement_hash.to_le_bytes());
        payload[36..40].copy_from_slice(&key_epoch.to_le_bytes());
        payload[40..48].copy_from_slice(&shared_secret.to_le_bytes());

        let k0 = shared_secret ^ 0xA5A5_A5A5_5A5A_5A5A;
        let k1 = shared_secret.rotate_left(23) ^ 0x5A5A_5A5A_A5A5_A5A5;

        let mut p0 = [0u8; 56];
        p0[0..48].copy_from_slice(&payload);
        p0[48..56].copy_from_slice(&0u64.to_le_bytes());

        let mut p1 = [0u8; 56];
        p1[0..48].copy_from_slice(&payload);
        p1[48..56].copy_from_slice(&1u64.to_le_bytes());

        [
            self.cap_token_sign_with_key(k0, k1, &p0),
            self.cap_token_sign_with_key(k0, k1, &p1),
        ]
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

    pub fn get_anomaly_stats(&self) -> AnomalyStats {
        self.anomaly_detector.lock().snapshot(crate::pit::get_ticks())
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

pub fn temporal_apply_intent_policy(policy: IntentPolicy) -> Result<(), &'static str> {
    security()
        .set_intent_policy(policy)
        .map_err(|e| e.as_str())
}

/// Initialize security subsystem
pub fn init() {
    // Seed random number generator
    let mut seed = 0xDEADBEEF_u64;
    if let Some(r) = crate::asm_bindings::try_rdrand() {
        seed ^= ((r as u64) << 32) | r as u64;
    }
    seed ^= read_rdtsc();

    if let Some(mut random) = SECURITY.random.try_lock() {
        random.state ^= seed;
    }

    // Initialize capability token key from RNG.
    let mut key_bytes = [0u8; 16];
    SECURITY.random.lock().fill_bytes(&mut key_bytes);
    let k0 = u64::from_le_bytes([
        key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3],
        key_bytes[4], key_bytes[5], key_bytes[6], key_bytes[7],
    ]);
    let k1 = u64::from_le_bytes([
        key_bytes[8], key_bytes[9], key_bytes[10], key_bytes[11],
        key_bytes[12], key_bytes[13], key_bytes[14], key_bytes[15],
    ]);
    if let Some(mut key) = SECURITY.cap_token_key.try_lock() {
        *key = [k0, k1];
    }
}

fn read_rdtsc() -> u64 {
    #[cfg(target_arch = "x86")]
    unsafe {
        core::arch::x86::_rdtsc() as u64
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc() as u64
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        0
    }
}

#[inline]
fn rotl64(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = 0x736f6d6570736575_u64 ^ k0;
    let mut v1 = 0x646f72616e646f6d_u64 ^ k1;
    let mut v2 = 0x6c7967656e657261_u64 ^ k0;
    let mut v3 = 0x7465646279746573_u64 ^ k1;

    let mut i = 0usize;
    while i + 8 <= data.len() {
        let m = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    let mut last = (data.len() as u64) << 56;
    let rem = &data[i..];
    for (idx, &b) in rem.iter().enumerate() {
        last |= (b as u64) << (idx * 8);
    }

    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xFF;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = (*v0).wrapping_add(*v1);
    *v1 = rotl64(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl64(*v0, 32);

    *v2 = (*v2).wrapping_add(*v3);
    *v3 = rotl64(*v3, 16);
    *v3 ^= *v2;

    *v0 = (*v0).wrapping_add(*v3);
    *v3 = rotl64(*v3, 21);
    *v3 ^= *v0;

    *v2 = (*v2).wrapping_add(*v1);
    *v1 = rotl64(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl64(*v2, 32);
}
