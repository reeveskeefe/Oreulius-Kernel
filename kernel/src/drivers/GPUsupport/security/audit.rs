// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


/*!
 * GPU subsystem audit log.
 *
 * A fixed-capacity ring buffer that records security-relevant GPU events.
 * The buffer holds `GPU_AUDIT_LOG_SIZE` entries; older entries are
 * overwritten when the ring is full (lossy by design — this is a
 * kernel-internal audit log, not a persistent record).
 *
 * # Thread safety
 * The global `GPU_AUDIT_LOG` is protected by a `spin::Mutex`.
 * Push operations are O(1) and must not block; do not call blocking
 * operations from within the lock.
 */

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const GPU_AUDIT_LOG_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Event kinds (extended from the original enum)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpuAuditEvent {
    Probe = 0,
    Activate = 1,
    FenceTimeout = 2,
    FirmwareRejected = 3,
    IommuBind = 4,
    IommuUnbind = 5,
    PageFault = 6,
    EngineHang = 7,
    BoAllocated = 8,
    BoFreed = 9,
    OwnerPurge = 10,
    AccessDenied = 11,
}

// ---------------------------------------------------------------------------
// Audit entry
// ---------------------------------------------------------------------------

/// A 24-byte audit record.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GpuAuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Additional event-specific data (fence ID, BO ID, PID, etc.).
    pub data: u64,
    /// Event kind.
    pub event: GpuAuditEvent,
    /// PID of the associated process (0 = kernel).
    pub pid: u32,
    _pad: [u8; 3],
}

static NEXT_AUDIT_SEQ: AtomicU32 = AtomicU32::new(1);

impl GpuAuditEntry {
    pub fn new(event: GpuAuditEvent, pid: u32, data: u64) -> Self {
        GpuAuditEntry {
            seq: NEXT_AUDIT_SEQ.fetch_add(1, Ordering::Relaxed) as u64,
            data,
            event,
            pid,
            _pad: [0u8; 3],
        }
    }
}

// ---------------------------------------------------------------------------
// Audit ring buffer
// ---------------------------------------------------------------------------

struct GpuAuditLog {
    ring: [Option<GpuAuditEntry>; GPU_AUDIT_LOG_SIZE],
    head: usize, // Next write index (wraps)
    total: u64,  // Total events ever pushed (not bounded by ring size)
}

impl GpuAuditLog {
    const fn new() -> Self {
        GpuAuditLog {
            ring: [None; GPU_AUDIT_LOG_SIZE],
            head: 0,
            total: 0,
        }
    }

    fn push(&mut self, entry: GpuAuditEntry) {
        self.ring[self.head] = Some(entry);
        self.head = (self.head + 1) % GPU_AUDIT_LOG_SIZE;
        self.total += 1;
    }

    /// Iterate over entries in chronological order (oldest → newest).
    ///
    /// Returns an iterator that yields up to `GPU_AUDIT_LOG_SIZE` entries.
    fn iter_chrono(&self) -> impl Iterator<Item = &GpuAuditEntry> {
        let len = GPU_AUDIT_LOG_SIZE;
        // The oldest entry is at `head` (the slot about to be overwritten).
        let head = self.head;
        (0..len)
            .map(move |i| (head + i) % len)
            .filter_map(move |idx| self.ring[idx].as_ref())
    }

    fn count(&self) -> u64 {
        self.total
    }
}

static GPU_AUDIT_LOG: Mutex<GpuAuditLog> = Mutex::new(GpuAuditLog::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Append a GPU audit event.
pub fn log_event(event: GpuAuditEvent, pid: u32, data: u64) {
    let entry = GpuAuditEntry::new(event, pid, data);
    GPU_AUDIT_LOG.lock().push(entry);
}

/// Convenience wrapper — no associated data.
pub fn log(event: GpuAuditEvent) {
    log_event(event, 0, 0);
}

/// Total number of events ever pushed (monotonically increasing).
pub fn total_events() -> u64 {
    GPU_AUDIT_LOG.lock().count()
}

/// Drain up to `max` entries into the provided buffer, oldest first.
///
/// Returns the number of entries written.
pub fn drain_into(buf: &mut [GpuAuditEntry]) -> usize {
    let log = GPU_AUDIT_LOG.lock();
    let mut n = 0;
    for entry in log.iter_chrono() {
        if n >= buf.len() {
            break;
        }
        buf[n] = *entry;
        n += 1;
    }
    n
}
