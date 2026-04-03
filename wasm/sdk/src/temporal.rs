// SPDX-License-Identifier: LicenseRef-Oreulius-Commercial-1.0
//! # Temporal Capabilities with Revocable History
//!
//! High-level wrappers for the Oreulius temporal capability host functions
//! (IDs 116–120).
//!
//! ## Concept
//! Capabilities in Oreulius are not just static access grants — they are
//! *temporal objects* bound to time or *transactional checkpoints*.
//!
//! - **Time-bound grants**: a capability expires automatically after a
//!   configurable number of 100 Hz PIT ticks.  No polling required; the kernel
//!   auto-revokes at the deadline.
//! - **Checkpoint + rollback**: the calling process can snapshot its entire
//!   capability set, perform operations, then roll back to the snapshot if
//!   something goes wrong — like a database transaction, but for kernel access.
//!
//! ## Quick start
//! ```rust,no_run
//! use oreulius_sdk::temporal;
//!
//! // Grant FS-read access for ~10 seconds (100 Hz × 1000 ticks).
//! let cap_id = temporal::cap_grant(14 /*FS_READ cap_type*/, 0x4000 /*FS_READ rights*/, 1000)
//!     .expect("grant failed");
//!
//! // Check remaining lifetime.
//! let remaining = temporal::cap_check(cap_id);   // Some(ticks) or None
//!
//! // Create a checkpoint before a risky operation.
//! let cp = temporal::checkpoint_create().expect("no checkpoint slots");
//!
//! // … do stuff …
//!
//! // If something went wrong, roll back the capability set.
//! temporal::checkpoint_rollback(cp).expect("rollback failed");
//! ```

use super::raw::oreulius as sys;

// ─────────────────────────────────────────────────────────────────────────────
// Time-bound capability grants
// ─────────────────────────────────────────────────────────────────────────────

/// Grant the calling process a time-bound capability.
///
/// - `cap_type`      — numeric capability type (see `oreulius_sdk::capability`
///   or the kernel `CapabilityType` enum).
/// - `rights`        — rights bitmask.
/// - `expires_ticks` — lifetime in 100 Hz PIT ticks.  At tick 0 the kernel
///   auto-revokes the capability.
///
/// Returns `Ok(cap_id)` on success, `Err(code)` on failure.
/// Common error codes:
/// - `-1` — invalid `cap_type`
/// - `-2` — capability table full for this process
/// - `-3` — temporal expiry table full
#[inline]
pub fn cap_grant(cap_type: u8, rights: u32, expires_ticks: u32) -> Result<u32, i32> {
    let ret = unsafe {
        sys::temporal_cap_grant(cap_type as i32, rights as i32, expires_ticks as i32)
    };
    if ret >= 0 { Ok(ret as u32) } else { Err(ret) }
}

/// Manually revoke a time-bound (or any) capability held by this process.
///
/// Returns `Ok(())` on success or `Err(-1)` if the capability was not found.
#[inline]
pub fn cap_revoke(cap_id: u32) -> Result<(), i32> {
    let ret = unsafe { sys::temporal_cap_revoke(cap_id as i32) };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// Query the remaining lifetime of a time-bound capability.
///
/// Returns `Some(ticks)` (may be `0` if expiring this tick) or `None` if
/// the `cap_id` is not found or not time-bound.
#[inline]
pub fn cap_check(cap_id: u32) -> Option<u32> {
    let ret = unsafe { sys::temporal_cap_check(cap_id as i32) };
    if ret >= 0 { Some(ret as u32) } else { None }
}

// ─────────────────────────────────────────────────────────────────────────────
// Capability checkpoint & rollback
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot the calling process's current capability set.
///
/// Returns `Ok(checkpoint_id)` (≥ 1) on success, or `Err(-1)` if the
/// checkpoint store is full (at most 8 outstanding checkpoints).
#[inline]
pub fn checkpoint_create() -> Result<u32, i32> {
    let ret = unsafe { sys::temporal_checkpoint_create() };
    if ret >= 0 { Ok(ret as u32) } else { Err(ret) }
}

/// Roll back the calling process's capability set to the named checkpoint.
///
/// All capabilities granted *after* the checkpoint are revoked; the
/// snapshotted set is re-granted from the kernel's temporal log.
///
/// Returns `Ok(())` on success, or:
/// - `Err(-1)` — checkpoint not found or not owned by this process
/// - `Err(-2)` — re-grant failure (insufficient kernel resources)
#[inline]
pub fn checkpoint_rollback(checkpoint_id: u32) -> Result<(), i32> {
    let ret = unsafe { sys::temporal_checkpoint_rollback(checkpoint_id as i32) };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoped guard
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that automatically revokes a time-bound capability when dropped.
///
/// ```rust,no_run
/// use oreulius_sdk::temporal::{TemporalCap, cap_grant};
///
/// let _guard = TemporalCap::new(cap_grant(14, 0x4000, 500).unwrap());
/// // … do work that requires FS_READ …
/// // capability is revoked when `_guard` drops
/// ```
pub struct TemporalCap {
    cap_id: u32,
}

impl TemporalCap {
    /// Wrap an existing `cap_id` in a revoke-on-drop guard.
    #[inline]
    pub fn new(cap_id: u32) -> Self {
        TemporalCap { cap_id }
    }

    /// Return the underlying capability ID.
    #[inline]
    pub fn id(&self) -> u32 {
        self.cap_id
    }
}

impl Drop for TemporalCap {
    fn drop(&mut self) {
        let _ = cap_revoke(self.cap_id);
    }
}

/// RAII guard that automatically rolls back to a capability checkpoint when
/// dropped, unless `commit()` is called first.
///
/// ```rust,no_run
/// use oreulius_sdk::temporal::{CapTransaction, checkpoint_create};
///
/// let tx = CapTransaction::begin().unwrap();
/// // … grant extra caps, do work …
/// tx.commit(); // don't roll back
/// ```
pub struct CapTransaction {
    checkpoint_id: u32,
    committed:     bool,
}

impl CapTransaction {
    /// Create a checkpoint and return a transaction guard.
    ///
    /// Returns `Err(-1)` if the checkpoint store is full.
    #[inline]
    pub fn begin() -> Result<Self, i32> {
        let id = checkpoint_create()?;
        Ok(CapTransaction { checkpoint_id: id, committed: false })
    }

    /// Commit the transaction — no rollback will occur on drop.
    #[inline]
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for CapTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = checkpoint_rollback(self.checkpoint_id);
        }
    }
}
