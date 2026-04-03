//! # Runtime Capability Graph Verification
//!
//! Query and verify the live delegation graph that the kernel maintains for
//! all capability transfers.  The kernel tracks every `(delegator, cap)` →
//! `(delegatee, cap)` edge and enforces two invariants at every delegation:
//!
//! 1. **No rights escalation** — delegated rights ⊆ delegator's rights.
//! 2. **No delegation cycles** — the authority graph must remain a DAG.
//!
//! ## Host functions (IDs 129–131)
//!
//! | ID  | Name                | Description |
//! |-----|---------------------|-------------|
//! | 129 | `cap_graph_query`   | Read raw delegation edges for a cap |
//! | 130 | `cap_graph_verify`  | Prospectively check a delegation for violations |
//! | 131 | `cap_graph_depth`   | Longest delegation chain length from a cap |
//!
//! ## Example
//!
//! ```rust,no_run
//! use oreulius_sdk::capgraph::{self, VerifyResult};
//!
//! // Prospectively check: would delegating cap_id to process 5 create a cycle?
//! match capgraph::verify(my_cap, 5) {
//!     VerifyResult::Safe           => { /* proceed */ }
//!     VerifyResult::Cycle          => panic!("cycle!"),
//!     VerifyResult::RightsEscalation => panic!("escalation!"),
//!     VerifyResult::NotFound       => panic!("cap not found"),
//! }
//!
//! // Query how deep the delegation chain goes from my_cap.
//! let depth = capgraph::depth(my_cap);
//! ```

use super::raw::oreulius as raw;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single delegation edge as returned by [`query`].
///
/// Semantics: `from_pid` delegated capability `from_cap` to `to_pid` who
/// received it as `to_cap`, with rights bitmask `rights`.
#[derive(Clone, Copy, Debug)]
pub struct DelegationEdge {
    pub from_pid:  u32,
    pub from_cap:  u32,
    pub to_pid:    u32,
    pub to_cap:    u32,
    /// Rights bitmask on the delegated capability.
    pub rights:    u32,
}

/// Result of a prospective invariant check via [`verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// The delegation would be safe.
    Safe,
    /// The delegation would create a rights escalation.
    RightsEscalation,
    /// The delegation would create a cycle in the authority graph.
    Cycle,
    /// The capability was not found (not owned by this process).
    NotFound,
}

/// Fixed-capacity list of delegation edges returned by [`query`].
#[derive(Clone, Copy)]
pub struct EdgeList {
    data: [DelegationEdge; 16],
    len:  usize,
}

impl EdgeList {
    #[inline]
    pub fn as_slice(&self) -> &[DelegationEdge] { &self.data[..self.len] }
    #[inline]
    pub fn len(&self) -> usize { self.len }
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/// Query the live delegation edges for `cap_id` owned by this process.
///
/// Returns up to 16 edges.  Returns `None` if no delegations exist.
#[inline]
pub fn query(cap_id: u32) -> Option<EdgeList> {
    // 16 edge slots × 20 bytes each = 320 bytes on the stack.
    let mut buf = [0u8; 16 * 20];
    let rc = unsafe {
        raw::cap_graph_query(cap_id as i32, buf.as_mut_ptr() as i32, 16)
    };
    if rc < 0 {
        return None;
    }
    let n = rc as usize;
    let mut list = EdgeList {
        data: [DelegationEdge { from_pid: 0, from_cap: 0, to_pid: 0, to_cap: 0, rights: 0 }; 16],
        len: 0,
    };
    let mut i = 0usize;
    while i < n && i < 16 {
        let off = i * 20;
        let from_pid  = u32::from_le_bytes([buf[off],   buf[off+1],  buf[off+2],  buf[off+3]]);
        let from_cap  = u32::from_le_bytes([buf[off+4], buf[off+5],  buf[off+6],  buf[off+7]]);
        let to_pid    = u32::from_le_bytes([buf[off+8], buf[off+9],  buf[off+10], buf[off+11]]);
        let to_cap    = u32::from_le_bytes([buf[off+12],buf[off+13], buf[off+14], buf[off+15]]);
        let rights    = u32::from_le_bytes([buf[off+16],buf[off+17], buf[off+18], buf[off+19]]);
        list.data[i] = DelegationEdge { from_pid, from_cap, to_pid, to_cap, rights };
        i += 1;
    }
    list.len = n.min(16);
    Some(list)
}

/// Prospectively check whether delegating `cap_id` to `delegatee_pid` would
/// violate a graph invariant **without actually performing the delegation**.
///
/// Use this before calling `capability::transfer` to get an early warning.
#[inline]
pub fn verify(cap_id: u32, delegatee_pid: u32) -> VerifyResult {
    let rc = unsafe { raw::cap_graph_verify(cap_id as i32, delegatee_pid as i32) };
    match rc {
        0 => VerifyResult::Safe,
        1 => VerifyResult::RightsEscalation,
        2 => VerifyResult::Cycle,
        _ => VerifyResult::NotFound,
    }
}

/// Return the longest delegation chain length reachable from `cap_id`.
///
/// - `0` means the capability has never been delegated to another process.
/// - `N` means there is a chain of N hops (capped at 32 by the kernel).
#[inline]
pub fn depth(cap_id: u32) -> u32 {
    let rc = unsafe { raw::cap_graph_depth(cap_id as i32) };
    if rc < 0 { 0 } else { rc as u32 }
}

// ---------------------------------------------------------------------------
// Convenience — assert-safe wrappers
// ---------------------------------------------------------------------------

/// Verify that delegating `cap_id` to `delegatee_pid` is safe, and return
/// `Err(VerifyResult)` if any invariant would be violated.
///
/// Typical use: call this right before `capability::transfer`.
#[inline]
pub fn assert_safe(cap_id: u32, delegatee_pid: u32) -> Result<(), VerifyResult> {
    match verify(cap_id, delegatee_pid) {
        VerifyResult::Safe => Ok(()),
        v                  => Err(v),
    }
}
