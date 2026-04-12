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

const MAX_GRAPH_EDGES: usize = 16;
const MAX_DELEGATION_DEPTH: u32 = 32;

#[inline]
fn query_len_from_rc(rc: i32) -> Option<usize> {
    if rc <= 0 {
        return None;
    }

    let len = rc as usize;
    if len > MAX_GRAPH_EDGES {
        None
    } else {
        Some(len)
    }
}

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
#[must_use]
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

impl VerifyResult {
    /// Returns `true` if the prospective delegation is safe.
    #[inline]
    pub const fn is_safe(self) -> bool {
        match self {
            VerifyResult::Safe => true,
            _ => false,
        }
    }
}

/// Fixed-capacity list of delegation edges returned by [`query`].
#[must_use]
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
    /// Return the delegation edge at `index`, if present.
    #[inline]
    pub fn get(&self, index: usize) -> Option<DelegationEdge> {
        self.as_slice().get(index).copied()
    }
    /// Iterate over the live delegation edges.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, DelegationEdge> {
        self.as_slice().iter()
    }
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/// Query the live delegation edges for `cap_id` owned by this process.
///
/// Returns up to 16 edges.  Returns `None` if no delegations exist or the
/// host reports an invalid count larger than the fixed-capacity buffer.
#[inline]
pub fn query(cap_id: u32) -> Option<EdgeList> {
    // 16 edge slots × 20 bytes each = 320 bytes on the stack.
    let mut buf = [0u8; 16 * 20];
    let rc = unsafe {
        raw::cap_graph_query(cap_id as i32, buf.as_mut_ptr() as i32, 16)
    };
    let n = query_len_from_rc(rc)?;
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
    list.len = n;
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
///   Host responses above 32 are clamped to the documented ceiling.
#[inline]
pub fn depth(cap_id: u32) -> u32 {
    let rc = unsafe { raw::cap_graph_depth(cap_id as i32) };
    if rc <= 0 {
        0
    } else {
        (rc as u32).min(MAX_DELEGATION_DEPTH)
    }
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
    let result = verify(cap_id, delegatee_pid);
    if result.is_safe() {
        Ok(())
    } else {
        Err(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_len_from_rc_rejects_nonpositive_and_overlarge_counts() {
        assert_eq!(query_len_from_rc(-1), None);
        assert_eq!(query_len_from_rc(0), None);
        assert_eq!(query_len_from_rc(1), Some(1));
        assert_eq!(query_len_from_rc(MAX_GRAPH_EDGES as i32), Some(MAX_GRAPH_EDGES));
        assert_eq!(query_len_from_rc(MAX_GRAPH_EDGES as i32 + 1), None);
    }

    #[test]
    fn verify_result_is_safe_only_for_safe() {
        assert!(VerifyResult::Safe.is_safe());
        assert!(!VerifyResult::Cycle.is_safe());
        assert!(!VerifyResult::RightsEscalation.is_safe());
        assert!(!VerifyResult::NotFound.is_safe());
    }

    #[test]
    fn edge_list_accessors_cover_slice_helpers() {
        let list = EdgeList {
            data: [
                DelegationEdge {
                    from_pid: 1,
                    from_cap: 11,
                    to_pid: 2,
                    to_cap: 22,
                    rights: 0x1,
                },
                DelegationEdge {
                    from_pid: 3,
                    from_cap: 33,
                    to_pid: 4,
                    to_cap: 44,
                    rights: 0x2,
                },
                DelegationEdge {
                    from_pid: 5,
                    from_cap: 55,
                    to_pid: 6,
                    to_cap: 66,
                    rights: 0x3,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
                DelegationEdge {
                    from_pid: 0,
                    from_cap: 0,
                    to_pid: 0,
                    to_cap: 0,
                    rights: 0,
                },
            ],
            len: 3,
        };

        assert_eq!(list.get(0).map(|e| e.from_cap), Some(11));
        assert_eq!(list.get(1).map(|e| e.to_cap), Some(44));
        assert!(list.get(3).is_none());
        let mut iter = list.iter();
        assert_eq!(iter.next().map(|e| e.from_pid), Some(1));
        assert_eq!(iter.next().map(|e| e.to_cap), Some(44));
        assert_eq!(iter.next().map(|e| e.rights), Some(0x3));
        assert!(iter.next().is_none());
    }
}
