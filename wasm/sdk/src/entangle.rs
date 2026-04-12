//! # Quantum-Inspired Capability Entanglement
//!
//! Link capabilities together so that revoking any one automatically cascades
//! revocation to all its entangled peers.  This mirrors quantum entanglement:
//! once linked, the fate of each capability is inseparable from the others.
//!
//! ## How it works
//!
//! 1. **Pairwise entanglement** ([`entangle`]): link two capabilities.
//!    Revoking either one revokes the other.
//!
//! 2. **Group entanglement** ([`entangle_group`]): link N capabilities into a
//!    named group.  The kernel stores a star topology internally; revoking any
//!    member cascades to all others in the group.
//!
//! 3. **Disentanglement** ([`disentangle`]): sever all entanglement links for
//!    a capability without revoking it.
//!
//! 4. **Query** ([`entangle_query`]): list all caps currently entangled with a
//!    given cap.
//!
//! ## Example
//!
//! ```rust,no_run
//! use oreulius_sdk::entangle;
//!
//! // Pairwise: revoking cap_a will also revoke cap_b.
//! entangle::entangle(cap_a, cap_b).expect("entangle failed");
//!
//! // Group: revoking any member revokes all.
//! let group_id = entangle::entangle_group(&[cap_x, cap_y, cap_z])
//!     .expect("group failed");
//!
//! // Query what cap_a is linked to.
//! let peers = entangle::entangle_query(cap_a).unwrap_or_default();
//! ```

use super::raw::oreulius as raw;

const MAX_ENTANGLE_PEERS: usize = 32;

#[inline]
fn positive_id_from_rc(rc: i32) -> Result<u32, i32> {
    match rc {
        r if r > 0 => Ok(r as u32),
        r if r < 0 => Err(r),
        _ => Err(-1),
    }
}

#[inline]
fn query_len_from_rc(rc: i32) -> Option<usize> {
    if rc <= 0 {
        return None;
    }

    let len = rc as usize;
    if len > MAX_ENTANGLE_PEERS {
        None
    } else {
        Some(len)
    }
}

// ---------------------------------------------------------------------------
// Core entanglement API
// ---------------------------------------------------------------------------

/// Link two capabilities owned by this process.
///
/// After this call, revoking either `cap_a` or `cap_b` will automatically
/// trigger revocation of the other.
///
/// # Errors
///
/// | Code | Meaning |
/// |------|---------|
/// | `-1` | `cap_a` not found / not owned by this process |
/// | `-2` | `cap_b` not found / not owned by this process |
/// | `-3` | entanglement table full (max 128 links) |
#[inline]
pub fn entangle(cap_a: u32, cap_b: u32) -> Result<(), i32> {
    let rc = unsafe { raw::cap_entangle(cap_a as i32, cap_b as i32) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Entangle a group of capabilities (up to 32).
///
/// All caps must be owned by the calling process.  A star topology is used
/// internally: revoking any member cascades to all others.
///
/// Returns the **group ID** (a positive `u32`) on success.
///
/// # Errors
///
/// | Code | Meaning |
/// |------|---------|
/// | `-1` | Invalid group size (must be 2–32) |
/// | `-2` | One or more cap IDs not found |
/// | `-3` | Not enough free link slots |
#[inline]
pub fn entangle_group(caps: &[u32]) -> Result<u32, i32> {
    if caps.len() < 2 || caps.len() > 32 {
        return Err(-1);
    }
    let rc = unsafe {
        raw::cap_entangle_group(caps.as_ptr() as i32, caps.len() as i32)
    };
    positive_id_from_rc(rc)
}

/// Remove all entanglement links involving `cap_id` for this process.
///
/// The capability itself is **not** revoked; only the linkage is removed.
///
/// Returns `Ok(())` if at least one link was removed, `Err(-1)` if none
/// existed.
#[inline]
pub fn disentangle(cap_id: u32) -> Result<(), i32> {
    let rc = unsafe { raw::cap_disentangle(cap_id as i32) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Return the cap IDs currently entangled with `cap_id`.
///
/// Returns `None` if `cap_id` has no entanglement links or the host reports
/// an invalid count.  Uses a fixed-size 32-slot read; caps beyond the 32nd
/// link will be omitted by the kernel and rejected here if the reported count
/// exceeds the fixed-capacity buffer.
#[inline]
pub fn entangle_query(cap_id: u32) -> Option<EntangleList> {
    let mut buf = [0u32; 32];
    let rc = unsafe {
        raw::cap_entangle_query(
            cap_id as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    let len = query_len_from_rc(rc)?;
    Some(EntangleList { data: buf, len })
}

// ---------------------------------------------------------------------------
// EntangleList — fixed-capacity list of entangled cap IDs
// ---------------------------------------------------------------------------

/// A fixed-capacity list of entangled capability IDs returned by
/// [`entangle_query`].
#[must_use]
#[derive(Clone, Copy)]
pub struct EntangleList {
    data: [u32; 32],
    len:  usize,
}

impl EntangleList {
    /// Returns a slice of the entangled cap IDs.
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        &self.data[..self.len]
    }

    /// Number of entangled caps.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return the entangled capability ID at `index`, if present.
    #[inline]
    pub fn get(&self, index: usize) -> Option<u32> {
        self.as_slice().get(index).copied()
    }

    /// Iterate over the entangled capability IDs.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u32> {
        self.as_slice().iter()
    }

    /// Returns `true` if `cap_id` is present in the entanglement set.
    #[inline]
    pub fn contains(&self, cap_id: u32) -> bool {
        self.as_slice().contains(&cap_id)
    }

    /// Returns `true` if the list is empty (should not happen for a valid
    /// result from [`entangle_query`]).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// RAII guard — EntangleGuard
// ---------------------------------------------------------------------------

/// A pairwise entanglement that is automatically severed when dropped.
///
/// Note: the capabilities themselves are **not** revoked on drop; only the
/// entanglement link is removed.
///
/// # Example
///
/// ```rust,no_run
/// let _guard = EntangleGuard::new(cap_a, cap_b).expect("entangle failed");
/// // caps are linked here …
/// // automatically disentangled when _guard is dropped
/// ```
#[must_use]
pub struct EntangleGuard {
    cap_a: u32,
    cap_b: u32,
}

impl EntangleGuard {
    /// Entangle `cap_a` and `cap_b` and return a guard that disentangles
    /// both on drop.
    #[inline]
    pub fn new(cap_a: u32, cap_b: u32) -> Result<Self, i32> {
        entangle(cap_a, cap_b)?;
        Ok(Self { cap_a, cap_b })
    }

    /// Consume the guard without disentangling (the link remains active).
    #[inline]
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl Drop for EntangleGuard {
    #[inline]
    fn drop(&mut self) {
        let _ = disentangle(self.cap_a);
        let _ = disentangle(self.cap_b);
    }
}

// ---------------------------------------------------------------------------
// GroupEntangleGuard
// ---------------------------------------------------------------------------

/// A group entanglement that is automatically severed when dropped.
///
/// The capabilities themselves are not revoked on drop; only the group
/// linkage is removed.
#[must_use]
pub struct GroupEntangleGuard {
    group_id: u32,
    /// Cap IDs in the group (for disentanglement on drop).
    caps: [u32; 32],
    len:  usize,
}

impl GroupEntangleGuard {
    /// Entangle a group of caps and return a guard.
    #[inline]
    pub fn new(caps: &[u32]) -> Result<Self, i32> {
        let group_id = entangle_group(caps)?;
        let mut arr  = [0u32; 32];
        let len      = caps.len().min(32);
        let mut i    = 0usize;
        while i < len { arr[i] = caps[i]; i += 1; }
        Ok(Self { group_id, caps: arr, len })
    }

    /// The group ID assigned by the kernel.
    #[inline]
    pub fn group_id(&self) -> u32 { self.group_id }

    /// Consume the guard without disentangling.
    #[inline]
    pub fn leak(self) {
        core::mem::forget(self);
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
        assert_eq!(query_len_from_rc(MAX_ENTANGLE_PEERS as i32), Some(MAX_ENTANGLE_PEERS));
        assert_eq!(query_len_from_rc(MAX_ENTANGLE_PEERS as i32 + 1), None);
    }

    #[test]
    fn positive_id_from_rc_rejects_zero_but_preserves_negative_errors() {
        assert_eq!(positive_id_from_rc(7), Ok(7));
        assert_eq!(positive_id_from_rc(0), Err(-1));
        assert_eq!(positive_id_from_rc(-3), Err(-3));
    }

    #[test]
    fn entangle_list_accessors_cover_slice_helpers() {
        let list = EntangleList {
            data: [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 3,
        };

        assert_eq!(list.get(0), Some(10));
        assert_eq!(list.get(2), Some(30));
        assert_eq!(list.get(3), None);
        assert!(list.contains(20));
        assert!(!list.contains(99));
        let mut iter = list.iter();
        assert_eq!(iter.next(), Some(&10));
        assert_eq!(iter.next(), Some(&20));
        assert_eq!(iter.next(), Some(&30));
        assert_eq!(iter.next(), None);
    }
}

impl Drop for GroupEntangleGuard {
    fn drop(&mut self) {
        let mut i = 0usize;
        while i < self.len {
            let _ = disentangle(self.caps[i]);
            i += 1;
        }
    }
}
