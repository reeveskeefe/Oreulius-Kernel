//! # Intensional Kernel: Policy-as-Capability-Contracts
//!
//! Bind executable policy contracts to capabilities so that every access
//! decision can be evaluated against live context rather than static ACLs.
//!
//! ## OPOL stub format
//!
//! For lightweight deterministic policies you don't need full WASM bytecode.
//! Build an 8-byte OPOL stub with [`opol_stub`]:
//!
//! ```text
//! Byte 0-3 : b'O' b'P' b'O' b'L'  (magic)
//! Byte 4   : default_permit          (1 = permit when ctx is short)
//! Byte 5   : min_ctx_len             (ctx must be at least this many bytes)
//! Byte 6   : ctx_byte0_eq            (1 = inspect ctx[0], 0 = skip)
//! Byte 7   : ctx_byte0_val           (if ctx[0] != this → deny)
//! ```
//!
//! ## Full WASM contracts
//!
//! A 4 KiB WASM bytecode blob can be bound with [`bind`].  The kernel will
//! invoke the contract synchronously when [`eval`] is called.  In the current
//! implementation full-WASM contracts **fail-open** (permit) when the
//! contract interpreter is not yet wired in; use OPOL stubs for hard denials.
//!
//! ## Example
//!
//! ```rust,no_run
//! use oreulia_sdk::policy::{self, PolicyResult};
//!
//! let stub = policy::opol_stub(true, 1, true, 0xAA);
//! policy::bind(my_cap, &stub).expect("bind failed");
//!
//! let ctx = [0xAAu8, 42, 7];
//! assert_eq!(policy::eval(my_cap, &ctx), PolicyResult::Permit);
//! ```

use super::raw::oreulia as raw;

// ---------------------------------------------------------------------------
// Public result type
// ---------------------------------------------------------------------------

/// The result of evaluating a policy contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResult {
    /// The policy explicitly permits the operation.
    Permit,
    /// The policy explicitly denies the operation.
    Deny,
    /// No policy is bound to this capability (fail-open: treated as permit).
    NoPolicyBound,
}

// ---------------------------------------------------------------------------
// Policy metadata returned by `query`
// ---------------------------------------------------------------------------

/// Metadata about a bound policy contract.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInfo {
    /// FNV-1a hash of the bytecode as stored by the kernel.
    pub hash: u64,
    /// Stored bytecode length in bytes.
    pub wasm_len: u16,
    /// `true` if a contract is currently bound to this cap.
    pub bound: bool,
    /// The capability ID this policy is bound to.
    pub cap_id: u32,
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

/// Bind a policy contract to `cap_id`.
///
/// `bytecode` may be:
/// - An 8-byte OPOL stub (see [`opol_stub`]).
/// - Up to 4 096 bytes of raw WASM bytecode.
///
/// # Errors
///
/// Returns the raw host error code on failure:
/// - `-1` — capability not found.
/// - `-2` — bytecode too large (> 4 096 bytes).
/// - `-3` — policy store full (max 16 slots).
#[inline]
pub fn bind(cap_id: u32, bytecode: &[u8]) -> Result<(), i32> {
    let rc = unsafe {
        raw::policy_bind(
            cap_id as i32,
            bytecode.as_ptr() as i32,
            bytecode.len() as i32,
        )
    };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Remove the policy contract bound to `cap_id`.
///
/// Returns `Ok(())` if a contract was found and removed, `Err(-1)` if none
/// was bound.
#[inline]
pub fn unbind(cap_id: u32) -> Result<(), i32> {
    let rc = unsafe { raw::policy_unbind(cap_id as i32) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Evaluate the policy contract bound to `cap_id` against `ctx`.
///
/// `ctx` is arbitrary caller-defined context bytes passed to the contract.
/// For OPOL stubs the first byte is compared against the configured value.
///
/// Returns [`PolicyResult::NoPolicyBound`] (fail-open) when no contract is
/// bound.
#[inline]
pub fn eval(cap_id: u32, ctx: &[u8]) -> PolicyResult {
    let rc = unsafe {
        raw::policy_eval(
            cap_id as i32,
            ctx.as_ptr() as i32,
            ctx.len() as i32,
        )
    };
    match rc {
        0  => PolicyResult::Permit,
        1  => PolicyResult::Deny,
        _  => PolicyResult::NoPolicyBound,
    }
}

/// Query metadata about the policy contract bound to `cap_id`.
///
/// Returns `None` if no contract is bound or the host reported an error.
#[inline]
pub fn query(cap_id: u32) -> Option<PolicyInfo> {
    let mut buf = [0u8; 16];
    let rc = unsafe {
        raw::policy_query(
            cap_id as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if rc != 0 {
        return None;
    }
    let hash     = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let wasm_len = u16::from_le_bytes(buf[8..10].try_into().ok()?);
    let bound    = buf[10] != 0;
    let cap_id_r = u32::from_le_bytes(buf[12..16].try_into().ok()?);
    Some(PolicyInfo { hash, wasm_len, bound, cap_id: cap_id_r })
}

// ---------------------------------------------------------------------------
// OPOL stub builder
// ---------------------------------------------------------------------------

/// Build an 8-byte **OPOL** policy stub.
///
/// | Parameter       | Meaning |
/// |-----------------|---------|
/// | `default_permit`| When `ctx.len() < min_ctx_len`, permit (true) or deny |
/// | `min_ctx_len`   | Minimum required context length |
/// | `check_byte0`   | If `true`, inspect `ctx[0]` |
/// | `byte0_val`     | Required value of `ctx[0]` when `check_byte0` is set |
///
/// The returned array can be passed directly to [`bind`].
#[inline(always)]
pub const fn opol_stub(
    default_permit: bool,
    min_ctx_len:    u8,
    check_byte0:    bool,
    byte0_val:      u8,
) -> [u8; 8] {
    [
        b'O', b'P', b'O', b'L',
        default_permit as u8,
        min_ctx_len,
        check_byte0 as u8,
        byte0_val,
    ]
}

// ---------------------------------------------------------------------------
// RAII guard — PolicyGuard
// ---------------------------------------------------------------------------

/// A scoped policy binding that automatically unbinds when dropped.
///
/// # Example
///
/// ```rust,no_run
/// let _guard = PolicyGuard::bind(my_cap, &opol_stub(true, 0, false, 0))
///     .expect("bind failed");
/// // policy is active here …
/// // automatically unbound when _guard is dropped
/// ```
pub struct PolicyGuard {
    cap_id: u32,
}

impl PolicyGuard {
    /// Bind `bytecode` to `cap_id` and return a guard that unbinds on drop.
    #[inline]
    pub fn bind(cap_id: u32, bytecode: &[u8]) -> Result<Self, i32> {
        bind(cap_id, bytecode)?;
        Ok(Self { cap_id })
    }

    /// Evaluate the bound policy against `ctx` without releasing the guard.
    #[inline]
    pub fn eval(&self, ctx: &[u8]) -> PolicyResult {
        eval(self.cap_id, ctx)
    }

    /// Consume the guard without unbinding (the policy remains active).
    #[inline]
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl Drop for PolicyGuard {
    #[inline]
    fn drop(&mut self) {
        let _ = unbind(self.cap_id);
    }
}
