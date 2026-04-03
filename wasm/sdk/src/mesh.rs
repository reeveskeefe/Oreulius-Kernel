// SPDX-License-Identifier: LicenseRef-Oreulius-Commercial-1.0
//! # Decentralized Kernel Mesh
//!
//! High-level wrappers for the Oreulius mesh host functions (IDs 109–115).
//!
//! The mesh subsystem lets WASM modules:
//! - Federate capability tokens across physical/virtual device boundaries.
//! - Establish capability-secured peer sessions.
//! - Migrate bytecode (and its capabilities) to a remote peer.
//!
//! ## Quick start
//! ```rust,no_run
//! use oreulius_sdk::mesh;
//!
//! // Register a peer (e.g., device obtained via mDNS / CapNet beacon).
//! let peer: u64 = 0xDEAD_BEEF_CAFE_0001;
//! mesh::peer_register(peer, true);
//!
//! // Mint a capability token valid for 10 000 ticks.
//! let object_id: u64 = 0x1234_5678_0000_0001;
//! let mut token_buf = [0u8; TOKEN_LEN];
//! mesh::token_mint(object_id, 1 /*cap_type*/, 0x03 /*rights*/, 10_000, &mut token_buf).unwrap();
//!
//! // Send it to the peer.
//! mesh::token_send(peer, &token_buf).unwrap();
//! ```

use super::raw::oreulius as sys;

/// Byte length of an encoded `CapabilityTokenV1`.
pub const TOKEN_LEN: usize = 116;

// ─────────────────────────────────────────────────────────────────────────────
// Identity
// ─────────────────────────────────────────────────────────────────────────────

/// Return the low 32 bits of this device's 64-bit CapNet device ID.
///
/// Use this value (e.g., as a rendezvous key) when advertising the node
/// to other devices on the mesh.
#[inline]
pub fn local_id() -> u32 {
    unsafe { sys::mesh_local_id() as u32 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Peer management
// ─────────────────────────────────────────────────────────────────────────────

/// Register `peer_id` as a known remote peer.
///
/// - `enforce`: when `true` the kernel sets `PeerTrustPolicy::Enforce`;
///   when `false` it sets `PeerTrustPolicy::Audit` (allows the frame
///   through while logging anomalies).
///
/// Returns `true` on success.
#[inline]
pub fn peer_register(peer_id: u64, enforce: bool) -> bool {
    let lo = (peer_id & 0xFFFF_FFFF) as i32;
    let hi = (peer_id >> 32) as i32;
    let trust = if enforce { 1 } else { 0 };
    unsafe { sys::mesh_peer_register(lo, hi, trust) == 0 }
}

/// Query the active session-key epoch for a registered peer.
///
/// Returns `Some(epoch)` (≥ 1) if a session is active, `Some(0)` if the
/// peer is registered but no session has been established, or `None` if the
/// peer is not known.
#[inline]
pub fn peer_session(peer_id: u64) -> Option<i32> {
    let lo = (peer_id & 0xFFFF_FFFF) as i32;
    let hi = (peer_id >> 32) as i32;
    let v = unsafe { sys::mesh_peer_session(lo, hi) };
    if v < 0 { None } else { Some(v) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Token operations
// ─────────────────────────────────────────────────────────────────────────────

/// Mint a signed `CapabilityTokenV1` for `object_id`.
///
/// The 116-byte encoded token is written into `out` (which must be exactly
/// [`TOKEN_LEN`] bytes long).
///
/// - `cap_type`      — numeric capability type (application-defined).
/// - `rights`        — rights bitmask (bit 0 = Read, bit 1 = Write, …).
/// - `expires_ticks` — lifetime in PIT ticks from "now".
///
/// Returns `Ok(())` on success, `Err(i32)` with the negative error code on
/// failure.
#[inline]
pub fn token_mint(
    object_id:     u64,
    cap_type:      u8,
    rights:        u32,
    expires_ticks: u32,
    out:           &mut [u8; TOKEN_LEN],
) -> Result<(), i32> {
    let obj_lo = (object_id & 0xFFFF_FFFF) as i32;
    let obj_hi = (object_id >> 32) as i32;
    let ret = unsafe {
        sys::mesh_token_mint(
            obj_lo,
            obj_hi,
            cap_type as i32,
            rights as i32,
            expires_ticks as i32,
            out.as_mut_ptr() as i32,
        )
    };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// Send the 116-byte token slice `token` to peer `peer_id`.
///
/// The kernel wraps the token in a CapNet `TokenOffer` control frame signed
/// with the current session key and emits it on the observer/network bus.
///
/// Returns `Ok(frame_len)` on success, `Err(code)` on failure.
#[inline]
pub fn token_send(peer_id: u64, token: &[u8; TOKEN_LEN]) -> Result<usize, i32> {
    let lo = (peer_id & 0xFFFF_FFFF) as i32;
    let hi = (peer_id >> 32) as i32;
    let ret = unsafe {
        sys::mesh_token_send(lo, hi, token.as_ptr() as i32, TOKEN_LEN as i32)
    };
    if ret >= 0 { Ok(ret as usize) } else { Err(ret) }
}

/// Receive a remote capability lease visible to this process as a
/// 116-byte `CapabilityTokenV1` snapshot.
///
/// Returns `Ok(())` on success or `Err(-1)` if no visible lease is
/// currently available.
#[inline]
pub fn token_recv(buf: &mut [u8; TOKEN_LEN]) -> Result<(), i32> {
    let ret = unsafe {
        sys::mesh_token_recv(buf.as_mut_ptr() as i32, TOKEN_LEN as i32)
    };
    if ret == 0 { Ok(()) } else { Err(ret) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live migration
// ─────────────────────────────────────────────────────────────────────────────

/// Queue WASM `bytecode` for live migration to `peer_id`.
///
/// The bytecode must be ≤ 64 KiB.  Pass an empty slice (`&[]`) to migrate
/// the calling module's own bytecode (the kernel fills in the source).
///
/// Returns `Ok(())` on success, `Err(-1)` if the migration queue is full,
/// or `Err(-2)` if the bytecode exceeds the size limit.
#[inline]
pub fn migrate(peer_id: u64, bytecode: &[u8]) -> Result<(), i32> {
    let lo   = (peer_id & 0xFFFF_FFFF) as i32;
    let hi   = (peer_id >> 32) as i32;
    let ptr  = if bytecode.is_empty() { core::ptr::null() } else { bytecode.as_ptr() };
    let len  = bytecode.len() as i32;
    let ret  = unsafe { sys::mesh_migrate(lo, hi, ptr as i32, len) };
    if ret == 0 { Ok(()) } else { Err(ret) }
}
