/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Shared intent-graph CTMC data.
//!
//! This module is the single source of truth for the transition matrix used by
//! both the runtime intent graph and the build-time spectral checker.

pub const INTENT_NODE_COUNT: usize = 9;
pub const CTMC_SCALE: i32 = 1024;

/// CTMC integer-scaled (×1024) generator matrix Q for the 9 IntentNode states.
///
/// Rows represent "from" states (indexed by IntentNode discriminant).
/// Columns represent "to" states.
/// Row sums must equal zero (holding time on diagonal = -sum of off-diagonal row).
///
/// Rates are empirical starting points; calibrate from production telemetry.
/// Fixed-point ×1024 allows first-order Euler steps in pure integer arithmetic:
///   P(t+dt) ≈ P(t) + P(t)·Q·dt   where dt is expressed in 1/1024-tick units.
///
/// Node index mapping (IntentNode discriminant):
///   0=CapabilityProbe  1=CapabilityDenied  2=InvalidCapability
///   3=IpcSend          4=IpcRecv           5=WasmCall
///   6=FsRead           7=FsWrite           8=Syscall
#[rustfmt::skip]
pub const CTMC_Q: [[i32; INTENT_NODE_COUNT]; INTENT_NODE_COUNT] = [
    // From CapabilityProbe: likely to Syscall or Denied
    [ -3072,  1024,   512,   256,   256,   256,   256,   256,   256 ],
    // From CapabilityDenied: high rate to InvalidCapability or stays (self-loop absorbed)
    [  256, -3072,  1536,   256,   256,   256,   256,   256,   256 - 256 + 256 ],
    // From InvalidCapability: high risk — tends toward Syscall anomaly
    [  256,   512, -3072,   256,   256,   256,   256,   256,  1024 ],
    // From IpcSend: mostly paired with IpcRecv
    [  256,   256,   256, -3072,  1536,   256,   256,   256,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From IpcRecv
    [  256,   256,   256,  1536, -3072,   256,   256,   256,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From WasmCall: can probe capabilities or hit syscall
    [  512,   256,   256,   256,   256, -3072,   256,   256,  1024 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From FsRead
    [  256,   256,   256,   256,   256,   256, -3072,   512,  1024 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From FsWrite: high correlation with capability checks
    [  512,   512,   256,   256,   256,   256,   512, -3072,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From Syscall: returns to various states
    [  512,   256,   256,   384,   384,   256,   384,   384, -3072 - 256 + 256 - 256 + 256 - 256 + 256 ],
];
