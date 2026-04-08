/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Driver facade for the kernel tree.
//!
//! The concrete hardware driver tree lives under `drivers::x86` for the current
//! x86-family backends. `drivers::aarch64` is intentionally minimal and exists
//! only as the explicit AArch64 root for future target-specific driver work.

#[cfg(not(target_arch = "aarch64"))]
pub mod x86;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
