/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Facade for the CapNet subsystem.
//!
//! The implementation currently lives in a private legacy module so the split
//! can land without changing wire formats. The named submodules provide the
//! ownership boundaries and re-export grouped responsibilities.

#[path = "../capnet.rs"]
mod legacy;

pub mod encoding;
pub mod session;
pub mod persistence;
pub mod audit;
pub mod metrics;

pub use legacy::*;
