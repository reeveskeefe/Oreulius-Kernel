/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

pub mod policy;

pub use policy::{
    FailureAction, FailureKind, FailureOutcome, FailurePolicy, FailureSubsystem,
    handle_failure,
};