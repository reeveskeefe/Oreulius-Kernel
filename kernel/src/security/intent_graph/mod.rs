/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Facade for the intent-graph subsystem.
//!
//! The implementation is split into focused submodules to keep policy,
//! runtime state, and data-model responsibilities separate.

pub mod model;
pub mod policy;
pub mod runtime;

pub use model::{
    AdaptiveRestriction, IntentDecision, IntentGraphStats, IntentNode, IntentProcessSnapshot,
    IntentSignal, ADAPTIVE_RESTRICTION_MAX_QUARANTINE,
};
pub use policy::{
    IntentPolicy, IntentPolicyError, PolicyTensor, INTENT_ALERT_COOLDOWN_MS, INTENT_ALERT_SCORE,
    INTENT_ISOLATE_RESTRICTIONS, INTENT_ISOLATION_EXTENSION_SECONDS, INTENT_RESTRICT_BASE_SECONDS,
    INTENT_RESTRICT_COOLDOWN_MS, INTENT_RESTRICT_MAX_SECONDS, INTENT_RESTRICT_SCORE,
    INTENT_SEVERITY_STEP_SCORE, INTENT_TERMINATE_RESTRICTIONS, INTENT_WINDOW_SECONDS,
};
pub use runtime::IntentGraph;
