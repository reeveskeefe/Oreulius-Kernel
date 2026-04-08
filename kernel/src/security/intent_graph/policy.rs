/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Intent-graph policy and threshold tuning.

use crate::math::linear_capability::{ScalarTensor, SimdTensor};

/// A mathematically bounded strict representation of capability access thresholds.
/// Converts sequential discrete capability comparisons into constant SIMD vector dot products.
#[derive(Clone, Copy)]
pub struct PolicyTensor<const N: usize> {
    pub weights: ScalarTensor<i32, N>,
    pub threshold: i32,
}

impl<const N: usize> PolicyTensor<N> {
    pub const fn new(weights: [i32; N], threshold: i32) -> Self {
        Self {
            weights: ScalarTensor { data: weights },
            threshold,
        }
    }

    /// Authorizes capability access by projecting policy conditions over real-time environmental intent
    /// behavior bounds, validating the equation via a strict mathematical threshold.
    pub fn authorize_vectorized(&self, environment_state: &ScalarTensor<i32, N>) -> bool {
        let risk_score = self.weights.dot_product(environment_state);
        risk_score < self.threshold
    }
}

/// Sliding window size used by intent scoring.
pub const INTENT_WINDOW_SECONDS: u64 = 8;
/// Score threshold where alerts are emitted.
pub const INTENT_ALERT_SCORE: u32 = 84;
/// Score threshold where predictive revocation starts.
pub const INTENT_RESTRICT_SCORE: u32 = 136;
/// Number of restriction decisions in window before full capability isolation.
pub const INTENT_ISOLATE_RESTRICTIONS: u16 = 3;
/// Number of restriction decisions in window before termination is recommended.
pub const INTENT_TERMINATE_RESTRICTIONS: u16 = 6;
/// Base restriction duration (seconds).
pub const INTENT_RESTRICT_BASE_SECONDS: u16 = 2;
/// Maximum restriction duration (seconds).
pub const INTENT_RESTRICT_MAX_SECONDS: u16 = 12;
/// Isolation extension duration (seconds).
pub const INTENT_ISOLATION_EXTENSION_SECONDS: u16 = 20;
/// Score delta per duration severity step.
pub const INTENT_SEVERITY_STEP_SCORE: u16 = 16;
/// Minimum alert emission gap (milliseconds).
pub const INTENT_ALERT_COOLDOWN_MS: u16 = 1000;
/// Minimum restrict emission gap (milliseconds).
pub const INTENT_RESTRICT_COOLDOWN_MS: u16 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntentPolicy {
    pub window_seconds: u64,
    pub alert_score: u32,
    pub restrict_score: u32,
    pub isolate_restrictions: u16,
    pub terminate_restrictions: u16,
    pub restrict_base_seconds: u16,
    pub restrict_max_seconds: u16,
    pub isolate_extension_seconds: u16,
    pub severity_step_score: u16,
    pub alert_cooldown_ms: u16,
    pub restrict_cooldown_ms: u16,
}

impl IntentPolicy {
    pub const fn baseline() -> Self {
        Self {
            window_seconds: INTENT_WINDOW_SECONDS,
            alert_score: INTENT_ALERT_SCORE,
            restrict_score: INTENT_RESTRICT_SCORE,
            isolate_restrictions: INTENT_ISOLATE_RESTRICTIONS,
            terminate_restrictions: INTENT_TERMINATE_RESTRICTIONS,
            restrict_base_seconds: INTENT_RESTRICT_BASE_SECONDS,
            restrict_max_seconds: INTENT_RESTRICT_MAX_SECONDS,
            isolate_extension_seconds: INTENT_ISOLATION_EXTENSION_SECONDS,
            severity_step_score: INTENT_SEVERITY_STEP_SCORE,
            alert_cooldown_ms: INTENT_ALERT_COOLDOWN_MS,
            restrict_cooldown_ms: INTENT_RESTRICT_COOLDOWN_MS,
        }
    }

    pub fn validate(&self) -> Result<(), IntentPolicyError> {
        if self.window_seconds == 0 || self.window_seconds > 3600 {
            return Err(IntentPolicyError::WindowSecondsOutOfRange);
        }
        if self.alert_score > 255 {
            return Err(IntentPolicyError::AlertScoreOutOfRange);
        }
        if self.restrict_score > 255 {
            return Err(IntentPolicyError::RestrictScoreOutOfRange);
        }
        if self.restrict_score < self.alert_score {
            return Err(IntentPolicyError::RestrictScoreBelowAlert);
        }
        if self.isolate_restrictions == 0 {
            return Err(IntentPolicyError::IsolateRestrictionsZero);
        }
        if self.terminate_restrictions < self.isolate_restrictions {
            return Err(IntentPolicyError::TerminateRestrictionsBelowIsolate);
        }
        if self.restrict_base_seconds == 0 {
            return Err(IntentPolicyError::RestrictBaseSecondsZero);
        }
        if self.restrict_max_seconds < self.restrict_base_seconds {
            return Err(IntentPolicyError::RestrictMaxBelowBase);
        }
        if self.isolate_extension_seconds < self.restrict_base_seconds {
            return Err(IntentPolicyError::IsolateExtensionBelowBase);
        }
        if self.severity_step_score == 0 {
            return Err(IntentPolicyError::SeverityStepZero);
        }
        if self.alert_cooldown_ms == 0 {
            return Err(IntentPolicyError::AlertCooldownZero);
        }
        if self.restrict_cooldown_ms == 0 {
            return Err(IntentPolicyError::RestrictCooldownZero);
        }
        Ok(())
    }
}

impl Default for IntentPolicy {
    fn default() -> Self {
        Self::baseline()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentPolicyError {
    WindowSecondsOutOfRange,
    AlertScoreOutOfRange,
    RestrictScoreOutOfRange,
    RestrictScoreBelowAlert,
    IsolateRestrictionsZero,
    TerminateRestrictionsBelowIsolate,
    RestrictBaseSecondsZero,
    RestrictMaxBelowBase,
    IsolateExtensionBelowBase,
    SeverityStepZero,
    AlertCooldownZero,
    RestrictCooldownZero,
}

impl IntentPolicyError {
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentPolicyError::WindowSecondsOutOfRange => "window_seconds must be in 1..=3600",
            IntentPolicyError::AlertScoreOutOfRange => "alert_score must be in 0..=255",
            IntentPolicyError::RestrictScoreOutOfRange => "restrict_score must be in 0..=255",
            IntentPolicyError::RestrictScoreBelowAlert => "restrict_score must be >= alert_score",
            IntentPolicyError::IsolateRestrictionsZero => "isolate_restrictions must be >= 1",
            IntentPolicyError::TerminateRestrictionsBelowIsolate => {
                "terminate_restrictions must be >= isolate_restrictions"
            }
            IntentPolicyError::RestrictBaseSecondsZero => "restrict_base_seconds must be >= 1",
            IntentPolicyError::RestrictMaxBelowBase => {
                "restrict_max_seconds must be >= restrict_base_seconds"
            }
            IntentPolicyError::IsolateExtensionBelowBase => {
                "isolate_extension_seconds must be >= restrict_base_seconds"
            }
            IntentPolicyError::SeverityStepZero => "severity_step_score must be >= 1",
            IntentPolicyError::AlertCooldownZero => "alert_cooldown_ms must be >= 1",
            IntentPolicyError::RestrictCooldownZero => "restrict_cooldown_ms must be >= 1",
        }
    }
}
