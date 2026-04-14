/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Capability enforcement validation helpers.

use crate::observability::{EventLevel, EventType, Subsystem};

pub const CAP_CHECK_NONCE_MISMATCH: u16 = 0x8101;
pub const CAP_CHECK_RIGHTS_ESCALATION: u16 = 0x8102;
pub const CAP_CHECK_TRANSFER_CONSTRAINT: u16 = 0x8103;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityValidationInput {
    pub expected_nonce: u64,
    pub presented_nonce: u64,
    pub source_rights: u64,
    pub target_rights: u64,
    pub source_pid: u32,
    pub target_pid: u32,
    pub transferable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityValidationResult {
    pub valid: bool,
    pub reason_code: u16,
}

pub fn validate_nonce(expected_nonce: u64, presented_nonce: u64) -> bool {
    expected_nonce == presented_nonce
}

pub fn validate_rights_subset(parent_rights: u64, delegated_rights: u64) -> bool {
    delegated_rights & !parent_rights == 0
}

pub fn validate_transfer_constraints(source_pid: u32, target_pid: u32, transferable: bool) -> bool {
    source_pid != 0 && target_pid != 0 && source_pid != target_pid && transferable
}

pub fn validate_capability(input: CapabilityValidationInput) -> CapabilityValidationResult {
    if !validate_nonce(input.expected_nonce, input.presented_nonce) {
        report_violation(CAP_CHECK_NONCE_MISMATCH, b"capability nonce mismatch");
        return CapabilityValidationResult {
            valid: false,
            reason_code: CAP_CHECK_NONCE_MISMATCH,
        };
    }
    if !validate_rights_subset(input.source_rights, input.target_rights) {
        report_violation(CAP_CHECK_RIGHTS_ESCALATION, b"capability rights escalation attempt");
        return CapabilityValidationResult {
            valid: false,
            reason_code: CAP_CHECK_RIGHTS_ESCALATION,
        };
    }
    if !validate_transfer_constraints(input.source_pid, input.target_pid, input.transferable) {
        report_violation(
            CAP_CHECK_TRANSFER_CONSTRAINT,
            b"capability transfer constraint violated",
        );
        return CapabilityValidationResult {
            valid: false,
            reason_code: CAP_CHECK_TRANSFER_CONSTRAINT,
        };
    }
    CapabilityValidationResult {
        valid: true,
        reason_code: 0,
    }
}

fn report_violation(code: u16, detail: &[u8]) {
    crate::observability::logger::emit_structured(
        EventLevel::Error,
        Subsystem::Capability,
        EventType::SecurityViolation,
        code,
        detail,
    );
    let _ = crate::failure::handle_failure(
        crate::failure::FailureSubsystem::Capability,
        crate::failure::FailureKind::EscalationAttempt,
        detail,
    );
}