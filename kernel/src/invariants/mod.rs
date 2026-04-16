// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

pub mod mmu;
pub mod scheduler;
pub mod syscall;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantSeverity {
    Safety,
    Consistency,
    Progress,
    Diagnostic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantCheckResult {
    pub id: &'static str,
    pub severity: InvariantSeverity,
    pub code: u16,
    pub valid: bool,
}

impl InvariantCheckResult {
    pub const fn ok(id: &'static str, severity: InvariantSeverity, code: u16) -> Self {
        Self {
            id,
            severity,
            code,
            valid: true,
        }
    }

    pub const fn violation(id: &'static str, severity: InvariantSeverity, code: u16) -> Self {
        Self {
            id,
            severity,
            code,
            valid: false,
        }
    }
}

pub fn enforce(result: InvariantCheckResult, detail: &[u8]) -> Option<crate::failure::FailureOutcome> {
    if result.valid {
        return None;
    }

    crate::observability::logger::emit_structured(
        crate::observability::EventLevel::InvariantViolation,
        crate::observability::Subsystem::Invariant,
        crate::observability::EventType::InvariantViolation,
        result.code,
        detail,
    );

    let (subsystem, kind) = match result.severity {
        InvariantSeverity::Safety => (
            crate::failure::FailureSubsystem::Invariant,
            crate::failure::FailureKind::InternalFault,
        ),
        InvariantSeverity::Consistency => (
            crate::failure::FailureSubsystem::Invariant,
            crate::failure::FailureKind::InvalidState,
        ),
        InvariantSeverity::Progress => (
            crate::failure::FailureSubsystem::Scheduler,
            crate::failure::FailureKind::InvalidState,
        ),
        InvariantSeverity::Diagnostic => (
            crate::failure::FailureSubsystem::Invariant,
            crate::failure::FailureKind::InternalFault,
        ),
    };

    Some(crate::failure::handle_failure(subsystem, kind, detail))
}