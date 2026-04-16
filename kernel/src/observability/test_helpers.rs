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

//! Test helpers for closure-chain assertion across negative-trace tests.
//!
//! Eliminates duplication when validating invariant→event→failure→outcome chains.

#[cfg(test)]
use crate::failure::policy::{FailureAction, FailureSubsystem};
#[cfg(test)]
use crate::failure::policy::last_failure_outcome;
#[cfg(test)]
use crate::observability::EventType;
#[cfg(test)]
use crate::observability::ring_buffer;

/// Asserts the complete closure chain for a negative-trace violation:
/// 1. Event count increased (before < after)
/// 2. Expected event types present in [before..after) range
/// 3. Last failure outcome matches expected subsystem and action
///
/// # Arguments
/// * `event_count_before` - Ring buffer write count before violation trigger
/// * `event_count_after` - Ring buffer write count after violation trigger
/// * `expected_event_types` - Slice of EventTypes that should appear (e.g., &[EventType::InvariantViolation, EventType::FailurePolicyAction])
/// * `expected_subsystem` - FailureSubsystem that should be recorded in outcome
/// * `expected_action` - FailureAction that should be recorded in outcome
///
/// # Panics
/// * If after <= before (no events emitted)
/// * If any expected event type is not found in the range
/// * If failure outcome is missing or doesn't match expected values
#[cfg(test)]
pub fn assert_closure_chain_closure(
    event_count_before: usize,
    event_count_after: usize,
    expected_event_types: &[EventType],
    expected_subsystem: FailureSubsystem,
    expected_action: FailureAction,
) {
    // 1. Verify events were emitted
    assert!(
        event_count_after > event_count_before,
        "expected events to be emitted; before={} after={}",
        event_count_before,
        event_count_after
    );

    // 2. Verify all expected event types are present
    for expected_type in expected_event_types {
        let mut found = false;
        for seq in event_count_before..event_count_after {
            if let Some(ev) = ring_buffer::snapshot_seq(seq) {
                if ev.event_type == *expected_type {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "expected event type {:?} not found in range [{}..{})",
            expected_type, event_count_before, event_count_after
        );
    }

    // 3. Verify failure outcome matches expected values
    let outcome = last_failure_outcome().expect("failure outcome snapshot should exist");
    assert_eq!(
        outcome.subsystem, expected_subsystem,
        "failure subsystem mismatch"
    );
    assert_eq!(outcome.action, expected_action, "failure action mismatch");
}
