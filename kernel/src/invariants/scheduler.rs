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

use crate::invariants::{InvariantCheckResult, InvariantSeverity};

pub fn scheduler_state_valid(quantum: u32, tick_pos: u32) -> bool {
    quantum > 0 && tick_pos <= quantum
}

pub fn check_scheduler_state(quantum: u32, tick_pos: u32) -> InvariantCheckResult {
    if scheduler_state_valid(quantum, tick_pos) {
        InvariantCheckResult::ok("INV-SCHED-STATE-001", InvariantSeverity::Consistency, 0x7101)
    } else {
        InvariantCheckResult::violation(
            "INV-SCHED-STATE-001",
            InvariantSeverity::Consistency,
            0x7101,
        )
    }
}

pub fn check_fairness_window(runnable_threads: u32, serviced_threads: u32) -> InvariantCheckResult {
    let valid = runnable_threads == 0 || serviced_threads > 0;
    if valid {
        InvariantCheckResult::ok("INV-SCHED-FAIR-001", InvariantSeverity::Progress, 0x7102)
    } else {
        InvariantCheckResult::violation("INV-SCHED-FAIR-001", InvariantSeverity::Progress, 0x7102)
    }
}