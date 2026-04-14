/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

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