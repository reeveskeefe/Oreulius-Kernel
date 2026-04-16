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

pub fn syscall_number_valid(syscall_number: u16, max_syscall: u16) -> bool {
    syscall_number <= max_syscall
}

pub fn check_syscall_number(syscall_number: u16, max_syscall: u16) -> InvariantCheckResult {
    if syscall_number_valid(syscall_number, max_syscall) {
        InvariantCheckResult::ok("INV-SYSCALL-NUM-001", InvariantSeverity::Consistency, 0x7301)
    } else {
        InvariantCheckResult::violation(
            "INV-SYSCALL-NUM-001",
            InvariantSeverity::Consistency,
            0x7301,
        )
    }
}

pub fn check_user_frame(frame_ptr: usize, frame_size: usize, user_space_limit: usize) -> InvariantCheckResult {
    let in_range = frame_ptr > 0
        && frame_size > 0
        && frame_ptr.checked_add(frame_size).is_some()
        && frame_ptr + frame_size <= user_space_limit;

    if in_range {
        InvariantCheckResult::ok("INV-SYSCALL-FRAME-001", InvariantSeverity::Safety, 0x7302)
    } else {
        InvariantCheckResult::violation("INV-SYSCALL-FRAME-001", InvariantSeverity::Safety, 0x7302)
    }
}