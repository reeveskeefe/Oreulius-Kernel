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

pub fn mapping_bounds_valid(virt_addr: usize, length: usize, page_size: usize) -> bool {
    length > 0 && page_size > 0 && virt_addr % page_size == 0 && length % page_size == 0
}

pub fn check_mapping_bounds(
    virt_addr: usize,
    length: usize,
    page_size: usize,
) -> InvariantCheckResult {
    if mapping_bounds_valid(virt_addr, length, page_size) {
        InvariantCheckResult::ok("INV-MMU-MAP-001", InvariantSeverity::Safety, 0x7201)
    } else {
        InvariantCheckResult::violation("INV-MMU-MAP-001", InvariantSeverity::Safety, 0x7201)
    }
}

pub fn check_permission_transition(executable: bool, writable: bool) -> InvariantCheckResult {
    let valid = !(executable && writable);
    if valid {
        InvariantCheckResult::ok("INV-MMU-WX-001", InvariantSeverity::Safety, 0x7202)
    } else {
        InvariantCheckResult::violation("INV-MMU-WX-001", InvariantSeverity::Safety, 0x7202)
    }
}

pub fn check_tlb_sync(flag_acknowledged: bool) -> InvariantCheckResult {
    if flag_acknowledged {
        InvariantCheckResult::ok("INV-MMU-TLB-001", InvariantSeverity::Diagnostic, 0x7203)
    } else {
        InvariantCheckResult::violation("INV-MMU-TLB-001", InvariantSeverity::Diagnostic, 0x7203)
    }
}