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


/*!
 * Safe MMIO region wrapper.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRegion {
    pub base: usize,
    pub len: usize,
}

impl MmioRegion {
    pub const fn new(base: usize, len: usize) -> Self {
        MmioRegion { base, len }
    }

    pub const fn contains(&self, offset: usize, width: usize) -> bool {
        offset <= self.len && width <= self.len.saturating_sub(offset)
    }

    pub unsafe fn read_u32(&self, offset: usize) -> Option<u32> {
        if !self.contains(offset, 4) {
            return None;
        }
        Some(core::ptr::read_volatile((self.base + offset) as *const u32))
    }

    pub unsafe fn write_u32(&self, offset: usize, value: u32) -> bool {
        if !self.contains(offset, 4) {
            return false;
        }
        core::ptr::write_volatile((self.base + offset) as *mut u32, value);
        true
    }
}
