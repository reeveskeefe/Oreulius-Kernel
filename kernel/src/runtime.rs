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

//! Stable runtime facade for cross-subsystem helpers.
//!
//! This module is the preferred home for small runtime queries and maintenance
//! hooks that do not belong to a specific subsystem.

#[inline]
pub fn page_size() -> usize {
    crate::arch::mmu::page_size()
}

#[inline]
pub fn heap_range() -> (usize, usize) {
    crate::memory::heap_range()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn jit_arena_range() -> (usize, usize) {
    crate::memory::jit_arena_range()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn jit_arena_range() -> (usize, usize) {
    (0, 0)
}

#[inline]
pub fn background_maintenance() {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::execution::wasm::drain_pending_spawns();
        crate::execution::wasm::tick_background_threads();
    }
}
