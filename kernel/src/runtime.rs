/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

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
