/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


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
