/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * CPU/GPU mapping metadata.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferMapping {
    pub cpu_addr: usize,
    pub len: usize,
    pub writable: bool,
}

impl BufferMapping {
    pub const fn null() -> Self {
        BufferMapping {
            cpu_addr: 0,
            len: 0,
            writable: false,
        }
    }
}
