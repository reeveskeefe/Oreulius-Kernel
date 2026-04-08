/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Stable storage facade for filesystem-related exports.
//!
//! This module keeps the historical filesystem helpers available while giving
//! callers a more explicit entrypoint than the crate root.

pub use crate::fs::{vfs, vfs_platform, virtio_blk};
#[cfg(not(target_arch = "aarch64"))]
pub use crate::fs::{ata, disk, nvme, paging};
