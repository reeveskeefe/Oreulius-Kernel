/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * Aperture and mapping policy.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Uncached,
    WriteCombine,
    Cached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApertureMapping {
    pub base: usize,
    pub len: usize,
    pub policy: CachePolicy,
}
