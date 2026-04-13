/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/*!
 * Cache/coherency policy markers.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherencyModel {
    Unknown,
    Coherent,
    FlushRequired,
}
