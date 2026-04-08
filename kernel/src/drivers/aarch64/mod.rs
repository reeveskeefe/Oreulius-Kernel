/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Minimal AArch64 driver root.
//!
//! The current hardware-driver tree is intentionally x86-family only. This
//! module exists so the top-level `drivers` facade has an explicit AArch64
//! backend root without pretending that legacy x86 hardware drivers exist on
//! this target.
