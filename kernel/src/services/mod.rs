/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#[cfg(not(target_arch = "aarch64"))]
pub mod fleet;
#[cfg(not(target_arch = "aarch64"))]
pub mod health;
#[cfg(not(target_arch = "aarch64"))]
pub mod ota;
pub mod registry;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasi;
