/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

#[cfg(not(target_arch = "aarch64"))]
pub mod advanced_commands;
#[cfg(not(target_arch = "aarch64"))]
pub mod commands;
#[cfg(target_arch = "aarch64")]
pub mod commands_aarch64;
#[cfg(target_arch = "aarch64")]
pub use commands_aarch64 as commands;
pub mod commands_shared;
pub(crate) mod network_commands_shared;
#[cfg(not(target_arch = "aarch64"))]
pub mod console_service;
#[cfg(not(target_arch = "aarch64"))]
pub mod terminal;
