/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
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
#[cfg(not(target_arch = "aarch64"))]
pub mod console_service;
#[cfg(not(target_arch = "aarch64"))]
pub mod terminal;
