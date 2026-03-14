/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

pub mod pit;
pub mod process;
#[cfg(not(target_arch = "aarch64"))]
pub mod process_asm;
pub mod process_platform;
pub mod quantum_scheduler;
#[cfg(not(target_arch = "aarch64"))]
pub mod scheduler;
pub mod scheduler_platform;
pub mod scheduler_runtime_platform;
#[cfg(not(target_arch = "aarch64"))]
pub mod tasks;

// Preserve the legacy `crate::scheduler::*` surface while grouping scheduler code.
#[cfg(not(target_arch = "aarch64"))]
pub use self::scheduler::*;
