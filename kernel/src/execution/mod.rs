/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#[cfg(not(target_arch = "aarch64"))]
pub mod elf;
pub mod intent_wasm;
pub mod replay;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm;
pub mod wasm_jit;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm_thread;
