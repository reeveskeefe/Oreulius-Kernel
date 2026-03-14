/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#[cfg(not(target_arch = "aarch64"))]
pub mod gdt;
#[cfg(not(target_arch = "aarch64"))]
pub mod idt_asm;
pub mod interrupt_dag;
pub mod syscall;
pub mod usermode;
