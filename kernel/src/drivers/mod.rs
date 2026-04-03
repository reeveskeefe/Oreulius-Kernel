/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#[cfg(not(target_arch = "aarch64"))]
pub mod acpi_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod audio;
#[cfg(not(target_arch = "aarch64"))]
pub mod bluetooth;
#[cfg(not(target_arch = "aarch64"))]
pub mod compositor;
#[cfg(not(target_arch = "aarch64"))]
pub mod dma_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod framebuffer;
#[cfg(not(target_arch = "aarch64"))]
#[path = "GPUsupport/mod.rs"]
pub mod gpu_support;
#[cfg(not(target_arch = "aarch64"))]
pub mod input;
#[cfg(not(target_arch = "aarch64"))]
pub mod keyboard;
#[cfg(not(target_arch = "aarch64"))]
pub mod memopt_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod mouse;
#[cfg(not(target_arch = "aarch64"))]
pub mod pci;
#[cfg(not(target_arch = "aarch64"))]
pub mod usb;
#[cfg(not(target_arch = "aarch64"))]
pub mod vga;
