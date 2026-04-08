/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! x86-family driver root.
//!
//! This module owns the current hardware-driver tree and is re-exported by the
//! top-level `drivers` facade on x86 and x86_64 targets.

#[path = "../acpi_asm.rs"]
pub mod acpi_asm;
#[path = "../audio.rs"]
pub mod audio;
#[path = "../bluetooth.rs"]
pub mod bluetooth;
#[path = "../compositor.rs"]
pub mod compositor;
#[path = "../dma_asm.rs"]
pub mod dma_asm;
#[path = "../framebuffer.rs"]
pub mod framebuffer;
#[path = "../GPUsupport/mod.rs"]
pub mod gpu_support;
#[path = "../input.rs"]
pub mod input;
#[path = "../keyboard.rs"]
pub mod keyboard;
#[path = "../memopt_asm.rs"]
pub mod memopt_asm;
#[path = "../mouse.rs"]
pub mod mouse;
#[path = "../pci.rs"]
pub mod pci;
#[path = "../usb.rs"]
pub mod usb;
#[path = "../vga.rs"]
pub mod vga;
