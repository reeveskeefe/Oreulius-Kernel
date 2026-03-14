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

//! Architecture abstraction shim for incremental multi-arch bring-up.
//!
//! This module intentionally starts small: it wraps the current x86/i686
//! platform initialization sequence behind a stable interface so future
//! x86_64/AArch64 implementations can slot in without touching `rust_main`
//! call ordering again.

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_dtb;
#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_pl011;
#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_runtime;
#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_vectors;
/// Architecture-specific FPU/SIMD context save/restore (PMA §5.1).
pub mod fpu;
pub mod mmu;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64_runtime;
#[cfg(target_arch = "x86")]
pub(crate) mod x86_runtime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootProtocol {
    Unknown,
    Multiboot1,
    Multiboot2,
}

#[derive(Clone, Copy, Debug)]
pub struct BootInfo {
    /// Boot protocol used for kernel entry.
    pub protocol: BootProtocol,
    /// Raw boot magic passed by the bootloader (when available).
    pub raw_boot_magic: Option<u32>,
    /// Raw boot information structure pointer.
    pub raw_info_ptr: Option<usize>,
    /// Optional command-line string pointer provided by the bootloader.
    pub cmdline_ptr: Option<usize>,
    /// Optional bootloader-name string pointer.
    pub boot_loader_name_ptr: Option<usize>,
    /// Optional ACPI RSDP pointer (x86/x86_64 path).
    pub acpi_rsdp_ptr: Option<usize>,
    /// Optional Device Tree Blob pointer (ARM/AArch64 path).
    pub dtb_ptr: Option<usize>,
}

impl Default for BootInfo {
    fn default() -> Self {
        Self {
            protocol: BootProtocol::Unknown,
            raw_boot_magic: None,
            raw_info_ptr: None,
            cmdline_ptr: None,
            boot_loader_name_ptr: None,
            acpi_rsdp_ptr: None,
            dtb_ptr: None,
        }
    }
}

impl BootInfo {
    const MAX_BOOT_STRING_BYTES: usize = 1024;

    #[inline]
    pub fn cmdline_str(&self) -> Option<&'static str> {
        self.read_cstr(self.cmdline_ptr)
    }

    #[inline]
    pub fn boot_loader_name_str(&self) -> Option<&'static str> {
        self.read_cstr(self.boot_loader_name_ptr)
    }

    fn read_cstr(&self, ptr: Option<usize>) -> Option<&'static str> {
        let ptr = ptr?;
        if ptr == 0 {
            return None;
        }

        // Best-effort bounded scan for early-boot pointers supplied by the bootloader.
        // This avoids walking unbounded memory if a terminator is missing.
        let bytes =
            unsafe { core::slice::from_raw_parts(ptr as *const u8, Self::MAX_BOOT_STRING_BYTES) };
        let len = bytes.iter().position(|&b| b == 0)?;
        if len == 0 {
            return Some("");
        }
        core::str::from_utf8(&bytes[..len]).ok()
    }
}

pub trait ArchPlatform {
    fn name(&self) -> &'static str;
    fn boot_info(&self) -> BootInfo {
        BootInfo::default()
    }
    fn init_cpu_tables(&self);
    fn init_trap_table(&self);
    fn init_interrupt_controller(&self);
    fn init_interrupts(&self) {
        self.init_trap_table();
        self.init_interrupt_controller();
    }
    fn init_timer(&self);
    fn enable_interrupts(&self);
    fn halt_loop(&self) -> !;
}

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64_virt;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
mod unsupported;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_legacy;

#[cfg(target_arch = "aarch64")]
use aarch64_virt::PLATFORM;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
use unsupported::PLATFORM;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_legacy::PLATFORM;

#[inline]
fn active() -> &'static dyn ArchPlatform {
    &PLATFORM
}

#[inline]
pub fn platform_name() -> &'static str {
    active().name()
}

#[inline]
pub fn boot_info() -> BootInfo {
    active().boot_info()
}

#[inline]
pub fn init_cpu_tables() {
    active().init_cpu_tables()
}

#[inline]
pub fn init_interrupts() {
    active().init_interrupts()
}

#[inline]
pub fn init_trap_table() {
    active().init_trap_table()
}

#[inline]
pub fn init_interrupt_controller() {
    active().init_interrupt_controller()
}

#[inline]
pub fn init_timer() {
    active().init_timer()
}

#[inline]
pub fn enable_interrupts() {
    active().enable_interrupts()
}

#[inline]
pub fn halt_loop() -> ! {
    active().halt_loop()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn enter_runtime() -> ! {
    aarch64_runtime::enter_runtime()
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn enter_runtime() -> ! {
    x86_64_runtime::enter_runtime()
}

#[cfg(target_arch = "x86")]
#[inline]
pub fn enter_runtime() -> ! {
    x86_runtime::enter_runtime()
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn enter_runtime() -> ! {
    halt_loop()
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub fn shell_loop() -> ! {
    x86_64_runtime::run_serial_shell()
}

#[cfg(target_arch = "x86")]
#[inline]
pub fn shell_loop() -> ! {
    x86_runtime::shell_loop()
}
