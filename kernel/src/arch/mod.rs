// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

//! Architecture abstraction shim for incremental multi-arch bring-up.
//!
//! This module stays narrow: it selects the target-owned backend roots and
//! exposes a stable interface to the rest of the kernel while the x86-family
//! and AArch64 implementation files remain behind `#[path]` shims.

/// Architecture-specific FPU/SIMD context save/restore (PMA §5.1).
pub mod fpu;
pub mod mmu;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
mod unsupported;

#[cfg(target_arch = "aarch64")]
use self::aarch64 as backend;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use self::x86 as backend;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
use self::unsupported as backend;

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

#[inline]
pub fn platform_name() -> &'static str {
    backend::platform_name()
}

#[inline]
pub fn boot_info() -> BootInfo {
    backend::boot_info()
}

#[inline]
pub fn init_cpu_tables() {
    backend::init_cpu_tables()
}

#[inline]
pub fn init_interrupts() {
    backend::init_trap_table();
    backend::init_interrupt_controller();
}

#[inline]
pub fn init_trap_table() {
    backend::init_trap_table()
}

#[inline]
pub fn init_interrupt_controller() {
    backend::init_interrupt_controller()
}

#[inline]
pub fn init_timer() {
    backend::init_timer()
}

#[inline]
pub fn enable_interrupts() {
    backend::enable_interrupts()
}

#[inline]
pub fn halt_loop() -> ! {
    backend::halt_loop()
}

#[inline]
pub fn enter_runtime() -> ! {
    backend::enter_runtime()
}

#[inline]
pub fn shell_loop() -> ! {
    backend::shell_loop()
}
