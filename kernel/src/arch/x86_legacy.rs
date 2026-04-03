/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::{ArchPlatform, BootInfo, BootProtocol};

const MULTIBOOT1_BOOTLOADER_MAGIC: u32 = 0x2BADB002;
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_6289;

const MB1_FLAG_CMDLINE: u32 = 1 << 2;
const MB1_FLAG_BOOT_LOADER_NAME: u32 = 1 << 9;

const MB2_TAG_END: u32 = 0;
const MB2_TAG_CMDLINE: u32 = 1;
const MB2_TAG_BOOT_LOADER_NAME: u32 = 2;
const MB2_TAG_ACPI_OLD: u32 = 14;
const MB2_TAG_ACPI_NEW: u32 = 15;

static BOOT_MAGIC: AtomicU32 = AtomicU32::new(0);
static BOOT_INFO_PTR: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct Multiboot1Info {
    flags: u32,
    mem_lower: u32,
    mem_upper: u32,
    boot_device: u32,
    cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    syms: [u32; 4],
    mmap_length: u32,
    mmap_addr: u32,
    drives_length: u32,
    drives_addr: u32,
    config_table: u32,
    boot_loader_name: u32,
}

#[repr(C)]
struct Multiboot2InfoHeader {
    total_size: u32,
    _reserved: u32,
}

#[repr(C)]
struct Multiboot2TagHeader {
    tag_type: u32,
    size: u32,
}

#[inline]
const fn align_up_8(v: usize) -> usize {
    (v + 7) & !7
}

#[inline]
fn nonzero_ptr(ptr: usize) -> Option<usize> {
    if ptr == 0 {
        None
    } else {
        Some(ptr)
    }
}

unsafe fn parse_multiboot1(info_ptr: usize, boot: &mut BootInfo) {
    if info_ptr == 0 {
        return;
    }
    let mbi = &*(info_ptr as *const Multiboot1Info);
    if (mbi.flags & MB1_FLAG_CMDLINE) != 0 {
        boot.cmdline_ptr = nonzero_ptr(mbi.cmdline as usize);
    }
    if (mbi.flags & MB1_FLAG_BOOT_LOADER_NAME) != 0 {
        boot.boot_loader_name_ptr = nonzero_ptr(mbi.boot_loader_name as usize);
    }
    // Multiboot1 doesn't provide an ACPI RSDP directly in the standard info block.
}

unsafe fn parse_multiboot2(info_ptr: usize, boot: &mut BootInfo) {
    if info_ptr == 0 {
        return;
    }

    let hdr = &*(info_ptr as *const Multiboot2InfoHeader);
    let total_size = hdr.total_size as usize;
    if total_size < core::mem::size_of::<Multiboot2InfoHeader>() || total_size > (16 * 1024 * 1024)
    {
        return;
    }

    let mut off = core::mem::size_of::<Multiboot2InfoHeader>();
    while off + core::mem::size_of::<Multiboot2TagHeader>() <= total_size {
        let tag_ptr = (info_ptr + off) as *const Multiboot2TagHeader;
        let tag = &*tag_ptr;
        let tag_size = tag.size as usize;
        if tag_size < core::mem::size_of::<Multiboot2TagHeader>() || off + tag_size > total_size {
            break;
        }

        let data_ptr = (tag_ptr as usize) + core::mem::size_of::<Multiboot2TagHeader>();
        match tag.tag_type {
            MB2_TAG_END => break,
            MB2_TAG_CMDLINE => {
                boot.cmdline_ptr = nonzero_ptr(data_ptr);
            }
            MB2_TAG_BOOT_LOADER_NAME => {
                boot.boot_loader_name_ptr = nonzero_ptr(data_ptr);
            }
            MB2_TAG_ACPI_OLD | MB2_TAG_ACPI_NEW => {
                boot.acpi_rsdp_ptr = nonzero_ptr(data_ptr);
            }
            _ => {}
        }

        off = align_up_8(off + tag_size);
    }
}

#[no_mangle]
pub extern "C" fn arch_x86_record_boot_handoff(magic: u32, info_ptr: u32) {
    BOOT_MAGIC.store(magic, Ordering::Relaxed);
    BOOT_INFO_PTR.store(info_ptr as usize, Ordering::Relaxed);
}

pub(super) struct X86LegacyPlatform;

pub(super) static PLATFORM: X86LegacyPlatform = X86LegacyPlatform;

impl ArchPlatform for X86LegacyPlatform {
    fn name(&self) -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "x86_64"
        }
        #[cfg(not(target_arch = "x86_64"))]
        "x86-legacy"
    }

    fn boot_info(&self) -> BootInfo {
        let magic = BOOT_MAGIC.load(Ordering::Relaxed);
        let info_ptr = BOOT_INFO_PTR.load(Ordering::Relaxed);

        let mut boot = BootInfo {
            raw_boot_magic: if magic == 0 { None } else { Some(magic) },
            raw_info_ptr: nonzero_ptr(info_ptr),
            ..BootInfo::default()
        };

        match magic {
            MULTIBOOT1_BOOTLOADER_MAGIC => {
                boot.protocol = BootProtocol::Multiboot1;
                unsafe {
                    parse_multiboot1(info_ptr, &mut boot);
                }
            }
            MULTIBOOT2_BOOTLOADER_MAGIC => {
                boot.protocol = BootProtocol::Multiboot2;
                unsafe {
                    parse_multiboot2(info_ptr, &mut boot);
                }
            }
            _ => {}
        }

        boot
    }

    fn init_cpu_tables(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64_runtime::init_cpu_tables();
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::gdt::init();
    }

    fn init_trap_table(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64_runtime::init_trap_table();
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::idt_asm::init_trap_table();
    }

    fn init_interrupt_controller(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64_runtime::init_interrupt_controller();
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::idt_asm::init_interrupt_controller();
    }

    fn init_timer(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64_runtime::init_timer();
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::pit::init();
    }

    fn enable_interrupts(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            super::x86_64_runtime::enable_interrupts();
        }
        #[cfg(not(target_arch = "x86_64"))]
        crate::asm_bindings::enable_interrupts();
    }

    fn halt_loop(&self) -> ! {
        loop {
            unsafe { core::arch::asm!("hlt") };
        }
    }
}
