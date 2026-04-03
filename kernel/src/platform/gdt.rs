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

use core::mem::size_of;

use crate::process_asm::{tss_load, tss_set_kernel_stack};

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    gran: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn null() -> Self {
        GdtEntry {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            gran: 0,
            base_high: 0,
        }
    }

    const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        let limit_low = (limit & 0xFFFF) as u16;
        let base_low = (base & 0xFFFF) as u16;
        let base_mid = ((base >> 16) & 0xFF) as u8;
        let base_high = ((base >> 24) & 0xFF) as u8;
        let gran = (((limit >> 16) & 0x0F) as u8) | (flags & 0xF0);
        GdtEntry {
            limit_low,
            base_low,
            base_mid,
            access,
            gran,
            base_high,
        }
    }
}

#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u32,
}

#[repr(C, packed)]
struct Tss {
    prev_tss: u32,
    esp0: u32,
    ss0: u32,
    esp1: u32,
    ss1: u32,
    esp2: u32,
    ss2: u32,
    cr3: u32,
    eip: u32,
    eflags: u32,
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
    esp: u32,
    ebp: u32,
    esi: u32,
    edi: u32,
    es: u32,
    cs: u32,
    ss: u32,
    ds: u32,
    fs: u32,
    gs: u32,
    ldt: u32,
    trap: u16,
    iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Tss {
            prev_tss: 0,
            esp0: 0,
            ss0: 0,
            esp1: 0,
            ss1: 0,
            esp2: 0,
            ss2: 0,
            cr3: 0,
            eip: 0,
            eflags: 0,
            eax: 0,
            ecx: 0,
            edx: 0,
            ebx: 0,
            esp: 0,
            ebp: 0,
            esi: 0,
            edi: 0,
            es: 0,
            cs: 0,
            ss: 0,
            ds: 0,
            fs: 0,
            gs: 0,
            ldt: 0,
            trap: 0,
            iomap_base: size_of::<Tss>() as u16,
        }
    }
}

#[cfg(target_arch = "x86")]
extern "C" {
    fn gdt_load(gdt_ptr: *const GdtPointer);
}

#[cfg(target_arch = "x86")]
#[inline]
unsafe fn gdt_load_compat(gdt_ptr: *const GdtPointer) {
    gdt_load(gdt_ptr);
}

#[cfg(not(target_arch = "x86"))]
#[inline]
unsafe fn gdt_load_compat(_gdt_ptr: *const GdtPointer) {}

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_CS: u16 = 0x1B;
pub const USER_DS: u16 = 0x23;
pub const TSS_SELECTOR: u16 = 0x28;

static mut GDT: [GdtEntry; 6] = [GdtEntry::null(); 6];
static mut TSS_ENTRY: Tss = Tss::new();

const SYSENTER_STACK_SIZE: usize = 4096;
static mut SYSENTER_STACK: [u8; SYSENTER_STACK_SIZE] = [0; SYSENTER_STACK_SIZE];

fn read_esp() -> u32 {
    let esp: u32;
    unsafe {
        core::arch::asm!("mov {0:e}, esp", out(reg) esp, options(nomem, nostack, preserves_flags));
    }
    esp
}

pub fn init() {
    unsafe {
        // Null
        GDT[0] = GdtEntry::null();
        // Kernel code/data
        GDT[1] = GdtEntry::new(0, 0xFFFFF, 0x9A, 0xCF);
        GDT[2] = GdtEntry::new(0, 0xFFFFF, 0x92, 0xCF);
        // User code/data
        GDT[3] = GdtEntry::new(0, 0xFFFFF, 0xFA, 0xCF);
        GDT[4] = GdtEntry::new(0, 0xFFFFF, 0xF2, 0xCF);

        // TSS
        TSS_ENTRY = Tss::new();
        let tss_base = &TSS_ENTRY as *const _ as u32;
        let tss_limit = (size_of::<Tss>() - 1) as u32;
        GDT[5] = GdtEntry::new(tss_base, tss_limit, 0x89, 0x00);

        let gdt_ptr = GdtPointer {
            limit: (size_of::<[GdtEntry; 6]>() - 1) as u16,
            base: (&GDT as *const _ as u32),
        };

        gdt_load_compat(&gdt_ptr);

        // Initialize TSS kernel stack
        let esp0 = read_esp();
        tss_set_kernel_stack(&mut TSS_ENTRY as *mut _ as *mut u32, esp0, KERNEL_DS);
        tss_load(TSS_SELECTOR);
    }
}

pub fn update_kernel_stack(esp0: u32) {
    unsafe {
        tss_set_kernel_stack(&mut TSS_ENTRY as *mut _ as *mut u32, esp0, KERNEL_DS);
    }
}

pub fn sysenter_stack_top() -> u32 {
    unsafe { SYSENTER_STACK.as_ptr().add(SYSENTER_STACK_SIZE) as u32 }
}

pub fn gdt_range() -> (usize, usize) {
    let start = unsafe { &GDT as *const _ as usize };
    let end = start + core::mem::size_of::<[GdtEntry; 6]>();
    (start, end)
}

pub fn tss_range() -> (usize, usize) {
    let start = unsafe { &TSS_ENTRY as *const _ as usize };
    let end = start + core::mem::size_of::<Tss>();
    (start, end)
}

pub fn sysenter_stack_range() -> (usize, usize) {
    let start = unsafe { SYSENTER_STACK.as_ptr() as usize };
    let end = start + SYSENTER_STACK_SIZE;
    (start, end)
}

pub fn kernel_stack_ptr() -> u32 {
    unsafe { TSS_ENTRY.esp0 }
}
