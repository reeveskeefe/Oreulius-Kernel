/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! Kernel Page-Table Isolation (KPTI) support for user-mode execution.
//!
//! This builds a minimal, user-visible IDT that points to trampoline stubs.
//! Trampolines switch to the full kernel page directory before jumping into
//! the real handlers. On return to user mode, the common ISR/IRQ paths restore
//! the user CR3 when appropriate.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::idt_asm::{self, IdtEntry, IdtPointer, FLAG_DPL0, FLAG_DPL3, FLAG_PRESENT, GATE_INTERRUPT_32};
use crate::memory;
use crate::paging;
use crate::gdt;
use crate::process_asm::{write_msr, MSR_IA32_SYSENTER_EIP};

#[no_mangle]
pub static KPTI_KERNEL_CR3: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
pub static KPTI_USER_CR3: AtomicU32 = AtomicU32::new(0);

static KPTI_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct KptiState {
    tramp_base: usize,
    idt_base: usize,
    idt_ptr: IdtPointer,
    sysenter_stub: u32,
    sysenter_kernel: u32,
}

static KPTI_STATE: Mutex<Option<KptiState>> = Mutex::new(None);

extern "C" {
    fn isr0();
    fn isr1();
    fn isr2();
    fn isr3();
    fn isr4();
    fn isr5();
    fn isr6();
    fn isr7();
    fn isr8();
    fn isr9();
    fn isr10();
    fn isr11();
    fn isr12();
    fn isr13();
    fn isr14();
    fn isr15();
    fn isr16();
    fn isr17();
    fn isr18();
    fn isr19();
    fn isr20();
    fn isr21();
    fn isr22();
    fn isr23();
    fn isr24();
    fn isr25();
    fn isr26();
    fn isr27();
    fn isr28();
    fn isr29();
    fn isr30();
    fn isr31();

    fn irq0();
    fn irq1();
    fn irq2();
    fn irq3();
    fn irq4();
    fn irq5();
    fn irq6();
    fn irq7();
    fn irq8();
    fn irq9();
    fn irq10();
    fn irq11();
    fn irq12();
    fn irq13();
    fn irq14();
    fn irq15();

    fn syscall_entry();
    fn sysenter_entry();
}

const STUB_STRIDE: usize = 16;

fn write_trampoline_stub(base: *mut u8, offset: usize, target: usize) -> Result<usize, &'static str> {
    let addr = base as usize + offset;
    unsafe {
        let mut p = base.add(offset);
        // mov eax, [imm32]
        *p = 0xA1;
        p = p.add(1);
        let cr3_addr = core::ptr::addr_of!(KPTI_KERNEL_CR3) as u32;
        let cr3_bytes = cr3_addr.to_le_bytes();
        core::ptr::copy_nonoverlapping(cr3_bytes.as_ptr(), p, 4);
        p = p.add(4);
        // mov cr3, eax
        *p = 0x0F;
        p = p.add(1);
        *p = 0x22;
        p = p.add(1);
        *p = 0xD8;
        p = p.add(1);
        // jmp rel32
        *p = 0xE9;
        p = p.add(1);
        let rel = (target as isize).wrapping_sub((addr + 13) as isize) as i32;
        let rel_bytes = rel.to_le_bytes();
        core::ptr::copy_nonoverlapping(rel_bytes.as_ptr(), p, 4);
        p = p.add(4);
        // pad with NOPs
        let used = 13usize;
        for _ in used..STUB_STRIDE {
            *p = 0x90;
            p = p.add(1);
        }
    }
    Ok(addr)
}

fn set_idt_entry(idt: *mut IdtEntry, index: u8, handler: usize, flags: u8) {
    unsafe {
        (*idt.add(index as usize)).set_handler(handler, crate::gdt::KERNEL_CS, flags);
    }
}

pub fn enabled() -> bool {
    KPTI_ENABLED.load(Ordering::SeqCst)
}

pub fn init() -> Result<(), &'static str> {
    let kernel_cr3 = paging::kernel_page_directory_addr()
        .unwrap_or_else(|| paging::current_page_directory_addr());
    KPTI_KERNEL_CR3.store(kernel_cr3, Ordering::SeqCst);

    let tramp_base = memory::jit_allocate_pages(1)?;
    let idt_base = memory::jit_allocate_pages(1)?;

    unsafe {
        core::ptr::write_bytes(tramp_base as *mut u8, 0x90, paging::PAGE_SIZE);
        core::ptr::write_bytes(idt_base as *mut u8, 0, paging::PAGE_SIZE);
    }

    let tramp_ptr = tramp_base as *mut u8;
    let idt_ptr = idt_base as *mut IdtEntry;

    let mut offset = 0usize;
    let mut stub_addr = [0usize; 48];
    let isrs: [usize; 32] = [
        isr0 as usize, isr1 as usize, isr2 as usize, isr3 as usize, isr4 as usize, isr5 as usize,
        isr6 as usize, isr7 as usize, isr8 as usize, isr9 as usize, isr10 as usize, isr11 as usize,
        isr12 as usize, isr13 as usize, isr14 as usize, isr15 as usize, isr16 as usize, isr17 as usize,
        isr18 as usize, isr19 as usize, isr20 as usize, isr21 as usize, isr22 as usize, isr23 as usize,
        isr24 as usize, isr25 as usize, isr26 as usize, isr27 as usize, isr28 as usize, isr29 as usize,
        isr30 as usize, isr31 as usize,
    ];
    for (i, &handler) in isrs.iter().enumerate() {
        let addr = write_trampoline_stub(tramp_ptr, offset, handler)?;
        stub_addr[i] = addr;
        offset += STUB_STRIDE;
    }
    let irqs: [usize; 16] = [
        irq0 as usize, irq1 as usize, irq2 as usize, irq3 as usize,
        irq4 as usize, irq5 as usize, irq6 as usize, irq7 as usize,
        irq8 as usize, irq9 as usize, irq10 as usize, irq11 as usize,
        irq12 as usize, irq13 as usize, irq14 as usize, irq15 as usize,
    ];
    for (i, &handler) in irqs.iter().enumerate() {
        let addr = write_trampoline_stub(tramp_ptr, offset, handler)?;
        stub_addr[32 + i] = addr;
        offset += STUB_STRIDE;
    }
    let syscall_stub = write_trampoline_stub(tramp_ptr, offset, syscall_entry as usize)?;
    offset += STUB_STRIDE;
    let sysenter_stub = write_trampoline_stub(tramp_ptr, offset, sysenter_entry as usize)?;

    let flags_k = FLAG_PRESENT | GATE_INTERRUPT_32 | FLAG_DPL0;
    for i in 0..32u8 {
        set_idt_entry(idt_ptr, i, stub_addr[i as usize], flags_k);
    }
    for i in 0..16u8 {
        set_idt_entry(idt_ptr, 32 + i, stub_addr[(32 + i) as usize], flags_k);
    }
    let flags_u = FLAG_PRESENT | GATE_INTERRUPT_32 | FLAG_DPL3;
    set_idt_entry(idt_ptr, 0x80, syscall_stub, flags_u);

    let user_idt_ptr = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: idt_base as u32,
    };

    let state = KptiState {
        tramp_base,
        idt_base,
        idt_ptr: user_idt_ptr,
        sysenter_stub: sysenter_stub as u32,
        sysenter_kernel: sysenter_entry as u32,
    };
    *KPTI_STATE.lock() = Some(state);

    let _ = paging::set_page_writable_range(tramp_base, paging::PAGE_SIZE, false);
    let _ = paging::set_page_writable_range(idt_base, paging::PAGE_SIZE, false);

    KPTI_ENABLED.store(true, Ordering::SeqCst);
    crate::vga::print_str("[KPTI] Trampoline + user IDT ready\n");
    Ok(())
}

pub fn enter_user(cr3: u32) -> Result<(), &'static str> {
    if !enabled() {
        return Ok(());
    }
    if let Some(state) = *KPTI_STATE.lock() {
        KPTI_USER_CR3.store(cr3, Ordering::SeqCst);
        unsafe { write_msr(MSR_IA32_SYSENTER_EIP, state.sysenter_stub, 0) };
        unsafe { idt_asm::idt_load(&state.idt_ptr) };
        return Ok(());
    }
    Err("KPTI not initialized")
}

pub fn leave_user() {
    if !enabled() {
        return;
    }
    KPTI_USER_CR3.store(0, Ordering::SeqCst);
    if let Some(state) = *KPTI_STATE.lock() {
        unsafe { write_msr(MSR_IA32_SYSENTER_EIP, state.sysenter_kernel, 0) };
    }
    idt_asm::reload();
}

pub fn map_user_support(
    space: &mut paging::AddressSpace,
    kernel_space: &paging::AddressSpace,
) -> Result<(), &'static str> {
    if !enabled() {
        return Ok(());
    }
    let state = match *KPTI_STATE.lock() {
        Some(s) => s,
        None => return Err("KPTI not initialized"),
    };

    let tramp_phys = kernel_space
        .virt_to_phys(state.tramp_base)
        .ok_or("KPTI trampoline not mapped")?;
    let idt_phys = kernel_space
        .virt_to_phys(state.idt_base)
        .ok_or("KPTI IDT not mapped")?;

    space.map_page(state.tramp_base, tramp_phys, false, false)?;
    space.map_page(state.idt_base, idt_phys, false, false)?;

    // Map GDT + TSS pages (supervisor only)
    let (gdt_start, gdt_end) = gdt::gdt_range();
    map_kernel_range(space, kernel_space, gdt_start, gdt_end, false)?;
    let (tss_start, tss_end) = gdt::tss_range();
    map_kernel_range(space, kernel_space, tss_start, tss_end, true)?;

    // Map SYSENTER stack page
    let (sys_start, sys_end) = gdt::sysenter_stack_range();
    map_kernel_range(space, kernel_space, sys_start, sys_end, true)?;

    // Map current kernel stack page (TSS.esp0)
    let esp0 = gdt::kernel_stack_ptr() as usize;
    map_kernel_range(
        space,
        kernel_space,
        esp0.saturating_sub(paging::PAGE_SIZE),
        esp0 + paging::PAGE_SIZE,
        true,
    )?;

    // Map KPTI globals used by trampolines
    let (kpti_start, kpti_end) = kpti_globals_range();
    map_kernel_range(space, kernel_space, kpti_start, kpti_end, true)?;

    Ok(())
}

fn kpti_globals_range() -> (usize, usize) {
    let kcr3 = core::ptr::addr_of!(KPTI_KERNEL_CR3) as usize;
    let ucr3 = core::ptr::addr_of!(KPTI_USER_CR3) as usize;
    let start = core::cmp::min(kcr3, ucr3);
    let end = core::cmp::max(kcr3, ucr3) + core::mem::size_of::<AtomicU32>();
    (start, end)
}

fn map_kernel_range(
    space: &mut paging::AddressSpace,
    kernel_space: &paging::AddressSpace,
    start: usize,
    end: usize,
    writable: bool,
) -> Result<(), &'static str> {
    if end <= start {
        return Ok(());
    }
    let mut addr = start & !(paging::PAGE_SIZE - 1);
    let end = (end + paging::PAGE_SIZE - 1) & !(paging::PAGE_SIZE - 1);
    while addr < end {
        let phys = kernel_space
            .virt_to_phys(addr)
            .ok_or("Kernel range not mapped")?;
        space.map_page(addr, phys, writable, false)?;
        addr += paging::PAGE_SIZE;
    }
    Ok(())
}
