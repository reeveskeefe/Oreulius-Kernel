/*!
 * Oreulia Kernel Project
 * 
 *License-Identifier: Oreulius License (see LICENSE)
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


use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::asm_bindings;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_CS: u16 = 0x1B;
pub const USER_DS: u16 = 0x23;
const TSS_SELECTOR: u16 = 0x28;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

const COM1_BASE: u16 = 0x3F8;
const COM_LSR: u16 = COM1_BASE + 5;
const COM_DATA: u16 = COM1_BASE;

const IDT_TYPE_INTERRUPT_GATE: u8 = 0x8E;
const IDT_TYPE_INTERRUPT_GATE_DPL3: u8 = 0xEE;

static LAST_VECTOR: AtomicU8 = AtomicU8::new(0);
static LAST_ERROR: AtomicU64 = AtomicU64::new(0);
static EXC_COUNTS: [AtomicU64; 32] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static IRQ_COUNTS: [AtomicU64; 16] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

#[repr(C, packed)]
struct DescriptorTablePtr64 {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry64 {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry64 {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    fn set_handler(&mut self, handler: usize, selector: u16, type_attr: u8) {
        self.offset_low = handler as u16;
        self.selector = selector;
        self.ist = 0;
        self.type_attr = type_attr;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.zero = 0;
    }
}

#[repr(C)]
pub(crate) struct TrapFrameHead64 {
    rip: u64,
    cs: u64,
    rflags: u64,
}

#[repr(C)]
struct TrapFrameUser64 {
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

static mut IDT: [IdtEntry64; 256] = [IdtEntry64::missing(); 256];
static mut GDT: [u64; 7] = [0; 7];
static mut TSS64_BYTES: [u8; 104] = [0; 104];
static mut IRQ_STACK: [u8; 16 * 1024] = [0; 16 * 1024];

macro_rules! declare_isr_irq_stubs {
    ($($name:ident),* $(,)?) => {
        extern "C" {
            $(fn $name(); )*
        }
    };
}

declare_isr_irq_stubs!(
    isr0, isr1, isr2, isr3, isr4, isr5, isr6, isr7,
    isr8, isr9, isr10, isr11, isr12, isr13, isr14, isr15,
    isr16, isr17, isr18, isr19, isr20, isr21, isr22, isr23,
    isr24, isr25, isr26, isr27, isr28, isr29, isr30, isr31,
    irq0, irq1, irq2, irq3, irq4, irq5, irq6, irq7,
    irq8, irq9, irq10, irq11, irq12, irq13, irq14, irq15,
);

extern "C" {
    fn gdt_load(ptr: *const DescriptorTablePtr64);
    fn idt_load(ptr: *const DescriptorTablePtr64);
    fn tss_load(selector: u16);
    fn tss_set_kernel_stack(tss_addr: *mut u32, esp0: u32, ss0: u16);
    fn syscall_entry();
}

#[inline]
unsafe fn io_wait() {
    asm_bindings::outb(0x80, 0);
}

#[inline]
unsafe fn outb(port: u16, value: u8) {
    asm_bindings::outb(port, value);
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    asm_bindings::inb(port)
}

fn build_tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let mut low = 0u64;
    low |= (limit as u64) & 0xFFFF;
    low |= (base & 0x00FF_FFFF) << 16;
    low |= (0x89u64) << 40; // present, type=64-bit available TSS
    low |= (((limit as u64) >> 16) & 0xF) << 48;
    low |= ((base >> 24) & 0xFF) << 56;
    let high = (base >> 32) & 0xFFFF_FFFF;
    (low, high)
}

fn tss_set_rsp0(rsp0: u64) {
    unsafe {
        let tss = core::ptr::addr_of_mut!(TSS64_BYTES) as *mut u8;
        core::ptr::write_unaligned(tss.add(4) as *mut u64, rsp0);
        core::ptr::write_unaligned(tss.add(102) as *mut u16, TSS64_BYTES.len() as u16);
        if rsp0 <= (u32::MAX as u64) {
            // Compatibility signature used by existing Rust declarations.
            tss_set_kernel_stack(tss as *mut u32, rsp0 as u32, KERNEL_DS);
        }
    }
}

pub fn update_jit_kernel_stack_top(rsp0: usize) {
    tss_set_rsp0(rsp0 as u64);
}

pub fn init_cpu_tables() {
    unsafe {
        let irq_stack_top =
            (core::ptr::addr_of!(IRQ_STACK) as *const u8).add(IRQ_STACK.len()) as u64;
        tss_set_rsp0(irq_stack_top);

        GDT[0] = 0;
        GDT[1] = 0x00AF9A000000FFFF; // kernel code
        GDT[2] = 0x00AF92000000FFFF; // kernel data

        let tss_base = core::ptr::addr_of!(TSS64_BYTES) as u64;
        let (tss_low, tss_high) = build_tss_descriptor(tss_base, (TSS64_BYTES.len() - 1) as u32);
        GDT[3] = 0x00AFFA000000FFFF; // user code (64-bit, DPL3)
        GDT[4] = 0x00AFF2000000FFFF; // user data (DPL3)
        GDT[5] = tss_low;
        GDT[6] = tss_high;

        let gdt_ptr = DescriptorTablePtr64 {
            limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as *const _ as u64,
        };
        gdt_load(&gdt_ptr);

        let data_sel = KERNEL_DS;
        core::arch::asm!(
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            in("ax") data_sel,
            options(nostack, preserves_flags),
        );

        tss_load(TSS_SELECTOR);
    }
}

fn idt_set(vector: u8, handler: usize) {
    unsafe {
        IDT[vector as usize].set_handler(handler, KERNEL_CS, IDT_TYPE_INTERRUPT_GATE);
    }
}

fn idt_set_with_attr(vector: u8, handler: usize, type_attr: u8) {
    unsafe {
        IDT[vector as usize].set_handler(handler, KERNEL_CS, type_attr);
    }
}

pub fn init_trap_table() {
    let exceptions: [usize; 32] = [
        isr0 as usize, isr1 as usize, isr2 as usize, isr3 as usize,
        isr4 as usize, isr5 as usize, isr6 as usize, isr7 as usize,
        isr8 as usize, isr9 as usize, isr10 as usize, isr11 as usize,
        isr12 as usize, isr13 as usize, isr14 as usize, isr15 as usize,
        isr16 as usize, isr17 as usize, isr18 as usize, isr19 as usize,
        isr20 as usize, isr21 as usize, isr22 as usize, isr23 as usize,
        isr24 as usize, isr25 as usize, isr26 as usize, isr27 as usize,
        isr28 as usize, isr29 as usize, isr30 as usize, isr31 as usize,
    ];
    let irqs: [usize; 16] = [
        irq0 as usize, irq1 as usize, irq2 as usize, irq3 as usize,
        irq4 as usize, irq5 as usize, irq6 as usize, irq7 as usize,
        irq8 as usize, irq9 as usize, irq10 as usize, irq11 as usize,
        irq12 as usize, irq13 as usize, irq14 as usize, irq15 as usize,
    ];

    for (i, &h) in exceptions.iter().enumerate() {
        idt_set(i as u8, h);
    }
    for (i, &h) in irqs.iter().enumerate() {
        idt_set((32 + i) as u8, h);
    }
    idt_set_with_attr(0x80, syscall_entry as usize, IDT_TYPE_INTERRUPT_GATE_DPL3);

    unsafe {
        let idt_ptr = DescriptorTablePtr64 {
            limit: (core::mem::size_of::<[IdtEntry64; 256]>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as *const _ as u64,
        };
        idt_load(&idt_ptr);
    }
}

pub fn init_interrupt_controller() {
    unsafe {
        let pic1_mask = inb(PIC1_DATA);
        let pic2_mask = inb(PIC2_DATA);

        outb(PIC1_CMD, 0x11);
        io_wait();
        outb(PIC2_CMD, 0x11);
        io_wait();

        outb(PIC1_DATA, 32);
        io_wait();
        outb(PIC2_DATA, 40);
        io_wait();

        outb(PIC1_DATA, 4);
        io_wait();
        outb(PIC2_DATA, 2);
        io_wait();

        outb(PIC1_DATA, 0x01);
        io_wait();
        outb(PIC2_DATA, 0x01);
        io_wait();

        let _ = (pic1_mask, pic2_mask);

        // Unmask timer (IRQ0) only.
        outb(PIC1_DATA, 0xFE);
        outb(PIC2_DATA, 0xFF);
    }
}

pub fn init_timer() {
    crate::pit::init();
}

pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

fn pic_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, PIC_EOI);
        }
        outb(PIC1_CMD, PIC_EOI);
    }
}

fn is_error_code_vector(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

#[no_mangle]
pub extern "C" fn x86_64_trap_dispatch(vector: u64, error: u64, frame: *mut TrapFrameHead64) {
    let vector = vector as u8;
    LAST_VECTOR.store(vector, Ordering::Relaxed);
    LAST_ERROR.store(error, Ordering::Relaxed);

    if vector < 32 {
        EXC_COUNTS[vector as usize].fetch_add(1, Ordering::Relaxed);

        let mut frame_rip = 0u64;
        let mut frame_cs = 0u64;
        let mut frame_rsp = 0u64;
        let mut have_user_frame = false;
        if !frame.is_null() {
            let f = unsafe { &mut *frame };
            frame_rip = f.rip;
            frame_cs = f.cs;
            if (f.cs & 0x3) == 0x3 {
                let uf = unsafe { &mut *(frame as *mut TrapFrameUser64) };
                frame_rsp = uf.rsp;
                have_user_frame = true;
            }
        }

        if vector == 14 {
            let fault_addr: usize;
            unsafe {
                core::arch::asm!("mov {}, cr2", out(reg) fault_addr, options(nomem, nostack, preserves_flags));
            }
            if have_user_frame && !frame.is_null() {
                let uf = unsafe { &mut *(frame as *mut TrapFrameUser64) };
                if crate::wasm::jit_handle_page_fault_x86_64(
                    fault_addr,
                    error,
                    &mut uf.rip,
                    uf.cs,
                    &mut uf.rsp,
                ) {
                    return;
                }
            }
            if crate::arch::mmu::handle_page_fault(fault_addr, error) {
                return;
            }
            crate::serial_println!(
                "[X64-PF] unhandled cr2={:#018x} err={:#x}",
                fault_addr,
                error
            );
        }

        if vector != 14 && have_user_frame && !frame.is_null() {
            let uf = unsafe { &mut *(frame as *mut TrapFrameUser64) };
            if crate::wasm::jit_handle_exception_x86_64(
                vector as u64,
                error,
                &mut uf.rip,
                uf.cs,
                &mut uf.rsp,
            ) {
                return;
            }
        }

        // Log a subset of exceptions during bring-up to validate the trap path.
        if vector == 3 || vector == 13 || vector == 14 {
            if !frame.is_null() {
                let f = unsafe { &*frame };
                crate::serial_println!(
                    "[X64-TRAP] vec={} err={:#x} rip={:#018x} cs={:#x} rflags={:#018x}",
                    vector,
                    error,
                    f.rip,
                    f.cs,
                    f.rflags
                );
            } else {
                crate::serial_println!("[X64-TRAP] vec={} err={:#x}", vector, error);
            }
        }
        return;
    }

    if (32..48).contains(&vector) {
        let irq = vector - 32;
        IRQ_COUNTS[irq as usize].fetch_add(1, Ordering::Relaxed);
        if irq == 0 {
            crate::pit::tick();
            if !frame.is_null() {
                let f = unsafe { &*frame };
                if (f.cs & 0x3) == 0x3 {
                    let uf = unsafe { &mut *(frame as *mut TrapFrameUser64) };
                    let _ = crate::wasm::jit_handle_timer_interrupt_x86_64(
                        &mut uf.rip,
                        uf.cs,
                        &mut uf.rsp,
                    );
                }
            }
        }
        pic_eoi(irq);
    }
}

pub fn exception_count(vector: u8) -> u64 {
    EXC_COUNTS.get(vector as usize).map(|v| v.load(Ordering::Relaxed)).unwrap_or(0)
}

pub fn irq_count(irq: u8) -> u64 {
    IRQ_COUNTS.get(irq as usize).map(|v| v.load(Ordering::Relaxed)).unwrap_or(0)
}

pub fn last_vector() -> u8 {
    LAST_VECTOR.load(Ordering::Relaxed)
}

pub fn last_error() -> u64 {
    LAST_ERROR.load(Ordering::Relaxed)
}

pub fn trigger_breakpoint() {
    unsafe {
        core::arch::asm!("int3", options(nomem, nostack));
    }
}

fn serial_try_read_byte() -> Option<u8> {
    unsafe {
        let status = inb(COM_LSR);
        if (status & 0x01) == 0 {
            return None;
        }
        Some(inb(COM_DATA))
    }
}

fn serial_write_prompt() {
    crate::serial_print!("\r\nx64> ");
}

fn serial_exec_command(cmd: &str) -> bool {
    match cmd {
        "" => {}
        "help" => {
            crate::serial_println!("commands: help ticks irq0 int3 traps pfstats cowtest vmtest jitpre jitcall jitbench jitfuzz jitfuzzreg mmu regs halt");
        }
        "ticks" => {
            crate::serial_println!("[X64] ticks={}", crate::pit::get_ticks());
        }
        "irq0" => {
            crate::serial_println!("[X64] irq0-count={}", irq_count(0));
        }
        "int3" => {
            crate::serial_println!("[X64] triggering int3");
            trigger_breakpoint();
            crate::serial_println!(
                "[X64] breakpoint count={} last_vec={} last_err={:#x}",
                exception_count(3),
                last_vector(),
                last_error(),
            );
        }
        "traps" => {
            crate::serial_println!(
                "[X64] trap-counts: #BP={} #GP={} #PF={} last_vec={} last_err={:#x}",
                exception_count(3),
                exception_count(13),
                exception_count(14),
                last_vector(),
                last_error(),
            );
        }
        "pfstats" => {
            let (pf, cow, copies) = crate::arch::mmu::x86_64_debug_pf_stats();
            crate::serial_println!(
                "[X64] pf-stats faults={} cow={} copies={}",
                pf, cow, copies
            );
        }
        "mmu" => {
            crate::serial_println!(
                "[X64] mmu backend={} cr3={:#018x}",
                crate::arch::mmu::backend_name(),
                crate::arch::mmu::current_page_table_root_addr(),
            );
        }
        "regs" => {
            let (cr0, cr3, cr4) = read_ctrl_regs();
            let efer = read_efer();
            crate::serial_println!(
                "[X64] cr0={:#018x} cr3={:#018x} cr4={:#018x} efer={:#018x}",
                cr0, cr3, cr4, efer
            );
        }
        "cowtest" => {
            match cow_self_test() {
                Ok(()) => crate::serial_println!("[X64] cowtest ok"),
                Err(e) => crate::serial_println!("[X64] cowtest failed: {}", e),
            }
        }
        "vmtest" => {
            match vm_map_self_test() {
                Ok(()) => crate::serial_println!("[X64] vmtest ok"),
                Err(e) => crate::serial_println!("[X64] vmtest failed: {}", e),
            }
        }
        "jitpre" => {
            match crate::wasm::jit_x86_64_sandbox_preflight() {
                Ok(()) => crate::serial_println!("[X64] jitpre ok"),
                Err(e) => crate::serial_println!("[X64] jitpre failed: {}", e),
            }
        }
        "jitcall" => {
            match crate::wasm::jit_x86_64_call_user_path_probe() {
                Ok(msg) => crate::serial_println!("[X64] jitcall ok: {}", msg),
                Err(e) => crate::serial_println!("[X64] jitcall failed: {}", e),
            }
        }
        "jitbench" => {
            match crate::wasm::jit_bounds_self_test() {
                Ok(()) => crate::serial_println!("[X64] jitbench ok: wasm-jit-bounds-selftest"),
                Err(e) => crate::serial_println!("[X64] jitbench failed: {}", e),
            }
        }
        "jitfuzz" => {
            match jit_fuzz_smoke_self_test() {
                Ok((iters, ok, traps)) => crate::serial_println!(
                    "[X64] jitfuzz ok: iters={} ok={} traps={}",
                    iters, ok, traps
                ),
                Err(e) => crate::serial_println!("[X64] jitfuzz failed: {}", e),
            }
        }
        "jitfuzzreg" => {
            crate::serial_println!("[X64] jitfuzzreg begin: regression dry-run");
            match crate::wasm::jit_fuzz_regression_default(1) {
                Ok(stats) => crate::serial_println!(
                    "[X64] jitfuzzreg ok: seeds_passed={} seeds_failed={} mismatches={} compile_errors={}",
                    stats.seeds_passed,
                    stats.seeds_failed,
                    stats.total_mismatches,
                    stats.total_compile_errors
                ),
                Err(e) => crate::serial_println!("[X64] jitfuzzreg failed: {}", e),
            }
        }
        "halt" | "exit" => {
            crate::serial_println!("[X64] halting");
            return false;
        }
        _ => {
            crate::serial_println!("[X64] unknown command: {}", cmd);
        }
    }
    true
}

fn cow_self_test() -> Result<(), &'static str> {
    let page = crate::memory::allocate_frame()?;
    let ptr = page as *mut u8;
    unsafe {
        ptr.write(0x41);
        ptr.add(1).write(0x42);
    }

    let phys_before = crate::arch::mmu::x86_64_debug_virt_to_phys(page).ok_or("virt->phys before failed")?;
    crate::arch::mmu::x86_64_debug_mark_page_cow(page)?;

    let (_pf_before, cow_before, copies_before) = crate::arch::mmu::x86_64_debug_pf_stats();

    // This should trap (#PF write) and be resolved by the x86_64 MMU COW handler.
    unsafe {
        ptr.write(0x7A);
        ptr.add(1).write(0x7B);
    }

    let phys_after = crate::arch::mmu::x86_64_debug_virt_to_phys(page).ok_or("virt->phys after failed")?;
    let (_pf_after, cow_after, copies_after) = crate::arch::mmu::x86_64_debug_pf_stats();

    let a = unsafe { ptr.read() };
    let b = unsafe { ptr.add(1).read() };
    crate::serial_println!(
        "[X64] cowtest phys {:#x} -> {:#x}, bytes={:#x}/{:#x}, cow {}->{}, copies {}->{}",
        phys_before,
        phys_after,
        a,
        b,
        cow_before,
        cow_after,
        copies_before,
        copies_after
    );

    if phys_before == phys_after {
        return Err("COW page fault did not remap page");
    }
    if a != 0x7A || b != 0x7B {
        return Err("COW write verification failed");
    }
    if cow_after <= cow_before || copies_after <= copies_before {
        return Err("COW/page-copy counters did not advance");
    }
    Ok(())
}

fn native_jit_exec_self_test() -> Result<(), &'static str> {
    // x86_64: mov eax, 0x12345678 ; ret
    const CODE: [u8; 6] = [0xB8, 0x78, 0x56, 0x34, 0x12, 0xC3];
    let exec = crate::memory::jit_allocate_pages(1)?;
    let _ = crate::memory_isolation::tag_jit_code_kernel(exec, crate::paging::PAGE_SIZE, false);
    crate::arch::mmu::set_page_writable_range(exec, crate::paging::PAGE_SIZE, true)?;
    unsafe {
        core::ptr::copy_nonoverlapping(CODE.as_ptr(), exec as *mut u8, CODE.len());
    }
    crate::arch::mmu::set_page_writable_range(exec, crate::paging::PAGE_SIZE, false)?;
    let _ = crate::memory_isolation::tag_jit_code_kernel(exec, crate::paging::PAGE_SIZE, true);

    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(exec) };
    let ret = f();
    if ret != 0x1234_5678 {
        return Err("native JIT exec returned wrong value");
    }
    Ok(())
}

fn jit_fuzz_smoke_self_test() -> Result<(u32, u32, u32), &'static str> {
    use alloc::vec::Vec;
    use crate::wasm::{Opcode, MAX_INSTRUCTIONS_PER_CALL};

    const ITERS: usize = 32;

    #[derive(Clone, Copy)]
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self { Self(seed) }
        fn next_u32(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            (x as u32) ^ ((x >> 32) as u32)
        }
    }

    fn push_uleb128(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 { byte |= 0x80; }
            buf.push(byte);
            if value == 0 { break; }
        }
    }

    fn push_sleb128_i32(buf: &mut Vec<u8>, mut value: i32) {
        let mut more = true;
        while more {
            let mut byte = (value & 0x7F) as u8;
            let sign = (byte & 0x40) != 0;
            value >>= 7;
            if (value == 0 && !sign) || (value == -1 && sign) {
                more = false;
            } else {
                byte |= 0x80;
            }
            buf.push(byte);
        }
    }

    fn emit_i32_const(code: &mut Vec<u8>, v: i32) { code.push(Opcode::I32Const as u8); push_sleb128_i32(code, v); }
    fn emit_local_get(code: &mut Vec<u8>, idx: u32) { code.push(Opcode::LocalGet as u8); push_uleb128(code, idx); }
    fn emit_local_set(code: &mut Vec<u8>, idx: u32) { code.push(Opcode::LocalSet as u8); push_uleb128(code, idx); }
    fn emit_local_tee(code: &mut Vec<u8>, idx: u32) { code.push(Opcode::LocalTee as u8); push_uleb128(code, idx); }
    fn emit_i32_load(code: &mut Vec<u8>, off: u32) { code.push(Opcode::I32Load as u8); push_uleb128(code, 0); push_uleb128(code, off); }
    fn emit_i32_store(code: &mut Vec<u8>, off: u32) { code.push(Opcode::I32Store as u8); push_uleb128(code, 0); push_uleb128(code, off); }

    let mut rng = Rng::new(0x5846_554A_4954_0002);
    let mut code: Vec<u8> = Vec::with_capacity(128);

    let state_bytes = core::mem::size_of::<crate::wasm::JitUserState>();
    let state_pages = state_bytes
        .checked_add(crate::paging::PAGE_SIZE - 1)
        .ok_or("jitfuzz state size overflow")?
        / crate::paging::PAGE_SIZE;
    let state_base = crate::memory::jit_allocate_pages(state_pages)? as *mut crate::wasm::JitUserState;
    if state_base.is_null() {
        return Err("jitfuzz state alloc failed");
    }
    unsafe {
        core::ptr::write_bytes(state_base as *mut u8, 0, state_pages * crate::paging::PAGE_SIZE);
    }

    let mem_pages = 1usize;
    let mem_len = crate::paging::PAGE_SIZE;
    let mem_base = crate::memory::jit_allocate_pages(mem_pages)? as *mut u8;
    if mem_base.is_null() {
        return Err("jitfuzz mem alloc failed");
    }
    unsafe {
        core::ptr::write_bytes(mem_base, 0, mem_pages * crate::paging::PAGE_SIZE);
    }

    let state = unsafe { &mut *state_base };

    let mut ok = 0u32;
    let mut traps = 0u32;
    let mut compile_errors = 0u32;

    for iter in 0..ITERS {
        code.clear();
        let locals_total = 2usize;
        let mut stack_depth = 0i32;
        let mut used_store = false;
        let mut used_local = false;
        let mut used_arith = false;

        emit_i32_const(&mut code, (rng.next_u32() as i32) & 0xFF);
        stack_depth += 1;
        emit_i32_const(&mut code, (rng.next_u32() as i32) & 0xFF);
        stack_depth += 1;
        if (rng.next_u32() & 1) == 0 {
            code.push(Opcode::I32Add as u8);
        } else {
            code.push(Opcode::I32Xor as u8);
        }
        used_arith = true;
        stack_depth -= 1;

        emit_local_set(&mut code, 0);
        stack_depth -= 1;
        used_local = true;

        emit_i32_const(&mut code, ((rng.next_u32() & 0x3FF) as i32) & !3);
        stack_depth += 1;
        emit_local_get(&mut code, 0);
        stack_depth += 1;
        emit_i32_store(&mut code, 0);
        stack_depth -= 2;
        used_store = true;

        emit_i32_const(&mut code, ((rng.next_u32() & 0x3FF) as i32) & !3);
        stack_depth += 1;
        emit_i32_load(&mut code, 0);

        if (rng.next_u32() % 3) == 0 {
            emit_local_tee(&mut code, 1);
            used_local = true;
        }
        if (rng.next_u32() % 2) == 0 {
            code.push(Opcode::I32Eqz as u8);
        } else {
            emit_i32_const(&mut code, 0);
            code.push(Opcode::I32Ne as u8);
        }
        used_arith = true;

        if stack_depth <= 0 {
            emit_i32_const(&mut code, iter as i32);
        }
        code.push(Opcode::End as u8);

        if !used_store || !used_local || !used_arith || code.len() > MAX_INSTRUCTIONS_PER_CALL {
            return Err("jitfuzz internal program shape failure");
        }

        let jit = match crate::wasm_jit::compile(&code, locals_total) {
            Ok(j) => j,
            Err(_) => {
                compile_errors = compile_errors.saturating_add(1);
                continue;
            }
        };
        let jit_entry = crate::wasm::JitExecInfo {
            entry: jit.entry,
            exec_ptr: jit.exec.ptr,
            exec_len: jit.exec.len,
        };

        unsafe {
            core::ptr::write_bytes(mem_base, 0, mem_len);
        }
        state.sp = 0;
        state.shadow_sp = 0;
        state.instr_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
        state.mem_fuel = MAX_INSTRUCTIONS_PER_CALL as u32;
        state.trap_code = 0;
        for local in state.locals.iter_mut() { *local = 0; }

        let _ret = crate::wasm::call_jit_kernel(
            jit_entry,
            state.stack.as_mut_ptr(),
            &mut state.sp as *mut usize,
            mem_base,
            mem_len,
            state.locals.as_mut_ptr(),
            &mut state.instr_fuel as *mut u32,
            &mut state.mem_fuel as *mut u32,
            &mut state.trap_code as *mut i32,
            state.shadow_stack.as_mut_ptr(),
            &mut state.shadow_sp as *mut usize,
        );

        if state.trap_code == 0 {
            ok = ok.saturating_add(1);
        } else {
            traps = traps.saturating_add(1);
        }
    }

    if compile_errors != 0 {
        return Err("x86_64 jitfuzz compile-errors");
    }
    if ok == 0 {
        return Err("x86_64 jitfuzz no-successful-runs");
    }
    Ok((ITERS as u32, ok, traps))
}

fn vm_map_self_test() -> Result<(), &'static str> {
    let mut space = crate::arch::mmu::AddressSpace::new()?;

    let code_va = 0x0040_0000usize;
    let stack_va = crate::paging::USER_TOP - crate::paging::PAGE_SIZE;
    let phys_map_va = 0x0080_0000usize;

    crate::arch::mmu::alloc_user_pages(&mut space, code_va, 1, true)?;
    crate::arch::mmu::alloc_user_pages(&mut space, stack_va, 1, true)?;

    let phys_page = crate::memory::allocate_frame()?;
    crate::arch::mmu::map_user_range_phys(&mut space, phys_map_va, phys_page, crate::paging::PAGE_SIZE, true)?;

    if !space.is_mapped(code_va) || !space.is_mapped(stack_va) || !space.is_mapped(phys_map_va) {
        return Err("mapped pages not visible in new address space");
    }

    let old_root = crate::arch::mmu::current_page_table_root_addr();
    unsafe { space.activate(); }
    unsafe {
        (code_va as *mut u8).write(0xC3);
        (stack_va as *mut u8).write(0x5A);
        (phys_map_va as *mut u8).write(0xA5);
    }
    let code_byte = unsafe { (code_va as *const u8).read() };
    let stack_byte = unsafe { (stack_va as *const u8).read() };
    let phys_byte = unsafe { (phys_map_va as *const u8).read() };
    crate::arch::mmu::set_page_table_root(old_root)?;

    crate::serial_println!(
        "[X64] vmtest root={:#x} bytes code={:#x} stack={:#x} physmap={:#x}",
        space.page_table_root_addr(),
        code_byte,
        stack_byte,
        phys_byte,
    );

    if code_byte != 0xC3 || stack_byte != 0x5A || phys_byte != 0xA5 {
        return Err("write/read verification failed");
    }

    crate::arch::mmu::unmap_page(&mut space, code_va)?;
    crate::arch::mmu::unmap_page(&mut space, phys_map_va)?;
    if space.is_mapped(code_va) || space.is_mapped(phys_map_va) {
        return Err("unmap verification failed");
    }

    Ok(())
}

pub fn read_ctrl_regs() -> (u64, u64, u64) {
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr0, cr3, cr4)
}

pub fn read_efer() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0080u32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

pub fn wait_for_ticks(min_delta: u64, max_spin_hlt: usize) -> bool {
    let start = crate::pit::get_ticks();
    for _ in 0..max_spin_hlt {
        if crate::pit::get_ticks().wrapping_sub(start) >= min_delta {
            return true;
        }
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
    false
}

pub fn run_serial_shell() -> ! {
    crate::serial_println!("[X64] minimal serial shell ready (type 'help')");
    serial_write_prompt();

    let mut buf = [0u8; 128];
    let mut len = 0usize;
    let mut last_heartbeat = crate::pit::get_ticks();

    loop {
        if let Some(byte) = serial_try_read_byte() {
            match byte {
                b'\r' | b'\n' => {
                    crate::serial_println!("");
                    let cmd = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    let keep_running = serial_exec_command(cmd.trim());
                    len = 0;
                    if !keep_running {
                        crate::arch::halt_loop();
                    }
                    serial_write_prompt();
                }
                8 | 127 => {
                    if len > 0 {
                        len -= 1;
                        crate::serial_print!("\x08 \x08");
                    }
                }
                b if (0x20..=0x7E).contains(&b) => {
                    if len < buf.len() - 1 {
                        buf[len] = b;
                        len += 1;
                        crate::serial_print!("{}", b as char);
                    }
                }
                _ => {}
            }
        }

        let ticks = crate::pit::get_ticks();
        if ticks.wrapping_sub(last_heartbeat) >= 100 {
            last_heartbeat = ticks;
            let (pf, cow, _) = crate::arch::mmu::x86_64_debug_pf_stats();
            crate::serial_println!(
                "[X64] heartbeat ticks={} irq0={} #BP={} #PF={} COW={}",
                ticks,
                irq_count(0),
                exception_count(3),
                pf,
                cow,
            );
            if len > 0 {
                crate::serial_print!("x64> {}", core::str::from_utf8(&buf[..len]).unwrap_or(""));
            } else {
                crate::serial_print!("x64> ");
            }
        }

        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

pub fn self_test_traps_and_timer() {
    crate::serial_println!("[X64] loading #BP self-test...");
    let before_bp = exception_count(3);
    trigger_breakpoint();
    let after_bp = exception_count(3);
    crate::serial_println!(
        "[X64] #BP self-test count {} -> {} (ok={})",
        before_bp,
        after_bp,
        if after_bp == before_bp + 1 { 1 } else { 0 }
    );

    let got_ticks = wait_for_ticks(3, 20_000);
    crate::serial_println!(
        "[X64] timer self-test irq0={} ticks={} ok={}",
        irq_count(0),
        crate::pit::get_ticks(),
        if got_ticks { 1 } else { 0 }
    );
}

#[allow(dead_code)]
pub fn vector_has_error_code(vector: u8) -> bool {
    is_error_code_vector(vector)
}
