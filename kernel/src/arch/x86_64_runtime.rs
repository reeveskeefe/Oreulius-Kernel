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


use core::{fmt, sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering}};

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
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

const IDT_TYPE_INTERRUPT_GATE: u8 = 0x8E;
const IDT_TYPE_INTERRUPT_GATE_DPL3: u8 = 0xEE;

static LAST_VECTOR: AtomicU8 = AtomicU8::new(0);
static LAST_ERROR: AtomicU64 = AtomicU64::new(0);
static HEARTBEAT_LOG_ENABLED: AtomicBool = AtomicBool::new(false);
static SHELL_CONSOLE_MODE: AtomicU8 = AtomicU8::new(0); // 0=both, 1=serial, 2=vga
static KBDTEST_ENABLED: AtomicBool = AtomicBool::new(false);
static PF_LOOP_LAST_RIP: AtomicU64 = AtomicU64::new(0);
static PF_LOOP_LAST_ADDR: AtomicU64 = AtomicU64::new(0);
static PF_LOOP_REPEAT_COUNT: AtomicU64 = AtomicU64::new(0);
static PS2_SHIFT_DOWN: AtomicBool = AtomicBool::new(false);
static PS2_EXTENDED_PREFIX: AtomicBool = AtomicBool::new(false);
static PS2_KBD_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static PS2_KBD_LAST_RAW: AtomicU8 = AtomicU8::new(0);
static PS2_KBD_LAST_DECODED: AtomicU8 = AtomicU8::new(0);
static PS2_KBD_LAST_FLAGS: AtomicU8 = AtomicU8::new(0);
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

macro_rules! shell_print {
    ($($arg:tt)*) => {{
        shell_print_fmt(format_args!($($arg)*));
    }};
}

macro_rules! shell_println {
    () => {{
        shell_print_fmt(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        shell_print_fmt(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

const KBD_FLAG_RELEASE: u8 = 1 << 0;
const KBD_FLAG_DECODED: u8 = 1 << 1;
const KBD_FLAG_E0_PREFIX: u8 = 1 << 2;
const KBD_FLAG_EXTENDED: u8 = 1 << 3;
const KBD_FLAG_SHIFT: u8 = 1 << 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellConsoleMode {
    Both,
    SerialOnly,
    VgaOnly,
}

fn shell_console_mode() -> ShellConsoleMode {
    match SHELL_CONSOLE_MODE.load(Ordering::Relaxed) {
        1 => ShellConsoleMode::SerialOnly,
        2 => ShellConsoleMode::VgaOnly,
        _ => ShellConsoleMode::Both,
    }
}

fn shell_set_console_mode(mode: ShellConsoleMode) {
    let raw = match mode {
        ShellConsoleMode::Both => 0,
        ShellConsoleMode::SerialOnly => 1,
        ShellConsoleMode::VgaOnly => 2,
    };
    SHELL_CONSOLE_MODE.store(raw, Ordering::Relaxed);
}

fn shell_print_fmt(args: fmt::Arguments<'_>) {
    use core::fmt::Write;

    let mode = shell_console_mode();

    if mode != ShellConsoleMode::VgaOnly {
        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = serial.write_fmt(args);
        }
    }

    if mode != ShellConsoleMode::SerialOnly {
        struct TerminalAdapter;
        impl fmt::Write for TerminalAdapter {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                // Avoid double-echoing to serial: the x86_64 shell wrapper already
                // writes to COM1 when serial output is enabled.
                crate::terminal::write_str_no_serial(s);
                Ok(())
            }
        }
        let mut terminal_writer = TerminalAdapter;
        let _ = terminal_writer.write_fmt(args);
    }
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

#[cold]
fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nomem, nostack, preserves_flags));
        }
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
            if !frame.is_null() {
                if have_user_frame {
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
                } else {
                    let f = unsafe { &mut *frame };
                    let mut dummy_rsp = 0u64;
                    if crate::wasm::jit_handle_page_fault_x86_64(
                        fault_addr,
                        error,
                        &mut f.rip,
                        f.cs,
                        &mut dummy_rsp,
                    ) {
                        return;
                    }
                }
            }
            if crate::arch::mmu::handle_page_fault(fault_addr, error) {
                PF_LOOP_REPEAT_COUNT.store(0, Ordering::Relaxed);
                return;
            }
            let rip = if !frame.is_null() {
                unsafe { (*frame).rip }
            } else {
                0
            };
            let prev_rip = PF_LOOP_LAST_RIP.load(Ordering::Relaxed);
            let prev_addr = PF_LOOP_LAST_ADDR.load(Ordering::Relaxed);
            let repeat = if prev_rip == rip && prev_addr == fault_addr as u64 {
                PF_LOOP_REPEAT_COUNT
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1)
            } else {
                PF_LOOP_LAST_RIP.store(rip, Ordering::Relaxed);
                PF_LOOP_LAST_ADDR.store(fault_addr as u64, Ordering::Relaxed);
                PF_LOOP_REPEAT_COUNT.store(1, Ordering::Relaxed);
                1
            };
            crate::serial_println!(
                "[X64-PF] unhandled cr2={:#018x} err={:#x} rip={:#018x} repeat={}",
                fault_addr,
                error,
                rip,
                repeat,
            );
            if repeat >= 64 {
                crate::serial_println!(
                    "[X64-PF] repeating unhandled PF at same RIP/CR2; halting to avoid livelock"
                );
                halt_forever();
            }
        }

        if vector != 14 && !frame.is_null() {
            if have_user_frame {
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
            } else {
                let f = unsafe { &mut *frame };
                let mut dummy_rsp = 0u64;
                if crate::wasm::jit_handle_exception_x86_64(
                    vector as u64,
                    error,
                    &mut f.rip,
                    f.cs,
                    &mut dummy_rsp,
                ) {
                    return;
                }
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
                let f = unsafe { &mut *frame };
                if (f.cs & 0x3) == 0x3 {
                    let uf = unsafe { &mut *(frame as *mut TrapFrameUser64) };
                    let _ = crate::wasm::jit_handle_timer_interrupt_x86_64(
                        &mut uf.rip,
                        uf.cs,
                        &mut uf.rsp,
                    );
                } else {
                    let mut dummy_rsp = 0u64;
                    let _ = crate::wasm::jit_handle_timer_interrupt_x86_64(
                        &mut f.rip,
                        f.cs,
                        &mut dummy_rsp,
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

fn ps2_set1_scancode_to_ascii(sc: u8, shifted: bool) -> Option<u8> {
    let ch = match sc {
        0x02 => if shifted { b'!' } else { b'1' },
        0x03 => if shifted { b'@' } else { b'2' },
        0x04 => if shifted { b'#' } else { b'3' },
        0x05 => if shifted { b'$' } else { b'4' },
        0x06 => if shifted { b'%' } else { b'5' },
        0x07 => if shifted { b'^' } else { b'6' },
        0x08 => if shifted { b'&' } else { b'7' },
        0x09 => if shifted { b'*' } else { b'8' },
        0x0A => if shifted { b'(' } else { b'9' },
        0x0B => if shifted { b')' } else { b'0' },
        0x0C => if shifted { b'_' } else { b'-' },
        0x0D => if shifted { b'+' } else { b'=' },
        0x10 => if shifted { b'Q' } else { b'q' },
        0x11 => if shifted { b'W' } else { b'w' },
        0x12 => if shifted { b'E' } else { b'e' },
        0x13 => if shifted { b'R' } else { b'r' },
        0x14 => if shifted { b'T' } else { b't' },
        0x15 => if shifted { b'Y' } else { b'y' },
        0x16 => if shifted { b'U' } else { b'u' },
        0x17 => if shifted { b'I' } else { b'i' },
        0x18 => if shifted { b'O' } else { b'o' },
        0x19 => if shifted { b'P' } else { b'p' },
        0x1A => if shifted { b'{' } else { b'[' },
        0x1B => if shifted { b'}' } else { b']' },
        0x1C => b'\n',
        0x1E => if shifted { b'A' } else { b'a' },
        0x1F => if shifted { b'S' } else { b's' },
        0x20 => if shifted { b'D' } else { b'd' },
        0x21 => if shifted { b'F' } else { b'f' },
        0x22 => if shifted { b'G' } else { b'g' },
        0x23 => if shifted { b'H' } else { b'h' },
        0x24 => if shifted { b'J' } else { b'j' },
        0x25 => if shifted { b'K' } else { b'k' },
        0x26 => if shifted { b'L' } else { b'l' },
        0x27 => if shifted { b':' } else { b';' },
        0x28 => if shifted { b'"' } else { b'\'' },
        0x29 => if shifted { b'~' } else { b'`' },
        0x2B => if shifted { b'|' } else { b'\\' },
        0x2C => if shifted { b'Z' } else { b'z' },
        0x2D => if shifted { b'X' } else { b'x' },
        0x2E => if shifted { b'C' } else { b'c' },
        0x2F => if shifted { b'V' } else { b'v' },
        0x30 => if shifted { b'B' } else { b'b' },
        0x31 => if shifted { b'N' } else { b'n' },
        0x32 => if shifted { b'M' } else { b'm' },
        0x33 => if shifted { b'<' } else { b',' },
        0x34 => if shifted { b'>' } else { b'.' },
        0x35 => if shifted { b'?' } else { b'/' },
        0x39 => b' ',
        0x0E => 8, // backspace
        _ => return None,
    };
    Some(ch)
}

fn kbdtest_record_event(raw: u8, decoded: Option<u8>, mut flags: u8) {
    if PS2_SHIFT_DOWN.load(Ordering::Relaxed) {
        flags |= KBD_FLAG_SHIFT;
    }
    if decoded.is_some() {
        flags |= KBD_FLAG_DECODED;
    }

    PS2_KBD_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    PS2_KBD_LAST_RAW.store(raw, Ordering::Relaxed);
    PS2_KBD_LAST_DECODED.store(decoded.unwrap_or(0), Ordering::Relaxed);
    PS2_KBD_LAST_FLAGS.store(flags, Ordering::Relaxed);

    if !KBDTEST_ENABLED.load(Ordering::Relaxed) {
        return;
    }

    let event_kind = if (flags & KBD_FLAG_E0_PREFIX) != 0 {
        "e0-prefix"
    } else if (flags & KBD_FLAG_EXTENDED) != 0 {
        if (flags & KBD_FLAG_RELEASE) != 0 { "ext-break" } else { "ext-make" }
    } else if (flags & KBD_FLAG_RELEASE) != 0 {
        "break"
    } else {
        "make"
    };

    if let Some(b) = decoded {
        match b {
            b'\n' => shell_println!(
                "[X64-KBD] raw=0x{:02x} kind={} dec=<ENTER>(0x0a) shift={}",
                raw,
                event_kind,
                if (flags & KBD_FLAG_SHIFT) != 0 { 1 } else { 0 }
            ),
            8 => shell_println!(
                "[X64-KBD] raw=0x{:02x} kind={} dec=<BS>(0x08) shift={}",
                raw,
                event_kind,
                if (flags & KBD_FLAG_SHIFT) != 0 { 1 } else { 0 }
            ),
            c if (0x20..=0x7e).contains(&c) => shell_println!(
                "[X64-KBD] raw=0x{:02x} kind={} dec='{}'(0x{:02x}) shift={}",
                raw,
                event_kind,
                c as char,
                c,
                if (flags & KBD_FLAG_SHIFT) != 0 { 1 } else { 0 }
            ),
            _ => shell_println!(
                "[X64-KBD] raw=0x{:02x} kind={} dec=0x{:02x} shift={}",
                raw,
                event_kind,
                b,
                if (flags & KBD_FLAG_SHIFT) != 0 { 1 } else { 0 }
            ),
        }
    } else {
        shell_println!(
            "[X64-KBD] raw=0x{:02x} kind={} shift={}",
            raw,
            event_kind,
            if (flags & KBD_FLAG_SHIFT) != 0 { 1 } else { 0 }
        );
    }
}

fn kbdtest_print_status() {
    let raw = PS2_KBD_LAST_RAW.load(Ordering::Relaxed);
    let decoded = PS2_KBD_LAST_DECODED.load(Ordering::Relaxed);
    let flags = PS2_KBD_LAST_FLAGS.load(Ordering::Relaxed);
    let events = PS2_KBD_EVENT_COUNT.load(Ordering::Relaxed);
    let enabled = KBDTEST_ENABLED.load(Ordering::Relaxed);

    shell_println!(
        "[X64] kbdtest {} events={} last_raw=0x{:02x} flags=0x{:02x}",
        if enabled { "on" } else { "off" },
        events,
        raw,
        flags
    );

    if (flags & KBD_FLAG_DECODED) != 0 {
        match decoded {
            b'\n' => shell_println!("[X64] kbdtest last_dec=<ENTER>(0x0a)"),
            8 => shell_println!("[X64] kbdtest last_dec=<BS>(0x08)"),
            c if (0x20..=0x7e).contains(&c) => {
                shell_println!("[X64] kbdtest last_dec='{}'(0x{:02x})", c as char, c)
            }
            _ => shell_println!("[X64] kbdtest last_dec=0x{:02x}", decoded),
        }
    } else {
        shell_println!("[X64] kbdtest last_dec=<none>");
    }
}

fn ps2_try_read_byte() -> Option<u8> {
    unsafe {
        let status = inb(PS2_STATUS);
        if (status & 0x01) == 0 {
            return None;
        }
        let sc = inb(PS2_DATA);

        if sc == 0xE0 {
            PS2_EXTENDED_PREFIX.store(true, Ordering::Relaxed);
            kbdtest_record_event(sc, None, KBD_FLAG_E0_PREFIX);
            return None;
        }

        let had_extended = PS2_EXTENDED_PREFIX.swap(false, Ordering::Relaxed);
        if had_extended {
            // Minimal bring-up shell: ignore extended-key sequences for now.
            let mut flags = KBD_FLAG_EXTENDED;
            if (sc & 0x80) != 0 {
                flags |= KBD_FLAG_RELEASE;
            }
            kbdtest_record_event(sc, None, flags);
            return None;
        }

        match sc {
            0x2A | 0x36 => {
                PS2_SHIFT_DOWN.store(true, Ordering::Relaxed);
                kbdtest_record_event(sc, None, 0);
                return None;
            }
            0xAA | 0xB6 => {
                PS2_SHIFT_DOWN.store(false, Ordering::Relaxed);
                kbdtest_record_event(sc, None, KBD_FLAG_RELEASE);
                return None;
            }
            _ => {}
        }

        if (sc & 0x80) != 0 {
            // Key release for non-shift keys.
            kbdtest_record_event(sc, None, KBD_FLAG_RELEASE);
            return None;
        }
        let decoded = ps2_set1_scancode_to_ascii(sc, PS2_SHIFT_DOWN.load(Ordering::Relaxed));
        kbdtest_record_event(sc, decoded, 0);
        decoded
    }
}

fn shell_try_read_byte() -> Option<u8> {
    if let Some(b) = serial_try_read_byte() {
        return Some(b);
    }
    ps2_try_read_byte()
}

fn serial_write_prompt() {
    match shell_console_mode() {
        ShellConsoleMode::Both => {
            crate::serial_print!("\r\nx64> ");
            crate::terminal::write_str_no_serial("\nx64> ");
        }
        ShellConsoleMode::SerialOnly => {
            crate::serial_print!("\r\nx64> ");
        }
        ShellConsoleMode::VgaOnly => {
            crate::terminal::write_str_no_serial("\nx64> ");
        }
    }
}

const X64_MINI_HELP: &str =
    "help help-all help-mini ticks irq0 int3 traps pfstats cowtest vmtest \
     jitpre jitcall jitbench jitfuzz jitfuzz24dbg heartbeat console kbdtest \
     mmu regs halt";

fn x64_print_mini_help() {
    shell_println!("x86_64 bring-up commands:");
    shell_println!("  {}", X64_MINI_HELP);
    shell_println!("[X64] `help` shows the shared command menu plus x86_64 extensions.");
}

fn x64_print_combined_help() {
    crate::commands::execute("help");
    shell_println!("");
    shell_println!("[X64] x86_64 window/bring-up shell extensions:");
    shell_println!("  {}", X64_MINI_HELP);
    shell_println!("[X64] shared JIT commands (full path via commands.rs):");
    shell_println!("  wasm-jit-selftest");
    shell_println!("  wasm-jit-fuzz <iters> [seed] [auto|user|kernel]");
    shell_println!("  wasm-jit-fuzz-corpus <iters>");
    shell_println!("  wasm-jit-fuzz-soak <iters> <rounds>");
    shell_println!("  jitfuzzreg [iters [seeds]] | jitfuzzreg full [iters]");
    shell_println!("  jitfuzz24dbg [iters] [diag]  (24-bin deterministic debug corpus)");
    shell_println!("[X64] jitcall/jitpre are still x86_64 bring-up specific probes.");
}

fn x64_parse_u32(s: &str) -> Option<u32> {
    let mut out = 0u32;
    for ch in s.chars() {
        let d = ch.to_digit(10)?;
        out = out.checked_mul(10)?.checked_add(d)?;
    }
    Some(out)
}

struct X64ScopedJitUserMode {
    prev: bool,
}

impl X64ScopedJitUserMode {
    fn enter(user_mode: bool) -> Self {
        let mut cfg = crate::wasm::jit_config().lock();
        let prev = cfg.user_mode;
        cfg.user_mode = user_mode;
        Self { prev }
    }
}

impl Drop for X64ScopedJitUserMode {
    fn drop(&mut self) {
        let mut cfg = crate::wasm::jit_config().lock();
        cfg.user_mode = self.prev;
    }
}

struct X64ScopedJitRecover;

impl Drop for X64ScopedJitRecover {
    fn drop(&mut self) {
        crate::wasm::jit_runtime_recover_transient();
    }
}

struct X64ScopedJitFuzzDiag {
    prev: bool,
}

impl X64ScopedJitFuzzDiag {
    fn enter(enabled: bool) -> Self {
        let prev = crate::wasm::jit_fuzz_set_x64_diag(enabled);
        Self { prev }
    }
}

impl Drop for X64ScopedJitFuzzDiag {
    fn drop(&mut self) {
        let _ = crate::wasm::jit_fuzz_set_x64_diag(self.prev);
    }
}

fn x64_alias_jitfuzz24dbg(parts: &mut core::str::SplitWhitespace<'_>) -> bool {
    let _ = parts.next();
    let mut iterations_per_seed: u32 = 32;
    let mut seen_iters = false;
    let mut diag = false;

    while let Some(arg) = parts.next() {
        if arg == "diag" {
            diag = true;
            continue;
        }
        if let Some(v) = x64_parse_u32(arg) {
            if seen_iters {
                shell_println!("[X64] usage: jitfuzz24dbg [iters] [diag]");
                return true;
            }
            iterations_per_seed = v.max(1);
            seen_iters = true;
            continue;
        }
        shell_println!("[X64] usage: jitfuzz24dbg [iters] [diag]");
        return true;
    }

    if !crate::wasm::jit_fuzz_24bin_feature_enabled() {
        shell_println!("[X64] jitfuzz24dbg requires build feature `jit-fuzz-24bin`.");
        shell_println!("[X64] rebuild x86_64 with KERNEL_CARGO_FEATURES=jit-fuzz-24bin");
        return true;
    }

    const MAX_ITERS_PER_SEED: u32 = 256;
    if iterations_per_seed > MAX_ITERS_PER_SEED {
        shell_println!(
            "[X64] jitfuzz24dbg iters too high; use <= {}",
            MAX_ITERS_PER_SEED
        );
        return true;
    }

    shell_println!(
        "[X64] jitfuzz24dbg begin: iters/seed={} seeds={} diag={}",
        iterations_per_seed,
        crate::wasm::jit_fuzz_x64_debug_seed_count(),
        if diag { "on" } else { "off" }
    );
    shell_println!("[X64] path: direct deterministic corpus (no alias chunking)");

    crate::wasm::jit_runtime_recover_transient();
    let _recover_guard = X64ScopedJitRecover;
    let _jit_mode_guard = X64ScopedJitUserMode::enter(false);
    let _diag_guard = X64ScopedJitFuzzDiag::enter(diag);
    let edges_total = crate::wasm::jit_fuzz_opcode_edges_total();

    match crate::wasm::jit_fuzz_x64_debug_corpus(iterations_per_seed) {
        Ok(stats) => {
            shell_println!(
                "[X64] jitfuzz24dbg ok: seeds_passed={} seeds_failed={} mismatches={} compile_errors={} edges_full={}/{} edges_adm={}/{}",
                stats.seeds_passed,
                stats.seeds_failed,
                stats.total_mismatches,
                stats.total_compile_errors,
                stats.max_opcode_edges_hit,
                edges_total,
                stats.max_opcode_edges_hit_admissible,
                stats.opcode_edges_admissible_total,
            );
            if let Some(seed) = stats.first_failed_seed {
                shell_println!(
                    "[X64] jitfuzz24dbg first_failed_seed={} mismatches={} compile_errors={}",
                    seed,
                    stats.first_failed_mismatches,
                    stats.first_failed_compile_errors
                );
            }
        }
        Err(e) => shell_println!("[X64] jitfuzz24dbg failed: {}", e),
    }
    true
}

fn x64_is_runtime_extension_command(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    matches!(
        first,
        "help"
            | "help-mini"
            | "help-all"
            | "heartbeat"
            | "console"
            | "kbdtest"
            | "ticks"
            | "irq0"
            | "int3"
            | "traps"
            | "pfstats"
            | "mmu"
            | "regs"
            | "cowtest"
            | "vmtest"
            | "jitpre"
            | "jitcall"
            | "jitbench"
            | "jitfuzz"
            | "jitfuzz24dbg"
            | "halt"
            | "exit"
    )
}

fn serial_exec_command(cmd: &str) -> bool {
    // Keep shared fuzz commands on the shared command stack regardless of
    // x86_64 bring-up extension handling order.
    let first = cmd.split_whitespace().next().unwrap_or("");
    if matches!(
        first,
        "wasm-jit-fuzz" | "wasm-jit-fuzz-corpus" | "wasm-jit-fuzz-soak" | "jitfuzzreg"
    ) {
        crate::commands::execute(cmd);
        return true;
    }

    if let Some(rest) = cmd.strip_prefix("jitfuzz24dbg") {
        if rest.is_empty() || rest.starts_with(' ') {
            return x64_alias_jitfuzz24dbg(&mut cmd.split_whitespace());
        }
    }

    // Shared command stack parity:
    // default to shared commands unless this is an explicit x86_64 runtime
    // extension handled below.
    if !x64_is_runtime_extension_command(cmd) {
        crate::commands::execute(cmd);
        return true;
    }

    match cmd {
        "" => {}
        "help" => {
            x64_print_combined_help();
        }
        "help-mini" => {
            x64_print_mini_help();
        }
        "help-all" => {
            x64_print_combined_help();
        }
        "heartbeat" => {
            shell_println!(
                "[X64] heartbeat {} (use: heartbeat on|off)",
                if HEARTBEAT_LOG_ENABLED.load(Ordering::Relaxed) { "on" } else { "off" }
            );
        }
        "heartbeat on" => {
            HEARTBEAT_LOG_ENABLED.store(true, Ordering::Relaxed);
            shell_println!("[X64] heartbeat on");
        }
        "heartbeat off" => {
            HEARTBEAT_LOG_ENABLED.store(false, Ordering::Relaxed);
            shell_println!("[X64] heartbeat off");
        }
        "console" => {
            let mode = match shell_console_mode() {
                ShellConsoleMode::Both => "both",
                ShellConsoleMode::SerialOnly => "serial",
                ShellConsoleMode::VgaOnly => "vga",
            };
            shell_println!("[X64] console {} (use: console both|serial|vga)", mode);
        }
        "console both" => {
            shell_set_console_mode(ShellConsoleMode::Both);
            shell_println!("[X64] console both");
        }
        "console serial" => {
            shell_set_console_mode(ShellConsoleMode::SerialOnly);
            shell_println!("[X64] console serial");
        }
        "console vga" => {
            shell_set_console_mode(ShellConsoleMode::VgaOnly);
            shell_println!("[X64] console vga");
        }
        "kbdtest" => {
            kbdtest_print_status();
            shell_println!("[X64] kbdtest usage: kbdtest on|off");
        }
        "kbdtest on" => {
            KBDTEST_ENABLED.store(true, Ordering::Relaxed);
            shell_println!("[X64] kbdtest on (raw scancode + decoded char logging)");
            kbdtest_print_status();
        }
        "kbdtest off" => {
            KBDTEST_ENABLED.store(false, Ordering::Relaxed);
            shell_println!("[X64] kbdtest off");
            kbdtest_print_status();
        }
        "ticks" => {
            shell_println!("[X64] ticks={}", crate::pit::get_ticks());
        }
        "irq0" => {
            shell_println!("[X64] irq0-count={}", irq_count(0));
        }
        "int3" => {
            shell_println!("[X64] triggering int3");
            trigger_breakpoint();
            shell_println!(
                "[X64] breakpoint count={} last_vec={} last_err={:#x}",
                exception_count(3),
                last_vector(),
                last_error(),
            );
        }
        "traps" => {
            shell_println!(
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
            shell_println!(
                "[X64] pf-stats faults={} cow={} copies={}",
                pf, cow, copies
            );
        }
        "mmu" => {
            let (pf, cow, copies) = crate::arch::mmu::x86_64_debug_pf_stats();
            let (pt_used, pt_cap, rec_fail, rec_addr, rec_err, rec_reason) =
                crate::arch::mmu::x86_64_debug_recover_stats();
            shell_println!(
                "[X64] mmu backend={} cr3={:#018x} pf={} cow={} copies={} pt_pool={}/{} rec_fail={} rec_last={:#x}/err={:#x}/why={}",
                crate::arch::mmu::backend_name(),
                crate::arch::mmu::current_page_table_root_addr(),
                pf,
                cow,
                copies,
                pt_used,
                pt_cap,
                rec_fail,
                rec_addr,
                rec_err,
                rec_reason,
            );
        }
        "regs" => {
            let (cr0, cr3, cr4) = read_ctrl_regs();
            let efer = read_efer();
            shell_println!(
                "[X64] cr0={:#018x} cr3={:#018x} cr4={:#018x} efer={:#018x}",
                cr0, cr3, cr4, efer
            );
        }
        "cowtest" => {
            match cow_self_test() {
                Ok(()) => shell_println!("[X64] cowtest ok"),
                Err(e) => shell_println!("[X64] cowtest failed: {}", e),
            }
        }
        "vmtest" => {
            match vm_map_self_test() {
                Ok(()) => shell_println!("[X64] vmtest ok"),
                Err(e) => shell_println!("[X64] vmtest failed: {}", e),
            }
        }
        "jitpre" => {
            match crate::wasm::jit_x86_64_sandbox_preflight() {
                Ok(()) => shell_println!("[X64] jitpre ok"),
                Err(e) => shell_println!("[X64] jitpre failed: {}", e),
            }
        }
        "jitcall" => {
            match crate::wasm::jit_x86_64_call_user_path_probe() {
                Ok(msg) => shell_println!("[X64] jitcall ok: {}", msg),
                Err(e) => shell_println!("[X64] jitcall failed: {}", e),
            }
        }
        "jitbench" => {
            match crate::wasm::jit_bounds_self_test() {
                Ok(()) => shell_println!("[X64] jitbench ok: wasm-jit-bounds-selftest"),
                Err(e) => shell_println!("[X64] jitbench failed: {}", e),
            }
        }
        "jitfuzz" => {
            match jit_fuzz_smoke_self_test() {
                Ok((iters, ok, traps)) => shell_println!(
                    "[X64] jitfuzz ok: iters={} ok={} traps={}",
                    iters, ok, traps
                ),
                Err(e) => shell_println!("[X64] jitfuzz failed: {}", e),
            }
        }
        "halt" | "exit" => {
            shell_println!("[X64] halting");
            return false;
        }
        _ => {
            // Fall back to the shared command stack (same command surface used by the
            // legacy shell) so x86_64 users can exercise more of the kernel without
            // waiting for the full x86_64 shell port.
            crate::commands::execute(cmd);
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
    shell_println!(
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
        let locals_total = 0usize;
        let mut stack_depth = 0i32;
        // Keep x86_64 smoke deterministic and compile-safe: this path is a
        // CI liveness gate, not broad opcode-coverage fuzz.
        emit_i32_const(&mut code, ((rng.next_u32() as i32) & 0x7FFF) + (iter as i32));
        stack_depth += 1;

        if stack_depth <= 0 {
            emit_i32_const(&mut code, iter as i32);
        }
        code.push(Opcode::End as u8);

        if code.len() > MAX_INSTRUCTIONS_PER_CALL {
            return Err("jitfuzz internal program shape failure");
        }

        let jit = match crate::wasm_jit::compile(&code, locals_total) {
            Ok(j) => j,
            Err(e) => {
                if compile_errors == 0 {
                    crate::serial_println!("[X64] jitfuzz dbg first compile-fail err={} len={}", e, code.len());
                    for (i, b) in code.iter().enumerate() {
                        crate::serial_println!("[X64] jitfuzz dbg byte[{}]=0x{:02x}", i, b);
                    }
                }
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

    shell_println!(
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
    crate::terminal::clear_screen();
    crate::terminal::write_str_no_serial("Oreulia OS (x86_64 bring-up)\n");
    crate::terminal::write_str_no_serial(
        "Type 'help' for the full shared command list.\nType 'help-mini' for x86_64 bring-up commands.\n\n"
    );
    shell_println!("[X64] x86_64 shell ready (serial + VGA keyboard)");
    serial_write_prompt();

    let mut buf = [0u8; 128];
    let mut len = 0usize;
    let mut last_heartbeat = crate::pit::get_ticks();

    loop {
        if let Some(byte) = shell_try_read_byte() {
            match byte {
                b'\r' | b'\n' => {
                    shell_println!("");
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
                        crate::vga::backspace();
                    }
                }
                b if (0x20..=0x7E).contains(&b) => {
                    if len < buf.len() - 1 {
                        buf[len] = b;
                        len += 1;
                        shell_print!("{}", b as char);
                    }
                }
                _ => {}
            }
        }

        let ticks = crate::pit::get_ticks();
        if HEARTBEAT_LOG_ENABLED.load(Ordering::Relaxed)
            && ticks.wrapping_sub(last_heartbeat) >= 100
        {
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
                shell_print!("x64> {}", core::str::from_utf8(&buf[..len]).unwrap_or(""));
            } else {
                shell_print!("x64> ");
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
