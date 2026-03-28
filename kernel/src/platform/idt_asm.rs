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

// Interrupt Descriptor Table (IDT) assembly bindings
// Exception and IRQ handlers with PIC/APIC support

use core::fmt;

/// IDT entry structure
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IdtEntry {
    pub base_low: u16,  // Handler address bits 0-15
    pub selector: u16,  // Code segment selector
    pub zero: u8,       // Reserved (must be zero)
    pub flags: u8,      // Type and attributes
    pub base_high: u16, // Handler address bits 16-31
}

impl IdtEntry {
    pub const fn new() -> Self {
        Self {
            base_low: 0,
            selector: 0,
            zero: 0,
            flags: 0,
            base_high: 0,
        }
    }

    pub fn set_handler(&mut self, handler: usize, selector: u16, flags: u8) {
        self.base_low = (handler & 0xFFFF) as u16;
        self.base_high = ((handler >> 16) & 0xFFFF) as u16;
        self.selector = selector;
        self.zero = 0;
        self.flags = flags;
    }
}

/// IDT pointer structure for LIDT instruction
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IdtPointer {
    pub limit: u16, // Size of IDT - 1
    pub base: u32,  // Address of first IDT entry
}

/// Interrupt frame passed to exception handlers
#[repr(C)]
pub struct InterruptFrame {
    // Segment registers
    pub gs: u32,
    pub fs: u32,
    pub es: u32,
    pub ds: u32,

    // General purpose registers (pushed by pushad)
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,

    // Interrupt number and error code
    pub int_no: u32,
    pub err_code: u32,

    // Pushed by CPU on interrupt
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub user_esp: u32, // Only if privilege change
    pub ss: u32,       // Only if privilege change
}

impl fmt::Debug for InterruptFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "InterruptFrame {{ int_no: {}, err_code: 0x{:x}, eip: 0x{:x}, cs: 0x{:x}, eflags: 0x{:x} }}",
            self.int_no, self.err_code, self.eip, self.cs, self.eflags)
    }
}

extern "C" {
    // IDT Management
    #[cfg(target_arch = "x86")]
    pub fn idt_load(idt_ptr: *const IdtPointer);
    pub fn idt_set_gate(idt: *mut IdtEntry, num: u8, handler: u32, selector: u16, flags: u8);

    // Exception handlers (ISR 0-31)
    pub fn isr0();
    pub fn isr1();
    pub fn isr2();
    pub fn isr3();
    pub fn isr4();
    pub fn isr5();
    pub fn isr6();
    pub fn isr7();
    pub fn isr8();
    pub fn isr9();
    pub fn isr10();
    pub fn isr11();
    pub fn isr12();
    pub fn isr13();
    pub fn isr14();
    pub fn isr15();
    pub fn isr16();
    pub fn isr17();
    pub fn isr18();
    pub fn isr19();
    pub fn isr20();
    pub fn isr21();
    pub fn isr22();
    pub fn isr23();
    pub fn isr24();
    pub fn isr25();
    pub fn isr26();
    pub fn isr27();
    pub fn isr28();
    pub fn isr29();
    pub fn isr30();
    pub fn isr31();

    // IRQ handlers (32-47)
    pub fn irq0();
    pub fn irq1();
    pub fn irq2();
    pub fn irq3();
    pub fn irq4();
    pub fn irq5();
    pub fn irq6();
    pub fn irq7();
    pub fn irq8();
    pub fn irq9();
    pub fn irq10();
    pub fn irq11();
    pub fn irq12();
    pub fn irq13();
    pub fn irq14();
    pub fn irq15();

    // Context-switch debug latches from context_switch.asm
    static asm_dbg_ctx_ptr: u32;
    static asm_dbg_eip_target: u32;
    static asm_dbg_esp_loaded: u32;
    static asm_dbg_entry_popped: u32;
    static asm_dbg_stage: u32;
    static asm_sw_old_ptr: u32;
    static asm_sw_new_ptr: u32;
    static asm_sw_saved_old_eip: u32;
    static asm_sw_new_eip: u32;
    static asm_sw_new_esp: u32;
    static asm_sw_stage: u32;

    // PIC Operations
    pub fn pic_send_eoi(irq: u8);
    pub fn pic_remap(offset1: u8, offset2: u8);
    pub fn pic_disable();

    // APIC Operations
    pub fn apic_write(reg: u32, value: u32);
    pub fn apic_read(reg: u32) -> u32;
    pub fn apic_send_eoi();

    // Interrupt Control
    pub fn fast_cli();
    pub fn fast_sti();
    pub fn fast_cli_save() -> u32;
    pub fn fast_sti_restore(flags: u32);
    pub fn trigger_interrupt(vector: u8);

    // Interrupt Statistics
    pub fn get_interrupt_count(vector: u8) -> u32;
    pub fn increment_interrupt_count(vector: u8);
    pub fn clear_interrupt_counts();

    // NMI Control
    pub fn enable_nmi();
    pub fn disable_nmi();

    // Exception Names
    pub fn get_exception_name(vector: u8) -> *const u8;
}

#[cfg(target_arch = "x86")]
#[inline]
pub unsafe fn idt_load_compat(idt_ptr: *const IdtPointer) {
    idt_load(idt_ptr);
}

#[cfg(not(target_arch = "x86"))]
#[inline]
pub unsafe fn idt_load_compat(_idt_ptr: *const IdtPointer) {}

// IDT gate types
pub const GATE_TASK: u8 = 0x05;
pub const GATE_INTERRUPT_16: u8 = 0x06;
pub const GATE_TRAP_16: u8 = 0x07;
pub const GATE_INTERRUPT_32: u8 = 0x0E;
pub const GATE_TRAP_32: u8 = 0x0F;

// IDT flags
pub const FLAG_PRESENT: u8 = 0x80;
pub const FLAG_DPL0: u8 = 0x00; // Kernel privilege
pub const FLAG_DPL1: u8 = 0x20;
pub const FLAG_DPL2: u8 = 0x40;
pub const FLAG_DPL3: u8 = 0x60; // User privilege

/// Exception vector numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exception {
    DivideByZero = 0,
    Debug = 1,
    NonMaskableInterrupt = 2,
    Breakpoint = 3,
    Overflow = 4,
    BoundRangeExceeded = 5,
    InvalidOpcode = 6,
    DeviceNotAvailable = 7,
    DoubleFault = 8,
    CoprocessorSegmentOverrun = 9,
    InvalidTSS = 10,
    SegmentNotPresent = 11,
    StackSegmentFault = 12,
    GeneralProtectionFault = 13,
    PageFault = 14,
    Reserved15 = 15,
    X87FloatingPoint = 16,
    AlignmentCheck = 17,
    MachineCheck = 18,
    SimdFloatingPoint = 19,
    Virtualization = 20,
    ControlProtection = 21,
    Reserved22 = 22,
    Reserved23 = 23,
    Reserved24 = 24,
    Reserved25 = 25,
    Reserved26 = 26,
    Reserved27 = 27,
    Reserved28 = 28,
    Reserved29 = 29,
    Security = 30,
    Reserved31 = 31,
}

impl Exception {
    pub fn from_u8(n: u8) -> Option<Self> {
        if n <= 31 {
            Some(unsafe { core::mem::transmute(n) })
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::DivideByZero => "Divide-by-zero",
            Self::Debug => "Debug",
            Self::NonMaskableInterrupt => "Non-maskable Interrupt",
            Self::Breakpoint => "Breakpoint",
            Self::Overflow => "Overflow",
            Self::BoundRangeExceeded => "Bound Range Exceeded",
            Self::InvalidOpcode => "Invalid Opcode",
            Self::DeviceNotAvailable => "Device Not Available",
            Self::DoubleFault => "Double Fault",
            Self::CoprocessorSegmentOverrun => "Coprocessor Segment Overrun",
            Self::InvalidTSS => "Invalid TSS",
            Self::SegmentNotPresent => "Segment Not Present",
            Self::StackSegmentFault => "Stack-Segment Fault",
            Self::GeneralProtectionFault => "General Protection Fault",
            Self::PageFault => "Page Fault",
            Self::X87FloatingPoint => "x87 FPU Error",
            Self::AlignmentCheck => "Alignment Check",
            Self::MachineCheck => "Machine Check",
            Self::SimdFloatingPoint => "SIMD Floating-Point Exception",
            Self::Virtualization => "Virtualization Exception",
            Self::ControlProtection => "Control Protection Exception",
            Self::Security => "Security Exception",
            _ => "Reserved",
        }
    }
}

/// Hardware IRQ numbers (remapped to 32-47)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Irq {
    Timer = 0,         // IRQ 0 - PIT
    Keyboard = 1,      // IRQ 1
    Cascade = 2,       // IRQ 2 - Slave PIC
    COM2 = 3,          // IRQ 3
    COM1 = 4,          // IRQ 4
    LPT2 = 5,          // IRQ 5
    Floppy = 6,        // IRQ 6
    LPT1 = 7,          // IRQ 7 (spurious)
    RTC = 8,           // IRQ 8
    Free1 = 9,         // IRQ 9
    Free2 = 10,        // IRQ 10
    Free3 = 11,        // IRQ 11
    Mouse = 12,        // IRQ 12 - PS/2 Mouse
    FPU = 13,          // IRQ 13
    PrimaryATA = 14,   // IRQ 14
    SecondaryATA = 15, // IRQ 15
}

impl Irq {
    pub fn as_vector(&self) -> u8 {
        32 + (*self as u8)
    }

    pub fn from_vector(vector: u8) -> Option<Self> {
        if vector >= 32 && vector < 48 {
            Some(unsafe { core::mem::transmute(vector - 32) })
        } else {
            None
        }
    }
}

/// IDT manager
pub struct Idt {
    entries: [IdtEntry; 256],
}

static mut IDT: Idt = Idt::new();

const KERNEL_CODE_SELECTOR: u16 = 0x08;

const PIC1_DATA: u16 = 0x21;
const PIC2_DATA: u16 = 0xA1;

impl Idt {
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::new(); 256],
        }
    }

    pub fn set_handler(&mut self, index: u8, handler: usize, selector: u16, flags: u8) {
        self.entries[index as usize].set_handler(handler, selector, flags);
    }

    pub fn load(&self) {
        let ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: self.entries.as_ptr() as u32,
        };
        unsafe { idt_load_compat(&ptr) }
    }

    pub fn init_exceptions(&mut self, code_selector: u16) {
        let flags = FLAG_PRESENT | GATE_INTERRUPT_32 | FLAG_DPL0;

        // Set up all exception handlers
        self.set_handler(0, isr0 as usize, code_selector, flags);
        self.set_handler(1, isr1 as usize, code_selector, flags);
        self.set_handler(2, isr2 as usize, code_selector, flags);
        self.set_handler(3, isr3 as usize, code_selector, flags);
        self.set_handler(4, isr4 as usize, code_selector, flags);
        self.set_handler(5, isr5 as usize, code_selector, flags);
        self.set_handler(6, isr6 as usize, code_selector, flags);
        self.set_handler(7, isr7 as usize, code_selector, flags);
        self.set_handler(8, isr8 as usize, code_selector, flags);
        self.set_handler(9, isr9 as usize, code_selector, flags);
        self.set_handler(10, isr10 as usize, code_selector, flags);
        self.set_handler(11, isr11 as usize, code_selector, flags);
        self.set_handler(12, isr12 as usize, code_selector, flags);
        self.set_handler(13, isr13 as usize, code_selector, flags);
        self.set_handler(14, isr14 as usize, code_selector, flags);
        self.set_handler(15, isr15 as usize, code_selector, flags);
        self.set_handler(16, isr16 as usize, code_selector, flags);
        self.set_handler(17, isr17 as usize, code_selector, flags);
        self.set_handler(18, isr18 as usize, code_selector, flags);
        self.set_handler(19, isr19 as usize, code_selector, flags);
        self.set_handler(20, isr20 as usize, code_selector, flags);
        self.set_handler(21, isr21 as usize, code_selector, flags);
        self.set_handler(22, isr22 as usize, code_selector, flags);
        self.set_handler(23, isr23 as usize, code_selector, flags);
        self.set_handler(24, isr24 as usize, code_selector, flags);
        self.set_handler(25, isr25 as usize, code_selector, flags);
        self.set_handler(26, isr26 as usize, code_selector, flags);
        self.set_handler(27, isr27 as usize, code_selector, flags);
        self.set_handler(28, isr28 as usize, code_selector, flags);
        self.set_handler(29, isr29 as usize, code_selector, flags);
        self.set_handler(30, isr30 as usize, code_selector, flags);
        self.set_handler(31, isr31 as usize, code_selector, flags);
    }

    pub fn init_irqs(&mut self, code_selector: u16) {
        let flags = FLAG_PRESENT | GATE_INTERRUPT_32 | FLAG_DPL0;

        // Set up all IRQ handlers
        self.set_handler(32, irq0 as usize, code_selector, flags);
        self.set_handler(33, irq1 as usize, code_selector, flags);
        self.set_handler(34, irq2 as usize, code_selector, flags);
        self.set_handler(35, irq3 as usize, code_selector, flags);
        self.set_handler(36, irq4 as usize, code_selector, flags);
        self.set_handler(37, irq5 as usize, code_selector, flags);
        self.set_handler(38, irq6 as usize, code_selector, flags);
        self.set_handler(39, irq7 as usize, code_selector, flags);
        self.set_handler(40, irq8 as usize, code_selector, flags);
        self.set_handler(41, irq9 as usize, code_selector, flags);
        self.set_handler(42, irq10 as usize, code_selector, flags);
        self.set_handler(43, irq11 as usize, code_selector, flags);
        self.set_handler(44, irq12 as usize, code_selector, flags);
        self.set_handler(45, irq13 as usize, code_selector, flags);
        self.set_handler(46, irq14 as usize, code_selector, flags);
        self.set_handler(47, irq15 as usize, code_selector, flags);
    }
}

/// PIC manager
pub struct Pic;

impl Pic {
    pub fn remap(offset1: u8, offset2: u8) {
        unsafe { pic_remap(offset1, offset2) }
    }

    pub fn disable() {
        unsafe { pic_disable() }
    }

    pub fn send_eoi(irq: Irq) {
        unsafe { pic_send_eoi(irq as u8) }
    }
}

#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

fn set_pic_masks(master: u8, slave: u8) {
    unsafe {
        outb(PIC1_DATA, master);
        outb(PIC2_DATA, slave);

        let m1 = inb(PIC1_DATA);
        let m2 = inb(PIC2_DATA);
        crate::serial_println!(
            "[PIC] Masks set to M:{:02X} S:{:02X} (Read back: M:{:02X} S:{:02X})",
            master,
            slave,
            m1,
            m2
        );
    }
}

/// Set PIC IRQ masks (1 = masked, 0 = unmasked)
pub fn set_irq_masks(master: u8, slave: u8) {
    set_pic_masks(master, slave);
}

pub fn current_irq_masks() -> (u8, u8) {
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}

pub fn mask_irq(irq: Irq) {
    let (mut master, mut slave) = current_irq_masks();
    let bit = 1u8 << ((irq as u8) & 7);
    if (irq as u8) < 8 {
        master |= bit;
    } else {
        slave |= bit;
    }
    unsafe {
        outb(PIC1_DATA, master);
        outb(PIC2_DATA, slave);
    }
}

pub fn unmask_irq(irq: Irq) {
    let (mut master, mut slave) = current_irq_masks();
    let bit = 1u8 << ((irq as u8) & 7);
    if (irq as u8) < 8 {
        master &= !bit;
    } else {
        slave &= !bit;
    }
    unsafe {
        outb(PIC1_DATA, master);
        outb(PIC2_DATA, slave);
    }
}

/// Initialize IDT, PIC remap, and IRQ masks
pub fn init() {
    init_trap_table();
    init_interrupt_controller();
}

/// Initialize the trap/interrupt vector table and load the IDT.
pub fn init_trap_table() {
    unsafe {
        let idt = &mut IDT;
        idt.init_exceptions(KERNEL_CODE_SELECTOR);
        idt.init_irqs(KERNEL_CODE_SELECTOR);

        // Install INT 0x80 syscall gate (ring 3)
        extern "C" {
            fn syscall_entry();
        }
        idt.set_handler(
            0x80,
            syscall_entry as usize,
            KERNEL_CODE_SELECTOR,
            FLAG_PRESENT | GATE_INTERRUPT_32 | FLAG_DPL3,
        );

        idt.load();
    }
}

/// Initialize the legacy interrupt controller (PIC remap + masks).
pub fn init_interrupt_controller() {
    // Remap PIC to 32-47 to avoid conflicts with CPU exceptions
    Pic::remap(32, 40);

    // DEBUG: Unmask Timer(0) and Keyboard(1) IMMEDIATELY to test interrupts
    let master_mask = 0xFC; // 11111100b
    let slave_mask = 0xFF; // 11111111b
    set_pic_masks(master_mask, slave_mask);
}

/// Reload the current kernel IDT (used after temporary user IDT loads).
pub fn reload() {
    unsafe {
        IDT.load();
    }
}

/// Interrupt statistics
pub struct InterruptStats;

impl InterruptStats {
    pub fn get_count(vector: u8) -> u32 {
        unsafe { get_interrupt_count(vector) }
    }

    pub fn clear_all() {
        unsafe { clear_interrupt_counts() }
    }
}

/// Rust exception handler (called from assembly)
#[no_mangle]
pub extern "C" fn rust_exception_handler(frame: *const InterruptFrame) {
    let frame = unsafe { &mut *(frame as *const _ as *mut InterruptFrame) };

    if frame.int_no == Exception::DeviceNotAvailable as u32 {
        // Quantum scheduler is the primary advanced scheduler in Oreulia
        crate::quantum_scheduler::handle_fpu_trap();
        return;
    }

    if frame.int_no == Exception::PageFault as u32 {
        let fault_addr: usize;
        unsafe {
            #[cfg(target_arch = "x86")]
            core::arch::asm!("mov {0:e}, cr2", out(reg) fault_addr);
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {}, cr2", out(reg) fault_addr);
        }
        if crate::wasm::jit_handle_page_fault(frame, fault_addr, frame.err_code) {
            return;
        }
        let dbg_ctx_ptr = unsafe { asm_dbg_ctx_ptr };
        let dbg_eip_target = unsafe { asm_dbg_eip_target };
        let dbg_esp_loaded = unsafe { asm_dbg_esp_loaded };
        let dbg_entry_popped = unsafe { asm_dbg_entry_popped };
        let dbg_stage = unsafe { asm_dbg_stage };
        let sw_old_ptr = unsafe { asm_sw_old_ptr };
        let sw_new_ptr = unsafe { asm_sw_new_ptr };
        let sw_saved_old_eip = unsafe { asm_sw_saved_old_eip };
        let sw_new_eip = unsafe { asm_sw_new_eip };
        let sw_new_esp = unsafe { asm_sw_new_esp };
        let sw_stage = unsafe { asm_sw_stage };
        crate::serial::_print(format_args!(
            "[CTX-DBG] stage={} ctx_ptr=0x{:08x} eip_target=0x{:08x} esp_loaded=0x{:08x} entry_popped=0x{:08x}\n",
            dbg_stage, dbg_ctx_ptr, dbg_eip_target, dbg_esp_loaded, dbg_entry_popped
        ));
        crate::serial::_print(format_args!(
            "[SW-DBG] stage={} old=0x{:08x} new=0x{:08x} save_eip=0x{:08x} load_eip=0x{:08x} load_esp=0x{:08x}\n",
            sw_stage, sw_old_ptr, sw_new_ptr, sw_saved_old_eip, sw_new_eip, sw_new_esp
        ));
        crate::serial::_print(format_args!(
            "[PF-REGS] eax=0x{:08x} ebx=0x{:08x} ecx=0x{:08x} edx=0x{:08x} esi=0x{:08x} edi=0x{:08x} ebp=0x{:08x} esp=0x{:08x}\n",
            frame.eax,
            frame.ebx,
            frame.ecx,
            frame.edx,
            frame.esi,
            frame.edi,
            frame.ebp,
            frame.esp
        ));
        crate::paging::rust_page_fault_handler_ex(
            frame.err_code,
            fault_addr,
            frame.eip as usize,
            frame.esp as usize,
        );
        return;
    }

    if crate::wasm::jit_handle_exception(frame) {
        return;
    }

    if let Some(exc) = Exception::from_u8(frame.int_no as u8) {
        crate::serial::_print(format_args!(
            "\n!!! EXCEPTION: {} ({})\n",
            exc.name(),
            frame.int_no
        ));
        crate::serial::_print(format_args!("Error Code: 0x{:08x}\n", frame.err_code));
        crate::serial::_print(format_args!(
            "EIP: 0x{:08x}, CS: 0x{:04x}, EFLAGS: 0x{:08x}\n",
            frame.eip, frame.cs, frame.eflags
        ));
        crate::serial::_print(format_args!(
            "EAX: 0x{:08x}, EBX: 0x{:08x}, ECX: 0x{:08x}, EDX: 0x{:08x}\n",
            frame.eax, frame.ebx, frame.ecx, frame.edx
        ));
        if exc == Exception::InvalidOpcode {
            let dbg_ctx_ptr = unsafe { asm_dbg_ctx_ptr };
            let dbg_eip_target = unsafe { asm_dbg_eip_target };
            let dbg_esp_loaded = unsafe { asm_dbg_esp_loaded };
            let dbg_entry_popped = unsafe { asm_dbg_entry_popped };
            let dbg_stage = unsafe { asm_dbg_stage };
            let sw_old_ptr = unsafe { asm_sw_old_ptr };
            let sw_new_ptr = unsafe { asm_sw_new_ptr };
            let sw_saved_old_eip = unsafe { asm_sw_saved_old_eip };
            let sw_new_eip = unsafe { asm_sw_new_eip };
            let sw_new_esp = unsafe { asm_sw_new_esp };
            let sw_stage = unsafe { asm_sw_stage };
            crate::serial::_print(format_args!(
                "[CTX-DBG] stage={} ctx_ptr=0x{:08x} eip_target=0x{:08x} esp_loaded=0x{:08x} entry_popped=0x{:08x}\n",
                dbg_stage, dbg_ctx_ptr, dbg_eip_target, dbg_esp_loaded, dbg_entry_popped
            ));
            crate::serial::_print(format_args!(
                "[SW-DBG] stage={} old=0x{:08x} new=0x{:08x} save_eip=0x{:08x} load_eip=0x{:08x} load_esp=0x{:08x}\n",
                sw_stage, sw_old_ptr, sw_new_ptr, sw_saved_old_eip, sw_new_eip, sw_new_esp
            ));
        }
    }

    // Halt the system
    loop {
        unsafe { core::arch::asm!("hlt") }
    }
}

/// Rust IRQ handler (called from assembly)
#[no_mangle]
pub extern "C" fn rust_irq_handler(frame: *const InterruptFrame) {
    // Debug entry
    // unsafe { crate::advanced_commands::print_hex(frame as usize); crate::vga::print_char('I'); }

    let frame = unsafe { &mut *(frame as *const _ as *mut InterruptFrame) };

    // VISUAL DEBUG: Every time IRQ 33 (Keyboard) fires, increment a counter on screen at (0, 70)
    // We use a raw VGA write to avoid locks or dependencies.
    if frame.int_no == 33 {
        unsafe {
            let val = crate::early_console_read_cell(70);
            let char_part = (val & 0xFF) as u8;
            let new_char = if char_part >= b'z' {
                b'a'
            } else {
                char_part + 1
            };
            crate::early_console_write_cell(70, 0x0E00 | (new_char as u16));
        }
    }

    unsafe { increment_interrupt_count(frame.int_no as u8) }

    if let Some(irq) = Irq::from_vector(frame.int_no as u8) {
        let jit_user_active = crate::wasm::jit_user_active();

        // While user-JIT is running under sandbox CR3, avoid servicing device IRQ
        // paths that may require MMIO regions absent from the sandbox mapping.
        if jit_user_active && irq != Irq::Timer {
            Pic::send_eoi(irq);
            return;
        }

        // Handle specific IRQs
        match irq {
            Irq::Timer => {
                let jit_timed_out = crate::wasm::jit_handle_timer_interrupt(frame);
                // Acknowledge before preemptive scheduling
                Pic::send_eoi(irq);
                crate::pit::tick();
                crate::wasm::on_timer_tick();

                // Network stack tick
                // if let Some(mut stack) = crate::netstack::NETWORK_STACK.try_lock() {
                //     stack.tick();
                // }

                if !jit_user_active && !jit_timed_out {
                    crate::quantum_scheduler::on_timer_tick();
                }
                return;
            }
            Irq::Keyboard => unsafe {
                crate::keyboard::handle_irq();
            },
            Irq::COM1 => {
                crate::serial::handle_com1_irq();
            }
            Irq::Mouse => unsafe {
                crate::keyboard::handle_aux_irq();
            },
            Irq::PrimaryATA => {
                crate::disk::handle_primary_irq();
            }
            Irq::SecondaryATA => {
                crate::disk::handle_secondary_irq();
            }
            Irq::Free2 | Irq::Free3 => {
                crate::net_reactor::on_irq();
            }
            _ => {}
        }

        Pic::send_eoi(irq);
    }
}
