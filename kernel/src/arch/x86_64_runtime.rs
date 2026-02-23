use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::asm_bindings;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x18;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;
const PIC_EOI: u8 = 0x20;

const COM1_BASE: u16 = 0x3F8;
const COM_LSR: u16 = COM1_BASE + 5;
const COM_DATA: u16 = COM1_BASE;

const IDT_TYPE_INTERRUPT_GATE: u8 = 0x8E;

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

static mut IDT: [IdtEntry64; 256] = [IdtEntry64::missing(); 256];
static mut GDT: [u64; 5] = [0; 5];
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
        GDT[3] = tss_low;
        GDT[4] = tss_high;

        let gdt_ptr = DescriptorTablePtr64 {
            limit: (core::mem::size_of::<[u64; 5]>() - 1) as u16,
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
pub extern "C" fn x86_64_trap_dispatch(vector: u64, error: u64, frame: *const TrapFrameHead64) {
    let vector = vector as u8;
    LAST_VECTOR.store(vector, Ordering::Relaxed);
    LAST_ERROR.store(error, Ordering::Relaxed);

    if vector < 32 {
        EXC_COUNTS[vector as usize].fetch_add(1, Ordering::Relaxed);

        if vector == 14 {
            let fault_addr: usize;
            unsafe {
                core::arch::asm!("mov {}, cr2", out(reg) fault_addr, options(nomem, nostack, preserves_flags));
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
            crate::serial_println!("commands: help ticks irq0 int3 traps mmu regs halt");
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
