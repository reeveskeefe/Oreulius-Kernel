/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

#[cfg(not(target_arch = "aarch64"))]
pub use crate::asm_bindings::ProcessContext;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessContext {
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub sp: u64,
    pub pc: u64,
    pub daif: u64,
    pub ttbr0_el1: u64,
    /// Low 32-bit stack shadow for legacy diagnostics in shared scheduler code.
    pub esp: u32,
    pub _reserved: u32,
}

#[cfg(target_arch = "aarch64")]
impl ProcessContext {
    pub const fn new() -> Self {
        Self {
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            x29: 0,
            x30: 0,
            sp: 0,
            pc: 0,
            daif: 0,
            ttbr0_el1: 0,
            esp: 0,
            _reserved: 0,
        }
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn aarch64_sched_load_context(ctx: *const ProcessContext) -> !;
    fn aarch64_sched_switch_context(old_ctx: *mut ProcessContext, new_ctx: *const ProcessContext);
    fn aarch64_thread_start_trampoline() -> !;
}

#[cfg(not(target_arch = "aarch64"))]
pub type IrqFlags = u32;
#[cfg(target_arch = "aarch64")]
pub type IrqFlags = u64;

#[inline]
pub fn context_new() -> ProcessContext {
    ProcessContext::new()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn ticks_now() -> u64 {
    crate::pit::get_ticks()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn ticks_now() -> u64 {
    crate::arch::aarch64_virt::timer_ticks()
}

#[cfg(not(target_arch = "aarch64"))]
pub fn validate_kernel_stack_mapping(stack_bottom: usize, stack_top: usize) -> bool {
    let guard = crate::paging::kernel_space().lock();
    if let Some(space) = guard.as_ref() {
        let bottom = stack_bottom;
        let top_byte = stack_top.saturating_sub(1);
        space.is_mapped(bottom) && space.is_mapped(top_byte)
    } else {
        // During very early boot this may not be initialized yet.
        true
    }
}

#[cfg(target_arch = "aarch64")]
pub fn validate_kernel_stack_mapping(_stack_bottom: usize, _stack_top: usize) -> bool {
    true
}

#[cfg(not(target_arch = "aarch64"))]
pub fn init_kernel_thread_context(
    entry: extern "C" fn() -> !,
    stack_top: usize,
) -> Result<(ProcessContext, usize, usize), &'static str> {
    let entry_addr = entry as *const () as usize;
    let trampoline_addr = crate::asm_bindings::thread_start_trampoline as usize;

    let mut ctx = ProcessContext::new();
    ctx.eip = trampoline_addr as u32;
    // context_switch does 'add esp, 4' to simulate `ret`, so start 4 bytes lower
    // than the pushed entry pointer.
    ctx.esp = (stack_top - 8) as u32;
    ctx.ebp = (stack_top - 8) as u32;
    ctx.cr3 = crate::arch::mmu::current_page_table_root_addr() as u32;
    // Keep IF cleared until thread entry explicitly enables interrupts.
    ctx.eflags = 0x0000_0002;

    Ok((ctx, entry_addr, trampoline_addr))
}

#[cfg(target_arch = "aarch64")]
pub fn init_kernel_thread_context(
    entry: extern "C" fn() -> !,
    stack_top: usize,
) -> Result<(ProcessContext, usize, usize), &'static str> {
    let entry_addr = entry as usize as u64;
    let trampoline_addr = aarch64_thread_start_trampoline as usize as u64;
    let sp = (stack_top as u64) & !0xFu64;

    if sp < 0x1000 {
        return Err("invalid kernel stack");
    }

    let mut ctx = ProcessContext::new();
    ctx.x19 = entry_addr;
    ctx.x29 = sp;
    ctx.sp = sp;
    ctx.pc = trampoline_addr;
    // Mirror current TTBR0 so future per-task address-space switching can work
    // through the same context structure once the scheduler is enabled on AArch64.
    ctx.ttbr0_el1 = crate::arch::mmu::current_page_table_root_addr() as u64;
    // Keep IRQ masked until the thread entry explicitly enables interrupts.
    ctx.daif = 1u64 << 7;
    ctx.esp = sp as u32;

    Ok((ctx, entry_addr as usize, trampoline_addr as usize))
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn context_stack_pointer(ctx: &ProcessContext) -> usize {
    ctx.esp as usize
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn context_stack_pointer(ctx: &ProcessContext) -> usize {
    ctx.sp as usize
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn load_context(ctx: *const ProcessContext) -> ! {
    crate::asm_bindings::asm_load_context(ctx)
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn load_context(ctx: *const ProcessContext) -> ! {
    aarch64_sched_load_context(ctx)
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn switch_context(from: *mut ProcessContext, to: *const ProcessContext) {
    crate::asm_bindings::asm_switch_context(from, to)
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn switch_context(from: *mut ProcessContext, to: *const ProcessContext) {
    aarch64_sched_switch_context(from, to)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn runtime_pid_sync(_pid_raw: u32) {}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn runtime_pid_sync(pid_raw: u32) {
    let _ = crate::arch::aarch64_virt::scheduler_note_context_switch(pid_raw);
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn irq_save_disable() -> IrqFlags {
    crate::idt_asm::fast_cli_save()
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn irq_save_disable() -> IrqFlags {
    let flags: u64;
    core::arch::asm!("mrs {0}, DAIF", out(reg) flags, options(nomem, nostack, preserves_flags));
    // Set I-bit (IRQ mask) while leaving other mask bits unchanged.
    core::arch::asm!("msr DAIFSet, #2", options(nomem, nostack, preserves_flags));
    flags
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn irq_restore(flags: IrqFlags) {
    crate::idt_asm::fast_sti_restore(flags);
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn irq_restore(flags: IrqFlags) {
    core::arch::asm!("msr DAIF, {0}", in(reg) flags, options(nomem, nostack, preserves_flags));
    core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn debug_dump_launch_context(ctx_ptr: *const ProcessContext) {
    if !cfg!(debug_assertions) {
        // Keep diagnostics available in release if the caller wants them.
    }

    let ctx = &*ctx_ptr;
    crate::serial_println!(
        "[SCHED] ctx_ptr={:p} eip=0x{:08x} esp=0x{:08x} ebp=0x{:08x} eflags=0x{:08x} cr3=0x{:08x}",
        ctx_ptr,
        ctx.eip,
        ctx.esp,
        ctx.ebp,
        ctx.eflags,
        ctx.cr3
    );
    let slot0 = *(ctx.esp as *const u32);
    let slot1 = *((ctx.esp + 4) as *const u32);
    crate::serial_println!(
        "[SCHED] stack slots: [esp]=0x{:08x} [esp+4]=0x{:08x}",
        slot0,
        slot1
    );
    let esp: u32;
    core::arch::asm!(
        "mov {0:e}, esp",
        out(reg) esp,
        options(nomem, nostack, preserves_flags)
    );
    let top = *(esp as *const u32);
    crate::serial_println!(
        "[SCHED] esp=0x{:08x} top=0x{:08x} ctx_ptr=0x{:08x}",
        esp,
        top,
        ctx_ptr as u32
    );
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn debug_dump_launch_context(ctx_ptr: *const ProcessContext) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    uart.init_early();
    let ctx = &*ctx_ptr;

    fn w_hex(uart: &crate::arch::aarch64_pl011::Pl011, v: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 18];
        buf[0] = b'0';
        buf[1] = b'x';
        for i in 0..16 {
            let shift = (15 - i) * 4;
            buf[2 + i] = HEX[((v >> shift) & 0xF) as usize];
        }
        for &b in &buf {
            uart.write_byte(b);
        }
    }

    unsafe fn read_sysreg(name: &str) -> u64 {
        let mut val: u64 = 0;
        match name {
            "ttbr0" => {
                core::arch::asm!("mrs {0}, TTBR0_EL1", out(reg) val, options(nomem, nostack))
            }
            "ttbr1" => {
                core::arch::asm!("mrs {0}, TTBR1_EL1", out(reg) val, options(nomem, nostack))
            }
            "tcr" => core::arch::asm!("mrs {0}, TCR_EL1", out(reg) val, options(nomem, nostack)),
            "sctlr" => {
                core::arch::asm!("mrs {0}, SCTLR_EL1", out(reg) val, options(nomem, nostack))
            }
            "daif" => core::arch::asm!("mrs {0}, DAIF", out(reg) val, options(nomem, nostack)),
            "vbar" => core::arch::asm!("mrs {0}, VBAR_EL1", out(reg) val, options(nomem, nostack)),
            _ => {}
        }
        val
    }

    let load_addr = aarch64_sched_load_context as usize;
    let switch_addr = aarch64_sched_switch_context as usize;
    let tramp_addr = aarch64_thread_start_trampoline as usize;
    let code_page = load_addr & !0xFFFusize;

    uart.write_str("[A64-SCHED] launch-context ctx=");
    w_hex(&uart, ctx_ptr as usize as u64);
    uart.write_str(" pc=");
    w_hex(&uart, ctx.pc);
    uart.write_str(" sp=");
    w_hex(&uart, ctx.sp);
    uart.write_str(" daif=");
    w_hex(&uart, ctx.daif);
    uart.write_str(" ctx.ttbr0=");
    w_hex(&uart, ctx.ttbr0_el1);
    uart.write_str("\n");

    uart.write_str("[A64-SCHED] symbols load=");
    w_hex(&uart, load_addr as u64);
    uart.write_str(" switch=");
    w_hex(&uart, switch_addr as u64);
    uart.write_str(" tramp=");
    w_hex(&uart, tramp_addr as u64);
    uart.write_str("\n");

    let ttbr0 = read_sysreg("ttbr0");
    let ttbr1 = read_sysreg("ttbr1");
    let tcr = read_sysreg("tcr");
    let sctlr = read_sysreg("sctlr");
    let daif = read_sysreg("daif");
    let vbar = read_sysreg("vbar");
    uart.write_str("[A64-SCHED] regs TTBR0=");
    w_hex(&uart, ttbr0);
    uart.write_str(" TTBR1=");
    w_hex(&uart, ttbr1);
    uart.write_str(" TCR=");
    w_hex(&uart, tcr);
    uart.write_str(" SCTLR=");
    w_hex(&uart, sctlr);
    uart.write_str(" DAIF=");
    w_hex(&uart, daif);
    uart.write_str(" VBAR=");
    w_hex(&uart, vbar);
    uart.write_str("\n");

    let code_phys = crate::arch::mmu::aarch64_debug_virt_to_phys(load_addr);
    let tramp_phys = crate::arch::mmu::aarch64_debug_virt_to_phys(tramp_addr);
    let (root_phys, l0, l1, l2, l3, walk_phys) = crate::arch::mmu::aarch64_debug_walk(load_addr);
    uart.write_str("[A64-SCHED] mmu load_phys=");
    w_hex(&uart, code_phys.unwrap_or(0) as u64);
    uart.write_str(" tramp_phys=");
    w_hex(&uart, tramp_phys.unwrap_or(0) as u64);
    uart.write_str(" walk.root=");
    w_hex(&uart, root_phys as u64);
    uart.write_str("\n");
    uart.write_str("[A64-SCHED] walk l0=");
    w_hex(&uart, l0);
    uart.write_str(" l1=");
    w_hex(&uart, l1);
    uart.write_str(" l2=");
    w_hex(&uart, l2);
    uart.write_str(" l3=");
    w_hex(&uart, l3);
    uart.write_str(" phys=");
    w_hex(&uart, walk_phys.unwrap_or(0) as u64);
    uart.write_str("\n");

    uart.write_str("[A64-SCHED] code bytes @");
    w_hex(&uart, load_addr as u64);
    uart.write_str(": ");
    for i in 0..16usize {
        let b = *(load_addr as *const u8).add(i);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        uart.write_byte(HEX[(b >> 4) as usize]);
        uart.write_byte(HEX[(b & 0xF) as usize]);
        uart.write_byte(if i == 15 { b'\n' } else { b' ' });
    }

    uart.write_str("[A64-SCHED] code page=");
    w_hex(&uart, code_page as u64);
    uart.write_str("\n");
}
