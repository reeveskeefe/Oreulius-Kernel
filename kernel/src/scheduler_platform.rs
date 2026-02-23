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
    _reserved: u64,
}

#[cfg(target_arch = "aarch64")]
impl ProcessContext {
    pub const fn new() -> Self {
        Self { _reserved: 0 }
    }
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
pub fn validate_kernel_stack_mapping(stack_bottom: u32, stack_top: u32) -> bool {
    let guard = crate::paging::kernel_space().lock();
    if let Some(space) = guard.as_ref() {
        let bottom = stack_bottom as usize;
        let top_byte = (stack_top as usize).saturating_sub(1);
        space.is_mapped(bottom) && space.is_mapped(top_byte)
    } else {
        // During very early boot this may not be initialized yet.
        true
    }
}

#[cfg(target_arch = "aarch64")]
pub fn validate_kernel_stack_mapping(_stack_bottom: u32, _stack_top: u32) -> bool {
    true
}

#[cfg(not(target_arch = "aarch64"))]
pub fn init_kernel_thread_context(
    entry: extern "C" fn() -> !,
    stack_top: u32,
) -> Result<(ProcessContext, u32, u32), &'static str> {
    let entry_addr = entry as *const () as u32;
    let trampoline_addr = crate::asm_bindings::thread_start_trampoline as usize as u32;

    let mut ctx = ProcessContext::new();
    ctx.eip = trampoline_addr;
    // context_switch does 'add esp, 4' to simulate `ret`, so start 4 bytes lower
    // than the pushed entry pointer.
    ctx.esp = stack_top - 8;
    ctx.ebp = stack_top - 8;
    ctx.cr3 = crate::arch::mmu::current_page_table_root_addr() as u32;
    // Keep IF cleared until thread entry explicitly enables interrupts.
    ctx.eflags = 0x0000_0002;

    Ok((ctx, entry_addr, trampoline_addr))
}

#[cfg(target_arch = "aarch64")]
pub fn init_kernel_thread_context(
    _entry: extern "C" fn() -> !,
    _stack_top: u32,
) -> Result<(ProcessContext, u32, u32), &'static str> {
    Err("kernel thread context init not implemented on AArch64")
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn load_context(ctx: *const ProcessContext) -> ! {
    crate::asm_bindings::asm_load_context(ctx)
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn load_context(_ctx: *const ProcessContext) -> ! {
    panic!("scheduler load_context not implemented on AArch64")
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn switch_context(from: *mut ProcessContext, to: *const ProcessContext) {
    crate::asm_bindings::asm_switch_context(from, to)
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn switch_context(_from: *mut ProcessContext, _to: *const ProcessContext) {}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn irq_save_disable() -> IrqFlags {
    crate::idt_asm::fast_cli_save()
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn irq_save_disable() -> IrqFlags {
    0
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn irq_restore(flags: IrqFlags) {
    crate::idt_asm::fast_sti_restore(flags);
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn irq_restore(_flags: IrqFlags) {}

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
pub unsafe fn debug_dump_launch_context(_ctx_ptr: *const ProcessContext) {}

