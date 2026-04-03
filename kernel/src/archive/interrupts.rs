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

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;
use x86_64::instructions::port::Port;
use crate::serial_println;
use crate::interrupt_dag::{InterruptContext, DAG_LEVEL_IRQ};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        // IRQ0 → PIT timer (mapped to vector 32 by PIC remapping in init_pic)
        idt[32].set_handler_fn(timer_handler);
        // IDT vector 7 → Device-Not-Available / #NM — fired when CR0.TS=1 and
        // a process attempts an FP or SIMD instruction (§5.1 lazy FPU switch).
        idt[7].set_handler_fn(device_not_available_handler);
        idt
    };
}

/// Constructs the IRQ-level interrupt context for this handler invocation.
///
/// `InterruptContext<DAG_LEVEL_IRQ>` is a zero-sized type — this has no runtime cost.
/// All lock acquisition inside an interrupt handler must go through this context to
/// enforce the DAG priority ordering (PMA §9).
///
/// # Safety
/// Safe to call at hardware-interrupt entry because:
///   1. No mutable state is captured — the type is zero-sized.
///   2. The `LEVEL` const-generic is `DAG_LEVEL_IRQ = 20`, which is strictly greater
///      than all subsystem levels (scheduler=10, vfs=5).
#[inline(always)]
fn irq_context() -> InterruptContext<DAG_LEVEL_IRQ> {
    // SAFETY: DAG_LEVEL_IRQ > all subsystem levels; constructing the context is
    // equivalent to asserting "I am executing at IRQ priority."
    unsafe { InterruptContext::<DAG_LEVEL_IRQ>::new() }
}

pub fn init_idt() {
    IDT.load();
}

pub fn init_pic() {
    unsafe {
        // ICW1
        Port::<u8>::new(0x20).write(0x11);
        Port::<u8>::new(0xA0).write(0x11);
        // ICW2
        Port::<u8>::new(0x21).write(0x20);
        Port::<u8>::new(0xA1).write(0x28);
        // ICW3
        Port::<u8>::new(0x21).write(0x04);
        Port::<u8>::new(0xA1).write(0x02);
        // ICW4
        Port::<u8>::new(0x21).write(0x01);
        Port::<u8>::new(0xA1).write(0x01);
        // Mask all interrupts except timer
        Port::<u8>::new(0x21).write(0xFE);
        Port::<u8>::new(0xA1).write(0xFF);
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Hardware timer interrupt handler (IRQ 0, mapped to IDT vector 32).
///
/// Acquires the scheduler lock through the DAG context — this statically proves
/// that no higher-priority lock can be held when we call into the scheduler,
/// preventing priority-inversion deadlocks (PMA §9).
extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    static mut TICKS: u64 = 0;

    // Obtain the IRQ-level DAG context (zero-cost, zero-sized type).
    let ctx = irq_context();

    unsafe {
        TICKS += 1;

        // §5.1 Lazy FPU: Guard mid-IRQ FPU state before any scheduler work.
        // Sets CR0.TS so that if the preempted process re-enters FP code after
        // iretq it will fault cleanly into handle_fpu_trap() rather than silently
        // corrupting state.
        crate::quantum_scheduler::scheduler()
            .lock()
            .guard_irq_fpu_state();

        // Every 8 ticks (~8 ms at 1 kHz PIT) drain up to 16 TelemetryEvents from the
        // wait-free ring and forward them to the userspace Math Daemon over COM2.
        // Using `try_lock` inside drain_telemetry_to_serial means this is a no-op
        // if the serial port is busy — it never spins (PMA §3.2, §6.1).
        if TICKS % 8 == 0 {
            crate::wait_free_ring::drain_telemetry_to_serial(16);
        }
    }

    // Tick the legacy scheduler through the DAG-ordered context (PMA §9).
    ctx.acquire_lock(
        &crate::scheduler::SCHEDULER,
        |sched, _sub| {
            sched.on_timer_tick();
        },
    );

    // Acknowledge PIC (EOI to master PIC on port 0x20).
    unsafe {
        Port::<u8>::new(0x20).write(0x20u8);
    }
}

/// Device-Not-Available (#NM) exception handler — IDT vector 7.
///
/// Fired by the CPU when CR0.TS = 1 and a process executes an FP or SIMD
/// instruction.  This is the entry point for the §5.1 lazy FPU context switch.
///
/// Delegates to [`QuantumScheduler::handle_fpu_trap`] which:
///   1. Clears the trap (CLTS on x86_64 / re-enables FPEN on AArch64).
///   2. Saves the previous FPU owner's state into its `ExtFpuState` buffer.
///   3. Restores (or zero-initialises) the current process's FPU state.
///   4. Updates `fpu_owner` to the current process.
///
/// CPU exceptions do **not** require a PIC end-of-interrupt acknowledgement.
extern "x86-interrupt" fn device_not_available_handler(_stack_frame: InterruptStackFrame) {
    // SAFETY: we are inside a CPU exception handler.  CR0.TS=1 caused the fault,
    // so no partial FP write has occurred and no FP context is live in the
    // CPU's register file for the faulting instruction.
    unsafe {
        crate::quantum_scheduler::scheduler()
            .lock()
            .handle_fpu_trap();
    }
    // No PIC EOI — CPU exceptions are synchronous, not IRQ-line driven.
}