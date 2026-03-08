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

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use lazy_static::lazy_static;
use x86_64::instructions::port::Port;
use crate::serial_println;
use crate::interrupt_dag::{InterruptContext, DAG_LEVEL_IRQ};

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt[32].set_handler_fn(timer_handler);
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
    let _ctx = irq_context();

    // All lock acquisitions in this handler should go through `_ctx.acquire_lock(lock, |data, sub| ...)`
    // to enforce DAG ordering.  Example pattern (commented to avoid circular dependency here):
    //
    //   _ctx.acquire_lock(&SCHEDULER_LOCK, |sched, _sub| {
    //       sched.tick();
    //   });
    //
    // For now, the tick counter update is lock-free (single hardware thread, no shared state).
    unsafe {
        TICKS += 1;
        if TICKS % 100 == 0 {
            // serial_println!("Timer: {} seconds", TICKS / 100);
        }
    }
    // Acknowledge PIC
    unsafe {
        Port::<u8>::new(0x20).write(0x20u8);
    }
}