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

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt[32].set_handler_fn(timer_handler);
        idt
    };
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

extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    static mut TICKS: u64 = 0;
    unsafe {
        TICKS += 1;
        if TICKS % 100 == 0 {
            // serial_println!("Timer: {} seconds", TICKS / 100);
        }
    }
    // Acknowledge PIC
    unsafe {
        Port::<u8>::new(0x20).write(0x20);
    }
}