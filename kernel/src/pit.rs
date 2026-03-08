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

//! Programmable Interval Timer (PIT) Driver
//!
//! The PIT generates periodic timer interrupts for preemptive multitasking.
//! We configure it to fire IRQ0 at a configurable frequency (default 100 Hz).

use core::sync::atomic::{AtomicU32, Ordering};

// PIT I/O ports
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

// PIT frequency (1.193182 MHz)
const PIT_FREQUENCY: u32 = 1193182;

// Target interrupt frequency (100 Hz = 10ms ticks)
const TIMER_HZ: u32 = 100;

// Global tick counter (IRQ-safe, 64-bit via two 32-bit atomics)
static TICKS_LO: AtomicU32 = AtomicU32::new(0);
static TICKS_HI: AtomicU32 = AtomicU32::new(0);

/// Initialize the PIT timer
pub fn init() {
    let divisor = (PIT_FREQUENCY / TIMER_HZ) as u16;

    unsafe {
        // Command: Channel 0, Access mode lo/hi byte, Rate generator
        outb(PIT_COMMAND, 0x36);

        // Set frequency divisor
        outb(PIT_CHANNEL_0, (divisor & 0xFF) as u8);
        outb(PIT_CHANNEL_0, ((divisor >> 8) & 0xFF) as u8);
    }
}

/// Called by the timer interrupt handler
pub fn tick() {
    let prev = TICKS_LO.fetch_add(1, Ordering::Relaxed);
    if prev == u32::MAX {
        TICKS_HI.fetch_add(1, Ordering::Relaxed);
    }
}

/// Get current tick count
pub fn get_ticks() -> u64 {
    loop {
        let hi1 = TICKS_HI.load(Ordering::Relaxed);
        let lo = TICKS_LO.load(Ordering::Relaxed);
        let hi2 = TICKS_HI.load(Ordering::Relaxed);
        if hi1 == hi2 {
            return ((hi1 as u64) << 32) | (lo as u64);
        }
    }
}

/// Try to get ticks (non-blocking) - returns None if lock held
pub fn try_get_ticks() -> Option<u64> {
    Some(get_ticks())
}

/// Get timer frequency in Hz
pub fn get_frequency() -> u32 {
    TIMER_HZ
}

/// Sleep for approximately N milliseconds
/// Note: This is a busy-wait for now, will be replaced with scheduler sleep
pub fn sleep_ms(ms: u32) {
    let start = get_ticks();
    let target_ticks = (ms as u64 * TIMER_HZ as u64) / 1000;

    while get_ticks() - start < target_ticks {
        unsafe {
            // Use HLT to save power while waiting
            core::arch::asm!("hlt");
        }
    }
}

// Port I/O functions
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}
