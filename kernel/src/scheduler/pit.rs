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

//! Programmable Interval Timer (PIT) Driver
//!
//! The PIT generates periodic timer interrupts for preemptive multitasking.
//! We configure it to fire IRQ0 at a configurable frequency (default 100 Hz).

#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::AtomicU32;
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::Ordering;

// PIT I/O ports
#[cfg(not(target_arch = "aarch64"))]
const PIT_CHANNEL_0: u16 = 0x40;
#[cfg(not(target_arch = "aarch64"))]
const PIT_COMMAND: u16 = 0x43;

// PIT frequency (1.193182 MHz)
#[cfg(not(target_arch = "aarch64"))]
const PIT_FREQUENCY: u32 = 1193182;

// Target interrupt frequency (100 Hz = 10ms ticks)
#[cfg(not(target_arch = "aarch64"))]
const TIMER_HZ: u32 = 100;

// Global tick counter (IRQ-safe, 64-bit via two 32-bit atomics)
#[cfg(not(target_arch = "aarch64"))]
static TICKS_LO: AtomicU32 = AtomicU32::new(0);
#[cfg(not(target_arch = "aarch64"))]
static TICKS_HI: AtomicU32 = AtomicU32::new(0);

/// Initialize the PIT timer
#[cfg(not(target_arch = "aarch64"))]
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

#[cfg(target_arch = "aarch64")]
pub fn init() {}

/// Called by the timer interrupt handler
#[cfg(not(target_arch = "aarch64"))]
pub fn tick() {
    let prev = TICKS_LO.fetch_add(1, Ordering::Relaxed);
    if prev == u32::MAX {
        TICKS_HI.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn tick() {}

/// Get current tick count
#[cfg(not(target_arch = "aarch64"))]
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

#[cfg(target_arch = "aarch64")]
pub fn get_ticks() -> u64 {
    crate::arch::aarch64_virt::timer_ticks()
}

/// Try to get ticks (non-blocking) - returns None if lock held
pub fn try_get_ticks() -> Option<u64> {
    Some(get_ticks())
}

/// Get timer frequency in Hz
#[cfg(not(target_arch = "aarch64"))]
pub fn get_frequency() -> u32 {
    TIMER_HZ
}

#[cfg(target_arch = "aarch64")]
pub fn get_frequency() -> u32 {
    let hz = crate::arch::aarch64_virt::timer_frequency_hz();
    hz.try_into().unwrap_or(u32::MAX).max(1)
}

/// Sleep for approximately N milliseconds
/// Note: This is a busy-wait for now, will be replaced with scheduler sleep
pub fn sleep_ms(ms: u32) {
    let start = get_ticks();
    let target_ticks = (ms as u64 * get_frequency() as u64) / 1000;

    while get_ticks() - start < target_ticks {
        #[cfg(target_arch = "aarch64")]
        core::hint::spin_loop();

        #[cfg(not(target_arch = "aarch64"))]
        unsafe {
            // Use HLT to save power while waiting
            core::arch::asm!("hlt");
        }
    }
}

// Port I/O functions
#[cfg(not(target_arch = "aarch64"))]
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}
