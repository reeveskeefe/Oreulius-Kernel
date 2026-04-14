/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
#[cfg(test)]
extern crate std;
use alloc::boxed::Box;

#[cfg(test)]
use std::sync::{Mutex, OnceLock};

pub mod arch;
pub mod capability;
pub mod browser_backend;
pub mod compositor;
pub mod crypto;
pub mod drivers;
pub mod execution;
pub mod fs;
pub mod ipc;
pub mod invariants;
pub mod math;
pub mod memory;
pub mod net;
pub mod observability;
pub mod platform;
pub mod scheduler;
pub mod security;
pub mod serial;
pub mod services;
pub mod shell;
pub mod storage;
pub mod failure;
pub mod runtime;
pub mod temporal;

/// Helper to ensure Box is available for heap allocations across modules.
#[inline]
pub fn ensure_heap_available() -> Option<Box<u32>> {
    Some(Box::new(42))
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn early_console_write_word(slot: *mut u16, value: u16) {
    core::ptr::write_volatile(slot, value);
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn early_console_write_cell(cell: usize, value: u16) {
    early_console_write_word((0xb8000 as *mut u16).add(cell), value);
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub(crate) unsafe fn early_console_read_cell(cell: usize) -> u16 {
    core::ptr::read_volatile((0xb8000 as *const u16).add(cell))
}

#[inline]
pub fn runtime_page_size() -> usize {
    runtime::page_size()
}

#[inline]
pub fn runtime_heap_range() -> (usize, usize) {
    runtime::heap_range()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn runtime_jit_arena_range() -> (usize, usize) {
    runtime::jit_arena_range()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn runtime_jit_arena_range() -> (usize, usize) {
    runtime::jit_arena_range()
}

#[inline]
pub fn runtime_background_maintenance() {
    runtime::background_maintenance()
}

#[cfg(test)]
pub(crate) fn test_serial_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// Host-side lib tests link against the platform test harness instead of the
// kernel linker script, so these symbols are provided as inert placeholders to
// satisfy any non-executed references outside the allocator fast paths.
#[cfg(any(test, feature = "host-tests"))]
#[no_mangle]
pub static _heap_start: u8 = 0;
#[cfg(any(test, feature = "host-tests"))]
#[no_mangle]
pub static _heap_end: u8 = 0;
#[cfg(any(test, feature = "host-tests"))]
#[no_mangle]
pub static _jit_arena_start: u8 = 0;
#[cfg(any(test, feature = "host-tests"))]
#[no_mangle]
pub static _jit_arena_end: u8 = 0;

#[cfg(not(any(test, feature = "host-tests")))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Classify the crash for structured telemetry and OTA rollback decisions.
    // crash_log is x86-only; on AArch64 we use a static fallback.
    #[cfg(not(target_arch = "aarch64"))]
    let crash_class = crate::security::crash_log::classify_panic(info);

    #[cfg(target_arch = "aarch64")]
    {
        struct UartWriter;
        impl core::fmt::Write for UartWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
                uart.init_early();
                uart.write_str(s);
                Ok(())
            }
        }

        use core::fmt::Write;
        let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
        uart.init_early();
        uart.write_str("[PANIC] ");
        let mut out = UartWriter;
        let _ = writeln!(out, "{}", info);
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        use core::fmt::Write;

        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = writeln!(serial, "[PANIC] class={} {}", crash_class.as_str(), info);
        }

        unsafe {
            let s = "PANIC";
            for (i, byte) in s.bytes().enumerate() {
                early_console_write_cell(i, 0x4F00 | (byte as u16));
            }
        }

        crate::security::crash_log::record_panic(info);
    }

    crate::arch::halt_loop()
}

#[cfg(not(any(test, feature = "host-tests")))]
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = layout;
        let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
        uart.init_early();
        uart.write_str("[ALLOC ERROR]\n");
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        use core::fmt::Write;

        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = writeln!(serial, "[ALLOC ERROR] Layout: {:?}", layout);
        }

        unsafe {
            let msg = b"ALLOC FAIL";
            for (i, &b) in msg.iter().enumerate() {
                early_console_write_cell(i, 0x4F00 | (b as u16));
            }
        }
    }

    crate::arch::halt_loop()
}

#[cfg(all(test, not(target_arch = "aarch64")))]
mod tests {
    use super::early_console_write_word;

    #[test]
    fn early_console_write_word_updates_target() {
        let mut slot = 0u16;
        unsafe {
            early_console_write_word(&mut slot as *mut u16, 0x4F50);
        }
        assert_eq!(
            unsafe { core::ptr::read_volatile(&slot as *const u16) },
            0x4F50
        );
    }
}

/// Arch-neutral timer tick hook.
///
/// On x86/x86_64 this feeds the existing slice scheduler tick path.
/// On AArch64 bring-up it routes to the AArch64 runtime hook until the
/// full scheduler module is ported.
#[allow(dead_code)]
#[inline]
pub(crate) fn kernel_timer_tick_hook() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::scheduler::slice_scheduler::on_timer_tick();
        crate::arch::aarch64::aarch64_virt::scheduler_timer_tick_hook();
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::scheduler::slice_scheduler::on_timer_tick();
    }

    // Pump compositor input + present dirty windows on every tick.
    crate::compositor::tick();
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    crate::arch::enter_runtime()
}
