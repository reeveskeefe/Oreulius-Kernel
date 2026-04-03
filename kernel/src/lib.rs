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

#![no_std]
#![feature(alloc_error_handler)]
#![feature(new_uninit)]

extern crate alloc;
use alloc::boxed::Box;

pub mod arch;
pub mod capability;
pub use capability::cap_graph;
pub mod browser_backend;
pub mod compositor;
pub mod crypto;
pub mod drivers;
pub mod execution;
pub mod fs;
pub mod ipc;
pub mod math;
pub mod memory;
pub mod net;
pub mod platform;
pub mod scheduler;
pub mod security;
pub mod serial;
pub mod services;
pub mod shell;
pub mod temporal;

// Execution subsystems — elf/wasm/wasm_thread are x86-only JIT paths.
// wasm_jit is now available on all architectures (AArch64 uses interpreter path).
// AArch64 only builds the interpreter (intent_wasm) and the replay engine.
#[cfg(not(target_arch = "aarch64"))]
pub use execution::{elf, intent_wasm, replay, wasm, wasm_jit, wasm_thread};
#[cfg(target_arch = "aarch64")]
pub use execution::{intent_wasm, replay, wasm_jit};

// Filesystem extras — ATA/NVMe/paging are x86 hardware drivers; AArch64 uses
// virtio-blk + MMU stubs already in place.  paging.rs uses x86 inline asm
// and is gated out of fs/mod.rs on AArch64, so we cannot re-export it there.
#[cfg(not(target_arch = "aarch64"))]
pub use fs::{ata, disk, nvme, paging};

pub use fs::{vfs, vfs_platform, virtio_blk};
pub use math::exact_rational;
pub use math::linear_capability;

// Memory helpers — asm_bindings / hardened_allocator are x86-specific inline asm.
pub use memory::wait_free_ring;
#[cfg(not(target_arch = "aarch64"))]
pub use memory::{asm_bindings, hardened_allocator};

// Platform — gdt/idt are x86-only; syscall/usermode/interrupt_dag are shared.
#[cfg(not(target_arch = "aarch64"))]
pub use platform::{gdt, idt_asm};
pub use platform::{interrupt_dag, syscall, usermode};

// Scheduler subsystems — fully shared.
pub use scheduler::{
    pit, process, process_platform, quantum_scheduler, scheduler_platform,
    scheduler_runtime_platform,
};
#[cfg(not(target_arch = "aarch64"))]
pub use scheduler::{process_asm, tasks};

// Security — cpu_security/crash_log/enclave/formal/kpti/memory_isolation are x86-only.
// intent_graph is arch-neutral and always re-exported.
#[cfg(target_arch = "aarch64")]
pub use security::intent_graph;
#[cfg(not(target_arch = "aarch64"))]
pub use security::{
    cpu_security, crash_log, enclave, formal, intent_graph, kpti, memory_isolation,
};

// Services — all modules now available on all architectures.
pub use services::{fleet, health, ota, registry, wasi};

// Shell — console_service/terminal use VGA on x86; AArch64 uses PL011 serial.
#[cfg(not(target_arch = "aarch64"))]
pub use shell::{advanced_commands, console_service, terminal};
pub use shell::{commands, commands_shared};

// Temporal — fully arch-neutral.
pub use temporal::{persistence, temporal_asm};

// Drivers — hardware-specific drivers gated per arch.
#[cfg(not(target_arch = "aarch64"))]
pub use drivers::{
    acpi_asm, audio, bluetooth, dma_asm, framebuffer, gpu_support, input, keyboard, memopt_asm,
    mouse, pci, usb, vga,
};

// Network — the full network stack (capnet, virtio_net, netstack, tls) is
// available on all arches.  Legacy x86-specific NIC drivers (e1000/rtl8139)
// remain x86-only.
pub use net::{capnet, net_reactor, netstack, tls, virtio_net};
#[cfg(not(target_arch = "aarch64"))]
pub use net::{e1000, rtl8139, wifi};

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
    crate::arch::mmu::page_size()
}

#[inline]
pub fn runtime_heap_range() -> (usize, usize) {
    crate::memory::heap_range()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn runtime_jit_arena_range() -> (usize, usize) {
    crate::memory::jit_arena_range()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn runtime_jit_arena_range() -> (usize, usize) {
    (0, 0)
}

#[inline]
pub fn runtime_background_maintenance() {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::wasm::drain_pending_spawns();
        crate::wasm::tick_background_threads();
    }
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
    let crash_class = crate::crash_log::classify_panic(info);

    #[cfg(target_arch = "aarch64")]
    {
        struct UartWriter;
        impl core::fmt::Write for UartWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let uart = crate::arch::aarch64_pl011::early_uart();
                uart.init_early();
                uart.write_str(s);
                Ok(())
            }
        }

        use core::fmt::Write;
        let uart = crate::arch::aarch64_pl011::early_uart();
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

        crate::crash_log::record_panic(info);
    }

    crate::arch::halt_loop()
}

#[cfg(not(any(test, feature = "host-tests")))]
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = layout;
        let uart = crate::arch::aarch64_pl011::early_uart();
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

#[cfg(test)]
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
/// On x86/x86_64 this feeds the existing quantum scheduler tick path.
/// On AArch64 bring-up it routes to the AArch64 runtime hook until the
/// full scheduler module is ported.
#[allow(dead_code)]
#[inline]
pub(crate) fn kernel_timer_tick_hook() {
    #[cfg(target_arch = "aarch64")]
    {
        crate::quantum_scheduler::on_timer_tick();
        crate::arch::aarch64_virt::scheduler_timer_tick_hook();
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::quantum_scheduler::on_timer_tick();
    }

    // Pump compositor input + present dirty windows on every tick.
    crate::compositor::tick();
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    crate::arch::enter_runtime()
}
