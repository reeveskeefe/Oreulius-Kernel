/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
#[cfg(not(target_arch = "aarch64"))]
use alloc::boxed::Box;

pub mod arch;
pub mod capability;
pub use capability::cap_graph;
pub mod crypto;
pub mod drivers;
pub mod execution;
pub mod fs;
pub mod ipc;
pub mod math;
pub mod memory;
#[cfg(not(target_arch = "aarch64"))]
pub mod net;
pub mod platform;
pub mod scheduler;
pub mod security;
pub mod serial;
pub mod services;
pub mod shell;
pub mod temporal;
pub use execution::{intent_wasm, replay};
#[cfg(not(target_arch = "aarch64"))]
pub use execution::{elf, wasm, wasm_jit, wasm_thread};
#[cfg(not(target_arch = "aarch64"))]
pub use fs::{ata, disk, nvme, paging};
pub use fs::{vfs, vfs_platform, virtio_blk};
pub use math::exact_rational;
pub use math::tensor_core;
#[cfg(not(target_arch = "aarch64"))]
pub use memory::{asm_bindings, hardened_allocator};
pub use memory::wait_free_ring;
pub use platform::{interrupt_dag, syscall, usermode};
#[cfg(not(target_arch = "aarch64"))]
pub use platform::{gdt, idt_asm};
pub use scheduler::{
    pit, process, process_platform, quantum_scheduler, scheduler_platform,
    scheduler_runtime_platform,
};
#[cfg(not(target_arch = "aarch64"))]
pub use scheduler::{process_asm, tasks};
pub use security::intent_graph;
#[cfg(not(target_arch = "aarch64"))]
pub use security::{cpu_security, crash_log, enclave, formal, kpti, memory_isolation};
pub use services::registry;
#[cfg(not(target_arch = "aarch64"))]
pub use services::{fleet, health, ota, wasi};
pub use shell::{commands, commands_shared};
#[cfg(not(target_arch = "aarch64"))]
pub use shell::{advanced_commands, console_service, terminal};
pub use temporal::{persistence, temporal_asm};
#[cfg(not(target_arch = "aarch64"))]
pub use drivers::{
    acpi_asm, audio, bluetooth, compositor, dma_asm, framebuffer, gpu_support, input,
    keyboard, memopt_asm, mouse, pci, usb, vga,
};
#[cfg(not(target_arch = "aarch64"))]
pub use net::{capnet, e1000, net_reactor, netstack, rtl8139, tls, wifi};

/// Helper to ensure Box is available for heap allocations across modules.
#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn ensure_heap_available() -> Option<Box<u32>> {
    Some(Box::new(42))
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

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.init_early();
        let _ = info;
        uart.write_str("[PANIC]\n");
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        use core::fmt::Write;

        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = writeln!(serial, "[PANIC] {}", info);
        }

        unsafe {
            let vga_buf = 0xb8000 as *mut u16;
            let s = "PANIC";
            for (i, byte) in s.bytes().enumerate() {
                *vga_buf.add(i) = 0x4F00 | (byte as u16);
            }
        }

        crate::crash_log::record_panic(info);
    }

    crate::arch::halt_loop()
}

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
            let vga = 0xb8000 as *mut u16;
            let msg = b"ALLOC FAIL";
            for (i, &b) in msg.iter().enumerate() {
                *vga.add(i) = 0x4F00 | (b as u16);
            }
        }
    }

    crate::arch::halt_loop()
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
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    crate::arch::enter_runtime()
}
