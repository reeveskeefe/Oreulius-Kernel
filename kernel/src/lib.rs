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
pub mod net;
pub mod platform;
pub mod scheduler;
pub mod security;
pub mod serial;
pub mod services;
pub mod shell;
pub mod temporal;

// Execution subsystems — wasm/elf/replay/jit available on all arches.
// On AArch64 the JIT path is stubbed to interpreter-only (see wasm_jit.rs).
pub use execution::{elf, intent_wasm, replay, wasm, wasm_jit, wasm_thread};

// Filesystem extras — ATA/NVMe/paging are x86 hardware drivers; AArch64 uses
// virtio-blk + MMU stubs already in place.
#[cfg(not(target_arch = "aarch64"))]
pub use fs::{ata, disk, nvme, paging};
#[cfg(target_arch = "aarch64")]
pub use fs::paging;

pub use fs::{vfs, vfs_platform, virtio_blk};
pub use math::exact_rational;
pub use math::tensor_core;

// Memory helpers — asm_bindings / hardened_allocator are x86-specific inline asm.
#[cfg(not(target_arch = "aarch64"))]
pub use memory::{asm_bindings, hardened_allocator};
pub use memory::wait_free_ring;

// Platform — gdt/idt are x86-only; syscall/usermode/interrupt_dag are shared.
pub use platform::{interrupt_dag, syscall, usermode};
#[cfg(not(target_arch = "aarch64"))]
pub use platform::{gdt, idt_asm};

// Scheduler subsystems — fully shared.
pub use scheduler::{
    pit, process, process_platform, quantum_scheduler, scheduler_platform,
    scheduler_runtime_platform,
};
#[cfg(not(target_arch = "aarch64"))]
pub use scheduler::{process_asm, tasks};

// Security — all security modules compiled for all arches.
// crash_log/enclave/formal/kpti/memory_isolation contain no x86 intrinsics.
pub use security::{cpu_security, crash_log, enclave, formal, intent_graph, kpti, memory_isolation};

// Services — fleet/health/ota/wasi compiled for all arches.
pub use services::{fleet, health, ota, registry, wasi};

// Shell — console_service/terminal use VGA on x86; AArch64 uses PL011 serial.
pub use shell::{commands, commands_shared};
#[cfg(not(target_arch = "aarch64"))]
pub use shell::{advanced_commands, console_service, terminal};

// Temporal — fully arch-neutral.
pub use temporal::{persistence, temporal_asm};

// Drivers — hardware-specific drivers gated per arch.
#[cfg(not(target_arch = "aarch64"))]
pub use drivers::{
    acpi_asm, audio, bluetooth, compositor, dma_asm, framebuffer, gpu_support, input,
    keyboard, memopt_asm, mouse, pci, usb, vga,
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
    // Classify the crash for structured telemetry and OTA rollback decisions.
    let crash_class = crate::crash_log::classify_panic(info);

    #[cfg(target_arch = "aarch64")]
    {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.init_early();
        uart.write_str("[PANIC] class=");
        uart.write_str(crash_class.as_str());
        uart.write_str("\n");
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        use core::fmt::Write;

        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = writeln!(serial, "[PANIC] class={} {}", crash_class.as_str(), info);
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
