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

#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
#[cfg(not(target_arch = "aarch64"))]
use alloc::boxed::Box;
// use alloc::vec::Vec;
// use alloc::string::String;

#[cfg(target_arch = "aarch64")]
mod aarch64_alloc;
#[cfg(not(target_arch = "aarch64"))]
pub mod acpi_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod advanced_commands;
pub mod arch;
#[cfg(not(target_arch = "aarch64"))]
pub mod asm_bindings;
#[cfg(not(target_arch = "aarch64"))]
pub mod capability;
#[cfg(not(target_arch = "aarch64"))]
pub mod capnet;
#[cfg(not(target_arch = "aarch64"))]
pub mod commands;
#[cfg(target_arch = "aarch64")]
#[path = "commands_aarch64.rs"]
pub mod commands;
pub mod commands_shared;
#[cfg(not(target_arch = "aarch64"))]
pub mod console_service;
#[cfg(not(target_arch = "aarch64"))]
pub mod cpu_security;
#[cfg(not(target_arch = "aarch64"))]
pub mod crypto;
#[cfg(not(target_arch = "aarch64"))]
pub mod disk;
#[cfg(not(target_arch = "aarch64"))]
pub mod dma_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod e1000;
#[cfg(not(target_arch = "aarch64"))]
pub mod elf;
#[cfg(not(target_arch = "aarch64"))]
pub mod enclave;
pub mod exact_rational;
#[cfg(not(target_arch = "aarch64"))]
pub mod formal;
#[cfg(not(target_arch = "aarch64"))]
pub mod fs;
#[cfg(not(target_arch = "aarch64"))]
pub mod gdt;
#[cfg(not(target_arch = "aarch64"))]
pub mod hardened_allocator;
#[cfg(not(target_arch = "aarch64"))]
pub mod idt_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod intent_graph;
#[cfg(not(target_arch = "aarch64"))]
pub mod intent_wasm;
pub mod interrupt_dag;
#[cfg(not(target_arch = "aarch64"))]
pub mod ipc;
#[cfg(not(target_arch = "aarch64"))]
pub mod keyboard;
#[cfg(not(target_arch = "aarch64"))]
pub mod kpti;
#[cfg(not(target_arch = "aarch64"))]
pub mod memopt_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod memory;
#[cfg(not(target_arch = "aarch64"))]
pub mod memory_isolation;
#[cfg(not(target_arch = "aarch64"))]
pub mod net;
#[cfg(not(target_arch = "aarch64"))]
pub mod net_reactor;
#[cfg(not(target_arch = "aarch64"))]
pub mod netstack;
#[cfg(not(target_arch = "aarch64"))]
pub mod paging;
#[cfg(not(target_arch = "aarch64"))]
pub mod pci;
#[cfg(not(target_arch = "aarch64"))]
pub mod persistence;
#[cfg(not(target_arch = "aarch64"))]
pub mod pit;
pub mod process;
#[cfg(not(target_arch = "aarch64"))]
pub mod process_asm;
pub mod process_platform;
pub mod quantum_scheduler;
#[cfg(not(target_arch = "aarch64"))]
pub mod registry;
#[cfg(not(target_arch = "aarch64"))]
pub mod replay;
#[cfg(not(target_arch = "aarch64"))]
pub mod scheduler;
pub mod scheduler_platform;
pub mod scheduler_runtime_platform;
#[cfg(not(target_arch = "aarch64"))]
pub mod security;
#[cfg(not(target_arch = "aarch64"))]
pub mod serial;
#[cfg(not(target_arch = "aarch64"))]
pub mod syscall;
#[cfg(not(target_arch = "aarch64"))]
pub mod tasks;
#[cfg(not(target_arch = "aarch64"))]
pub mod temporal;
#[cfg(not(target_arch = "aarch64"))]
pub mod temporal_asm;
#[cfg(not(target_arch = "aarch64"))]
pub mod terminal;
#[cfg(not(target_arch = "aarch64"))]
pub mod usermode;
pub mod vfs;
pub mod vfs_platform;
#[cfg(not(target_arch = "aarch64"))]
pub mod vga;
pub mod virtio_blk;
pub mod wait_free_ring;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm_jit;
#[cfg(not(target_arch = "aarch64"))]
pub mod wifi;

/// Helper to ensure Box is available for heap allocations across modules
#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn ensure_heap_available() -> Option<Box<u32>> {
    // Try to allocate on heap to verify allocator is working
    Some(Box::new(42))
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
        // Attempt to print to serial port first (best effort, no locks if possible)
        use core::fmt::Write;
        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = writeln!(serial, "[PANIC] {}", info);
        }

        // Direct VGA write to guarantee visibility (bypassing all locks)
        unsafe {
            let vga_buf = 0xb8000 as *mut u16;
            let s = "PANIC";
            // Write PANIC in Red/White at top left
            for (i, byte) in s.bytes().enumerate() {
                *vga_buf.add(i) = 0x4F00 | (byte as u16);
            }
        }

        // Try normal printing if locks aren't held (might deadlock, but we tried)
        // vga::print_str("[PANIC] Kernel panic\n");
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

#[cfg(target_arch = "x86_64")]
fn x86_64_read_rflags() -> u64 {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
    }
    flags
}

#[cfg(target_arch = "x86_64")]
fn x86_64_read_ctrl_regs() -> (u64, u64, u64) {
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    (cr0, cr3, cr4)
}

#[cfg(target_arch = "x86_64")]
fn x86_64_read_efer() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0xC000_0080u32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack),
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[cfg(target_arch = "x86_64")]
fn rust_main_x86_64_bringup() -> ! {
    unsafe {
        let vga = 0xb8000 as *mut u16;
        *(vga.add(8)) = 0x0E58; // 'X'
        *(vga.add(9)) = 0x0E36; // '6'
        *(vga.add(10)) = 0x0E34; // '4'
    }

    crate::serial_println!("[X64] Early bring-up path");

    let boot_info = arch::boot_info();
    let protocol = match boot_info.protocol {
        arch::BootProtocol::Unknown => "unknown",
        arch::BootProtocol::Multiboot1 => "multiboot1",
        arch::BootProtocol::Multiboot2 => "multiboot2",
    };

    crate::serial_println!("[X64] platform={}", arch::platform_name());
    crate::serial_println!("[X64] boot protocol={}", protocol);
    crate::serial_println!(
        "[X64] raw magic={:#010x} info_ptr={:#018x}",
        boot_info.raw_boot_magic.unwrap_or(0),
        boot_info.raw_info_ptr.unwrap_or(0)
    );
    crate::serial_println!(
        "[X64] cmdline ptr={:#018x} text={}",
        boot_info.cmdline_ptr.unwrap_or(0),
        boot_info.cmdline_str().unwrap_or("<none>")
    );
    crate::serial_println!(
        "[X64] loader  ptr={:#018x} text={}",
        boot_info.boot_loader_name_ptr.unwrap_or(0),
        boot_info.boot_loader_name_str().unwrap_or("<none>")
    );
    crate::serial_println!(
        "[X64] acpi rsdp={:#018x}",
        boot_info.acpi_rsdp_ptr.unwrap_or(0)
    );

    memory::init();
    crate::serial_println!("[X64] heap allocator initialized");

    if let Err(e) = arch::mmu::init() {
        crate::serial_println!("[X64] mmu init failed: {}", e);
        crate::arch::halt_loop();
    }
    crate::serial_println!(
        "[X64] mmu backend={} root={:#018x}",
        arch::mmu::backend_name(),
        arch::mmu::current_page_table_root_addr()
    );

    let (cr0, cr3, cr4) = crate::arch::x86_64_runtime::read_ctrl_regs();
    let efer = crate::arch::x86_64_runtime::read_efer();
    crate::serial_println!(
        "[X64] cr0={:#018x} cr3={:#018x} cr4={:#018x} efer={:#018x}",
        cr0,
        cr3,
        cr4,
        efer
    );
    crate::serial_println!(
        "[X64] paging sanity pg={} pae={} lme={} lma={}",
        (cr0 >> 31) & 1,
        (cr4 >> 5) & 1,
        (efer >> 8) & 1,
        (efer >> 10) & 1
    );

    let rflags_before = x86_64_read_rflags();
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
    let rflags_after = x86_64_read_rflags();
    crate::serial_println!(
        "[X64] irq flag sanity IF {} -> {}",
        (rflags_before >> 9) & 1,
        (rflags_after >> 9) & 1
    );

    crate::serial_println!("[X64] init gdt/tss...");
    arch::init_cpu_tables();
    crate::serial_println!("[X64] init idt/traps...");
    arch::init_trap_table();
    crate::serial_println!("[X64] init pic...");
    arch::init_interrupt_controller();
    crate::serial_println!("[X64] init pit...");
    arch::init_timer();
    crate::serial_println!("[X64] enabling interrupts...");
    arch::enable_interrupts();
    crate::serial_println!("[X64] interrupts enabled");

    crate::arch::x86_64_runtime::self_test_traps_and_timer();

    unsafe {
        let vga = 0xb8000 as *mut u16;
        *(vga.add(11)) = 0x0E48; // 'H'
        *(vga.add(12)) = 0x0E4C; // 'L'
        *(vga.add(13)) = 0x0E53; // 'S'
        *(vga.add(14)) = 0x0E48; // 'H'
    }
    crate::serial_println!("[X64] Bring-up diagnostics complete; entering shell");
    crate::arch::x86_64_runtime::run_serial_shell()
}

#[cfg(target_arch = "aarch64")]
fn aarch64_uart_write_hex(value: usize) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 2 + (core::mem::size_of::<usize>() * 2)];
    buf[0] = b'0';
    buf[1] = b'x';
    let digits = core::mem::size_of::<usize>() * 2;
    for i in 0..digits {
        let shift = (digits - 1 - i) * 4;
        buf[2 + i] = HEX[((value >> shift) & 0xF) as usize];
    }
    for &b in &buf {
        uart.write_byte(b);
    }
}

#[cfg(target_arch = "aarch64")]
fn aarch64_uart_log_line(msg: &str) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(msg);
    uart.write_str("\n");
}

#[cfg(target_arch = "aarch64")]
fn aarch64_uart_log_hex_line(prefix: &str, value: usize) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(prefix);
    aarch64_uart_write_hex(value);
    uart.write_str("\n");
}

#[cfg(target_arch = "aarch64")]
extern "C" fn aarch64_shell_scheduler_task() -> ! {
    crate::arch::enable_interrupts();
    crate::arch::aarch64_virt::run_serial_shell()
}

#[cfg(target_arch = "aarch64")]
fn rust_main_aarch64_bringup() -> ! {
    aarch64_uart_log_line("[A64] Early bring-up path");
    aarch64_uart_log_line("[A64] init early platform...");
    arch::init_cpu_tables();

    let boot_info = arch::boot_info();
    {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.write_str("[A64] platform=");
        uart.write_str(arch::platform_name());
        uart.write_str("\n");
    }
    aarch64_uart_log_hex_line(
        "[A64] boot raw_info_ptr=",
        boot_info.raw_info_ptr.unwrap_or(0),
    );
    aarch64_uart_log_hex_line("[A64] boot dtb_ptr=", boot_info.dtb_ptr.unwrap_or(0));

    aarch64_uart_log_line("[A64] mmu init...");
    match arch::mmu::init() {
        Ok(()) => {
            let uart = crate::arch::aarch64_pl011::early_uart();
            uart.write_str("[A64] mmu backend=");
            uart.write_str(arch::mmu::backend_name());
            uart.write_str("\n");
        }
        Err(e) => {
            let uart = crate::arch::aarch64_pl011::early_uart();
            uart.write_str("[A64] mmu init failed: ");
            uart.write_str(e);
            uart.write_str("\n");
            crate::arch::halt_loop();
        }
    }

    aarch64_uart_log_line("[A64] init process backend...");
    crate::process::init();
    crate::vfs_platform::aarch64_register_default_shared_process_bridge();

    match boot_info.raw_info_ptr {
        Some(ptr) => match crate::arch::aarch64_dtb::parse_dtb_header(ptr) {
            Some(hdr) => {
                aarch64_uart_log_line("[A64] DTB header parse: ok");
                aarch64_uart_log_hex_line("[A64] dtb total_size=", hdr.total_size);
                aarch64_uart_log_hex_line("[A64] dtb off_dt_struct=", hdr.off_dt_struct);
                aarch64_uart_log_hex_line("[A64] dtb off_dt_strings=", hdr.off_dt_strings);
                aarch64_uart_log_hex_line("[A64] dtb off_mem_rsvmap=", hdr.off_mem_rsvmap);
                aarch64_uart_log_hex_line("[A64] dtb version=", hdr.version as usize);
                aarch64_uart_log_hex_line(
                    "[A64] dtb last_comp_version=",
                    hdr.last_comp_version as usize,
                );
                aarch64_uart_log_hex_line("[A64] dtb size_dt_struct=", hdr.size_dt_struct);
                aarch64_uart_log_hex_line("[A64] dtb size_dt_strings=", hdr.size_dt_strings);
            }
            None => aarch64_uart_log_line("[A64] DTB header parse: invalid"),
        },
        None => aarch64_uart_log_line("[A64] DTB header parse: no pointer"),
    }

    aarch64_uart_log_line("[A64] init vectors...");
    arch::init_trap_table();
    aarch64_uart_log_line("[A64] init GIC...");
    arch::init_interrupt_controller();
    aarch64_uart_log_line("[A64] init timer...");
    arch::init_timer();
    aarch64_uart_log_line("[A64] enable interrupts...");
    arch::enable_interrupts();
    crate::arch::aarch64_virt::self_test_sync_exception();
    aarch64_uart_log_line("[A64] bring-up complete; starting shared scheduler");

    crate::quantum_scheduler::init();
    {
        let mut sched = crate::quantum_scheduler::scheduler().lock();
        if let Err(e) = sched.add_kernel_thread(
            aarch64_shell_scheduler_task,
            crate::process::ProcessPriority::Normal,
        ) {
            let uart = crate::arch::aarch64_pl011::early_uart();
            uart.write_str("[A64] scheduler add shell task failed: ");
            uart.write_str(e);
            uart.write_str("\n");
            crate::arch::halt_loop();
        }
    }
    crate::quantum_scheduler::QuantumScheduler::start_scheduling()
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    #[cfg(target_arch = "aarch64")]
    {
        return rust_main_aarch64_bringup();
    }

    #[cfg(target_arch = "x86_64")]
    {
        return rust_main_x86_64_bringup();
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        // IMMEDIATE VGA WRITE to confirm we reached Rust code
        unsafe {
            let vga = 0xb8000 as *mut u16;
            *(vga.add(8)) = 0x0252; // 'R' in green at position 8 (after "BOOTCALL")
        }

        // CRITICAL: Initialize memory allocator FIRST before ANY allocations
        memory::init();

        unsafe {
            let vga = 0xb8000 as *mut u16;
            *(vga.add(9)) = 0x024d; // 'M' in green - memory initialized
        }

        // Now we can use VGA (and everything else)
        vga::print_str("[MEMORY] Heap allocator initialized\n");
        let boot_info = arch::boot_info();
        vga::print_str("[ARCH] Platform: ");
        vga::print_str(arch::platform_name());
        vga::print_str("\n");
        vga::print_str("[BOOT] Protocol: ");
        match boot_info.protocol {
            arch::BootProtocol::Unknown => vga::print_str("unknown"),
            arch::BootProtocol::Multiboot1 => vga::print_str("multiboot1"),
            arch::BootProtocol::Multiboot2 => vga::print_str("multiboot2"),
        }
        vga::print_str("\n");
        vga::print_str("[BOOT] Cmdline ptr: 0x");
        advanced_commands::print_hex(boot_info.cmdline_ptr.unwrap_or(0));
        vga::print_str("\n");
        vga::print_str("[BOOT] Cmdline: ");
        if let Some(cmdline) = boot_info.cmdline_str() {
            vga::print_str(cmdline);
        } else {
            vga::print_str("<none>");
        }
        vga::print_str("\n");
        vga::print_str("[BOOT] Loader ptr: 0x");
        advanced_commands::print_hex(boot_info.boot_loader_name_ptr.unwrap_or(0));
        vga::print_str("\n");
        vga::print_str("[BOOT] Loader: ");
        if let Some(loader) = boot_info.boot_loader_name_str() {
            vga::print_str(loader);
        } else {
            vga::print_str("<none>");
        }
        vga::print_str("\n");
        vga::print_str("[BOOT] ACPI RSDP ptr: 0x");
        advanced_commands::print_hex(boot_info.acpi_rsdp_ptr.unwrap_or(0));
        vga::print_str("\n");
        vga::print_str("[MMU] Backend: ");
        vga::print_str(arch::mmu::backend_name());
        vga::print_str("\n");

        // Test heap allocation
        if ensure_heap_available().is_some() {
            vga::print_str("[MEMORY] Heap allocation test passed\n");
        }

        // Initialize GDT/TSS for ring transitions
        vga::print_str("[GDT] Initializing GDT/TSS...\n");
        arch::init_cpu_tables();
        vga::print_str("[GDT] GDT loaded, TSS ready\n");

        // Initialize IDT and PIC before enabling paging/interrupts
        vga::print_str("[IDT] Initializing interrupt descriptor table...\n");
        arch::init_trap_table();
        vga::print_str("[IDT] IDT loaded\n");
        vga::print_str("[IRQCTL] Initializing interrupt controller...\n");
        arch::init_interrupt_controller();
        vga::print_str("[IRQCTL] Controller initialized\n");

        // Initialize Keyboard (specifically PS/2 configuration)
        keyboard::init();

        // Initialize virtual memory management (must be early, after physical memory)
        vga::print_str("[PAGING] Enabling virtual memory...\n");
        if let Err(e) = arch::mmu::init() {
            vga::print_str("[PAGING] Failed to initialize: ");
            vga::print_str(e);
            vga::print_str("\n");
            loop {
                core::hint::spin_loop();
            }
        }
        vga::print_str("[PAGING] Virtual memory enabled (4KB pages, user/kernel separation)\n");
        vga::print_str("[PAGING] Kernel root addr: 0x");
        advanced_commands::print_hex(arch::mmu::kernel_page_table_root_addr().unwrap_or(0));
        vga::print_str("\n");

        // Enable CPU hardening features (SMEP/SMAP) if supported.
        cpu_security::init();
        if let Err(e) = kpti::init() {
            vga::print_str("[KPTI] Init failed: ");
            vga::print_str(e);
            vga::print_str("\n");
        }
        memory_isolation::init();
        enclave::init();

        // Initialize syscall interface
        vga::print_str("[SYSCALL] Setting up system call interface...\n");
        syscall::init();
        vga::print_str("[SYSCALL] INT 0x80 handler registered\n");

        vga::print_str("[DEBUG] About to initialize WASM runtime...\n");

        vga::print_str("[WASM] Runtime initialized\n");

        // Initialize services
        vga::print_str("[DEBUG] About to init fs...\n");
        fs::init();
        vga::print_str("[DEBUG] About to init vfs...\n");
        vfs::init();
        vga::print_str("[DEBUG] About to init persistence...\n");
        persistence::init();
        vga::print_str("[DEBUG] About to init temporal...\n");
        temporal::init();
        vga::print_str("[DEBUG] About to init ipc...\n");
        ipc::init();
        vga::print_str("[DEBUG] About to init registry...\n");
        registry::init();
        vga::print_str("[DEBUG] About to init process...\n");
        process::init(); // Creates init process (PID 1)
        vga::print_str("[DEBUG] About to init wasm...\n");
        wasm::init(); // Initialize WASM runtime

        // Initialize security subsystem
        vga::print_str("[SECURITY] Initializing security manager...\n");
        security::init();
        vga::print_str("[SECURITY] Audit logging enabled\n");
        capnet::init();
        vga::print_str("[CAPNET] Peer token subsystem initialized\n");

        // Initialize capability subsystem
        vga::print_str("[CAPABILITY] Initializing capability manager...\n");
        capability::init();
        vga::print_str("[CAPABILITY] Authority model enabled\n");

        // Initialize console service
        vga::print_str("[CONSOLE] Initializing console service...\n");
        console_service::init();
        vga::print_str("[CONSOLE] Capability-based I/O ready\n");

        vga::print_str("[DEBUG] About to initialize timer...\n");

        // Initialize timer for preemptive scheduling
        vga::print_str("[TIMER] Initializing PIT (100 Hz)...\n");
        arch::init_timer();
        vga::print_str("[SCHED] Preemptive scheduler ready\n");

        // Enable CPU interrupts now that IDT/PIC/PIT are configured
        vga::print_str("[IRQ] Enabling interrupts...\n");
        arch::enable_interrupts();
        vga::print_str("[IRQ] Interrupts enabled\n");

        vga::print_str("[DEBUG] Timer initialized successfully\n");

        // Initialize PCI and detect devices
        vga::print_str("[PCI] Scanning for devices...\n");
        let mut pci_scanner = pci::PciScanner::new();
        pci_scanner.scan();

        if let Some(blk_device) = pci_scanner.find_virtio_block() {
            vga::print_str("[BLOCK] VirtIO block device detected\n");
            if let Err(e) = virtio_blk::init(blk_device) {
                vga::print_str("[BLOCK] Init failed: ");
                vga::print_str(e);
                vga::print_str("\n");
            } else {
                vga::print_str("[BLOCK] VirtIO block ready\n");
                persistence::init();
                match temporal::recover_from_persistence() {
                    Ok(()) => vga::print_str("[TEMPORAL] Recovery check complete\n"),
                    Err(e) => {
                        vga::print_str("[TEMPORAL] Recovery skipped: ");
                        vga::print_str(e);
                        vga::print_str("\n");
                    }
                }
            }
        } else {
            vga::print_str("[BLOCK] No VirtIO block device found\n");
        }

        // Try WiFi first, then Ethernet (init currently disabled)
        if let Some(_wifi_device) = pci_scanner.find_wifi_device() {
            vga::print_str("[NET] WiFi device detected (init disabled)\n");
            // net::init(Some(wifi_device));
        } else if let Some(eth_device) = pci_scanner.find_ethernet_device() {
            vga::print_str("[NET] Ethernet device detected, initializing...\n");

            // Use a copy to read BAR for mapping, before moving device into init
            let bar0 = unsafe { eth_device.read_bar(0) };
            if bar0 != 0 {
                vga::print_str("[NET] Mapping MMIO region...\n");
                let phys_base = (bar0 & !0xF) as usize;
                let size = 128 * 1024; // 128KB

                // DEBUG: Print phys_base
                vga::print_str("MMIO Base: 0x");
                advanced_commands::print_hex(phys_base);
                vga::print_str("\n");

                if let Some(ref mut space) = *paging::kernel_space().lock() {
                    for offset in (0..size).step_by(paging::PAGE_SIZE) {
                        let addr = phys_base + offset;
                        let _ = space.map_page(addr, addr, true, false);
                    }
                }

                // DEBUG: Verify mapping
                if let Some(ref mut space) = *paging::kernel_space().lock() {
                    if space.is_mapped(phys_base) {
                        vga::print_str("MMIO Base Mapped successfully\n");
                    } else {
                        vga::print_str("MMIO Base failed to map\n");
                    }
                }
            }

            if e1000::init(eth_device).is_ok() {
                vga::print_str("[NET] E1000 initialized - Ready for DNS/ARP/UDP\n");
                // Enable network stack processing
                // if let Some(mut stack) = netstack::NETWORK_STACK.try_lock() {
                //      vga::print_str("[NET] Network stack available, link up\n");
                // }
            } else {
                vga::print_str("[NET] E1000 init failed\n");
            }
        } else {
            vga::print_str("[NET] No network device found\n");
        }

        vga::print_str("\n[INIT] Initialization complete, starting scheduler...\n");
        tasks::start();
    }
}

#[cfg(not(target_arch = "aarch64"))]
static mut SHELL_HISTORY: [[u8; 256]; 16] = [[0; 256]; 16];
#[cfg(not(target_arch = "aarch64"))]
static mut SHELL_HISTORY_LENS: [usize; 16] = [0; 16];
#[cfg(not(target_arch = "aarch64"))]
static mut SHELL_HISTORY_COUNT: usize = 0;

/// Shell loop (runs as init process)
#[cfg(not(target_arch = "aarch64"))]
pub fn shell_loop() -> ! {
    // Add debug print before touching terminal
    vga::print_str("[SHELL] Starting shell loop...\n");
    terminal::clear_screen();
    vga::print_str("[SHELL] Screen cleared\n");
    terminal::write_str("Oreulia OS\n");
    vga::print_str("[SHELL] Banner printed\n");
    terminal::write_str("Type 'help' for commands.\n\n");
    terminal::write_str("> ");

    let mut input: [u8; 256] = [0; 256];
    let mut len: usize = 0;
    let mut cursor: usize = 0;
    let mut history_index: usize = unsafe { SHELL_HISTORY_COUNT };
    let mut prompt_pos = terminal::cursor_position();
    let mut _max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);

    // Diagnostic Counters
    let mut loops: usize = 0;
    const HEARTBEAT: &[u8] = b"|/-\\";

    loop {
        // Yield to let interrupts happen
        core::hint::spin_loop();

        // 1. Diagnostics (Safe VGA Write at Bottom-Right Corner)
        loops = loops.wrapping_add(1);
        if loops % 10000 == 0 {
            unsafe {
                let vga = 0xB8000 as *mut u16;
                // Heartbeat at Row 24, Col 79
                let pos = 24 * 80 + 79;
                let char_idx = (loops / 10000) % 4;
                *vga.add(pos) = 0x0F00 | (HEARTBEAT[char_idx] as u16);

                // IRQ Count at Row 24, Col 70 "I:XX"
                let irq_cnt = idt_asm::get_interrupt_count(33); // IRQ1 = 32+1 = 33
                let hex = b"0123456789ABCDEF";
                *vga.add(pos - 8) = 0x0F49; // 'I'
                *vga.add(pos - 7) = 0x0F3A; // ':'
                *vga.add(pos - 6) = 0x0F00 | (hex[((irq_cnt >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 5) = 0x0F00 | (hex[(irq_cnt & 0xF) as usize] as u16);

                // Buffer Len at Row 24, Col 60 "B:XX"
                let buf_len = keyboard::event_buffer_len();
                *vga.add(pos - 18) = 0x0F42; // 'B'
                *vga.add(pos - 17) = 0x0F3A; // ':'
                *vga.add(pos - 16) = 0x0F00 | (hex[((buf_len >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 15) = 0x0F00 | (hex[(buf_len & 0xF) as usize] as u16);

                // Last Scancode at Row 24, Col 50 "S:XX"
                let sc = keyboard::get_last_scancode();
                *vga.add(pos - 28) = 0x0F53; // 'S'
                *vga.add(pos - 27) = 0x0F3A; // ':'
                *vga.add(pos - 26) = 0x0F00 | (hex[((sc >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 25) = 0x0F00 | (hex[(sc & 0xF) as usize] as u16);

                // Flags at Row 24, Col 40 "C:0 A:0 S:0 E:0"
                // Removed get_flags() locally to prevent live lock on KEYBOARD mutex.

                let row_offset = 24 * 80;

                // Dropped Packets at Row 24, Col 20 "D:XX"
                let dropped = keyboard::get_dropped_packets();
                *vga.add(row_offset + 20) = 0x0F44; // D
                *vga.add(row_offset + 21) = 0x0F3A; // :
                *vga.add(row_offset + 22) = 0x0F00 | (hex[((dropped >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 23) = 0x0F00 | (hex[(dropped & 0xF) as usize] as u16);

                // Event stats at Row 24, Col 30 "P:XX N:XX E:XX"
                let (pushed, _popped, none, errors) = keyboard::get_event_stats();
                *vga.add(row_offset + 30) = 0x0F50; // P
                *vga.add(row_offset + 31) = 0x0F3A; // :
                *vga.add(row_offset + 32) = 0x0F00 | (hex[((pushed >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 33) = 0x0F00 | (hex[(pushed & 0xF) as usize] as u16);

                *vga.add(row_offset + 35) = 0x0F4E; // N
                *vga.add(row_offset + 36) = 0x0F3A; // :
                *vga.add(row_offset + 37) = 0x0F00 | (hex[((none >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 38) = 0x0F00 | (hex[(none & 0xF) as usize] as u16);

                *vga.add(row_offset + 40) = 0x0F45; // E
                *vga.add(row_offset + 41) = 0x0F3A; // :
                *vga.add(row_offset + 42) = 0x0F00 | (hex[((errors >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 43) = 0x0F00 | (hex[(errors & 0xF) as usize] as u16);
            }
        }

        if let Some(ev) = keyboard::poll_event() {
            match ev {
                keyboard::KeyEvent::AltFn(n) => {
                    terminal::switch_terminal((n.saturating_sub(1)) as usize);
                    terminal::write_str("\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    prompt_pos = terminal::cursor_position();
                    _max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Enter => {
                    terminal::write_char('\n');
                    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
                    if len > 0 {
                        unsafe {
                            if SHELL_HISTORY_COUNT < 16 {
                                SHELL_HISTORY[SHELL_HISTORY_COUNT] = input;
                                SHELL_HISTORY_LENS[SHELL_HISTORY_COUNT] = len;
                                SHELL_HISTORY_COUNT += 1;
                            } else {
                                // Rotate history
                                for i in 1..16 {
                                    SHELL_HISTORY[i - 1] = SHELL_HISTORY[i];
                                    SHELL_HISTORY_LENS[i - 1] = SHELL_HISTORY_LENS[i];
                                }
                                SHELL_HISTORY[15] = input;
                                SHELL_HISTORY_LENS[15] = len;
                            }
                            history_index = SHELL_HISTORY_COUNT;
                        }
                    }
                    commands::execute(line);
                    len = 0;
                    cursor = 0;
                    input = [0; 256];
                    terminal::write_str("> ");
                    prompt_pos = terminal::cursor_position();
                    _max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Backspace => {
                    if cursor > 0 {
                        let start = cursor - 1;
                        for i in start..len.saturating_sub(1) {
                            input[i] = input[i + 1];
                        }
                        len -= 1;
                        cursor -= 1;
                        redraw_line(&input, len, cursor, prompt_pos);
                    }
                }
                keyboard::KeyEvent::Ctrl('a') => {
                    cursor = 0;
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                }
                keyboard::KeyEvent::Ctrl('e') => {
                    cursor = len;
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                keyboard::KeyEvent::Ctrl('k') => {
                    for i in cursor..len {
                        input[i] = 0;
                    }
                    len = cursor;
                    redraw_line(&input, len, cursor, prompt_pos);
                }
                keyboard::KeyEvent::Ctrl('u') => {
                    let mut i = 0;
                    while cursor + i < len {
                        input[i] = input[cursor + i];
                        i += 1;
                    }
                    for j in i..len {
                        input[j] = 0;
                    }
                    len -= cursor;
                    cursor = 0;
                    redraw_line(&input, len, cursor, prompt_pos);
                }
                keyboard::KeyEvent::Ctrl('c') => {
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    terminal::clear_line_from_cursor();
                    terminal::write_str("^C\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    prompt_pos = terminal::cursor_position();
                    _max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Ctrl('z') => {
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    terminal::clear_line_from_cursor();
                    terminal::write_str("^Z\nJob control not implemented\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    prompt_pos = terminal::cursor_position();
                    _max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Ctrl(c) => {
                    // Fallback: treat unhandled Ctrl combinations as normal input
                    if (c.is_ascii_graphic() || c == ' ') && len < input.len() - 1 {
                        for i in (cursor..len).rev() {
                            input[i + 1] = input[i];
                        }
                        input[cursor] = c as u8;
                        len += 1;
                        cursor += 1;
                        redraw_line(&input, len, cursor, prompt_pos);
                    }
                }
                keyboard::KeyEvent::Left => {
                    if cursor > 0 {
                        cursor -= 1;
                        terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                    }
                }
                keyboard::KeyEvent::Right => {
                    if cursor < len {
                        cursor += 1;
                        terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                    }
                }
                keyboard::KeyEvent::Home => {
                    cursor = 0;
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                keyboard::KeyEvent::End => {
                    cursor = len;
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                keyboard::KeyEvent::Up => {
                    if history_index > 0 {
                        history_index -= 1;
                        unsafe {
                            input = SHELL_HISTORY[history_index];
                            len = SHELL_HISTORY_LENS[history_index];
                            cursor = len;
                            redraw_line(&input, len, cursor, prompt_pos);
                        }
                    }
                }
                keyboard::KeyEvent::Down => unsafe {
                    if history_index < SHELL_HISTORY_COUNT {
                        history_index += 1;
                        if history_index == SHELL_HISTORY_COUNT {
                            len = 0;
                            input = [0; 256];
                            cursor = 0;
                            redraw_line(&input, len, cursor, prompt_pos);
                        } else {
                            input = SHELL_HISTORY[history_index];
                            len = SHELL_HISTORY_LENS[history_index];
                            cursor = len;
                            redraw_line(&input, len, cursor, prompt_pos);
                        }
                    }
                },
                keyboard::KeyEvent::AltChar(c) => {
                    // Treat Alt-modified character as a normal character for input
                    if (c.is_ascii_graphic() || c == ' ') && len < input.len() - 1 {
                        for i in (cursor..len).rev() {
                            input[i + 1] = input[i];
                        }
                        input[cursor] = c as u8;
                        len += 1;
                        cursor += 1;
                        redraw_line(&input, len, cursor, prompt_pos);
                    }
                }
                keyboard::KeyEvent::Char(c) => {
                    // Visual debug: print '*' at Row 1, Col 40 to prove we entered Char handler
                    unsafe {
                        let vga_buffer = 0xb8000 as *mut u8;
                        // 80 columns * 2 bytes * 1 row + 40 columns * 2 bytes = 160 + 80 = 240
                        *vga_buffer.offset(240) = b'*';
                        *vga_buffer.offset(241) = 0x0E; // Yellow
                    }

                    // Debug: bypassing max_len and forcing output
                    // terminal::write_char(c); // Commented out to avoid double printing if proper logic works

                    if (c.is_ascii_graphic() || c == ' ') && len < input.len() - 1
                    /* && len < max_len */
                    {
                        for i in (cursor..len).rev() {
                            input[i + 1] = input[i];
                        }
                        input[cursor] = c as u8;
                        len += 1;
                        cursor += 1;
                        redraw_line(&input, len, cursor, prompt_pos);
                    }
                }
                _ => {}
            }
        }

        crate::quantum_scheduler::yield_now();
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn redraw_line(input: &[u8; 256], len: usize, cursor: usize, prompt_pos: (usize, usize)) {
    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
    terminal::clear_line_from_cursor();
    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
    terminal::write_str_no_serial(line);
    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
}
pub mod telemetry;
pub mod tensor_core;
