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

fn uart_write_hex(value: usize) {
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

fn uart_log_line(msg: &str) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(msg);
    uart.write_str("\n");
}

fn uart_log_hex_line(prefix: &str, value: usize) {
    let uart = crate::arch::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(prefix);
    uart_write_hex(value);
    uart.write_str("\n");
}

extern "C" fn shell_scheduler_task() -> ! {
    crate::arch::enable_interrupts();
    crate::arch::aarch64_virt::run_serial_shell()
}

pub fn enter_runtime() -> ! {
    uart_log_line("[A64] Early bring-up path");
    uart_log_line("[A64] init early platform...");
    crate::arch::init_cpu_tables();

    let boot_info = crate::arch::boot_info();
    {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.write_str("[A64] platform=");
        uart.write_str(crate::arch::platform_name());
        uart.write_str("\n");
    }
    uart_log_hex_line("[A64] boot raw_info_ptr=", boot_info.raw_info_ptr.unwrap_or(0));
    uart_log_hex_line("[A64] boot dtb_ptr=", boot_info.dtb_ptr.unwrap_or(0));

    uart_log_line("[A64] mmu init...");
    match crate::arch::mmu::init() {
        Ok(()) => {
            let uart = crate::arch::aarch64_pl011::early_uart();
            uart.write_str("[A64] mmu backend=");
            uart.write_str(crate::arch::mmu::backend_name());
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

    uart_log_line("[A64] init process backend...");
    crate::process::init();
    uart_log_line("[A64] init syscall core...");
    crate::syscall::init();

    match boot_info.raw_info_ptr {
        Some(ptr) => match crate::arch::aarch64_dtb::parse_dtb_header(ptr) {
            Some(hdr) => {
                uart_log_line("[A64] DTB header parse: ok");
                uart_log_hex_line("[A64] dtb total_size=", hdr.total_size);
                uart_log_hex_line("[A64] dtb off_dt_struct=", hdr.off_dt_struct);
                uart_log_hex_line("[A64] dtb off_dt_strings=", hdr.off_dt_strings);
                uart_log_hex_line("[A64] dtb off_mem_rsvmap=", hdr.off_mem_rsvmap);
                uart_log_hex_line("[A64] dtb version=", hdr.version as usize);
                uart_log_hex_line("[A64] dtb last_comp_version=", hdr.last_comp_version as usize);
                uart_log_hex_line("[A64] dtb size_dt_struct=", hdr.size_dt_struct);
                uart_log_hex_line("[A64] dtb size_dt_strings=", hdr.size_dt_strings);
            }
            None => uart_log_line("[A64] DTB header parse: invalid"),
        },
        None => uart_log_line("[A64] DTB header parse: no pointer"),
    }

    uart_log_line("[A64] init vectors...");
    crate::arch::init_trap_table();
    uart_log_line("[A64] init GIC...");
    crate::arch::init_interrupt_controller();
    uart_log_line("[A64] init timer...");
    crate::arch::init_timer();
    uart_log_line("[A64] enable interrupts...");
    crate::arch::enable_interrupts();
    crate::arch::aarch64_virt::self_test_sync_exception();
    uart_log_line("[A64] bring-up complete; starting shared scheduler");

    crate::quantum_scheduler::init();
    {
        let mut sched = crate::quantum_scheduler::scheduler().lock();
        if let Err(e) = sched.add_kernel_thread(
            shell_scheduler_task,
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
