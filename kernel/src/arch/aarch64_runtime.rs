/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

fn uart_write_hex(value: usize) {
    let uart = super::aarch64_pl011::early_uart();
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
    let uart = super::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(msg);
    uart.write_str("\n");
}

fn uart_log_hex_line(prefix: &str, value: usize) {
    let uart = super::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str(prefix);
    uart_write_hex(value);
    uart.write_str("\n");
}

fn init_shared_runtime_step(name: &str, init: impl FnOnce()) {
    let uart = super::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str("[A64] init ");
    uart.write_str(name);
    uart.write_str("...\n");
    init();
}

fn init_shared_runtime() {
    init_shared_runtime_step("memory", crate::memory::init);
    init_shared_runtime_step("fs", crate::fs::init);
    init_shared_runtime_step("vfs", crate::fs::vfs::init);
    init_shared_runtime_step("persistence", crate::temporal::persistence::init);
    init_shared_runtime_step("temporal", crate::temporal::init);
    init_shared_runtime_step("ipc", crate::ipc::init);
    init_shared_runtime_step("registry", crate::services::registry::init);
    init_shared_runtime_step("capability", crate::capability::init);
    init_shared_runtime_step("security", crate::security::init);
    init_shared_runtime_step("process backend", crate::scheduler::process::init);
    init_shared_runtime_step("syscall core", crate::platform::syscall::init);
}

extern "C" fn shell_scheduler_task() -> ! {
    crate::arch::enable_interrupts();
    super::aarch64_virt::run_serial_shell()
}

extern "C" fn network_scheduler_task() -> ! {
    crate::arch::enable_interrupts();
    crate::serial_println!("[NET] AArch64 network task started");
    crate::net::net_reactor::run()
}

pub fn enter_runtime() -> ! {
    uart_log_line("[A64] Early bring-up path");
    uart_log_line("[A64] init early platform...");
    crate::arch::init_cpu_tables();

    let boot_info = crate::arch::boot_info();
    {
        let uart = super::aarch64_pl011::early_uart();
        uart.write_str("[A64] platform=");
        uart.write_str(crate::arch::platform_name());
        uart.write_str("\n");
    }
    uart_log_hex_line(
        "[A64] boot raw_info_ptr=",
        boot_info.raw_info_ptr.unwrap_or(0),
    );
    uart_log_hex_line("[A64] boot dtb_ptr=", boot_info.dtb_ptr.unwrap_or(0));

    uart_log_line("[A64] mmu init...");
    match crate::arch::mmu::init() {
        Ok(()) => {
            let uart = super::aarch64_pl011::early_uart();
            uart.write_str("[A64] mmu backend=");
            uart.write_str(crate::arch::mmu::backend_name());
            uart.write_str("\n");
        }
        Err(e) => {
            let uart = super::aarch64_pl011::early_uart();
            uart.write_str("[A64] mmu init failed: ");
            uart.write_str(e);
            uart.write_str("\n");
            crate::arch::halt_loop();
        }
    }

    init_shared_runtime();

    match boot_info.raw_info_ptr {
        Some(ptr) => match super::aarch64_dtb::parse_dtb_header(ptr) {
            Some(hdr) => {
                uart_log_line("[A64] DTB header parse: ok");
                uart_log_hex_line("[A64] dtb total_size=", hdr.total_size);
                uart_log_hex_line("[A64] dtb off_dt_struct=", hdr.off_dt_struct);
                uart_log_hex_line("[A64] dtb off_dt_strings=", hdr.off_dt_strings);
                uart_log_hex_line("[A64] dtb off_mem_rsvmap=", hdr.off_mem_rsvmap);
                uart_log_hex_line("[A64] dtb version=", hdr.version as usize);
                uart_log_hex_line(
                    "[A64] dtb last_comp_version=",
                    hdr.last_comp_version as usize,
                );
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
    super::aarch64_virt::self_test_sync_exception();
    let _scheduler_irq_flags = unsafe { crate::scheduler::scheduler_platform::irq_save_disable() };
    uart_log_line("[A64] bring-up complete; starting shared scheduler");

    crate::scheduler::quantum_scheduler::init();
    let launch = {
        let mut sched = crate::scheduler::quantum_scheduler::scheduler().lock();
        if super::aarch64_virt::discovered_virtio_net_base().is_some() {
            if let Err(e) = sched.add_kernel_thread(
                network_scheduler_task,
                crate::scheduler::process::ProcessPriority::Normal,
            ) {
                let uart = super::aarch64_pl011::early_uart();
                uart.write_str("[A64] scheduler add network task failed: ");
                uart.write_str(e);
                uart.write_str("\n");
                crate::arch::halt_loop();
            }
        }
        if let Err(e) = sched.add_kernel_thread(
            shell_scheduler_task,
            crate::scheduler::process::ProcessPriority::Normal,
        ) {
            let uart = super::aarch64_pl011::early_uart();
            uart.write_str("[A64] scheduler add shell task failed: ");
            uart.write_str(e);
            uart.write_str("\n");
            crate::arch::halt_loop();
        }
        sched.prepare_start_locked()
    };
    crate::scheduler::quantum_scheduler::QuantumScheduler::launch_prepared_context(
        launch.0, launch.1, launch.2,
    )
}
