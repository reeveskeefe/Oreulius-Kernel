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

use crate::process;
use crate::process::ProcessPriority;
use crate::quantum_scheduler;
use crate::vga;

#[no_mangle]
extern "C" fn shell_task() -> ! {
    vga::print_str("[TASK] Shell task entered\n");

    vga::print_str("[TASK] Enabling COM1 RX...\n");
    crate::serial::enable_rx_interrupts();
    crate::idt_asm::unmask_irq(crate::idt_asm::Irq::COM1);

    vga::print_str("[TASK] Enabling interrupts for scheduler...\n");
    crate::asm_bindings::enable_interrupts();

    #[cfg(target_arch = "x86")]
    {
        let eflags: u32;
        unsafe {
            core::arch::asm!("pushfd", "pop {}", out(reg) eflags, options(nomem, nostack));
        }
        if (eflags & 0x200) != 0 {
            vga::print_str("[TASK] Shell interrupts verified enabled\n");
        } else {
            vga::print_str("[TASK] ERROR: Failed to enable interrupts!\n");
        }
    }

    let int_state = unsafe { crate::process_asm::get_interrupt_state() };
    if int_state != 0 {
        vga::print_str("[TASK] Scheduler interrupts verified active\n");
    } else {
        vga::print_str("[TASK] WARNING: Interrupt state check failed\n");
    }

    vga::print_str("[TASK] Interrupts enabled, starting shell...\n");

    // Start the actual shell loop
    crate::arch::shell_loop();
}

#[no_mangle]
extern "C" fn worker_task() -> ! {
    // Write marker to confirm worker started
    unsafe {
        let vga = 0xB8000 as *mut u16;
        *(vga.add(1)) = 0x0B57; // 'W' cyan - worker started
    }

    // Enable interrupts for this task too
    crate::asm_bindings::enable_interrupts();

    // Log interrupt state for worker task
    crate::serial_println!("[WORKER] Interrupts enabled for background task");

    loop {
        // Simple background task to demonstrate preemption
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        vga::print_str(".");
    }
}

#[no_mangle]
extern "C" fn network_task() -> ! {
    crate::serial_println!("[NET] Network task started");

    // Enable interrupts for network processing
    crate::asm_bindings::enable_interrupts();

    // Verify interrupt delivery for network events
    let int_state = unsafe { crate::process_asm::get_interrupt_state() };
    crate::serial_println!(
        "[NET] Interrupt state: {}",
        if int_state != 0 {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );

    crate::net_reactor::run();
}

pub fn start() -> ! {
    vga::print_str("[TASK] Starting scheduler setup...\n");
    crate::asm_bindings::disable_interrupts();
    // Unmask essential IRQs now that we're about to start scheduling
    crate::idt_asm::set_irq_masks(0xF8, 0x37);

    vga::print_str("[TASK] Getting init PID...\n");
    let init_pid = process::Pid(1);
    if let Err(e) = process::validate_kernel_bootstrap() {
        vga::print_str("[TASK] FATAL: kernel bootstrap invalid: ");
        vga::print_str(e);
        vga::print_str("\n");
        crate::serial_println!("[TASK] FATAL: kernel bootstrap invalid: {}", e);
        loop {
            unsafe { core::arch::asm!("hlt") };
        }
    }
    {
        let pm = process::process_manager();
        let Some(init_proc) = pm.get(init_pid) else {
            vga::print_str("[TASK] FATAL: shared process backend missing PID=1\n");
            crate::serial_println!("[TASK] FATAL: shared process backend missing PID=1");
            loop {
                unsafe { core::arch::asm!("hlt") };
            }
        };

        if process::current_pid() != Some(init_pid) {
            if let Err(e) = process::set_current_runtime_pid(init_pid) {
                vga::print_str("[TASK] FATAL: failed to sync init PID=1: ");
                vga::print_str(e);
                vga::print_str("\n");
                crate::serial_println!("[TASK] FATAL: failed to sync init PID=1: {}", e);
                loop {
                    unsafe { core::arch::asm!("hlt") };
                }
            }
        }

        vga::print_str("[TASK] Init process validated: name='");
        vga::print_str(init_proc.name_str());
        vga::print_str("'\n");
    }

    vga::print_str("[TASK] Adding network task to scheduler...\n");
    let network_pid = {
        let mut sched = quantum_scheduler::scheduler().lock();
        sched.add_kernel_thread(network_task, ProcessPriority::Normal)
    };
    match network_pid {
        Ok(pid) => {
            vga::print_str("[TASK] Network task registered (PID=");
            crate::commands::print_u32(pid.0);
            vga::print_str(")\n");
        }
        Err(e) => {
            vga::print_str("[TASK] FATAL: failed to add network task: ");
            vga::print_str(e);
            vga::print_str("\n");
            crate::serial_println!("[TASK] FATAL: failed to add network task: {}", e);
            loop {
                unsafe { core::arch::asm!("hlt") };
            }
        }
    }

    vga::print_str("[TASK] Adding shell task to scheduler...\n");
    let shell_pid = {
        let mut sched = quantum_scheduler::scheduler().lock();
        sched.add_kernel_thread(shell_task, ProcessPriority::Normal)
    };
    let shell_pid = match shell_pid {
        Ok(pid) => pid,
        Err(e) => {
            vga::print_str("[TASK] FATAL: failed to add shell task: ");
            vga::print_str(e);
            vga::print_str("\n");
            crate::serial_println!("[TASK] FATAL: failed to add shell task: {}", e);
            loop {
                unsafe { core::arch::asm!("hlt") };
            }
        }
    };
    vga::print_str("[TASK] Shell task added successfully (PID=");
    crate::commands::print_u32(shell_pid.0);
    vga::print_str(")\n");
    vga::print_str("[TASK] Shell task registered\n");

    // Keep worker disabled for now - test single task first
    // vga::print_str("[TASK] Adding worker task to scheduler...\n");
    // let _ = quantum_scheduler::scheduler()
    //     .lock()
    //     .add_kernel_thread(worker_task, ProcessPriority::Normal);
    // vga::print_str("[TASK] Worker task registered\n");

    // Note: We now enable interrupts IN the tasks themselves, not before scheduler
    vga::print_str("[TASK] Ready to start scheduler (interrupts will be enabled in tasks)...\n");

    vga::print_str("[TASK] Entering scheduler...\n");
    crate::quantum_scheduler::QuantumScheduler::start_scheduling();
}
