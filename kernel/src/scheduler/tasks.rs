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

use crate::process;
use crate::process::ProcessPriority;
use crate::quantum_scheduler;
use crate::vga;

#[no_mangle]
extern "C" fn shell_task() -> ! {
    vga::print_str("[TASK] Shell task entered\n");

    // CRITICAL: Enable interrupts NOW that task is safely running
    // This must be the FIRST operation to prevent race condition where
    // timer interrupt fires during trampoline execution before stack is ready

    // Enhanced interrupt state management with verification
    crate::asm_bindings::enable_interrupts();

    // Verify interrupts are actually enabled by reading EFLAGS IF bit
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

    // Write marker to confirm we reached the task
    // unsafe {
    //     let vga = 0xB8000 as *mut u16;
    //     *vga = 0x0A40; // '@' green - task started!
    // }

    // Unmask IRQs for keyboard and timer
    vga::print_str("[TASK] Unmasking IRQs...\n");
    crate::idt_asm::set_irq_masks(0xF8, 0x37);

    // Enable interrupts for preemptive scheduling
    vga::print_str("[TASK] Enabling interrupts for scheduler...\n");
    crate::asm_bindings::enable_interrupts();

    // Verify interrupt state after enabling
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

    // Init process is created in process::init(); reuse it for shell task.
    let init_pid = match process::current_pid() {
        Some(pid) => {
            vga::print_str("[TASK] Found existing init PID=");
            crate::commands::print_u32(pid.0);
            vga::print_str("\n");
            pid
        }
        None => {
            vga::print_str("[TASK] Creating new init process...\n");
            // Fallback: create init process if missing
            let pid = process::process_manager()
                .spawn("init", None)
                .unwrap_or(process::Pid(1));
            vga::print_str("[TASK] Created init PID=");
            crate::commands::print_u32(pid.0);
            vga::print_str("\n");
            pid
        }
    };

    // Validate that init process exists before starting scheduler
    vga::print_str("[TASK] Validating init process (PID=");
    crate::commands::print_u32(init_pid.0);
    vga::print_str(")...\n");

    let pm = process::process_manager();
    if let Some(init_proc) = pm.get(init_pid) {
        vga::print_str("[TASK] Init process validated: name='");
        vga::print_str(init_proc.name_str());
        vga::print_str("', state=");
        match init_proc.state {
            process::ProcessState::Ready => vga::print_str("Ready"),
            process::ProcessState::Running => vga::print_str("Running"),
            process::ProcessState::Blocked => vga::print_str("Blocked"),
            process::ProcessState::Terminated => vga::print_str("Terminated"),
            process::ProcessState::WaitingOnChannel => vga::print_str("WaitingOnChannel"),
        }
        vga::print_str("\n");
    } else {
        vga::print_str("[TASK] WARNING: Init process not found in process table!\n");
    }

    vga::print_str("[TASK] Getting init process...\n");
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
            vga::print_str("[TASK] WARNING: failed to add network task: ");
            vga::print_str(e);
            vga::print_str("\n");
            crate::serial_println!("[TASK] WARNING: failed to add network task: {}", e);
        }
    }

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
