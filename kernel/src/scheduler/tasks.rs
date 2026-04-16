// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

use crate::scheduler::process;
use crate::scheduler::process::ProcessPriority;
use crate::scheduler::slice_scheduler;
use crate::drivers::x86::vga;

#[no_mangle]
extern "C" fn shell_task() -> ! {
    vga::print_str("[TASK] Shell task entered\n");

    vga::print_str("[TASK] Enabling COM1 RX...\n");
    crate::serial::enable_rx_interrupts();
    crate::platform::idt_asm::unmask_irq(crate::platform::idt_asm::Irq::COM1);

    vga::print_str("[TASK] Enabling interrupts for scheduler...\n");
    crate::memory::asm_bindings::enable_interrupts();

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

    let int_state = unsafe { crate::scheduler::process_asm::get_interrupt_state() };
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
    crate::memory::asm_bindings::enable_interrupts();

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
    crate::memory::asm_bindings::enable_interrupts();

    // Verify interrupt delivery for network events
    let int_state = unsafe { crate::scheduler::process_asm::get_interrupt_state() };
    crate::serial_println!(
        "[NET] Interrupt state: {}",
        if int_state != 0 {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );

    crate::net::net_reactor::run();
}

pub fn start() -> ! {
    vga::print_str("[TASK] Starting scheduler setup...\n");
    crate::memory::asm_bindings::disable_interrupts();
    // Unmask essential IRQs now that we're about to start scheduling
    crate::platform::idt_asm::set_irq_masks(0xF8, 0x37);

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
        let mut sched = slice_scheduler::scheduler().lock();
        sched.add_kernel_thread(network_task, ProcessPriority::Normal)
    };
    match network_pid {
        Ok(pid) => {
            vga::print_str("[TASK] Network task registered (PID=");
            crate::shell::commands::print_u32(pid.0);
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
        let mut sched = slice_scheduler::scheduler().lock();
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
    crate::shell::commands::print_u32(shell_pid.0);
    vga::print_str(")\n");
    vga::print_str("[TASK] Shell task registered\n");

    // Keep worker disabled for now - test single task first
    // vga::print_str("[TASK] Adding worker task to scheduler...\n");
    // let _ = slice_scheduler::scheduler()
    //     .lock()
    //     .add_kernel_thread(worker_task, ProcessPriority::Normal);
    // vga::print_str("[TASK] Worker task registered\n");

    // Note: We now enable interrupts IN the tasks themselves, not before scheduler
    vga::print_str("[TASK] Ready to start scheduler (interrupts will be enabled in tasks)...\n");

    vga::print_str("[TASK] Entering scheduler...\n");
    crate::scheduler::slice_scheduler::SliceScheduler::start_scheduling();
}
