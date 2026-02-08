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
    unsafe { crate::asm_bindings::enable_interrupts(); }
    
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
    unsafe { crate::asm_bindings::enable_interrupts(); }
    vga::print_str("[TASK] Interrupts enabled, starting shell...\n");
    
    // Start the actual shell loop
    crate::shell_loop();
}

#[no_mangle]
extern "C" fn worker_task() -> ! {
    // Write marker to confirm worker started
    unsafe {
        let vga = 0xB8000 as *mut u16;
        *(vga.add(1)) = 0x0B57; // 'W' cyan - worker started
    }
    
    // Enable interrupts for this task too
    unsafe { crate::asm_bindings::enable_interrupts(); }
    
    loop {
        // Simple background task to demonstrate preemption
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        vga::print_str(".");
    }
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
            vga::print_str("[TASK] Found existing init PID\n");
            pid
        }
        None => {
            vga::print_str("[TASK] Creating new init process...\n");
            // Fallback: create init process if missing
            process::process_manager()
                .spawn("init", None)
                .unwrap_or(process::Pid(1))
        }
    };
    
    vga::print_str("[TASK] Getting init process...\n");
    vga::print_str("[TASK] Adding shell task to scheduler...\n");
    let _ = quantum_scheduler::scheduler()
        .lock()
        .add_kernel_thread(shell_task, ProcessPriority::Normal);
    vga::print_str("[TASK] Shell task added successfully\n");
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
