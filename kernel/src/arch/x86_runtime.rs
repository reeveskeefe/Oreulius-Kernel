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

static mut SHELL_HISTORY: [[u8; 256]; 16] = [[0; 256]; 16];
static mut SHELL_HISTORY_LENS: [usize; 16] = [0; 16];
static mut SHELL_HISTORY_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// Job control — minimal POSIX-style ^Z / jobs / fg support.
//
// The shell has at most JOB_TABLE_MAX concurrent suspended jobs. Each entry
// records the PID and the command string that was running when ^Z was pressed.
// `fg` resumes the most-recently suspended job by moving it back to Ready in
// the scheduler. When no user process is running the foreground slot is None.
// ---------------------------------------------------------------------------
const JOB_TABLE_MAX: usize = 8;

#[derive(Copy, Clone)]
struct Job {
    pid: crate::process::Pid,
    cmd: [u8; 64],
    cmd_len: usize,
}

static mut JOB_TABLE: [Option<Job>; JOB_TABLE_MAX] = [None; JOB_TABLE_MAX];
static mut JOB_TABLE_LEN: usize = 0;
/// PID of the process currently running in the foreground (None = shell owns tty).
static mut FOREGROUND_PID: Option<crate::process::Pid> = None;

/// Add a stopped job to the job table. Returns the 1-based job number.
unsafe fn job_add(pid: crate::process::Pid, cmd: &[u8]) -> usize {
    let slot = if JOB_TABLE_LEN < JOB_TABLE_MAX {
        let s = JOB_TABLE_LEN;
        JOB_TABLE_LEN += 1;
        s
    } else {
        // Reclaim first empty slot (oldest job).
        JOB_TABLE.iter().position(|j| j.is_none()).unwrap_or(0)
    };
    let mut entry = Job {
        pid,
        cmd: [0u8; 64],
        cmd_len: 0,
    };
    let copy_len = cmd.len().min(63);
    entry.cmd[..copy_len].copy_from_slice(&cmd[..copy_len]);
    entry.cmd_len = copy_len;
    JOB_TABLE[slot] = Some(entry);
    slot + 1 // 1-based job number
}

/// Remove a job from the table by PID.
unsafe fn job_remove(pid: crate::process::Pid) {
    for slot in JOB_TABLE.iter_mut() {
        if let Some(j) = slot {
            if j.pid == pid {
                *slot = None;
                return;
            }
        }
    }
}

/// Print the current job table to the terminal.
pub fn print_jobs() {
    let mut any = false;
    unsafe {
        for (i, slot) in JOB_TABLE.iter().enumerate() {
            if let Some(j) = slot {
                any = true;
                crate::terminal::write_str("[");
                // Print job number
                let n = i + 1;
                let d = (b'0' + n as u8) as char;
                crate::terminal::write_char(d);
                crate::terminal::write_str("] Stopped  ");
                let cmd = core::str::from_utf8(&j.cmd[..j.cmd_len]).unwrap_or("?");
                crate::terminal::write_str(cmd);
                crate::terminal::write_char('\n');
            }
        }
    }
    if !any {
        crate::terminal::write_str("No jobs\n");
    }
}

/// Resume the most-recently suspended job (last slot).
pub fn fg_last_job() -> bool {
    unsafe {
        // Walk backwards to find the most-recently added job.
        for i in (0..JOB_TABLE_MAX).rev() {
            if let Some(j) = JOB_TABLE[i] {
                // Wake the process in the scheduler.
                {
                    let _ = crate::quantum_scheduler::scheduler()
                        .lock()
                        .wake_one(j.pid.0 as usize);
                    // If wake_one found no wait queue (process was just Blocked),
                    // re-enqueue it directly.
                    let still_blocked = {
                        let sched = crate::quantum_scheduler::scheduler().lock();
                        sched
                            .get_process_info(j.pid)
                            .map(|info| info.process.state == crate::process::ProcessState::Blocked)
                            .unwrap_or(false)
                    };
                    if still_blocked {
                        {
                            let mut sched2 = crate::quantum_scheduler::scheduler().lock();
                            if let Some(info_mut) = sched2.get_process_info_mut(j.pid) {
                                info_mut.process.state = crate::process::ProcessState::Ready;
                                let priority = info_mut.process.priority;
                                drop(sched2);
                                crate::quantum_scheduler::enqueue_ready_pid(j.pid, priority);
                            }
                        }
                    }
                }
                FOREGROUND_PID = Some(j.pid);
                let cmd = core::str::from_utf8(&j.cmd[..j.cmd_len]).unwrap_or("?");
                crate::terminal::write_str(cmd);
                crate::terminal::write_char('\n');
                JOB_TABLE[i] = None;
                return true;
            }
        }
    }
    false
}

const COM1_BASE: u16 = 0x3F8;
const COM_LSR: u16 = COM1_BASE + 5;
const COM_DATA: u16 = COM1_BASE;

fn serial_try_read_byte() -> Option<u8> {
    unsafe {
        let status = crate::asm_bindings::inb(COM_LSR);
        if (status & 0x01) == 0 {
            return None;
        }
        Some(crate::asm_bindings::inb(COM_DATA))
    }
}

fn drain_serial_input() {
    while serial_try_read_byte().is_some() {}
}

pub fn enter_runtime() -> ! {
    unsafe {
        crate::early_console_write_cell(8, 0x0252); // 'R' in green at position 8
    }

    crate::memory::init();

    unsafe {
        crate::early_console_write_cell(9, 0x024d); // 'M' in green - memory initialized
    }

    crate::vga::print_str("[MEMORY] Heap allocator initialized\n");
    let boot_info = crate::arch::boot_info();
    crate::vga::print_str("[ARCH] Platform: ");
    crate::vga::print_str(crate::arch::platform_name());
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] Protocol: ");
    match boot_info.protocol {
        crate::arch::BootProtocol::Unknown => crate::vga::print_str("unknown"),
        crate::arch::BootProtocol::Multiboot1 => crate::vga::print_str("multiboot1"),
        crate::arch::BootProtocol::Multiboot2 => crate::vga::print_str("multiboot2"),
    }
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] Cmdline ptr: 0x");
    crate::advanced_commands::print_hex(boot_info.cmdline_ptr.unwrap_or(0));
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] Cmdline: ");
    if let Some(cmdline) = boot_info.cmdline_str() {
        crate::vga::print_str(cmdline);
    } else {
        crate::vga::print_str("<none>");
    }
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] Loader ptr: 0x");
    crate::advanced_commands::print_hex(boot_info.boot_loader_name_ptr.unwrap_or(0));
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] Loader: ");
    if let Some(loader) = boot_info.boot_loader_name_str() {
        crate::vga::print_str(loader);
    } else {
        crate::vga::print_str("<none>");
    }
    crate::vga::print_str("\n");
    crate::vga::print_str("[BOOT] ACPI RSDP ptr: 0x");
    crate::advanced_commands::print_hex(boot_info.acpi_rsdp_ptr.unwrap_or(0));
    crate::vga::print_str("\n");
    crate::vga::print_str("[MMU] Backend: ");
    crate::vga::print_str(crate::arch::mmu::backend_name());
    crate::vga::print_str("\n");

    if crate::ensure_heap_available().is_some() {
        crate::vga::print_str("[MEMORY] Heap allocation test passed\n");
    }

    crate::vga::print_str("[GDT] Initializing GDT/TSS...\n");
    crate::arch::init_cpu_tables();
    crate::vga::print_str("[GDT] GDT loaded, TSS ready\n");

    crate::vga::print_str("[IDT] Initializing interrupt descriptor table...\n");
    crate::arch::init_trap_table();
    crate::vga::print_str("[IDT] IDT loaded\n");
    crate::vga::print_str("[IRQCTL] Initializing interrupt controller...\n");
    crate::arch::init_interrupt_controller();
    crate::vga::print_str("[IRQCTL] Controller initialized\n");

    crate::keyboard::init();

    crate::vga::print_str("[PAGING] Enabling virtual memory...\n");
    if let Err(e) = crate::arch::mmu::init() {
        crate::vga::print_str("[PAGING] Failed to initialize: ");
        crate::vga::print_str(e);
        crate::vga::print_str("\n");
        loop {
            core::hint::spin_loop();
        }
    }
    crate::vga::print_str("[PAGING] Virtual memory enabled (4KB pages, user/kernel separation)\n");
    crate::vga::print_str("[PAGING] Kernel root addr: 0x");
    crate::advanced_commands::print_hex(
        crate::arch::mmu::kernel_page_table_root_addr().unwrap_or(0),
    );
    crate::vga::print_str("\n");

    crate::cpu_security::init();
    if let Err(e) = crate::kpti::init() {
        crate::vga::print_str("[KPTI] Init failed: ");
        crate::vga::print_str(e);
        crate::vga::print_str("\n");
    }
    crate::memory_isolation::init();
    crate::enclave::init();

    crate::vga::print_str("[SYSCALL] Setting up system call interface...\n");
    crate::syscall::init();
    crate::vga::print_str("[SYSCALL] INT 0x80 handler registered\n");

    crate::vga::print_str("[DEBUG] About to initialize WASM runtime...\n");
    crate::vga::print_str("[WASM] Runtime initialized\n");

    crate::vga::print_str("[DEBUG] About to init fs...\n");
    crate::fs::init();
    crate::vga::print_str("[DEBUG] About to init vfs...\n");
    crate::vfs::init();
    crate::vga::print_str("[DEBUG] About to init persistence...\n");
    crate::persistence::init();
    match crate::vfs::recover_from_persistence() {
        Ok(()) => crate::vga::print_str("[VFS] Recovery check complete\n"),
        Err(e) => {
            crate::vga::print_str("[VFS] Recovery skipped: ");
            crate::vga::print_str(e);
            crate::vga::print_str("\n");
        }
    }
    crate::vga::print_str("[DEBUG] About to init temporal...\n");
    crate::temporal::init();
    crate::vga::print_str("[DEBUG] About to init ipc...\n");
    crate::ipc::init();
    crate::vga::print_str("[DEBUG] About to init registry...\n");
    crate::registry::init();
    crate::vga::print_str("[DEBUG] About to init process...\n");
    crate::process::init();
    crate::vga::print_str("[DEBUG] About to init wasm...\n");
    crate::wasm::init();

    crate::vga::print_str("[SECURITY] Initializing security manager...\n");
    crate::security::init();
    crate::vga::print_str("[SECURITY] Audit logging enabled\n");
    crate::capnet::init();
    crate::capnet::offline_certificate::assert_certificate_valid();
    crate::vga::print_str("[CAPNET] Peer token subsystem initialized (spectral certificate OK)\n");

    crate::vga::print_str("[CAPABILITY] Initializing capability manager...\n");
    crate::capability::init();
    crate::vga::print_str("[CAPABILITY] Authority model enabled\n");

    crate::vga::print_str("[CONSOLE] Initializing console service...\n");
    crate::console_service::init();
    crate::vga::print_str("[CONSOLE] Capability-based I/O ready\n");

    crate::vga::print_str("[DEBUG] About to initialize timer...\n");
    crate::vga::print_str("[TIMER] Initializing PIT (100 Hz)...\n");
    crate::arch::init_timer();
    crate::vga::print_str("[SCHED] Preemptive scheduler ready\n");

    crate::vga::print_str("[IRQ] Enabling interrupts...\n");
    crate::arch::enable_interrupts();
    crate::vga::print_str("[IRQ] Interrupts enabled\n");

    crate::vga::print_str("[DEBUG] Timer initialized successfully\n");
    crate::vga::print_str("[PCI] Scanning for devices...\n");
    let mut pci_scanner = crate::pci::PciScanner::new();
    pci_scanner.scan();

    if let Some(blk_device) = pci_scanner.find_virtio_block() {
        crate::vga::print_str("[BLOCK] VirtIO block device detected\n");
        if let Err(e) = crate::virtio_blk::init(blk_device) {
            crate::vga::print_str("[BLOCK] Init failed: ");
            crate::vga::print_str(e);
            crate::vga::print_str("\n");
        } else {
            crate::vga::print_str("[BLOCK] VirtIO block ready\n");
            crate::persistence::init();
            match crate::vfs::recover_from_persistence() {
                Ok(()) => crate::vga::print_str("[VFS] Durable recovery complete\n"),
                Err(e) => {
                    crate::vga::print_str("[VFS] Durable recovery skipped: ");
                    crate::vga::print_str(e);
                    crate::vga::print_str("\n");
                }
            }
            match crate::temporal::recover_from_persistence() {
                Ok(()) => crate::vga::print_str("[TEMPORAL] Recovery check complete\n"),
                Err(e) => {
                    crate::vga::print_str("[TEMPORAL] Recovery skipped: ");
                    crate::vga::print_str(e);
                    crate::vga::print_str("\n");
                }
            }
        }
    } else {
        crate::vga::print_str("[BLOCK] No VirtIO block device found\n");
    }

    if let Some(_wifi_device) = pci_scanner.find_wifi_device() {
        crate::vga::print_str("[NET] WiFi device detected (init disabled)\n");
    } else if let Some(eth_device) = pci_scanner.find_ethernet_device() {
        crate::vga::print_str("[NET] Ethernet device detected, initializing...\n");

        let bar0 = unsafe { eth_device.read_bar(0) };
        if bar0 != 0 {
            crate::vga::print_str("[NET] Mapping MMIO region...\n");
            let phys_base = (bar0 & !0xF) as usize;
            let size = 128 * 1024;

            crate::vga::print_str("MMIO Base: 0x");
            crate::advanced_commands::print_hex(phys_base);
            crate::vga::print_str("\n");

            if let Some(ref mut space) = *crate::paging::kernel_space().lock() {
                for offset in (0..size).step_by(crate::paging::PAGE_SIZE) {
                    let addr = phys_base + offset;
                    let _ = space.map_page(addr, addr, true, false);
                }
            }

            if let Some(ref mut space) = *crate::paging::kernel_space().lock() {
                if space.is_mapped(phys_base) {
                    crate::vga::print_str("MMIO Base Mapped successfully\n");
                } else {
                    crate::vga::print_str("MMIO Base failed to map\n");
                }
            }
        }

        if crate::e1000::init(eth_device).is_ok() {
            crate::vga::print_str("[NET] E1000 initialized - Ready for DNS/ARP/UDP\n");
        } else {
            crate::vga::print_str("[NET] E1000 init failed\n");
        }
    } else if let Some(rtl_device) = pci_scanner.find_rtl8139() {
        crate::vga::print_str("[NET] RTL8139 detected, initializing...\n");
        crate::rtl8139::init(&[rtl_device]);
        crate::vga::print_str("[NET] RTL8139 ready\n");
    } else {
        crate::vga::print_str("[NET] No network device found\n");
    }

    {
        let usb_pci = pci_scanner.find_all_usb_controllers();
        let non_empty = usb_pci.iter().any(|x| x.is_some());
        if non_empty {
            crate::vga::print_str("[USB] Initializing USB host controllers...\n");
            crate::usb::init(&usb_pci);
            crate::vga::print_str("[USB] USB ready\n");
            crate::bluetooth::init();
        } else {
            crate::vga::print_str("[USB] No USB controllers found\n");
        }
    }

    {
        let nvme_pci = pci_scanner.find_all_nvme_controllers();
        let mut nvme_flat: [crate::pci::PciDevice; 4] = unsafe { core::mem::zeroed() };
        let mut nvme_count = 0usize;
        for opt in nvme_pci.iter() {
            if let Some(d) = opt {
                nvme_flat[nvme_count] = *d;
                nvme_count += 1;
            }
        }
        if nvme_count > 0 {
            crate::vga::print_str("[NVME] Initializing NVMe controller...\n");
            crate::nvme::init(&nvme_flat[..nvme_count]);
            crate::vga::print_str("[NVME] NVMe init done\n");
        }
    }

    if let Some(audio_device) = pci_scanner.find_audio_controller() {
        crate::vga::print_str("[AUDIO] Initializing audio controller...\n");
        crate::audio::init(&[audio_device]);
        crate::vga::print_str("[AUDIO] Audio ready\n");
    }

    {
        let mb2_ptr = boot_info.raw_info_ptr.unwrap_or(0) as u32;
        crate::vga::print_str("[GPU] Initializing framebuffer...\n");
        crate::gpu_support::init(mb2_ptr);
        crate::vga::print_str("[GPU] Framebuffer ready\n");

        let (w, h) = crate::gpu_support::active_dimensions();
        crate::compositor::init(w, h);
    }

    crate::vga::print_str("[MOUSE] Enabling PS/2 auxiliary port...\n");
    crate::mouse::init();
    crate::vga::print_str("[MOUSE] PS/2 mouse ready\n");

    crate::input::init();
    crate::vga::print_str("[INPUT] Unified input queue ready\n");

    crate::vga::print_str("\n[INIT] Initialization complete, starting scheduler...\n");
    crate::tasks::start();
}

pub fn shell_loop() -> ! {
    crate::vga::print_str("[SHELL] Starting shell loop...\n");
    crate::terminal::clear_screen();
    crate::vga::print_str("[SHELL] Screen cleared\n");
    crate::terminal::write_str("Oreulia OS\n");
    crate::vga::print_str("[SHELL] Banner printed\n");
    crate::terminal::write_str("Type 'help' for commands.\n\n");
    drain_serial_input();
    crate::terminal::write_str("> ");

    let mut input: [u8; 256] = [0; 256];
    let mut len: usize = 0;
    let mut cursor: usize = 0;
    let mut history_index: usize = unsafe { SHELL_HISTORY_COUNT };
    let mut prompt_pos = crate::terminal::cursor_position();
    let mut _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);

    let mut loops: usize = 0;
    const HEARTBEAT: &[u8] = b"|/-\\";

    loop {
        core::hint::spin_loop();
        crate::wasm::drain_pending_spawns();
        crate::wasm::tick_background_threads();

        loops = loops.wrapping_add(1);
        if loops % 10000 == 0 {
            unsafe {
                let vga = 0xB8000 as *mut u16;
                let pos = 24 * 80 + 79;
                let char_idx = (loops / 10000) % 4;
                *vga.add(pos) = 0x0F00 | (HEARTBEAT[char_idx] as u16);

                let irq_cnt = crate::idt_asm::get_interrupt_count(33);
                let hex = b"0123456789ABCDEF";
                *vga.add(pos - 8) = 0x0F49;
                *vga.add(pos - 7) = 0x0F3A;
                *vga.add(pos - 6) = 0x0F00 | (hex[((irq_cnt >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 5) = 0x0F00 | (hex[(irq_cnt & 0xF) as usize] as u16);

                let buf_len = crate::keyboard::event_buffer_len();
                *vga.add(pos - 18) = 0x0F42;
                *vga.add(pos - 17) = 0x0F3A;
                *vga.add(pos - 16) = 0x0F00 | (hex[((buf_len >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 15) = 0x0F00 | (hex[(buf_len & 0xF) as usize] as u16);

                let sc = crate::keyboard::get_last_scancode();
                *vga.add(pos - 28) = 0x0F53;
                *vga.add(pos - 27) = 0x0F3A;
                *vga.add(pos - 26) = 0x0F00 | (hex[((sc >> 4) & 0xF) as usize] as u16);
                *vga.add(pos - 25) = 0x0F00 | (hex[(sc & 0xF) as usize] as u16);

                let row_offset = 24 * 80;
                let dropped = crate::keyboard::get_dropped_packets();
                *vga.add(row_offset + 20) = 0x0F44;
                *vga.add(row_offset + 21) = 0x0F3A;
                *vga.add(row_offset + 22) = 0x0F00 | (hex[((dropped >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 23) = 0x0F00 | (hex[(dropped & 0xF) as usize] as u16);

                let (pushed, _popped, none, errors) = crate::keyboard::get_event_stats();
                *vga.add(row_offset + 30) = 0x0F50;
                *vga.add(row_offset + 31) = 0x0F3A;
                *vga.add(row_offset + 32) = 0x0F00 | (hex[((pushed >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 33) = 0x0F00 | (hex[(pushed & 0xF) as usize] as u16);

                *vga.add(row_offset + 35) = 0x0F4E;
                *vga.add(row_offset + 36) = 0x0F3A;
                *vga.add(row_offset + 37) = 0x0F00 | (hex[((none >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 38) = 0x0F00 | (hex[(none & 0xF) as usize] as u16);

                *vga.add(row_offset + 40) = 0x0F45;
                *vga.add(row_offset + 41) = 0x0F3A;
                *vga.add(row_offset + 42) = 0x0F00 | (hex[((errors >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 43) = 0x0F00 | (hex[(errors & 0xF) as usize] as u16);
            }
        }

        if let Some(byte) = serial_try_read_byte() {
            match byte {
                b'\r' | b'\n' => {
                    crate::terminal::write_char('\n');
                    let line = core::str::from_utf8(&input[..len])
                        .unwrap_or("")
                        .trim_start_matches('?');
                    if len > 0 {
                        unsafe {
                            if SHELL_HISTORY_COUNT < 16 {
                                SHELL_HISTORY[SHELL_HISTORY_COUNT] = input;
                                SHELL_HISTORY_LENS[SHELL_HISTORY_COUNT] = len;
                                SHELL_HISTORY_COUNT += 1;
                            } else {
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
                    crate::commands::execute(line);
                    len = 0;
                    cursor = 0;
                    input = [0; 256];
                    drain_serial_input();
                    crate::terminal::write_str("> ");
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                8 | 127 => {
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
                3 => {
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    crate::terminal::clear_line_from_cursor();
                    crate::terminal::write_str("^C\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    drain_serial_input();
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                26 => {
                    // ^Z — suspend foreground process into job table
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    crate::terminal::clear_line_from_cursor();
                    crate::terminal::write_str("^Z\n");
                    let suspended = unsafe {
                        if let Some(fg_pid) = FOREGROUND_PID.take() {
                            // Block the foreground process.
                            let mut sched = crate::quantum_scheduler::scheduler().lock();
                            if let Some(info) = sched.get_process_info_mut(fg_pid) {
                                info.process.state = crate::process::ProcessState::Blocked;
                            }
                            drop(sched);
                            let job_num = job_add(fg_pid, &input[..len]);
                            Some((fg_pid, job_num))
                        } else {
                            None
                        }
                    };
                    if let Some((_pid, jnum)) = suspended {
                        crate::terminal::write_str("[Stopped] job ");
                        let d = (b'0' + jnum as u8) as char;
                        crate::terminal::write_char(d);
                        crate::terminal::write_char('\n');
                    } else {
                        crate::terminal::write_str("[No foreground process]\n");
                    }
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    drain_serial_input();
                    crate::terminal::write_str("> ");
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                b if (0x20..=0x7e).contains(&b) && len < input.len() - 1 => {
                    for i in (cursor..len).rev() {
                        input[i + 1] = input[i];
                    }
                    input[cursor] = b;
                    len += 1;
                    cursor += 1;
                    redraw_line(&input, len, cursor, prompt_pos);
                }
                _ => {}
            }
        }

        if let Some(ev) = crate::keyboard::poll_event() {
            match ev {
                crate::keyboard::KeyEvent::AltFn(n) => {
                    crate::terminal::switch_terminal((n.saturating_sub(1)) as usize);
                    crate::terminal::write_str("\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    drain_serial_input();
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Enter => {
                    crate::terminal::write_char('\n');
                    let line = core::str::from_utf8(&input[..len])
                        .unwrap_or("")
                        .trim_start_matches('?');
                    if len > 0 {
                        unsafe {
                            if SHELL_HISTORY_COUNT < 16 {
                                SHELL_HISTORY[SHELL_HISTORY_COUNT] = input;
                                SHELL_HISTORY_LENS[SHELL_HISTORY_COUNT] = len;
                                SHELL_HISTORY_COUNT += 1;
                            } else {
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
                    crate::commands::execute(line);
                    len = 0;
                    cursor = 0;
                    input = [0; 256];
                    drain_serial_input();
                    crate::terminal::write_str("> ");
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Backspace => {
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
                crate::keyboard::KeyEvent::Ctrl('a') => {
                    cursor = 0;
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                }
                crate::keyboard::KeyEvent::Ctrl('e') => {
                    cursor = len;
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                crate::keyboard::KeyEvent::Ctrl('k') => {
                    for slot in input.iter_mut().take(len).skip(cursor) {
                        *slot = 0;
                    }
                    len = cursor;
                    redraw_line(&input, len, cursor, prompt_pos);
                }
                crate::keyboard::KeyEvent::Ctrl('u') => {
                    let mut i = 0;
                    while cursor + i < len {
                        input[i] = input[cursor + i];
                        i += 1;
                    }
                    for slot in input.iter_mut().take(len).skip(i) {
                        *slot = 0;
                    }
                    len -= cursor;
                    cursor = 0;
                    redraw_line(&input, len, cursor, prompt_pos);
                }
                crate::keyboard::KeyEvent::Ctrl('c') => {
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    crate::terminal::clear_line_from_cursor();
                    crate::terminal::write_str("^C\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    drain_serial_input();
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Ctrl('z') => {
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    crate::terminal::clear_line_from_cursor();
                    crate::terminal::write_str("^Z\n");
                    let suspended = unsafe {
                        if let Some(fg_pid) = FOREGROUND_PID.take() {
                            let mut sched = crate::quantum_scheduler::scheduler().lock();
                            if let Some(info) = sched.get_process_info_mut(fg_pid) {
                                info.process.state = crate::process::ProcessState::Blocked;
                            }
                            drop(sched);
                            let job_num = job_add(fg_pid, &input[..len]);
                            Some((fg_pid, job_num))
                        } else {
                            None
                        }
                    };
                    if let Some((_pid, jnum)) = suspended {
                        crate::terminal::write_str("[Stopped] job ");
                        let d = (b'0' + jnum as u8) as char;
                        crate::terminal::write_char(d);
                        crate::terminal::write_char('\n');
                    } else {
                        crate::terminal::write_str("[No foreground process]\n");
                    }
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    drain_serial_input();
                    crate::terminal::write_str("> ");
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Ctrl(c) => {
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
                crate::keyboard::KeyEvent::Left => {
                    if cursor > 0 {
                        cursor -= 1;
                        crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                    }
                }
                crate::keyboard::KeyEvent::Right => {
                    if cursor < len {
                        cursor += 1;
                        crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                    }
                }
                crate::keyboard::KeyEvent::Home => {
                    cursor = 0;
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                crate::keyboard::KeyEvent::End => {
                    cursor = len;
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
                }
                crate::keyboard::KeyEvent::Up => {
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
                crate::keyboard::KeyEvent::Down => unsafe {
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
                crate::keyboard::KeyEvent::AltChar(c) => {
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
                crate::keyboard::KeyEvent::Char(c) => {
                    unsafe {
                        crate::early_console_write_cell(120, 0x0E2A);
                    }

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
                _ => {}
            }
        }

        crate::quantum_scheduler::yield_now();
    }
}

fn redraw_line(input: &[u8; 256], len: usize, cursor: usize, prompt_pos: (usize, usize)) {
    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
    crate::terminal::clear_line_from_cursor();
    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
    crate::terminal::write_str_no_serial(line);
    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
}
