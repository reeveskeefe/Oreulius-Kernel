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

pub fn enter_runtime() -> ! {
    unsafe {
        let vga = 0xb8000 as *mut u16;
        *(vga.add(8)) = 0x0252; // 'R' in green at position 8 (after "BOOTCALL")
    }

    crate::memory::init();

    unsafe {
        let vga = 0xb8000 as *mut u16;
        *(vga.add(9)) = 0x024d; // 'M' in green - memory initialized
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

        let (w, h) = {
            let fb = crate::gpu_support::GPU_FB.lock();
            fb.as_ref().map(|f| (f.width(), f.height())).unwrap_or((1024, 768))
        };
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
                *vga.add(row_offset + 22) =
                    0x0F00 | (hex[((dropped >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 23) = 0x0F00 | (hex[(dropped & 0xF) as usize] as u16);

                let (pushed, _popped, none, errors) = crate::keyboard::get_event_stats();
                *vga.add(row_offset + 30) = 0x0F50;
                *vga.add(row_offset + 31) = 0x0F3A;
                *vga.add(row_offset + 32) =
                    0x0F00 | (hex[((pushed >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 33) = 0x0F00 | (hex[(pushed & 0xF) as usize] as u16);

                *vga.add(row_offset + 35) = 0x0F4E;
                *vga.add(row_offset + 36) = 0x0F3A;
                *vga.add(row_offset + 37) =
                    0x0F00 | (hex[((none >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 38) = 0x0F00 | (hex[(none & 0xF) as usize] as u16);

                *vga.add(row_offset + 40) = 0x0F45;
                *vga.add(row_offset + 41) = 0x0F3A;
                *vga.add(row_offset + 42) =
                    0x0F00 | (hex[((errors >> 4) & 0xF) as usize] as u16);
                *vga.add(row_offset + 43) = 0x0F00 | (hex[(errors & 0xF) as usize] as u16);
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
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Enter => {
                    crate::terminal::write_char('\n');
                    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
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
                    prompt_pos = crate::terminal::cursor_position();
                    _max_len = crate::vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                crate::keyboard::KeyEvent::Ctrl('z') => {
                    crate::terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    crate::terminal::clear_line_from_cursor();
                    crate::terminal::write_str("^Z\nJob control not implemented\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
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
                        let vga_buffer = 0xb8000 as *mut u8;
                        *vga_buffer.offset(240) = b'*';
                        *vga_buffer.offset(241) = 0x0E;
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
