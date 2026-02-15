#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
use alloc::boxed::Box;
// use alloc::vec::Vec;
// use alloc::string::String;

pub mod advanced_commands;
pub mod acpi_asm;
pub mod asm_bindings;
pub mod capability;
pub mod commands;
pub mod console_service;
pub mod cpu_security;
pub mod dma_asm;
pub mod disk;
pub mod elf;
pub mod gdt;
pub mod e1000;
pub mod fs;
pub mod hardened_allocator;
pub mod idt_asm;
pub mod ipc;
pub mod keyboard;
pub mod memory;
pub mod memopt_asm;
pub mod net;
pub mod net_reactor;
pub mod netstack;
pub mod paging;
pub mod pci;
pub mod persistence;
pub mod pit;
pub mod process;
pub mod process_asm;
pub mod quantum_scheduler;
pub mod registry;
pub mod replay;
pub mod scheduler;
pub mod security;
pub mod serial;
pub mod syscall;
pub mod terminal;
pub mod vga;
pub mod vfs;
pub mod virtio_blk;
pub mod wasm_jit;
pub mod wasm;
pub mod wifi;
pub mod kpti;
pub mod usermode;
pub mod tasks;

/// Helper to ensure Box is available for heap allocations across modules
#[inline]
pub fn ensure_heap_available() -> Option<Box<u32>> {
    // Try to allocate on heap to verify allocator is working
    Some(Box::new(42))
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
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

    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
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
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
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
    
    // Test heap allocation
    if ensure_heap_available().is_some() {
        vga::print_str("[MEMORY] Heap allocation test passed\n");
    }
    
    // Initialize GDT/TSS for ring transitions
    vga::print_str("[GDT] Initializing GDT/TSS...\n");
    gdt::init();
    vga::print_str("[GDT] GDT loaded, TSS ready\n");
    
    // Initialize IDT and PIC before enabling paging/interrupts
    vga::print_str("[IDT] Initializing interrupt descriptor table...\n");
    idt_asm::init();
    vga::print_str("[IDT] IDT loaded, PIC remapped\n");

    // Initialize Keyboard (specifically PS/2 configuration)
    keyboard::init();
    
    // Initialize virtual memory management (must be early, after physical memory)
    vga::print_str("[PAGING] Enabling virtual memory...\n");
    if let Err(e) = paging::init() {
        vga::print_str("[PAGING] Failed to initialize: ");
        vga::print_str(e);
        vga::print_str("\n");
        loop { core::hint::spin_loop(); }
    }
    vga::print_str("[PAGING] Virtual memory enabled (4KB pages, user/kernel separation)\n");

    // Enable CPU hardening features (SMEP/SMAP) if supported.
    cpu_security::init();
    if let Err(e) = kpti::init() {
        vga::print_str("[KPTI] Init failed: ");
        vga::print_str(e);
        vga::print_str("\n");
    }
    
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
    vga::print_str("[DEBUG] About to init ipc...\n");
    ipc::init();
    vga::print_str("[DEBUG] About to init registry...\n");
    registry::init();
    vga::print_str("[DEBUG] About to init process...\n");
    process::init();  // Creates init process (PID 1)
    vga::print_str("[DEBUG] About to init wasm...\n");
    wasm::init();     // Initialize WASM runtime
    
    // Initialize security subsystem
    vga::print_str("[SECURITY] Initializing security manager...\n");
    security::init();
    vga::print_str("[SECURITY] Audit logging enabled\n");
    
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
    pit::init();
    vga::print_str("[SCHED] Preemptive scheduler ready\n");
    
    // Enable CPU interrupts now that IDT/PIC/PIT are configured
    vga::print_str("[IRQ] Enabling interrupts...\n");
    asm_bindings::enable_interrupts();
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

static mut SHELL_HISTORY: [[u8; 256]; 16] = [[0; 256]; 16];
static mut SHELL_HISTORY_LENS: [usize; 16] = [0; 16];
static mut SHELL_HISTORY_COUNT: usize = 0;

/// Shell loop (runs as init process)
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
                                    SHELL_HISTORY[i-1] = SHELL_HISTORY[i];
                                    SHELL_HISTORY_LENS[i-1] = SHELL_HISTORY_LENS[i];
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
                keyboard::KeyEvent::Down => {
                    unsafe {
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
                    }
                }
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

                    if (c.is_ascii_graphic() || c == ' ') && len < input.len() - 1 /* && len < max_len */ {
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
    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
    terminal::clear_line_from_cursor();
    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
    terminal::write_str_no_serial(line);
    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
}
