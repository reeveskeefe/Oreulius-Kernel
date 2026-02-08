#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
use alloc::boxed::Box;

pub mod advanced_commands;
pub mod acpi_asm;
pub mod asm_bindings;
pub mod capability;
pub mod commands;
pub mod console_service;
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
pub mod netstack;
pub mod paging;
pub mod pci;
pub mod persistence;
pub mod pit;
pub mod process;
pub mod process_asm;
pub mod quantum_scheduler;
pub mod registry;
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
pub mod usermode;
pub mod tasks;

/// Helper to ensure Box is available for heap allocations across modules
#[inline]
pub fn ensure_heap_available() -> Option<Box<u32>> {
    // Try to allocate on heap to verify allocator is working
    Some(Box::new(42))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    vga::print_str("[PANIC] Kernel panic\n");
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    vga::print_str("[ALLOC] Allocation failed\n");
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
    } else if let Some(_eth_device) = pci_scanner.find_ethernet_device() {
        vga::print_str("[NET] Ethernet device detected (init disabled)\n");
        // if e1000::init(eth_device).is_ok() {
        //     vga::print_str("[NET] E1000 initialized - Ready for DNS/ARP/UDP\n");
        // }
        // Don't call net::init for ethernet - it expects WiFi device!
    } else {
        vga::print_str("[NET] No network device found\n");
    }
    
    vga::print_str("\n[INIT] Initialization complete, starting scheduler...\n");
    tasks::start();
}

/// Shell loop (runs as init process)
pub fn shell_loop() -> ! {
    terminal::clear_screen();
    terminal::write_str("Oreulia OS\n");
    terminal::write_str("Type 'help' for commands.\n\n");
    terminal::write_str("> ");

    let mut input: [u8; 256] = [0; 256];
    let mut len: usize = 0;
    let mut cursor: usize = 0;
    let mut prompt_pos = terminal::cursor_position();
    let mut max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);

    loop {
        if let Some(ev) = keyboard::poll_event() {
            match ev {
                keyboard::KeyEvent::AltFn(n) => {
                    terminal::switch_terminal((n.saturating_sub(1)) as usize);
                    terminal::write_str("\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    prompt_pos = terminal::cursor_position();
                    max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Enter => {
                    terminal::write_char('\n');
                    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
                    commands::execute(line);
                    len = 0;
                    cursor = 0;
                    input = [0; 256];
                    terminal::write_str("> ");
                    prompt_pos = terminal::cursor_position();
                    max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
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
                    max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
                }
                keyboard::KeyEvent::Ctrl('z') => {
                    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
                    terminal::clear_line_from_cursor();
                    terminal::write_str("^Z\nJob control not implemented\n> ");
                    input = [0; 256];
                    len = 0;
                    cursor = 0;
                    prompt_pos = terminal::cursor_position();
                    max_len = vga::SCREEN_WIDTH.saturating_sub(prompt_pos.1 + 1);
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
                keyboard::KeyEvent::Char(c) => {
                    if (c.is_ascii_graphic() || c == ' ') && len < input.len() - 1 && len < max_len {
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

        core::hint::spin_loop();
    }
}

fn redraw_line(input: &[u8; 256], len: usize, cursor: usize, prompt_pos: (usize, usize)) {
    terminal::set_cursor(prompt_pos.0, prompt_pos.1);
    terminal::clear_line_from_cursor();
    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
    terminal::write_str(line);
    terminal::set_cursor(prompt_pos.0, prompt_pos.1 + cursor);
}
