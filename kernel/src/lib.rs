#![no_std]

extern crate alloc;
use alloc::boxed::Box;

pub mod advanced_commands;
pub mod asm_bindings;
pub mod capability;
pub mod commands;
pub mod console_service;
pub mod e1000;
pub mod fs;
pub mod hardened_allocator;
pub mod ipc;
pub mod keyboard;
pub mod memory;
pub mod net;
pub mod netstack;
pub mod paging;
pub mod pci;
pub mod persistence;
pub mod pit;
pub mod process;
pub mod quantum_scheduler;
pub mod registry;
pub mod scheduler;
pub mod security;
pub mod syscall;
pub mod vga;
pub mod wasm;
pub mod wifi;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    // CRITICAL: Initialize memory allocator FIRST before ANY allocations
    memory::init();
    
    // Now we can use VGA (and everything else)
    vga::print_str("[MEMORY] Heap allocator initialized\n");
    
    // Initialize virtual memory management (must be early, after physical memory)
    vga::print_str("[PAGING] Enabling virtual memory...\n");
    paging::init();
    vga::print_str("[PAGING] Virtual memory enabled (4KB pages, user/kernel separation)\n");
    
    // Initialize syscall interface
    vga::print_str("[SYSCALL] Setting up system call interface...\n");
    syscall::init();
    vga::print_str("[SYSCALL] INT 0x80 handler registered\n");
    
    vga::print_str("[WASM] Runtime initialized\n");
    
    // Initialize services
    fs::init();
    persistence::init();
    ipc::init();
    registry::init();
    process::init();  // Creates init process (PID 1)
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
    
    vga::print_str("[DEBUG] Timer initialized successfully\n");
    
    // Initialize PCI and detect network devices  
    vga::print_str("[PCI] Scanning for devices...\n");
    // TEMPORARILY DISABLED for debugging
    // let mut pci_scanner = pci::PciScanner::new();
    // pci_scanner.scan();
    
    // Try WiFi first, then Ethernet
    // if let Some(wifi_device) = pci_scanner.find_wifi_device() {
    //     vga::print_str("[NET] WiFi device detected\n");
    //     net::init(Some(wifi_device));
    // } else if let Some(eth_device) = pci_scanner.find_ethernet_device() {
    //     vga::print_str("[NET] Ethernet device detected (e1000)\n");
    //     if e1000::init(eth_device).is_ok() {
    //         vga::print_str("[NET] E1000 initialized - Ready for DNS/ARP/UDP\n");
    //     }
    //     // Don't call net::init for ethernet - it expects WiFi device!
    // } else {
        vga::print_str("[NET] No network device found (PCI scan disabled for debugging)\n");
    // }
    
    vga::print_str("\n[INIT] Initialization complete, starting shell...\n");
    
    // Small delay to ensure message is visible
    for _ in 0..10000000 {
        core::hint::spin_loop();
    }
    
    vga::clear_screen();
    vga::print_str("Oreulia OS\n");
    vga::print_str("Type 'help' for commands.\n\n");
    vga::print_str("> ");

    let mut input: [u8; 256] = [0; 256];
    let mut len: usize = 0;

    loop {
        if let Some(ch) = keyboard::poll() {
            match ch {
                '\n' => {
                    vga::print_char('\n');
                    let line = core::str::from_utf8(&input[..len]).unwrap_or("");
                    commands::execute(line);
                    len = 0;
                    input = [0; 256];
                    vga::print_str("> ");
                }
                '\x08' => {
                    if len > 0 {
                        len -= 1;
                        input[len] = 0;
                        vga::backspace();
                    }
                }
                c if c.is_ascii_graphic() || c == ' ' => {
                    if len < input.len() - 1 {
                        input[len] = c as u8;
                        len += 1;
                        vga::print_char(c);
                    }
                }
                _ => {}
            }
        }

        core::hint::spin_loop();
    }
}
