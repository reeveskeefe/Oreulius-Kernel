#![no_std]

extern crate alloc;
use alloc::boxed::Box;

pub mod commands;
pub mod e1000;
pub mod fs;
pub mod ipc;
pub mod keyboard;
pub mod memory;
pub mod net;
pub mod netstack;
pub mod pci;
pub mod persistence;
pub mod process;
pub mod registry;
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
    // Initialize services
    fs::init();
    persistence::init();
    ipc::init();
    registry::init();
    process::init();  // Creates init process (PID 1)
    wasm::init();     // Initialize WASM runtime
    
    // Initialize PCI and detect network devices
    vga::print_str("[PCI] Scanning for devices...\n");
    let mut pci_scanner = pci::PciScanner::new();
    pci_scanner.scan();
    
    // Try WiFi first, then Ethernet
    if let Some(wifi_device) = pci_scanner.find_wifi_device() {
        vga::print_str("[NET] WiFi device detected\n");
        net::init(Some(wifi_device));
    } else if let Some(eth_device) = pci_scanner.find_ethernet_device() {
        vga::print_str("[NET] Ethernet device detected (e1000)\n");
        if e1000::init(eth_device).is_ok() {
            vga::print_str("[NET] E1000 initialized - Ready for DNS/ARP/UDP\n");
        }
        // Don't call net::init for ethernet - it expects WiFi device!
    } else {
        vga::print_str("[NET] No network device found\n");
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
