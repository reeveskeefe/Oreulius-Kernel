#![no_std]

pub mod commands;
pub mod fs;
pub mod ipc;
pub mod keyboard;
pub mod memory;
pub mod persistence;
pub mod process;
pub mod registry;
pub mod vga;

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
