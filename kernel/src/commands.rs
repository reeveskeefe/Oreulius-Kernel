use crate::vga;

pub fn execute(input: &str) {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return;
    }

    let mut parts = trimmed.split_whitespace();
    let command = parts.next().unwrap_or("");

    match command {
        "help" => {
            vga::print_str("Available commands:\n");
            vga::print_str("  help  - Display this help message\n");
            vga::print_str("  clear - Clear the screen\n");
            vga::print_str("  echo  - Echo text back to screen\n");
        }
        "clear" => {
            vga::clear_screen();
        }
        "echo" => {
            let mut first = true;
            for arg in parts {
                if !first {
                    vga::print_char(' ');
                }
                first = false;
                vga::print_str(arg);
            }
            vga::print_char('\n');
        }
        _ => {
            vga::print_str("Unknown command: ");
            vga::print_str(command);
            vga::print_str(". Type 'help' for available commands.\n");
        }
    }
}
