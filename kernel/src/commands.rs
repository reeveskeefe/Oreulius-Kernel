use crate::vga;
use crate::fs;

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
            vga::print_str("  help      - Display this help message\n");
            vga::print_str("  clear     - Clear the screen\n");
            vga::print_str("  echo      - Echo text back to screen\n");
            vga::print_str("  fs-write  - Write a file (usage: fs-write <key> <data>)\n");
            vga::print_str("  fs-read   - Read a file (usage: fs-read <key>)\n");
            vga::print_str("  fs-delete - Delete a file (usage: fs-delete <key>)\n");
            vga::print_str("  fs-list   - List all files\n");
            vga::print_str("  fs-stats  - Show filesystem statistics\n");
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
        "fs-write" => {
            cmd_fs_write(parts);
        }
        "fs-read" => {
            cmd_fs_read(parts);
        }
        "fs-delete" => {
            cmd_fs_delete(parts);
        }
        "fs-list" => {
            cmd_fs_list();
        }
        "fs-stats" => {
            cmd_fs_stats();
        }
        _ => {
            vga::print_str("Unknown command: ");
            vga::print_str(command);
            vga::print_str(". Type 'help' for available commands.\n");
        }
    }
}

fn cmd_fs_write(mut parts: core::str::SplitWhitespace) {
    let key_str = match parts.next() {
        Some(k) => k,
        None => {
            vga::print_str("Usage: fs-write <key> <data>\n");
            return;
        }
    };

    let data_str = match parts.next() {
        Some(d) => d,
        None => {
            vga::print_str("Usage: fs-write <key> <data>\n");
            return;
        }
    };

    let key = match fs::FileKey::new(key_str) {
        Ok(k) => k,
        Err(e) => {
            vga::print_str("Error creating key: ");
            vga::print_str(match e {
                fs::FilesystemError::KeyTooLong => "key too long\n",
                fs::FilesystemError::InvalidKey => "invalid key\n",
                _ => "unknown error\n",
            });
            return;
        }
    };

    // Create a root capability for demo purposes
    let cap = fs::filesystem().create_capability(
        1,
        fs::FilesystemRights::all(),
        None,
    );

    let request = match fs::Request::write(key, data_str.as_bytes(), cap) {
        Ok(r) => r,
        Err(e) => {
            vga::print_str("Error creating request: ");
            vga::print_str(match e {
                fs::FilesystemError::FileTooLarge => "file too large\n",
                _ => "unknown error\n",
            });
            return;
        }
    };

    let response = fs::filesystem().handle_request(request);
    
    match response.status {
        fs::ResponseStatus::Ok => {
            vga::print_str("File written successfully: ");
            vga::print_str(key_str);
            vga::print_str("\n");
        }
        fs::ResponseStatus::Error(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                fs::FilesystemError::NotFound => "not found\n",
                fs::FilesystemError::AlreadyExists => "already exists\n",
                fs::FilesystemError::FileTooLarge => "file too large\n",
                fs::FilesystemError::PermissionDenied => "permission denied\n",
                fs::FilesystemError::FilesystemFull => "filesystem full\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_fs_read(mut parts: core::str::SplitWhitespace) {
    let key_str = match parts.next() {
        Some(k) => k,
        None => {
            vga::print_str("Usage: fs-read <key>\n");
            return;
        }
    };

    let key = match fs::FileKey::new(key_str) {
        Ok(k) => k,
        Err(_) => {
            vga::print_str("Error: invalid key\n");
            return;
        }
    };

    let cap = fs::filesystem().create_capability(
        1,
        fs::FilesystemRights::all(),
        None,
    );

    let request = fs::Request::read(key, cap);
    let response = fs::filesystem().handle_request(request);
    
    match response.status {
        fs::ResponseStatus::Ok => {
            vga::print_str("File contents: ");
            if let Ok(s) = core::str::from_utf8(response.get_data()) {
                vga::print_str(s);
            } else {
                vga::print_str("<binary data>");
            }
            vga::print_str("\n");
        }
        fs::ResponseStatus::Error(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                fs::FilesystemError::NotFound => "file not found\n",
                fs::FilesystemError::PermissionDenied => "permission denied\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_fs_delete(mut parts: core::str::SplitWhitespace) {
    let key_str = match parts.next() {
        Some(k) => k,
        None => {
            vga::print_str("Usage: fs-delete <key>\n");
            return;
        }
    };

    let key = match fs::FileKey::new(key_str) {
        Ok(k) => k,
        Err(_) => {
            vga::print_str("Error: invalid key\n");
            return;
        }
    };

    let cap = fs::filesystem().create_capability(
        1,
        fs::FilesystemRights::all(),
        None,
    );

    let request = fs::Request::delete(key, cap);
    let response = fs::filesystem().handle_request(request);
    
    match response.status {
        fs::ResponseStatus::Ok => {
            vga::print_str("File deleted: ");
            vga::print_str(key_str);
            vga::print_str("\n");
        }
        fs::ResponseStatus::Error(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                fs::FilesystemError::NotFound => "file not found\n",
                fs::FilesystemError::PermissionDenied => "permission denied\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_fs_list() {
    let cap = fs::filesystem().create_capability(
        1,
        fs::FilesystemRights::all(),
        None,
    );

    let request = fs::Request::list(cap);
    let response = fs::filesystem().handle_request(request);
    
    match response.status {
        fs::ResponseStatus::Ok => {
            let data = response.get_data();
            if data.is_empty() {
                vga::print_str("No files in filesystem.\n");
            } else {
                vga::print_str("Files:\n");
                if let Ok(s) = core::str::from_utf8(data) {
                    vga::print_str(s);
                }
            }
        }
        fs::ResponseStatus::Error(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                fs::FilesystemError::PermissionDenied => "permission denied\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_fs_stats() {
    let (count, max) = fs::filesystem().stats();
    vga::print_str("Filesystem statistics:\n");
    vga::print_str("  Files: ");
    print_number(count);
    vga::print_str(" / ");
    print_number(max);
    vga::print_str("\n");
}

fn print_number(n: usize) {
    if n == 0 {
        vga::print_char('0');
        return;
    }

    let mut num = n;
    let mut digits = [0u8; 20];
    let mut i = 0;

    while num > 0 {
        digits[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }

    while i > 0 {
        i -= 1;
        vga::print_char(digits[i] as char);
    }
}
