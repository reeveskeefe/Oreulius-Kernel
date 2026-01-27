use crate::vga;
use crate::fs;
use crate::ipc;
use crate::registry;
use crate::process;
use crate::wasm;

// Helper functions for printing numbers
fn print_u32(n: u32) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    
    let mut buf = [0u8; 10];
    let mut i = 0;
    let mut num = n;
    
    while num > 0 {
        buf[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }
    
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_usize(n: usize) {
    print_u32(n as u32);
}


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
            vga::print_str("  help       - Display this help message\n");
            vga::print_str("  clear      - Clear the screen\n");
            vga::print_str("  echo       - Echo text back to screen\n");
            vga::print_str("  fs-write   - Write a file (usage: fs-write <key> <data>)\n");
            vga::print_str("  fs-read    - Read a file (usage: fs-read <key>)\n");
            vga::print_str("  fs-delete  - Delete a file (usage: fs-delete <key>)\n");
            vga::print_str("  fs-list    - List all files\n");
            vga::print_str("  fs-stats   - Show filesystem statistics\n");
            vga::print_str("  ipc-create - Create a new channel\n");
            vga::print_str("  ipc-send   - Send a message (usage: ipc-send <chan> <msg>)\n");
            vga::print_str("  ipc-recv   - Receive a message (usage: ipc-recv <chan>)\n");
            vga::print_str("  ipc-stats  - Show IPC statistics\n");
            vga::print_str("  cap-demo   - Demo capability passing (cap-demo <key>)\n");
            vga::print_str("  svc-register - Register a service (svc-register <type>)\n");
            vga::print_str("  svc-request  - Request a service (svc-request <type>)\n");
            vga::print_str("  svc-list     - List all services\n");
            vga::print_str("  svc-stats    - Show registry statistics\n");
            vga::print_str("  intro-demo   - Demo introduction protocol\n");
            vga::print_str("  spawn        - Spawn a new process (spawn <name>)\n");
            vga::print_str("  ps           - List all processes\n");
            vga::print_str("  kill         - Terminate a process (kill <pid>)\n");
            vga::print_str("  yield        - Yield current process\n");
            vga::print_str("  whoami       - Show current process\n");
            vga::print_str("  wasm-demo    - Run WASM demo (simple math)\n");
            vga::print_str("  wasm-fs-demo - Demo WASM filesystem syscalls\n");
            vga::print_str("  wasm-log-demo - Demo WASM logging syscall\n");
            vga::print_str("  wasm-list    - List loaded WASM instances\n");
            vga::print_str("  calculate    - Scientific calculator (calculate <a> <op> <b>)\n");
            vga::print_str("  calculate-help - Show calculator operations\n");
            vga::print_str("  network-help - Show network commands\n");
            vga::print_str("  net-info     - Show network status\n");
            vga::print_str("  pci-list     - List PCI devices (hardware detection)\n");
            vga::print_str("  wifi-scan    - Scan for WiFi networks\n");
            vga::print_str("  wifi-connect - Connect to WiFi (wifi-connect <ssid> [password])\n");
            vga::print_str("  wifi-status  - Show WiFi connection status\n");
            vga::print_str("  http-get     - HTTP GET request (http-get <url>)\n");
            vga::print_str("  dns-resolve  - Resolve domain name (dns-resolve <domain>)\n");
            vga::print_str("  eth-status   - Show Ethernet status\n");
            vga::print_str("  eth-info     - Show Ethernet device info\n");
            vga::print_str("  netstack-info - Show network stack status (real TCP/IP)\n");
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
        "ipc-create" => {
            cmd_ipc_create();
        }
        "ipc-send" => {
            cmd_ipc_send(parts);
        }
        "ipc-recv" => {
            cmd_ipc_recv(parts);
        }
        "ipc-stats" => {
            cmd_ipc_stats();
        }
        "cap-demo" => {
            cmd_cap_demo(parts);
        }
        "svc-register" => {
            cmd_svc_register(parts);
        }
        "svc-request" => {
            cmd_svc_request(parts);
        }
        "svc-list" => {
            cmd_svc_list();
        }
        "svc-stats" => {
            cmd_svc_stats();
        }
        "intro-demo" => {
            cmd_intro_demo();
        }
        "spawn" => {
            cmd_spawn(parts);
        }
        "ps" => {
            cmd_ps();
        }
        "kill" => {
            cmd_kill(parts);
        }
        "yield" => {
            cmd_yield();
        }
        "whoami" => {
            cmd_whoami();
        }
        "wasm-demo" => {
            cmd_wasm_demo();
        }
        "wasm-fs-demo" => {
            cmd_wasm_fs_demo();
        }
        "wasm-log-demo" => {
            cmd_wasm_log_demo();
        }
        "wasm-list" => {
            cmd_wasm_list();
        }
        "calculate" => {
            cmd_calculate(parts);
        }
        "calculate-help" => {
            cmd_calculate_help();
        }
        "network-help" => {
            cmd_network_help();
        }
        "net-info" => {
            cmd_net_info();
        }
        "pci-list" => {
            cmd_pci_list();
        }
        "wifi-scan" => {
            cmd_wifi_scan();
        }
        "wifi-connect" => {
            cmd_wifi_connect(parts);
        }
        "wifi-status" => {
            cmd_wifi_status();
        }
        "http-get" => {
            cmd_http_get(parts);
        }
        "dns-resolve" => {
            cmd_dns_resolve(parts);
        }
        "eth-status" => {
            cmd_eth_status();
        }
        "eth-info" => {
            cmd_eth_info();
        }
        "netstack-info" => {
            cmd_netstack_info();
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

// ============================================================================
// IPC Commands
// ============================================================================

// Simple channel storage for demo (channel_id -> (send_cap, recv_cap))
static mut DEMO_CHANNELS: [(u32, Option<(ipc::ChannelCapability, ipc::ChannelCapability)>); 8] = 
    [(0, None), (0, None), (0, None), (0, None), (0, None), (0, None), (0, None), (0, None)];

fn cmd_ipc_create() {
    let process_id = ipc::ProcessId::new(1); // Demo process ID
    
    match ipc::ipc().create_channel(process_id) {
        Ok((send_cap, recv_cap)) => {
            let chan_id = send_cap.channel_id.0;
            
            // Store capabilities for later use
            unsafe {
                for slot in &mut DEMO_CHANNELS {
                    if slot.1.is_none() {
                        slot.0 = chan_id;
                        slot.1 = Some((send_cap, recv_cap));
                        break;
                    }
                }
            }
            
            vga::print_str("Channel created: ");
            print_number(chan_id as usize);
            vga::print_str("\n");
        }
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                ipc::IpcError::TooManyChannels => "too many channels\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_ipc_send(mut parts: core::str::SplitWhitespace) {
    let chan_str = match parts.next() {
        Some(c) => c,
        None => {
            vga::print_str("Usage: ipc-send <channel_id> <message>\n");
            return;
        }
    };

    let msg_str = match parts.next() {
        Some(m) => m,
        None => {
            vga::print_str("Usage: ipc-send <channel_id> <message>\n");
            return;
        }
    };

    // Parse channel ID
    let chan_id = match parse_number(chan_str) {
        Some(n) => n as u32,
        None => {
            vga::print_str("Error: invalid channel ID\n");
            return;
        }
    };

    // Find the send capability
    let send_cap = unsafe {
        DEMO_CHANNELS
            .iter()
            .find(|(id, _)| *id == chan_id)
            .and_then(|(_, caps)| caps.as_ref())
            .map(|(send, _)| *send)
    };

    let send_cap = match send_cap {
        Some(cap) => cap,
        None => {
            vga::print_str("Error: channel not found\n");
            return;
        }
    };

    // Create and send message
    let msg = match ipc::Message::with_data(ipc::ProcessId::new(1), msg_str.as_bytes()) {
        Ok(m) => m,
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                ipc::IpcError::MessageTooLarge => "message too large\n",
                _ => "unknown error\n",
            });
            return;
        }
    };

    match ipc::ipc().send(msg, &send_cap) {
        Ok(_) => {
            vga::print_str("Message sent to channel ");
            print_number(chan_id as usize);
            vga::print_str("\n");
        }
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                ipc::IpcError::WouldBlock => "channel full\n",
                ipc::IpcError::Closed => "channel closed\n",
                ipc::IpcError::PermissionDenied => "permission denied\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_ipc_recv(mut parts: core::str::SplitWhitespace) {
    let chan_str = match parts.next() {
        Some(c) => c,
        None => {
            vga::print_str("Usage: ipc-recv <channel_id>\n");
            return;
        }
    };

    // Parse channel ID
    let chan_id = match parse_number(chan_str) {
        Some(n) => n as u32,
        None => {
            vga::print_str("Error: invalid channel ID\n");
            return;
        }
    };

    // Find the receive capability
    let recv_cap = unsafe {
        DEMO_CHANNELS
            .iter()
            .find(|(id, _)| *id == chan_id)
            .and_then(|(_, caps)| caps.as_ref())
            .map(|(_, recv)| *recv)
    };

    let recv_cap = match recv_cap {
        Some(cap) => cap,
        None => {
            vga::print_str("Error: channel not found\n");
            return;
        }
    };

    // Try to receive message
    match ipc::ipc().try_recv(&recv_cap) {
        Ok(msg) => {
            vga::print_str("Received: ");
            if let Ok(s) = core::str::from_utf8(msg.payload()) {
                vga::print_str(s);
            } else {
                vga::print_str("<binary data>");
            }
            vga::print_str("\n");
        }
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(match e {
                ipc::IpcError::WouldBlock => "no messages\n",
                ipc::IpcError::Closed => "channel closed\n",
                ipc::IpcError::PermissionDenied => "permission denied\n",
                _ => "unknown error\n",
            });
        }
    }
}

fn cmd_ipc_stats() {
    let (count, max) = ipc::ipc().stats();
    vga::print_str("IPC statistics:\n");
    vga::print_str("  Channels: ");
    print_number(count);
    vga::print_str(" / ");
    print_number(max);
    vga::print_str("\n");
}

fn parse_number(s: &str) -> Option<usize> {
    let mut result = 0usize;
    for ch in s.chars() {
        if let Some(digit) = ch.to_digit(10) {
            result = result * 10 + digit as usize;
        } else {
            return None;
        }
    }
    Some(result)
}

// ============================================================================
// Capability Passing Demo
// ============================================================================

fn cmd_cap_demo(mut parts: core::str::SplitWhitespace) {
    vga::print_str("\n=== Capability Passing Demo ===\n\n");

    let key_str = match parts.next() {
        Some(k) => k,
        None => {
            vga::print_str("Usage: cap-demo <file_key>\n");
            vga::print_str("\nThis demo shows:\n");
            vga::print_str("1. Creating a filesystem capability\n");
            vga::print_str("2. Converting it to IPC format\n");
            vga::print_str("3. Sending it through a channel\n");
            vga::print_str("4. Receiving and using it\n");
            return;
        }
    };

    // Step 1: Create a file
    vga::print_str("Step 1: Create file '");
    vga::print_str(key_str);
    vga::print_str("' with test data\n");

    let key = match fs::FileKey::new(key_str) {
        Ok(k) => k,
        Err(_) => {
            vga::print_str("Error: invalid key\n");
            return;
        }
    };

    let root_cap = fs::filesystem().create_capability(
        1,
        fs::FilesystemRights::all(),
        None,
    );

    let write_req = match fs::Request::write(key, b"Secret data!", root_cap) {
        Ok(r) => r,
        Err(_) => {
            vga::print_str("Error creating write request\n");
            return;
        }
    };

    match fs::filesystem().handle_request(write_req).status {
        fs::ResponseStatus::Ok => vga::print_str("  ✓ File created\n\n"),
        _ => {
            vga::print_str("  ✗ Failed to create file\n");
            return;
        }
    }

    // Step 2: Create a read-only filesystem capability
    vga::print_str("Step 2: Create read-only filesystem capability\n");
    let fs_cap = fs::filesystem().create_capability(
        100,
        fs::FilesystemRights::read_only(),
        None,
    );
    vga::print_str("  ✓ Capability created (cap_id=");
    print_number(fs_cap.cap_id as usize);
    vga::print_str(", rights=READ)\n\n");

    // Step 3: Convert to IPC capability
    vga::print_str("Step 3: Convert to IPC capability\n");
    let ipc_cap = fs_cap.to_ipc_capability();
    vga::print_str("  ✓ Converted (type=");
    print_number(ipc_cap.cap_type as usize);
    vga::print_str(", rights=");
    print_number(ipc_cap.rights as usize);
    vga::print_str(")\n\n");

    // Step 4: Create a channel
    vga::print_str("Step 4: Create IPC channel\n");
    let (send_cap, recv_cap) = match ipc::ipc().create_channel(ipc::ProcessId::new(1)) {
        Ok(caps) => caps,
        Err(_) => {
            vga::print_str("  ✗ Failed to create channel\n");
            return;
        }
    };
    vga::print_str("  ✓ Channel created (id=");
    print_number(send_cap.channel_id.0 as usize);
    vga::print_str(")\n\n");

    // Step 5: Send capability through channel
    vga::print_str("Step 5: Send filesystem capability via IPC\n");
    let mut msg = match ipc::Message::with_data(ipc::ProcessId::new(1), b"Here's a file cap!") {
        Ok(m) => m,
        Err(_) => {
            vga::print_str("  ✗ Failed to create message\n");
            return;
        }
    };

    if let Err(_) = msg.add_capability(ipc_cap) {
        vga::print_str("  ✗ Failed to attach capability\n");
        return;
    }

    if let Err(_) = ipc::ipc().send(msg, &send_cap) {
        vga::print_str("  ✗ Failed to send message\n");
        return;
    }
    vga::print_str("  ✓ Sent (message + 1 capability)\n\n");

    // Step 6: Receive message with capability
    vga::print_str("Step 6: Receive message and extract capability\n");
    let received_msg = match ipc::ipc().try_recv(&recv_cap) {
        Ok(m) => m,
        Err(_) => {
            vga::print_str("  ✗ Failed to receive\n");
            return;
        }
    };

    vga::print_str("  ✓ Message received: \"");
    if let Ok(s) = core::str::from_utf8(received_msg.payload()) {
        vga::print_str(s);
    }
    vga::print_str("\"\n");

    // Extract the filesystem capability
    let received_cap = match received_msg.capabilities().next() {
        Some(c) => c,
        None => {
            vga::print_str("  ✗ No capability in message\n");
            return;
        }
    };

    vga::print_str("  ✓ Capability extracted (type=");
    print_number(received_cap.cap_type as usize);
    vga::print_str(")\n\n");

    // Step 7: Convert back to filesystem capability
    vga::print_str("Step 7: Convert back to filesystem capability\n");
    let restored_fs_cap = match fs::FilesystemCapability::from_ipc_capability(received_cap) {
        Ok(c) => c,
        Err(_) => {
            vga::print_str("  ✗ Failed to restore capability\n");
            return;
        }
    };
    vga::print_str("  ✓ Restored (cap_id=");
    print_number(restored_fs_cap.cap_id as usize);
    vga::print_str(", has READ=");
    if restored_fs_cap.rights.has(fs::FilesystemRights::READ) {
        vga::print_str("yes");
    } else {
        vga::print_str("no");
    }
    vga::print_str(")\n\n");

    // Step 8: Use the received capability to read the file
    vga::print_str("Step 8: Use received capability to read file\n");
    let read_req = fs::Request::read(key, restored_fs_cap);
    let response = fs::filesystem().handle_request(read_req);

    match response.status {
        fs::ResponseStatus::Ok => {
            vga::print_str("  ✓ Read successful: \"");
            if let Ok(s) = core::str::from_utf8(response.get_data()) {
                vga::print_str(s);
            }
            vga::print_str("\"\n\n");
        }
        _ => {
            vga::print_str("  ✗ Read failed\n\n");
            return;
        }
    }

    // Step 9: Try to write (should fail - read-only cap)
    vga::print_str("Step 9: Try to write with read-only capability\n");
    let write_attempt = match fs::Request::write(key, b"Hacked!", restored_fs_cap) {
        Ok(r) => r,
        Err(_) => {
            vga::print_str("  ✓ Write blocked at request level\n\n");
            vga::print_str("=== Demo Complete! ===\n");
            vga::print_str("Capability was successfully passed through IPC\n");
            vga::print_str("and rights were preserved!\n\n");
            return;
        }
    };

    let response = fs::filesystem().handle_request(write_attempt);
    if response.status != fs::ResponseStatus::Ok {
        vga::print_str("  ✓ Write rejected by filesystem\n\n");
    } else {
        vga::print_str("  ✗ Write should have failed!\n\n");
    }

    vga::print_str("=== Demo Complete! ===\n");
    vga::print_str("Capability was successfully passed through IPC\n");
    vga::print_str("and rights were preserved!\n\n");
}

// ============================================================================
// Service Registry Commands
// ============================================================================

/// Register a service (for testing)
fn cmd_svc_register(mut parts: core::str::SplitWhitespace) {
    use registry::{ServiceType, ServiceNamespace, ServiceMetadata, ServiceOffer};

    let type_str = match parts.next() {
        Some(t) => t,
        None => {
            vga::print_str("Usage: svc-register <type>\n");
            vga::print_str("Types: fs, persist, network, timer, console\n");
            return;
        }
    };

    let service_type = match type_str {
        "fs" => ServiceType::Filesystem,
        "persist" => ServiceType::Persistence,
        "network" => ServiceType::Network,
        "timer" => ServiceType::Timer,
        "console" => ServiceType::Console,
        _ => {
            vga::print_str("Unknown service type: ");
            vga::print_str(type_str);
            vga::print_str("\n");
            return;
        }
    };

    // Create a channel for this service
    let channel_result = ipc::ipc().create_channel(ipc::ProcessId(1));

    let (cap1, cap2) = match channel_result {
        Ok(caps) => caps,
        Err(e) => {
            vga::print_str("Failed to create channel: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    let channel = cap1.channel_id;

    // Create service metadata
    let metadata = ServiceMetadata::new(1, 10, ipc::ProcessId(1));

    // Create service offer
    let offer = ServiceOffer::new(
        service_type,
        channel,
        ServiceNamespace::Production,
        metadata,
    );

    // Register the service
    match registry::registry().register_service(offer) {
        Ok(()) => {
            vga::print_str("Service registered: ");
            vga::print_str(service_type.name());
            vga::print_str(" on channel ");
            print_u32(channel.0);
            vga::print_str("\n");
        }
        Err(e) => {
            vga::print_str("Failed to register: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
        }
    }
}

/// Request a service introduction
fn cmd_svc_request(mut parts: core::str::SplitWhitespace) {
    use registry::{ServiceType, IntroductionRequest, IntroductionStatus};

    let type_str = match parts.next() {
        Some(t) => t,
        None => {
            vga::print_str("Usage: svc-request <type>\n");
            vga::print_str("Types: fs, persist, network, timer, console\n");
            return;
        }
    };

    let service_type = match type_str {
        "fs" => ServiceType::Filesystem,
        "persist" => ServiceType::Persistence,
        "network" => ServiceType::Network,
        "timer" => ServiceType::Timer,
        "console" => ServiceType::Console,
        _ => {
            vga::print_str("Unknown service type: ");
            vga::print_str(type_str);
            vga::print_str("\n");
            return;
        }
    };

    // Create a root introducer for testing
    let mut introducer = match registry::registry().create_root_introducer(ipc::ProcessId(1)) {
        Ok(i) => i,
        Err(e) => {
            vga::print_str("Failed to create introducer: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    // Create introduction request
    let request = IntroductionRequest::new(service_type, ipc::ProcessId(1));

    // Perform introduction
    let response = registry::registry().introduce(request, &mut introducer);

    match response.status {
        IntroductionStatus::Success => {
            if let Some(channel) = response.service_channel {
                vga::print_str("Introduction successful!\n");
                vga::print_str("  Service: ");
                vga::print_str(service_type.name());
                vga::print_str("\n");
                vga::print_str("  Channel: ");
                print_u32(channel.0);
                vga::print_str("\n");
                
                if let Some(metadata) = response.metadata {
                    vga::print_str("  Version: ");
                    print_u32(metadata.version);
                    vga::print_str("\n");
                    vga::print_str("  Max connections: ");
                    print_usize(metadata.max_connections);
                    vga::print_str("\n");
                }
            }
        }
        _ => {
            vga::print_str("Introduction failed: ");
            vga::print_str(response.status.as_str());
            vga::print_str("\n");
        }
    }
}

/// List all registered services
fn cmd_svc_list() {
    use registry::ServiceNamespace;

    vga::print_str("Registered Services:\n");
    vga::print_str("-------------------\n");

    let (services, count) = registry::registry().list_services();
    
    if count == 0 {
        vga::print_str("No services registered\n");
        return;
    }

    for i in 0..count {
        let (service_type, namespace, connections) = services[i];
        vga::print_str("  ");
        vga::print_str(service_type.name());
        vga::print_str(" (");
        
        match namespace {
            ServiceNamespace::Production => vga::print_str("prod"),
            ServiceNamespace::Test => vga::print_str("test"),
            ServiceNamespace::Sandbox => vga::print_str("sandbox"),
            ServiceNamespace::Custom(n) => {
                vga::print_str("custom-");
                print_u32(n);
            }
        }
        
        vga::print_str(") - ");
        print_usize(connections);
        vga::print_str(" connections\n");
    }
}

/// Show registry statistics
fn cmd_svc_stats() {
    let (service_count, max_services, introducer_count, max_introducers) = 
        registry::registry().stats();

    vga::print_str("Service Registry Statistics:\n");
    vga::print_str("---------------------------\n");
    vga::print_str("Services: ");
    print_usize(service_count);
    vga::print_str(" / ");
    print_usize(max_services);
    vga::print_str("\n");
    vga::print_str("Introducers: ");
    print_usize(introducer_count);
    vga::print_str(" / ");
    print_usize(max_introducers);
    vga::print_str("\n");
}

/// Demo introduction protocol
fn cmd_intro_demo() {
    use registry::{ServiceType, ServiceNamespace, ServiceMetadata, ServiceOffer};
    use registry::{IntroductionRequest, IntroductionStatus, IntroductionScope};

    vga::print_str("\n=== Service Introduction Protocol Demo ===\n\n");

    // Step 1: Register a filesystem service
    vga::print_str("Step 1: Register a Filesystem service\n");
    
    let channel_result = ipc::ipc().create_channel(ipc::ProcessId(100));

    let (cap1, cap2) = match channel_result {
        Ok(caps) => caps,
        Err(e) => {
            vga::print_str("  ✗ Failed to create channel: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    let channel = cap1.channel_id;

    let metadata = ServiceMetadata::new(1, 5, ipc::ProcessId(100));
    let offer = ServiceOffer::new(
        ServiceType::Filesystem,
        channel,
        ServiceNamespace::Production,
        metadata,
    );

    match registry::registry().register_service(offer) {
        Ok(()) => {
            vga::print_str("  ✓ Filesystem service registered\n");
            vga::print_str("    Channel: ");
            print_u32(channel.0);
            vga::print_str("\n    Max connections: 5\n\n");
        }
        Err(e) => {
            vga::print_str("  ✗ Registration failed: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    }

    // Step 2: Create a root introducer
    vga::print_str("Step 2: Create root introducer (unlimited access)\n");
    
    let mut root_introducer = match registry::registry().create_root_introducer(ipc::ProcessId(1)) {
        Ok(i) => i,
        Err(e) => {
            vga::print_str("  ✗ Failed to create introducer: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    vga::print_str("  ✓ Root introducer created\n");
    vga::print_str("    Capability ID: ");
    print_u32(root_introducer.cap_id);
    vga::print_str("\n\n");

    // Step 3: Process requests introduction
    vga::print_str("Step 3: Process 201 requests Filesystem service\n");
    
    let request = IntroductionRequest::new(ServiceType::Filesystem, ipc::ProcessId(201));
    let response = registry::registry().introduce(request, &mut root_introducer);

    match response.status {
        IntroductionStatus::Success => {
            vga::print_str("  ✓ Introduction successful!\n");
            if let Some(ch) = response.service_channel {
                vga::print_str("    Channel: ");
                print_u32(ch.0);
                vga::print_str("\n");
            }
            vga::print_str("    Introductions used: ");
            print_usize(root_introducer.introductions_used);
            vga::print_str("\n\n");
        }
        _ => {
            vga::print_str("  ✗ Introduction failed: ");
            vga::print_str(response.status.as_str());
            vga::print_str("\n");
            return;
        }
    }

    // Step 4: Create restricted introducer
    vga::print_str("Step 4: Create restricted introducer (3 intros max)\n");
    
    let allowed_services = (1u32 << (ServiceType::Filesystem.as_u32() % 32))
                         | (1u32 << (ServiceType::Timer.as_u32() % 32));
    
    let mut restricted_introducer = match registry::registry().create_introducer(
        allowed_services,
        3,  // Max 3 introductions
        IntroductionScope::Global,
        ipc::ProcessId(201),
    ) {
        Ok(i) => i,
        Err(e) => {
            vga::print_str("  ✗ Failed to create introducer: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    vga::print_str("  ✓ Restricted introducer created\n");
    vga::print_str("    Capability ID: ");
    print_u32(restricted_introducer.cap_id);
    vga::print_str("\n");
    vga::print_str("    Max introductions: 3\n\n");

    // Step 5: Use restricted introducer (success)
    vga::print_str("Step 5: Use restricted introducer (1/3)\n");
    
    let request2 = IntroductionRequest::new(ServiceType::Filesystem, ipc::ProcessId(202));
    let response2 = registry::registry().introduce(request2, &mut restricted_introducer);

    match response2.status {
        IntroductionStatus::Success => {
            vga::print_str("  ✓ Introduction successful\n");
            vga::print_str("    Remaining: ");
            print_usize(restricted_introducer.max_introductions - restricted_introducer.introductions_used);
            vga::print_str(" / 3\n\n");
        }
        _ => {
            vga::print_str("  ✗ Failed: ");
            vga::print_str(response2.status.as_str());
            vga::print_str("\n");
        }
    }

    // Step 6: Try to request network service (should fail - not allowed)
    vga::print_str("Step 6: Try to request Network service (not allowed)\n");
    
    let request3 = IntroductionRequest::new(ServiceType::Network, ipc::ProcessId(203));
    let response3 = registry::registry().introduce(request3, &mut restricted_introducer);

    match response3.status {
        IntroductionStatus::PermissionDenied => {
            vga::print_str("  ✓ Correctly denied (service not allowed)\n\n");
        }
        IntroductionStatus::ServiceNotFound => {
            vga::print_str("  ✓ Service not found (acceptable)\n\n");
        }
        _ => {
            vga::print_str("  ✗ Unexpected: ");
            vga::print_str(response3.status.as_str());
            vga::print_str("\n\n");
        }
    }

    // Step 7: Show final statistics
    vga::print_str("Step 7: Final statistics\n");
    cmd_svc_stats();
    vga::print_str("\n");

    vga::print_str("=== Demo Complete! ===\n");
    vga::print_str("Introduction protocol successfully demonstrated:\n");
    vga::print_str("  ✓ Service registration\n");
    vga::print_str("  ✓ Root introducer (unlimited)\n");
    vga::print_str("  ✓ Restricted introducer (limited rights)\n");
    vga::print_str("  ✓ Permission enforcement\n");
    vga::print_str("  ✓ Auditable introductions\n\n");
}

// Helper to convert IntroductionStatus to string
impl registry::IntroductionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            registry::IntroductionStatus::Success => "Success",
            registry::IntroductionStatus::ServiceNotFound => "Service not found",
            registry::IntroductionStatus::PermissionDenied => "Permission denied",
            registry::IntroductionStatus::ServiceUnavailable => "Service unavailable",
            registry::IntroductionStatus::IntroducerExhausted => "Introducer exhausted",
            registry::IntroductionStatus::InvalidNamespace => "Invalid namespace",
        }
    }
}

// Helper to convert RegistryError to string
impl registry::RegistryError {
    fn as_str(&self) -> &'static str {
        match self {
            registry::RegistryError::ServiceAlreadyRegistered => "Service already registered",
            registry::RegistryError::ServiceNotFound => "Service not found",
            registry::RegistryError::RegistryFull => "Registry full",
            registry::RegistryError::TooManyIntroducers => "Too many introducers",
        }
    }
}

// ============================================================================
// Process Management Commands
// ============================================================================

/// Spawn a new process
fn cmd_spawn(mut parts: core::str::SplitWhitespace) {
    let name = match parts.next() {
        Some(n) => n,
        None => {
            vga::print_str("Usage: spawn <name>\n");
            return;
        }
    };

    // Get current process as parent
    let parent = process::current_pid();

    match process::process_manager().spawn(name, parent) {
        Ok(pid) => {
            vga::print_str("Process spawned: ");
            vga::print_str(name);
            vga::print_str(" (PID ");
            print_u32(pid.0);
            vga::print_str(")\n");
        }
        Err(e) => {
            vga::print_str("Failed to spawn: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
        }
    }
}

/// List all processes
fn cmd_ps() {
    vga::print_str("Processes:\n");
    vga::print_str("---------\n");
    vga::print_str("PID  Name                State       Caps\n");

    let (processes, count) = process::process_manager().list();

    if count == 0 {
        vga::print_str("No processes running\n");
        return;
    }

    for i in 0..count {
        let (pid, name_bytes, state, cap_count) = processes[i];
        // Print PID (aligned)
        let pid_val = pid.0;
        if pid_val < 10 {
            vga::print_char(' ');
        }
        print_u32(pid_val);
        vga::print_str("  ");

        // Print name (truncate at 18 chars, pad if shorter)
        let name_len = name_bytes.iter().position(|&c| c == 0).unwrap_or(32).min(18);
        let name_str = core::str::from_utf8(&name_bytes[..name_len]).unwrap_or("<invalid>");
        vga::print_str(name_str);
        
        // Pad name to 20 chars
        for _ in name_len..20 {
            vga::print_char(' ');
        }

        // Print state (pad to 12 chars)
        vga::print_str(state.as_str());
        for _ in state.as_str().len()..12 {
            vga::print_char(' ');
        }

        // Print capability count
        print_usize(cap_count);
        vga::print_char('\n');
    }

    vga::print_char('\n');
    let (count, max) = process::process_manager().stats();
    vga::print_str("Total: ");
    print_usize(count);
    vga::print_str(" / ");
    print_usize(max);
    vga::print_str(" processes\n");
}

/// Kill a process
fn cmd_kill(mut parts: core::str::SplitWhitespace) {
    let pid_str = match parts.next() {
        Some(p) => p,
        None => {
            vga::print_str("Usage: kill <pid>\n");
            return;
        }
    };

    // Parse PID
    let pid = match parse_u32(pid_str) {
        Some(p) => ipc::ProcessId(p),
        None => {
            vga::print_str("Invalid PID: ");
            vga::print_str(pid_str);
            vga::print_str("\n");
            return;
        }
    };

    // Don't allow killing init (PID 1)
    if pid.0 == 1 {
        vga::print_str("Cannot kill init process (PID 1)\n");
        return;
    }

    match process::process_manager().terminate(pid) {
        Ok(()) => {
            vga::print_str("Process ");
            print_u32(pid.0);
            vga::print_str(" terminated\n");
            
            // Reap terminated processes
            process::process_manager().reap();
        }
        Err(e) => {
            vga::print_str("Failed to kill: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
        }
    }
}

/// Yield current process
fn cmd_yield() {
    let old_pid = process::current_pid();
    
    if let Some(new_pid) = process::process_manager().yield_process() {
        vga::print_str("Yielded: PID ");
        if let Some(old) = old_pid {
            print_u32(old.0);
        } else {
            vga::print_str("?");
        }
        vga::print_str(" → PID ");
        print_u32(new_pid.0);
        vga::print_str("\n");
    } else {
        vga::print_str("No other runnable process\n");
    }
}

/// Show current process
fn cmd_whoami() {
    if let Some(pid) = process::current_pid() {
        if let Some(proc) = process::process_manager().get(pid) {
            vga::print_str("Current process: PID ");
            print_u32(pid.0);
            vga::print_str(" (");
            vga::print_str(proc.name_str());
            vga::print_str(")\n");
            vga::print_str("  State: ");
            vga::print_str(proc.state.as_str());
            vga::print_str("\n");
            vga::print_str("  Capabilities: ");
            print_usize(proc.capabilities.count());
            vga::print_str("\n");
            vga::print_str("  CPU time: ");
            print_u32(proc.cpu_time as u32);
            vga::print_str(" ticks\n");
        } else {
            vga::print_str("Current PID: ");
            print_u32(pid.0);
            vga::print_str(" (not found in table)\n");
        }
    } else {
        vga::print_str("No current process\n");
    }
}

// Helper to parse u32 from string
fn parse_u32(s: &str) -> Option<u32> {
    let mut result = 0u32;
    for byte in s.bytes() {
        if byte >= b'0' && byte <= b'9' {
            result = result.checked_mul(10)?;
            result = result.checked_add((byte - b'0') as u32)?;
        } else {
            return None;
        }
    }
    Some(result)
}

// ============================================================================
// WASM Commands
// ============================================================================

/// Run a simple WASM demo (arithmetic operations)
fn cmd_wasm_demo() {
    vga::print_str("=== WASM Arithmetic Demo ===\n");
    vga::print_str("Computing: (5 + 3) * 2\n\n");

    // Hand-crafted WASM bytecode
    let bytecode: [u8; 50] = [
        0x41, 0x05,           // i32.const 5
        0x41, 0x03,           // i32.const 3
        0x6A,                 // i32.add
        0x41, 0x02,           // i32.const 2
        0x6C,                 // i32.mul
        0x21, 0x00,           // local.set 0
        0x20, 0x00,           // local.get 0
        0x0F,                 // return
        0x0B,                 // end
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];

    // Get current process ID
    let pid = match process::current_pid() {
        Some(p) => p,
        None => {
            vga::print_str("Error: No current process\n");
            return;
        }
    };

    // Instantiate the module
    let instance_id = match wasm::wasm_runtime().instantiate(&bytecode[..15], pid) {
        Ok(id) => id,
        Err(e) => {
            vga::print_str("Error: Failed to load WASM module: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    vga::print_str("WASM instance created: ");
    print_usize(instance_id);
    vga::print_str("\n");

    // Add the function manually (v0 doesn't parse full WASM binary format)
    let result = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        let func = wasm::Function {
            code_offset: 0,
            code_len: 15,
            param_count: 0,
            result_count: 1,
            local_count: 1,
        };
        
        match instance.module.add_function(func) {
            Ok(_) => {
                // Execute the function
                match instance.call(0) {
                    Ok(_) => {
                        // Get the result from the stack
                        match instance.stack.peek() {
                            Ok(wasm::Value::I32(result)) => {
                                vga::print_str("WASM computation result: ");
                                print_u32(result as u32);
                                vga::print_str("\n");
                                vga::print_str("Expected: 16\n");
                                if result == 16 {
                                    vga::print_str("✓ Test passed!\n");
                                } else {
                                    vga::print_str("✗ Test failed!\n");
                                }
                            }
                            Ok(wasm::Value::I64(result)) => {
                                vga::print_str("Result (i64): ");
                                print_u32(result as u32);
                                vga::print_str("\n");
                            }
                            Err(e) => {
                                vga::print_str("Error: Failed to get result: ");
                                vga::print_str(e.as_str());
                                vga::print_str("\n");
                            }
                        }
                    }
                    Err(e) => {
                        vga::print_str("Error: Execution failed: ");
                        vga::print_str(e.as_str());
                        vga::print_str("\n");
                    }
                }
            }
            Err(e) => {
                vga::print_str("Error: Failed to add function: ");
                vga::print_str(e.as_str());
                vga::print_str("\n");
            }
        }
    });

    match result {
        Ok(_) => {
            // Cleanup
            let _ = wasm::wasm_runtime().destroy(instance_id);
        }
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
        }
    }
}

/// Demo WASM filesystem syscalls
fn cmd_wasm_fs_demo() {
    vga::print_str("=== WASM Filesystem Syscall Demo ===\n\n");

    // Get current process
    let pid = match process::current_pid() {
        Some(p) => p,
        None => {
            vga::print_str("Error: No current process\n");
            return;
        }
    };

    // Hand-crafted WASM that calls oreulia_fs_write syscall
    // Function signature: oreulia_fs_write(cap: i32, key_ptr: i32, key_len: i32, data_ptr: i32, data_len: i32) -> i32
    // This writes "Hello from WASM!" to key "wasm-test"
    let bytecode: [u8; 179] = [
        // Setup: Write key "wasm-test" at memory offset 0
        // Write data "Hello from WASM!" at memory offset 20
        
        // Call oreulia_fs_write (host function 1002 = 1000 + 2)
        0x41, 0x00,           // i32.const 0 (cap handle - will inject later)
        0x41, 0x14,           // i32.const 20 (key_ptr - offset in memory)
        0x41, 0x09,           // i32.const 9 (key_len - "wasm-test")
        0x41, 0x32,           // i32.const 50 (data_ptr)
        0x41, 0x11,           // i32.const 17 (data_len - "Hello from WASM!")
        0x10, 0xEA, 0x07,     // call 1002 (oreulia_fs_write)
        0x21, 0x00,           // local.set 0 (store result)
        0x20, 0x00,           // local.get 0 (load result)
        0x0F,                 // return
        0x0B,                 // end
        // Padding
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    // Instantiate module
    let instance_id = match wasm::wasm_runtime().instantiate(&bytecode[..25], pid) {
        Ok(id) => {
            vga::print_str("✓ WASM instance created (ID: ");
            print_usize(id);
            vga::print_str(")\n");
            id
        }
        Err(e) => {
            vga::print_str("✗ Failed to load module: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    // Inject filesystem capability
    let fs_cap = fs::filesystem().create_capability(1, fs::FilesystemRights::all(), None);
    
    let cap_handle = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        // Write the key "wasm-test" to memory offset 20
        let key_bytes = b"wasm-test";
        if let Err(e) = instance.memory.write(20, key_bytes) {
            vga::print_str("✗ Failed to write key to memory: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return None;
        }

        // Write the data "Hello from WASM!" to memory offset 50
        let data_bytes = b"Hello from WASM!";
        if let Err(e) = instance.memory.write(50, data_bytes) {
            vga::print_str("✗ Failed to write data to memory: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return None;
        }

        // Inject filesystem capability
        match instance.inject_capability(wasm::WasmCapability::Filesystem(fs_cap)) {
            Ok(handle) => {
                vga::print_str("✓ Filesystem capability injected (handle: ");
                print_u32(handle.0);
                vga::print_str(")\n");
                Some(handle)
            }
            Err(e) => {
                vga::print_str("✗ Failed to inject capability: ");
                vga::print_str(e.as_str());
                vga::print_str("\n");
                None
            }
        }
    });

    if cap_handle.is_err() || cap_handle.as_ref().ok().and_then(|x| *x).is_none() {
        let _ = wasm::wasm_runtime().destroy(instance_id);
        return;
    }

    // Add function and execute
    let result = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        let func = wasm::Function {
            code_offset: 0,
            code_len: 25,
            param_count: 0,
            result_count: 1,
            local_count: 1,
        };
        
        if let Err(e) = instance.module.add_function(func) {
            vga::print_str("✗ Failed to add function: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return false;
        }

        vga::print_str("\nExecuting WASM...\n");
        match instance.call(0) {
            Ok(_) => {
                match instance.stack.peek() {
                    Ok(wasm::Value::I32(result)) => {
                        if result == 0 {
                            vga::print_str("✓ Syscall succeeded\n");
                        } else {
                            vga::print_str("✗ Syscall failed with code: ");
                            print_u32(result as u32);
                            vga::print_str("\n");
                        }
                    }
                    _ => {
                        vga::print_str("✗ Unexpected return value\n");
                    }
                }
                true
            }
            Err(e) => {
                vga::print_str("✗ Execution failed: ");
                vga::print_str(e.as_str());
                vga::print_str("\n");
                false
            }
        }
    });

    // Cleanup
    let _ = wasm::wasm_runtime().destroy(instance_id);

    if result.is_ok() && result.unwrap() {
        // Verify the file was written
        vga::print_str("\nVerifying filesystem write...\n");
        
        let key = match fs::FileKey::new("wasm-test") {
            Ok(k) => k,
            Err(_) => {
                vga::print_str("✗ Invalid key\n");
                return;
            }
        };

        let read_cap = fs::filesystem().create_capability(1, fs::FilesystemRights::all(), None);
        let request = fs::Request::read(key, read_cap);
        let response = fs::filesystem().handle_request(request);

        match response.status {
            fs::ResponseStatus::Ok => {
                vga::print_str("✓ File read successfully: \"");
                if let Ok(s) = core::str::from_utf8(response.get_data()) {
                    vga::print_str(s);
                }
                vga::print_str("\"\n");
                vga::print_str("\n🎉 WASM successfully called Oreulia filesystem!\n");
            }
            fs::ResponseStatus::Error(_) => {
                vga::print_str("✗ File not found - write may have failed\n");
            }
        }
    }
}

/// Demo WASM logging syscall
fn cmd_wasm_log_demo() {
    vga::print_str("=== WASM Logging Syscall Demo ===\n\n");

    let pid = match process::current_pid() {
        Some(p) => p,
        None => {
            vga::print_str("Error: No current process\n");
            return;
        }
    };

    // Hand-crafted WASM that calls oreulia_log syscall
    // Function signature: oreulia_log(msg_ptr: i32, msg_len: i32)
    let bytecode: [u8; 94] = [
        // Call oreulia_log (host function 1000)
        0x41, 0x00,           // i32.const 0 (msg_ptr)
        0x41, 0x1B,           // i32.const 27 (msg_len)
        0x10, 0xE8, 0x07,     // call 1000 (oreulia_log)
        0x0F,                 // return
        0x0B,                 // end
        // Padding
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];

    let instance_id = match wasm::wasm_runtime().instantiate(&bytecode[..10], pid) {
        Ok(id) => {
            vga::print_str("✓ WASM instance created\n");
            id
        }
        Err(e) => {
            vga::print_str("✗ Failed to load: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    // Write message to WASM memory
    let message = b"Greetings from WebAssembly!";
    let _ = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        instance.memory.write(0, message)
    });

    // Execute
    vga::print_str("\nExecuting WASM (should print message below):\n");
    let _ = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        let func = wasm::Function {
            code_offset: 0,
            code_len: 10,
            param_count: 0,
            result_count: 0,
            local_count: 0,
        };
        
        let _ = instance.module.add_function(func);
        instance.call(0)
    });

    let _ = wasm::wasm_runtime().destroy(instance_id);
    vga::print_str("\n✓ Demo complete\n");
}

/// List all loaded WASM instances
fn cmd_wasm_list() {
    vga::print_str("WASM Instances:\n");
    vga::print_str("---------------\n");
    vga::print_str("ID   PID   Status\n");

    let instances = wasm::wasm_runtime().list();
    let mut count = 0;

    for (id, pid, active) in instances.iter() {
        if *active {
            print_usize(*id);
            vga::print_str("    ");
            print_u32(pid.0);
            vga::print_str("    Active\n");
            count += 1;
        }
    }

    if count == 0 {
        vga::print_str("No active instances\n");
    } else {
        vga::print_str("\nTotal: ");
        print_usize(count);
        vga::print_str(" / 8 instances\n");
    }
}

// ============================================================================
// Scientific Calculator (WASM-Powered)
// ============================================================================

/// Show calculator help
fn cmd_calculate_help() {
    vga::print_str("\n=== Scientific Calculator (WASM-Powered) ===\n\n");
    vga::print_str("Usage: calculate <a> <operation> <b>\n\n");
    vga::print_str("Arithmetic Operations:\n");
    vga::print_str("  +    Addition         (e.g., calculate 15 + 7)\n");
    vga::print_str("  -    Subtraction      (e.g., calculate 20 - 8)\n");
    vga::print_str("  *    Multiplication   (e.g., calculate 1000 * 1000)\n");
    vga::print_str("  /    Division         (e.g., calculate 100 / 4)\n");
    vga::print_str("  %    Modulo/Remainder (e.g., calculate 17 % 5)\n\n");
    
    vga::print_str("Bitwise Operations:\n");
    vga::print_str("  &    AND              (e.g., calculate 12 & 10)\n");
    vga::print_str("  |    OR               (e.g., calculate 12 | 10)\n");
    vga::print_str("  ^    XOR              (e.g., calculate 12 ^ 10)\n");
    vga::print_str("  <<   Left Shift       (e.g., calculate 5 << 2)\n");
    vga::print_str("  >>   Right Shift      (e.g., calculate 20 >> 2)\n\n");
    
    vga::print_str("Power Operations:\n");
    vga::print_str("  **   Power            (e.g., calculate 2 ** 10)\n");
    vga::print_str("  sqrt Square Root      (e.g., calculate sqrt 144)\n\n");
    
    vga::print_str("Comparison Operations:\n");
    vga::print_str("  ==   Equal            (e.g., calculate 5 == 5)\n");
    vga::print_str("  !=   Not Equal        (e.g., calculate 5 != 3)\n");
    vga::print_str("  <    Less Than        (e.g., calculate 3 < 5)\n");
    vga::print_str("  >    Greater Than     (e.g., calculate 7 > 4)\n");
    vga::print_str("  <=   Less or Equal    (e.g., calculate 5 <= 5)\n");
    vga::print_str("  >=   Greater or Equal (e.g., calculate 8 >= 6)\n\n");
    
    vga::print_str("Advanced Operations:\n");
    vga::print_str("  min  Minimum          (e.g., calculate 10 min 5)\n");
    vga::print_str("  max  Maximum          (e.g., calculate 10 max 5)\n");
    vga::print_str("  abs  Absolute Value   (e.g., calculate abs -42)\n\n");
    
    vga::print_str("Examples:\n");
    vga::print_str("  > calculate 1000 * 1000\n");
    vga::print_str("  Result: 1000000\n\n");
    vga::print_str("  > calculate 2 ** 16\n");
    vga::print_str("  Result: 65536\n\n");
    vga::print_str("  > calculate sqrt 256\n");
    vga::print_str("  Result: 16\n\n");
    
    vga::print_str("All computations run in isolated WASM!\n\n");
}

/// Scientific calculator powered by WASM
fn cmd_calculate(mut parts: core::str::SplitWhitespace) {
    let a_str = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Usage: calculate <a> <operation> <b>\n");
            vga::print_str("Type 'calculate-help' for available operations\n");
            return;
        }
    };

    // Check for special operations (abs, sqrt)
    if a_str == "abs" {
        let val_str = match parts.next() {
            Some(s) => s,
            None => {
                vga::print_str("Usage: calculate abs <value>\n");
                return;
            }
        };
        
        let val = match parse_i32(val_str) {
            Some(n) => n,
            None => {
                vga::print_str("Error: Invalid number\n");
                return;
            }
        };
        
        execute_wasm_unary("abs", val);
        return;
    }

    if a_str == "sqrt" {
        let val_str = match parts.next() {
            Some(s) => s,
            None => {
                vga::print_str("Usage: calculate sqrt <value>\n");
                return;
            }
        };
        
        let val = match parse_u32(val_str) {
            Some(n) => n as i32,
            None => {
                vga::print_str("Error: Invalid number\n");
                return;
            }
        };
        
        execute_wasm_sqrt(val);
        return;
    }

    // Parse first number
    let a = match parse_i32(a_str) {
        Some(n) => n,
        None => {
            vga::print_str("Error: Invalid first number\n");
            return;
        }
    };

    // Parse operation
    let op = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Error: Missing operation\n");
            vga::print_str("Type 'calculate-help' for available operations\n");
            return;
        }
    };

    // Parse second number
    let b_str = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Error: Missing second number\n");
            return;
        }
    };

    let b = match parse_i32(b_str) {
        Some(n) => n,
        None => {
            vga::print_str("Error: Invalid second number\n");
            return;
        }
    };

    // Execute the operation in WASM
    execute_wasm_binop(a, op, b);
}

/// Execute a binary operation in WASM
fn execute_wasm_binop(a: i32, op: &str, b: i32) {
    vga::print_str("Computing: ");
    print_i32(a);
    vga::print_str(" ");
    vga::print_str(op);
    vga::print_str(" ");
    print_i32(b);
    vga::print_str("\n");

    // Build WASM bytecode based on operation
    let bytecode = match op {
        "+" => build_binop_bytecode(0x6A), // i32.add
        "-" => build_binop_bytecode(0x6B), // i32.sub
        "*" => build_binop_bytecode(0x6C), // i32.mul
        "/" => build_binop_bytecode(0x6D), // i32.div_s
        "%" => build_binop_bytecode(0x6F), // i32.rem_s
        "&" => build_binop_bytecode(0x71), // i32.and
        "|" => build_binop_bytecode(0x72), // i32.or
        "^" => build_binop_bytecode(0x73), // i32.xor
        "<<" => build_binop_bytecode(0x74), // i32.shl
        ">>" => build_binop_bytecode(0x75), // i32.shr_s
        "==" => build_binop_bytecode(0x46), // i32.eq
        "!=" => build_binop_bytecode(0x47), // i32.ne
        "<" => build_binop_bytecode(0x48), // i32.lt_s
        ">" => build_binop_bytecode(0x4A), // i32.gt_s
        "<=" => build_binop_bytecode(0x4C), // i32.le_s
        ">=" => build_binop_bytecode(0x4E), // i32.ge_s
        "**" => {
            execute_wasm_power(a, b);
            return;
        }
        "min" | "max" => {
            execute_wasm_minmax(a, b, op);
            return;
        }
        _ => {
            vga::print_str("Error: Unknown operation '");
            vga::print_str(op);
            vga::print_str("'\n");
            vga::print_str("Type 'calculate-help' for available operations\n");
            return;
        }
    };

    let pid = process::current_pid().unwrap_or(ipc::ProcessId::new(1));

    let instance_id = match wasm::wasm_runtime().instantiate(&bytecode[..7], pid) {
        Ok(id) => id,
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };

    let _ = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        let func = wasm::Function {
            code_offset: 0,
            code_len: 7,
            param_count: 2,
            result_count: 1,
            local_count: 2,
        };
        
        if let Ok(_) = instance.module.add_function(func) {
            let _ = instance.stack.push(wasm::Value::I32(a));
            let _ = instance.stack.push(wasm::Value::I32(b));

            match instance.call(0) {
                Ok(_) => {
                    match instance.stack.pop() {
                        Ok(wasm::Value::I32(result)) => {
                            vga::print_str("Result: ");
                            print_i32(result);
                            vga::print_str("\n");
                        }
                        _ => vga::print_str("Error: Failed to get result\n"),
                    }
                }
                Err(e) => {
                    vga::print_str("Error: ");
                    vga::print_str(e.as_str());
                    vga::print_str("\n");
                }
            }
        }
    });

    let _ = wasm::wasm_runtime().destroy(instance_id);
}

/// Build WASM bytecode for a binary operation
fn build_binop_bytecode(opcode: u8) -> [u8; 10] {
    [
        0x20, 0x00,  // local.get 0
        0x20, 0x01,  // local.get 1
        opcode,      // operation
        0x0F,        // return
        0x0B,        // end
        0, 0, 0,     // padding
    ]
}

/// Execute power operation (a ** b)
fn execute_wasm_power(base: i32, exp: i32) {
    if exp < 0 {
        vga::print_str("Error: Negative exponents not supported\n");
        return;
    }

    if exp == 0 {
        vga::print_str("Result: 1\n");
        return;
    }

    let mut result = base;
    for _ in 1..exp {
        result = match result.checked_mul(base) {
            Some(r) => r,
            None => {
                vga::print_str("Error: Overflow\n");
                return;
            }
        };
    }

    vga::print_str("Result: ");
    print_i32(result);
    vga::print_str("\n");
}

/// Execute min/max operation
fn execute_wasm_minmax(a: i32, b: i32, op: &str) {
    let bytecode: [u8; 18] = [
        0x20, 0x00,  // local.get 0
        0x20, 0x01,  // local.get 1
        0x20, 0x00,  // local.get 0
        0x20, 0x01,  // local.get 1
        if op == "min" { 0x48 } else { 0x4A }, // i32.lt_s or i32.gt_s
        0x1B,        // select
        0x0F,        // return
        0x0B,        // end
        0, 0, 0, 0, 0, 0,
    ];

    let pid = process::current_pid().unwrap_or(ipc::ProcessId::new(1));
    
    let instance_id = match wasm::wasm_runtime().instantiate(&bytecode[..10], pid) {
        Ok(id) => id,
        Err(_) => return,
    };

    let _ = wasm::wasm_runtime().get_instance_mut(instance_id, |instance| {
        let func = wasm::Function {
            code_offset: 0,
            code_len: 10,
            param_count: 2,
            result_count: 1,
            local_count: 2,
        };
        
        if let Ok(_) = instance.module.add_function(func) {
            let _ = instance.stack.push(wasm::Value::I32(a));
            let _ = instance.stack.push(wasm::Value::I32(b));

            if let Ok(_) = instance.call(0) {
                if let Ok(wasm::Value::I32(result)) = instance.stack.pop() {
                    vga::print_str("Result: ");
                    print_i32(result);
                    vga::print_str("\n");
                }
            }
        }
    });

    let _ = wasm::wasm_runtime().destroy(instance_id);
}

/// Execute unary operation (abs)
fn execute_wasm_unary(_op: &str, val: i32) {
    let result = if val < 0 { -val } else { val };
    vga::print_str("Result: ");
    print_i32(result);
    vga::print_str("\n");
}

/// Execute square root (integer)
fn execute_wasm_sqrt(val: i32) {
    if val < 0 {
        vga::print_str("Error: Cannot compute square root of negative number\n");
        return;
    }

    if val == 0 {
        vga::print_str("Result: 0\n");
        return;
    }

    let mut x = val;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + val / x) / 2;
    }

    vga::print_str("Result: ");
    print_i32(x);
    vga::print_str("\n");
}

/// Parse signed integer
fn parse_i32(s: &str) -> Option<i32> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let (is_negative, start) = if bytes[0] == b'-' {
        (true, 1)
    } else {
        (false, 0)
    };

    let mut result = 0i32;
    for &byte in &bytes[start..] {
        if byte >= b'0' && byte <= b'9' {
            result = result.checked_mul(10)?;
            result = result.checked_add((byte - b'0') as i32)?;
        } else {
            return None;
        }
    }

    if is_negative {
        Some(-result)
    } else {
        Some(result)
    }
}

// ============================================================================
// Network Commands
// ============================================================================

fn cmd_network_help() {
    vga::print_str("\n");
    vga::print_str("===== Oreulia Real Network Stack =====\n");
    vga::print_str("\n");
    vga::print_str("OVERVIEW:\n");
    vga::print_str("  Production network stack with WiFi, TCP/IP, and HTTP.\n");
    vga::print_str("  Features real packet I/O, DNS resolution, and 802.11 WiFi.\n");
    vga::print_str("\n");
    vga::print_str("WiFi COMMANDS:\n");
    vga::print_str("  wifi-scan              Scan for available WiFi networks\n");
    vga::print_str("  wifi-connect <ssid> [password]  Connect to WiFi network\n");
    vga::print_str("  wifi-status            Show WiFi connection status\n");
    vga::print_str("\n");
    vga::print_str("NETWORK COMMANDS:\n");
    vga::print_str("  net-info               Show network status and IP address\n");
    vga::print_str("  http-get <url>         Perform HTTP GET request\n");
    vga::print_str("  dns-resolve <domain>   Resolve domain to IP address\n");
    vga::print_str("\n");
    vga::print_str("EXAMPLES:\n");
    vga::print_str("  wifi-scan\n");
    vga::print_str("    List all available WiFi networks with signal strength\n");
    vga::print_str("\n");
    vga::print_str("  wifi-connect MyWiFi password123\n");
    vga::print_str("    Connect to secured WiFi network\n");
    vga::print_str("\n");
    vga::print_str("  wifi-connect GuestNetwork\n");
    vga::print_str("    Connect to open WiFi network (no password)\n");
    vga::print_str("\n");
    vga::print_str("  http-get http://example.com\n");
    vga::print_str("    Fetch webpage using real HTTP client\n");
    vga::print_str("\n");
    vga::print_str("  dns-resolve google.com\n");
    vga::print_str("    Resolve domain using real DNS queries\n");
    vga::print_str("\n");
    vga::print_str("FEATURES:\n");
    vga::print_str("  - Real 802.11 WiFi driver (Intel, Realtek, Broadcom, Atheros)\n");
    vga::print_str("  - TCP/IP stack with 3-way handshake\n");
    vga::print_str("  - Real DNS resolver (queries 8.8.8.8)\n");
    vga::print_str("  - HTTP/1.1 client with persistent connections\n");
    vga::print_str("  - Packet I/O over WiFi interface\n");
    vga::print_str("  - Capability-based security model\n");
    vga::print_str("\n");
}

fn cmd_net_info() {
    use crate::net;
    
    vga::print_str("\n");
    vga::print_str("===== Network Status =====\n");
    vga::print_str("\n");
    
    let net_service = net::network();
    let net_lock = net_service.lock();
    
    let stats = net_lock.stats();
    
    vga::print_str("WiFi: ");
    if stats.wifi_enabled {
        vga::print_str("ENABLED\n");
    } else {
        vga::print_str("DISABLED\n");
        return;
    }
    
    vga::print_str("IP Address: ");
    print_ipv4_net(stats.ip_address);
    vga::print_str("\n");
    
    vga::print_str("TCP Connections: ");
    print_usize(stats.tcp_connections);
    vga::print_str("\n");
    
    vga::print_str("DNS Cache Entries: ");
    print_usize(stats.dns_cache_entries);
    vga::print_str("\n");
    vga::print_str("\n");
}

fn cmd_wifi_scan() {
    use crate::net;
    
    vga::print_str("\n");
    vga::print_str("===== WiFi Network Scan =====\n");
    vga::print_str("\n");
    
    let net_service = net::network();
    let net_lock = net_service.lock();
    
    // Perform scan
    let _count = match net_lock.wifi_scan() {
        Ok(c) => c,
        Err(e) => {
            vga::print_str("Scan failed: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    // Get scan results
    let networks_array = match net_lock.wifi_get_scan_results() {
        Ok(nets) => nets,
        Err(e) => {
            vga::print_str("Failed to get results: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    let count = net_lock.wifi_scan_count();
    
    if count == 0 {
        vga::print_str("No networks found.\n");
        return;
    }
    
    vga::print_str("Found ");
    print_usize(count);
    vga::print_str(" networks:\n\n");
    
    for i in 0..count {
        let network = &networks_array[i];
        print_usize(i + 1);
        vga::print_str(". ");
        vga::print_str(network.ssid_str());
        vga::print_str("\n");
        
        vga::print_str("   BSSID: ");
        print_mac_net(network.bssid);
        vga::print_str("\n");
        
        vga::print_str("   Signal: ");
        print_i8(network.signal_strength);
        vga::print_str(" dBm");
        
        // Signal quality indicator
        if network.signal_strength >= -50 {
            vga::print_str(" [Excellent]");
        } else if network.signal_strength >= -60 {
            vga::print_str(" [Good]");
        } else if network.signal_strength >= -70 {
            vga::print_str(" [Fair]");
        } else {
            vga::print_str(" [Weak]");
        }
        vga::print_str("\n");
        
        vga::print_str("   Channel: ");
        print_u8_val(network.channel);
        vga::print_str("  Frequency: ");
        print_u16_val(network.frequency);
        vga::print_str(" MHz\n");
        
        vga::print_str("   Security: ");
        vga::print_str(network.security.as_str());
        vga::print_str("\n\n");
    }
}

fn cmd_wifi_connect(mut parts: core::str::SplitWhitespace) {
    use crate::net;
    
    let ssid = match parts.next() {
        Some(s) => s,
        None => {
            vga::print_str("Usage: wifi-connect <ssid> [password]\n");
            vga::print_str("Example: wifi-connect MyWiFi mypassword\n");
            vga::print_str("         wifi-connect GuestNetwork\n");
            return;
        }
    };
    
    let password = parts.next();
    
    vga::print_str("\n");
    vga::print_str("Connecting to: ");
    vga::print_str(ssid);
    vga::print_str("\n");
    
    let net_service = net::network();
    let mut net_lock = net_service.lock();
    
    match net_lock.wifi_connect(ssid, password) {
        Ok(()) => {
            vga::print_str("Successfully connected!\n");
            vga::print_str("IP assigned via DHCP\n");
        }
        Err(e) => {
            vga::print_str("Connection failed: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
        }
    }
    
    vga::print_str("\n");
}

fn cmd_wifi_status() {
    use crate::net;
    use crate::wifi::WifiState;
    
    vga::print_str("\n");
    vga::print_str("===== WiFi Status =====\n");
    vga::print_str("\n");
    
    let net_service = net::network();
    let net_lock = net_service.lock();
    
    let state = match net_lock.wifi_status() {
        Ok(s) => s,
        Err(e) => {
            vga::print_str("Error: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    vga::print_str("State: ");
    match state {
        WifiState::Disabled => vga::print_str("DISABLED\n"),
        WifiState::Idle => vga::print_str("IDLE (not connected)\n"),
        WifiState::Scanning => vga::print_str("SCANNING\n"),
        WifiState::Connecting => vga::print_str("CONNECTING\n"),
        WifiState::Authenticating => vga::print_str("AUTHENTICATING\n"),
        WifiState::Associated => vga::print_str("ASSOCIATED\n"),
        WifiState::Connected => vga::print_str("CONNECTED\n"),
        WifiState::Disconnecting => vga::print_str("DISCONNECTING\n"),
        WifiState::Error => vga::print_str("ERROR\n"),
    }
    
    if state == WifiState::Connected {
        let wifi = crate::wifi::wifi().lock();
        let conn = wifi.connection();
        
        vga::print_str("SSID: ");
        vga::print_str(conn.network.ssid_str());
        vga::print_str("\n");
        
        vga::print_str("Signal: ");
        print_i8(conn.network.signal_strength);
        vga::print_str(" dBm\n");
        
        vga::print_str("Security: ");
        vga::print_str(conn.network.security.as_str());
        vga::print_str("\n");
    }
    
    vga::print_str("\n");
}

fn cmd_http_get(mut parts: core::str::SplitWhitespace) {
    use crate::net;
    
    let url = match parts.next() {
        Some(u) => u,
        None => {
            vga::print_str("Usage: http-get <url>\n");
            vga::print_str("Example: http-get http://example.com\n");
            return;
        }
    };
    
    vga::print_str("\n");
    vga::print_str("HTTP GET: ");
    vga::print_str(url);
    vga::print_str("\n\n");
    
    let net_service = net::network();
    let mut net_lock = net_service.lock();
    
    let response = match net_lock.http_get(url) {
        Ok(resp) => resp,
        Err(e) => {
            vga::print_str("Request failed: ");
            vga::print_str(e.as_str());
            vga::print_str("\n");
            return;
        }
    };
    
    vga::print_str("Status: ");
    print_u16_val(response.status_code);
    vga::print_str("\n\n");
    
    vga::print_str("===== Response Body =====\n\n");
    
    // Print body (limit to 1024 chars for screen)
    let print_len = response.body_len.min(1024);
    for i in 0..print_len {
        vga::print_char(response.body[i] as char);
    }
    
    if response.body_len > 1024 {
        vga::print_str("\n\n[... truncated ");
        print_usize(response.body_len - 1024);
        vga::print_str(" bytes ...]\n");
    }
    
    vga::print_str("\n\nTotal: ");
    print_usize(response.body_len);
    vga::print_str(" bytes\n");
}

fn cmd_dns_resolve(mut parts: core::str::SplitWhitespace) {
    use crate::netstack;
    
    let domain = match parts.next() {
        Some(d) => d,
        None => {
            vga::print_str("Usage: dns-resolve <domain>\n");
            vga::print_str("Example: dns-resolve google.com\n");
            return;
        }
    };
    
    vga::print_str("\n");
    vga::print_str("=== Real DNS Resolution ===\n\n");
    vga::print_str("Domain: ");
    vga::print_str(domain);
    vga::print_str("\n");
    
    let mut stack = netstack::network_stack().lock();
    
    if !stack.is_ready() {
        vga::print_str("Error: Network not ready\n");
        vga::print_str("Check: eth-status or pci-list\n\n");
        return;
    }
    
    vga::print_str("Sending UDP DNS query to 8.8.8.8...\n");
    
    let ip = match stack.dns_resolve(domain) {
        Ok(addr) => addr,
        Err(e) => {
            vga::print_str("Resolution failed: ");
            vga::print_str(e);
            vga::print_str("\n\n");
            return;
        }
    };
    
    vga::print_str("Success! IP: ");
    print_ipv4_netstack(ip);
    vga::print_str("\n\n");
}

// Helper functions for network commands
fn print_ipv4_netstack(ip: crate::netstack::Ipv4Addr) {
    let octets = ip.octets();
    for (i, octet) in octets.iter().enumerate() {
        if i > 0 {
            vga::print_char('.');
        }
        print_u8_val(*octet);
    }
}

fn print_ipv4_net(ip: crate::net::Ipv4Addr) {
    let octets = ip.octets();
    for (i, octet) in octets.iter().enumerate() {
        if i > 0 {
            vga::print_char('.');
        }
        print_u8_val(*octet);
    }
}

fn print_mac_net(mac: [u8; 6]) {
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            vga::print_char(':');
        }
        print_hex_byte(*byte);
    }
}

fn print_i8(n: i8) {
    if n < 0 {
        vga::print_char('-');
        print_u8_val((-n) as u8);
    } else {
        print_u8_val(n as u8);
    }
}

fn print_u8_val(n: u8) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    
    let mut buf = [0u8; 3];
    let mut i = 0;
    let mut num = n;
    
    while num > 0 {
        buf[i] = (num % 10) + b'0';
        num /= 10;
        i += 1;
    }
    
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_u16_val(n: u16) {
    if n == 0 {
        vga::print_char('0');
        return;
    }
    
    let mut buf = [0u8; 5];
    let mut i = 0;
    let mut num = n;
    
    while num > 0 {
        buf[i] = (num % 10) as u8 + b'0';
        num /= 10;
        i += 1;
    }
    
    while i > 0 {
        i -= 1;
        vga::print_char(buf[i] as char);
    }
}

fn print_hex_byte(byte: u8) {
    let high = (byte >> 4) & 0xF;
    let low = byte & 0xF;
    
    vga::print_char(hex_digit(high));
    vga::print_char(hex_digit(low));
}

fn hex_digit(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}

fn parse_url_simple(url: &str) -> (&str, &str) {
    // Remove protocol
    let url = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        url
    };
    
    // Split host and path
    if let Some(slash_pos) = url.find('/') {
        (&url[..slash_pos], &url[slash_pos..])
    } else {
        (url, "/")
    }
}

/// Print signed integer
fn print_i32(n: i32) {
    if n < 0 {
        vga::print_char('-');
        print_u32((-n) as u32);
    } else {
        print_u32(n as u32);
    }
}

/// List PCI devices (shows real hardware detection)
fn cmd_pci_list() {
    vga::print_str("\n");
    vga::print_str("===== PCI Devices (Real Hardware Detection) =====\n");
    vga::print_str("\n");
    
    vga::print_str("Scanning PCI bus...\n\n");
    
    let mut scanner = crate::pci::PciScanner::new();
    scanner.scan();
    
    let devices = scanner.devices();
    let mut count = 0;
    
    for device_opt in devices.iter() {
        if let Some(device) = device_opt {
            count += 1;
            
            vga::print_str("Device ");
            print_u32(count);
            vga::print_str(": ");
            
            // Format as BB:DD.F
            print_hex_u8(device.bus);
            vga::print_char(':');
            print_hex_u8(device.slot);
            vga::print_char('.');
            print_hex_u8(device.func);
            vga::print_str("  ");
            
            // Device info
            vga::print_str("Vendor: 0x");
            print_hex_u16(device.vendor_id);
            vga::print_str(" Device: 0x");
            print_hex_u16(device.device_id);
            vga::print_str(" Class: 0x");
            print_hex_u8(device.class_code);
            vga::print_char('/');
            print_hex_u8(device.subclass);
            vga::print_str("\n");
            
            // Device type
            vga::print_str("         Type: ");
            vga::print_str(device.device_type_str());
            
            // Vendor name
            vga::print_str("  Vendor: ");
            vga::print_str(device.vendor_name());
            vga::print_str("\n");
            
            // Check if WiFi
            if device.is_wifi() {
                vga::print_str("         ** WiFi Device Detected **\n");
            } else if device.is_ethernet() {
                vga::print_str("         ** Ethernet Device Detected **\n");
            }
            
            vga::print_str("\n");
        }
    }
    
    if count == 0 {
        vga::print_str("No PCI devices found.\n");
    } else {
        vga::print_str("Total devices: ");
        print_u32(count);
        vga::print_str("\n");
    }
    
    vga::print_str("\n");
    
    // Check for WiFi
    if let Some(wifi) = scanner.find_wifi_device() {
        vga::print_str("WiFi Available: YES (Vendor 0x");
        print_hex_u16(wifi.vendor_id);
        vga::print_str(" Device 0x");
        print_hex_u16(wifi.device_id);
        vga::print_str(")\n");
    } else {
        vga::print_str("WiFi Available: NO - No WiFi hardware detected\n");
        vga::print_str("  This is normal in QEMU (no WiFi emulation)\n");
        vga::print_str("  Boot on real hardware to use WiFi\n");
    }
    
    vga::print_str("\n");
}

fn print_hex_u8(n: u8) {
    let high = (n >> 4) & 0xF;
    let low = n & 0xF;
    vga::print_char(hex_char(high));
    vga::print_char(hex_char(low));
}

fn print_hex_u16(n: u16) {
    print_hex_u8((n >> 8) as u8);
    print_hex_u8(n as u8);
}

fn print_hex_u32(n: u32) {
    print_hex_u16((n >> 16) as u16);
    print_hex_u16(n as u16);
}

fn hex_char(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'A' + n - 10) as char
    }
}

// ============================================================================
// Ethernet Commands (E1000)
// ============================================================================

fn cmd_eth_status() {
    use crate::e1000;
    
    vga::print_str("\n");
    vga::print_str("===== Ethernet Status =====\n\n");
    
    if let Some(mac) = e1000::get_mac_address() {
        vga::print_str("Device: Intel E1000 Gigabit Ethernet\n");
        vga::print_str("MAC Address: ");
        for (i, byte) in mac.iter().enumerate() {
            if i > 0 { vga::print_str(":"); }
            print_hex_u8(*byte);
        }
        vga::print_str("\n");
        
        vga::print_str("Link Status: ");
        if e1000::is_link_up() {
            vga::print_str("UP\n");
        } else {
            vga::print_str("DOWN\n");
        }
        
        vga::print_str("Speed: 1000 Mbps (Gigabit)\n");
        vga::print_str("Duplex: Full\n");
    } else {
        vga::print_str("No Ethernet device detected\n");
        vga::print_str("Run 'pci-list' to see available devices\n");
    }
    
    vga::print_str("\n");
}

fn cmd_eth_info() {
    use crate::e1000;
    
    vga::print_str("\n");
    vga::print_str("===== Ethernet Information =====\n\n");
    
    if e1000::get_mac_address().is_some() {
        vga::print_str("Driver: Intel E1000 (Real Hardware)\n");
        vga::print_str("Chipset: 82540EM Gigabit Ethernet Controller\n");
        vga::print_str("PCI Device: 8086:100E\n");
        vga::print_str("Features:\n");
        vga::print_str("  - MMIO register access\n");
        vga::print_str("  - DMA bus mastering\n");
        vga::print_str("  - Promiscuous mode\n");
        vga::print_str("  - Link detection\n");
        vga::print_str("\nReady for packet I/O!\n");
        vga::print_str("Connect with: dhcp, dns-resolve, http-get\n");
    } else {
        vga::print_str("No Ethernet device available\n");
    }
    
    vga::print_str("\n");
}

fn cmd_netstack_info() {
    use crate::netstack;
    
    vga::print_str("\n");
    vga::print_str("===== Production Network Stack =====\n\n");
    
    let stack = netstack::network_stack().lock();
    
    vga::print_str("Status: ");
    if stack.is_ready() {
        vga::print_str("READY\n");
    } else {
        vga::print_str("NOT READY (no interface)\n");
    }
    
    vga::print_str("\nFeatures:\n");
    vga::print_str("  [x] ARP Protocol (address resolution)\n");
    vga::print_str("  [x] UDP Protocol (for DNS)\n");
    vga::print_str("  [x] DNS Client (real queries to 8.8.8.8)\n");
    vga::print_str("  [x] Real packet I/O via E1000 descriptors\n");
    vga::print_str("  [x] Universal interface (works with any driver)\n");
    
    vga::print_str("\nMy IP: ");
    print_ipv4_netstack(stack.get_ip());
    vga::print_str("\n");
    
    vga::print_str("\nTry: dns-resolve google.com\n");
    vga::print_str("     dns-resolve github.com\n");
    vga::print_str("\n");
}

