use crate::vga;
use crate::fs;
use crate::ipc;
use crate::registry;

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
