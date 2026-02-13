//! Console Service with Capability-Based Access Control
//!
//! Unlike POSIX/Unix/Linux/NT where stdout/stderr are ambient resources
//! available to all processes, Oreulia requires explicit Console capabilities.
//!
//! This eliminates ambient authority and makes I/O explicit in the capability graph.

use crate::capability::{
    capability_manager, OreuliaCapability, CapabilityType, Rights, CapabilityError
};
use crate::ipc::ProcessId;
use crate::vga;
use spin::Mutex;

// ============================================================================
// Console Object Management
// ============================================================================

const MAX_CONSOLES: usize = 16;

/// A console represents an output stream
#[derive(Debug, Clone, Copy)]
struct Console {
    object_id: u64,
    owner: ProcessId,
    write_count: u64,
    read_count: u64,
}

impl Console {
    fn new(object_id: u64, owner: ProcessId) -> Self {
        Console {
            object_id,
            owner,
            write_count: 0,
            read_count: 0,
        }
    }
    
    /// Validate that the given process ID owns this console
    fn validate_owner(&self, pid: ProcessId) -> bool {
        self.owner == pid
    }
    
    /// Check if process has access to this console
    fn check_access(&self, pid: ProcessId) -> Result<(), &'static str> {
        if !self.validate_owner(pid) {
            return Err("Access denied: not console owner");
        }
        Ok(())
    }
}

struct ConsoleRegistry {
    consoles: [Option<Console>; MAX_CONSOLES],
}

impl ConsoleRegistry {
    const fn new() -> Self {
        ConsoleRegistry {
            consoles: [None; MAX_CONSOLES],
        }
    }
    
    fn register(&mut self, console: Console) -> Result<(), ConsoleError> {
        for slot in self.consoles.iter_mut() {
            if slot.is_none() {
                *slot = Some(console);
                return Ok(());
            }
        }
        Err(ConsoleError::RegistryFull)
    }
    
    fn lookup_mut(&mut self, object_id: u64) -> Option<&mut Console> {
        self.consoles
            .iter_mut()
            .find(|c| c.as_ref().map_or(false, |con| con.object_id == object_id))
            .and_then(|c| c.as_mut())
    }
}

static CONSOLE_REGISTRY: Mutex<ConsoleRegistry> = Mutex::new(ConsoleRegistry::new());

// ============================================================================
// Console Service API
// ============================================================================

/// Create a console and grant capability to owner
pub fn create_console(owner: ProcessId) -> Result<u32, ConsoleError> {
    vga::print_str("[CONSOLE-DEBUG] create_console start\n");
    // Create kernel object
    let object_id = capability_manager().create_object();
    vga::print_str("[CONSOLE-DEBUG] object created\n");
    let console = Console::new(object_id, owner);
    
    // Register console
    vga::print_str("[CONSOLE-DEBUG] registering console\n");
    CONSOLE_REGISTRY.lock().register(console)?;
    vga::print_str("[CONSOLE-DEBUG] registered\n");
    
    // Grant capability to owner with write rights
    let rights = Rights::new(Rights::CONSOLE_WRITE | Rights::CONSOLE_READ);
    vga::print_str("[CONSOLE-DEBUG] granting capability\n");
    let cap_id = capability_manager()
        .grant_capability(owner, object_id, CapabilityType::Console, rights, owner)
        .map_err(|_| ConsoleError::CapabilityFailed)?;
    vga::print_str("[CONSOLE-DEBUG] capability granted\n");
    
    Ok(cap_id)
}

/// Write to console (requires CONSOLE_WRITE capability)
pub fn console_write(
    pid: ProcessId,
    cap_id: u32,
    data: &[u8],
) -> Result<usize, ConsoleError> {
    // Verify capability
    let object_id = capability_manager()
        .verify_and_get_object(pid, cap_id, CapabilityType::Console, Rights::CONSOLE_WRITE)
        .map_err(|e| ConsoleError::CapabilityDenied(e))?;
    
    // Lookup console
    let mut registry = CONSOLE_REGISTRY.lock();
    let console = registry.lookup_mut(object_id)
        .ok_or(ConsoleError::InvalidConsole)?;
    
    // Validate owner has access
    console.check_access(pid).map_err(|_| ConsoleError::AccessDenied)?;
    
    // Write to VGA (actual output)
    for &byte in data {
        if byte == b'\n' {
            vga::print_char('\n');
        } else if byte >= 32 && byte < 127 {
            vga::print_char(byte as char);
        }
    }
    
    // Update statistics
    console.write_count += data.len() as u64;
    
    Ok(data.len())
}

/// Read from console (requires CONSOLE_READ capability)
/// Note: Currently not implemented (keyboard is direct)
pub fn console_read(
    pid: ProcessId,
    cap_id: u32,
    _buffer: &mut [u8],
) -> Result<usize, ConsoleError> {
    // Verify capability
    let _object_id = capability_manager()
        .verify_and_get_object(pid, cap_id, CapabilityType::Console, Rights::CONSOLE_READ)
        .map_err(|e| ConsoleError::CapabilityDenied(e))?;
    
    // TODO: Implement keyboard input queue
    Err(ConsoleError::NotImplemented)
}

/// Get console statistics (for debugging)
pub fn console_stats(pid: ProcessId, cap_id: u32) -> Result<(u64, u64), ConsoleError> {
    // Verify capability (any right allows stats)
    let object_id = capability_manager()
        .verify_and_get_object(pid, cap_id, CapabilityType::Console, Rights::CONSOLE_WRITE | Rights::CONSOLE_READ)
        .map_err(|e| ConsoleError::CapabilityDenied(e))?;
    
    let registry = CONSOLE_REGISTRY.lock();
    let console = registry.consoles
        .iter()
        .find(|c| c.as_ref().map_or(false, |con| con.object_id == object_id))
        .and_then(|c| c.as_ref())
        .ok_or(ConsoleError::InvalidConsole)?;
    
    Ok((console.write_count, console.read_count))
}

/// Validate a capability structure (used for IPC capability transfer)
pub fn validate_console_capability(cap: &OreuliaCapability) -> Result<(), ConsoleError> {
    // Check type matches
    if cap.cap_type != CapabilityType::Console {
        return Err(ConsoleError::InvalidConsole);
    }
    
    // Verify the console object exists
    let registry = CONSOLE_REGISTRY.lock();
    if !registry.consoles.iter().any(|c| c.as_ref().map_or(false, |con| con.object_id == cap.object_id)) {
        return Err(ConsoleError::InvalidConsole);
    }
    
    Ok(())
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum ConsoleError {
    RegistryFull,
    InvalidConsole,
    CapabilityFailed,
    CapabilityDenied(CapabilityError),
    NotImplemented,
    AccessDenied,
}

impl ConsoleError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConsoleError::RegistryFull => "Console registry full",
            ConsoleError::InvalidConsole => "Invalid console object",
            ConsoleError::CapabilityFailed => "Failed to create capability",
            ConsoleError::CapabilityDenied(_) => "Console access denied",
            ConsoleError::NotImplemented => "Feature not implemented",
            ConsoleError::AccessDenied => "Access denied: not console owner",
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

pub fn init() {
    // Create default console for kernel (PID 0)
    let kernel_pid = ProcessId::new(0);
    if let Ok(_cap_id) = create_console(kernel_pid) {
        vga::print_str("[CONSOLE] Default console created\n");
    }
}
