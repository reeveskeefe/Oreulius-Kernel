//! System Call Interface
//!
//! Provides the boundary between user mode (ring 3) and kernel mode (ring 0).
//! Includes capability checking at the syscall boundary.

use crate::vga;
use crate::capability::{self, CapabilityType, Rights};

/// System call numbers
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyscallNumber {
    // Process management
    Exit = 0,
    Fork = 1,
    Yield = 2,
    GetPid = 3,
    Sleep = 4,
    
    // IPC
    ChannelCreate = 10,
    ChannelSend = 11,
    ChannelRecv = 12,
    ChannelClose = 13,
    
    // Filesystem
    FileOpen = 20,
    FileRead = 21,
    FileWrite = 22,
    FileClose = 23,
    FileDelete = 24,
    DirList = 25,
    
    // Memory
    MemoryAlloc = 30,
    MemoryFree = 31,
    MemoryMap = 32,
    MemoryUnmap = 33,
    
    // Capability
    CapabilityGrant = 40,
    CapabilityRevoke = 41,
    CapabilityQuery = 42,
    
    // Console
    ConsoleWrite = 50,
    ConsoleRead = 51,
    
    // WASM
    WasmLoad = 60,
    WasmCall = 61,
    
    // Invalid
    Invalid = 0xFFFFFFFF,
}

impl From<u32> for SyscallNumber {
    fn from(n: u32) -> Self {
        match n {
            0 => SyscallNumber::Exit,
            1 => SyscallNumber::Fork,
            2 => SyscallNumber::Yield,
            3 => SyscallNumber::GetPid,
            4 => SyscallNumber::Sleep,
            10 => SyscallNumber::ChannelCreate,
            11 => SyscallNumber::ChannelSend,
            12 => SyscallNumber::ChannelRecv,
            13 => SyscallNumber::ChannelClose,
            20 => SyscallNumber::FileOpen,
            21 => SyscallNumber::FileRead,
            22 => SyscallNumber::FileWrite,
            23 => SyscallNumber::FileClose,
            24 => SyscallNumber::FileDelete,
            25 => SyscallNumber::DirList,
            30 => SyscallNumber::MemoryAlloc,
            31 => SyscallNumber::MemoryFree,
            32 => SyscallNumber::MemoryMap,
            33 => SyscallNumber::MemoryUnmap,
            40 => SyscallNumber::CapabilityGrant,
            41 => SyscallNumber::CapabilityRevoke,
            42 => SyscallNumber::CapabilityQuery,
            50 => SyscallNumber::ConsoleWrite,
            51 => SyscallNumber::ConsoleRead,
            60 => SyscallNumber::WasmLoad,
            61 => SyscallNumber::WasmCall,
            _ => SyscallNumber::Invalid,
        }
    }
}

/// System call arguments (passed via registers)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub number: u32,  // EAX
    pub arg1: u32,    // EBX
    pub arg2: u32,    // ECX
    pub arg3: u32,    // EDX
    pub arg4: u32,    // ESI
    pub arg5: u32,    // EDI
}

/// System call result
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallResult {
    pub value: i32,   // Return value (or error code if negative)
    pub errno: u32,   // Error number (0 = success)
}

impl SyscallResult {
    pub fn ok(value: i32) -> Self {
        SyscallResult { value, errno: 0 }
    }

    pub fn err(errno: u32) -> Self {
        SyscallResult { value: -1, errno }
    }
}

/// Error codes
pub const EPERM: u32 = 1;      // Operation not permitted
pub const ENOENT: u32 = 2;     // No such file or directory
pub const EINVAL: u32 = 22;    // Invalid argument
pub const EACCES: u32 = 13;    // Permission denied
pub const ENOMEM: u32 = 12;    // Out of memory
pub const ENOSYS: u32 = 38;    // Function not implemented

/// Main syscall handler (called from interrupt/trap)
pub fn handle_syscall(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let syscall = SyscallNumber::from(args.number);
    
    // Security: audit syscall
    // TODO: Implement audit_syscall in security module
    // crate::security::audit_syscall(caller_pid, syscall, args);
    
    match syscall {
        SyscallNumber::Exit => sys_exit(args, caller_pid),
        SyscallNumber::Fork => sys_fork(args, caller_pid),
        SyscallNumber::Yield => sys_yield(args, caller_pid),
        SyscallNumber::GetPid => sys_getpid(args, caller_pid),
        SyscallNumber::Sleep => sys_sleep(args, caller_pid),
        
        SyscallNumber::ChannelCreate => sys_channel_create(args, caller_pid),
        SyscallNumber::ChannelSend => sys_channel_send(args, caller_pid),
        SyscallNumber::ChannelRecv => sys_channel_recv(args, caller_pid),
        SyscallNumber::ChannelClose => sys_channel_close(args, caller_pid),
        
        SyscallNumber::FileOpen => sys_file_open(args, caller_pid),
        SyscallNumber::FileRead => sys_file_read(args, caller_pid),
        SyscallNumber::FileWrite => sys_file_write(args, caller_pid),
        SyscallNumber::FileClose => sys_file_close(args, caller_pid),
        SyscallNumber::FileDelete => sys_file_delete(args, caller_pid),
        
        SyscallNumber::MemoryAlloc => sys_memory_alloc(args, caller_pid),
        SyscallNumber::MemoryFree => sys_memory_free(args, caller_pid),
        SyscallNumber::MemoryMap => sys_memory_map(args, caller_pid),
        SyscallNumber::MemoryUnmap => sys_memory_unmap(args, caller_pid),
        
        SyscallNumber::CapabilityGrant => sys_cap_grant(args, caller_pid),
        SyscallNumber::CapabilityRevoke => sys_cap_revoke(args, caller_pid),
        SyscallNumber::CapabilityQuery => sys_cap_query(args, caller_pid),
        
        SyscallNumber::ConsoleWrite => sys_console_write(args, caller_pid),
        SyscallNumber::ConsoleRead => sys_console_read(args, caller_pid),
        
        SyscallNumber::WasmLoad => sys_wasm_load(args, caller_pid),
        SyscallNumber::WasmCall => sys_wasm_call(args, caller_pid),
        
        SyscallNumber::Invalid => SyscallResult::err(ENOSYS),
    }
}

// ============================================================================
// Process Management Syscalls
// ============================================================================

fn sys_exit(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let exit_code = args.arg1 as i32;
    // TODO: Implement process termination
    vga::print_str("[SYSCALL] Exit called with code ");
    vga::print_str("\n");
    SyscallResult::ok(0)
}

fn sys_fork(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    // TODO: Implement process forking with COW
    SyscallResult::err(ENOSYS)
}

fn sys_yield(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    crate::scheduler::yield_cpu();
    SyscallResult::ok(0)
}

fn sys_getpid(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::ok(caller_pid.0 as i32)
}

fn sys_sleep(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let ms = args.arg1;
    // TODO: Implement sleep via scheduler
    SyscallResult::ok(0)
}

// ============================================================================
// IPC Syscalls
// ============================================================================

fn sys_channel_create(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    // Check capability: process must have general IPC capability
    // For now, allow all processes to create channels
    
    match crate::ipc::create_channel() {
        Ok(channel_id) => SyscallResult::ok(channel_id as i32),
        Err(_) => SyscallResult::err(ENOMEM),
    }
}

fn sys_channel_send(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let msg_ptr = args.arg2 as usize;
    let msg_len = args.arg3 as usize;
    
    // Check capability: process must have WRITE right on channel
    if !check_capability(caller_pid, channel_id as u64, CapabilityType::Channel, Rights::new(Rights::CHANNEL_SEND)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Validate msg_ptr is in user space
    // TODO: Copy message from user space
    // TODO: Send via IPC
    
    SyscallResult::err(ENOSYS)
}

fn sys_channel_recv(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let buf_ptr = args.arg2 as usize;
    let buf_len = args.arg3 as usize;
    
    // Check capability: process must have READ right on channel
    if !check_capability(caller_pid, channel_id as u64, CapabilityType::Channel, Rights::new(Rights::CHANNEL_RECEIVE)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Implement receive
    SyscallResult::err(ENOSYS)
}

fn sys_channel_close(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    
    // Check capability
    if !check_capability(caller_pid, channel_id as u64, CapabilityType::Channel, Rights::new(Rights::ALL)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Implement close
    SyscallResult::ok(0)
}

// ============================================================================
// Filesystem Syscalls
// ============================================================================

fn sys_file_open(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let path_ptr = args.arg1 as usize;
    let flags = args.arg2;
    
    // TODO: Validate path_ptr, copy string from user space
    // TODO: Check filesystem capability
    // TODO: Open file
    
    SyscallResult::err(ENOSYS)
}

fn sys_file_read(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let fd = args.arg1;
    let buf_ptr = args.arg2 as usize;
    let count = args.arg3 as usize;
    
    // Check capability for this file descriptor
    if !check_capability(caller_pid, fd as u64, CapabilityType::Filesystem, Rights::new(Rights::FS_READ)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Validate buf_ptr
    // TODO: Read from file
    
    SyscallResult::err(ENOSYS)
}

fn sys_file_write(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let fd = args.arg1;
    let buf_ptr = args.arg2 as usize;
    let count = args.arg3 as usize;
    
    // Check capability
    if !check_capability(caller_pid, fd as u64, CapabilityType::Filesystem, Rights::new(Rights::FS_WRITE)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Implement write
    SyscallResult::err(ENOSYS)
}

fn sys_file_close(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

fn sys_file_delete(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// Memory Management Syscalls
// ============================================================================

fn sys_memory_alloc(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let size = args.arg1 as usize;
    let flags = args.arg2;
    
    // TODO: Allocate user pages
    // TODO: Map into process address space
    
    SyscallResult::err(ENOSYS)
}

fn sys_memory_free(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

fn sys_memory_map(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

fn sys_memory_unmap(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// Capability Syscalls
// ============================================================================

fn sys_cap_grant(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let target_pid = capability::ProcessId(args.arg1);
    let object_id = args.arg2 as u64;
    let cap_type_raw = args.arg3;
    let rights = Rights::new(args.arg4);
    
    // TODO: Verify caller has authority to grant
    // TODO: Grant capability
    
    SyscallResult::err(ENOSYS)
}

fn sys_cap_revoke(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

fn sys_cap_query(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// Console Syscalls
// ============================================================================

fn sys_console_write(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let buf_ptr = args.arg1 as usize;
    let len = args.arg2 as usize;
    
    // Check console write capability
    if !check_capability(caller_pid, 0, CapabilityType::Console, Rights::new(Rights::CONSOLE_WRITE)) {
        return SyscallResult::err(EACCES);
    }
    
    // TODO: Validate buffer, copy from user space, write to console
    
    SyscallResult::ok(len as i32)
}

fn sys_console_read(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    // Check console read capability
    if !check_capability(caller_pid, 0, CapabilityType::Console, Rights::new(Rights::CONSOLE_READ)) {
        return SyscallResult::err(EACCES);
    }
    
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// WASM Syscalls
// ============================================================================

fn sys_wasm_load(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

fn sys_wasm_call(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if process has required capability
fn check_capability(
    pid: capability::ProcessId,
    object_id: u64,
    cap_type: CapabilityType,
    required_rights: Rights,
) -> bool {
    capability::check_capability(pid, object_id, cap_type, required_rights)
}

/// Saved register state from syscall entry
#[repr(C)]
pub struct SavedRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
}

/// Called from assembly syscall_entry stub
#[no_mangle]
pub extern "C" fn syscall_handler_rust(regs: *const SavedRegisters) -> u64 {
    let regs = unsafe { &*regs };
    
    let args = SyscallArgs {
        number: regs.eax,
        arg1: regs.ebx,
        arg2: regs.ecx,
        arg3: regs.edx,
        arg4: regs.esi,
        arg5: regs.edi,
    };
    
    // TODO: Get actual caller PID from current process
    let caller_pid = capability::ProcessId(0);
    
    // Update stats
    unsafe {
        SYSCALL_STATS.total_calls += 1;
        if (args.number as usize) < SYSCALL_STATS.by_number.len() {
            SYSCALL_STATS.by_number[args.number as usize] += 1;
        }
    }
    
    let result = handle_syscall(args, caller_pid);
    
    if result.errno != 0 {
        unsafe {
            SYSCALL_STATS.errors += 1;
        }
    }
    
    // Pack result into EAX:EDX (EAX = value, EDX = errno)
    ((result.errno as u64) << 32) | ((result.value as u32) as u64)
}

/// Initialize syscall subsystem
pub fn init() {
    // Register INT 0x80 handler
    extern "C" {
        fn syscall_entry();
    }
    
    // TODO: Set up IDT entry for INT 0x80 pointing to syscall_entry
    
    vga::print_str("[SYSCALL] System call interface initialized (INT 0x80)\n");
}

/// Statistics
pub struct SyscallStats {
    pub total_calls: u64,
    pub by_number: [u64; 256],
    pub denied: u64,
    pub errors: u64,
}

static mut SYSCALL_STATS: SyscallStats = SyscallStats {
    total_calls: 0,
    by_number: [0; 256],
    denied: 0,
    errors: 0,
};

pub fn get_stats() -> &'static SyscallStats {
    unsafe { &SYSCALL_STATS }
}
