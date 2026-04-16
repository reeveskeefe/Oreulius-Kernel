// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

//! System Call Interface
//!
//! Provides the boundary between user mode (ring 3) and kernel mode (ring 0).
//! Includes capability checking at the syscall boundary.

use crate::capability::{self, CapabilityType, Rights};
#[cfg(target_arch = "x86")]
use crate::platform::gdt;
#[cfg(target_arch = "x86")]
use crate::scheduler::process_asm::{
    write_msr, MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_EIP, MSR_IA32_SYSENTER_ESP,
};
#[cfg(not(target_arch = "aarch64"))]
use crate::drivers::x86::vga;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use core::sync::atomic::{AtomicUsize, Ordering};

// POSIX-style error codes
const ENOSYS: u32 = 38; // Function not implemented
const EINVAL: u32 = 22; // Invalid argument
const EACCES: u32 = 13; // Permission denied
const EPERM: u32 = 1; // Operation not permitted (caller not privileged)
const EFAULT: u32 = 14; // Bad address
const ENOMEM: u32 = 12; // Out of memory
const EIO: u32 = 5; // I/O error
const EBADF: u32 = 9; // Bad file descriptor
const ENOENT: u32 = 2; // No such file or directory
const EAGAIN: u32 = 11; // Try again
#[cfg(not(target_arch = "aarch64"))]
const ENODEV: u32 = 19; // No such device

#[cfg(not(target_arch = "aarch64"))]
const MAP_ANONYMOUS: u32 = 1 << 0;
#[cfg(not(target_arch = "aarch64"))]
const MAP_SHARED: u32 = 1 << 1;

/// Internal syscall number used to return from user-mode JIT execution.
pub const SYSCALL_JIT_RETURN: u32 = 250;

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
    Exec = 5,

    // IPC
    ChannelCreate = 10,
    ChannelSend = 11,
    ChannelRecv = 12,
    ChannelClose = 13,
    ChannelSendCaps = 14,
    ChannelRecvCaps = 15,

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
    /// Privileged cross-PID capability revocation issued by the Math Daemon (PMA §6.2).
    /// Only callable by the process whose PID equals `MATH_DAEMON_PID`.
    /// arg1 = target_pid (u32), arg2 = cap_id (u32; 0 = revoke all).
    CapabilityRevokeForPid = 43,

    // Console
    ConsoleWrite = 50,
    ConsoleRead = 51,

    // WASM
    WasmLoad = 60,
    WasmCall = 61,
    ServicePointerRegister = 62,
    ServicePointerInvoke = 63,
    ServicePointerRevoke = 64,
    JitReturn = SYSCALL_JIT_RETURN,

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
            5 => SyscallNumber::Exec,
            10 => SyscallNumber::ChannelCreate,
            11 => SyscallNumber::ChannelSend,
            12 => SyscallNumber::ChannelRecv,
            13 => SyscallNumber::ChannelClose,
            14 => SyscallNumber::ChannelSendCaps,
            15 => SyscallNumber::ChannelRecvCaps,
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
            43 => SyscallNumber::CapabilityRevokeForPid,
            50 => SyscallNumber::ConsoleWrite,
            51 => SyscallNumber::ConsoleRead,
            60 => SyscallNumber::WasmLoad,
            61 => SyscallNumber::WasmCall,
            62 => SyscallNumber::ServicePointerRegister,
            63 => SyscallNumber::ServicePointerInvoke,
            64 => SyscallNumber::ServicePointerRevoke,
            SYSCALL_JIT_RETURN => SyscallNumber::JitReturn,
            _ => SyscallNumber::Invalid,
        }
    }
}

/// System call arguments (passed via registers)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    pub number: u32, // EAX
    pub arg1: u32,   // EBX
    pub arg2: u32,   // ECX
    pub arg3: u32,   // EDX
    pub arg4: u32,   // ESI
    pub arg5: u32,   // EDI
}

/// System call result
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SyscallResult {
    pub value: i32, // Return value (or error code if negative)
    pub errno: u32, // Error number (0 = success)
}

impl SyscallResult {
    pub fn ok(value: i32) -> Self {
        SyscallResult { value, errno: 0 }
    }

    pub fn err(errno: u32) -> Self {
        SyscallResult { value: -1, errno }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SysIpcCapability {
    cap_id: u32,
    object_lo: u32,
    object_hi: u32,
    rights: u32,
    cap_type: u32,
    owner_pid: u32,
    issued_at_lo: u32,
    issued_at_hi: u32,
    expires_at_lo: u32,
    expires_at_hi: u32,
    flags: u32,
    extra0: u32,
    extra1: u32,
    extra2: u32,
    extra3: u32,
    token_lo: u32,
    token_hi: u32,
}

fn ipc_cap_type_from_raw(raw: u32) -> Option<crate::ipc::CapabilityType> {
    match raw {
        0 => Some(crate::ipc::CapabilityType::Generic),
        1 => Some(crate::ipc::CapabilityType::Channel),
        2 => Some(crate::ipc::CapabilityType::Filesystem),
        3 => Some(crate::ipc::CapabilityType::Store),
        4 => Some(crate::ipc::CapabilityType::ServicePointer),
        _ => None,
    }
}

fn ipc_cap_to_sys(cap: &crate::ipc::Capability) -> SysIpcCapability {
    SysIpcCapability {
        cap_id: cap.cap_id,
        object_lo: cap.object_id as u32,
        object_hi: (cap.object_id >> 32) as u32,
        rights: cap.rights.bits(),
        cap_type: cap.cap_type as u32,
        owner_pid: cap.owner_pid.0,
        issued_at_lo: cap.issued_at as u32,
        issued_at_hi: (cap.issued_at >> 32) as u32,
        expires_at_lo: cap.expires_at as u32,
        expires_at_hi: (cap.expires_at >> 32) as u32,
        flags: cap.flags,
        extra0: cap.extra[0],
        extra1: cap.extra[1],
        extra2: cap.extra[2],
        extra3: cap.extra[3],
        token_lo: cap.token as u32,
        token_hi: (cap.token >> 32) as u32,
    }
}

fn sys_cap_to_ipc(raw: &SysIpcCapability) -> Result<crate::ipc::Capability, ()> {
    let cap_type = ipc_cap_type_from_raw(raw.cap_type).ok_or(())?;
    let mut cap = crate::ipc::Capability::with_type(
        raw.cap_id,
        ((raw.object_hi as u64) << 32) | raw.object_lo as u64,
        Rights::new(raw.rights),
        cap_type,
    )
    .with_owner(crate::ipc::ProcessId(raw.owner_pid))
    .with_validity(
        ((raw.issued_at_hi as u64) << 32) | raw.issued_at_lo as u64,
        ((raw.expires_at_hi as u64) << 32) | raw.expires_at_lo as u64,
    )
    .with_flags(raw.flags);
    cap.extra = [raw.extra0, raw.extra1, raw.extra2, raw.extra3];
    cap.token = ((raw.token_hi as u64) << 32) | raw.token_lo as u64;
    Ok(cap)
}

/// Main syscall handler (called from interrupt/trap)
pub fn handle_syscall(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    crate::observability::emit_syscall_boundary(
        crate::observability::EventType::SyscallBoundary,
        0x3100,
        b"handle_syscall_enter",
    );

    let syscall_number_check = crate::invariants::syscall::check_syscall_number(args.number as u16, 64);
    if !syscall_number_check.valid {
        crate::invariants::enforce(syscall_number_check, b"invalid syscall number at boundary");
    }

    let syscall = SyscallNumber::from(args.number);

    if syscall == SyscallNumber::Invalid {
        let _ = crate::failure::handle_failure(
            crate::failure::FailureSubsystem::Syscall,
            crate::failure::FailureKind::InvalidState,
            b"invalid syscall dispatch number",
        );
        crate::observability::emit_syscall_boundary(
            crate::observability::EventType::SyscallBoundary,
            0x31FF,
            b"handle_syscall_invalid",
        );
        return SyscallResult::err(ENOSYS);
    }

    let sec = crate::security::security();
    let syscall_args = [args.arg1, args.arg2, args.arg3, args.arg4, args.arg5];
    sec.audit_syscall(caller_pid, args.number, syscall_args);
    if sec.syscall_policy_blocked(caller_pid, args.number, syscall_args) {
        return SyscallResult::err(EACCES);
    }

    let result = match syscall {
        SyscallNumber::Exit => sys_exit(args, caller_pid),
        SyscallNumber::Fork => sys_fork(args, caller_pid),
        SyscallNumber::Yield => sys_yield(args, caller_pid),
        SyscallNumber::GetPid => sys_getpid(args, caller_pid),
        SyscallNumber::Sleep => sys_sleep(args, caller_pid),
        SyscallNumber::Exec => sys_exec(args, caller_pid),

        SyscallNumber::ChannelCreate => sys_channel_create(args, caller_pid),
        SyscallNumber::ChannelSend => sys_channel_send(args, caller_pid),
        SyscallNumber::ChannelRecv => sys_channel_recv(args, caller_pid),
        SyscallNumber::ChannelClose => sys_channel_close(args, caller_pid),
        SyscallNumber::ChannelSendCaps => sys_channel_send_caps(args, caller_pid),
        SyscallNumber::ChannelRecvCaps => sys_channel_recv_caps(args, caller_pid),

        SyscallNumber::FileOpen => sys_file_open(args, caller_pid),
        SyscallNumber::FileRead => sys_file_read(args, caller_pid),
        SyscallNumber::FileWrite => sys_file_write(args, caller_pid),
        SyscallNumber::FileClose => sys_file_close(args, caller_pid),
        SyscallNumber::FileDelete => sys_file_delete(args, caller_pid),
        SyscallNumber::DirList => sys_dir_list(args, caller_pid),

        SyscallNumber::MemoryAlloc => sys_memory_alloc(args, caller_pid),
        SyscallNumber::MemoryFree => sys_memory_free(args, caller_pid),
        SyscallNumber::MemoryMap => sys_memory_map(args, caller_pid),
        SyscallNumber::MemoryUnmap => sys_memory_unmap(args, caller_pid),

        SyscallNumber::CapabilityGrant => sys_cap_grant(args, caller_pid),
        SyscallNumber::CapabilityRevoke => sys_cap_revoke(args, caller_pid),
        SyscallNumber::CapabilityQuery => sys_cap_query(args, caller_pid),
        SyscallNumber::CapabilityRevokeForPid => sys_cap_revoke_for_pid(args, caller_pid),

        SyscallNumber::ConsoleWrite => sys_console_write(args, caller_pid),
        SyscallNumber::ConsoleRead => sys_console_read(args, caller_pid),

        SyscallNumber::WasmLoad => sys_wasm_load(args, caller_pid),
        SyscallNumber::WasmCall => sys_wasm_call(args, caller_pid),
        SyscallNumber::ServicePointerRegister => sys_service_pointer_register(args, caller_pid),
        SyscallNumber::ServicePointerInvoke => sys_service_pointer_invoke(args, caller_pid),
        SyscallNumber::ServicePointerRevoke => sys_service_pointer_revoke(args, caller_pid),
        SyscallNumber::JitReturn => sys_jit_return(args, caller_pid),

        SyscallNumber::Invalid => SyscallResult::err(ENOSYS),
    };

    // Escalation stage: repeated predictive restrictions can request termination.
    if syscall != SyscallNumber::Exit && sec.take_intent_termination_recommendation(caller_pid) {
        let _ = crate::scheduler::process::process_manager().terminate(crate::scheduler::process::Pid(caller_pid.0));
        let mut scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
        let _ = scheduler.remove_process(caller_pid);
        return SyscallResult::err(EACCES);
    }

    result
}

// ============================================================================
// Process Management Syscalls
// ============================================================================

fn sys_exit(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let exit_code = args.arg1 as i32;

    // Log the exit
    #[cfg(not(target_arch = "aarch64"))]
    {
        vga::print_str("[SYSCALL] Process ");
        crate::shell::commands::print_u32(caller_pid.0);
        vga::print_str(" exiting with code ");
        crate::shell::commands::print_u32(exit_code as u32);
        vga::print_str("\n");
    }

    // Remove process from process/security/capability subsystems.
    let _ = crate::scheduler::process::process_manager().terminate(crate::scheduler::process::Pid(caller_pid.0));

    // Remove from runtime scheduler.
    let mut scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    let _ = scheduler.remove_process(caller_pid);

    // Yield to next process
    drop(scheduler);
    crate::scheduler::slice_scheduler::yield_now();

    SyscallResult::ok(exit_code)
}

fn sys_fork(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _flags = args.arg1;
    crate::scheduler::scheduler_runtime_platform::logf(format_args!(
        "[SYSCALL] fork caller_pid={} flags={}",
        caller_pid.0, args.arg1
    ));

    #[cfg(not(target_arch = "aarch64"))]
    {
        vga::print_str("[SYSCALL] Fork requested by PID ");
        crate::shell::commands::print_u32(caller_pid.0);
        vga::print_str("\n");
    }

    let mut scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    match scheduler.fork_current_cow() {
        Ok(child_pid) => {
            #[cfg(not(target_arch = "aarch64"))]
            {
                vga::print_str("[SYSCALL] Fork successful, child PID=");
                crate::shell::commands::print_u32(child_pid.0);
                vga::print_str("\n");
            }
            SyscallResult::ok(child_pid.0 as i32)
        }
        Err(_) => {
            #[cfg(not(target_arch = "aarch64"))]
            vga::print_str("[SYSCALL] Fork failed\n");
            SyscallResult::err(ENOMEM)
        }
    }
}

fn sys_yield(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _yield_hint = args.arg1; // Optional: 0=normal, 1=I/O wait, 2=explicit
    if args.arg1 > 0 {
        crate::scheduler::scheduler_runtime_platform::logf(format_args!(
            "[SYSCALL] yield caller_pid={} hint={}",
            caller_pid.0, args.arg1
        ));
    }

    // Mark process as yielding voluntarily (good for statistics)
    let mut scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    scheduler.record_voluntary_yield();
    drop(scheduler);

    // Log for debugging (optional, can be removed for production)
    #[cfg(not(target_arch = "aarch64"))]
    if args.arg1 > 0 {
        vga::print_str("[SYSCALL] PID ");
        crate::shell::commands::print_u32(caller_pid.0);
        vga::print_str(" yielding (hint=");
        crate::shell::commands::print_u32(args.arg1);
        vga::print_str(")\n");
    }

    crate::scheduler::slice_scheduler::yield_now();
    SyscallResult::ok(0)
}

fn sys_getpid(_args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::ok(caller_pid.0 as i32)
}

fn sys_sleep(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let ms = args.arg1;

    if ms == 0 {
        // Sleep(0) is just a yield
        crate::scheduler::slice_scheduler::yield_now();
        return SyscallResult::ok(0);
    }

    // Calculate wake time (current ticks + ms converted to ticks)
    let current_ticks = crate::scheduler::pit::get_ticks();
    let sleep_ticks = (ms as u64 * 100) / 1000; // Convert ms to ticks (100 Hz timer)
    let wake_time = current_ticks + sleep_ticks;

    if crate::scheduler::slice_scheduler::sleep_until(caller_pid, wake_time).is_err() {
        return SyscallResult::err(EINVAL);
    }

    SyscallResult::ok(0)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_exec(args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    let buf_ptr = args.arg1 as usize;
    let len = args.arg2 as usize;

    if len == 0 || len > 256 * 1024 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= crate::fs::paging::KERNEL_BASE || buf_ptr + len >= crate::fs::paging::KERNEL_BASE {
        return SyscallResult::err(EFAULT);
    }

    let bytes = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
    let module_id = match crate::execution::wasm::load_module(bytes) {
        Ok(id) => id,
        Err(_) => return SyscallResult::err(EIO),
    };

    {
        let mut scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
        if scheduler.exec_current_wasm(module_id as u32).is_err() {
            return SyscallResult::err(EINVAL);
        }
    }

    if crate::execution::wasm::call_function(module_id, 0, &[]).is_err() {
        return SyscallResult::err(EINVAL);
    }

    SyscallResult::ok(0)
}

#[cfg(target_arch = "aarch64")]
fn sys_exec(args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = args;
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// IPC Syscalls
// ============================================================================

fn sys_channel_create(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    // Check capability: process must have general IPC capability
    if !capability::check_capability(
        caller_pid,
        0,
        CapabilityType::Channel,
        Rights::new(Rights::CHANNEL_CREATE),
    ) {
        // Allow kernel and root processes (PID 0-2) to create channels
        if caller_pid.0 > 2 {
            return SyscallResult::err(EACCES);
        }
    }

    // Parse channel configuration flags from arg1
    // Bits 0-7: Channel flags (bounded, unbounded, high-priority, reliable, async)
    // Bits 8-15: Priority level (0-255)
    let config = args.arg1 as u32;
    let flags_bits = config & 0xFF;
    let priority = ((config >> 8) & 0xFF) as u8;

    // Default to medium priority if not specified
    let priority = if priority == 0 { 128 } else { priority };

    let flags = crate::ipc::ChannelFlags::new(flags_bits);

    #[cfg(not(target_arch = "aarch64"))]
    {
        vga::print_str("[SYSCALL] Channel create by PID ");
        crate::shell::commands::print_u32(caller_pid.0);
        vga::print_str(" with flags=0x");
        crate::shell::commands::print_hex_u32(flags_bits);
        vga::print_str(" priority=");
        crate::shell::commands::print_u32(priority as u32);
        vga::print_str("\n");
    }

    // Create channel via IPC manager with custom configuration
    match crate::ipc::create_channel_for_process_with_flags(
        crate::ipc::ProcessId(caller_pid.0),
        flags,
        priority,
    ) {
        Ok(channel_id) => {
            #[cfg(not(target_arch = "aarch64"))]
            {
                vga::print_str("[SYSCALL] Created channel ID=");
                crate::shell::commands::print_u32(channel_id as u32);
                vga::print_str("\n");
            }
            SyscallResult::ok(channel_id as i32)
        }
        Err(_) => SyscallResult::err(ENOMEM),
    }
}

fn sys_channel_send(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let msg_ptr = args.arg2 as usize;
    let msg_len = args.arg3 as usize;

    // Validate message length
    if msg_len == 0 || msg_len > 4096 {
        return SyscallResult::err(EINVAL);
    }

    // Validate msg_ptr is in user space (below kernel boundary 0xC0000000)
    if msg_ptr >= 0xC0000000 || msg_ptr + msg_len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Copy message from user space to kernel
    let mut message_vec = alloc::vec![0u8; msg_len];
    let user_slice = unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, msg_len) };
    message_vec.copy_from_slice(user_slice);
    let message = &message_vec;

    // Send via IPC
    match crate::ipc::send_message_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        message,
    ) {
        Ok(_) => SyscallResult::ok(msg_len as i32),
        Err(e) => {
            if e == "Missing channel capability" {
                SyscallResult::err(EACCES)
            } else {
                SyscallResult::err(EIO)
            }
        }
    }
}

fn sys_channel_recv(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let buf_ptr = args.arg2 as usize;
    let buf_len = args.arg3 as usize;

    // Validate buffer
    if buf_len == 0 || buf_len > 4096 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= 0xC0000000 || buf_ptr + buf_len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Receive from IPC
    let mut buffer_vec = alloc::vec![0u8; buf_len];

    match crate::ipc::receive_message_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        &mut buffer_vec,
    ) {
        Ok(bytes_received) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer_vec.as_ptr(),
                    buf_ptr as *mut u8,
                    bytes_received,
                );
            }
            SyscallResult::ok(bytes_received as i32)
        }
        Err(e) => {
            if e == "Missing channel capability" {
                SyscallResult::err(EACCES)
            } else {
                SyscallResult::err(EAGAIN) // No message available
            }
        }
    }
}

fn sys_channel_close(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;

    // Close the channel
    match crate::ipc::close_channel_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
    ) {
        Ok(_) => {
            // Revoke capability
            capability::capability_manager()
                .revoke_capability(caller_pid, channel_id as u32)
                .ok();
            SyscallResult::ok(0)
        }
        Err(e) => {
            if e == "Missing channel capability" {
                SyscallResult::err(EACCES)
            } else {
                SyscallResult::err(EBADF)
            }
        }
    }
}

fn sys_channel_send_caps(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let msg_ptr = args.arg2 as usize;
    let msg_len = args.arg3 as usize;
    let caps_ptr = args.arg4 as usize;
    let caps_count = args.arg5 as usize;

    if msg_len == 0 || msg_len > 4096 {
        return SyscallResult::err(EINVAL);
    }
    if caps_count > crate::ipc::MAX_CAPS_PER_MESSAGE {
        return SyscallResult::err(EINVAL);
    }
    if msg_ptr >= 0xC0000000 || msg_ptr + msg_len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }
    if caps_count > 0 {
        let caps_bytes = caps_count.saturating_mul(core::mem::size_of::<SysIpcCapability>());
        if caps_ptr >= 0xC0000000 || caps_ptr + caps_bytes >= 0xC0000000 {
            return SyscallResult::err(EFAULT);
        }
    }

    let mut message_vec = alloc::vec![0u8; msg_len];
    let user_slice = unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, msg_len) };
    message_vec.copy_from_slice(user_slice);
    let message = &message_vec;
    let mut caps = [crate::ipc::Capability::new(0, 0, Rights::new(0)); crate::ipc::MAX_CAPS_PER_MESSAGE];
    if caps_count > 0 {
        let raw_caps =
            unsafe { core::slice::from_raw_parts(caps_ptr as *const SysIpcCapability, caps_count) };
        let mut i = 0usize;
        while i < caps_count {
            caps[i] = match sys_cap_to_ipc(&raw_caps[i]) {
                Ok(c) => c,
                Err(_) => return SyscallResult::err(EINVAL),
            };
            i += 1;
        }
    }

    match crate::ipc::send_message_with_caps_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        message,
        &caps[..caps_count],
    ) {
        Ok(_) => SyscallResult::ok(msg_len as i32),
        Err(e) => {
            if e == "Missing channel capability" {
                SyscallResult::err(EACCES)
            } else {
                SyscallResult::err(EIO)
            }
        }
    }
}

fn sys_channel_recv_caps(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let channel_id = args.arg1 as usize;
    let buf_ptr = args.arg2 as usize;
    let buf_len = args.arg3 as usize;
    let caps_ptr = args.arg4 as usize;
    let caps_count_ptr = args.arg5 as usize;

    if buf_len == 0 || buf_len > 4096 {
        return SyscallResult::err(EINVAL);
    }
    if buf_ptr >= 0xC0000000 || buf_ptr + buf_len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }
    if caps_ptr >= 0xC0000000 || caps_count_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    let caps_bytes =
        crate::ipc::MAX_CAPS_PER_MESSAGE.saturating_mul(core::mem::size_of::<SysIpcCapability>());
    if caps_ptr + caps_bytes >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    let mut buffer_vec = alloc::vec![0u8; buf_len];
    let mut caps = [crate::ipc::Capability::new(0, 0, Rights::new(0)); crate::ipc::MAX_CAPS_PER_MESSAGE];

    match crate::ipc::receive_message_with_caps_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        &mut buffer_vec,
        &mut caps,
    ) {
        Ok((bytes_received, caps_received)) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buffer_vec.as_ptr(),
                    buf_ptr as *mut u8,
                    bytes_received,
                );
            }
            let caps_out = unsafe {
                core::slice::from_raw_parts_mut(
                    caps_ptr as *mut SysIpcCapability,
                    crate::ipc::MAX_CAPS_PER_MESSAGE,
                )
            };
            let mut i = 0usize;
            while i < caps_received {
                caps_out[i] = ipc_cap_to_sys(&caps[i]);
                i += 1;
            }
            unsafe {
                (caps_count_ptr as *mut u32).write(caps_received as u32);
            }
            SyscallResult::ok(bytes_received as i32)
        }
        Err(e) => {
            if e == "Missing channel capability" {
                SyscallResult::err(EACCES)
            } else {
                SyscallResult::err(EAGAIN)
            }
        }
    }
}

// ============================================================================
// Filesystem Syscalls
// ============================================================================

fn sys_file_open(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let path_ptr = args.arg1 as usize;
    let flags = args.arg2;

    // Validate pointer
    if path_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Read path string from user space (max 256 bytes)
    let mut path_buf = [0u8; 256];
    let mut path_len = 0;

    unsafe {
        let ptr = path_ptr as *const u8;
        for i in 0..256 {
            let byte = ptr.add(i).read();
            if byte == 0 {
                break;
            }
            path_buf[i] = byte;
            path_len = i + 1;
        }
    }

    let path = core::str::from_utf8(&path_buf[..path_len]).unwrap_or("");

    // Determine required rights from flags
    let mut required_rights = 0;
    if flags & 0x01 != 0 {
        required_rights |= Rights::FS_READ;
    } // O_RDONLY
    if flags & 0x02 != 0 {
        required_rights |= Rights::FS_WRITE;
    } // O_WRONLY
    if flags & 0x04 != 0 {
        required_rights |= Rights::FS_WRITE;
    } // O_RDWR

    // Check filesystem capability
    if !check_capability(
        caller_pid,
        0,
        CapabilityType::Filesystem,
        Rights::new(required_rights),
    ) {
        return SyscallResult::err(EACCES);
    }

    let path_hash = crate::security::hash_data(path.as_bytes());
    if (required_rights & Rights::FS_READ) != 0 {
        crate::security::security().intent_fs_read(caller_pid, path_hash);
    }
    if (required_rights & Rights::FS_WRITE) != 0 {
        crate::security::security().intent_fs_write(caller_pid, path_hash);
    }

    // Open file via filesystem
    match crate::fs::open(path) {
        Ok(fd) => SyscallResult::ok(fd as i32),
        Err(_) => SyscallResult::err(ENOENT),
    }
}

fn sys_file_read(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let fd = args.arg1;
    let buf_ptr = args.arg2 as usize;
    let count = args.arg3 as usize;

    // Check capability for this file descriptor
    if !check_capability(
        caller_pid,
        fd as u64,
        CapabilityType::Filesystem,
        Rights::new(Rights::FS_READ),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate buffer
    if count == 0 || count > 65536 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= 0xC0000000 || buf_ptr + count >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Read from file
    crate::security::security().intent_fs_read(caller_pid, fd as u64);
    let mut buffer_vec = alloc::vec![0u8; count];

    match crate::fs::read(fd as usize, &mut buffer_vec) {
        Ok(bytes_read) => {
            unsafe {
                core::ptr::copy_nonoverlapping(buffer_vec.as_ptr(), buf_ptr as *mut u8, bytes_read);
            }
            SyscallResult::ok(bytes_read as i32)
        }
        Err(_) => SyscallResult::err(EIO),
    }
}

fn sys_file_write(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let fd = args.arg1;
    let buf_ptr = args.arg2 as usize;
    let count = args.arg3 as usize;

    // Check capability
    if !check_capability(
        caller_pid,
        fd as u64,
        CapabilityType::Filesystem,
        Rights::new(Rights::FS_WRITE),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate buffer
    if count == 0 || count > 65536 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= 0xC0000000 || buf_ptr + count >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Write to file
    crate::security::security().intent_fs_write(caller_pid, fd as u64);
    let buffer = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };

    match crate::fs::write(fd as usize, buffer) {
        Ok(bytes_written) => SyscallResult::ok(bytes_written as i32),
        Err(_) => SyscallResult::err(EIO),
    }
}

fn sys_file_close(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let fd = args.arg1 as usize;

    // Require at least one filesystem right on this descriptor.
    let has_read = check_capability(
        caller_pid,
        fd as u64,
        CapabilityType::Filesystem,
        Rights::new(Rights::FS_READ),
    );
    let has_write = if has_read {
        true
    } else {
        check_capability(
            caller_pid,
            fd as u64,
            CapabilityType::Filesystem,
            Rights::new(Rights::FS_WRITE),
        )
    };
    if !has_read && !has_write {
        return SyscallResult::err(EACCES);
    }

    // Close file
    match crate::fs::close(fd) {
        Ok(_) => SyscallResult::ok(0),
        Err(_) => SyscallResult::err(EBADF),
    }
}

fn sys_file_delete(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let path_ptr = args.arg1 as usize;

    // Check capability
    if !check_capability(
        caller_pid,
        0,
        CapabilityType::Filesystem,
        Rights::new(Rights::FS_DELETE),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate pointer
    if path_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Read path string
    let mut path_buf = [0u8; 256];
    let mut path_len = 0;

    unsafe {
        let ptr = path_ptr as *const u8;
        for i in 0..256 {
            let byte = ptr.add(i).read();
            if byte == 0 {
                break;
            }
            path_buf[i] = byte;
            path_len = i + 1;
        }
    }

    let path = core::str::from_utf8(&path_buf[..path_len]).unwrap_or("");
    crate::security::security()
        .intent_fs_write(caller_pid, crate::security::hash_data(path.as_bytes()));

    // Delete file
    match crate::fs::delete(path) {
        Ok(_) => SyscallResult::ok(0),
        Err(_) => SyscallResult::err(ENOENT),
    }
}

fn sys_dir_list(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let path_ptr = args.arg1 as usize;
    let buf_ptr = args.arg2 as usize;
    let buf_len = args.arg3 as usize;

    // Check capability
    if !check_capability(
        caller_pid,
        0,
        CapabilityType::Filesystem,
        Rights::new(Rights::FS_LIST),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate pointers
    if path_ptr >= 0xC0000000 || buf_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Read path
    let mut path_buf = [0u8; 256];
    let mut path_len = 0;
    unsafe {
        let ptr = path_ptr as *const u8;
        for i in 0..256 {
            let byte = ptr.add(i).read();
            if byte == 0 {
                break;
            }
            path_buf[i] = byte;
            path_len = i + 1;
        }
    }
    let path = core::str::from_utf8(&path_buf[..path_len]).unwrap_or("/");
    crate::security::security()
        .intent_fs_read(caller_pid, crate::security::hash_data(path.as_bytes()));

    // List directory
    let mut buffer_vec = alloc::vec![0u8; buf_len];

    match crate::fs::list_dir(path, &mut buffer_vec) {
        Ok(count) => {
            unsafe {
                core::ptr::copy_nonoverlapping(buffer_vec.as_ptr(), buf_ptr as *mut u8, buf_len);
            }
            SyscallResult::ok(count as i32)
        }
        Err(_) => SyscallResult::err(ENOENT),
    }
}

// ============================================================================
// Memory Management Syscalls
// ============================================================================

#[cfg(not(target_arch = "aarch64"))]
fn sys_memory_alloc(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let size = args.arg1 as usize;
    let requested_addr = match args.arg2 as usize {
        0 => None,
        value => Some(value),
    };

    if size == 0 || size > 1024 * 1024 * 64 {
        return SyscallResult::err(EINVAL);
    }

    let flags = crate::scheduler::slice_scheduler::VmaFlags::READ
        | crate::scheduler::slice_scheduler::VmaFlags::WRITE
        | crate::scheduler::slice_scheduler::VmaFlags::USER;

    let _ = caller_pid;
    match crate::scheduler::slice_scheduler::memory_alloc_current(requested_addr, size, flags) {
        Ok(addr) => SyscallResult::ok(addr as i32),
        Err("virtual address space exhausted") => SyscallResult::err(ENOMEM),
        Err("memory alloc unsupported on this architecture") => SyscallResult::err(ENOSYS),
        Err(_) => SyscallResult::err(EINVAL),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_memory_alloc(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_memory_free(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let addr = args.arg1 as usize;
    let size = args.arg2 as usize;

    if addr < 0x10000000 || addr >= crate::fs::paging::USER_TOP || size == 0 {
        return SyscallResult::err(EINVAL);
    }

    let _ = caller_pid;
    match crate::scheduler::slice_scheduler::memory_free_current(addr, size) {
        Ok(()) => SyscallResult::ok(0),
        Err("memory free unsupported on this architecture") => SyscallResult::err(ENOSYS),
        Err(_) => SyscallResult::err(EINVAL),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_memory_free(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_memory_map(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let addr = args.arg1 as usize;
    let size = args.arg2 as usize;
    let prot = args.arg3;
    let map_flags = args.arg4;
    let fd_and_offset = args.arg5;

    if size == 0 || size > 1024 * 1024 * 64 {
        return SyscallResult::err(EINVAL);
    }

    let mut flags = crate::scheduler::slice_scheduler::VmaFlags::USER;
    if (prot & 0x1) != 0 {
        flags |= crate::scheduler::slice_scheduler::VmaFlags::READ;
    }
    if (prot & 0x2) != 0 {
        flags |= crate::scheduler::slice_scheduler::VmaFlags::WRITE;
    }
    if (prot & 0x4) != 0 {
        flags |= crate::scheduler::slice_scheduler::VmaFlags::EXEC;
    }
    if (map_flags & MAP_SHARED) != 0 {
        flags |= crate::scheduler::slice_scheduler::VmaFlags::SHARED;
    }
    if !flags.intersects(
        crate::scheduler::slice_scheduler::VmaFlags::READ
            | crate::scheduler::slice_scheduler::VmaFlags::WRITE
            | crate::scheduler::slice_scheduler::VmaFlags::EXEC,
    ) {
        flags |= crate::scheduler::slice_scheduler::VmaFlags::READ | crate::scheduler::slice_scheduler::VmaFlags::WRITE;
    }

    let requested_addr = if addr == 0 { None } else { Some(addr) };

    if (map_flags & MAP_ANONYMOUS) != 0 {
        let _ = caller_pid;
        return match crate::scheduler::slice_scheduler::memory_alloc_current(requested_addr, size, flags) {
            Ok(mapped) => SyscallResult::ok(mapped as i32),
            Err("memory alloc unsupported on this architecture")
            | Err("memory map unsupported on this architecture") => SyscallResult::err(ENOSYS),
            Err("virtual address space exhausted") => SyscallResult::err(ENOMEM),
            Err(_) => SyscallResult::err(EINVAL),
        };
    }

    let fd = (fd_and_offset & 0xFFFF) as usize;
    let page_offset = (fd_and_offset >> 16) as usize;
    let offset = page_offset.saturating_mul(crate::arch::mmu::page_size());
    let source = match crate::fs::vfs::mmap_source_for_fd(caller_pid, fd) {
        Ok(source) => source,
        Err("mmap: raw block handles unsupported") => {
            return SyscallResult::err(ENODEV)
        }
        Err("mmap: not a file") | Err("Invalid handle") | Err("FD not open") => {
            return SyscallResult::err(EBADF)
        }
        Err(_) => return SyscallResult::err(EINVAL),
    };

    match crate::scheduler::slice_scheduler::memory_map_file_current(
        requested_addr,
        size,
        flags,
        source,
        offset,
    ) {
        Ok(mapped) => SyscallResult::ok(mapped as i32),
        Err("memory map unsupported on this architecture")
        | Err("memory alloc unsupported on this architecture") => SyscallResult::err(ENOSYS),
        Err("virtual address space exhausted") => SyscallResult::err(ENOMEM),
        Err(_) => SyscallResult::err(EINVAL),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_memory_map(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_memory_unmap(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let addr = args.arg1 as usize;
    let size = args.arg2 as usize;

    // Validate
    if addr < 0x10000000 || addr >= 0xC0000000 || size == 0 {
        return SyscallResult::err(EINVAL);
    }

    // Unmap the region
    let _ = (addr, size, caller_pid);

    SyscallResult::err(ENOSYS)
}

#[cfg(target_arch = "aarch64")]
fn sys_memory_unmap(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
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

    // Convert cap_type_raw to CapabilityType
    let cap_type = match cap_type_raw {
        0 => CapabilityType::Channel,
        1 => CapabilityType::Task,
        2 => CapabilityType::Spawner,
        10 => CapabilityType::Console,
        11 => CapabilityType::Clock,
        12 => CapabilityType::Store,
        13 => CapabilityType::Filesystem,
        14 => CapabilityType::ServicePointer,
        _ => return SyscallResult::err(EINVAL),
    };

    // Verify caller has authority to grant (must have the capability themselves)
    if !check_capability(caller_pid, object_id, cap_type, rights) {
        return SyscallResult::err(EACCES);
    }

    // Grant capability to target
    match capability::capability_manager()
        .grant_capability(target_pid, object_id, cap_type, rights, caller_pid)
    {
        Ok(cap_id) => SyscallResult::ok(cap_id as i32),
        Err(_) => SyscallResult::err(ENOMEM),
    }
}

fn sys_cap_revoke(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let cap_id = args.arg1;

    // Revoke capability from caller's table
    match capability::capability_manager().revoke_capability(caller_pid, cap_id) {
        Ok(_) => SyscallResult::ok(0),
        Err(_) => SyscallResult::err(EINVAL),
    }
}

/// PID assigned to the privileged Math Daemon at boot.
/// The kernel grants cross-PID revocation authority only to this PID.
const MATH_DAEMON_PID: u32 = 2;

/// Privileged cross-PID capability revocation — PMA §6.2.
///
/// Allows the Math Daemon to revoke capabilities from a rogue process after
/// detecting a CTMC anomaly.  Gated behind a static PID check: only the
/// process with PID == `MATH_DAEMON_PID` may invoke this syscall.
///
/// * `arg1` — target_pid: PID of the process whose capability should be revoked.
/// * `arg2` — cap_id: specific capability ID to revoke (0 = revoke all).
fn sys_cap_revoke_for_pid(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    // Security gate: only the Math Daemon may use this syscall.
    if caller_pid.0 != MATH_DAEMON_PID {
        return SyscallResult::err(EPERM);
    }

    let target_pid = capability::ProcessId(args.arg1);
    let cap_id = args.arg2;

    if cap_id == 0 {
        // Revoke every capability held by target_pid.
        match capability::capability_manager().revoke_all_capabilities(target_pid) {
            Ok(_) => SyscallResult::ok(0),
            Err(_) => SyscallResult::err(EINVAL),
        }
    } else {
        // Revoke a single specific capability.
        match capability::capability_manager().revoke_capability(target_pid, cap_id) {
            Ok(_) => SyscallResult::ok(0),
            Err(_) => SyscallResult::err(EINVAL),
        }
    }
}

fn sys_cap_query(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let cap_id = args.arg1;
    let info_ptr = args.arg2 as usize;

    // Validate pointer
    if info_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Query capability from caller's table
    match capability::capability_manager().query_capability(caller_pid, cap_id) {
        Ok((cap_type, object_id)) => {
            // Write capability info to user space buffer
            unsafe {
                let ptr = info_ptr as *mut u32;
                ptr.add(0).write((object_id >> 32) as u32); // High 32 bits
                ptr.add(1).write(object_id as u32); // Low 32 bits
                ptr.add(2).write(cap_type); // Type
            }
            SyscallResult::ok(0)
        }
        Err(_) => SyscallResult::err(EINVAL),
    }
}

// ============================================================================
// Console Syscalls
// ============================================================================

fn sys_console_write(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let buf_ptr = args.arg1 as usize;
    let len = args.arg2 as usize;

    // Check console write capability
    if !check_capability(
        caller_pid,
        0,
        CapabilityType::Console,
        Rights::new(Rights::CONSOLE_WRITE),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate buffer
    if len == 0 || len > 4096 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= 0xC0000000 || buf_ptr + len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Copy from user space and write to console
    let buffer = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };

    #[cfg(not(target_arch = "aarch64"))]
    // Write to VGA console
    for &byte in buffer {
        if byte == b'\n' {
            vga::print_char('\n');
        } else if byte >= 32 && byte < 127 {
            vga::print_char(byte as char);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
        for &byte in buffer {
            uart.write_byte(byte);
        }
    }

    SyscallResult::ok(len as i32)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_console_read(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let buf_ptr = args.arg1 as usize;
    let len = args.arg2 as usize;

    // Check console read capability
    if !check_capability(
        caller_pid,
        0,
        CapabilityType::Console,
        Rights::new(Rights::CONSOLE_READ),
    ) {
        return SyscallResult::err(EACCES);
    }

    // Validate buffer
    if len == 0 || len > 4096 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= 0xC0000000 || buf_ptr + len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Read from keyboard buffer
    let mut buffer_vec = alloc::vec![0u8; len];

    let mut bytes_read = 0;
    for i in 0..len {
        if let Some(ch) = crate::drivers::x86::keyboard::poll() {
            buffer_vec[i] = ch as u8;
            bytes_read += 1;
        } else {
            break;
        }
    }

    unsafe {
        core::ptr::copy_nonoverlapping(buffer_vec.as_ptr(), buf_ptr as *mut u8, bytes_read);
    }

    SyscallResult::ok(bytes_read as i32)
}

#[cfg(target_arch = "aarch64")]
fn sys_console_read(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

// ============================================================================
// WASM Syscalls
// ============================================================================

#[cfg(not(target_arch = "aarch64"))]
fn sys_wasm_load(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let wasm_ptr = args.arg1 as usize;
    let wasm_len = args.arg2 as usize;

    // Validate buffer
    if wasm_len == 0 || wasm_len > 1024 * 1024 {
        // Max 1MB WASM module
        return SyscallResult::err(EINVAL);
    }

    if wasm_ptr >= 0xC0000000 || wasm_ptr + wasm_len >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Copy WASM bytecode
    let wasm_bytes = unsafe { core::slice::from_raw_parts(wasm_ptr as *const u8, wasm_len) };

    // Load and validate WASM module
    match crate::execution::wasm::load_module(wasm_bytes) {
        Ok(module_id) => {
            let _ = caller_pid; // Use variable
            SyscallResult::ok(module_id as i32)
        }
        Err(_) => SyscallResult::err(EINVAL),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_wasm_load(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_wasm_call(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let module_id = args.arg1 as usize;
    let func_idx = args.arg2 as usize;
    let args_ptr = args.arg3 as usize;
    let args_count = args.arg4 as usize;

    // Validate
    if args_count > 16 {
        return SyscallResult::err(EINVAL);
    }

    if args_ptr >= 0xC0000000 {
        return SyscallResult::err(EFAULT);
    }

    // Copy arguments
    let wasm_args = if args_count > 0 {
        unsafe { core::slice::from_raw_parts(args_ptr as *const u32, args_count) }
    } else {
        &[]
    };

    // Call WASM function
    match crate::execution::wasm::call_function(module_id, func_idx, wasm_args) {
        Ok(result) => {
            let _ = caller_pid; // Use variable
            SyscallResult::ok(result as i32)
        }
        Err(_) => SyscallResult::err(EINVAL),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_wasm_call(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_jit_return(_args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    if crate::execution::wasm::jit_user_mark_returned() {
        SyscallResult::ok(0)
    } else {
        SyscallResult::err(EACCES)
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_jit_return(_args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_service_pointer_register(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let instance_id = args.arg1 as usize;
    let function_index = args.arg2 as usize;
    let allow_delegate = (args.arg3 & 0x1) != 0;

    match crate::execution::wasm::register_service_pointer(
        caller_pid,
        instance_id,
        function_index,
        allow_delegate,
    ) {
        Ok(registration) => SyscallResult::ok(registration.cap_id as i32),
        Err(_) => SyscallResult::err(EACCES),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_service_pointer_register(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_service_pointer_invoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let object_id = ((args.arg2 as u64) << 32) | args.arg1 as u64;
    let args_ptr = args.arg3 as usize;
    let args_count = args.arg4 as usize;

    if args_count > crate::execution::wasm::MAX_SERVICE_CALL_ARGS {
        return SyscallResult::err(EINVAL);
    }
    if args_count > 0 {
        let bytes = args_count.saturating_mul(4);
        if args_ptr >= 0xC0000000 || args_ptr.saturating_add(bytes) >= 0xC0000000 {
            return SyscallResult::err(EFAULT);
        }
    }

    let call_args: &[u32] = if args_count == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(args_ptr as *const u32, args_count) }
    };

    match crate::execution::wasm::invoke_service_pointer(caller_pid, object_id, call_args) {
        Ok(result) => SyscallResult::ok(result as i32),
        Err(_) => SyscallResult::err(EACCES),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_service_pointer_invoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let _ = (args, caller_pid);
    SyscallResult::err(ENOSYS)
}

#[cfg(not(target_arch = "aarch64"))]
fn sys_service_pointer_revoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let object_id = ((args.arg2 as u64) << 32) | args.arg1 as u64;
    match crate::execution::wasm::revoke_service_pointer(caller_pid, object_id) {
        Ok(()) => SyscallResult::ok(0),
        Err(_) => SyscallResult::err(EACCES),
    }
}

#[cfg(target_arch = "aarch64")]
fn sys_service_pointer_revoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let _ = (args, caller_pid);
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

/// Get current process PID from scheduler
fn get_current_pid() -> capability::ProcessId {
    let scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    if let Some(pid) = scheduler.get_current_pid() {
        capability::ProcessId(pid.0)
    } else {
        // No current process, return kernel PID
        capability::ProcessId(0)
    }
}

/// Saved register state from syscall entry
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct SavedRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    ebp: u32,
}

/// Saved register state from x86_64 syscall entry.
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub struct SavedRegisters {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

/// Saved register state from an AArch64 exception/SVC entry.
#[repr(C)]
#[cfg(target_arch = "aarch64")]
pub struct SavedRegisters {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
}

#[cfg(target_arch = "x86_64")]
const X86_64_SYSCALL_SAVED_QWORDS: usize = 16;
#[cfg(target_arch = "x86_64")]
const X86_64_SYSCALL_IRET_QWORDS: usize = 5;
#[cfg(target_arch = "x86_64")]
const X86_64_SYSCALL_FRAME_BYTES: usize =
    (X86_64_SYSCALL_SAVED_QWORDS + X86_64_SYSCALL_IRET_QWORDS) * core::mem::size_of::<u64>();
#[cfg(target_arch = "x86_64")]
static CURRENT_X86_64_SYSCALL_FRAME: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_arch = "x86")]
fn saved_registers_to_args(regs: &SavedRegisters) -> SyscallArgs {
    SyscallArgs {
        number: regs.eax,
        arg1: regs.ebx,
        arg2: regs.ecx,
        arg3: regs.edx,
        arg4: regs.esi,
        arg5: regs.edi,
    }
}

#[cfg(target_arch = "x86_64")]
fn saved_registers_to_args(regs: &SavedRegisters) -> SyscallArgs {
    SyscallArgs {
        number: regs.rax as u32,
        arg1: regs.rbx as u32,
        arg2: regs.rcx as u32,
        arg3: regs.rdx as u32,
        arg4: regs.rsi as u32,
        arg5: regs.rdi as u32,
    }
}

#[cfg(target_arch = "aarch64")]
fn saved_registers_to_args(regs: &SavedRegisters) -> SyscallArgs {
    SyscallArgs {
        number: regs.x8 as u32,
        arg1: regs.x0 as u32,
        arg2: regs.x1 as u32,
        arg3: regs.x2 as u32,
        arg4: regs.x3 as u32,
        arg5: regs.x4 as u32,
    }
}

#[cfg(target_arch = "aarch64")]
static CURRENT_AARCH64_SYSCALL_FRAME: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_arch = "aarch64")]
pub fn aarch64_syscall_from_exception(regs: *mut SavedRegisters) {
    if regs.is_null() {
        let _ = crate::failure::handle_failure(
            crate::failure::FailureSubsystem::Syscall,
            crate::failure::FailureKind::InvalidFrame,
            b"aarch64 syscall frame pointer null",
        );
        return;
    }

    let frame_check = crate::invariants::syscall::check_user_frame(
        regs as usize,
        core::mem::size_of::<SavedRegisters>(),
        usize::MAX,
    );
    if !frame_check.valid {
        crate::invariants::enforce(frame_check, b"aarch64 syscall frame invariant failed");
        let _ = crate::failure::handle_failure(
            crate::failure::FailureSubsystem::Syscall,
            crate::failure::FailureKind::InvalidFrame,
            b"aarch64 syscall frame invalid",
        );
        return;
    }

    crate::observability::emit_syscall_boundary(
        crate::observability::EventType::SyscallBoundary,
        0x3101,
        b"aarch64_syscall_exception_entry",
    );

    let regs = unsafe { &mut *regs };
    // Store the current exception frame pointer so fork_current_cow can clone it.
    CURRENT_AARCH64_SYSCALL_FRAME.store(regs as *const _ as usize, Ordering::Release);

    let args = saved_registers_to_args(regs);
    let caller_pid = get_current_pid();

    unsafe {
        SYSCALL_STATS.total_calls += 1;
        if (args.number as usize) < SYSCALL_STATS_SLOTS {
            SYSCALL_STATS.by_number[args.number as usize] += 1;
        }
    }

    let result = handle_syscall(args, caller_pid);

    if result.errno != 0 {
        unsafe {
            SYSCALL_STATS.errors += 1;
        }
    }

    regs.x0 = result.value as i64 as u64;
    regs.x1 = result.errno as u64;

    CURRENT_AARCH64_SYSCALL_FRAME.store(0, Ordering::Release);
}

/// Returns the address of `aarch64_fork_child_trampoline` — the AArch64 child
/// process entry point used by `fork_current_cow`.
#[cfg(target_arch = "aarch64")]
pub fn aarch64_fork_child_resume_rip() -> usize {
    extern "C" {
        fn aarch64_fork_child_trampoline();
    }
    aarch64_fork_child_trampoline as *const () as usize
}

/// Copy the current AArch64 SVC exception frame (x0-x30, 256 bytes) onto
/// `child_stack_top`, set x0=0 (fork child return value), and return the new
/// SP value that `fork_current_cow` should place in the child's `ProcessContext.sp`.
#[cfg(target_arch = "aarch64")]
pub fn clone_current_aarch64_syscall_return_frame(
    child_stack_top: usize,
) -> Result<usize, &'static str> {
    let frame_src = CURRENT_AARCH64_SYSCALL_FRAME.load(Ordering::Acquire);
    if frame_src == 0 {
        return Err("aarch64 syscall frame unavailable for fork");
    }
    const FRAME_SIZE: usize = 256; // VEC_FRAME_SIZE in aarch64_vectors.S
    let frame_base = child_stack_top
        .checked_sub(FRAME_SIZE)
        .ok_or("aarch64 fork: kernel stack too small for exception frame")?
        & !15usize;
    // SAFETY: frame_src points to a valid SavedRegisters on the current kernel
    // stack that is live for the duration of the syscall; frame_base points to
    // allocated child kernel stack memory.  Both are kernel-only addresses.
    unsafe {
        core::ptr::copy_nonoverlapping(frame_src as *const u8, frame_base as *mut u8, FRAME_SIZE);
        // x0 is the first field (offset 0); set to 0 so fork() returns 0 in child.
        core::ptr::write(frame_base as *mut u64, 0u64);
    }
    Ok(frame_base)
}

#[cfg(target_arch = "x86_64")]
struct X86_64SyscallFrameGuard;

#[cfg(target_arch = "x86_64")]
impl X86_64SyscallFrameGuard {
    #[inline]
    fn enter(regs: *const SavedRegisters) -> Self {
        CURRENT_X86_64_SYSCALL_FRAME.store(regs as usize, Ordering::Release);
        Self
    }
}

#[cfg(target_arch = "x86_64")]
impl Drop for X86_64SyscallFrameGuard {
    fn drop(&mut self) {
        CURRENT_X86_64_SYSCALL_FRAME.store(0, Ordering::Release);
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn x86_64_syscall_return_resume();
}

#[cfg(target_arch = "x86_64")]
pub fn x86_64_syscall_resume_rip() -> usize {
    x86_64_syscall_return_resume as usize
}

#[cfg(target_arch = "x86_64")]
pub fn clone_current_syscall_return_frame(
    kernel_stack_top: usize,
    packed_result: u64,
) -> Result<usize, &'static str> {
    let frame_src = CURRENT_X86_64_SYSCALL_FRAME.load(Ordering::Acquire);
    if frame_src == 0 {
        return Err("x86_64 syscall frame unavailable");
    }

    let total_bytes = X86_64_SYSCALL_FRAME_BYTES
        .checked_add(core::mem::size_of::<u64>())
        .ok_or("x86_64 syscall frame size overflow")?;
    let frame_base = kernel_stack_top
        .checked_sub(total_bytes)
        .ok_or("x86_64 syscall frame stack underflow")?
        & !15usize;
    let copy_dst = frame_base
        .checked_add(core::mem::size_of::<u64>())
        .ok_or("x86_64 syscall frame destination overflow")?;

    unsafe {
        core::ptr::write(frame_base as *mut u64, 0);
        core::ptr::copy_nonoverlapping(
            frame_src as *const u8,
            copy_dst as *mut u8,
            X86_64_SYSCALL_FRAME_BYTES,
        );
        core::ptr::write(
            (copy_dst as *mut u64).add(X86_64_SYSCALL_SAVED_QWORDS - 1),
            packed_result,
        );
    }

    Ok(frame_base)
}

/// SYSENTER handler (fast syscall path)
#[no_mangle]
#[cfg(target_arch = "x86")]
pub extern "C" fn sysenter_handler_rust(regs: *const SavedRegisters) -> u64 {
    syscall_handler_rust(regs)
}

/// Called from assembly syscall_entry stub
#[no_mangle]
pub extern "C" fn syscall_handler_rust(regs: *const SavedRegisters) -> u64 {
    let regs = unsafe { &*regs };

    #[cfg(target_arch = "x86_64")]
    let _frame_guard = X86_64SyscallFrameGuard::enter(regs as *const SavedRegisters);

    let args = saved_registers_to_args(regs);

    // Get actual caller PID from current process
    let caller_pid = get_current_pid();

    // Update stats
    unsafe {
        SYSCALL_STATS.total_calls += 1;
        if (args.number as usize) < SYSCALL_STATS_SLOTS {
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

/// x86_64 SYSCALL fast-path dispatcher used by `x86_64_sysenter.asm`.
///
/// The legacy Rust syscall core takes a saved-register frame, but the SYSCALL
/// entry stub already has the decoded arguments in registers. This thin wrapper
/// keeps the assembly link surface stable without duplicating the full frame
/// layout in assembly.
#[no_mangle]
#[cfg(target_arch = "x86_64")]
pub extern "C" fn oreulius_syscall_dispatch(
    nr: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    _a6: u64,
) -> u64 {
    let args = SyscallArgs {
        number: nr as u32,
        arg1: a1 as u32,
        arg2: a2 as u32,
        arg3: a3 as u32,
        arg4: a4 as u32,
        arg5: a5 as u32,
    };

    let caller_pid = get_current_pid();
    let result = handle_syscall(args, caller_pid);
    ((result.errno as u64) << 32) | ((result.value as u32) as u64)
}

/// Initialize syscall subsystem
pub fn init() {
    // Register INT 0x80 handler
    extern "C" {
        #[allow(dead_code)] // Used via address cast, not direct call
        fn syscall_entry();
        #[cfg(target_arch = "x86")]
        fn sysenter_entry();
    }

    // Set up IDT entry for INT 0x80 (system call interrupt)
    // The syscall_entry function in asm/syscall_entry.asm will:
    // 1. Save all registers to stack
    // 2. Call syscall_handler_rust() with register state
    // 3. Restore registers
    // 4. Return to user space with result in EAX:EDX

    // Register the handler with the interrupt system
    #[cfg(target_arch = "x86")]
    {
        // Enhanced IDT entry verification and validation
        let handler_addr = syscall_entry as usize;

        // Validate handler address is in kernel space and properly aligned
        if handler_addr < 0xC0000000 {
            vga::print_str("[SYSCALL] WARNING: Handler address in user space!\n");
        }
        if handler_addr % 4 != 0 {
            vga::print_str("[SYSCALL] WARNING: Handler address misaligned!\n");
        }

        // Log handler registration details
        crate::serial_println!("[SYSCALL] Registered handler at 0x{:08X}", handler_addr);
        crate::serial_println!("[SYSCALL] IDT vector: 0x80 (INT 0x80)");
        crate::serial_println!("[SYSCALL] Handler: syscall_entry -> syscall_handler_rust");

        // Verify the IDT entry (read back from IDT)
        // Note: Full verification would require reading IDTR and parsing IDT structure
        crate::serial_println!("[SYSCALL] IDT entry verification: assembly-managed");
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        vga::print_str("[SYSCALL] System call interface initialized (INT 0x80)\n");
        vga::print_str("[SYSCALL] Handler: syscall_entry -> syscall_handler_rust\n");
    }

    #[cfg(target_arch = "x86")]
    unsafe {
        // Configure SYSENTER/SYSEXIT fast path on 32-bit x86.
        write_msr(MSR_IA32_SYSENTER_CS, gdt::KERNEL_CS as u32, 0);
        write_msr(MSR_IA32_SYSENTER_ESP, gdt::sysenter_stack_top(), 0);
        write_msr(MSR_IA32_SYSENTER_EIP, sysenter_entry as u32, 0);
    }
    #[cfg(target_arch = "x86")]
    vga::print_str("[SYSCALL] SYSENTER configured\n");

    #[cfg(target_arch = "x86_64")]
    {
        let handler_addr = syscall_entry as usize;
        crate::serial_println!(
            "[SYSCALL] Registered x86_64 INT 0x80 handler at 0x{:016X}",
            handler_addr
        );
        vga::print_str("[SYSCALL] x86_64 INT 0x80 dispatch enabled\n");
    }

    #[cfg(target_arch = "aarch64")]
    {
        let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
        uart.init_early();
        uart.write_str("[SYSCALL] AArch64 syscall core initialized (kernel-side only)\n");
    }
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
const SYSCALL_STATS_SLOTS: usize = 256;

pub fn get_stats() -> &'static SyscallStats {
    unsafe { &*core::ptr::addr_of!(SYSCALL_STATS) }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_smoke_test_current_process() -> Result<u32, &'static str> {
    let caller_pid = get_current_pid();
    if caller_pid.0 == 0 {
        return Err("no current process");
    }

    let result = handle_syscall(
        SyscallArgs {
            number: SyscallNumber::GetPid as u32,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        caller_pid,
    );

    if result.errno != 0 {
        return Err("getpid smoke failed");
    }

    let returned = result.value as u32;
    if returned != caller_pid.0 {
        return Err("getpid smoke pid mismatch");
    }

    Ok(returned)
}

#[cfg(test)]
mod tests {
    use super::{handle_syscall, SyscallArgs};
    use crate::failure::policy::{last_failure_outcome, FailureAction, FailureSubsystem};
    use crate::observability::{ring_buffer, EventType};

    #[test]
    fn syscall_negative_trace_closure_chain() {
        let expected = crate::invariants::syscall::check_syscall_number(u16::MAX, 64);
        assert!(!expected.valid);
        assert_eq!(expected.id, "INV-SYSCALL-NUM-001");
        assert_eq!(expected.severity, crate::invariants::InvariantSeverity::Consistency);

        let before = ring_buffer::write_count();
        let result = handle_syscall(
            SyscallArgs {
                number: u32::MAX,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            crate::capability::ProcessId(0),
        );
        assert_ne!(result.errno, 0);

        let after = ring_buffer::write_count();

        crate::observability::assert_closure_chain_closure(
            before,
            after,
            &[
                EventType::InvariantViolation,
                EventType::FailurePolicyAction,
                EventType::TerminalFailure,
            ],
            FailureSubsystem::Syscall,
            FailureAction::FailStop,
        );
    }
}
