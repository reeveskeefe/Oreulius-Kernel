/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! System Call Interface
//!
//! Provides the boundary between user mode (ring 3) and kernel mode (ring 0).
//! Includes capability checking at the syscall boundary.

use crate::capability::{self, CapabilityType, Rights};
use crate::gdt;
use crate::process_asm::{
    write_msr, MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_EIP, MSR_IA32_SYSENTER_ESP,
};
use crate::vga;

// POSIX-style error codes
const ENOSYS: u32 = 38; // Function not implemented
const EINVAL: u32 = 22; // Invalid argument
const EACCES: u32 = 13; // Permission denied
const EPERM:  u32 =  1; // Operation not permitted (caller not privileged)
const EFAULT: u32 = 14; // Bad address
const ENOMEM: u32 = 12; // Out of memory
const EIO: u32 = 5; // I/O error
const EBADF: u32 = 9; // Bad file descriptor
const ENOENT: u32 = 2; // No such file or directory
const EAGAIN: u32 = 11; // Try again

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
    object_hi: u32,
    object_lo: u32,
    rights: u32,
    cap_type: u32,
    extra0: u32,
    extra1: u32,
    extra2: u32,
    extra3: u32,
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
        object_hi: cap.extra[0],
        object_lo: cap.object_id,
        rights: cap.rights,
        cap_type: cap.cap_type as u32,
        extra0: cap.extra[0],
        extra1: cap.extra[1],
        extra2: cap.extra[2],
        extra3: cap.extra[3],
    }
}

fn sys_cap_to_ipc(raw: &SysIpcCapability) -> Result<crate::ipc::Capability, ()> {
    let cap_type = ipc_cap_type_from_raw(raw.cap_type).ok_or(())?;
    let mut cap =
        crate::ipc::Capability::with_type(raw.cap_id, raw.object_lo, raw.rights, cap_type);
    cap.extra = [raw.object_hi, raw.extra1, raw.extra2, raw.extra3];
    Ok(cap)
}

/// Main syscall handler (called from interrupt/trap)
pub fn handle_syscall(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let syscall = SyscallNumber::from(args.number);

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
        let _ = crate::process::process_manager().terminate(crate::process::Pid(caller_pid.0));
        let mut scheduler = crate::quantum_scheduler::scheduler().lock();
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
    vga::print_str("[SYSCALL] Process ");
    crate::commands::print_u32(caller_pid.0);
    vga::print_str(" exiting with code ");
    crate::commands::print_u32(exit_code as u32);
    vga::print_str("\n");

    // Remove process from process/security/capability subsystems.
    let _ = crate::process::process_manager().terminate(crate::process::Pid(caller_pid.0));

    // Remove from runtime scheduler.
    let mut scheduler = crate::quantum_scheduler::scheduler().lock();
    let _ = scheduler.remove_process(caller_pid);

    // Yield to next process
    drop(scheduler);
    crate::quantum_scheduler::yield_now();

    SyscallResult::ok(exit_code)
}

fn sys_fork(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _flags = args.arg1;

    vga::print_str("[SYSCALL] Fork requested by PID ");
    crate::commands::print_u32(caller_pid.0);
    vga::print_str("\n");

    let mut scheduler = crate::quantum_scheduler::scheduler().lock();
    match scheduler.fork_current_cow() {
        Ok(child_pid) => {
            vga::print_str("[SYSCALL] Fork successful, child PID=");
            crate::commands::print_u32(child_pid.0);
            vga::print_str("\n");
            SyscallResult::ok(child_pid.0 as i32)
        }
        Err(_) => {
            vga::print_str("[SYSCALL] Fork failed\n");
            SyscallResult::err(ENOMEM)
        }
    }
}

fn sys_yield(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let _yield_hint = args.arg1; // Optional: 0=normal, 1=I/O wait, 2=explicit

    // Mark process as yielding voluntarily (good for statistics)
    let mut scheduler = crate::quantum_scheduler::scheduler().lock();
    scheduler.record_voluntary_yield();
    drop(scheduler);

    // Log for debugging (optional, can be removed for production)
    if args.arg1 > 0 {
        vga::print_str("[SYSCALL] PID ");
        crate::commands::print_u32(caller_pid.0);
        vga::print_str(" yielding (hint=");
        crate::commands::print_u32(args.arg1);
        vga::print_str(")\n");
    }

    crate::quantum_scheduler::yield_now();
    SyscallResult::ok(0)
}

fn sys_getpid(_args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    SyscallResult::ok(caller_pid.0 as i32)
}

fn sys_sleep(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let ms = args.arg1;

    if ms == 0 {
        // Sleep(0) is just a yield
        crate::quantum_scheduler::yield_now();
        return SyscallResult::ok(0);
    }

    // Calculate wake time (current ticks + ms converted to ticks)
    let current_ticks = crate::pit::get_ticks();
    let sleep_ticks = (ms as u64 * 100) / 1000; // Convert ms to ticks (100 Hz timer)
    let wake_time = current_ticks + sleep_ticks;

    if crate::quantum_scheduler::sleep_until(caller_pid, wake_time).is_err() {
        return SyscallResult::err(EINVAL);
    }

    SyscallResult::ok(0)
}

fn sys_exec(args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    let buf_ptr = args.arg1 as usize;
    let len = args.arg2 as usize;

    if len == 0 || len > 256 * 1024 {
        return SyscallResult::err(EINVAL);
    }

    if buf_ptr >= crate::paging::KERNEL_BASE || buf_ptr + len >= crate::paging::KERNEL_BASE {
        return SyscallResult::err(EFAULT);
    }

    let bytes = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
    let module_id = match crate::wasm::load_module(bytes) {
        Ok(id) => id,
        Err(_) => return SyscallResult::err(EIO),
    };

    {
        let mut scheduler = crate::quantum_scheduler::scheduler().lock();
        if scheduler.exec_current_wasm(module_id as u32).is_err() {
            return SyscallResult::err(EINVAL);
        }
    }

    if crate::wasm::call_function(module_id, 0, &[]).is_err() {
        return SyscallResult::err(EINVAL);
    }

    SyscallResult::ok(0)
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

    vga::print_str("[SYSCALL] Channel create by PID ");
    crate::commands::print_u32(caller_pid.0);

    // Parse channel configuration flags from arg1
    // Bits 0-7: Channel flags (bounded, unbounded, high-priority, reliable, async)
    // Bits 8-15: Priority level (0-255)
    let config = args.arg1 as u32;
    let flags_bits = config & 0xFF;
    let priority = ((config >> 8) & 0xFF) as u8;

    // Default to medium priority if not specified
    let priority = if priority == 0 { 128 } else { priority };

    let flags = crate::ipc::ChannelFlags::new(flags_bits);

    vga::print_str(" with flags=0x");
    crate::commands::print_hex_u32(flags_bits);
    vga::print_str(" priority=");
    crate::commands::print_u32(priority as u32);
    vga::print_str("\n");

    // Create channel via IPC manager with custom configuration
    match crate::ipc::create_channel_for_process_with_flags(
        crate::ipc::ProcessId(caller_pid.0),
        flags,
        priority,
    ) {
        Ok(channel_id) => {
            vga::print_str("[SYSCALL] Created channel ID=");
            crate::commands::print_u32(channel_id as u32);
            vga::print_str("\n");
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

    // Copy message from user space (for now, treat as kernel space for testing)
    let message = unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, msg_len) };

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
    let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len) };

    match crate::ipc::receive_message_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        buffer,
    ) {
        Ok(bytes_received) => SyscallResult::ok(bytes_received as i32),
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

    let message = unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, msg_len) };
    let mut caps = [crate::ipc::Capability::new(0, 0, 0); crate::ipc::MAX_CAPS_PER_MESSAGE];
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

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len) };
    let mut caps = [crate::ipc::Capability::new(0, 0, 0); crate::ipc::MAX_CAPS_PER_MESSAGE];

    match crate::ipc::receive_message_with_caps_for_process(
        crate::ipc::ProcessId(caller_pid.0),
        crate::ipc::ChannelId(channel_id as u32),
        buffer,
        &mut caps,
    ) {
        Ok((bytes_received, caps_received)) => {
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
    let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };

    match crate::fs::read(fd as usize, buffer) {
        Ok(bytes_read) => SyscallResult::ok(bytes_read as i32),
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
    let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len) };

    match crate::fs::list_dir(path, buffer) {
        Ok(count) => SyscallResult::ok(count as i32),
        Err(_) => SyscallResult::err(ENOENT),
    }
}

// ============================================================================
// Memory Management Syscalls
// ============================================================================

fn sys_memory_alloc(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let size = args.arg1 as usize;
    let flags = args.arg2;

    // Validate size
    if size == 0 || size > 1024 * 1024 * 64 {
        // Max 64MB
        return SyscallResult::err(EINVAL);
    }

    // Round up to page size
    let page_size = 4096;
    let aligned_size = (size + page_size - 1) & !(page_size - 1);

    // Allocate pages from memory manager
    let num_pages = aligned_size / page_size;
    let mut base_addr = 0;

    for i in 0..num_pages {
        match crate::memory::allocate_frame() {
            Ok(addr) => {
                if i == 0 {
                    base_addr = addr;
                }
                // Map into process address space (user space starts at 0x10000000)
                let virt_addr = 0x10000000 + (i * page_size);
                // Would call paging::map_page() here
                let _ = (addr, virt_addr); // Use variables to avoid warnings
            }
            Err(_) => {
                // Out of memory - free any already allocated
                return SyscallResult::err(ENOMEM);
            }
        }
    }

    // Return virtual address to user space
    let user_addr = 0x10000000;
    let _ = (base_addr, flags, caller_pid); // Use variables
    SyscallResult::ok(user_addr as i32)
}

fn sys_memory_free(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let addr = args.arg1 as usize;
    let _size = args.arg2 as usize;

    // Validate address is in user space
    if addr < 0x10000000 || addr >= 0xC0000000 {
        return SyscallResult::err(EINVAL);
    }

    // Unmap pages and free physical memory
    // Would call paging::unmap_page() and memory::free_frame()
    let _ = (addr, caller_pid); // Use variables

    SyscallResult::ok(0)
}

fn sys_memory_map(args: SyscallArgs, caller_pid: capability::ProcessId) -> SyscallResult {
    let addr = args.arg1 as usize;
    let size = args.arg2 as usize;
    let prot = args.arg3; // Protection flags: R/W/X
    let flags = args.arg4; // MAP_SHARED, MAP_PRIVATE, etc.

    // Validate parameters
    if size == 0 || size > 1024 * 1024 * 64 {
        return SyscallResult::err(EINVAL);
    }

    // Would implement full mmap() semantics here
    let _ = (addr, prot, flags, caller_pid);

    SyscallResult::err(ENOSYS)
}

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
    let cap_id     = args.arg2;

    if cap_id == 0 {
        // Revoke every capability held by target_pid.
        match capability::capability_manager().revoke_all_capabilities(target_pid) {
            Ok(_)  => SyscallResult::ok(0),
            Err(_) => SyscallResult::err(EINVAL),
        }
    } else {
        // Revoke a single specific capability.
        match capability::capability_manager().revoke_capability(target_pid, cap_id) {
            Ok(_)  => SyscallResult::ok(0),
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

    // Write to VGA console
    for &byte in buffer {
        if byte == b'\n' {
            vga::print_char('\n');
        } else if byte >= 32 && byte < 127 {
            vga::print_char(byte as char);
        }
    }

    SyscallResult::ok(len as i32)
}

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
    let buffer = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };

    let mut bytes_read = 0;
    for i in 0..len {
        if let Some(ch) = crate::keyboard::poll() {
            buffer[i] = ch as u8;
            bytes_read += 1;
        } else {
            break;
        }
    }

    SyscallResult::ok(bytes_read as i32)
}

// ============================================================================
// WASM Syscalls
// ============================================================================

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
    match crate::wasm::load_module(wasm_bytes) {
        Ok(module_id) => {
            let _ = caller_pid; // Use variable
            SyscallResult::ok(module_id as i32)
        }
        Err(_) => SyscallResult::err(EINVAL),
    }
}

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
    match crate::wasm::call_function(module_id, func_idx, wasm_args) {
        Ok(result) => {
            let _ = caller_pid; // Use variable
            SyscallResult::ok(result as i32)
        }
        Err(_) => SyscallResult::err(EINVAL),
    }
}

fn sys_jit_return(_args: SyscallArgs, _caller_pid: capability::ProcessId) -> SyscallResult {
    if crate::wasm::jit_user_mark_returned() {
        SyscallResult::ok(0)
    } else {
        SyscallResult::err(EACCES)
    }
}

fn sys_service_pointer_register(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let instance_id = args.arg1 as usize;
    let function_index = args.arg2 as usize;
    let allow_delegate = (args.arg3 & 0x1) != 0;

    match crate::wasm::register_service_pointer(
        caller_pid,
        instance_id,
        function_index,
        allow_delegate,
    ) {
        Ok(registration) => SyscallResult::ok(registration.cap_id as i32),
        Err(_) => SyscallResult::err(EACCES),
    }
}

fn sys_service_pointer_invoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let object_id = ((args.arg2 as u64) << 32) | args.arg1 as u64;
    let args_ptr = args.arg3 as usize;
    let args_count = args.arg4 as usize;

    if args_count > crate::wasm::MAX_SERVICE_CALL_ARGS {
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

    match crate::wasm::invoke_service_pointer(caller_pid, object_id, call_args) {
        Ok(result) => SyscallResult::ok(result as i32),
        Err(_) => SyscallResult::err(EACCES),
    }
}

fn sys_service_pointer_revoke(
    args: SyscallArgs,
    caller_pid: capability::ProcessId,
) -> SyscallResult {
    let object_id = ((args.arg2 as u64) << 32) | args.arg1 as u64;
    match crate::wasm::revoke_service_pointer(caller_pid, object_id) {
        Ok(()) => SyscallResult::ok(0),
        Err(_) => SyscallResult::err(EACCES),
    }
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
    let scheduler = crate::quantum_scheduler::scheduler().lock();
    if let Some(pid) = scheduler.get_current_pid() {
        capability::ProcessId(pid.0)
    } else {
        // No current process, return kernel PID
        capability::ProcessId(0)
    }
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

/// SYSENTER handler (fast syscall path)
#[no_mangle]
pub extern "C" fn sysenter_handler_rust(regs: *const SavedRegisters) -> u64 {
    syscall_handler_rust(regs)
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

    // Get actual caller PID from current process
    let caller_pid = get_current_pid();

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
        #[allow(dead_code)] // Used via address cast, not direct call
        fn syscall_entry();
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

    vga::print_str("[SYSCALL] System call interface initialized (INT 0x80)\n");
    vga::print_str("[SYSCALL] Handler: syscall_entry -> syscall_handler_rust\n");

    // Configure SYSENTER/SYSEXIT fast path
    unsafe {
        write_msr(MSR_IA32_SYSENTER_CS, gdt::KERNEL_CS as u32, 0);
        write_msr(MSR_IA32_SYSENTER_ESP, gdt::sysenter_stack_top(), 0);
        write_msr(MSR_IA32_SYSENTER_EIP, sysenter_entry as u32, 0);
    }
    vga::print_str("[SYSCALL] SYSENTER configured\n");
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
