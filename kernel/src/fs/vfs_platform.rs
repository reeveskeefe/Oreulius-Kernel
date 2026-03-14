/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
use spin::Mutex;

#[cfg(not(target_arch = "aarch64"))]
pub type Pid = crate::process::Pid;

#[cfg(target_arch = "aarch64")]
pub type Pid = u32;

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn current_pid() -> Option<Pid> {
    crate::process::current_pid()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn current_pid() -> Option<Pid> {
    Some(aarch64_current_pid())
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub const fn pid_from_raw(raw: u32) -> Pid {
    crate::ipc::ProcessId(raw)
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub const fn pid_from_raw(raw: u32) -> Pid {
    raw
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub const fn pid_to_raw(pid: Pid) -> u32 {
    pid.0
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub const fn pid_to_raw(pid: Pid) -> u32 {
    pid
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn alloc_fd(pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
    crate::process::process_manager()
        .alloc_fd(pid, handle_id)
        .map_err(|e| e.as_str())
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn get_fd_handle(pid: Pid, fd: usize) -> Result<u64, &'static str> {
    crate::process::process_manager()
        .get_fd_handle(pid, fd)
        .map_err(|e| e.as_str())
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    crate::process::process_manager()
        .close_fd(pid, fd)
        .map_err(|e| e.as_str())
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn ticks_now() -> u64 {
    crate::pit::get_ticks()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn temporal_record_write(path: &str, payload: &[u8]) -> Result<u64, &'static str> {
    crate::temporal::record_write(path, payload).map_err(|_| "temporal record_write failed")
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn temporal_record_object_write(path: &str, payload: &[u8]) -> Result<u64, &'static str> {
    crate::temporal::record_object_write(path, payload)
        .map_err(|_| "temporal record_object_write failed")
}

#[cfg(target_arch = "aarch64")]
const AARCH64_BOOT_PID: Pid = 1;

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct Aarch64ProcessBridgeHooks {
    pub current_pid: fn() -> Option<Pid>,
    pub set_current_pid: fn(Pid) -> Result<(), &'static str>,
    pub spawn_process: fn(Option<Pid>) -> Result<Pid, &'static str>,
    pub destroy_process: fn(Pid) -> Result<(), &'static str>,
    pub process_fd_stats: fn() -> (usize, usize, Pid),
    pub alloc_fd: fn(Pid, u64) -> Result<usize, &'static str>,
    pub get_fd_handle: fn(Pid, usize) -> Result<u64, &'static str>,
    pub close_fd: fn(Pid, usize) -> Result<(), &'static str>,
}

#[cfg(target_arch = "aarch64")]
static AARCH64_PROCESS_BRIDGE: Mutex<Option<Aarch64ProcessBridgeHooks>> = Mutex::new(None);

#[cfg(target_arch = "aarch64")]
#[inline]
fn aarch64_bridge_hooks() -> Option<Aarch64ProcessBridgeHooks> {
    *AARCH64_PROCESS_BRIDGE.lock()
}

#[cfg(target_arch = "aarch64")]
fn aarch64_current_pid() -> Pid {
    if let Some(pid) = crate::process::current_pid().map(shared_pid_to_vfs) {
        if pid != 0 {
            return pid;
        }
    }
    if let Some(hooks) = aarch64_bridge_hooks() {
        if let Some(pid) = (hooks.current_pid)() {
            if pid != 0 {
                return pid;
            }
        }
    }
    AARCH64_BOOT_PID
}

#[cfg(target_arch = "aarch64")]
fn aarch64_require_bridge() -> Result<Aarch64ProcessBridgeHooks, &'static str> {
    aarch64_bridge_hooks().ok_or("Shared process backend not registered")
}

#[cfg(target_arch = "aarch64")]
fn shared_pid_to_vfs(pid: crate::process::Pid) -> Pid {
    pid.0
}

#[cfg(target_arch = "aarch64")]
fn vfs_pid_to_shared(pid: Pid) -> crate::process::Pid {
    crate::process::Pid::new(pid)
}

#[cfg(target_arch = "aarch64")]
fn bridge_current_pid_shared() -> Option<Pid> {
    crate::process::current_pid().map(shared_pid_to_vfs)
}

#[cfg(target_arch = "aarch64")]
fn bridge_set_current_pid_shared(pid: Pid) -> Result<(), &'static str> {
    crate::process::set_current_runtime_pid(vfs_pid_to_shared(pid))
}

#[cfg(target_arch = "aarch64")]
fn bridge_spawn_process_shared(parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
    let spawned = crate::process::process_manager()
        .spawn("a64-task", parent_pid.map(vfs_pid_to_shared))
        .map(shared_pid_to_vfs)
        .map_err(|e| e.as_str())?;
    if let Some(parent_pid) = parent_pid {
        let _ = crate::vfs::inherit_process_capability(parent_pid, spawned, None);
    }
    Ok(spawned)
}

#[cfg(target_arch = "aarch64")]
fn bridge_destroy_process_shared(pid: Pid) -> Result<(), &'static str> {
    let shared_pid = vfs_pid_to_shared(pid);
    crate::process::process_manager()
        .terminate(shared_pid)
        .map_err(|e| e.as_str())?;
    crate::vfs::clear_process_capability(pid);
    if crate::process::current_pid() == Some(shared_pid) {
        let _ = crate::process::set_current_runtime_pid(crate::process::Pid::new(AARCH64_BOOT_PID));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn bridge_process_fd_stats_shared() -> (usize, usize, Pid) {
    let (proc_count, fd_count, current_pid) = crate::process::runtime_fd_stats();
    (
        proc_count,
        fd_count,
        current_pid
            .map(shared_pid_to_vfs)
            .unwrap_or(AARCH64_BOOT_PID),
    )
}

#[cfg(target_arch = "aarch64")]
fn bridge_alloc_fd_shared(pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
    crate::process::process_manager()
        .alloc_fd(vfs_pid_to_shared(pid), handle_id)
        .map_err(|e| e.as_str())
}

#[cfg(target_arch = "aarch64")]
fn bridge_get_fd_handle_shared(pid: Pid, fd: usize) -> Result<u64, &'static str> {
    crate::process::process_manager()
        .get_fd_handle(vfs_pid_to_shared(pid), fd)
        .map_err(|e| e.as_str())
}

#[cfg(target_arch = "aarch64")]
fn bridge_close_fd_shared(pid: Pid, fd: usize) -> Result<(), &'static str> {
    crate::process::process_manager()
        .close_fd(vfs_pid_to_shared(pid), fd)
        .map_err(|e| e.as_str())
}

#[cfg(target_arch = "aarch64")]
fn aarch64_direct_set_current_pid(pid: Pid) -> Result<(), &'static str> {
    crate::process::set_current_runtime_pid(vfs_pid_to_shared(pid))
}

#[cfg(target_arch = "aarch64")]
fn aarch64_direct_spawn_process(parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
    let spawned = crate::process::process_manager()
        .spawn("a64-task", parent_pid.map(vfs_pid_to_shared))
        .map(shared_pid_to_vfs)
        .map_err(|e| e.as_str())?;
    if let Some(parent_pid) = parent_pid {
        let _ = crate::vfs::inherit_process_capability(parent_pid, spawned, None);
    }
    Ok(spawned)
}

#[cfg(target_arch = "aarch64")]
fn aarch64_direct_destroy_process(pid: Pid) -> Result<(), &'static str> {
    let shared_pid = vfs_pid_to_shared(pid);
    crate::process::process_manager()
        .terminate(shared_pid)
        .map_err(|e| e.as_str())?;
    crate::vfs::clear_process_capability(pid);
    if crate::process::current_pid() == Some(shared_pid) {
        let _ = crate::process::set_current_runtime_pid(crate::process::Pid::new(0));
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn aarch64_direct_process_fd_stats() -> (usize, usize, Pid) {
    let (proc_count, fd_count, current_pid) = crate::process::runtime_fd_stats();
    (
        proc_count,
        fd_count,
        current_pid
            .map(shared_pid_to_vfs)
            .unwrap_or(AARCH64_BOOT_PID),
    )
}

#[cfg(target_arch = "aarch64")]
pub fn alloc_fd(pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.alloc_fd)(pid, handle_id)
    } else {
        bridge_alloc_fd_shared(pid, handle_id)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn get_fd_handle(pid: Pid, fd: usize) -> Result<u64, &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.get_fd_handle)(pid, fd)
    } else {
        bridge_get_fd_handle_shared(pid, fd)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.close_fd)(pid, fd)
    } else {
        bridge_close_fd_shared(pid, fd)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_register_shared_process_bridge(hooks: Aarch64ProcessBridgeHooks) {
    *AARCH64_PROCESS_BRIDGE.lock() = Some(hooks);
    if let Some(pid) = (hooks.current_pid)() {
        if pid != 0 {
            let _ = (hooks.set_current_pid)(pid);
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_register_default_shared_process_bridge() {
    aarch64_register_shared_process_bridge(Aarch64ProcessBridgeHooks {
        current_pid: bridge_current_pid_shared,
        set_current_pid: bridge_set_current_pid_shared,
        spawn_process: bridge_spawn_process_shared,
        destroy_process: bridge_destroy_process_shared,
        process_fd_stats: bridge_process_fd_stats_shared,
        alloc_fd: bridge_alloc_fd_shared,
        get_fd_handle: bridge_get_fd_handle_shared,
        close_fd: bridge_close_fd_shared,
    });
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_clear_shared_process_bridge() {
    *AARCH64_PROCESS_BRIDGE.lock() = None;
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_shared_process_bridge_registered() -> bool {
    AARCH64_PROCESS_BRIDGE.lock().is_some()
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_set_current_pid(pid: Pid) -> Result<(), &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.set_current_pid)(pid)
    } else {
        aarch64_direct_set_current_pid(pid)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_spawn_process(parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.spawn_process)(parent_pid)
    } else {
        aarch64_direct_spawn_process(parent_pid)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_destroy_process(pid: Pid) -> Result<(), &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.destroy_process)(pid)
    } else {
        aarch64_direct_destroy_process(pid)
    }
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_process_fd_stats() -> (usize, usize, Pid) {
    if let Some(hooks) = aarch64_bridge_hooks() {
        (hooks.process_fd_stats)()
    } else {
        aarch64_direct_process_fd_stats()
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn ticks_now() -> u64 {
    crate::arch::aarch64_virt::timer_ticks()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn temporal_record_write(_path: &str, _payload: &[u8]) -> Result<u64, &'static str> {
    Ok(0)
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn temporal_record_object_write(_path: &str, _payload: &[u8]) -> Result<u64, &'static str> {
    Ok(0)
}
