/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Unified Pid type
//
// Both x86 and AArch64 use the shared `crate::ipc::ProcessId` wrapper.
// The old AArch64 bridge shim that remapped Pid → u32 has been removed:
// process::Pid is already `repr(transparent)` over u32, so the two
// representations were equivalent.  Using a single canonical type eliminates
// the impedance mismatch and allows all subsystems to share code paths.
// ---------------------------------------------------------------------------

pub type Pid = crate::process::Pid;

#[inline]
pub fn current_pid() -> Option<Pid> {
    crate::process::current_pid()
}

#[inline]
pub const fn pid_from_raw(raw: u32) -> Pid {
    crate::ipc::ProcessId(raw)
}

#[inline]
pub const fn pid_to_raw(pid: Pid) -> u32 {
    pid.0
}

// ---------------------------------------------------------------------------
// File-descriptor helpers — delegate to the shared process manager
// ---------------------------------------------------------------------------

#[inline]
pub fn alloc_fd(pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
    crate::process::process_manager()
        .alloc_fd(pid, handle_id)
        .map_err(|e| e.as_str())
}

#[inline]
pub fn get_fd_handle(pid: Pid, fd: usize) -> Result<u64, &'static str> {
    crate::process::process_manager()
        .get_fd_handle(pid, fd)
        .map_err(|e| e.as_str())
}

#[inline]
pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    crate::process::process_manager()
        .close_fd(pid, fd)
        .map_err(|e| e.as_str())
}

// ---------------------------------------------------------------------------
// Process lifecycle helpers
// ---------------------------------------------------------------------------

#[inline]
pub fn spawn_process(parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
    let spawned = crate::process::process_manager()
        .spawn("task", parent_pid)
        .map_err(|e| e.as_str())?;
    if let Some(parent) = parent_pid {
        let _ = crate::vfs::inherit_process_capability(parent, spawned, None);
    }
    Ok(spawned)
}

#[inline]
pub fn destroy_process(pid: Pid) -> Result<(), &'static str> {
    crate::process::process_manager()
        .terminate(pid)
        .map_err(|e| e.as_str())?;
    crate::vfs::clear_process_capability(pid);
    Ok(())
}

#[inline]
pub fn process_fd_stats() -> (usize, usize, Pid) {
    let (proc_count, fd_count, current) = crate::process::runtime_fd_stats();
    (proc_count, fd_count, current.unwrap_or(Pid::new(1)))
}

// ---------------------------------------------------------------------------
// Tick / time
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn ticks_now() -> u64 {
    crate::pit::get_ticks()
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn ticks_now() -> u64 {
    crate::arch::aarch64_virt::timer_ticks()
}

// ---------------------------------------------------------------------------
// Temporal recording — real write-through on all arches.
//
// On AArch64 the temporal subsystem was previously gated out, leaving these
// as silent Ok(0) stubs.  Now that temporal is part of the shared compile
// surface we route through the same persistence path used on x86_64.
// ---------------------------------------------------------------------------

#[inline]
pub fn temporal_record_write(path: &str, payload: &[u8]) -> Result<u64, &'static str> {
    crate::temporal::record_write(path, payload).map_err(|_| "temporal record_write failed")
}

#[inline]
pub fn temporal_record_object_write(path: &str, payload: &[u8]) -> Result<u64, &'static str> {
    crate::temporal::record_object_write(path, payload)
        .map_err(|_| "temporal record_object_write failed")
}
