/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
use spin::Mutex;
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU32, Ordering};

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
const AARCH64_MAX_PROCS: usize = 32;
#[cfg(target_arch = "aarch64")]
const AARCH64_MAX_FD: usize = 64;

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct Aarch64ProcSlot {
    in_use: bool,
    pid: Pid,
    parent_pid: Pid,
    fds: [Option<u64>; AARCH64_MAX_FD],
}

#[cfg(target_arch = "aarch64")]
impl Aarch64ProcSlot {
    const EMPTY: Self = Self {
        in_use: false,
        pid: 0,
        parent_pid: 0,
        fds: [None; AARCH64_MAX_FD],
    };

    fn init(&mut self, pid: Pid, parent_pid: Pid) {
        self.in_use = true;
        self.pid = pid;
        self.parent_pid = parent_pid;
        self.fds.fill(None);
    }
}

#[cfg(target_arch = "aarch64")]
struct Aarch64ProcManager {
    next_pid: Pid,
    slots: [Aarch64ProcSlot; AARCH64_MAX_PROCS],
}

#[cfg(target_arch = "aarch64")]
impl Aarch64ProcManager {
    const fn new() -> Self {
        Self {
            next_pid: AARCH64_BOOT_PID + 1,
            slots: [Aarch64ProcSlot::EMPTY; AARCH64_MAX_PROCS],
        }
    }

    fn find_slot_index(&self, pid: Pid) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.in_use && slot.pid == pid)
    }

    fn alloc_slot_index(&mut self) -> Result<usize, &'static str> {
        self.slots
            .iter()
            .position(|slot| !slot.in_use)
            .ok_or("AArch64 process table full")
    }

    fn ensure_process(&mut self, pid: Pid) -> Result<usize, &'static str> {
        if pid == 0 {
            return Err("Invalid PID 0");
        }
        if let Some(idx) = self.find_slot_index(pid) {
            return Ok(idx);
        }
        let idx = self.alloc_slot_index()?;
        let parent = if pid == AARCH64_BOOT_PID { 0 } else { AARCH64_BOOT_PID };
        self.slots[idx].init(pid, parent);
        Ok(idx)
    }

    fn create_process(&mut self, parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
        for _ in 0..AARCH64_MAX_PROCS * 2 {
            let pid = if self.next_pid == 0 { AARCH64_BOOT_PID + 1 } else { self.next_pid };
            self.next_pid = self.next_pid.wrapping_add(1).max(AARCH64_BOOT_PID + 1);
            if self.find_slot_index(pid).is_none() {
                let idx = self.alloc_slot_index()?;
                self.slots[idx].init(pid, parent_pid.unwrap_or(AARCH64_BOOT_PID));
                return Ok(pid);
            }
        }
        Err("No free PID available")
    }

    fn destroy_process(&mut self, pid: Pid) -> Result<(), &'static str> {
        if pid == 0 {
            return Err("Invalid PID 0");
        }
        let Some(idx) = self.find_slot_index(pid) else {
            return Err("Process not found");
        };
        if pid == AARCH64_BOOT_PID {
            self.slots[idx].fds.fill(None);
            return Ok(());
        }
        self.slots[idx] = Aarch64ProcSlot::EMPTY;
        Ok(())
    }

    fn alloc_fd(&mut self, pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
        let idx = self.ensure_process(pid)?;
        let slot = &mut self.slots[idx];
        for (fd, entry) in slot.fds.iter_mut().enumerate() {
            if entry.is_none() {
                *entry = Some(handle_id);
                return Ok(fd);
            }
        }
        Err("File descriptor table full")
    }

    fn get_fd_handle(&mut self, pid: Pid, fd: usize) -> Result<u64, &'static str> {
        let idx = self.ensure_process(pid)?;
        self.slots[idx]
            .fds
            .get(fd)
            .and_then(|entry| *entry)
            .ok_or("Invalid file descriptor")
    }

    fn close_fd(&mut self, pid: Pid, fd: usize) -> Result<(), &'static str> {
        let idx = self.ensure_process(pid)?;
        let entry = self.slots[idx]
            .fds
            .get_mut(fd)
            .ok_or("Invalid file descriptor")?;
        if entry.is_none() {
            return Err("Invalid file descriptor");
        }
        *entry = None;
        Ok(())
    }

    fn stats(&self) -> (usize, usize) {
        let proc_count = self.slots.iter().filter(|slot| slot.in_use).count();
        let fd_count = self
            .slots
            .iter()
            .filter(|slot| slot.in_use)
            .map(|slot| slot.fds.iter().filter(|fd| fd.is_some()).count())
            .sum();
        (proc_count, fd_count)
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub struct Aarch64ProcessBridgeHooks {
    pub current_pid: fn() -> Option<Pid>,
    pub alloc_fd: fn(Pid, u64) -> Result<usize, &'static str>,
    pub get_fd_handle: fn(Pid, usize) -> Result<u64, &'static str>,
    pub close_fd: fn(Pid, usize) -> Result<(), &'static str>,
}

#[cfg(target_arch = "aarch64")]
static AARCH64_CURRENT_PID: AtomicU32 = AtomicU32::new(AARCH64_BOOT_PID);
#[cfg(target_arch = "aarch64")]
static AARCH64_PROC_MANAGER: Mutex<Aarch64ProcManager> = Mutex::new(Aarch64ProcManager::new());
#[cfg(target_arch = "aarch64")]
static AARCH64_PROCESS_BRIDGE: Mutex<Option<Aarch64ProcessBridgeHooks>> = Mutex::new(None);

#[cfg(target_arch = "aarch64")]
#[inline]
fn aarch64_bridge_hooks() -> Option<Aarch64ProcessBridgeHooks> {
    *AARCH64_PROCESS_BRIDGE.lock()
}

#[cfg(target_arch = "aarch64")]
fn aarch64_current_pid() -> Pid {
    if let Some(hooks) = aarch64_bridge_hooks() {
        if let Some(pid) = (hooks.current_pid)() {
            if pid != 0 {
                return pid;
            }
        }
    }

    let pid = match AARCH64_CURRENT_PID.load(Ordering::Relaxed) {
        0 => AARCH64_BOOT_PID,
        pid => pid,
    };
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    let _ = mgr.ensure_process(pid);
    pid
}

#[cfg(target_arch = "aarch64")]
pub fn alloc_fd(pid: Pid, handle_id: u64) -> Result<usize, &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        return (hooks.alloc_fd)(pid, handle_id);
    }
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    mgr.alloc_fd(pid, handle_id)
}

#[cfg(target_arch = "aarch64")]
pub fn get_fd_handle(pid: Pid, fd: usize) -> Result<u64, &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        return (hooks.get_fd_handle)(pid, fd);
    }
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    mgr.get_fd_handle(pid, fd)
}

#[cfg(target_arch = "aarch64")]
pub fn close_fd(pid: Pid, fd: usize) -> Result<(), &'static str> {
    if let Some(hooks) = aarch64_bridge_hooks() {
        return (hooks.close_fd)(pid, fd);
    }
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    mgr.close_fd(pid, fd)
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_register_shared_process_bridge(hooks: Aarch64ProcessBridgeHooks) {
    *AARCH64_PROCESS_BRIDGE.lock() = Some(hooks);
    if let Some(pid) = (hooks.current_pid)() {
        if pid != 0 {
            let _ = aarch64_set_current_pid(pid);
        }
    }
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
    {
        let mut mgr = AARCH64_PROC_MANAGER.lock();
        let _ = mgr.ensure_process(pid)?;
    }
    AARCH64_CURRENT_PID.store(pid, Ordering::Relaxed);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_spawn_process(parent_pid: Option<Pid>) -> Result<Pid, &'static str> {
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    mgr.create_process(parent_pid)
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_destroy_process(pid: Pid) -> Result<(), &'static str> {
    let mut mgr = AARCH64_PROC_MANAGER.lock();
    mgr.destroy_process(pid)?;
    if AARCH64_CURRENT_PID.load(Ordering::Relaxed) == pid {
        AARCH64_CURRENT_PID.store(AARCH64_BOOT_PID, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub fn aarch64_process_fd_stats() -> (usize, usize, Pid) {
    let current = aarch64_current_pid();
    let mgr = AARCH64_PROC_MANAGER.lock();
    let (proc_count, fd_count) = mgr.stats();
    (proc_count, fd_count, current)
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
