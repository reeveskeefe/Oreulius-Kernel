/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Oreulia Process Manager v0
//!
//! Provides multi-tasking with per-process capability tables.
//!
//! Key principles:
//! - Fixed number of processes (64 max)
//! - Round-robin cooperative scheduling
//! - Per-process capability isolation
//! - Explicit yield() for context switching
//! - No preemption in v0 (simplified)

#![allow(dead_code)]

use crate::arch::mmu::PhysAddr;
use crate::process_platform::{self, ChannelCapability};
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Mutex;

/// Maximum number of processes
pub const MAX_PROCESSES: usize = 64;

/// Maximum capabilities per process
pub const MAX_CAPS_PER_PROCESS: usize = 128;

/// Maximum open file descriptors per process
pub const MAX_FD: usize = 32;

/// Stack size per process (64 KiB)
pub const STACK_SIZE: usize = 64 * 1024;

// ============================================================================
// Fork / Clone Flags
// ============================================================================

/// `rust_create_process` flag: child inherits parent's open file descriptors.
/// Without this flag the child starts with an empty FD table.
pub const CLONE_FILES: u32 = 0x0001;

/// `rust_create_process` flag: child inherits parent's capability table.
/// Each capability is re-signed with the child PID by `clone_task_capabilities`.
/// Without this flag the child starts with an empty capability table.
pub const CLONE_CAPS: u32 = 0x0002;

// ============================================================================
// Process ID Management
// ============================================================================

/// Process ID newtype (re-exported through process_platform for cross-arch ports)
pub use crate::process_platform::Pid;

// ============================================================================
// Process State
// ============================================================================

/// Process execution state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is ready to run
    Ready,
    /// Process is currently running
    Running,
    /// Process is blocked waiting for I/O
    Blocked,
    /// Process is waiting on a channel
    WaitingOnChannel,
    /// Process has terminated
    Terminated,
}

impl ProcessState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessState::Ready => "Ready",
            ProcessState::Running => "Running",
            ProcessState::Blocked => "Blocked",
            ProcessState::WaitingOnChannel => "Waiting",
            ProcessState::Terminated => "Terminated",
        }
    }
}

// ============================================================================
// Capability Table
// ============================================================================

/// A capability stored in a process's capability table
#[derive(Debug, Clone, Copy)]
pub struct StoredCapability {
    /// Slot index in the table
    pub slot: u32,
    /// The actual capability
    pub cap: CapabilityVariant,
    /// Whether this slot is occupied
    pub occupied: bool,
}

/// Different types of capabilities a process can hold
#[derive(Debug, Clone, Copy)]
pub enum CapabilityVariant {
    /// Channel capability for IPC
    Channel(ChannelCapability),
    /// Filesystem capability (from fs module)
    Filesystem { cap_id: u32, rights: u32 },
    /// Generic capability
    Generic {
        cap_id: u32,
        object_id: u32,
        rights: u32,
    },
}

/// Per-process capability table
#[derive(Clone)]
pub struct CapabilityTable {
    /// Capability slots
    caps: [Option<CapabilityVariant>; MAX_CAPS_PER_PROCESS],
    /// Next capability slot to allocate
    next_slot: u32,
}

impl CapabilityTable {
    pub const fn new() -> Self {
        CapabilityTable {
            caps: [None; MAX_CAPS_PER_PROCESS],
            next_slot: 0,
        }
    }

    /// Insert a capability and return its slot
    pub fn insert(&mut self, cap: CapabilityVariant) -> Result<u32, ProcessError> {
        // Find empty slot
        for (idx, slot) in self.caps.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cap);
                return Ok(idx as u32);
            }
        }

        Err(ProcessError::CapabilityTableFull)
    }

    /// Get a capability by slot
    pub fn get(&self, slot: u32) -> Option<&CapabilityVariant> {
        if (slot as usize) < MAX_CAPS_PER_PROCESS {
            self.caps[slot as usize].as_ref()
        } else {
            None
        }
    }

    /// Remove a capability
    pub fn remove(&mut self, slot: u32) -> Result<(), ProcessError> {
        if (slot as usize) < MAX_CAPS_PER_PROCESS {
            self.caps[slot as usize] = None;
            Ok(())
        } else {
            Err(ProcessError::InvalidCapSlot)
        }
    }

    /// Get count of capabilities
    pub fn count(&self) -> usize {
        self.caps.iter().filter(|c| c.is_some()).count()
    }

    /// List all capability slots
    pub fn list(&self) -> impl Iterator<Item = (u32, &CapabilityVariant)> {
        self.caps
            .iter()
            .enumerate()
            .filter_map(|(idx, cap)| cap.as_ref().map(|c| (idx as u32, c)))
    }
}

// ============================================================================
// Process Control Block
// ============================================================================

/// Process priority (for future scheduler improvements)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessPriority {
    High = 3,
    Normal = 2,
    Low = 1,
}

/// 16-byte aligned FPU State Buffer (512 bytes for fxsave)
#[repr(align(16))]
#[derive(Clone)]
pub struct FpuState(pub [u8; 512]);

/// Process Control Block (PCB)
#[derive(Clone)]
pub struct Process {
    /// Process ID
    pub pid: Pid,
    /// Process name
    pub name: [u8; 32],
    /// Current state
    pub state: ProcessState,
    /// Priority
    pub priority: ProcessPriority,
    /// Parent process ID (None for init)
    pub parent: Option<Pid>,
    /// Capability table
    pub capabilities: CapabilityTable,
    /// Stack pointer (simplified - not real yet)
    pub stack_ptr: usize,
    /// Program counter (simplified - not real yet)
    pub program_counter: usize,
    /// CPU time used (in ticks)
    pub cpu_time: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// File descriptor table (per-process)
    pub fd_table: [Option<u64>; MAX_FD],
    /// Physical address of the process page-table root.
    ///
    /// `PhysAddr::new(0)` means the process does not currently have an owned
    /// page-table root recorded.
    pub page_dir_phys: PhysAddr,
    /// FPU/SIMD state buffer
    pub fpu_state: FpuState,
    /// Whether this process has ever used the FPU
    pub has_used_fpu: bool,
}

impl Process {
    /// Create a new process
    pub fn new(pid: Pid, name: &str, parent: Option<Pid>) -> Self {
        let mut name_bytes = [0u8; 32];
        let bytes = name.as_bytes();
        let len = bytes.len().min(31);
        name_bytes[..len].copy_from_slice(&bytes[..len]);

        Process {
            pid,
            name: name_bytes,
            state: ProcessState::Ready,
            priority: ProcessPriority::Normal,
            parent,
            capabilities: CapabilityTable::new(),
            stack_ptr: 0,
            program_counter: 0,
            cpu_time: 0,
            created_at: 0,
            fd_table: [None; MAX_FD],
            page_dir_phys: PhysAddr::new(0), // Will be set by caller or init
            fpu_state: FpuState([0; 512]),
            has_used_fpu: false,
        }
    }

    /// Get process name as string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(32);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Check if process is runnable
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, ProcessState::Ready | ProcessState::Running)
    }

    /// Allocate a file descriptor (reserves 0,1,2 for stdio)
    pub fn alloc_fd(&mut self, handle_id: u64) -> Result<usize, ProcessError> {
        for fd in 3..MAX_FD {
            if self.fd_table[fd].is_none() {
                self.fd_table[fd] = Some(handle_id);
                return Ok(fd);
            }
        }
        Err(ProcessError::FdTableFull)
    }

    /// Get handle id for a file descriptor
    pub fn get_fd(&self, fd: usize) -> Result<u64, ProcessError> {
        if fd >= MAX_FD {
            return Err(ProcessError::InvalidFd);
        }
        self.fd_table[fd].ok_or(ProcessError::InvalidFd)
    }

    /// Close a file descriptor
    pub fn close_fd(&mut self, fd: usize) -> Result<(), ProcessError> {
        if fd >= MAX_FD {
            return Err(ProcessError::InvalidFd);
        }
        if self.fd_table[fd].is_none() {
            return Err(ProcessError::InvalidFd);
        }
        self.fd_table[fd] = None;
        Ok(())
    }

    /// Mark process as running
    pub fn mark_running(&mut self) {
        self.state = ProcessState::Running;
    }

    /// Mark process as ready
    pub fn mark_ready(&mut self) {
        if self.state != ProcessState::Terminated {
            self.state = ProcessState::Ready;
        }
    }

    /// Mark process as blocked
    pub fn mark_blocked(&mut self) {
        self.state = ProcessState::Blocked;
    }

    /// Mark process as terminated
    pub fn mark_terminated(&mut self) {
        self.state = ProcessState::Terminated;
    }

    /// Increment CPU time
    pub fn tick(&mut self) {
        self.cpu_time += 1;
    }
}

// ============================================================================
// Process Table
// ============================================================================

/// Global process table
pub struct ProcessTable {
    /// Array of processes
    processes: [Option<Process>; MAX_PROCESSES],
    /// Next PID to allocate
    next_pid: u32,
    /// Number of active processes
    count: usize,
}

const NONE_PROCESS: Option<Process> = None;

impl ProcessTable {
    fn live_count(&self) -> usize {
        self.processes.iter().filter(|slot| slot.is_some()).count()
    }

    fn refresh_count(&mut self) -> usize {
        let count = self.live_count();
        self.count = count;
        count
    }

    pub const fn new() -> Self {
        ProcessTable {
            processes: [NONE_PROCESS; MAX_PROCESSES],
            next_pid: 1,
            count: 0,
        }
    }

    /// Spawn a new process
    pub fn spawn(&mut self, name: &str, parent: Option<Pid>) -> Result<Pid, ProcessError> {
        self.refresh_count();

        let pid = Pid::new(self.next_pid);
        self.next_pid += 1;

        let process = Process::new(pid, name, parent);

        if let Some(idx) = self.processes.iter().position(|slot| slot.is_none()) {
            self.processes[idx] = Some(process);
            self.count += 1;
            return Ok(pid);
        }

        self.count = MAX_PROCESSES;
        Err(ProcessError::TooManyProcesses)
    }

    /// Spawn a process with a caller-specified PID (temporal restore path).
    pub fn spawn_with_pid(
        &mut self,
        pid: Pid,
        name: &str,
        parent: Option<Pid>,
    ) -> Result<(), ProcessError> {
        if self.get(pid).is_some() {
            return Ok(());
        }
        self.refresh_count();

        let process = Process::new(pid, name, parent);
        if let Some(idx) = self.processes.iter().position(|slot| slot.is_none()) {
            self.processes[idx] = Some(process);
            self.count += 1;
            if self.next_pid <= pid.0 {
                self.next_pid = pid.0.saturating_add(1);
            }
            return Ok(());
        }

        self.count = MAX_PROCESSES;
        Err(ProcessError::TooManyProcesses)
    }

    /// Fork the parent process into a freshly allocated child PID.
    ///
    /// Clones all PCB fields that make sense to inherit (name, priority, state,
    /// page_dir_phys, stack_ptr, program_counter).  Resets per-child fields:
    /// cpu_time, created_at, has_used_fpu, fpu_state.
    ///
    /// `inherit_fds`: when `true` the child inherits the parent's FD table;
    /// when `false` the child's FD table is left empty.
    pub fn fork(
        &mut self,
        parent_pid: Pid,
        inherit_fds: bool,
    ) -> Result<(Process, Pid), ProcessError> {
        self.refresh_count();

        let parent = self
            .get(parent_pid)
            .ok_or(ProcessError::ProcessNotFound)?
            .clone();

        let child_pid = Pid::new(self.next_pid);
        self.next_pid = self.next_pid.saturating_add(1);

        let mut child = parent;
        child.pid = child_pid;
        child.parent = Some(parent_pid);
        child.state = ProcessState::Ready;
        child.cpu_time = 0;
        child.created_at = crate::pit::get_ticks();
        child.has_used_fpu = false;
        child.fpu_state = FpuState([0u8; 512]);

        if !inherit_fds {
            child.fd_table = [None; MAX_FD];
        }

        if let Some(slot) = self.processes.iter_mut().find(|s| s.is_none()) {
            *slot = Some(child.clone());
            self.count += 1;
            return Ok((child, child_pid));
        }

        self.count = MAX_PROCESSES;
        Err(ProcessError::TooManyProcesses)
    }

    /// Clone an existing process into a caller-specified PID.
    pub fn fork_process_with_pid(
        &mut self,
        parent_pid: Pid,
        child_pid: Pid,
    ) -> Result<Process, ProcessError> {
        self.refresh_count();
        if self.get(child_pid).is_some() {
            return Err(ProcessError::TooManyProcesses);
        }

        let mut child = self
            .get(parent_pid)
            .ok_or(ProcessError::ProcessNotFound)?
            .clone();
        child.pid = child_pid;
        child.parent = Some(parent_pid);
        child.state = ProcessState::Ready;
        child.cpu_time = 0;
        child.created_at = crate::pit::get_ticks();
        child.has_used_fpu = false;
        child.fpu_state = FpuState([0u8; 512]);

        if let Some(idx) = self.processes.iter().position(|slot| slot.is_none()) {
            self.processes[idx] = Some(child.clone());
            self.count += 1;
            if self.next_pid <= child_pid.0 {
                self.next_pid = child_pid.0.saturating_add(1);
            }
            return Ok(child);
        }

        self.count = MAX_PROCESSES;
        Err(ProcessError::TooManyProcesses)
    }

    /// Get a process by PID
    pub fn get(&self, pid: Pid) -> Option<&Process> {
        self.processes
            .iter()
            .find_map(|p| p.as_ref().filter(|proc| proc.pid == pid))
    }

    /// Get the page directory physical address for a process
    pub fn get_page_dir(&self, pid: Pid) -> Option<PhysAddr> {
        self.get(pid).map(|p| p.page_dir_phys)
    }

    /// Set the page directory physical address for a process
    pub fn set_page_dir(&mut self, pid: Pid, pd_phys: PhysAddr) -> Result<(), ProcessError> {
        if let Some(proc) = self.get_mut(pid) {
            proc.page_dir_phys = pd_phys;
            Ok(())
        } else {
            Err(ProcessError::ProcessNotFound)
        }
    }

    /// Get a mutable process by PID
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut Process> {
        self.processes
            .iter_mut()
            .find_map(|p| p.as_mut().filter(|proc| proc.pid == pid))
    }

    /// Terminate a process
    pub fn terminate(&mut self, pid: Pid) -> Result<(), ProcessError> {
        let proc = self.get_mut(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.mark_terminated();
        Ok(())
    }

    /// Remove terminated processes (garbage collection)
    pub fn reap_terminated(&mut self) {
        for slot in &mut self.processes {
            if let Some(proc) = slot {
                if proc.state == ProcessState::Terminated {
                    *slot = None;
                }
            }
        }
        self.refresh_count();
    }

    /// List all processes (returns array with count)
    pub fn list(&self) -> ([(Pid, [u8; 32], ProcessState, usize); MAX_PROCESSES], usize) {
        let mut result = [(Pid(0), [0u8; 32], ProcessState::Terminated, 0); MAX_PROCESSES];
        let mut count = 0;

        for proc in self.processes.iter().filter_map(|p| p.as_ref()) {
            if count < MAX_PROCESSES {
                result[count] = (proc.pid, proc.name, proc.state, proc.capabilities.count());
                count += 1;
            }
        }

        (result, count)
    }

    /// Get process count
    pub fn count(&self) -> usize {
        self.live_count()
    }
}

// ============================================================================
// Scheduler
// ============================================================================

/// Simple round-robin scheduler
pub struct Scheduler {
    /// Current running process
    current_pid: Option<Pid>,
    /// Last scheduled process index (for round-robin)
    last_index: usize,
}

impl Scheduler {
    pub const fn new() -> Self {
        Scheduler {
            current_pid: None,
            last_index: 0,
        }
    }

    /// Get current running process
    pub fn current(&self) -> Option<Pid> {
        self.current_pid
    }

    /// Set current process
    pub fn set_current(&mut self, pid: Option<Pid>) {
        self.current_pid = pid;
    }

    /// Schedule next process (round-robin)
    pub fn schedule_next(&mut self, table: &mut ProcessTable) -> Option<Pid> {
        let start_index = self.last_index;
        let mut checked = 0;

        // Round-robin through process table
        while checked < MAX_PROCESSES {
            self.last_index = (self.last_index + 1) % MAX_PROCESSES;
            checked += 1;

            if let Some(proc) = &mut table.processes[self.last_index] {
                if proc.is_runnable() && proc.state != ProcessState::Running {
                    proc.mark_running();
                    self.current_pid = Some(proc.pid);
                    return Some(proc.pid);
                }
            }

            // Wrapped around
            if self.last_index == start_index {
                break;
            }
        }

        None
    }

    /// Yield current process (move to back of queue)
    pub fn yield_current(&mut self, table: &mut ProcessTable) -> Option<Pid> {
        if let Some(current) = self.current_pid {
            if let Some(proc) = table.get_mut(current) {
                proc.mark_ready();
            }
        }

        self.schedule_next(table)
    }
}

// ============================================================================
// Process Manager
// ============================================================================

/// Global process manager
pub struct ProcessManager {
    table: Mutex<ProcessTable>,
    scheduler: Mutex<Scheduler>,
}

impl ProcessManager {
    pub const fn new() -> Self {
        ProcessManager {
            table: Mutex::new(ProcessTable::new()),
            scheduler: Mutex::new(Scheduler::new()),
        }
    }

    /// Spawn a new process
    pub fn spawn(&self, name: &str, parent: Option<Pid>) -> Result<Pid, ProcessError> {
        let pid = self.table.lock().spawn(name, parent)?;

        process_platform::on_process_spawn(pid, parent, name);

        Ok(pid)
    }

    /// Terminate a process
    pub fn terminate(&self, pid: Pid) -> Result<(), ProcessError> {
        self.table.lock().terminate(pid)?;

        process_platform::on_process_terminate(pid);

        Ok(())
    }

    pub fn temporal_spawn_with_pid(
        &self,
        pid: Pid,
        name: &str,
        parent: Option<Pid>,
    ) -> Result<(), ProcessError> {
        self.table.lock().spawn_with_pid(pid, name, parent)?;
        process_platform::on_process_restore_spawn(pid);
        Ok(())
    }

    pub fn fork_process_with_pid(
        &self,
        parent_pid: Pid,
        child_pid: Pid,
    ) -> Result<Process, ProcessError> {
        let child = self
            .table
            .lock()
            .fork_process_with_pid(parent_pid, child_pid)?;

        process_platform::on_process_spawn(child_pid, Some(parent_pid), child.name_str());
        let _ =
            crate::capability::capability_manager().clone_task_capabilities(parent_pid, child_pid);

        Ok(child)
    }

    /// Fork `parent_pid`, allocating a new child PID automatically.
    ///
    /// `flags` is a bitmask of `CLONE_FILES | CLONE_CAPS`:  
    ///   - `CLONE_FILES`: propagate the parent's open file descriptors to the child.  
    ///   - `CLONE_CAPS`:  clone and re-sign the parent's capability table for the child.
    pub fn fork_process(&self, parent_pid: Pid, flags: u32) -> Result<Pid, ProcessError> {
        let inherit_fds = flags & CLONE_FILES != 0;

        let (child, child_pid) = self.table.lock().fork(parent_pid, inherit_fds)?;

        process_platform::on_process_spawn(child_pid, Some(parent_pid), child.name_str());

        if flags & CLONE_CAPS != 0 {
            let _ = crate::capability::capability_manager()
                .clone_task_capabilities(parent_pid, child_pid);
        }

        Ok(child_pid)
    }

    /// Get current running process
    pub fn current(&self) -> Option<Pid> {
        self.scheduler.lock().current()
    }

    /// Helper to access page directory (needs to be public for paging module)
    pub fn get_process_page_dir(&self, pid: Pid) -> Option<PhysAddr> {
        self.table.lock().get_page_dir(pid)
    }

    /// Helper to set page directory
    pub fn set_process_page_dir(&self, pid: Pid, pd_phys: PhysAddr) -> Result<(), ProcessError> {
        self.table.lock().set_page_dir(pid, pd_phys)
    }

    /// Yield current process and schedule next
    pub fn yield_process(&self) -> Option<Pid> {
        let mut scheduler = self.scheduler.lock();
        let mut table = self.table.lock();
        scheduler.yield_current(&mut table)
    }

    /// Schedule next process
    pub fn schedule(&self) -> Option<Pid> {
        let mut scheduler = self.scheduler.lock();
        let mut table = self.table.lock();
        scheduler.schedule_next(&mut table)
    }

    /// Get process by PID
    pub fn get(&self, pid: Pid) -> Option<Process> {
        self.table.lock().get(pid).cloned()
    }

    /// Insert capability into process's table
    pub fn insert_capability(&self, pid: Pid, cap: CapabilityVariant) -> Result<u32, ProcessError> {
        let mut table = self.table.lock();
        let proc = table.get_mut(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.capabilities.insert(cap)
    }

    /// Get capability from process's table
    pub fn get_capability(&self, pid: Pid, slot: u32) -> Result<CapabilityVariant, ProcessError> {
        let table = self.table.lock();
        let proc = table.get(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.capabilities
            .get(slot)
            .cloned()
            .ok_or(ProcessError::InvalidCapSlot)
    }

    /// Allocate a file descriptor for a process
    pub fn alloc_fd(&self, pid: Pid, handle_id: u64) -> Result<usize, ProcessError> {
        let mut table = self.table.lock();
        let proc = table.get_mut(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.alloc_fd(handle_id)
    }

    /// Get handle id for a file descriptor
    pub fn get_fd_handle(&self, pid: Pid, fd: usize) -> Result<u64, ProcessError> {
        let table = self.table.lock();
        let proc = table.get(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.get_fd(fd)
    }

    /// Close a file descriptor
    pub fn close_fd(&self, pid: Pid, fd: usize) -> Result<(), ProcessError> {
        let mut table = self.table.lock();
        let proc = table.get_mut(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.close_fd(fd)
    }

    /// Remove capability from process's table
    pub fn remove_capability(&self, pid: Pid, slot: u32) -> Result<(), ProcessError> {
        let mut table = self.table.lock();
        let proc = table.get_mut(pid).ok_or(ProcessError::ProcessNotFound)?;
        proc.capabilities.remove(slot)
    }

    /// List all processes (returns array with count)
    pub fn list(&self) -> ([(Pid, [u8; 32], ProcessState, usize); MAX_PROCESSES], usize) {
        let table = self.table.lock();
        table.list()
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, usize) {
        let table = self.table.lock();
        (table.count(), MAX_PROCESSES)
    }

    /// Count active processes and open file descriptors.
    pub fn fd_stats(&self) -> (usize, usize) {
        let table = self.table.lock();
        let proc_count = table.count();
        let fd_count = table
            .processes
            .iter()
            .filter_map(|p| p.as_ref())
            .map(|proc| proc.fd_table.iter().filter(|fd| fd.is_some()).count())
            .sum();
        (proc_count, fd_count)
    }

    /// Reap terminated processes
    pub fn reap(&self) {
        self.table.lock().reap_terminated();
    }

    /// Increment CPU time for current process
    pub fn tick_current(&self) {
        if let Some(pid) = self.current() {
            let mut table = self.table.lock();
            if let Some(proc) = table.get_mut(pid) {
                proc.tick();
            }
        }
    }

    /// Bring-up helper for runtimes that need to drive the shared process
    /// backend before the full scheduler port is enabled.
    pub fn set_current_runtime_pid(&self, pid: Pid) -> Result<(), ProcessError> {
        let mut scheduler = self.scheduler.lock();
        let mut table = self.table.lock();
        if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
            trace_kernel_bootstrap_locked("set_current_runtime_pid:before", &table, &scheduler);
        }

        if pid.0 == 0 {
            scheduler.set_current(None);
            if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
                trace_kernel_bootstrap_locked(
                    "set_current_runtime_pid:cleared",
                    &table,
                    &scheduler,
                );
            }
            return Ok(());
        }

        if table.get(pid).is_none() {
            let parent = if pid.0 == 1 { None } else { Some(Pid::new(1)) };
            table.spawn_with_pid(pid, "a64-task", parent)?;
        }

        if let Some(prev_pid) = scheduler.current() {
            if prev_pid != pid {
                if let Some(prev) = table.get_mut(prev_pid) {
                    prev.mark_ready();
                }
            }
        }

        if let Some(proc) = table.get_mut(pid) {
            proc.mark_running();
        }
        scheduler.set_current(Some(pid));
        if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
            trace_kernel_bootstrap_locked("set_current_runtime_pid:after", &table, &scheduler);
        }
        Ok(())
    }

    /// Ensure a runtime-visible PID exists in the shared process backend and
    /// is marked current. Used by legacy bring-up before full process/scheduler
    /// parity exists.
    pub fn ensure_runtime_pid(&self, pid: Pid, name: &str) -> Result<(), ProcessError> {
        let mut scheduler = self.scheduler.lock();
        let mut table = self.table.lock();
        if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
            trace_kernel_bootstrap_locked("ensure_runtime_pid:before", &table, &scheduler);
        }

        if pid.0 == 0 {
            scheduler.set_current(None);
            if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
                trace_kernel_bootstrap_locked("ensure_runtime_pid:cleared", &table, &scheduler);
            }
            return Ok(());
        }

        if table.get(pid).is_none() {
            let parent = if pid.0 == 1 { None } else { Some(Pid::new(1)) };
            table.spawn_with_pid(pid, name, parent)?;
        }

        if let Some(prev_pid) = scheduler.current() {
            if prev_pid != pid {
                if let Some(prev) = table.get_mut(prev_pid) {
                    prev.mark_ready();
                }
            }
        }

        if let Some(proc) = table.get_mut(pid) {
            proc.mark_running();
        }
        scheduler.set_current(Some(pid));
        if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
            trace_kernel_bootstrap_locked("ensure_runtime_pid:after", &table, &scheduler);
        }
        Ok(())
    }
}

// ============================================================================
// Process Errors
// ============================================================================

/// Process-related errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// Too many processes
    TooManyProcesses,
    /// Process not found
    ProcessNotFound,
    /// Invalid capability slot
    InvalidCapSlot,
    /// Capability table full
    CapabilityTableFull,
    /// Process already terminated
    AlreadyTerminated,
    /// File descriptor table full
    FdTableFull,
    /// Invalid file descriptor
    InvalidFd,
}

impl ProcessError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessError::TooManyProcesses => "Too many processes",
            ProcessError::ProcessNotFound => "Process not found",
            ProcessError::InvalidCapSlot => "Invalid capability slot",
            ProcessError::CapabilityTableFull => "Capability table full",
            ProcessError::AlreadyTerminated => "Already terminated",
            ProcessError::FdTableFull => "File descriptor table full",
            ProcessError::InvalidFd => "Invalid file descriptor",
        }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Global Process Manager Instance
// ============================================================================

/// Global process manager
static PROCESS_MANAGER: ProcessManager = ProcessManager::new();
const KERNEL_BOOTSTRAP_UNSEEDED: u8 = 0;
const KERNEL_BOOTSTRAP_SEEDED: u8 = 1;
const KERNEL_BOOTSTRAP_SEALED: u8 = 2;
static KERNEL_BOOTSTRAP_PHASE: AtomicU8 = AtomicU8::new(KERNEL_BOOTSTRAP_UNSEEDED);

fn kernel_bootstrap_phase_name(phase: u8) -> &'static str {
    match phase {
        KERNEL_BOOTSTRAP_UNSEEDED => "unseeded",
        KERNEL_BOOTSTRAP_SEEDED => "seeded",
        KERNEL_BOOTSTRAP_SEALED => "sealed",
        _ => "unknown",
    }
}

#[cfg(target_arch = "x86")]
fn proc_boot_trace_enabled() -> bool {
    let Some(cmdline) = crate::arch::boot_info().cmdline_str() else {
        return false;
    };
    cmdline.split_whitespace().any(|token| {
        token == "oreulia.proc_boot_debug"
            || matches!(
                token.strip_prefix("oreulia.proc_boot_debug="),
                Some("1" | "true" | "on" | "yes")
            )
    })
}

#[cfg(not(target_arch = "x86"))]
fn proc_boot_trace_enabled() -> bool {
    false
}

#[cfg(target_arch = "x86")]
fn trace_kernel_bootstrap_locked(label: &str, table: &ProcessTable, scheduler: &Scheduler) {
    if !proc_boot_trace_enabled() {
        return;
    }
    let has_init = table.get(Pid::new(1)).is_some();
    let current = scheduler.current().map(|pid| pid.0).unwrap_or(0);
    crate::serial_println!(
        "[PROC-BOOT] {} init={} current={} count={} phase={}",
        label,
        if has_init { 1 } else { 0 },
        current,
        table.count(),
        kernel_bootstrap_phase_name(KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire))
    );
}

#[cfg(not(target_arch = "x86"))]
fn trace_kernel_bootstrap_locked(_label: &str, _table: &ProcessTable, _scheduler: &Scheduler) {}

fn reconcile_kernel_bootstrap_locked(
    table: &mut ProcessTable,
    scheduler: &mut Scheduler,
    label: &str,
) -> Result<(), &'static str> {
    let init_pid = Pid::new(1);
    trace_kernel_bootstrap_locked(label, table, scheduler);
    if table.get(init_pid).is_none() {
        table
            .spawn_with_pid(init_pid, "init", None)
            .map_err(|e| e.as_str())?;
        trace_kernel_bootstrap_locked("spawn_with_pid(pid=1)", table, scheduler);
    }

    if let Some(prev_pid) = scheduler.current() {
        if prev_pid != init_pid {
            if let Some(prev) = table.get_mut(prev_pid) {
                prev.mark_ready();
            }
        }
    }

    let Some(init) = table.get_mut(init_pid) else {
        return Err("shared process backend missing PID=1");
    };
    init.mark_running();
    scheduler.set_current(Some(init_pid));
    trace_kernel_bootstrap_locked("reconcile:after", table, scheduler);
    Ok(())
}

/// Get the global process manager
pub fn process_manager() -> &'static ProcessManager {
    &PROCESS_MANAGER
}

pub fn debug_kernel_bootstrap(label: &str) {
    #[cfg(target_arch = "x86")]
    {
        let scheduler = PROCESS_MANAGER.scheduler.lock();
        let table = PROCESS_MANAGER.table.lock();
        trace_kernel_bootstrap_locked(label, &table, &scheduler);
    }
}

pub fn debug_kernel_bootstrap_layout(label: &str) {
    #[cfg(target_arch = "x86")]
    {
        if !proc_boot_trace_enabled() {
            return;
        }
        let scheduler = PROCESS_MANAGER.scheduler.lock();
        let table = PROCESS_MANAGER.table.lock();
        crate::serial_println!(
            "[PROC-BOOT] {} layout pm={:#x} table={:#x} procs={:#x} sched={:#x}",
            label,
            &PROCESS_MANAGER as *const _ as usize,
            &*table as *const _ as usize,
            table.processes.as_ptr() as usize,
            &*scheduler as *const _ as usize
        );
    }
}

/// Initialize the process manager
pub fn init() {
    let mut scheduler = PROCESS_MANAGER.scheduler.lock();
    let mut table = PROCESS_MANAGER.table.lock();
    let _ = reconcile_kernel_bootstrap_locked(&mut table, &mut scheduler, "init:before");
    let phase = KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire);
    if phase < KERNEL_BOOTSTRAP_SEEDED {
        KERNEL_BOOTSTRAP_PHASE.store(KERNEL_BOOTSTRAP_SEEDED, Ordering::Release);
    }
    trace_kernel_bootstrap_locked("init:after", &table, &scheduler);
}

/// Yield from current process
pub fn yield_now() {
    process_manager().yield_process();
}

/// Get current process ID
pub fn current_pid() -> Option<Pid> {
    process_manager().current()
}

/// Sync the shared process backend's current PID from an external runtime
/// (AArch64 bring-up shell/timer path) before full scheduler integration exists.
pub fn set_current_runtime_pid(pid: Pid) -> Result<(), &'static str> {
    process_manager()
        .set_current_runtime_pid(pid)
        .map_err(|e| e.as_str())
}

pub fn ensure_runtime_pid(pid: Pid, name: &str) -> Result<(), &'static str> {
    process_manager()
        .ensure_runtime_pid(pid, name)
        .map_err(|e| e.as_str())
}

pub fn seal_kernel_bootstrap() -> Result<(), &'static str> {
    let mut scheduler = PROCESS_MANAGER.scheduler.lock();
    let mut table = PROCESS_MANAGER.table.lock();
    reconcile_kernel_bootstrap_locked(&mut table, &mut scheduler, "seal:before")?;
    KERNEL_BOOTSTRAP_PHASE.store(KERNEL_BOOTSTRAP_SEALED, Ordering::Release);
    trace_kernel_bootstrap_locked("seal:after", &table, &scheduler);
    Ok(())
}

pub fn validate_kernel_bootstrap() -> Result<(), &'static str> {
    let phase = KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire);
    let mut scheduler = PROCESS_MANAGER.scheduler.lock();
    let mut table = PROCESS_MANAGER.table.lock();
    trace_kernel_bootstrap_locked("validate:before", &table, &scheduler);

    if phase < KERNEL_BOOTSTRAP_SEEDED {
        return Err("kernel bootstrap never seeded");
    }
    if table.get(Pid::new(1)).is_none() {
        return Err("shared process backend missing PID=1");
    }

    if scheduler.current() != Some(Pid::new(1)) {
        reconcile_kernel_bootstrap_locked(&mut table, &mut scheduler, "validate:sync-current")?;
    }

    if KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) < KERNEL_BOOTSTRAP_SEALED {
        return Err("kernel bootstrap not sealed");
    }

    trace_kernel_bootstrap_locked("validate:after", &table, &scheduler);
    Ok(())
}

/// Legacy-x86 scheduler bootstrap normalizes the shared process backend to a
/// clean pre-task state before the quantum scheduler takes over.
pub fn bootstrap_kernel_runtime() -> Result<(), &'static str> {
    let init_pid = Pid::new(1);
    let mut scheduler = PROCESS_MANAGER.scheduler.lock();
    let mut table = PROCESS_MANAGER.table.lock();

    trace_kernel_bootstrap_locked("bootstrap-reset:before", &table, &scheduler);
    *scheduler = Scheduler::new();
    *table = ProcessTable::new();
    table
        .spawn_with_pid(init_pid, "init", None)
        .map_err(|e| e.as_str())?;

    if let Some(init) = table.get_mut(init_pid) {
        init.mark_running();
    }
    scheduler.set_current(Some(init_pid));
    KERNEL_BOOTSTRAP_PHASE.store(KERNEL_BOOTSTRAP_SEEDED, Ordering::Release);
    trace_kernel_bootstrap_locked("bootstrap-reset:after", &table, &scheduler);
    Ok(())
}

/// Return (active process count, open fd count, current pid).
pub fn runtime_fd_stats() -> (usize, usize, Option<Pid>) {
    let (proc_count, fd_count) = process_manager().fd_stats();
    (proc_count, fd_count, current_pid())
}

pub fn temporal_apply_process_event(
    pid_raw: u32,
    parent_raw: u32,
    event: u8,
    name_bytes: &[u8],
) -> Result<(), &'static str> {
    #[cfg(target_arch = "x86")]
    {
        if pid_raw == 1 || KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire) >= KERNEL_BOOTSTRAP_SEEDED
        {
            crate::serial_println!(
                "[PROC-BOOT] temporal-event pid={} parent={} event={} phase={}",
                pid_raw,
                parent_raw,
                event,
                kernel_bootstrap_phase_name(KERNEL_BOOTSTRAP_PHASE.load(Ordering::Acquire))
            );
        }
    }
    let pid = Pid::new(pid_raw);
    match event {
        process_platform::TEMPORAL_PROCESS_EVENT_SPAWN => {
            let name = core::str::from_utf8(name_bytes).map_err(|_| "Invalid process name")?;
            let parent = if parent_raw == u32::MAX {
                None
            } else {
                Some(Pid::new(parent_raw))
            };
            process_manager()
                .temporal_spawn_with_pid(pid, name, parent)
                .map_err(|e| e.as_str())
        }
        process_platform::TEMPORAL_PROCESS_EVENT_TERMINATE => {
            if process_manager().get(pid).is_none() {
                return Ok(());
            }
            process_manager().terminate(pid).map_err(|e| e.as_str())
        }
        _ => Err("Unsupported process temporal event"),
    }
}

// ============================================================================
// C/Assembly Bindings
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_create_process(parent_pid_raw: u32, flags: u32) -> u32 {
    // flags is a bitmask of CLONE_FILES | CLONE_CAPS (defined in this module).
    // A zero flags value produces a minimal fork: process structure is cloned from the
    // parent but the child starts with an empty FD table and empty capability table.
    //
    // Returns the new child PID on success, or u32::MAX (-1) on any error
    // (parent not found, process table full, etc.).
    let parent_pid = Pid(parent_pid_raw);

    // Reject obviously invalid parent PIDs before touching the process table.
    if parent_pid_raw == 0 {
        return u32::MAX;
    }

    // Ensure the requested parent exists.
    if process_manager().get(parent_pid).is_none() {
        return u32::MAX;
    }

    match process_manager().fork_process(parent_pid, flags) {
        Ok(child_pid) => child_pid.0,
        Err(_) => u32::MAX,
    }
}
