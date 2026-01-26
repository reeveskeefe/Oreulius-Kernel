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

use core::fmt;
use spin::Mutex;
use crate::ipc::ChannelCapability;

/// Maximum number of processes
pub const MAX_PROCESSES: usize = 64;

/// Maximum capabilities per process
pub const MAX_CAPS_PER_PROCESS: usize = 128;

/// Stack size per process (64 KiB)
pub const STACK_SIZE: usize = 64 * 1024;

// ============================================================================
// Process ID Management
// ============================================================================

/// Process ID newtype (re-export from IPC for consistency)
pub use crate::ipc::ProcessId as Pid;

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
    Filesystem {
        cap_id: u32,
        rights: u32,
    },
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
    pub const fn new() -> Self {
        ProcessTable {
            processes: [NONE_PROCESS; MAX_PROCESSES],
            next_pid: 1,
            count: 0,
        }
    }

    /// Spawn a new process
    pub fn spawn(&mut self, name: &str, parent: Option<Pid>) -> Result<Pid, ProcessError> {
        if self.count >= MAX_PROCESSES {
            return Err(ProcessError::TooManyProcesses);
        }

        let pid = Pid::new(self.next_pid);
        self.next_pid += 1;

        let process = Process::new(pid, name, parent);

        // Find empty slot
        for slot in &mut self.processes {
            if slot.is_none() {
                *slot = Some(process);
                self.count += 1;
                return Ok(pid);
            }
        }

        Err(ProcessError::TooManyProcesses)
    }

    /// Get a process by PID
    pub fn get(&self, pid: Pid) -> Option<&Process> {
        self.processes.iter().find_map(|p| {
            p.as_ref().filter(|proc| proc.pid == pid)
        })
    }

    /// Get a mutable process by PID
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut Process> {
        self.processes.iter_mut().find_map(|p| {
            p.as_mut().filter(|proc| proc.pid == pid)
        })
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
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
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
        self.count
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
        self.table.lock().spawn(name, parent)
    }

    /// Terminate a process
    pub fn terminate(&self, pid: Pid) -> Result<(), ProcessError> {
        self.table.lock().terminate(pid)
    }

    /// Get current running process
    pub fn current(&self) -> Option<Pid> {
        self.scheduler.lock().current()
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
        proc.capabilities.get(slot)
            .cloned()
            .ok_or(ProcessError::InvalidCapSlot)
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
}

impl ProcessError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessError::TooManyProcesses => "Too many processes",
            ProcessError::ProcessNotFound => "Process not found",
            ProcessError::InvalidCapSlot => "Invalid capability slot",
            ProcessError::CapabilityTableFull => "Capability table full",
            ProcessError::AlreadyTerminated => "Already terminated",
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

/// Get the global process manager
pub fn process_manager() -> &'static ProcessManager {
    &PROCESS_MANAGER
}

/// Initialize the process manager
pub fn init() {
    // Create the init process (PID 1)
    match process_manager().spawn("init", None) {
        Ok(pid) => {
            // Mark init as current process
            let mut scheduler = PROCESS_MANAGER.scheduler.lock();
            scheduler.set_current(Some(pid));
            
            let mut table = PROCESS_MANAGER.table.lock();
            if let Some(init) = table.get_mut(pid) {
                init.mark_running();
            }
        }
        Err(_) => {
            // Failed to create init process - this is a panic condition
        }
    }
}

/// Yield from current process
pub fn yield_now() {
    process_manager().yield_process();
}

/// Get current process ID
pub fn current_pid() -> Option<Pid> {
    process_manager().current()
}
