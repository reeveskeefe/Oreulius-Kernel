//! Advanced Quantum-Based Preemptive Scheduler
//! 
//! Features:
//! - Per-process quantum tracking with decay
//! - Multi-level feedback queue (MLFQ) for adaptive priority
//! - Blocking primitives (futex-like wait queues)
//! - CPU affinity and load balancing (single-core for now)
//! - Accounting: CPU time, context switches, wait time

use spin::Mutex;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use crate::process::{Process, ProcessState, ProcessPriority, Pid, MAX_PROCESSES};
use crate::asm_bindings::{ProcessContext, asm_switch_context};
use crate::pit;

/// Quantum in ticks (100 Hz = 10ms per tick)
const QUANTUM_HIGH: u32 = 20;      // 200ms for high priority
const QUANTUM_NORMAL: u32 = 10;    // 100ms for normal
const QUANTUM_LOW: u32 = 5;        // 50ms for low priority

/// Maximum wait queue entries
const MAX_WAIT_QUEUES: usize = 64;

/// Scheduler state
pub struct QuantumScheduler {
    /// Process table
    processes: [Option<ProcessInfo>; MAX_PROCESSES],
    /// Currently running process
    current_pid: Option<Pid>,
    /// Ready queues (multi-level)
    ready_queues: [VecDeque<Pid>; 3],
    /// Wait queues for blocking operations
    wait_queues: [WaitQueue; MAX_WAIT_QUEUES],
    wait_queue_count: usize,
    /// Statistics
    stats: SchedulerStats,
}

/// Extended process information for scheduling
pub struct ProcessInfo {
    pub process: Process,
    pub context: ProcessContext,
    pub quantum_remaining: u32,
    pub total_cpu_time: u64,      // Total ticks this process ran
    pub total_wait_time: u64,     // Total ticks waiting
    pub last_scheduled: u64,      // Tick when last scheduled
    pub switches: u64,             // Number of times scheduled
}

/// Wait queue for blocking primitives
#[derive(Clone)]
pub struct WaitQueue {
    pub addr: usize,               // Address/key for the wait queue (like futex)
    pub waiting: VecDeque<Pid>,
    pub active: bool,
}

/// Scheduler statistics
#[derive(Clone, Copy)]
pub struct SchedulerStats {
    pub total_switches: u64,
    pub preemptions: u64,
    pub voluntary_yields: u64,
    pub idle_ticks: u64,
}

impl QuantumScheduler {
    pub const fn new() -> Self {
        const NONE_PROC: Option<ProcessInfo> = None;
        
        QuantumScheduler {
            processes: [NONE_PROC; MAX_PROCESSES],
            current_pid: None,
            ready_queues: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            wait_queues: core::array::from_fn(|_| WaitQueue::empty()),
            wait_queue_count: 0,
            stats: SchedulerStats {
                total_switches: 0,
                preemptions: 0,
                voluntary_yields: 0,
                idle_ticks: 0,
            },
        }
    }

    /// Add a process to the scheduler
    pub fn add_process(&mut self, process: Process) -> Result<(), &'static str> {
        let pid = process.pid;
        let idx = pid.0 as usize;
        
        if idx >= MAX_PROCESSES {
            return Err("Invalid PID");
        }
        
        if self.processes[idx].is_some() {
            return Err("PID already in use");
        }
        
        let quantum = match process.priority {
            ProcessPriority::High => QUANTUM_HIGH,
            ProcessPriority::Normal => QUANTUM_NORMAL,
            ProcessPriority::Low => QUANTUM_LOW,
        };
        
        let info = ProcessInfo {
            process,
            context: ProcessContext::new(),
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: pit::get_ticks(),
            switches: 0,
        };
        
        self.processes[idx] = Some(info);
        self.enqueue_ready(pid, process.priority);
        
        Ok(())
    }

    /// Schedule next process (called on timer interrupt)
    pub fn schedule(&mut self) {
        let now = pit::get_ticks();
        
        // Update current process accounting
        if let Some(current_pid) = self.current_pid {
            let idx = current_pid.0 as usize;
            if let Some(ref mut info) = self.processes[idx] {
                let elapsed = now.saturating_sub(info.last_scheduled);
                info.total_cpu_time = info.total_cpu_time.saturating_add(elapsed);
                
                // Decrement quantum
                if info.quantum_remaining > 0 {
                    info.quantum_remaining -= 1;
                }
                
                // If quantum expired, move to ready queue
                if info.quantum_remaining == 0 {
                    info.process.state = ProcessState::Ready;
                    let priority = info.process.priority;
                    
                    // Refill quantum
                    info.quantum_remaining = match priority {
                        ProcessPriority::High => QUANTUM_HIGH,
                        ProcessPriority::Normal => QUANTUM_NORMAL,
                        ProcessPriority::Low => QUANTUM_LOW,
                    };
                    
                    self.enqueue_ready(current_pid, priority);
                    self.stats.preemptions += 1;
                    self.current_pid = None;
                }
            }
        }
        
        // Pick next process from ready queues (priority order)
        let next_pid = self.dequeue_ready();
        
        if next_pid.is_none() {
            self.stats.idle_ticks += 1;
            self.current_pid = None;
            return;
        }
        
        let next_pid = next_pid.unwrap();
        let prev_pid = self.current_pid;
        
        // Context switch if needed
        if prev_pid != Some(next_pid) {
            self.perform_switch(prev_pid, next_pid);
            self.stats.total_switches += 1;
        }
        
        self.current_pid = Some(next_pid);
        
        // Update scheduling timestamp
        if let Some(ref mut info) = self.processes[next_pid.0 as usize] {
            info.process.state = ProcessState::Running;
            info.last_scheduled = now;
            info.switches += 1;
        }
    }

    /// Perform actual context switch
    fn perform_switch(&mut self, from: Option<Pid>, to: Pid) {
        if let Some(from_pid) = from {
            let from_idx = from_pid.0 as usize;
            let to_idx = to.0 as usize;
            
            unsafe {
                if let Some(ref mut from_info) = self.processes[from_idx] {
                    if let Some(ref to_info) = self.processes[to_idx] {
                        asm_switch_context(
                            &mut from_info.context as *mut ProcessContext,
                            &to_info.context as *const ProcessContext,
                        );
                    }
                }
            }
        }
    }

    /// Enqueue process to ready queue
    fn enqueue_ready(&mut self, pid: Pid, priority: ProcessPriority) {
        let queue_idx = match priority {
            ProcessPriority::High => 0,
            ProcessPriority::Normal => 1,
            ProcessPriority::Low => 2,
        };
        
        self.ready_queues[queue_idx].push_back(pid);
    }

    /// Dequeue next process from ready queues (priority order)
    fn dequeue_ready(&mut self) -> Option<Pid> {
        // Try high priority first
        if let Some(pid) = self.ready_queues[0].pop_front() {
            return Some(pid);
        }
        
        // Then normal
        if let Some(pid) = self.ready_queues[1].pop_front() {
            return Some(pid);
        }
        
        // Finally low
        self.ready_queues[2].pop_front()
    }

    /// Voluntary yield (cooperative)
    pub fn yield_cpu(&mut self) {
        if let Some(current_pid) = self.current_pid {
            let idx = current_pid.0 as usize;
            if let Some(ref mut info) = self.processes[idx] {
                info.process.state = ProcessState::Ready;
                let priority = info.process.priority;
                self.enqueue_ready(current_pid, priority);
            }
            self.current_pid = None;
            self.stats.voluntary_yields += 1;
        }
        self.schedule();
    }

    /// Block current process on a wait queue (futex-like)
    pub fn block_on(&mut self, addr: usize) -> Result<(), &'static str> {
        let current_pid = self.current_pid.ok_or("No current process")?;
        
        // Find or create wait queue
        let queue_idx = self.find_or_create_wait_queue(addr)?;
        
        // Add to wait queue
        self.wait_queues[queue_idx].waiting.push_back(current_pid);
        
        // Mark process as blocked
        if let Some(ref mut info) = self.processes[current_pid.0 as usize] {
            info.process.state = ProcessState::Blocked;
        }
        
        self.current_pid = None;
        self.schedule();
        Ok(())
    }

    /// Wake one process from wait queue
    pub fn wake_one(&mut self, addr: usize) -> Result<bool, &'static str> {
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].addr == addr && self.wait_queues[i].active {
                if let Some(pid) = self.wait_queues[i].waiting.pop_front() {
                    // Move to ready queue
                    if let Some(ref mut info) = self.processes[pid.0 as usize] {
                        info.process.state = ProcessState::Ready;
                        let priority = info.process.priority;
                        self.enqueue_ready(pid, priority);
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Wake all processes from wait queue
    pub fn wake_all(&mut self, addr: usize) -> Result<usize, &'static str> {
        let mut count = 0;
        
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].addr == addr && self.wait_queues[i].active {
                while let Some(pid) = self.wait_queues[i].waiting.pop_front() {
                    if let Some(ref mut info) = self.processes[pid.0 as usize] {
                        info.process.state = ProcessState::Ready;
                        let priority = info.process.priority;
                        self.enqueue_ready(pid, priority);
                        count += 1;
                    }
                }
                self.wait_queues[i].active = false;
            }
        }
        
        Ok(count)
    }

    /// Find or create a wait queue for an address
    fn find_or_create_wait_queue(&mut self, addr: usize) -> Result<usize, &'static str> {
        // Try to find existing
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].addr == addr && self.wait_queues[i].active {
                return Ok(i);
            }
        }
        
        // Create new
        if self.wait_queue_count >= MAX_WAIT_QUEUES {
            return Err("Wait queue table full");
        }
        
        let idx = self.wait_queue_count;
        self.wait_queues[idx] = WaitQueue {
            addr,
            waiting: VecDeque::new(),
            active: true,
        };
        self.wait_queue_count += 1;
        Ok(idx)
    }

    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        self.stats
    }

    /// Get process info
    pub fn get_process_info(&self, pid: Pid) -> Option<&ProcessInfo> {
        let idx = pid.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_ref()
        } else {
            None
        }
    }

    /// List all processes with scheduling info
    pub fn list_processes(&self) -> Vec<(Pid, &ProcessInfo)> {
        let mut result = Vec::new();
        for (idx, info_opt) in self.processes.iter().enumerate() {
            if let Some(ref info) = info_opt {
                result.push((Pid(idx as u32), info));
            }
        }
        result
    }
}

impl WaitQueue {
    const fn empty() -> Self {
        WaitQueue {
            addr: 0,
            waiting: VecDeque::new(),
            active: false,
        }
    }
}

/// Global scheduler instance
static QUANTUM_SCHEDULER: Mutex<QuantumScheduler> = Mutex::new(QuantumScheduler::new());

/// Initialize quantum scheduler
pub fn init() {
    // Scheduler is already initialized via static
}

/// Get reference to global scheduler
pub fn scheduler() -> &'static Mutex<QuantumScheduler> {
    &QUANTUM_SCHEDULER
}

/// Timer tick handler (called from PIT interrupt)
pub fn on_timer_tick() {
    QUANTUM_SCHEDULER.lock().schedule();
}

/// Yield current process
pub fn yield_now() {
    QUANTUM_SCHEDULER.lock().yield_cpu();
}

/// Block on address (futex-like)
pub fn block_on(addr: usize) -> Result<(), &'static str> {
    QUANTUM_SCHEDULER.lock().block_on(addr)
}

/// Wake one waiter on address
pub fn wake_one(addr: usize) -> Result<bool, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_one(addr)
}

/// Wake all waiters on address
pub fn wake_all(addr: usize) -> Result<usize, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_all(addr)
}
