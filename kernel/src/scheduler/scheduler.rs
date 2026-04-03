/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Preemptive Scheduler with Round-Robin
//!
//! Features:
//! - Timer-based preemption (10ms time slices)
//! - Round-robin scheduling per priority level
//! - Sleep/wake mechanisms
//! - Yield support
//! - Uses assembly context switching for speed

use crate::asm_bindings::{asm_switch_context, ProcessContext};
use crate::interrupt_dag::{DagSpinlock, InterruptContext, DAG_LEVEL_SCHEDULER, DAG_LEVEL_SYSCALL};
use crate::pit;
use crate::process::{Pid, Process, ProcessPriority, ProcessState, MAX_PROCESSES};
use core::sync::atomic::{AtomicBool, Ordering};

/// Time slice in milliseconds (10ms = 100 Hz)
const TIME_SLICE_MS: u32 = 10;

/// Maximum number of sleeping processes
const MAX_SLEEPING: usize = 32;

/// Scheduler state
pub struct Scheduler {
    /// Process table
    processes: [Option<Process>; MAX_PROCESSES],
    /// Context table (CPU state for each process)
    contexts: [ProcessContext; MAX_PROCESSES],
    /// Currently running process
    current_pid: Option<Pid>,
    /// Which process currently owns the FPU registers
    fpu_owner: Option<Pid>,
    /// Ready queues (one per priority level)
    ready_queue_high: [Option<Pid>; MAX_PROCESSES],
    ready_queue_normal: [Option<Pid>; MAX_PROCESSES],
    ready_queue_low: [Option<Pid>; MAX_PROCESSES],
    /// Queue lengths
    ready_high_len: usize,
    ready_normal_len: usize,
    ready_low_len: usize,
    /// Sleeping processes
    sleeping: [SleepingProcess; MAX_SLEEPING],
    sleeping_count: usize,
    /// Ticks since last schedule (for time slice enforcement)
    ticks_since_schedule: u32,
    /// Statistics
    total_switches: u64,
    preemptions: u64,
}

/// A process that is sleeping
#[derive(Clone, Copy)]
struct SleepingProcess {
    pid: Pid,
    wake_at: u64, // Tick count to wake at
}

impl Scheduler {
    pub const fn new() -> Self {
        const NONE_PROC: Option<Process> = None;
        const EMPTY_CTX: ProcessContext = ProcessContext::new();
        const NONE_PID: Option<Pid> = None;
        const EMPTY_SLEEP: SleepingProcess = SleepingProcess {
            pid: Pid(0),
            wake_at: 0,
        };

        Scheduler {
            processes: [NONE_PROC; MAX_PROCESSES],
            contexts: [EMPTY_CTX; MAX_PROCESSES],
            current_pid: None,
            fpu_owner: None,
            ready_queue_high: [NONE_PID; MAX_PROCESSES],
            ready_queue_normal: [NONE_PID; MAX_PROCESSES],
            ready_queue_low: [NONE_PID; MAX_PROCESSES],
            ready_high_len: 0,
            ready_normal_len: 0,
            ready_low_len: 0,
            sleeping: [EMPTY_SLEEP; MAX_SLEEPING],
            sleeping_count: 0,
            total_switches: 0,
            preemptions: 0,
            ticks_since_schedule: 0,
        }
    }

    /// Add a process to the scheduler
    pub fn add_process(&mut self, mut process: Process) -> Result<(), &'static str> {
        let pid = process.pid;
        let idx = pid.0 as usize;

        if idx >= MAX_PROCESSES {
            return Err("Invalid PID");
        }

        if self.processes[idx].is_some() {
            return Err("PID already in use");
        }

        process.state = ProcessState::Ready;
        self.processes[idx] = Some(process.clone());

        // Add to appropriate ready queue
        self.enqueue_ready(pid, process.priority);

        Ok(())
    }

    /// Remove a process from the scheduler
    pub fn remove_process(&mut self, pid: Pid) -> Result<(), &'static str> {
        let idx = pid.0 as usize;

        if idx >= MAX_PROCESSES {
            return Err("Invalid PID");
        }

        if let Some(ref mut proc) = self.processes[idx] {
            proc.state = ProcessState::Terminated;
            self.processes[idx] = None;
            self.remove_from_ready_queues(pid);
            Ok(())
        } else {
            Err("Process not found")
        }
    }

    /// Get a process by PID
    pub fn get_process(&self, pid: Pid) -> Option<&Process> {
        let idx = pid.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_ref()
        } else {
            None
        }
    }

    /// Get mutable process reference
    pub fn get_process_mut(&mut self, pid: Pid) -> Option<&mut Process> {
        let idx = pid.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_mut()
        } else {
            None
        }
    }

    /// Get currently running process
    pub fn current_process(&self) -> Option<&Process> {
        self.current_pid.and_then(|pid| self.get_process(pid))
    }

    /// Yield CPU to next process (cooperative)
    pub fn yield_cpu(&mut self) {
        if let Some(current_pid) = self.current_pid {
            let priority = if let Some(ref mut proc) = self.processes[current_pid.0 as usize] {
                proc.state = ProcessState::Ready;
                proc.priority
            } else {
                return;
            };
            self.enqueue_ready(current_pid, priority);
        }

        self.schedule();
    }

    /// Sleep current process for N milliseconds
    pub fn sleep(&mut self, ms: u32) {
        if let Some(current_pid) = self.current_pid {
            let wake_at = pit::get_ticks() + ((ms as u64 * pit::get_frequency() as u64) / 1000);

            if self.sleeping_count < MAX_SLEEPING {
                self.sleeping[self.sleeping_count] = SleepingProcess {
                    pid: current_pid,
                    wake_at,
                };
                self.sleeping_count += 1;

                if let Some(ref mut proc) = self.processes[current_pid.0 as usize] {
                    proc.state = ProcessState::Blocked;
                }

                self.current_pid = None;
                self.schedule();
            }
        }
    }

    /// Wake sleeping processes whose time has elapsed
    pub fn wake_sleeping(&mut self) {
        let now = pit::get_ticks();
        let mut i = 0;

        while i < self.sleeping_count {
            if self.sleeping[i].wake_at <= now {
                let pid = self.sleeping[i].pid;

                // Get priority before calling enqueue_ready
                let priority = if let Some(ref mut proc) = self.processes[pid.0 as usize] {
                    proc.state = ProcessState::Ready;
                    proc.priority
                } else {
                    // Skip if process doesn't exist
                    self.sleeping_count -= 1;
                    self.sleeping[i] = self.sleeping[self.sleeping_count];
                    continue;
                };

                // Move process to ready queue
                self.enqueue_ready(pid, priority);

                // Remove from sleeping array (swap with last)
                self.sleeping_count -= 1;
                self.sleeping[i] = self.sleeping[self.sleeping_count];
            } else {
                i += 1;
            }
        }
    }

    /// Timer tick handler (called by IRQ0)
    pub fn on_timer_tick(&mut self) {
        // Wake any sleeping processes
        self.wake_sleeping();

        // Increment tick counter
        self.ticks_since_schedule += 1;

        // Calculate ticks per time slice (100 Hz timer = 10ms per tick)
        const TIMER_HZ: u32 = 100;
        const TICKS_PER_SLICE: u32 = (TIME_SLICE_MS * TIMER_HZ) / 1000;

        // Only preempt after full time slice has elapsed
        if self.ticks_since_schedule < TICKS_PER_SLICE {
            return;
        }

        self.ticks_since_schedule = 0;
        self.preemptions += 1;

        // Preempt current process
        if let Some(current_pid) = self.current_pid {
            let priority = if let Some(ref mut proc) = self.processes[current_pid.0 as usize] {
                proc.state = ProcessState::Ready;
                proc.priority
            } else {
                return; // Exit early if process doesn't exist
            };
            self.enqueue_ready(current_pid, priority);
        }

        // Schedule next process
        self.schedule();
    }

    /// Schedule next process to run (round-robin within priority levels)
    fn schedule(&mut self) {
        // Select next process (priority order: High -> Normal -> Low)
        let next_pid = self
            .dequeue_ready_high()
            .or_else(|| self.dequeue_ready_normal())
            .or_else(|| self.dequeue_ready_low());

        if let Some(next_pid) = next_pid {
            // Context switch
            let old_pid = self.current_pid;
            self.current_pid = Some(next_pid);

            if let Some(ref mut proc) = self.processes[next_pid.0 as usize] {
                proc.state = ProcessState::Running;
                proc.cpu_time += 1;
            }

            self.total_switches += 1;

            // Set Task Switched (TS) bit in CR0 to enable lazy FPU context saving
            #[cfg(target_arch = "x86")]
            unsafe {
                let mut cr0: u32;
                core::arch::asm!("mov {0}, cr0", out(reg) cr0);
                cr0 |= 8; // Set TS bit
                core::arch::asm!("mov cr0, {0}", in(reg) cr0);
            }

            // Perform assembly context switch
            unsafe {
                let old_ctx = old_pid.map(|pid| &mut self.contexts[pid.0 as usize] as *mut _);
                let new_ctx = &self.contexts[next_pid.0 as usize] as *const _;

                if let Some(old_ctx_ptr) = old_ctx {
                    asm_switch_context(old_ctx_ptr, new_ctx);
                } else {
                    // First time scheduling, just load new context
                    // (In reality, we'd set up the initial context properly)
                }
            }
        } else {
            // No processes to run, idle
            self.current_pid = None;
            let interrupts_enabled = unsafe { crate::process_asm::get_interrupt_state() } != 0;
            if interrupts_enabled {
                // Enhanced power management during idle
                // Verify interrupt delivery will wake from HLT
                #[cfg(target_arch = "x86")]
                {
                    // Read EFLAGS to double-check IF bit
                    let eflags: u32;
                    unsafe {
                        core::arch::asm!("pushfd", "pop {}", out(reg) eflags, options(nomem, nostack));
                    }
                    if (eflags & 0x200) == 0 {
                        crate::serial_println!(
                            "[SCHED] WARNING: Attempting HLT with interrupts disabled!"
                        );
                        return; // Avoid deadlock
                    }
                }

                // Log idle entry for power profiling
                crate::serial_println!("[SCHED] Entering idle state (HLT)");

                // HLT to save power - CPU will wake on next interrupt
                crate::asm_bindings::hlt();

                // Track wakeup reason
                crate::serial_println!("[SCHED] Woke from idle");
            }
        }
    }

    /// Add process to ready queue based on priority
    fn enqueue_ready(&mut self, pid: Pid, priority: ProcessPriority) {
        match priority {
            ProcessPriority::High => {
                if self.ready_high_len < MAX_PROCESSES {
                    self.ready_queue_high[self.ready_high_len] = Some(pid);
                    self.ready_high_len += 1;
                }
            }
            ProcessPriority::Normal => {
                if self.ready_normal_len < MAX_PROCESSES {
                    self.ready_queue_normal[self.ready_normal_len] = Some(pid);
                    self.ready_normal_len += 1;
                }
            }
            ProcessPriority::Low => {
                if self.ready_low_len < MAX_PROCESSES {
                    self.ready_queue_low[self.ready_low_len] = Some(pid);
                    self.ready_low_len += 1;
                }
            }
        }
    }

    /// Dequeue from high priority ready queue
    fn dequeue_ready_high(&mut self) -> Option<Pid> {
        if self.ready_high_len > 0 {
            let pid = self.ready_queue_high[0];
            // Shift queue
            for i in 0..self.ready_high_len - 1 {
                self.ready_queue_high[i] = self.ready_queue_high[i + 1];
            }
            self.ready_high_len -= 1;
            pid
        } else {
            None
        }
    }

    /// Dequeue from normal priority ready queue
    fn dequeue_ready_normal(&mut self) -> Option<Pid> {
        if self.ready_normal_len > 0 {
            let pid = self.ready_queue_normal[0];
            for i in 0..self.ready_normal_len - 1 {
                self.ready_queue_normal[i] = self.ready_queue_normal[i + 1];
            }
            self.ready_normal_len -= 1;
            pid
        } else {
            None
        }
    }

    /// Dequeue from low priority ready queue
    fn dequeue_ready_low(&mut self) -> Option<Pid> {
        if self.ready_low_len > 0 {
            let pid = self.ready_queue_low[0];
            for i in 0..self.ready_low_len - 1 {
                self.ready_queue_low[i] = self.ready_queue_low[i + 1];
            }
            self.ready_low_len -= 1;
            pid
        } else {
            None
        }
    }

    /// Remove PID from all ready queues
    fn remove_from_ready_queues(&mut self, pid: Pid) {
        // High priority queue
        let mut i = 0;
        while i < self.ready_high_len {
            if self.ready_queue_high[i] == Some(pid) {
                for j in i..self.ready_high_len - 1 {
                    self.ready_queue_high[j] = self.ready_queue_high[j + 1];
                }
                self.ready_high_len -= 1;
            } else {
                i += 1;
            }
        }

        // Normal priority queue
        i = 0;
        while i < self.ready_normal_len {
            if self.ready_queue_normal[i] == Some(pid) {
                for j in i..self.ready_normal_len - 1 {
                    self.ready_queue_normal[j] = self.ready_queue_normal[j + 1];
                }
                self.ready_normal_len -= 1;
            } else {
                i += 1;
            }
        }

        // Low priority queue
        i = 0;
        while i < self.ready_low_len {
            if self.ready_queue_low[i] == Some(pid) {
                for j in i..self.ready_low_len - 1 {
                    self.ready_queue_low[j] = self.ready_queue_low[j + 1];
                }
                self.ready_low_len -= 1;
            } else {
                i += 1;
            }
        }
    }

    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        SchedulerStats {
            total_processes: self.processes.iter().filter(|p| p.is_some()).count(),
            running_processes: self
                .processes
                .iter()
                .filter(|p| {
                    p.as_ref()
                        .map(|proc| proc.state == ProcessState::Running)
                        .unwrap_or(false)
                })
                .count(),
            ready_processes: self.ready_high_len + self.ready_normal_len + self.ready_low_len,
            sleeping_processes: self.sleeping_count,
            total_switches: self.total_switches,
            preemptions: self.preemptions,
        }
    }

    /// List all processes
    pub fn list_processes(&self) -> impl Iterator<Item = &Process> {
        self.processes.iter().filter_map(|p| p.as_ref())
    }

    /// Handles Device Not Available (#NM) exception for lazy FPU state saving
    pub unsafe fn handle_fpu_trap(&mut self) {
        #[cfg(target_arch = "x86")]
        {
            // Clear TS bit
            core::arch::asm!("clts");
        }

        let current = match self.current_pid {
            Some(pid) => pid,
            None => return, // Shouldn't happen
        };

        if let Some(owner) = self.fpu_owner {
            if owner == current {
                // We still own the FPU! Nothing to do.
                return;
            }

            // Save state for the old owner
            if let Some(ref mut proc) = self.processes[owner.0 as usize] {
                crate::process_asm::save_fpu_state(proc.fpu_state.0.as_mut_ptr());
            }
        }

        // Restore or initialize state for the new owner
        if let Some(ref mut proc) = self.processes[current.0 as usize] {
            if proc.has_used_fpu {
                crate::process_asm::restore_fpu_state(proc.fpu_state.0.as_ptr());
            } else {
                #[cfg(target_arch = "x86")]
                {
                    core::arch::asm!("fninit");
                    // Can add fldcw / ldmxcsr here for SSE later if needed
                }
                proc.has_used_fpu = true;
            }
        }

        self.fpu_owner = Some(current);
    }
}

/// Scheduler statistics
#[derive(Debug, Clone, Copy)]
pub struct SchedulerStats {
    pub total_processes: usize,
    pub running_processes: usize,
    pub ready_processes: usize,
    pub sleeping_processes: usize,
    pub total_switches: u64,
    pub preemptions: u64,
}

static RESCHED_REQUESTED: AtomicBool = AtomicBool::new(false);

// Global scheduler instance
pub static SCHEDULER: DagSpinlock<DAG_LEVEL_SCHEDULER, Scheduler> =
    DagSpinlock::new(Scheduler::new());

/// Get the global scheduler
pub fn scheduler() -> &'static DagSpinlock<DAG_LEVEL_SCHEDULER, Scheduler> {
    &SCHEDULER
}

/// Constructs a syscall-level DAG context for scheduler operations.
///
/// `DAG_LEVEL_SYSCALL = 15 > DAG_LEVEL_SCHEDULER = 10`, so `acquire_lock(&SCHEDULER, …)`
/// is statically valid from this context.
#[inline(always)]
fn syscall_context() -> InterruptContext<DAG_LEVEL_SYSCALL> {
    // SAFETY: DAG_LEVEL_SYSCALL > DAG_LEVEL_SCHEDULER; we are in a thread/syscall
    // context, not inside a hardware IRQ handler.
    unsafe { InterruptContext::<DAG_LEVEL_SYSCALL>::new() }
}

/// Yield CPU to next process
pub fn yield_cpu() {
    syscall_context().acquire_lock(&SCHEDULER, |sched, _sub| {
        sched.yield_cpu();
    });
}

/// Sleep current process for N milliseconds
pub fn sleep(ms: u32) {
    syscall_context().acquire_lock(&SCHEDULER, |sched, _sub| {
        sched.sleep(ms);
    });
}

/// Timer interrupt handler (called by IRQ0)
pub fn on_timer_tick() {
    let in_interrupt = unsafe { crate::process_asm::get_interrupt_state() } == 0;
    if in_interrupt {
        syscall_context().acquire_lock(&SCHEDULER, |sched, _sub| {
            sched.preemptions += 1;
            sched.wake_sleeping();
            if let Some(current_pid) = sched.current_pid {
                let priority = if let Some(ref mut proc) = sched.processes[current_pid.0 as usize] {
                    proc.state = ProcessState::Ready;
                    proc.priority
                } else {
                    return;
                };
                sched.enqueue_ready(current_pid, priority);
            }
            RESCHED_REQUESTED.store(true, Ordering::SeqCst);
        });
        return;
    }

    syscall_context().acquire_lock(&SCHEDULER, |sched, _sub| {
        sched.on_timer_tick();
    });
}

/// Perform deferred reschedule if requested by timer IRQ
pub fn maybe_reschedule() {
    if RESCHED_REQUESTED.swap(false, Ordering::SeqCst) {
        syscall_context().acquire_lock(&SCHEDULER, |sched, _sub| {
            sched.schedule();
        });
    }
}
