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

//! Advanced Quantum-Based Preemptive Scheduler
//!
//! Features:
//! - Per-process quantum tracking with decay
//! - Multi-level feedback queue (MLFQ) for adaptive priority
//! - Blocking primitives (futex-like wait queues)
//! - CPU affinity and load balancing (single-core for now)
//! - Accounting: CPU time, context switches, wait time

use crate::process::{Pid, Process, ProcessPriority, ProcessState, MAX_PROCESSES};
use crate::scheduler_platform::{self, ProcessContext};
use crate::scheduler_runtime_platform as scheduler_rt;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// FIX #1: Module-level stacks (properly placed in BSS by linker)
const KERNEL_THREAD_STACK_BYTES: usize = 1024 * 1024;

#[repr(align(4096))]
struct AlignedStack {
    data: [u8; KERNEL_THREAD_STACK_BYTES],
}
static mut KERNEL_STACK_0: AlignedStack = AlignedStack {
    data: [0; KERNEL_THREAD_STACK_BYTES],
};
static mut KERNEL_STACK_1: AlignedStack = AlignedStack {
    data: [0; KERNEL_THREAD_STACK_BYTES],
};
static mut KERNEL_STACK_2: AlignedStack = AlignedStack {
    data: [0; KERNEL_THREAD_STACK_BYTES],
};

/// Quantum in ticks (100 Hz = 10ms per tick)
const QUANTUM_HIGH: u32 = 20; // 200ms for high priority
const QUANTUM_NORMAL: u32 = 10; // 100ms for normal
const QUANTUM_LOW: u32 = 5; // 50ms for low priority

/// Maximum wait queue entries
const MAX_WAIT_QUEUES: usize = 64;
const TEMPORAL_SCHEDULER_SCHEMA_V1: u8 = 1;
const TEMPORAL_SCHEDULER_HEADER_BYTES: usize = 60;
const TEMPORAL_SCHEDULER_PROCESS_ENTRY_BYTES: usize = 44;
const TEMPORAL_SCHEDULER_WAIT_QUEUE_HEADER_BYTES: usize = 12;
const READY_QUEUE_LEVELS: usize = 3;

#[derive(Clone, Copy)]
struct ReadyQueue {
    entries: [Pid; MAX_PROCESSES],
    head: usize,
    len: usize,
}

impl ReadyQueue {
    const fn new() -> Self {
        ReadyQueue {
            entries: [Pid(0); MAX_PROCESSES],
            head: 0,
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, pid: Pid) -> bool {
        if self.len >= MAX_PROCESSES {
            return false;
        }
        let tail = (self.head + self.len) % MAX_PROCESSES;
        self.entries[tail] = pid;
        self.len += 1;
        true
    }

    fn pop_front(&mut self) -> Option<Pid> {
        if self.len == 0 {
            return None;
        }
        let pid = self.entries[self.head];
        self.head = (self.head + 1) % MAX_PROCESSES;
        self.len -= 1;
        Some(pid)
    }

    fn for_each<F: FnMut(Pid)>(&self, mut f: F) {
        let mut i = 0usize;
        while i < self.len {
            let idx = (self.head + i) % MAX_PROCESSES;
            f(self.entries[idx]);
            i += 1;
        }
    }
}

fn scheduler_process_state_to_u8(state: ProcessState) -> u8 {
    match state {
        ProcessState::Ready => 1,
        ProcessState::Running => 2,
        ProcessState::Blocked => 3,
        ProcessState::WaitingOnChannel => 4,
        ProcessState::Terminated => 5,
    }
}

fn scheduler_process_state_from_u8(value: u8) -> Option<ProcessState> {
    match value {
        1 => Some(ProcessState::Ready),
        2 => Some(ProcessState::Running),
        3 => Some(ProcessState::Blocked),
        4 => Some(ProcessState::WaitingOnChannel),
        5 => Some(ProcessState::Terminated),
        _ => None,
    }
}

fn scheduler_priority_to_u8(priority: ProcessPriority) -> u8 {
    match priority {
        ProcessPriority::High => 3,
        ProcessPriority::Normal => 2,
        ProcessPriority::Low => 1,
    }
}

fn scheduler_priority_from_u8(value: u8) -> Option<ProcessPriority> {
    match value {
        3 => Some(ProcessPriority::High),
        2 => Some(ProcessPriority::Normal),
        1 => Some(ProcessPriority::Low),
        _ => None,
    }
}

fn scheduler_append_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn scheduler_append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn scheduler_append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn scheduler_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn scheduler_read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn scheduler_read_u64(data: &[u8], offset: usize) -> Option<u64> {
    if offset.saturating_add(8) > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

/// Scheduler state
pub struct QuantumScheduler {
    /// Process table
    processes: [Option<ProcessInfo>; MAX_PROCESSES],
    /// Currently running process
    current_pid: Option<Pid>,
    /// Which process currently owns the FPU registers
    fpu_owner: Option<Pid>,
    /// Ready queues (multi-level)
    ready_queues: [ReadyQueue; READY_QUEUE_LEVELS],
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
    pub shared_runtime_pid: Option<Pid>,
    /// Kernel stack allocation (heap-backed for user/forked processes).
    pub stack: Option<Box<[u8; crate::process::STACK_SIZE]>>,
    /// Owned user address space (Some for user processes, None for kernel threads).
    pub address_space: Option<Box<crate::arch::mmu::AddressSpace>>,
    pub quantum_remaining: u32,
    pub total_cpu_time: u64,  // Total ticks this process ran
    pub total_wait_time: u64, // Total ticks waiting
    pub last_scheduled: u64,  // Tick when last scheduled
    pub switches: u64,        // Number of times scheduled
    // --- Entropy Scheduling (PMA §3) ---
    /// Raw cooperative yield counter (reset on window roll).
    pub yield_count: u32,
    /// Raw page-fault counter (approximated via kernel-side fault accounting).
    pub pagefault_count: u32,
    /// EWMA of yield density: ewma = (ewma * 7 + sample * 1) >> 3.
    pub ewma_yield: u32,
    /// EWMA of fault density.
    pub ewma_fault: u32,
}

/// Wait queue for blocking primitives
#[derive(Clone)]
pub struct WaitQueue {
    pub addr: usize, // Address/key for the wait queue (like futex)
    pub waiting: VecDeque<Pid>,
    pub active: bool,
    pub wake_time: u64, // Non-zero only for timer sleep queues
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
    pub fn new() -> Self {
        const NONE_PROC: Option<ProcessInfo> = None;

        // Properly initialize wait queues array using from_fn
        let wait_queues: [WaitQueue; MAX_WAIT_QUEUES] =
            core::array::from_fn(|_| WaitQueue::default());

        QuantumScheduler {
            processes: [NONE_PROC; MAX_PROCESSES],
            current_pid: None,
            fpu_owner: None,
            ready_queues: [ReadyQueue::new(); READY_QUEUE_LEVELS],
            wait_queues,
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
        let priority = process.priority;
        let idx = pid.0 as usize;

        if idx >= MAX_PROCESSES {
            return Err("Invalid PID");
        }

        if self.processes[idx].is_some() {
            return Err("PID already in use");
        }

        let quantum = match priority {
            ProcessPriority::High => QUANTUM_HIGH,
            ProcessPriority::Normal => QUANTUM_NORMAL,
            ProcessPriority::Low => QUANTUM_LOW,
        };

        let info = ProcessInfo {
            process,
            context: scheduler_platform::context_new(),
            shared_runtime_pid: Some(pid),
            stack: None,
            address_space: None,
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: scheduler_platform::ticks_now(),
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
        };

        self.processes[idx] = Some(info);
        self.enqueue_ready(pid, priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

        Ok(())
    }

    /// Compute a per-process quantum adapted by Shannon entropy of its behavior.
    ///
    /// Uses the bit-shift EWMA approximation:
    ///   ΔS ≈ -( ewma_yield * log2(ewma_yield+1) + ewma_fault * log2(ewma_fault+1) ) / 64
    ///
    /// The kernel-friendly integer approximation replaces log2 with the position of the
    /// highest set bit (floor(log2(x+1))), avoiding any floating-point in ring-0.
    ///
    /// Result is clamped to [QUANTUM_LOW, QUANTUM_HIGH].
    #[cfg(feature = "experimental_entropy_sched")]
    fn compute_entropy_quantum(ewma_yield: u32, ewma_fault: u32, base: u32) -> u32 {
        // floor(log2(x+1)) via leading-zeros count — always well-defined on u32.
        let log2_yield = 31u32.saturating_sub((ewma_yield.saturating_add(1)).leading_zeros());
        let log2_fault = 31u32.saturating_sub((ewma_fault.saturating_add(1)).leading_zeros());

        // Entropy proxy: high cooperative yield → increase quantum (reward); high faults → shrink.
        let reward = ewma_yield.saturating_mul(log2_yield) >> 4;
        let penalty = ewma_fault.saturating_mul(log2_fault) >> 4;
        let adjusted = base.saturating_add(reward).saturating_sub(penalty);
        adjusted.clamp(QUANTUM_LOW, QUANTUM_HIGH)
    }

    /// Decide the next context to switch to (returns context pointers if switching).
    fn plan_switch(
        &mut self,
        prev_pid_override: Option<Pid>,
    ) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        let now = scheduler_platform::ticks_now();

        // Capture valid previous PID before it might get cleared
        let mut prev_pid = self.current_pid;
        if prev_pid.is_none() {
            prev_pid = prev_pid_override;
        }

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
                    #[cfg(not(feature = "experimental_entropy_sched"))]
                    {
                        info.quantum_remaining = match priority {
                            ProcessPriority::High => QUANTUM_HIGH,
                            ProcessPriority::Normal => QUANTUM_NORMAL,
                            ProcessPriority::Low => QUANTUM_LOW,
                        };
                    }
                    #[cfg(feature = "experimental_entropy_sched")]
                    {
                        let base = match priority {
                            ProcessPriority::High => QUANTUM_HIGH,
                            ProcessPriority::Normal => QUANTUM_NORMAL,
                            ProcessPriority::Low => QUANTUM_LOW,
                        };
                        info.quantum_remaining = Self::compute_entropy_quantum(
                            info.ewma_yield,
                            info.pagefault_count,
                            base,
                        );
                        // Roll EWMA: ewma = (ewma*7 + yield_count) >> 3
                        info.ewma_yield = ((info.ewma_yield.saturating_mul(7))
                            .saturating_add(info.yield_count))
                            >> 3;
                        info.ewma_fault = ((info.ewma_fault.saturating_mul(7))
                            .saturating_add(info.pagefault_count))
                            >> 3;
                        info.yield_count = 0;
                        info.pagefault_count = 0;
                    }

                    self.enqueue_ready(current_pid, priority);
                    self.stats.preemptions += 1;
                    self.current_pid = None;
                }
            }
        }

        // If we still have a running process with quantum remaining, keep running it
        if self.current_pid.is_some() {
            return None;
        }

        // Pick next process from ready queues (priority order)
        let next_pid = self.dequeue_ready();

        if next_pid.is_none() {
            self.stats.idle_ticks += 1;
            self.current_pid = None;
            return None;
        }

        let next_pid = next_pid.unwrap();
        // prev_pid was captured at start

        // If no switch needed, keep running current
        if prev_pid == Some(next_pid) {
            self.current_pid = Some(next_pid);
            if let Some(ref mut info) = self.processes[next_pid.0 as usize] {
                info.process.state = ProcessState::Running;
                info.last_scheduled = now;
                info.switches += 1;
            }
            return None;
        }

        self.current_pid = Some(next_pid);

        // Update scheduling timestamp
        if let Some(ref mut info) = self.processes[next_pid.0 as usize] {
            info.process.state = ProcessState::Running;
            info.last_scheduled = now;
            info.switches += 1;
        }

        self.stats.total_switches += 1;

        let from_ptr = prev_pid.and_then(|from_pid| {
            let from_idx = from_pid.0 as usize;
            self.processes[from_idx]
                .as_mut()
                .map(|info| &mut info.context as *mut ProcessContext)
        })?;
        let to_ptr = self.processes[next_pid.0 as usize]
            .as_ref()
            .map(|info| &info.context as *const ProcessContext)?;

        Some((from_ptr, to_ptr))
    }

    /// Schedule next process (called on timer interrupt)
    pub fn schedule(&mut self) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        self.plan_switch(None)
    }

    /// Enqueue process to ready queue
    fn enqueue_ready(&mut self, pid: Pid, priority: ProcessPriority) {
        let queue_idx = match priority {
            ProcessPriority::High => 0,
            ProcessPriority::Normal => 1,
            ProcessPriority::Low => 2,
        };

        let _ = self.ready_queues[queue_idx].push_back(pid);
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
    pub fn yield_cpu(&mut self) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        let prev = self.current_pid;
        if let Some(current_pid) = self.current_pid {
            let idx = current_pid.0 as usize;
            if let Some(ref mut info) = self.processes[idx] {
                // Record cooperative yield for entropy EWMA accounting.
                info.yield_count = info.yield_count.saturating_add(1);
                info.process.state = ProcessState::Ready;
                let priority = info.process.priority;
                self.enqueue_ready(current_pid, priority);
            }
            self.current_pid = None;
            self.stats.voluntary_yields += 1;
        }
        self.plan_switch(prev)
    }

    /// Record a page fault for the current process (called from fault handler).
    /// Used by entropy scheduling to track fault density.
    pub fn record_pagefault(&mut self) {
        if let Some(current_pid) = self.current_pid {
            let idx = current_pid.0 as usize;
            if let Some(ref mut info) = self.processes[idx] {
                info.pagefault_count = info.pagefault_count.saturating_add(1);
            }
        }
    }

    /// Block current process on a wait queue (futex-like)
    pub fn block_on(
        &mut self,
        addr: usize,
    ) -> Result<Option<(*mut ProcessContext, *const ProcessContext)>, &'static str> {
        let current_pid = self.current_pid.ok_or("No current process")?;
        let prev = Some(current_pid);

        // Find or create wait queue
        let queue_idx = self.find_or_create_wait_queue(addr)?;

        // Add to wait queue
        self.wait_queues[queue_idx].waiting.push_back(current_pid);

        // Mark process as blocked
        if let Some(ref mut info) = self.processes[current_pid.0 as usize] {
            info.process.state = ProcessState::Blocked;
        }

        self.current_pid = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(self.plan_switch(prev))
    }

    /// Wake one process from wait queue
    pub fn wake_one(&mut self, addr: usize) -> Result<bool, &'static str> {
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].addr == addr
                && self.wait_queues[i].active
                && self.wait_queues[i].wake_time == 0
            {
                if let Some(pid) = self.wait_queues[i].waiting.pop_front() {
                    // Move to ready queue
                    if let Some(ref mut info) = self.processes[pid.0 as usize] {
                        info.process.state = ProcessState::Ready;
                        let priority = info.process.priority;
                        self.enqueue_ready(pid, priority);
                        if self.wait_queues[i].waiting.is_empty() {
                            self.wait_queues[i].active = false;
                            self.wait_queues[i].addr = 0;
                        }
                        self.record_temporal_state_snapshot_locked(
                            scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
                        );
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
            if self.wait_queues[i].addr == addr
                && self.wait_queues[i].active
                && self.wait_queues[i].wake_time == 0
            {
                while let Some(pid) = self.wait_queues[i].waiting.pop_front() {
                    if let Some(ref mut info) = self.processes[pid.0 as usize] {
                        info.process.state = ProcessState::Ready;
                        let priority = info.process.priority;
                        self.enqueue_ready(pid, priority);
                        count += 1;
                    }
                }
                self.wait_queues[i].active = false;
                self.wait_queues[i].addr = 0;
                self.wait_queues[i].wake_time = 0;
            }
        }

        if count > 0 {
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );
        }
        Ok(count)
    }

    /// Find or create a wait queue for an address
    fn find_or_create_wait_queue(&mut self, addr: usize) -> Result<usize, &'static str> {
        // Try to find existing
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].addr == addr
                && self.wait_queues[i].active
                && self.wait_queues[i].wake_time == 0
            {
                return Ok(i);
            }
        }

        // Reuse an inactive slot before extending the active prefix.
        for i in 0..self.wait_queue_count {
            if !self.wait_queues[i].active {
                self.wait_queues[i] = WaitQueue {
                    addr,
                    waiting: VecDeque::new(),
                    active: true,
                    wake_time: 0,
                };
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
            wake_time: 0,
        };
        self.wait_queue_count += 1;
        Ok(idx)
    }

    fn find_or_create_sleep_queue(&mut self, wake_time: u64) -> Result<usize, &'static str> {
        for i in 0..self.wait_queue_count {
            if self.wait_queues[i].active && self.wait_queues[i].wake_time == wake_time {
                return Ok(i);
            }
        }

        for i in 0..self.wait_queue_count {
            if !self.wait_queues[i].active {
                self.wait_queues[i] = WaitQueue {
                    addr: 0,
                    waiting: VecDeque::new(),
                    active: true,
                    wake_time,
                };
                return Ok(i);
            }
        }

        if self.wait_queue_count >= MAX_WAIT_QUEUES {
            return Err("Sleep queue table full");
        }

        let idx = self.wait_queue_count;
        self.wait_queues[idx] = WaitQueue {
            addr: 0,
            waiting: VecDeque::new(),
            active: true,
            wake_time,
        };
        self.wait_queue_count += 1;
        Ok(idx)
    }

    fn wake_expired_sleepers(&mut self, now: u64) -> usize {
        let mut woken = 0usize;

        for i in 0..self.wait_queue_count {
            if !self.wait_queues[i].active
                || self.wait_queues[i].wake_time == 0
                || self.wait_queues[i].wake_time > now
            {
                continue;
            }

            let priority_updates = {
                let wait = &mut self.wait_queues[i];
                let mut waiting = VecDeque::new();
                core::mem::swap(&mut waiting, &mut wait.waiting);
                wait.active = false;
                wait.addr = 0;
                wait.wake_time = 0;
                waiting
            };

            for pid in priority_updates.into_iter() {
                if let Some(info) = self.processes[pid.0 as usize].as_mut() {
                    info.process.state = ProcessState::Ready;
                    let priority = info.process.priority;
                    self.enqueue_ready(pid, priority);
                    woken = woken.saturating_add(1);
                }
            }
        }

        if woken > 0 {
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );
        }

        woken
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

    #[inline]
    fn runtime_pid_for_scheduler_pid(&self, sched_pid: Pid) -> Option<Pid> {
        self.processes
            .get(sched_pid.0 as usize)
            .and_then(|slot| slot.as_ref())
            .and_then(|info| info.shared_runtime_pid)
            .or(Some(sched_pid))
    }

    #[inline]
    fn current_runtime_pid_raw(&self) -> Option<u32> {
        self.current_pid
            .and_then(|pid| self.runtime_pid_for_scheduler_pid(pid))
            .map(|pid| pid.0)
    }

    /// Add a kernel thread to the scheduler
    pub fn add_kernel_thread(
        &mut self,
        entry: extern "C" fn() -> !,
        priority: ProcessPriority,
    ) -> Result<Pid, &'static str> {
        // Enhanced process table diagnostics with validation
        let table_ptr = self.processes.as_ptr();
        let table_addr = table_ptr as usize;

        // Validate process table alignment against the actual type requirement.
        let required_align = core::mem::align_of::<Option<ProcessInfo>>();
        if table_addr % required_align != 0 {
            scheduler_rt::logf(format_args!(
                "[SCHED] WARNING: Process table misaligned at {:p} (required align: {})",
                table_ptr, required_align
            ));
        }

        // Log comprehensive process table state
        let active_count = self.processes.iter().filter(|p| p.is_some()).count();
        scheduler_rt::logf(format_args!(
            "[SCHED] Process Table: {:p} | Capacity: {} | Active: {} | Available: {}",
            table_ptr,
            MAX_PROCESSES,
            active_count,
            MAX_PROCESSES - active_count
        ));
        scheduler_rt::logf(format_args!(
            "[SCHED] Memory bounds: {:p} - {:p} ({} bytes)",
            table_ptr,
            (table_addr + core::mem::size_of_val(&self.processes)) as *const u8,
            core::mem::size_of_val(&self.processes)
        ));

        // Hardware memory barrier to ensure process table consistency across CPUs
        scheduler_rt::memory_barrier();

        // Find available PID
        let pid = (0..MAX_PROCESSES)
            .map(|i| Pid(i as u32))
            .find(|&pid| self.processes[pid.0 as usize].is_none())
            .ok_or("No available PIDs")?;

        let mut process = Process::new(pid, "kernel_thread", None);
        process.priority = priority;

        // Use module-level stacks (properly placed in BSS)
        let stack_slice = unsafe {
            match pid.0 {
                0 => &mut KERNEL_STACK_0.data[..],
                1 => &mut KERNEL_STACK_1.data[..],
                2 => &mut KERNEL_STACK_2.data[..],
                _ => return Err("Only 3 kernel threads supported with static stacks"),
            }
        };

        let stack_top =
            (unsafe { stack_slice.as_mut_ptr().add(stack_slice.len()) as usize }) & !15usize;

        // Verify stack address is sane and currently mapped.
        // Do not enforce a fixed upper bound: kernel image/heap placement can
        // legitimately exceed 32MB on this build configuration.
        let stack_bottom = stack_top.saturating_sub(8);
        if stack_bottom < 0x1000 || stack_top <= stack_bottom {
            return Err("Stack address invalid");
        }
        let mapped = scheduler_platform::validate_kernel_stack_mapping(stack_bottom, stack_top);
        if !mapped {
            return Err("Stack address not mapped");
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            // x86 trampoline pops the entry pointer from the new stack.
            let entry_addr = entry as *const () as u32;
            let entry_ptr = (stack_top - 4) as *mut u32;
            unsafe {
                entry_ptr.write(entry_addr);
            }
        }

        let (ctx, _entry_addr_debug, trampoline_addr) =
            scheduler_platform::init_kernel_thread_context(entry, stack_top)?;

        scheduler_rt::logf(format_args!(
            "[SCHED] kernel_thread ctx init: entry={:#x} tramp={:#x} sp={:#x}",
            _entry_addr_debug,
            trampoline_addr,
            scheduler_platform::context_stack_pointer(&ctx)
        ));

        #[cfg(target_arch = "aarch64")]
        let shared_runtime_pid = {
            if !crate::vfs_platform::aarch64_shared_process_bridge_registered() {
                crate::vfs_platform::aarch64_register_default_shared_process_bridge();
            }
            let parent = Some(1u32);
            let spawned = crate::vfs_platform::aarch64_spawn_process(parent).map_err(|e| {
                scheduler_rt::logf(format_args!(
                    "[SCHED] AArch64 shared process spawn failed for kernel thread PID {}: {}",
                    pid.0, e
                ));
                e
            })?;
            scheduler_rt::logf(format_args!(
                "[SCHED] AArch64 scheduler PID {} mapped to shared PID {}",
                pid.0, spawned
            ));
            Some(Pid::new(spawned))
        };
        #[cfg(not(target_arch = "aarch64"))]
        let shared_runtime_pid = None;

        process.state = ProcessState::Ready;

        let info = ProcessInfo {
            process,
            context: ctx,
            shared_runtime_pid,
            stack: None, // Stack is static, not heap-allocated
            address_space: None,
            quantum_remaining: QUANTUM_NORMAL,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: 0,
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
        };

        scheduler_rt::vga_print_str("\n");
        // Print stack assignment for debugging
        scheduler_rt::logf(format_args!(
            "[SCHED] Assigned PID {} stack: {:p} - {:p}",
            pid.0,
            stack_slice.as_ptr(),
            unsafe { stack_slice.as_ptr().add(stack_slice.len()) }
        ));
        Ok(pid)
    }

    /// Start the scheduler (never returns)
    /// Static method to avoid double locking. Caller must NOT hold the lock.
    pub fn start_scheduling() -> ! {
        scheduler_rt::vga_print_str("[SCHED] Starting scheduler (safe)\n");

        let (ctx_ptr, runtime_pid_raw) = {
            let mut scheduler = QUANTUM_SCHEDULER.lock();

            // Find next process (prefer ready queues, recover from process table if needed).
            let next_pid = match scheduler.dequeue_ready() {
                Some(pid) => pid,
                None => {
                    scheduler_rt::logf(format_args!(
                        "[SCHED] Ready queues empty at scheduler start, scanning process table"
                    ));
                    let recovered =
                        scheduler
                            .processes
                            .iter()
                            .enumerate()
                            .find_map(|(idx, info_opt)| {
                                let info = info_opt.as_ref()?;
                                if matches!(
                                    info.process.state,
                                    ProcessState::Ready | ProcessState::Running
                                ) {
                                    Some(Pid(idx as u32))
                                } else {
                                    None
                                }
                            });
                    match recovered {
                        Some(pid) => {
                            scheduler_rt::logf(format_args!(
                                "[SCHED] Recovered runnable PID {} from process table",
                                pid.0
                            ));
                            pid
                        }
                        None => {
                            scheduler_rt::logf(format_args!(
                                "[SCHED] FATAL: no runnable processes in scheduler"
                            ));
                            scheduler_rt::vga_print_str("[SCHED] FATAL: no runnable processes\n");
                            scheduler_rt::halt_cpu();
                        }
                    }
                }
            };

            scheduler.current_pid = Some(next_pid);
            SCHEDULER_STARTED.store(true, Ordering::Release);
            scheduler.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            if let Some(ref mut info) = scheduler.processes[next_pid.0 as usize] {
                info.process.state = ProcessState::Running;
                // Return pointer relative to the heap allocation (stable address)
                (
                    &info.context as *const ProcessContext,
                    scheduler.current_runtime_pid_raw().unwrap_or(next_pid.0),
                )
            } else {
                panic!("Process data missing");
            }
        }; // Lock is dropped here

        scheduler_rt::vga_print_str("[SCHED] Lock dropped, loading context\n");
        scheduler_rt::vga_print_str("[SCHED] Jumping to task...\n");
        unsafe {
            scheduler_platform::debug_dump_launch_context(ctx_ptr);
        }
        scheduler_platform::runtime_pid_sync(runtime_pid_raw);

        // Set Task Switched (TS) bit in CR0 to enable lazy FPU context saving natively on dispatch
        #[cfg(target_arch = "x86")]
        unsafe {
            let mut cr0: u32;
            core::arch::asm!("mov {0}, cr0", out(reg) cr0);
            cr0 |= 8;
            core::arch::asm!("mov cr0, {0}", in(reg) cr0);
        }

        unsafe {
            scheduler_platform::load_context(ctx_ptr);
        }
    }

    /// Add a user process with its own address space.
    ///
    /// `process`    – pre-built PCB (pid, name, priority already set by caller).
    /// `space`      – owned `AddressSpace` for this process (user page directory).
    /// `entry`      – virtual address of the user-mode entry point.
    /// `user_stack` – virtual address of the top of the user stack (pre-mapped by caller).
    ///
    /// On x86 the scheduler uses the kernel-mode `ProcessContext` layout
    /// (ebx/ecx/edx/esi/edi/ebp/esp/eip/eflags/cr3) and a dedicated
    /// per-process kernel stack for the initial supervisor-to-user transition.
    /// The physical address of the process page directory is stored in both
    /// `process.page_dir_phys` and `ctx.cr3` so the context switch can load CR3.
    pub fn add_user_process(
        &mut self,
        mut process: Process,
        space: Box<crate::arch::mmu::AddressSpace>,
        entry: u32,
        user_stack: u32,
    ) -> Result<Pid, &'static str> {
        #[cfg(target_arch = "x86_64")]
        {
            let _ = (&mut process, &space, entry, user_stack);
            return Err("add_user_process: not supported on this arch");
        }

        let pid = process.pid;
        let idx = pid.0 as usize;

        if idx >= MAX_PROCESSES {
            return Err("add_user_process: PID out of range");
        }
        if self.processes[idx].is_some() {
            return Err("add_user_process: PID already in use");
        }

        // Validate entry and stack look like user-space addresses
        // (below 0xC000_0000, the kernel base on this x86 build).
        const KERNEL_BASE_ADDR: u32 = 0xC000_0000;
        if entry >= KERNEL_BASE_ADDR {
            return Err("add_user_process: entry point in kernel space");
        }
        if user_stack == 0 || user_stack >= KERNEL_BASE_ADDR {
            return Err("add_user_process: user stack in kernel space or null");
        }

        // Allocate a kernel stack for this process (used by the kernel-side
        // of the context switch / syscall trampoline).
        let kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
            Box::new([0u8; crate::process::STACK_SIZE]);
        let stack_top = (kernel_stack.as_ptr() as usize + crate::process::STACK_SIZE) & !15usize;

        // Physical address of the page directory (= its kernel virtual address
        // because the kernel identity-maps all RAM on this platform).
        let page_dir_phys = space.phys_addr() as u32;

        process.state = ProcessState::Ready;
        process.page_dir_phys = page_dir_phys;
        process.stack_ptr = user_stack as usize;
        process.program_counter = entry as usize;

        let priority = process.priority;
        let quantum = match priority {
            ProcessPriority::High => QUANTUM_HIGH,
            ProcessPriority::Normal => QUANTUM_NORMAL,
            ProcessPriority::Low => QUANTUM_LOW,
        };

        // Build the initial kernel-side context.
        // eip  → kernel user-entry trampoline (kernel_user_entry_trampoline).
        //         On the very first schedule the trampoline is responsible for
        //         performing the ring-3 transition (iret) using the entry/stack
        //         values pushed on the kernel stack below.
        // esp  → top of the kernel stack, minus room for the trampoline frame.
        // cr3  → user address space physical root.
        // eflags → IF enabled (0x202), IOPL=0.
        //
        // The trampoline frame pushed on the kernel stack carries:
        //   [esp+0]  entry       (u32) – user EIP for iret
        //   [esp+4]  user_stack  (u32) – user ESP for iret
        //
        // NOTE: a full ring-3 iret also needs CS/SS/DS but those selectors are
        // architecture wiring done by the trampoline assembly. We pass the
        // virtual addresses here and leave segment plumbing to the trampoline.

        // Push the two-word frame the trampoline will consume.
        let frame_top = (stack_top - 8) as *mut u32;
        unsafe {
            // slot 0: user entry EIP
            frame_top.write(entry);
            // slot 1: user ESP
            frame_top.add(1).write(user_stack);
        }

        let mut ctx = scheduler_platform::context_new();

        // On x86 the non-aarch64 ProcessContext exposes eip/esp/ebp/cr3/eflags.
        #[cfg(target_arch = "x86")]
        {
            // Point to the user-entry trampoline.
            ctx.eip = crate::asm_bindings::kernel_user_entry_trampoline as u32;
            // Kernel stack is 8 bytes below the pushed frame (frame_top).
            ctx.esp = frame_top as u32;
            ctx.ebp = frame_top as u32;
            ctx.cr3 = page_dir_phys;
            // Enable interrupts once the process is first scheduled.
            ctx.eflags = 0x0000_0202;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // AArch64 user-mode entry: set PC to entry, SP to user_stack, TTBR0 to
            // the new address space root, and mask IRQs until the thread is running.
            ctx.pc = entry as u64;
            ctx.sp = user_stack as u64;
            ctx.ttbr0_el1 = page_dir_phys as u64;
            ctx.daif = 1u64 << 7; // IRQ masked; trampoline will unmask
            ctx.esp = user_stack;
        }

        #[cfg(target_arch = "aarch64")]
        let shared_runtime_pid = {
            if !crate::vfs_platform::aarch64_shared_process_bridge_registered() {
                crate::vfs_platform::aarch64_register_default_shared_process_bridge();
            }
            crate::vfs_platform::aarch64_spawn_process(Some(pid.0))
                .ok()
                .map(Pid::new)
        };
        #[cfg(not(target_arch = "aarch64"))]
        let shared_runtime_pid = None;

        let now = scheduler_platform::ticks_now();

        let info = ProcessInfo {
            process,
            context: ctx,
            shared_runtime_pid,
            stack: Some(kernel_stack),
            address_space: Some(space),
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: now,
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
        };

        self.processes[idx] = Some(info);
        self.enqueue_ready(pid, priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

        scheduler_rt::logf(format_args!(
            "[SCHED] add_user_process: pid={} entry={:#010x} user_sp={:#010x} cr3={:#010x}",
            pid.0, entry, user_stack, page_dir_phys,
        ));

        Ok(pid)
    }

    /// Remove a process from scheduler state and all run/wait queues.
    pub fn remove_process(&mut self, pid: Pid) -> Result<(), &'static str> {
        let idx = pid.0 as usize;
        if idx >= MAX_PROCESSES {
            return Err("Invalid PID");
        }
        if self.processes[idx].is_none() {
            return Err("Process not found");
        }

        if self.current_pid == Some(pid) {
            self.current_pid = None;
        }

        for queue in &mut self.ready_queues {
            let len = queue.len();
            for _ in 0..len {
                if let Some(queued_pid) = queue.pop_front() {
                    if queued_pid != pid {
                        let _ = queue.push_back(queued_pid);
                    }
                }
            }
        }

        for i in 0..self.wait_queue_count {
            let wait = &mut self.wait_queues[i];
            if !wait.active {
                continue;
            }
            let len = wait.waiting.len();
            for _ in 0..len {
                if let Some(waiting_pid) = wait.waiting.pop_front() {
                    if waiting_pid != pid {
                        wait.waiting.push_back(waiting_pid);
                    }
                }
            }
            if wait.waiting.is_empty() {
                wait.active = false;
            }
        }

        #[cfg(target_arch = "aarch64")]
        if let Some(info) = self.processes[idx].as_ref() {
            if let Some(shared_pid) = info.shared_runtime_pid {
                let _ = crate::vfs_platform::aarch64_destroy_process(shared_pid.0);
            }
        }

        self.processes[idx] = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(())
    }

    /// Fork the current process using copy-on-write address space duplication.
    ///
    /// Semantics mirror POSIX `fork()`:
    /// - A new PID is allocated from the process table.
    /// - The child's `Process` PCB is cloned from the parent (same name, same
    ///   priority, same capability table snapshot, same FD table).
    /// - The parent's address space is duplicated via `AddressSpace::clone_cow()`
    ///   which marks all writable user pages as read-only in *both* parent and
    ///   child; page-fault handling (not yet wired) will break sharing on write.
    /// - The child's `ProcessContext` is copied verbatim from the parent so that
    ///   on its first schedule it continues at the same EIP/PC.
    /// - The child is placed in the `Ready` state at the *same* priority level
    ///   as the parent and enqueued immediately.
    ///
    /// Returns `Ok(child_pid)` on success.
    ///
    /// # Limitations / TODO
    /// - COW page-fault break-out is not yet wired into the x86 `#PF` handler.
    /// - File descriptors are not duplicated (handles are copied by value only).
    /// - The actual COW fork path is only implemented on i686/x86 right now.
    ///   x86_64 and AArch64 still return
    ///   `Err("fork_current_cow: not supported on this arch")`.
    pub fn fork_current_cow(&mut self) -> Result<Pid, &'static str> {
        // ------------------------------------------------------------------ //
        // 1. Identify the current (parent) process
        // ------------------------------------------------------------------ //
        let parent_pid = self
            .current_pid
            .ok_or("fork_current_cow: no current process")?;
        let parent_idx = parent_pid.0 as usize;

        // ------------------------------------------------------------------ //
        // 2. Allocate a child PID
        // ------------------------------------------------------------------ //
        let child_pid = (0..MAX_PROCESSES)
            .map(|i| Pid(i as u32))
            .find(|&p| self.processes[p.0 as usize].is_none())
            .ok_or("fork_current_cow: process table full")?;
        let child_idx = child_pid.0 as usize;

        // ------------------------------------------------------------------ //
        // 3. Clone the parent PCB and adjust child-specific fields
        // ------------------------------------------------------------------ //
        // We need to read the parent info without a simultaneous mutable borrow,
        // so we extract the fields we need first.
        let (parent_process_clone, parent_ctx, parent_priority) = {
            let info = self.processes[parent_idx]
                .as_ref()
                .ok_or("fork_current_cow: parent info missing")?;
            (info.process.clone(), info.context, info.process.priority)
        };

        let mut child_process = parent_process_clone;
        child_process.pid = child_pid;
        child_process.parent = Some(parent_pid);
        child_process.state = ProcessState::Ready;
        // Reset runtime counters for the child
        child_process.cpu_time = 0;
        child_process.has_used_fpu = false;
        child_process.fpu_state = crate::process::FpuState([0u8; 512]);

        // ------------------------------------------------------------------ //
        // 4. COW address space duplication (i686/x86 only for now)
        // ------------------------------------------------------------------ //
        #[cfg(not(target_arch = "x86"))]
        {
            return Err("fork_current_cow: not supported on this arch");
        }

        #[cfg(target_arch = "x86")]
        let child_address_space: Box<crate::arch::mmu::AddressSpace>;
        #[cfg(target_arch = "x86")]
        let child_cr3: u32;

        #[cfg(target_arch = "x86")]
        {
            // Borrow the parent's stored AddressSpace mutably so we can call
            // clone_cow(). We hold no other mutable borrows into processes[parent_idx]
            // at this point.
            let child_space = self.processes[parent_idx]
                .as_mut()
                .and_then(|info| info.address_space.as_mut())
                .ok_or("fork_current_cow: parent has no owned address space")
                .and_then(|space| {
                    space
                        .clone_cow()
                        .map_err(|_| "fork_current_cow: clone_cow failed")
                })?;

            child_cr3 = child_space.phys_addr() as u32;
            child_address_space = Box::new(child_space);
            child_process.page_dir_phys = child_cr3;
        }

        // ------------------------------------------------------------------ //
        // 5. Build child context (copy of parent, but with child's CR3)
        // ------------------------------------------------------------------ //
        let mut child_ctx = parent_ctx;
        #[cfg(target_arch = "x86")]
        {
            child_ctx.cr3 = child_cr3;
            // The child returns 0 from fork (by convention eax is the return value
            // of the syscall). We leave eax=0; eax is not part of ProcessContext
            // so the child will naturally resume with the same register state and
            // the syscall return path will overwrite eax with 0 before iret.
        }

        // ------------------------------------------------------------------ //
        // 6. Allocate a kernel stack for the child
        // ------------------------------------------------------------------ //
        let child_kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
            Box::new([0u8; crate::process::STACK_SIZE]);

        let quantum = match parent_priority {
            ProcessPriority::High => QUANTUM_HIGH,
            ProcessPriority::Normal => QUANTUM_NORMAL,
            ProcessPriority::Low => QUANTUM_LOW,
        };

        let now = scheduler_platform::ticks_now();

        let child_info = ProcessInfo {
            process: child_process,
            context: child_ctx,
            shared_runtime_pid: None,
            stack: Some(child_kernel_stack),
            #[cfg(target_arch = "x86")]
            address_space: Some(child_address_space),
            #[cfg(not(target_arch = "x86"))]
            address_space: None,
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: now,
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
        };

        // ------------------------------------------------------------------ //
        // 7. Notify platform hooks (temporal, security, capability)
        // ------------------------------------------------------------------ //
        #[cfg(target_arch = "x86")]
        crate::process_platform::on_process_spawn(child_pid, Some(parent_pid), "forked");

        // ------------------------------------------------------------------ //
        // 8. Insert child into process table and ready queue
        // ------------------------------------------------------------------ //
        self.processes[child_idx] = Some(child_info);
        self.enqueue_ready(child_pid, parent_priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

        #[cfg(target_arch = "x86")]
        scheduler_rt::logf(format_args!(
            "[SCHED] fork_current_cow: parent={} -> child={} cr3={:#010x}",
            parent_pid.0, child_pid.0, child_cr3,
        ));

        Ok(child_pid)
    }

    /// Record voluntary yield
    pub fn record_voluntary_yield(&mut self) {
        self.stats.voluntary_yields += 1;
    }

    /// Block process
    pub fn block_process(
        &mut self,
        pid: Pid,
        wake_time: u64,
    ) -> Result<Option<(*mut ProcessContext, *const ProcessContext)>, &'static str> {
        let current_pid = self
            .current_pid
            .ok_or("block_process: no current process")?;
        if current_pid != pid {
            return Err("block_process: pid is not current");
        }

        let prev = Some(current_pid);
        let queue_idx = self.find_or_create_sleep_queue(wake_time)?;
        self.wait_queues[queue_idx].waiting.push_back(current_pid);

        if let Some(info) = self.processes[current_pid.0 as usize].as_mut() {
            info.process.state = ProcessState::Blocked;
            info.last_scheduled = scheduler_platform::ticks_now();
        }

        self.current_pid = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(self.plan_switch(prev))
    }

    /// Execute WASM in current process
    pub fn exec_current_wasm(&mut self, module_id: u32) -> Result<(), &'static str> {
        let current_pid = self
            .current_pid
            .ok_or("exec_current_wasm: no current process")?;
        let info = self.processes[current_pid.0 as usize]
            .as_mut()
            .ok_or("exec_current_wasm: current process missing")?;

        // Until usermode WASM replaces the whole process image, treat exec as
        // rebinding the current task to a new module entry. The actual module
        // execution happens outside the scheduler lock in the syscall path.
        info.process.program_counter = module_id as usize;
        info.process.state = ProcessState::Running;
        info.quantum_remaining = match info.process.priority {
            ProcessPriority::High => QUANTUM_HIGH,
            ProcessPriority::Normal => QUANTUM_NORMAL,
            ProcessPriority::Low => QUANTUM_LOW,
        };
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        scheduler_rt::logf(format_args!(
            "[SCHED] exec_current_wasm: pid={} module_id={}",
            current_pid.0, module_id
        ));
        Ok(())
    }

    fn encode_temporal_state_payload_locked(&self, event: u8) -> Option<Vec<u8>> {
        let mut process_count = 0usize;
        let mut i = 0usize;
        while i < self.processes.len() {
            if self.processes[i].is_some() {
                process_count += 1;
            }
            i += 1;
        }

        let mut ready_pid_count = 0usize;
        let mut q = 0usize;
        while q < self.ready_queues.len() {
            ready_pid_count = ready_pid_count.saturating_add(self.ready_queues[q].len());
            q += 1;
        }

        let mut wait_pid_count = 0usize;
        let mut wait_idx = 0usize;
        while wait_idx < self.wait_queue_count {
            if self.wait_queues[wait_idx].active {
                wait_pid_count =
                    wait_pid_count.saturating_add(self.wait_queues[wait_idx].waiting.len());
            }
            wait_idx += 1;
        }

        let total_len = TEMPORAL_SCHEDULER_HEADER_BYTES
            .saturating_add(process_count.saturating_mul(TEMPORAL_SCHEDULER_PROCESS_ENTRY_BYTES))
            .saturating_add(ready_pid_count.saturating_mul(4))
            .saturating_add(
                self.wait_queue_count
                    .saturating_mul(TEMPORAL_SCHEDULER_WAIT_QUEUE_HEADER_BYTES),
            )
            .saturating_add(wait_pid_count.saturating_mul(4));
        if total_len > scheduler_rt::MAX_TEMPORAL_VERSION_BYTES {
            return None;
        }

        let mut payload = Vec::with_capacity(total_len);
        payload.push(scheduler_rt::TEMPORAL_OBJECT_ENCODING_V1);
        payload.push(scheduler_rt::TEMPORAL_SCHEDULER_OBJECT);
        payload.push(event);
        payload.push(TEMPORAL_SCHEDULER_SCHEMA_V1);
        scheduler_append_u16(&mut payload, MAX_PROCESSES as u16);
        scheduler_append_u16(&mut payload, MAX_WAIT_QUEUES as u16);
        scheduler_append_u16(&mut payload, process_count as u16);
        scheduler_append_u16(&mut payload, self.wait_queue_count as u16);
        scheduler_append_u32(
            &mut payload,
            self.current_pid.map(|pid| pid.0).unwrap_or(u32::MAX),
        );
        scheduler_append_u32(&mut payload, self.ready_queues[0].len() as u32);
        scheduler_append_u32(&mut payload, self.ready_queues[1].len() as u32);
        scheduler_append_u32(&mut payload, self.ready_queues[2].len() as u32);
        scheduler_append_u64(&mut payload, self.stats.total_switches);
        scheduler_append_u64(&mut payload, self.stats.preemptions);
        scheduler_append_u64(&mut payload, self.stats.voluntary_yields);
        scheduler_append_u64(&mut payload, self.stats.idle_ticks);

        let mut idx = 0usize;
        while idx < self.processes.len() {
            if let Some(info) = self.processes[idx].as_ref() {
                scheduler_append_u32(&mut payload, idx as u32);
                payload.push(scheduler_process_state_to_u8(info.process.state));
                payload.push(scheduler_priority_to_u8(info.process.priority));
                scheduler_append_u16(&mut payload, 0);
                scheduler_append_u32(&mut payload, info.quantum_remaining);
                scheduler_append_u64(&mut payload, info.total_cpu_time);
                scheduler_append_u64(&mut payload, info.total_wait_time);
                scheduler_append_u64(&mut payload, info.last_scheduled);
                scheduler_append_u64(&mut payload, info.switches);
            }
            idx += 1;
        }

        let mut queue_idx = 0usize;
        while queue_idx < self.ready_queues.len() {
            self.ready_queues[queue_idx].for_each(|pid| scheduler_append_u32(&mut payload, pid.0));
            queue_idx += 1;
        }

        let mut i = 0usize;
        while i < self.wait_queue_count {
            let wait = &self.wait_queues[i];
            scheduler_append_u64(&mut payload, wait.addr as u64);
            payload.push(if wait.active { 1 } else { 0 });
            payload.push(0);
            scheduler_append_u16(&mut payload, wait.waiting.len() as u16);
            for pid in wait.waiting.iter() {
                scheduler_append_u32(&mut payload, pid.0);
            }
            i += 1;
        }

        Some(payload)
    }

    fn record_temporal_state_snapshot_locked(&self, event: u8) {
        if scheduler_rt::temporal_is_replay_active() {
            return;
        }
        let payload = match self.encode_temporal_state_payload_locked(event) {
            Some(v) => v,
            None => return,
        };
        let _ = scheduler_rt::temporal_record_scheduler_state_event(&payload);
    }

    /// Get current PID
    pub fn get_current_pid(&self) -> Option<Pid> {
        self.current_pid
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
            if let Some(ref mut info) = self.processes[owner.0 as usize] {
                crate::process_asm::save_fpu_state(info.process.fpu_state.0.as_mut_ptr());
            }
        }

        // Restore or initialize state for the new owner
        if let Some(ref mut info) = self.processes[current.0 as usize] {
            if info.process.has_used_fpu {
                crate::process_asm::restore_fpu_state(info.process.fpu_state.0.as_ptr());
            } else {
                #[cfg(target_arch = "x86")]
                {
                    core::arch::asm!("fninit");
                    // Can add fldcw / ldmxcsr here for SSE later if needed
                }
                info.process.has_used_fpu = true;
            }
        }

        self.fpu_owner = Some(current);
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        WaitQueue {
            addr: 0,
            waiting: VecDeque::new(),
            active: false,
            wake_time: 0,
        }
    }
}

lazy_static::lazy_static! {
    /// Global scheduler instance
    static ref QUANTUM_SCHEDULER: Mutex<QuantumScheduler> = Mutex::new(QuantumScheduler::new());
}
static SCHEDULER_STARTED: AtomicBool = AtomicBool::new(false);
static RESCHED_REQUEST: AtomicBool = AtomicBool::new(false);

/// Initialize quantum scheduler
pub fn init() {
    // Scheduler is already initialized via static
}

/// Get reference to global scheduler
pub fn scheduler() -> &'static Mutex<QuantumScheduler> {
    &QUANTUM_SCHEDULER
}

pub fn temporal_apply_scheduler_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < TEMPORAL_SCHEDULER_HEADER_BYTES {
        return Err("temporal scheduler payload too short");
    }
    if payload[0] != scheduler_rt::TEMPORAL_OBJECT_ENCODING_V1
        || payload[1] != scheduler_rt::TEMPORAL_SCHEDULER_OBJECT
    {
        return Err("temporal scheduler payload type mismatch");
    }
    if payload[2] != scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE {
        return Err("temporal scheduler event unsupported");
    }
    if payload[3] != TEMPORAL_SCHEDULER_SCHEMA_V1 {
        return Err("temporal scheduler schema unsupported");
    }

    let max_processes =
        scheduler_read_u16(payload, 4).ok_or("temporal scheduler max process missing")? as usize;
    let max_wait =
        scheduler_read_u16(payload, 6).ok_or("temporal scheduler max wait missing")? as usize;
    if max_processes != MAX_PROCESSES || max_wait != MAX_WAIT_QUEUES {
        return Err("temporal scheduler shape mismatch");
    }

    let process_count =
        scheduler_read_u16(payload, 8).ok_or("temporal scheduler process count missing")? as usize;
    let wait_queue_count = scheduler_read_u16(payload, 10)
        .ok_or("temporal scheduler wait queue count missing")? as usize;
    if process_count > MAX_PROCESSES || wait_queue_count > MAX_WAIT_QUEUES {
        return Err("temporal scheduler count out of range");
    }

    let current_pid_raw =
        scheduler_read_u32(payload, 12).ok_or("temporal scheduler current pid missing")?;
    let ready0_len =
        scheduler_read_u32(payload, 16).ok_or("temporal scheduler q0 len missing")? as usize;
    let ready1_len =
        scheduler_read_u32(payload, 20).ok_or("temporal scheduler q1 len missing")? as usize;
    let ready2_len =
        scheduler_read_u32(payload, 24).ok_or("temporal scheduler q2 len missing")? as usize;

    let stats_total_switches =
        scheduler_read_u64(payload, 28).ok_or("temporal scheduler stats switches missing")?;
    let stats_preemptions =
        scheduler_read_u64(payload, 36).ok_or("temporal scheduler stats preemptions missing")?;
    let stats_voluntary =
        scheduler_read_u64(payload, 44).ok_or("temporal scheduler stats voluntary missing")?;
    let stats_idle =
        scheduler_read_u64(payload, 52).ok_or("temporal scheduler stats idle missing")?;

    #[derive(Clone, Copy)]
    struct ProcessUpdate {
        pid: u32,
        state: ProcessState,
        priority: ProcessPriority,
        quantum_remaining: u32,
        total_cpu_time: u64,
        total_wait_time: u64,
        last_scheduled: u64,
        switches: u64,
    }

    #[derive(Clone)]
    struct WaitQueueUpdate {
        addr: usize,
        active: bool,
        wake_time: u64,
        waiting: Vec<u32>,
    }

    let mut offset = TEMPORAL_SCHEDULER_HEADER_BYTES;
    let mut process_updates = Vec::with_capacity(process_count);
    let mut i = 0usize;
    while i < process_count {
        if offset.saturating_add(TEMPORAL_SCHEDULER_PROCESS_ENTRY_BYTES) > payload.len() {
            return Err("temporal scheduler process entry truncated");
        }
        let pid =
            scheduler_read_u32(payload, offset).ok_or("temporal scheduler process pid missing")?;
        let state = scheduler_process_state_from_u8(payload[offset + 4])
            .ok_or("temporal scheduler process state invalid")?;
        let priority = scheduler_priority_from_u8(payload[offset + 5])
            .ok_or("temporal scheduler process priority invalid")?;
        let quantum_remaining = scheduler_read_u32(payload, offset + 8)
            .ok_or("temporal scheduler process quantum missing")?;
        let total_cpu_time = scheduler_read_u64(payload, offset + 12)
            .ok_or("temporal scheduler process cpu missing")?;
        let total_wait_time = scheduler_read_u64(payload, offset + 20)
            .ok_or("temporal scheduler process wait missing")?;
        let last_scheduled = scheduler_read_u64(payload, offset + 28)
            .ok_or("temporal scheduler process last scheduled missing")?;
        let switches = scheduler_read_u64(payload, offset + 36)
            .ok_or("temporal scheduler process switches missing")?;
        process_updates.push(ProcessUpdate {
            pid,
            state,
            priority,
            quantum_remaining,
            total_cpu_time,
            total_wait_time,
            last_scheduled,
            switches,
        });
        offset += TEMPORAL_SCHEDULER_PROCESS_ENTRY_BYTES;
        i += 1;
    }

    let mut ready0 = Vec::with_capacity(ready0_len);
    let mut i = 0usize;
    while i < ready0_len {
        let pid = scheduler_read_u32(payload, offset).ok_or("temporal scheduler q0 pid missing")?;
        ready0.push(pid);
        offset = offset.saturating_add(4);
        i += 1;
    }

    let mut ready1 = Vec::with_capacity(ready1_len);
    let mut i = 0usize;
    while i < ready1_len {
        let pid = scheduler_read_u32(payload, offset).ok_or("temporal scheduler q1 pid missing")?;
        ready1.push(pid);
        offset = offset.saturating_add(4);
        i += 1;
    }

    let mut ready2 = Vec::with_capacity(ready2_len);
    let mut i = 0usize;
    while i < ready2_len {
        let pid = scheduler_read_u32(payload, offset).ok_or("temporal scheduler q2 pid missing")?;
        ready2.push(pid);
        offset = offset.saturating_add(4);
        i += 1;
    }

    let mut wait_updates = Vec::with_capacity(wait_queue_count);
    let mut i = 0usize;
    while i < wait_queue_count {
        if offset.saturating_add(TEMPORAL_SCHEDULER_WAIT_QUEUE_HEADER_BYTES) > payload.len() {
            return Err("temporal scheduler wait queue truncated");
        }
        let addr =
            scheduler_read_u64(payload, offset).ok_or("temporal scheduler wait addr missing")?;
        let active = payload[offset + 8] != 0;
        let waiting_len = scheduler_read_u16(payload, offset + 10)
            .ok_or("temporal scheduler wait len missing")? as usize;
        offset += TEMPORAL_SCHEDULER_WAIT_QUEUE_HEADER_BYTES;
        let mut waiting = Vec::with_capacity(waiting_len);
        let mut j = 0usize;
        while j < waiting_len {
            let pid =
                scheduler_read_u32(payload, offset).ok_or("temporal scheduler wait pid missing")?;
            waiting.push(pid);
            offset = offset.saturating_add(4);
            j += 1;
        }
        wait_updates.push(WaitQueueUpdate {
            addr: addr as usize,
            active,
            wake_time: 0,
            waiting,
        });
        i += 1;
    }

    if offset != payload.len() {
        return Err("temporal scheduler payload trailing bytes");
    }

    let mut sched = QUANTUM_SCHEDULER.lock();
    sched.ready_queues[0].clear();
    sched.ready_queues[1].clear();
    sched.ready_queues[2].clear();
    let mut i = 0usize;
    while i < MAX_WAIT_QUEUES {
        sched.wait_queues[i] = WaitQueue::default();
        i += 1;
    }

    let mut i = 0usize;
    while i < process_updates.len() {
        let update = process_updates[i];
        let idx = update.pid as usize;
        if idx < MAX_PROCESSES {
            if let Some(info) = sched.processes[idx].as_mut() {
                info.process.state = update.state;
                info.process.priority = update.priority;
                info.quantum_remaining = update.quantum_remaining;
                info.total_cpu_time = update.total_cpu_time;
                info.total_wait_time = update.total_wait_time;
                info.last_scheduled = update.last_scheduled;
                info.switches = update.switches;
            }
        }
        i += 1;
    }

    for pid in ready0.into_iter() {
        let idx = pid as usize;
        if idx < MAX_PROCESSES && sched.processes[idx].is_some() {
            let _ = sched.ready_queues[0].push_back(Pid(pid));
        }
    }
    for pid in ready1.into_iter() {
        let idx = pid as usize;
        if idx < MAX_PROCESSES && sched.processes[idx].is_some() {
            let _ = sched.ready_queues[1].push_back(Pid(pid));
        }
    }
    for pid in ready2.into_iter() {
        let idx = pid as usize;
        if idx < MAX_PROCESSES && sched.processes[idx].is_some() {
            let _ = sched.ready_queues[2].push_back(Pid(pid));
        }
    }

    sched.wait_queue_count = wait_updates.len();
    let mut i = 0usize;
    while i < wait_updates.len() {
        let wait = &wait_updates[i];
        let mut queue = WaitQueue {
            addr: wait.addr,
            waiting: VecDeque::new(),
            active: wait.active,
            wake_time: wait.wake_time,
        };
        let mut j = 0usize;
        while j < wait.waiting.len() {
            let pid = wait.waiting[j];
            let idx = pid as usize;
            if idx < MAX_PROCESSES && sched.processes[idx].is_some() {
                queue.waiting.push_back(Pid(pid));
            }
            j += 1;
        }
        if queue.waiting.is_empty() {
            queue.active = false;
        }
        sched.wait_queues[i] = queue;
        i += 1;
    }

    sched.current_pid = if current_pid_raw == u32::MAX {
        None
    } else {
        let idx = current_pid_raw as usize;
        if idx < MAX_PROCESSES && sched.processes[idx].is_some() {
            Some(Pid(current_pid_raw))
        } else {
            None
        }
    };

    sched.stats = SchedulerStats {
        total_switches: stats_total_switches,
        preemptions: stats_preemptions,
        voluntary_yields: stats_voluntary,
        idle_ticks: stats_idle,
    };

    Ok(())
}

/// Kernel stack bounds for diagnostics (start, end) for each kernel thread stack.
pub fn kernel_stack_bounds() -> [(usize, usize); 2] {
    unsafe {
        let s0 = KERNEL_STACK_0.data.as_ptr() as usize;
        let e0 = s0 + KERNEL_STACK_0.data.len();
        let s1 = KERNEL_STACK_1.data.as_ptr() as usize;
        let e1 = s1 + KERNEL_STACK_1.data.len();
        [(s0, e0), (s1, e1)]
    }
}

/// Timer tick handler (called from PIT interrupt)
pub fn on_timer_tick() {
    if let Some(mut sched) = QUANTUM_SCHEDULER.try_lock() {
        let now = scheduler_platform::ticks_now();
        let _ = sched.wake_expired_sleepers(now);
    }
    // IRQ context: only mark that a reschedule is needed.
    RESCHED_REQUEST.store(true, Ordering::Release);
}

/// Block the current process until `wake_time` and switch away immediately.
pub fn sleep_until(pid: Pid, wake_time: u64) -> Result<(), &'static str> {
    let flags = unsafe { scheduler_platform::irq_save_disable() };
    let (result, next_runtime_pid) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let result = sched.block_process(pid, wake_time);
        let next_runtime_pid = sched.current_runtime_pid_raw();
        (result, next_runtime_pid)
    };
    match result {
        Ok(Some((from_ptr, to_ptr))) => {
            if let Some(pid_raw) = next_runtime_pid {
                scheduler_platform::runtime_pid_sync(pid_raw);
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                let mut cr0: u32;
                core::arch::asm!("mov {0}, cr0", out(reg) cr0);
                cr0 |= 8;
                core::arch::asm!("mov cr0, {0}", in(reg) cr0);
            }
            unsafe {
                scheduler_platform::switch_context(from_ptr, to_ptr);
            }
            unsafe { scheduler_platform::irq_restore(flags) };
            Ok(())
        }
        Ok(None) => {
            unsafe { scheduler_platform::irq_restore(flags) };
            Ok(())
        }
        Err(e) => {
            unsafe { scheduler_platform::irq_restore(flags) };
            Err(e)
        }
    }
}

/// Yield current process
pub fn yield_now() {
    let flags = unsafe { scheduler_platform::irq_save_disable() };
    RESCHED_REQUEST.store(false, Ordering::Release);
    let (switch, next_runtime_pid) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let switch = sched.yield_cpu();
        let next_runtime_pid = sched.current_runtime_pid_raw();
        (switch, next_runtime_pid)
    };
    if let Some((from_ptr, to_ptr)) = switch {
        if let Some(pid_raw) = next_runtime_pid {
            scheduler_platform::runtime_pid_sync(pid_raw);
        }
        // Set Task Switched (TS) bit in CR0 to enable lazy FPU context saving
        #[cfg(target_arch = "x86")]
        unsafe {
            let mut cr0: u32;
            core::arch::asm!("mov {0}, cr0", out(reg) cr0);
            cr0 |= 8; // Set TS bit
            core::arch::asm!("mov cr0, {0}", in(reg) cr0);
        }
        unsafe {
            scheduler_platform::switch_context(from_ptr, to_ptr);
        }
        // When this thread is resumed, restore its original interrupt state.
        unsafe { scheduler_platform::irq_restore(flags) };
    } else {
        unsafe { scheduler_platform::irq_restore(flags) };
    }
}

/// Block on address (futex-like)
pub fn block_on(addr: usize) -> Result<(), &'static str> {
    let flags = unsafe { scheduler_platform::irq_save_disable() };
    let (result, next_runtime_pid) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let result = sched.block_on(addr);
        let next_runtime_pid = sched.current_runtime_pid_raw();
        (result, next_runtime_pid)
    };
    match result {
        Ok(Some((from_ptr, to_ptr))) => {
            if let Some(pid_raw) = next_runtime_pid {
                scheduler_platform::runtime_pid_sync(pid_raw);
            }
            // Set Task Switched (TS) bit in CR0 to enable lazy FPU context saving
            #[cfg(target_arch = "x86")]
            unsafe {
                let mut cr0: u32;
                core::arch::asm!("mov {0}, cr0", out(reg) cr0);
                cr0 |= 8; // Set TS bit
                core::arch::asm!("mov cr0, {0}", in(reg) cr0);
            }
            unsafe {
                scheduler_platform::switch_context(from_ptr, to_ptr);
            }
            // When this thread is resumed, restore its original interrupt state.
            unsafe { scheduler_platform::irq_restore(flags) };
            Ok(())
        }
        Ok(None) => {
            unsafe { scheduler_platform::irq_restore(flags) };
            Ok(())
        }
        Err(e) => {
            unsafe { scheduler_platform::irq_restore(flags) };
            Err(e)
        }
    }
}

/// Wake one waiter on address
pub fn wake_one(addr: usize) -> Result<bool, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_one(addr)
}

/// Wake all waiters on address
pub fn wake_all(addr: usize) -> Result<usize, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_all(addr)
}

/// Global hook for Device Not Available (FPU) trap
pub fn handle_fpu_trap() {
    unsafe {
        QUANTUM_SCHEDULER.lock().handle_fpu_trap();
    }
}
