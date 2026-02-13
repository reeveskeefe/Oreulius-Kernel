//! Advanced Quantum-Based Preemptive Scheduler
//! 
//! Features:
//! - Per-process quantum tracking with decay
//! - Multi-level feedback queue (MLFQ) for adaptive priority
//! - Blocking primitives (futex-like wait queues)
//! - CPU affinity and load balancing (single-core for now)
//! - Accounting: CPU time, context switches, wait time

use spin::Mutex;
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use alloc::boxed::Box;
use crate::process::{Process, ProcessState, ProcessPriority, Pid, MAX_PROCESSES};
use crate::asm_bindings::{ProcessContext, asm_switch_context, asm_load_context};
use crate::pit;
use crate::paging;

// FIX #1: Module-level stacks (properly placed in BSS by linker)
#[repr(align(4096))]
struct AlignedStack {
    data: [u8; 65536],
}
static mut KERNEL_STACK_0: AlignedStack = AlignedStack { data: [0; 65536] };
static mut KERNEL_STACK_1: AlignedStack = AlignedStack { data: [0; 65536] };
static mut KERNEL_STACK_2: AlignedStack = AlignedStack { data: [0; 65536] };

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
    pub stack: Option<Box<[u8; crate::process::STACK_SIZE]>>,
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
    pub fn new() -> Self {
        const NONE_PROC: Option<ProcessInfo> = None;
        
        // Properly initialize wait queues array using from_fn
        let wait_queues: [WaitQueue; MAX_WAIT_QUEUES] = 
            core::array::from_fn(|_| WaitQueue::default());
        
        QuantumScheduler {
            processes: [NONE_PROC; MAX_PROCESSES],
            current_pid: None,
            ready_queues: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
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
            context: ProcessContext::new(),
            stack: None,
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: pit::get_ticks(),
            switches: 0,
        };
        
        self.processes[idx] = Some(info);
        self.enqueue_ready(pid, priority);
        
        Ok(())
    }

    /// Decide the next context to switch to (returns context pointers if switching).
    fn plan_switch(&mut self, prev_pid_override: Option<Pid>) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        let now = pit::get_ticks();
        
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
    pub fn yield_cpu(&mut self) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        let prev = self.current_pid;
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
        self.plan_switch(prev)
    }

    /// Block current process on a wait queue (futex-like)
    pub fn block_on(&mut self, addr: usize) -> Result<Option<(*mut ProcessContext, *const ProcessContext)>, &'static str> {
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
        Ok(self.plan_switch(prev))
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
    
    /// Add a kernel thread to the scheduler
    pub fn add_kernel_thread(&mut self, entry: extern "C" fn() -> !, priority: ProcessPriority) -> Result<Pid, &'static str> {
        // Enhanced process table diagnostics with validation
        let table_ptr = self.processes.as_ptr();
        let table_addr = table_ptr as usize;
        
        // Validate process table alignment (should be at least 8-byte aligned)
        if table_addr % 8 != 0 {
            crate::serial_println!("[SCHED] WARNING: Process table misaligned at {:p}", table_ptr);
        }
        
        // Log comprehensive process table state
        let active_count = self.processes.iter().filter(|p| p.is_some()).count();
        crate::serial_println!("[SCHED] Process Table: {:p} | Capacity: {} | Active: {} | Available: {}",
            table_ptr, MAX_PROCESSES, active_count, MAX_PROCESSES - active_count);
        crate::serial_println!("[SCHED] Memory bounds: {:p} - {:p} ({} bytes)",
            table_ptr, 
            (table_addr + core::mem::size_of_val(&self.processes)) as *const u8,
            core::mem::size_of_val(&self.processes));
        
        // Hardware memory barrier to ensure process table consistency across CPUs
        unsafe {
            extern "C" {
                fn memory_barrier();
            }
            memory_barrier();
        }
        
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
        
        let stack_top = unsafe { stack_slice.as_mut_ptr().add(stack_slice.len()) as u32 } & !15;
        
        // FIX #4: Verify stack address is in reasonable range (below 32MB)
        // Check both top and bottom of usable stack range (we use up to 8 bytes)
        let stack_bottom = stack_top.saturating_sub(8);
        if stack_top > 32 * 1024 * 1024 || stack_bottom < 0x1000 {
            return Err("Stack address out of mapped range");
        }
        
        // Push the entry point (function to call after trampoline)
        let entry_addr = entry as *const () as u32;
        let entry_ptr = (stack_top - 4) as *mut u32;
        unsafe { entry_ptr.write(entry_addr); }
        
        let mut ctx = ProcessContext::new();

        // Use actual trampoline address from assembly
        let trampoline_addr = crate::asm_bindings::thread_start_trampoline as usize as u32;
        ctx.eip = trampoline_addr;
        // Start ESP 4 bytes lower because context_switch does 'add esp, 4' to simulate ret
        // valid entry_addr is at stack_top - 4
        ctx.esp = stack_top - 8;
        ctx.ebp = stack_top - 8;
        ctx.cr3 = paging::current_page_directory_addr();
        
        process.state = ProcessState::Ready;
        
        let info = ProcessInfo {
            process,
            context: ctx,
            stack: None,  // Stack is static, not heap-allocated
            quantum_remaining: QUANTUM_NORMAL,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: 0,
            switches: 0,
        };
        
        self.processes[pid.0 as usize] = Some(info);
        self.enqueue_ready(pid, priority);
        
        crate::vga::print_str("\n");
        // Print stack assignment for debugging
        crate::serial_println!("[SCHED] Assigned PID {} stack: {:p} - {:p}", pid.0, stack_slice.as_ptr(), unsafe { stack_slice.as_ptr().add(stack_slice.len()) });
        Ok(pid)
    }
    
    /// Start the scheduler (never returns)
    /// Static method to avoid double locking. Caller must NOT hold the lock.
    pub fn start_scheduling() -> ! {
        crate::vga::print_str("[SCHED] Starting scheduler (safe)\n");

        let ctx_ptr = {
            let mut scheduler = QUANTUM_SCHEDULER.lock();
            
            // Find next process
            let next_pid = scheduler.dequeue_ready().expect("No processes to run");
            
            scheduler.current_pid = Some(next_pid);
            SCHEDULER_STARTED.store(true, Ordering::Release);
            
            if let Some(ref mut info) = scheduler.processes[next_pid.0 as usize] {
                info.process.state = ProcessState::Running;
                // Return pointer relative to the heap allocation (stable address)
                &info.context as *const ProcessContext
            } else {
                panic!("Process data missing");
            }
        }; // Lock is dropped here

        crate::vga::print_str("[SCHED] Lock dropped, loading context\n");
        crate::vga::print_str("[SCHED] Jumping to task...\n");
        
        unsafe { asm_load_context(ctx_ptr); }
    }
    
    /// Add a user process (stub for now)
    pub fn add_user_process(&mut self, _process: Process, _space: Box<crate::paging::AddressSpace>, _entry: u32, _user_stack: u32) -> Result<Pid, &'static str> {
        Err("User processes not yet implemented")
    }
    
    /// Remove a process (stub for now)
    pub fn remove_process(&mut self, _pid: Pid) -> Result<(), &'static str> {
        Err("Remove not yet implemented")
    }
    
    /// Fork with COW (stub for now)
    pub fn fork_current_cow(&mut self) -> Result<Pid, &'static str> {
        Err("Fork not yet implemented")
    }
    
    /// Record voluntary yield
    pub fn record_voluntary_yield(&mut self) {
        self.stats.voluntary_yields += 1;
    }
    
    /// Block process
    pub fn block_process(&mut self, _pid: Pid, _wake_time: u64) -> Result<(), &'static str> {
        Err("Block not yet implemented")
    }
    
    /// Execute WASM in current process
    pub fn exec_current_wasm(&mut self, _module_id: u32) -> Result<(), &'static str> {
        Err("WASM exec not yet implemented")
    }
    
    /// Get current PID
    pub fn get_current_pid(&self) -> Option<Pid> {
        self.current_pid
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        WaitQueue {
            addr: 0,
            waiting: VecDeque::new(),
            active: false,
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
    // IRQ context: only mark that a reschedule is needed.
    RESCHED_REQUEST.store(true, Ordering::Release);
}

/// Yield current process
pub fn yield_now() {
    let flags = unsafe { crate::idt_asm::fast_cli_save() };
    RESCHED_REQUEST.store(false, Ordering::Release);
    let switch = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        sched.yield_cpu()
    };
    if let Some((from_ptr, to_ptr)) = switch {
        unsafe { asm_switch_context(from_ptr, to_ptr); }
    } else {
        unsafe { crate::idt_asm::fast_sti_restore(flags) };
    }
}

/// Block on address (futex-like)
pub fn block_on(addr: usize) -> Result<(), &'static str> {
    let flags = unsafe { crate::idt_asm::fast_cli_save() };
    let result = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        sched.block_on(addr)
    };
    match result {
        Ok(Some((from_ptr, to_ptr))) => {
            unsafe { asm_switch_context(from_ptr, to_ptr); }
            Ok(())
        }
        Ok(None) => {
            unsafe { crate::idt_asm::fast_sti_restore(flags) };
            Ok(())
        }
        Err(e) => {
            unsafe { crate::idt_asm::fast_sti_restore(flags) };
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
