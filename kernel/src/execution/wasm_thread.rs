//! WASM Thread Infrastructure for Oreulia
//!
//! This module implements the WebAssembly Threads proposal thread model for
//! the Oreulia kernel. It provides:
//!
//! - `SharedLinearMemory` — an Arc-like wrapper around a raw WASM linear
//!   memory region that can be shared between multiple `WasmInstance`s.
//! - `WasmThread` — a lightweight execution context (stack + locals + PC)
//!   that runs inside a `WasmInstance` and shares memory with its siblings.
//! - `WasmThreadPool` — a fixed-capacity pool (up to `MAX_WASM_THREADS`)
//!   that manages thread lifecycle (spawn, join, detach).
//! - `WasmThreadHandle` — an opaque i32 identifier returned to WASM code.
//!
//! ## Design notes
//!
//! On bare-metal no_std with a spin-based allocator there are no OS threads.
//! Each `WasmThread` is cooperative: it runs to the next yield-point or host
//! call, then hands control back to the thread pool's `run_one_step` method.
//! The kernel quantum scheduler calls `WasmRuntime::tick_threads()` once per
//! timer interrupt to advance the pool.
//!
//! Thread-safe shared memory uses the atomic primitives already implemented on
//! `LinearMemory` (the `shared` flag + fence-based loads/stores).  Multiple
//! threads **share a single `SharedLinearMemory`** through a raw pointer held
//! inside each `WasmThread` — safe because:
//!   1. All threads inside a pool run on a single kernel thread (cooperative).
//!   2. The pool's `Mutex<WasmThreadPool>` serialises all access.
//!
//! ## Host functions exposed to WASM
//!
//! | ID | Name                        | Signature (WASM)                      |
//! |----|-----------------------------|---------------------------------------|
//! | 23 | `oreulia_thread_spawn`      | `(func_idx: i32, arg: i32) -> i32`    |
//! | 24 | `oreulia_thread_join`       | `(tid: i32) -> i32`                   |
//! | 25 | `oreulia_thread_id`         | `() -> i32`                           |
//! | 26 | `oreulia_thread_yield`      | `() -> ()`                            |
//! | 27 | `oreulia_thread_exit`       | `(code: i32) -> ()`                   |
//!
//! These IDs follow directly after the 22 existing host functions in wasm.rs.

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::wasm::{ControlFrame, Stack, Value, MAX_CONTROL_STACK, MAX_LOCALS};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of WASM threads per pool (all pools share this limit).
pub const MAX_WASM_THREADS: usize = 32;

/// Maximum value stack depth per thread.
pub const THREAD_STACK_DEPTH: usize = 1024;

/// Maximum local variable slots per thread.
pub const THREAD_MAX_LOCALS: usize = 256;

/// Sentinel thread id meaning "no thread" / "join already done".
pub const WASM_THREAD_NONE: i32 = -1;

// ---------------------------------------------------------------------------
// SharedLinearMemory
// ---------------------------------------------------------------------------

/// A raw pointer wrapper that lets multiple `WasmThread`s point at the same
/// `LinearMemory` allocation.  We never deallocate through this pointer — the
/// owning `WasmInstance` owns the `LinearMemory` struct and its pages; the
/// threads only borrow them for their lifetime.
///
/// Safety invariant: the owning `WasmInstance` must outlive every thread in
/// its pool.
#[repr(C)]
pub struct SharedLinearMemory {
    /// Pointer to the raw byte region managed by `LinearMemory`.
    pub base: *mut u8,
    /// Currently active bytes (pages * 64 KiB).
    pub active_bytes: usize,
    /// Maximum bytes allowed.
    pub max_bytes: usize,
}

// SAFETY: all access is serialised by the pool's Mutex.
unsafe impl Send for SharedLinearMemory {}
unsafe impl Sync for SharedLinearMemory {}

impl SharedLinearMemory {
    /// Construct from an already-allocated `LinearMemory`.
    pub const fn zeroed() -> Self {
        SharedLinearMemory {
            base: core::ptr::null_mut(),
            active_bytes: 0,
            max_bytes: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.base.is_null()
    }

    /// Read `len` bytes from `offset` into `dst`.
    pub fn read(&self, offset: usize, len: usize, dst: &mut [u8]) -> bool {
        if offset.saturating_add(len) > self.active_bytes || len > dst.len() {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(self.base.add(offset), dst.as_mut_ptr(), len);
        }
        true
    }

    /// Write `src` bytes to `offset`.
    pub fn write(&mut self, offset: usize, src: &[u8]) -> bool {
        if offset.saturating_add(src.len()) > self.active_bytes {
            return false;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), self.base.add(offset), src.len());
        }
        true
    }

    /// Read a little-endian i32 from shared memory.
    pub fn read_i32(&self, offset: usize) -> Option<i32> {
        if offset.saturating_add(4) > self.active_bytes {
            return None;
        }
        let mut buf = [0u8; 4];
        self.read(offset, 4, &mut buf);
        Some(i32::from_le_bytes(buf))
    }
}

// ---------------------------------------------------------------------------
// Thread State
// ---------------------------------------------------------------------------

/// Execution state of a `WasmThread`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreadState {
    /// Available slot — no thread.
    Empty,
    /// Thread is ready to run (never blocked).
    Runnable,
    /// Thread is waiting for another thread to finish.
    Joining(i32 /* target tid */),
    /// Thread has finished; exit code stored, not yet reaped.
    Finished(i32 /* exit_code */),
    /// Thread voluntarily yielded; will be rescheduled next tick.
    Yielded,
}

// ---------------------------------------------------------------------------
// Value type (mirrored subset of wasm.rs `Value`)
// ---------------------------------------------------------------------------
//
// We cannot import `wasm::Value` directly without a circular dependency, so
// we define a minimal shadow type here.  The pool interface converts between
// them when spawning threads.

/// A WASM value (i32 / i64 / f32 / f64).
#[derive(Clone, Copy, Debug)]
pub enum ThreadValue {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
}

impl Default for ThreadValue {
    fn default() -> Self {
        ThreadValue::I32(0)
    }
}

impl ThreadValue {
    pub fn as_i32(self) -> Option<i32> {
        match self {
            ThreadValue::I32(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_i64(self) -> Option<i64> {
        match self {
            ThreadValue::I64(v) => Some(v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// WasmThread
// ---------------------------------------------------------------------------

/// A single cooperative WASM execution context.
pub struct WasmThread {
    /// Unique ID within the pool (also the handle returned to WASM).
    pub tid: i32,
    /// Module-level function index this thread starts at.
    pub func_idx: u32,
    /// Single argument passed to the thread entry function.
    pub arg: i32,
    /// Whether the entry function has started executing.
    pub(crate) started: bool,
    /// Value stack.
    pub stack: [ThreadValue; THREAD_STACK_DEPTH],
    pub stack_top: usize,
    /// Local variable slots.
    pub locals: [ThreadValue; THREAD_MAX_LOCALS],
    /// Program counter inside the WASM bytecode.
    pub pc: usize,
    /// Call-return stack (function indices + return PCs).
    pub call_stack: [ThreadCallFrame; 64],
    pub call_stack_depth: usize,
    /// Current state.
    pub state: ThreadState,
    /// Instruction budget remaining for this scheduling quantum.
    pub fuel: u32,
    /// Cumulative instructions executed.
    pub total_instructions: u64,
    /// Exit code (set when state = Finished).
    pub exit_code: i32,
    /// Full interpreter stack snapshot for resumable execution.
    pub(crate) exec_stack: Stack,
    /// Full interpreter locals snapshot for resumable execution.
    pub(crate) exec_locals: [Value; MAX_LOCALS],
    /// Structured control frames active for this thread.
    pub(crate) exec_control_stack: [Option<ControlFrame>; MAX_CONTROL_STACK],
    /// Depth of `exec_control_stack`.
    pub(crate) exec_control_depth: usize,
    /// End bound for the current function body.
    pub(crate) current_func_end: usize,
    /// Nested call depth while this thread is executing.
    pub(crate) call_depth: usize,
    /// Pointer to the shared linear memory for this pool.
    pub shared_mem: *mut SharedLinearMemory,
}

/// A saved call frame for thread context switching.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadCallFrame {
    /// Function index.
    pub func_idx: u32,
    /// Return address (byte offset into bytecode).
    pub return_pc: usize,
    /// Stack depth at call site (for stack unwinding).
    pub saved_stack_top: usize,
}

// SAFETY: pool mutex serialises all access.
unsafe impl Send for WasmThread {}

impl WasmThread {
    /// Create a new, empty (not yet running) thread slot.
    pub const fn empty() -> Self {
        WasmThread {
            tid: WASM_THREAD_NONE,
            func_idx: 0,
            arg: 0,
            started: false,
            stack: [ThreadValue::I32(0); THREAD_STACK_DEPTH],
            stack_top: 0,
            locals: [ThreadValue::I32(0); THREAD_MAX_LOCALS],
            pc: 0,
            call_stack: [ThreadCallFrame {
                func_idx: 0,
                return_pc: 0,
                saved_stack_top: 0,
            }; 64],
            call_stack_depth: 0,
            state: ThreadState::Empty,
            fuel: 0,
            total_instructions: 0,
            exit_code: 0,
            exec_stack: Stack::new(),
            exec_locals: [Value::I32(0); MAX_LOCALS],
            exec_control_stack: [None; MAX_CONTROL_STACK],
            exec_control_depth: 0,
            current_func_end: 0,
            call_depth: 0,
            shared_mem: core::ptr::null_mut(),
        }
    }

    /// Returns true if this slot is in use.
    pub fn is_live(&self) -> bool {
        !matches!(self.state, ThreadState::Empty)
    }

    /// Returns true if this thread can be scheduled right now.
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, ThreadState::Runnable | ThreadState::Yielded)
    }

    /// Push a value onto the thread's value stack.
    pub fn push(&mut self, v: ThreadValue) -> Result<(), &'static str> {
        if self.stack_top >= THREAD_STACK_DEPTH {
            return Err("thread stack overflow");
        }
        self.stack[self.stack_top] = v;
        self.stack_top += 1;
        Ok(())
    }

    /// Pop a value from the thread's value stack.
    pub fn pop(&mut self) -> Result<ThreadValue, &'static str> {
        if self.stack_top == 0 {
            return Err("thread stack underflow");
        }
        self.stack_top -= 1;
        Ok(self.stack[self.stack_top])
    }

    /// Peek at the top of the stack without popping.
    pub fn peek(&self) -> Option<ThreadValue> {
        if self.stack_top == 0 {
            None
        } else {
            Some(self.stack[self.stack_top - 1])
        }
    }

    /// Set a local variable.
    pub fn set_local(&mut self, idx: usize, v: ThreadValue) -> Result<(), &'static str> {
        if idx >= THREAD_MAX_LOCALS {
            return Err("local index out of range");
        }
        self.locals[idx] = v;
        Ok(())
    }

    /// Get a local variable.
    pub fn get_local(&self, idx: usize) -> Result<ThreadValue, &'static str> {
        if idx >= THREAD_MAX_LOCALS {
            return Err("local index out of range");
        }
        Ok(self.locals[idx])
    }

    /// Mark the thread as finished with the given exit code.
    pub fn finish(&mut self, code: i32) {
        self.exit_code = code;
        self.state = ThreadState::Finished(code);
    }

    /// Yield execution — will be rescheduled next tick.
    pub fn yield_now(&mut self) {
        self.state = ThreadState::Yielded;
    }

    /// Instructions consumed this quantum.
    pub fn consume_fuel(&mut self, n: u32) -> bool {
        if self.fuel < n {
            self.fuel = 0;
            return false;
        }
        self.fuel -= n;
        self.total_instructions += n as u64;
        true
    }
}

// ---------------------------------------------------------------------------
// WasmThreadPool
// ---------------------------------------------------------------------------

/// Default instruction budget per thread per scheduler tick.
pub const DEFAULT_THREAD_FUEL: u32 = 10_000;

/// Result of one scheduling step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolStepResult {
    /// A thread ran for one quantum.
    Ran(i32 /* tid */),
    /// All runnable threads are exhausted for this tick.
    Idle,
    /// No threads exist.
    Empty,
}

/// A cooperative thread pool for WASM instances sharing linear memory.
pub struct WasmThreadPool {
    /// Thread slots.
    threads: Option<Box<[WasmThread; MAX_WASM_THREADS]>>,
    /// Number of live (non-Empty) threads.
    live_count: usize,
    /// Round-robin scheduling cursor.
    rr_cursor: usize,
    /// Monotonic thread ID counter.
    next_tid: u32,
    /// Shared linear memory region (borrowed from the owning WasmInstance).
    shared_mem: SharedLinearMemory,
    /// Whether the pool has been initialised.
    initialized: bool,
}

// SAFETY: Mutex<WasmThreadPool> is the synchronisation primitive.
unsafe impl Send for WasmThreadPool {}
unsafe impl Sync for WasmThreadPool {}

impl WasmThreadPool {
    /// Create an empty pool.
    pub const fn new() -> Self {
        WasmThreadPool {
            threads: None,
            live_count: 0,
            rr_cursor: 0,
            next_tid: 1, // tid 0 is reserved (means "main/no thread")
            shared_mem: SharedLinearMemory::zeroed(),
            initialized: false,
        }
    }

    fn ensure_threads(&mut self) -> &mut [WasmThread; MAX_WASM_THREADS] {
        if self.threads.is_none() {
            const EMPTY_THREAD: WasmThread = WasmThread::empty();
            self.threads = Some(Box::new([EMPTY_THREAD; MAX_WASM_THREADS]));
        }
        self.threads
            .as_mut()
            .map(Box::as_mut)
            .expect("lazy wasm thread pool allocation failed")
    }

    fn threads(&self) -> Option<&[WasmThread; MAX_WASM_THREADS]> {
        self.threads.as_ref().map(Box::as_ref)
    }

    fn threads_mut(&mut self) -> Option<&mut [WasmThread; MAX_WASM_THREADS]> {
        self.threads.as_mut().map(Box::as_mut)
    }

    /// Attach a linear memory region from the owning `WasmInstance`.
    /// Must be called before spawning any threads.
    pub fn attach_memory(&mut self, base: *mut u8, active_bytes: usize, max_bytes: usize) {
        self.shared_mem.base = base;
        self.shared_mem.active_bytes = active_bytes;
        self.shared_mem.max_bytes = max_bytes;
        self.initialized = true;
    }

    /// Returns true if a linear memory region has been attached to this pool.
    pub fn is_memory_attached(&self) -> bool {
        self.initialized && self.shared_mem.is_valid()
    }

    /// Update the active byte count (called when the WASM module executes
    /// `memory.grow`).
    pub fn notify_grow(&mut self, new_active_bytes: usize) {
        self.shared_mem.active_bytes = new_active_bytes;
        let shared_mem_ptr = &mut self.shared_mem as *mut SharedLinearMemory;
        // Update every live thread's shared_mem pointer (they all point into
        // the same SharedLinearMemory so updating self is enough, but refresh
        // the pointer in each thread for clarity).
        if let Some(threads) = self.threads_mut() {
            for t in threads.iter_mut() {
                if t.is_live() {
                    t.shared_mem = shared_mem_ptr;
                }
            }
        }
    }

    /// Spawn a new thread starting at `func_idx` with argument `arg`.
    /// Returns the new thread's tid, or an error.
    pub fn spawn(
        &mut self,
        func_idx: u32,
        arg: i32,
        initial_pc: usize,
    ) -> Result<i32, &'static str> {
        if !self.initialized {
            return Err("pool not initialized");
        }
        if self.live_count >= MAX_WASM_THREADS {
            return Err("thread limit reached");
        }
        let tid = self.next_tid as i32;
        self.next_tid = self.next_tid.wrapping_add(1);
        if self.next_tid == 0 {
            self.next_tid = 1;
        }
        let shared_mem_ptr = &mut self.shared_mem as *mut SharedLinearMemory;
        let threads = self.ensure_threads();
        // Find an empty slot.
        let slot = threads
            .iter()
            .position(|t| matches!(t.state, ThreadState::Empty))
            .ok_or("no empty thread slot")?;

        let t = &mut threads[slot];
        *t = WasmThread::empty();
        t.tid = tid;
        t.func_idx = func_idx;
        t.arg = arg;
        t.started = false;
        t.pc = initial_pc;
        t.state = ThreadState::Runnable;
        t.fuel = DEFAULT_THREAD_FUEL;
        t.shared_mem = shared_mem_ptr;
        // Set arg in locals[0] so the entry function can access it.
        t.locals[0] = ThreadValue::I32(arg);
        t.locals[1] = ThreadValue::I32(tid); // tid in locals[1] for convenience

        self.live_count += 1;
        Ok(tid)
    }

    /// Join a thread: if the target is Finished, return its exit code and reap
    /// the slot.  If it is still running, place the caller in Joining state.
    pub fn join(&mut self, caller_tid: i32, target_tid: i32) -> JoinResult {
        let Some(threads) = self.threads_mut() else {
            return JoinResult::NotFound;
        };
        let target_slot = threads.iter().position(|t| t.tid == target_tid);
        match target_slot {
            None => JoinResult::NotFound,
            Some(idx) => match threads[idx].state {
                ThreadState::Finished(code) => {
                    // Reap the finished thread.
                    threads[idx].state = ThreadState::Empty;
                    self.live_count = self.live_count.saturating_sub(1);
                    JoinResult::Done(code)
                }
                ThreadState::Empty => JoinResult::NotFound,
                _ => {
                    // Mark caller as blocked on target.
                    if let Some(caller_idx) = threads.iter().position(|t| t.tid == caller_tid) {
                        threads[caller_idx].state = ThreadState::Joining(target_tid);
                    }
                    JoinResult::Blocked
                }
            },
        }
    }

    /// Called when a thread exits — unblocks any thread that was joining it.
    fn wake_joiners(&mut self, finished_tid: i32) {
        if let Some(threads) = self.threads_mut() {
            for t in threads.iter_mut() {
                if matches!(t.state, ThreadState::Joining(tid) if tid == finished_tid) {
                    t.state = ThreadState::Runnable;
                    t.fuel = DEFAULT_THREAD_FUEL;
                }
            }
        }
    }

    /// Mark a thread as finished with the given exit code.
    pub fn exit_thread(&mut self, tid: i32, code: i32) {
        if let Some(threads) = self.threads_mut() {
            if let Some(idx) = threads.iter().position(|t| t.tid == tid) {
                threads[idx].finish(code);
            }
            self.wake_joiners(tid);
        }
    }

    /// Advance per-thread timer state without executing bytecode.
    pub fn on_timer_tick(&mut self) {
        if let Some(threads) = self.threads_mut() {
            for thread in threads.iter_mut() {
                if matches!(thread.state, ThreadState::Yielded) {
                    thread.state = ThreadState::Runnable;
                    thread.fuel = DEFAULT_THREAD_FUEL;
                }
            }
        }
        self.gc_finished();
    }

    /// Return the current thread fuel for inspection.
    pub fn thread_fuel(&self, tid: i32) -> Option<u32> {
        self.threads()?
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.fuel)
    }

    /// Advance the round-robin cursor and return a mutable reference to the
    /// next runnable thread.  Returns `PoolStepResult::Empty` if no threads
    /// exist, `PoolStepResult::Idle` if all are blocked/finished.
    ///
    /// The actual instruction execution is delegated back to the caller
    /// (the `WasmInstance`) which has access to the module bytecode.
    /// This method only selects the thread and refills its fuel.
    pub fn next_runnable(&mut self) -> Option<&mut WasmThread> {
        if self.live_count == 0 {
            return None;
        }
        // Phase 1: find a runnable slot index (read-only scan).
        let mut found_idx = None;
        for _ in 0..MAX_WASM_THREADS {
            self.rr_cursor = (self.rr_cursor + 1) % MAX_WASM_THREADS;
            if self.threads()?.get(self.rr_cursor)?.is_runnable() {
                found_idx = Some(self.rr_cursor);
                break;
            }
        }
        // Phase 2: mutably access the chosen slot.
        let idx = found_idx?;
        let threads = self.threads_mut()?;
        let t = &mut threads[idx];
        if matches!(t.state, ThreadState::Yielded) {
            t.state = ThreadState::Runnable;
        }
        t.fuel = DEFAULT_THREAD_FUEL;
        Some(t)
    }

    /// Remove the next runnable thread from the pool so the owning instance
    /// can execute it without aliasing `self`.
    pub fn take_next_runnable(&mut self) -> Option<(usize, WasmThread)> {
        if self.live_count == 0 {
            return None;
        }
        let mut found_idx = None;
        for _ in 0..MAX_WASM_THREADS {
            self.rr_cursor = (self.rr_cursor + 1) % MAX_WASM_THREADS;
            if matches!(
                self.threads()?.get(self.rr_cursor)?.state,
                ThreadState::Runnable
            ) {
                found_idx = Some(self.rr_cursor);
                break;
            }
        }
        let idx = found_idx?;
        let threads = self.threads_mut()?;
        let thread = core::mem::replace(&mut threads[idx], WasmThread::empty());
        Some((idx, thread))
    }

    /// Restore a thread into its original slot after execution.
    pub fn restore_thread_slot(
        &mut self,
        slot_idx: usize,
        thread: WasmThread,
    ) -> Result<(), &'static str> {
        let Some(threads) = self.threads_mut() else {
            return Err("thread pool storage not allocated");
        };
        if slot_idx >= threads.len() {
            return Err("invalid thread slot");
        }
        threads[slot_idx] = thread;
        Ok(())
    }

    /// Immutable look-up of a thread by tid.
    pub fn get(&self, tid: i32) -> Option<&WasmThread> {
        self.threads()?.iter().find(|t| t.tid == tid)
    }

    /// Mutable look-up of a thread by tid.
    pub fn get_mut(&mut self, tid: i32) -> Option<&mut WasmThread> {
        self.threads_mut()?.iter_mut().find(|t| t.tid == tid)
    }

    /// Number of live threads.
    pub fn live_count(&self) -> usize {
        self.live_count
    }

    /// Total threads ever created (approximately).
    pub fn total_spawned(&self) -> u32 {
        self.next_tid.wrapping_sub(1)
    }

    /// Detach a thread — it will free its slot when it finishes, without
    /// requiring a join.
    pub fn detach(&mut self, tid: i32) {
        // For detached threads we simply allow them to run to completion and
        // self-reap.  We mark them with a special exit that auto-cleans up.
        // Currently this is a no-op because exit_thread already reaps via
        // wake_joiners; a detached thread that finishes will just leave a
        // Finished slot until the pool GC pass.
        let _ = tid; // future: set a detached flag
    }

    /// Garbage-collect Finished slots that nobody is joining.
    pub fn gc_finished(&mut self) {
        // Phase 1: collect the set of tids that are currently being joined (immutable).
        let mut join_targets = [0i32; MAX_WASM_THREADS];
        let mut join_count = 0usize;
        if let Some(threads) = self.threads() {
            for t in threads.iter() {
                if let ThreadState::Joining(j) = t.state {
                    if join_count < MAX_WASM_THREADS {
                        join_targets[join_count] = j;
                        join_count += 1;
                    }
                }
            }
        }
        // Phase 2: reap Finished threads that nobody is waiting on (mutable).
        if let Some(threads) = self.threads_mut() {
            let mut reaped = 0usize;
            for t in threads.iter_mut() {
                if matches!(t.state, ThreadState::Finished(_)) {
                    let tid = t.tid;
                    let being_joined = join_targets[..join_count].iter().any(|&j| j == tid);
                    if !being_joined {
                        t.state = ThreadState::Empty;
                        reaped += 1;
                    }
                }
            }
            self.live_count = self.live_count.saturating_sub(reaped);
        }
    }

    /// Return a brief status snapshot for debugging / telemetry.
    pub fn status(&self) -> ThreadPoolStatus {
        let mut runnable = 0u32;
        let mut joining = 0u32;
        let mut finished = 0u32;
        let mut yielded = 0u32;
        if let Some(threads) = self.threads() {
            for t in threads.iter() {
                match t.state {
                    ThreadState::Runnable => runnable += 1,
                    ThreadState::Joining(_) => joining += 1,
                    ThreadState::Finished(_) => finished += 1,
                    ThreadState::Yielded => yielded += 1,
                    ThreadState::Empty => {}
                }
            }
        }
        ThreadPoolStatus {
            live: self.live_count as u32,
            runnable,
            joining,
            finished,
            yielded,
            total_spawned: self.next_tid.wrapping_sub(1),
        }
    }
}

/// A snapshot of pool health for telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadPoolStatus {
    pub live: u32,
    pub runnable: u32,
    pub joining: u32,
    pub finished: u32,
    pub yielded: u32,
    pub total_spawned: u32,
}

/// Result of a `join` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinResult {
    /// The target thread had already finished; the exit code is returned.
    Done(i32),
    /// The target thread is still running; caller is now blocked.
    Blocked,
    /// No thread with that tid exists.
    NotFound,
}

// ---------------------------------------------------------------------------
// Global pool registry
// ---------------------------------------------------------------------------
//
// Each `WasmInstance` owns a `WasmThreadPool`.  To allow cross-instance
// inspection (e.g. the kernel runtime calling `tick_all_pools`) we keep a
// global registry of active pool pointers.  The registry itself is protected
// by a `Mutex`.

/// Maximum number of concurrent thread pools (one per WasmInstance slot).
pub const MAX_THREAD_POOLS: usize = 8;

/// A raw pointer to a pool allocated inside a `WasmInstance`.
#[derive(Copy, Clone)]
struct PoolEntry {
    pool: *mut WasmThreadPool,
    instance_id: usize,
}
unsafe impl Send for PoolEntry {}

struct PoolRegistry {
    entries: [Option<PoolEntry>; MAX_THREAD_POOLS],
    count: usize,
}

static POOL_REGISTRY: Mutex<PoolRegistry> = Mutex::new(PoolRegistry {
    entries: [None; MAX_THREAD_POOLS],
    count: 0,
});

/// Register a pool pointer for a given instance slot.
///
/// # Safety
/// The pool pointer must remain valid until `unregister_pool` is called.
pub unsafe fn register_pool(instance_id: usize, pool: *mut WasmThreadPool) {
    if let Some(mut reg) = POOL_REGISTRY.try_lock() {
        for slot in reg.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(PoolEntry { pool, instance_id });
                reg.count += 1;
                return;
            }
        }
    }
}

/// Unregister a pool when its `WasmInstance` is dropped.
pub fn unregister_pool(instance_id: usize) {
    if let Some(mut reg) = POOL_REGISTRY.try_lock() {
        for slot in reg.entries.iter_mut() {
            if slot.as_ref().map(|e| e.instance_id) == Some(instance_id) {
                *slot = None;
                reg.count = reg.count.saturating_sub(1);
                return;
            }
        }
    }
}

/// Advance every registered pool by one scheduling step.
/// Called from the kernel timer interrupt via `wasm_thread::tick_all_pools()`.
pub fn tick_all_pools() {
    // We cannot block in an interrupt.  Use try_lock.
    if let Some(reg) = POOL_REGISTRY.try_lock() {
        for slot in reg.entries.iter() {
            if let Some(entry) = slot {
                // SAFETY: we only de-reference live pools (guarded by
                // unregister_pool being called on drop).
                let pool = unsafe { &mut *entry.pool };
                pool.on_timer_tick();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Atomic thread ID generator (for host function ID allocation at runtime)
// ---------------------------------------------------------------------------

static GLOBAL_THREAD_COUNTER: AtomicUsize = AtomicUsize::new(1);

/// Allocate a globally unique thread identifier.
pub fn alloc_global_tid() -> usize {
    GLOBAL_THREAD_COUNTER.fetch_add(1, Ordering::Relaxed)
}
