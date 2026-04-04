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

//! Advanced Quantum-Based Preemptive Scheduler
//!
//! Features:
//! - Per-process quantum tracking with decay
//! - Multi-level feedback queue (MLFQ) for adaptive priority
//! - Blocking primitives (futex-like wait queues)
//! - CPU affinity and load balancing (single-core for now)
//! - Accounting: CPU time, context switches, wait time

use crate::arch::mmu::PhysAddr;
use crate::process::{Pid, Process, ProcessPriority, ProcessState, MAX_PROCESSES};
use crate::scheduler_platform::{self, ProcessContext};
use crate::scheduler_runtime_platform as scheduler_rt;
use alloc::boxed::Box;
#[cfg(target_arch = "x86_64")]
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmaFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
        const USER = 1 << 3;
        const COW = 1 << 4;
        const STACK = 1 << 5;
        const GROW_DOWN = 1 << 6;
        const SHARED = 1 << 7;
    }
}

// Keep the 32-bit scheduler stacks smaller so the Multiboot image fits within
// GRUB's early allocation limits during CI boots.
#[cfg(target_arch = "x86")]
const KERNEL_THREAD_STACK_BYTES: usize = 256 * 1024;
#[cfg(not(target_arch = "x86"))]
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
static mut KERNEL_STACK_3: AlignedStack = AlignedStack {
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
const USER_MMAP_MIN_ADDR: usize = 0x1000_0000;
const ERR_PROCESS_DATA_MISSING: &str = "Process data missing";
const ERR_NO_CURRENT_PROCESS: &str = "No current process";
const ERR_SCHED_SWITCH_PREVIOUS_PROCESS_MISSING: &str = "Scheduler switch missing previous process";
const ERR_SCHED_SWITCH_NEXT_PROCESS_MISSING: &str = "Scheduler switch missing next process";
const ERR_BLOCK_ON_CURRENT_PROCESS_MISSING: &str = "block_on_with_state: current process missing";
const ERR_BLOCK_PROCESS_NO_CURRENT_PROCESS: &str = "block_process: no current process";
const ERR_BLOCK_PROCESS_CURRENT_PROCESS_MISSING: &str = "block_process: current process missing";
const ERR_BLOCK_PROCESS_PID_NOT_CURRENT: &str = "block_process: pid is not current";
const ERR_EXEC_CURRENT_WASM_NO_CURRENT_PROCESS: &str = "exec_current_wasm: no current process";
const ERR_EXEC_CURRENT_WASM_CURRENT_PROCESS_MISSING: &str =
    "exec_current_wasm: current process missing";
const ERR_READY_QUEUE_INVARIANT: &str = "ReadyQueue invariant violated";
#[cfg(target_arch = "x86")]
const KERNEL_THREAD_FRAME_BYTES: usize = 8;
#[cfg(not(target_arch = "x86"))]
const KERNEL_THREAD_FRAME_BYTES: usize = 16;

const fn priority_to_queue_idx(priority: ProcessPriority) -> usize {
    match priority {
        ProcessPriority::High => 0,
        ProcessPriority::Normal => 1,
        ProcessPriority::Low => 2,
    }
}

const fn base_quantum_for_priority(priority: ProcessPriority) -> u32 {
    match priority {
        ProcessPriority::High => QUANTUM_HIGH,
        ProcessPriority::Normal => QUANTUM_NORMAL,
        ProcessPriority::Low => QUANTUM_LOW,
    }
}

/// Compute the first byte of the bootstrap frame for a kernel thread stack.
///
/// Callers must pass an already ABI-aligned `stack_top`; this helper only
/// validates the range and derives the frame start from that aligned top.
fn kernel_thread_frame_top(
    stack_base: usize,
    stack_top: usize,
    required_bytes: usize,
) -> Result<usize, &'static str> {
    debug_assert_eq!(
        stack_top & 0xF,
        0,
        "kernel_thread_frame_top requires 16-byte aligned stack_top"
    );
    let frame_top = stack_top
        .checked_sub(required_bytes)
        .ok_or("Stack address invalid")?;
    if frame_top < stack_base || frame_top < 0x1000 {
        return Err("Stack address invalid");
    }
    Ok(frame_top)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntropyWindowState {
    ewma_yield: u32,
    ewma_fault: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyBenchResult {
    pub name: &'static str,
    pub base_quantum: u32,
    pub rolled_yield_ewma: u32,
    pub rolled_fault_ewma: u32,
    pub adjusted_quantum: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmaKind {
    Anonymous,
    Stack,
    Heap,
    File {
        source: crate::fs::vfs::MappedFileSource,
        offset: u64,
    },
    PhysicalMap { phys_start: usize },
    KernelSynthetic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vma {
    pub start: usize,
    pub end: usize,
    pub flags: VmaFlags,
    pub kind: VmaKind,
}

impl Vma {
    fn contains(&self, addr: usize) -> bool {
        self.start <= addr && addr < self.end
    }
}

#[derive(Clone, Debug)]
pub struct ProcessMemoryMap {
    pub vmas: Vec<Vma>,
    pub heap_base: usize,
    pub heap_end: usize,
    pub mmap_base: usize,
    pub mmap_cursor: usize,
    pub mmap_limit: usize,
}

#[derive(Clone, Debug)]
pub struct UserRegionSpec {
    pub start: usize,
    pub end: usize,
    pub flags: VmaFlags,
    pub kind: VmaKind,
}

#[derive(Clone, Debug)]
pub struct UserProcessLayout {
    pub regions: Vec<UserRegionSpec>,
    pub heap_base: usize,
    pub heap_end: usize,
    pub mmap_base: usize,
    pub mmap_limit: usize,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedFilePageKey {
    source: crate::fs::vfs::MappedFileSource,
    file_page_offset: usize,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedFilePageEntry {
    phys_addr: usize,
    refcount: usize,
}

// 7/8 previous value + 1/8 new sample, implemented as a cheap right shift.
// This keeps the scheduler accounting stable without any floating-point.
fn roll_entropy_signal(ewma: u32, sample: u32) -> u32 {
    ((ewma.saturating_mul(7)).saturating_add(sample)) >> 3
}

fn roll_entropy_window(
    previous: EntropyWindowState,
    yield_count: u32,
    fault_count: u32,
) -> EntropyWindowState {
    EntropyWindowState {
        ewma_yield: roll_entropy_signal(previous.ewma_yield, yield_count),
        ewma_fault: roll_entropy_signal(previous.ewma_fault, fault_count),
    }
}

/// Compute a per-process quantum adapted by Shannon entropy of its behavior.
///
/// Uses the bit-shift EWMA approximation:
///   ΔS ≈ -( ewma_yield * log2(ewma_yield+1) + ewma_fault * log2(ewma_fault+1) ) / 64
///
/// The kernel-friendly integer approximation replaces log2 with the position of the
/// highest set bit (floor(log2(x+1))), avoiding any floating-point in ring-0.
///
/// The `>> 4` scaling keeps the reward/penalty terms in the same rough range as the
/// 5/10/20 tick base quanta used by the scheduler and by `sched-entropy-bench`.
/// Values that exceed that envelope are clamped to `[QUANTUM_LOW, QUANTUM_HIGH]`
/// so tuning the EWMA inputs cannot starve or overrun the MLFQ bands.
fn compute_entropy_quantum(ewma_yield: u32, ewma_fault: u32, base: u32) -> u32 {
    let log2_yield = 31u32.saturating_sub((ewma_yield.saturating_add(1)).leading_zeros());
    let log2_fault = 31u32.saturating_sub((ewma_fault.saturating_add(1)).leading_zeros());

    let reward = ewma_yield.saturating_mul(log2_yield) >> 4;
    let penalty = ewma_fault.saturating_mul(log2_fault) >> 4;
    let adjusted = base.saturating_add(reward).saturating_sub(penalty);
    adjusted.clamp(QUANTUM_LOW, QUANTUM_HIGH)
}

fn entropy_adjusted_quantum(priority: ProcessPriority, rolled: EntropyWindowState) -> u32 {
    compute_entropy_quantum(
        rolled.ewma_yield,
        rolled.ewma_fault,
        base_quantum_for_priority(priority),
    )
}

fn entropy_bench_result(
    name: &'static str,
    priority: ProcessPriority,
    previous: EntropyWindowState,
    yield_count: u32,
    fault_count: u32,
) -> EntropyBenchResult {
    let rolled = roll_entropy_window(previous, yield_count, fault_count);
    EntropyBenchResult {
        name,
        base_quantum: base_quantum_for_priority(priority),
        rolled_yield_ewma: rolled.ewma_yield,
        rolled_fault_ewma: rolled.ewma_fault,
        adjusted_quantum: entropy_adjusted_quantum(priority, rolled),
    }
}

fn align_down_usize(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_up_usize(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(target_arch = "aarch64")]
fn scheduler_user_top() -> usize {
    0xC000_0000
}

#[cfg(not(target_arch = "aarch64"))]
fn scheduler_user_top() -> usize {
    crate::paging::USER_TOP
}

impl ProcessMemoryMap {
    pub fn new(heap_base: usize, heap_end: usize, mmap_base: usize, mmap_limit: usize) -> Self {
        Self {
            vmas: Vec::new(),
            heap_base,
            heap_end,
            mmap_base,
            mmap_cursor: mmap_base,
            mmap_limit,
        }
    }

    pub fn insert_vma(&mut self, vma: Vma) -> Result<(), &'static str> {
        if vma.start >= vma.end {
            return Err("invalid VMA range");
        }
        let mut insert_at = self.vmas.len();
        let mut i = 0usize;
        while i < self.vmas.len() {
            let existing = &self.vmas[i];
            if vma.end <= existing.start {
                insert_at = i;
                break;
            }
            if vma.start < existing.end && existing.start < vma.end {
                return Err("overlapping VMA");
            }
            i += 1;
        }
        self.vmas.insert(insert_at, vma);
        Ok(())
    }

    pub fn find_vma(&self, addr: usize) -> Option<&Vma> {
        self.vmas.iter().find(|vma| vma.contains(addr))
    }

    pub fn remove_exact_vma(&mut self, start: usize, end: usize) -> Result<Vma, &'static str> {
        let idx = self
            .vmas
            .iter()
            .position(|vma| vma.start == start && vma.end == end)
            .ok_or("VMA not found")?;
        Ok(self.vmas.remove(idx))
    }

    pub fn allocate_range(&mut self, size: usize, align: usize) -> Result<usize, &'static str> {
        let page = crate::arch::mmu::page_size();
        let size = align_up_usize(size, page);
        let align = align.max(page);
        let mut cursor = align_up_usize(self.mmap_cursor.max(self.mmap_base), align);
        loop {
            let end = cursor.checked_add(size).ok_or("mapping overflow")?;
            if end > self.mmap_limit {
                return Err("virtual address space exhausted");
            }
            let overlaps = self
                .vmas
                .iter()
                .find(|vma| cursor < vma.end && vma.start < end)
                .map(|vma| vma.end);
            if let Some(next) = overlaps {
                cursor = align_up_usize(next, align);
                continue;
            }
            self.mmap_cursor = end;
            return Ok(cursor);
        }
    }

    pub fn mark_cow_regions(&mut self) {
        for vma in &mut self.vmas {
            if vma.flags.contains(VmaFlags::WRITE)
                && !vma.flags.contains(VmaFlags::SHARED)
                && matches!(vma.kind, VmaKind::Anonymous | VmaKind::Heap | VmaKind::File { .. })
            {
                vma.flags.insert(VmaFlags::COW);
            }
        }
    }
}

fn default_user_layout(entry: usize, user_stack: usize) -> UserProcessLayout {
    let page = crate::arch::mmu::page_size();
    let code_start = align_down_usize(entry, page);
    let code_end = code_start.saturating_add(page);
    let stack_top = align_up_usize(user_stack.saturating_add(1), page);
    let stack_start = stack_top.saturating_sub(page * 4);
    let heap_base = align_up_usize(code_end.saturating_add(page), page);
    let mmap_base = align_up_usize(USER_MMAP_MIN_ADDR.max(heap_base.saturating_add(page)), page);
    let mmap_limit = scheduler_user_top().saturating_sub(page * 8);
    UserProcessLayout {
        regions: vec![
            UserRegionSpec {
                start: code_start,
                end: code_end,
                flags: VmaFlags::READ | VmaFlags::EXEC | VmaFlags::USER,
                kind: VmaKind::KernelSynthetic,
            },
            UserRegionSpec {
                start: stack_start,
                end: stack_top,
                flags: VmaFlags::READ
                    | VmaFlags::WRITE
                    | VmaFlags::USER
                    | VmaFlags::STACK
                    | VmaFlags::GROW_DOWN,
                kind: VmaKind::Stack,
            },
        ],
        heap_base,
        heap_end: heap_base,
        mmap_base,
        mmap_limit,
    }
}

fn build_process_memory_map(layout: UserProcessLayout) -> Result<ProcessMemoryMap, &'static str> {
    let mut map =
        ProcessMemoryMap::new(layout.heap_base, layout.heap_end, layout.mmap_base, layout.mmap_limit);
    for region in layout.regions {
        map.insert_vma(Vma {
            start: region.start,
            end: region.end,
            flags: region.flags,
            kind: region.kind,
        })?;
    }
    if layout.heap_end > layout.heap_base {
        map.insert_vma(Vma {
            start: layout.heap_base,
            end: layout.heap_end,
            flags: VmaFlags::READ | VmaFlags::WRITE | VmaFlags::USER,
            kind: VmaKind::Heap,
        })?;
    }
    Ok(map)
}

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

    fn is_sane(&self) -> bool {
        self.head < MAX_PROCESSES && self.len <= MAX_PROCESSES
    }

    #[inline]
    fn assert_sane(&self) {
        assert!(
            self.is_sane(),
            "{ERR_READY_QUEUE_INVARIANT}: head={} len={} capacity={}",
            self.head,
            self.len,
            MAX_PROCESSES
        );
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn len(&self) -> usize {
        self.assert_sane();
        self.len
    }

    fn push_back(&mut self, pid: Pid) -> bool {
        self.assert_sane();
        if self.len >= MAX_PROCESSES {
            return false;
        }
        let tail = (self.head + self.len) % MAX_PROCESSES;
        self.entries[tail] = pid;
        self.len += 1;
        true
    }

    fn pop_front(&mut self) -> Option<Pid> {
        self.assert_sane();
        if self.len == 0 {
            return None;
        }
        let pid = self.entries[self.head];
        self.head = (self.head + 1) % MAX_PROCESSES;
        self.len -= 1;
        Some(pid)
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn for_each<F: FnMut(Pid)>(&self, mut f: F) {
        self.assert_sane();
        let mut i = 0usize;
        while i < self.len {
            let idx = (self.head + i) % MAX_PROCESSES;
            f(self.entries[idx]);
            i += 1;
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
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

#[cfg(not(target_arch = "aarch64"))]
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

#[cfg(not(target_arch = "aarch64"))]
fn scheduler_append_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(not(target_arch = "aarch64"))]
fn scheduler_append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(not(target_arch = "aarch64"))]
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
    #[cfg(target_arch = "x86_64")]
    shared_file_pages: BTreeMap<SharedFilePageKey, SharedFilePageEntry>,
}

/// Extended process information for scheduling
pub struct ProcessInfo {
    pub process: Process,
    pub context: ProcessContext,
    pub shared_runtime_pid: Option<Pid>,
    /// Top of the per-process kernel entry stack used for ring-3 -> ring-0 transitions.
    pub kernel_stack_top: usize,
    /// Kernel stack allocation (heap-backed for user/forked processes).
    pub stack: Option<Box<[u8; crate::process::STACK_SIZE]>>,
    /// Owned user address space (Some for user processes, None for kernel threads).
    pub address_space: Option<Box<crate::arch::mmu::AddressSpace>>,
    /// Canonical per-process user virtual memory map.
    pub memory_map: Option<ProcessMemoryMap>,
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
    // --- Lazy FPU / Vector context (PMA §5.1) ---
    /// Whether this process has ever executed an FP/SIMD instruction.
    /// False on spawn; set to true inside handle_fpu_trap() on first use.
    pub has_used_fpu: bool,
    /// Whether the FPU registers contain state belonging to this process
    /// that has not yet been saved back to [fpu_state].
    pub fpu_dirty: bool,
    /// Extended FPU/SIMD state buffer (2816 bytes, 64-byte aligned).
    /// Covers the full AVX-512 XSAVE area on x86_64 and Q0-Q31/FPSR/FPCR on AArch64.
    /// Zero-initialised; only valid after the first call to save_fpu_state_ext.
    pub fpu_state: crate::arch::fpu::ExtFpuState,
}

/// Wait queue for blocking primitives
#[derive(Clone)]
pub struct WaitQueue {
    pub addr: usize, // Address/key for the wait queue (like futex)
    pub waiting: VecDeque<Pid>,
    pub active: bool,
    pub wake_time: u64, // Non-zero only for timer sleep queues
}

pub enum BlockAction {
    Custom(ProcessState),
    OnAddr(usize, ProcessState),
}

pub struct BlockOnPlan {
    irq_flags: scheduler_platform::IrqFlags,
    action: BlockAction,
    is_committed: bool,
}

impl Drop for BlockOnPlan {
    fn drop(&mut self) {
        if !self.is_committed {
            unsafe { scheduler_platform::irq_restore(self.irq_flags) };
        }
    }
}

/// Scheduler statistics
#[derive(Clone, Copy)]
pub struct SchedulerStats {
    pub total_switches: u64,
    pub preemptions: u64,
    pub voluntary_yields: u64,
    pub idle_ticks: u64,
}

#[derive(Clone, Copy)]
pub struct SchedulerOverview {
    pub total_processes: usize,
    pub running_processes: usize,
    pub ready_processes: usize,
    pub sleeping_processes: usize,
    pub total_switches: u64,
    pub preemptions: u64,
    pub voluntary_yields: u64,
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
            #[cfg(target_arch = "x86_64")]
            shared_file_pages: BTreeMap::new(),
        }
    }

    fn process_slot(&self, idx: usize) -> Result<&ProcessInfo, &'static str> {
        self.processes
            .get(idx)
            .and_then(Option::as_ref)
            .ok_or(ERR_PROCESS_DATA_MISSING)
    }

    fn process_slot_mut(&mut self, idx: usize) -> Result<&mut ProcessInfo, &'static str> {
        self.processes
            .get_mut(idx)
            .and_then(Option::as_mut)
            .ok_or(ERR_PROCESS_DATA_MISSING)
    }

    fn process_info(&self, pid: Pid, err: &'static str) -> Result<&ProcessInfo, &'static str> {
        self.process_slot(pid.0 as usize).map_err(|_| err)
    }

    fn process_info_mut(
        &mut self,
        pid: Pid,
        err: &'static str,
    ) -> Result<&mut ProcessInfo, &'static str> {
        self.process_slot_mut(pid.0 as usize).map_err(|_| err)
    }

    fn require_current_pid(&self, err: &'static str) -> Result<Pid, &'static str> {
        self.current_pid.ok_or(err)
    }

    fn remove_from_ready_queues(&mut self, pid: Pid) {
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
    }

    fn remove_from_wait_queues(&mut self, pid: Pid) {
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
                wait.addr = 0;
                wait.wake_time = 0;
            }
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

        let quantum = base_quantum_for_priority(priority);

        let info = ProcessInfo {
            process,
            context: scheduler_platform::context_new(),
            shared_runtime_pid: Some(pid),
            kernel_stack_top: 0,
            stack: None,
            address_space: None,
            memory_map: None,
            quantum_remaining: quantum,
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: scheduler_platform::ticks_now(),
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
            // §5.1 Lazy FPU — starts as "never used FPU"
            has_used_fpu: false,
            fpu_dirty: false,
            fpu_state: crate::arch::fpu::ExtFpuState::new(),
        };

        self.processes[idx] = Some(info);
        self.enqueue_ready(pid, priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

        Ok(())
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
                        info.quantum_remaining = base_quantum_for_priority(priority);
                    }
                    #[cfg(feature = "experimental_entropy_sched")]
                    {
                        let rolled = roll_entropy_window(
                            EntropyWindowState {
                                ewma_yield: info.ewma_yield,
                                ewma_fault: info.ewma_fault,
                            },
                            info.yield_count,
                            info.pagefault_count,
                        );
                        info.ewma_yield = rolled.ewma_yield;
                        info.ewma_fault = rolled.ewma_fault;
                        info.quantum_remaining = entropy_adjusted_quantum(priority, rolled);
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

        // §5.1 Lazy FPU — deny FP/SIMD access to the incoming process.
        // The next FP instruction from next_pid will fault into handle_fpu_trap()
        // (IDT vector 7 / #NM), which will then perform the actual save/restore.
        // If next_pid is already the FPU owner, we still set TS to ensure any
        // in-flight FPU dirty state from a preempted IRQ is handled correctly;
        // handle_fpu_trap() will clear it immediately without swapping state.
        if self.fpu_owner != Some(next_pid) {
            // x86_64: Set CR0.TS bit (bit 3) — causes #NM on next FP instruction.
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let cr0: u64;
                core::arch::asm!("mov {r}, cr0", r = out(reg) cr0, options(nostack, nomem));
                core::arch::asm!("mov cr0, {r}", r = in(reg) cr0 | (1u64 << 3),
                                 options(nostack, nomem));
            }
            // AArch64: Clear CPACR_EL1.FPEN [21:20] → trap any FP/NEON to EL1.
            #[cfg(target_arch = "aarch64")]
            unsafe {
                let cpacr: u64;
                core::arch::asm!("mrs {r}, cpacr_el1", r = out(reg) cpacr, options(nostack));
                // FPEN = 0b00 → traps from both EL0 and EL1 are enabled
                core::arch::asm!(
                    "msr cpacr_el1, {r}",
                    "isb",
                    r = in(reg) cpacr & !(3u64 << 20),
                    options(nostack)
                );
            }
        }

        // Update scheduling timestamp
        if let Some(ref mut info) = self.processes[next_pid.0 as usize] {
            info.process.state = ProcessState::Running;
            info.last_scheduled = now;
            info.switches += 1;
        }

        self.stats.total_switches += 1;

        let from_ptr = prev_pid.and_then(|from_pid| {
            Some({
                let info = self
                    .process_info_mut(from_pid, ERR_SCHED_SWITCH_PREVIOUS_PROCESS_MISSING)
                    .expect(ERR_SCHED_SWITCH_PREVIOUS_PROCESS_MISSING);
                &mut info.context as *mut ProcessContext
            })
        })?;
        let to_ptr = {
            let info = self
                .process_info(next_pid, ERR_SCHED_SWITCH_NEXT_PROCESS_MISSING)
                .expect(ERR_SCHED_SWITCH_NEXT_PROCESS_MISSING);
            &info.context as *const ProcessContext
        };

        Some((from_ptr, to_ptr))
    }

    /// Schedule next process (called on timer interrupt)
    pub fn schedule(&mut self) -> Option<(*mut ProcessContext, *const ProcessContext)> {
        self.plan_switch(None)
    }

    // -----------------------------------------------------------------------
    // §5.1  Lazy FPU / Vector context switch
    // -----------------------------------------------------------------------

    /// Called from the IDT #NM / Device-Not-Available handler (vector 7) when a
    /// process executes an FP or SIMD instruction while CR0.TS = 1.
    ///
    /// Algorithm:
    ///   1. Clear the trap (CLTS on x86_64, re-enable FPEN on AArch64).
    ///   2. If the current process already owns the FPU, we're done (spurious trap).
    ///   3. Save the previous FPU owner's state into its [ProcessInfo::fpu_state].
    ///   4. Restore (or initialise) the new owner's state.
    ///   5. Update [fpu_owner].
    ///
    /// # Safety
    /// Must be called from the IDT entry point with no other FPU-related
    /// interrupt pending. The scheduler lock must be held by the caller.
    pub unsafe fn handle_fpu_trap(&mut self) {
        // Step 1 — clear the FP trap so the faulting instruction can retry.
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("clts", options(nostack, nomem));
        #[cfg(target_arch = "aarch64")]
        {
            let cpacr: u64;
            core::arch::asm!("mrs {r}, cpacr_el1", r = out(reg) cpacr, options(nostack));
            // FPEN = 0b11 → no traps from EL0 or EL1
            core::arch::asm!(
                "msr cpacr_el1, {r}",
                "isb",
                r = in(reg) cpacr | (3u64 << 20),
                options(nostack)
            );
        }

        let current = match self.current_pid {
            Some(pid) => pid,
            None => return, // No current process — nothing to do.
        };

        // Step 2 — spurious trap: process already owns FPU (e.g. TS was set
        // by the IRQ-path save below, then the process immediately faults again).
        if self.fpu_owner == Some(current) {
            return;
        }

        // Step 3 — save old owner's state.
        if let Some(owner_pid) = self.fpu_owner {
            let owner_idx = owner_pid.0 as usize;
            if let Some(ref mut owner_info) = self.processes[owner_idx] {
                crate::arch::fpu::save_fpu_state_ext(owner_info.fpu_state.0.as_mut_ptr());
                owner_info.fpu_dirty = false;
            }
        }

        // Step 4 — restore (or init) new owner's state.
        let current_idx = current.0 as usize;
        if let Some(ref mut info) = self.processes[current_idx] {
            if info.has_used_fpu {
                // Restore previously saved state.
                crate::arch::fpu::restore_fpu_state_ext(info.fpu_state.0.as_ptr());
            } else {
                // First ever FP use by this process — provide a clean environment.
                crate::arch::fpu::init_fpu_state();
                info.has_used_fpu = true;
            }
            info.fpu_dirty = true;
        }

        // Step 5 — update ownership.
        self.fpu_owner = Some(current);
    }

    /// Called by the timer IRQ path **before** context-switching away from a
    /// process that currently owns the FPU.  This ensures the FPU state is
    /// consistent if an IRQ fires mid-FP-instruction-stream.
    ///
    /// If the current process owns the FPU and has dirty state, we re-enable
    /// CR0.TS now (the owner will fault via `handle_fpu_trap()` on next use).
    /// This avoids a full save/restore on every timer tick.
    pub unsafe fn guard_irq_fpu_state(&mut self) {
        let current = match self.current_pid {
            Some(pid) => pid,
            None => return,
        };
        if self.fpu_owner == Some(current) {
            // Set TS so the *next* FP instruction after IRQ return faults cleanly.
            #[cfg(target_arch = "x86_64")]
            {
                let cr0: u64;
                core::arch::asm!("mov {r}, cr0", r = out(reg) cr0, options(nostack, nomem));
                core::arch::asm!("mov cr0, {r}", r = in(reg) cr0 | (1u64 << 3),
                                 options(nostack, nomem));
            }
            #[cfg(target_arch = "aarch64")]
            {
                let cpacr: u64;
                core::arch::asm!("mrs {r}, cpacr_el1", r = out(reg) cpacr, options(nostack));
                core::arch::asm!(
                    "msr cpacr_el1, {r}",
                    "isb",
                    r = in(reg) cpacr & !(3u64 << 20),
                    options(nostack)
                );
            }
        }
    }

    /// Enqueue process to ready queue
    fn enqueue_ready(&mut self, pid: Pid, priority: ProcessPriority) {
        let queue_idx = priority_to_queue_idx(priority);
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
        self.block_on_with_state(addr, ProcessState::Blocked)
    }

    pub fn block_current_process_custom(
        &mut self,
        wait_state: ProcessState,
    ) -> Result<Option<(*mut ProcessContext, *const ProcessContext)>, &'static str> {
        let current_pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
        let _ = self.process_info(current_pid, ERR_BLOCK_ON_CURRENT_PROCESS_MISSING)?;
        let prev = Some(current_pid);

        self.process_info_mut(current_pid, ERR_BLOCK_ON_CURRENT_PROCESS_MISSING)?
            .process
            .state = wait_state;

        self.current_pid = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(self.plan_switch(prev))
    }

    pub fn block_on_with_state(
        &mut self,
        addr: usize,
        wait_state: ProcessState,
    ) -> Result<Option<(*mut ProcessContext, *const ProcessContext)>, &'static str> {
        let current_pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
        let _ = self.process_info(current_pid, ERR_BLOCK_ON_CURRENT_PROCESS_MISSING)?;
        let prev = Some(current_pid);

        // Find or create wait queue
        let queue_idx = self.find_or_create_wait_queue(addr)?;

        // Add to wait queue
        self.wait_queues[queue_idx].waiting.push_back(current_pid);

        // Mark process as blocked
        self.process_info_mut(current_pid, ERR_BLOCK_ON_CURRENT_PROCESS_MISSING)?
            .process
            .state = wait_state;

        self.current_pid = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(self.plan_switch(prev))
    }

    pub fn wake_process(&mut self, pid: Pid) -> Result<bool, &'static str> {
        if let Some(ref mut info) = self.processes[pid.0 as usize] {
            if matches!(
                info.process.state,
                ProcessState::Blocked | ProcessState::WaitingOnChannel
            ) {
                info.process.state = ProcessState::Ready;
                let priority = info.process.priority;
                self.enqueue_ready(pid, priority);
                self.record_temporal_state_snapshot_locked(
                    scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
                );
                return Ok(true);
            }
        }
        Ok(false)
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

    /// Count active non-sleep waiters registered on a specific address.
    pub fn waiter_count(&self, addr: usize) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < self.wait_queue_count {
            let wait = &self.wait_queues[i];
            if wait.active && wait.wake_time == 0 && wait.addr == addr {
                count = count.saturating_add(wait.waiting.len());
            }
            i += 1;
        }
        count
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

    pub fn snapshot_overview(&self) -> SchedulerOverview {
        let total_processes = self.processes.iter().filter(|slot| slot.is_some()).count();
        let running_processes = self
            .processes
            .iter()
            .filter_map(|slot| slot.as_ref())
            .filter(|info| info.process.state == ProcessState::Running)
            .count();
        let ready_processes = self.ready_queues.iter().map(|queue| queue.len()).sum();
        let sleeping_processes = self
            .wait_queues
            .iter()
            .filter(|queue| queue.active && queue.wake_time != 0)
            .map(|queue| queue.waiting.len())
            .sum();

        SchedulerOverview {
            total_processes,
            running_processes,
            ready_processes,
            sleeping_processes,
            total_switches: self.stats.total_switches,
            preemptions: self.stats.preemptions,
            voluntary_yields: self.stats.voluntary_yields,
        }
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

    /// Get mutable process info — used by job control and external state transitions
    pub fn get_process_info_mut(&mut self, pid: Pid) -> Option<&mut ProcessInfo> {
        let idx = pid.0 as usize;
        if idx < MAX_PROCESSES {
            self.processes[idx].as_mut()
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

    #[inline]
    fn current_kernel_stack_top(&self) -> Option<usize> {
        self.current_pid
            .and_then(|pid| self.processes.get(pid.0 as usize))
            .and_then(|slot| slot.as_ref())
            .map(|info| info.kernel_stack_top)
            .filter(|top| *top != 0)
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

        #[cfg(debug_assertions)]
        {
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
        }

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
                3 => &mut KERNEL_STACK_3.data[..],
                _ => return Err("Only 4 kernel threads supported with static stacks"),
            }
        };

        let stack_base = stack_slice.as_mut_ptr() as usize;
        let stack_top =
            (unsafe { stack_slice.as_mut_ptr().add(stack_slice.len()) as usize }) & !15usize;

        // Verify stack address is sane and currently mapped.
        // Do not enforce a fixed upper bound: kernel image/heap placement can
        // legitimately exceed 32MB on this build configuration.
        let frame_top = kernel_thread_frame_top(stack_base, stack_top, KERNEL_THREAD_FRAME_BYTES)?;
        let mapped = scheduler_platform::validate_kernel_stack_mapping(frame_top, stack_top);
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

        let (ctx, _entry_addr_debug, _trampoline_addr_debug) =
            scheduler_platform::init_kernel_thread_context(entry, stack_top)?;

        #[cfg(debug_assertions)]
        scheduler_rt::logf(format_args!(
            "[SCHED] kernel_thread ctx init: entry={:#x} tramp={:#x} sp={:#x}",
            _entry_addr_debug,
            _trampoline_addr_debug,
            scheduler_platform::context_stack_pointer(&ctx)
        ));

        #[cfg(target_arch = "aarch64")]
        let shared_runtime_pid = {
            // The AArch64 serial-shell bring-up path does not require a shadow runtime
            // process for kernel threads. Keep scheduler PIDs self-contained here so
            // early boot does not depend on the heavier process/temporal plumbing.
            let _ = pid;
            None
        };
        #[cfg(not(target_arch = "aarch64"))]
        let shared_runtime_pid = None;

        process.state = ProcessState::Ready;

        let info = ProcessInfo {
            process,
            context: ctx,
            shared_runtime_pid,
            kernel_stack_top: stack_top,
            stack: None, // Stack is static, not heap-allocated
            address_space: None,
            memory_map: None,
            quantum_remaining: base_quantum_for_priority(priority),
            total_cpu_time: 0,
            total_wait_time: 0,
            last_scheduled: 0,
            switches: 0,
            yield_count: 0,
            pagefault_count: 0,
            ewma_yield: 0,
            ewma_fault: 0,
            has_used_fpu: false,
            fpu_dirty: false,
            fpu_state: crate::arch::fpu::ExtFpuState::new(),
        };

        self.processes[pid.0 as usize] = Some(info);
        self.enqueue_ready(pid, priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

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

        #[cfg(target_arch = "aarch64")]
        scheduler_rt::logf(format_args!("[A64-SCHED] start_scheduling: before lock"));

        let (ctx_ptr, runtime_pid_raw, kernel_stack_top) = {
            let mut scheduler = QUANTUM_SCHEDULER.lock();

            #[cfg(target_arch = "aarch64")]
            scheduler_rt::logf(format_args!("[A64-SCHED] start_scheduling: lock acquired"));

            scheduler.prepare_start_locked()
        }; // Lock is dropped here

        Self::launch_prepared_context(ctx_ptr, runtime_pid_raw, kernel_stack_top)
    }

    pub(crate) fn prepare_start_locked(&mut self) -> (*const ProcessContext, u32, usize) {
        // Find next process (prefer ready queues, recover from process table if needed).
        let next_pid = match self.dequeue_ready() {
            Some(pid) => pid,
            None => {
                scheduler_rt::logf(format_args!(
                    "[SCHED] Ready queues empty at scheduler start, scanning process table"
                ));
                let recovered = self
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

        #[cfg(target_arch = "aarch64")]
        scheduler_rt::logf(format_args!(
            "[A64-SCHED] start_scheduling: next pid {}",
            next_pid.0
        ));

        self.current_pid = Some(next_pid);
        SCHEDULER_STARTED.store(true, Ordering::Release);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);

        #[cfg(target_arch = "aarch64")]
        scheduler_rt::logf(format_args!(
            "[A64-SCHED] start_scheduling: state snapshot recorded"
        ));
        let runtime_pid_raw = self
            .runtime_pid_for_scheduler_pid(next_pid)
            .map(|pid| pid.0)
            .unwrap_or(next_pid.0);

        if let Some(ref mut info) = self.processes[next_pid.0 as usize] {
            info.process.state = ProcessState::Running;
            (
                &info.context as *const ProcessContext,
                runtime_pid_raw,
                info.kernel_stack_top,
            )
        } else {
            panic!("{ERR_PROCESS_DATA_MISSING}");
        }
    }

    pub(crate) fn launch_prepared_context(
        ctx_ptr: *const ProcessContext,
        runtime_pid_raw: u32,
        kernel_stack_top: usize,
    ) -> ! {
        #[cfg(target_arch = "aarch64")]
        scheduler_rt::logf(format_args!("[A64-SCHED] start_scheduling: lock released"));
        scheduler_rt::vga_print_str("[SCHED] Lock dropped, loading context\n");
        scheduler_rt::vga_print_str("[SCHED] Jumping to task...\n");
        unsafe {
            scheduler_platform::debug_dump_launch_context(ctx_ptr);
        }
        scheduler_platform::runtime_pid_sync(runtime_pid_raw);
        scheduler_platform::runtime_kernel_stack_sync(kernel_stack_top);

        // Set Task Switched (TS) bit in CR0 to enable lazy FPU context saving natively on dispatch
        #[cfg(target_arch = "x86")]
        unsafe {
            let mut cr0: u32;
            core::arch::asm!("mov {0}, cr0", out(reg) cr0);
            cr0 |= 8;
            core::arch::asm!("mov cr0, {0}", in(reg) cr0);
        }

        unsafe {
            // The runtime pid/stack handoff above makes this context fully owned by the
            // low-level arch trampoline; no scheduler references are used after this call.
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
    pub fn add_user_process_with_layout(
        &mut self,
        process: Process,
        space: Box<crate::arch::mmu::AddressSpace>,
        entry: u32,
        user_stack: u32,
        layout: UserProcessLayout,
    ) -> Result<Pid, &'static str> {
        self.add_user_process_internal(process, space, entry, user_stack, layout)
    }

    pub fn add_user_process(
        &mut self,
        process: Process,
        space: Box<crate::arch::mmu::AddressSpace>,
        entry: u32,
        user_stack: u32,
    ) -> Result<Pid, &'static str> {
        let layout = default_user_layout(entry as usize, user_stack as usize);
        self.add_user_process_internal(process, space, entry, user_stack, layout)
    }

    fn add_user_process_internal(
        &mut self,
        mut process: Process,
        space: Box<crate::arch::mmu::AddressSpace>,
        entry: u32,
        user_stack: u32,
        layout: UserProcessLayout,
    ) -> Result<Pid, &'static str> {
        #[cfg(target_arch = "x86")]
        {
            let pid = process.pid;
            let idx = pid.0 as usize;

            if idx >= MAX_PROCESSES {
                return Err("add_user_process: PID out of range");
            }
            if self.processes[idx].is_some() {
                return Err("add_user_process: PID already in use");
            }

            const KERNEL_BASE_ADDR: u32 = 0xC000_0000;
            if entry >= KERNEL_BASE_ADDR {
                return Err("add_user_process: entry point in kernel space");
            }
            if user_stack == 0 || user_stack >= KERNEL_BASE_ADDR {
                return Err("add_user_process: user stack in kernel space or null");
            }

            // Non-IRQ process creation path: a dedicated kernel stack is expected here.
            let kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);
            let stack_top =
                (kernel_stack.as_ptr() as usize + crate::process::STACK_SIZE) & !15usize;
            let page_dir_phys = PhysAddr::new(space.phys_addr());
            let page_dir_phys_u32 = page_dir_phys
                .try_as_u32()
                .map_err(|_| "add_user_process: page directory address exceeds u32")?;

            process.state = ProcessState::Ready;
            process.page_dir_phys = page_dir_phys;
            process.set_user_execution_image(entry as usize, user_stack as usize);

            let priority = process.priority;
            let quantum = base_quantum_for_priority(priority);

            let frame_top = (stack_top - 8) as *mut u32;
            unsafe {
                frame_top.write(entry);
                frame_top.add(1).write(user_stack);
            }

            let mut ctx = scheduler_platform::context_new();
            ctx.eip = crate::asm_bindings::kernel_user_entry_trampoline as u32;
            ctx.esp = frame_top as u32;
            ctx.ebp = frame_top as u32;
            ctx.cr3 = page_dir_phys_u32;
            ctx.eflags = 0x0000_0202;

            let memory_map = build_process_memory_map(layout)?;
            let now = scheduler_platform::ticks_now();
            let info = ProcessInfo {
                process,
                context: ctx,
                shared_runtime_pid: None,
                kernel_stack_top: stack_top,
                stack: Some(kernel_stack),
                address_space: Some(space),
                memory_map: Some(memory_map),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            self.processes[idx] = Some(info);
            self.enqueue_ready(pid, priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] add_user_process: pid={} entry={:#010x} user_sp={:#010x} cr3={:#010x}",
                pid.0, entry, user_stack, page_dir_phys_u32,
            ));

            Ok(pid)
        }

        #[cfg(target_arch = "x86_64")]
        {
            let pid = process.pid;
            let idx = pid.0 as usize;

            if idx >= MAX_PROCESSES {
                return Err("add_user_process: PID out of range");
            }
            if self.processes[idx].is_some() {
                return Err("add_user_process: PID already in use");
            }

            const KERNEL_BASE_ADDR: u32 = 0xC000_0000;
            if entry >= KERNEL_BASE_ADDR {
                return Err("add_user_process: entry point in kernel space");
            }
            if user_stack == 0 || user_stack >= KERNEL_BASE_ADDR {
                return Err("add_user_process: user stack in kernel space or null");
            }

            // Non-IRQ process creation path: a dedicated kernel stack is expected here.
            let kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);
            let stack_top =
                (kernel_stack.as_ptr() as usize + crate::process::STACK_SIZE) & !15usize;
            let page_dir_phys = PhysAddr::new(space.phys_addr());
            let frame_top = stack_top
                .checked_sub(32)
                .ok_or("add_user_process: invalid stack")?;

            unsafe {
                let frame = frame_top as *mut u64;
                frame.write(0);
                frame.add(1).write(entry as u64);
                frame.add(2).write(user_stack as u64);
                frame.add(3).write(stack_top as u64);
            }

            process.state = ProcessState::Ready;
            process.page_dir_phys = page_dir_phys;
            process.set_user_execution_image(entry as usize, user_stack as usize);

            let priority = process.priority;
            let quantum = base_quantum_for_priority(priority);

            let mut ctx = scheduler_platform::context_new();
            ctx.rip = crate::asm_bindings::kernel_user_entry_trampoline as usize as u64;
            ctx.rsp = frame_top as u64;
            ctx.rbp = frame_top as u64;
            ctx.cr3 = page_dir_phys.as_u64();
            ctx.rflags = 0x0000_0002;

            let memory_map = build_process_memory_map(layout)?;
            let now = scheduler_platform::ticks_now();
            let info = ProcessInfo {
                process,
                context: ctx,
                shared_runtime_pid: None,
                kernel_stack_top: stack_top,
                stack: Some(kernel_stack),
                address_space: Some(space),
                memory_map: Some(memory_map),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            self.processes[idx] = Some(info);
            self.enqueue_ready(pid, priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] add_user_process: pid={} entry={:#010x} user_sp={:#010x} cr3={:#018x}",
                pid.0,
                entry,
                user_stack,
                page_dir_phys.as_u64(),
            ));

            Ok(pid)
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ---------------------------------------------------------------
            // AArch64 user-process initialisation
            //
            // Register convention at first schedule:
            //   PC  = aarch64_kernel_user_entry_trampoline (EL1)
            //   SP  = kernel exception stack
            //   x19 = EL0 entry point
            //   x20 = EL0 stack top
            //   DAIF = kernel interrupt mask while the EL1 trampoline runs
            //   TTBR0_EL1 = physical address of the process page table
            // ---------------------------------------------------------------

            extern "C" {
                fn aarch64_kernel_user_entry_trampoline() -> !;
            }

            let pid = process.pid;
            let idx = pid.0 as usize;

            if idx >= MAX_PROCESSES {
                return Err("add_user_process: PID out of range");
            }
            if self.processes[idx].is_some() {
                return Err("add_user_process: PID already in use");
            }

            // On AArch64 the kernel/user split is handled by TTBR0/TTBR1;
            // we don't impose a hard numeric limit on the entry address, but
            // we still reject null stacks.
            if user_stack == 0 {
                return Err("add_user_process: null user stack");
            }

            // Allocate a kernel-mode exception-handler stack (16-byte aligned).
            // Non-IRQ process creation path: a dedicated kernel stack is expected here.
            let kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);
            let stack_top =
                (kernel_stack.as_ptr() as usize + crate::process::STACK_SIZE) & !15usize;

            let page_dir_phys = PhysAddr::new(space.phys_addr());

            process.state = ProcessState::Ready;
            process.page_dir_phys = page_dir_phys;
            process.set_user_execution_image(entry as usize, user_stack as usize);

            let priority = process.priority;
            let quantum = base_quantum_for_priority(priority);

            // Build the initial register context.
            let mut ctx = scheduler_platform::context_new();
            ctx.pc = aarch64_kernel_user_entry_trampoline as *const () as usize as u64;
            ctx.sp = stack_top as u64;
            ctx.x19 = entry as u64;
            ctx.x20 = user_stack as u64;
            // Keep interrupts masked until the trampoline finishes the EL0 enter.
            ctx.daif = 0b1111 << 6;
            // TTBR0_EL1 — physical base of this process's page table.
            ctx.ttbr0_el1 = page_dir_phys.as_u64();
            // Legacy 32-bit shadow for shared diagnostics code.
            ctx.esp = user_stack as u32;

            let memory_map = build_process_memory_map(layout)?;
            let now = scheduler_platform::ticks_now();
            let info = ProcessInfo {
                process,
                context: ctx,
                shared_runtime_pid: None,
                kernel_stack_top: stack_top,
                stack: Some(kernel_stack),
                address_space: Some(space),
                memory_map: Some(memory_map),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            self.processes[idx] = Some(info);
            self.enqueue_ready(pid, priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] add_user_process(aa64): pid={} entry={:#010x} user_sp={:#010x} ttbr0={:#018x}",
                pid.0, entry, user_stack, page_dir_phys.as_u64(),
            ));

            Ok(pid)
        }
    }

    pub fn alloc_current_anonymous(
        &mut self,
        requested_addr: Option<usize>,
        size: usize,
        flags: VmaFlags,
    ) -> Result<usize, &'static str> {
        let pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
        self.alloc_anonymous_for_pid(pid, requested_addr, size, flags)
    }

    pub fn map_current_file(
        &mut self,
        requested_addr: Option<usize>,
        size: usize,
        flags: VmaFlags,
        source: crate::fs::vfs::MappedFileSource,
        offset: usize,
    ) -> Result<usize, &'static str> {
        let pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
        self.map_file_for_pid(pid, requested_addr, size, flags, source, offset)
    }

    pub fn alloc_anonymous_for_pid(
        &mut self,
        pid: Pid,
        requested_addr: Option<usize>,
        size: usize,
        flags: VmaFlags,
    ) -> Result<usize, &'static str> {
        #[cfg(target_arch = "x86_64")]
        {
            let page = crate::arch::mmu::page_size();
            let len = align_up_usize(size, page);
            let info = self.process_info_mut(pid, "memory alloc: process missing")?;
            let memory_map = info.memory_map.as_mut().ok_or("memory alloc: no memory map")?;
            let start = match requested_addr {
                Some(addr) if addr != 0 => {
                    let aligned = align_down_usize(addr, page);
                    if memory_map.find_vma(aligned).is_some() {
                        return Err("memory alloc: address already mapped");
                    }
                    aligned
                }
                _ => memory_map.allocate_range(len, page)?,
            };
            let end = start.checked_add(len).ok_or("memory alloc: range overflow")?;
            let writable = flags.contains(VmaFlags::WRITE);
            let space = info
                .address_space
                .as_mut()
                .ok_or("memory alloc: no address space")?;
            crate::arch::mmu::alloc_user_pages(space, start, len / page, writable)?;
            memory_map.insert_vma(Vma {
                start,
                end,
                flags: flags | VmaFlags::USER,
                kind: VmaKind::Anonymous,
            })?;
            return Ok(start);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (pid, requested_addr, size, flags);
            Err("memory alloc unsupported on this architecture")
        }
    }

    pub fn map_file_for_pid(
        &mut self,
        pid: Pid,
        requested_addr: Option<usize>,
        size: usize,
        flags: VmaFlags,
        source: crate::fs::vfs::MappedFileSource,
        offset: usize,
    ) -> Result<usize, &'static str> {
        #[cfg(target_arch = "x86_64")]
        {
            let page = crate::arch::mmu::page_size();
            let len = align_up_usize(size, page);
            let file_offset = align_down_usize(offset, page);
            let info = self.process_info_mut(pid, "memory map: process missing")?;
            let memory_map = info.memory_map.as_mut().ok_or("memory map: no memory map")?;
            let start = match requested_addr {
                Some(addr) if addr != 0 => {
                    let aligned = align_down_usize(addr, page);
                    let end = aligned
                        .checked_add(len)
                        .ok_or("memory map: range overflow")?;
                    if memory_map.vmas.iter().any(|vma| aligned < vma.end && vma.start < end) {
                        return Err("memory map: address already mapped");
                    }
                    aligned
                }
                _ => memory_map.allocate_range(len, page)?,
            };
            let end = start
                .checked_add(len)
                .ok_or("memory map: range overflow")?;
            memory_map.insert_vma(Vma {
                start,
                end,
                flags: flags | VmaFlags::USER,
                kind: VmaKind::File {
                    source,
                    offset: file_offset as u64,
                },
            })?;
            return Ok(start);
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (pid, requested_addr, size, flags, source, offset);
            Err("memory map unsupported on this architecture")
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn flush_shared_file_vma(
        space: &mut crate::arch::mmu::AddressSpace,
        vma: &Vma,
    ) -> Result<(), &'static str> {
        let (source, file_base_offset) = match &vma.kind {
            VmaKind::File { source, offset } => (source, *offset as usize),
            _ => return Ok(()),
        };
        if !vma.flags.contains(VmaFlags::SHARED) || !vma.flags.contains(VmaFlags::WRITE) {
            return Ok(());
        }

        let page = crate::arch::mmu::page_size();
        let old = crate::arch::mmu::current_page_table_root_addr();
        unsafe {
            space.activate();
        }
        let mut page_addr = vma.start;
        while page_addr < vma.end {
            if space.is_mapped(page_addr) {
                let mut page_buf = alloc::vec![0u8; page];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        page_addr as *const u8,
                        page_buf.as_mut_ptr(),
                        page,
                    );
                }
                let write_offset = file_base_offset.saturating_add(page_addr.saturating_sub(vma.start));
                crate::fs::vfs::write_mapped_file_at(source, write_offset, &page_buf)?;
            }
            page_addr = page_addr.saturating_add(page);
        }
        crate::arch::mmu::set_page_table_root(old)?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn retain_shared_file_page(
        &mut self,
        source: &crate::fs::vfs::MappedFileSource,
        file_page_offset: usize,
    ) -> Option<usize> {
        let key = SharedFilePageKey {
            source: source.clone(),
            file_page_offset,
        };
        let entry = self.shared_file_pages.get_mut(&key)?;
        entry.refcount = entry.refcount.saturating_add(1);
        Some(entry.phys_addr)
    }

    #[cfg(target_arch = "x86_64")]
    fn install_shared_file_page(
        &mut self,
        source: crate::fs::vfs::MappedFileSource,
        file_page_offset: usize,
        phys_addr: usize,
    ) {
        self.shared_file_pages.insert(
            SharedFilePageKey {
                source,
                file_page_offset,
            },
            SharedFilePageEntry {
                phys_addr,
                refcount: 1,
            },
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn release_shared_file_page_ref(
        &mut self,
        source: &crate::fs::vfs::MappedFileSource,
        file_page_offset: usize,
    ) {
        let key = SharedFilePageKey {
            source: source.clone(),
            file_page_offset,
        };
        let remove = if let Some(entry) = self.shared_file_pages.get_mut(&key) {
            if entry.refcount > 1 {
                entry.refcount -= 1;
                false
            } else {
                true
            }
        } else {
            false
        };
        if remove {
            let _ = self.shared_file_pages.remove(&key);
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn collect_shared_file_vma_keys(
        space: &crate::arch::mmu::AddressSpace,
        vma: &Vma,
    ) -> Vec<SharedFilePageKey> {
        let (source, file_base_offset) = match &vma.kind {
            VmaKind::File { source, offset } => (source, *offset as usize),
            _ => return Vec::new(),
        };
        if !vma.flags.contains(VmaFlags::SHARED) {
            return Vec::new();
        }

        let page = crate::arch::mmu::page_size();
        let mut keys = Vec::new();
        let mut page_addr = vma.start;
        while page_addr < vma.end {
            if space.is_mapped(page_addr) {
                keys.push(SharedFilePageKey {
                    source: source.clone(),
                    file_page_offset: file_base_offset
                        .saturating_add(page_addr.saturating_sub(vma.start)),
                });
            }
            page_addr = page_addr.saturating_add(page);
        }
        keys
    }

    #[cfg(target_arch = "x86_64")]
    fn release_shared_file_vma_refs(
        &mut self,
        space: &crate::arch::mmu::AddressSpace,
        vma: &Vma,
    ) {
        for key in Self::collect_shared_file_vma_keys(space, vma) {
            self.release_shared_file_page_ref(&key.source, key.file_page_offset);
        }
    }

    pub fn free_current_mapping(&mut self, addr: usize, size: usize) -> Result<(), &'static str> {
        let pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
        self.free_mapping_for_pid(pid, addr, size)
    }

    pub fn free_mapping_for_pid(
        &mut self,
        pid: Pid,
        addr: usize,
        size: usize,
    ) -> Result<(), &'static str> {
        #[cfg(target_arch = "x86_64")]
        {
            let page = crate::arch::mmu::page_size();
            let start = align_down_usize(addr, page);
            let end = start
                .checked_add(align_up_usize(size, page))
                .ok_or("memory free: range overflow")?;
            let shared_keys = {
                let info = self.process_info_mut(pid, "memory free: process missing")?;
                let memory_map = info.memory_map.as_mut().ok_or("memory free: no memory map")?;
                let vma = memory_map.remove_exact_vma(start, end)?;
                let space = info
                    .address_space
                    .as_mut()
                    .ok_or("memory free: no address space")?;
                Self::flush_shared_file_vma(space, &vma)?;
                let shared_keys = Self::collect_shared_file_vma_keys(space, &vma);
                let mut page_addr = vma.start;
                while page_addr < vma.end {
                    let _ = crate::arch::mmu::unmap_page(space, page_addr);
                    page_addr = page_addr.saturating_add(page);
                }
                shared_keys
            };
            for key in shared_keys {
                self.release_shared_file_page_ref(&key.source, key.file_page_offset);
            }
            return Ok(());
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (pid, addr, size);
            Err("memory free unsupported on this architecture")
        }
    }

    pub fn handle_current_user_page_fault(
        &mut self,
        fault_addr: usize,
        error: u64,
    ) -> Result<bool, &'static str> {
        #[cfg(target_arch = "x86_64")]
        {
            let pid = self.require_current_pid(ERR_NO_CURRENT_PROCESS)?;
            self.record_pagefault();
            let page = crate::arch::mmu::page_size();
            let page_addr = align_down_usize(fault_addr, page);
            let is_write = (error & (1 << 1)) != 0;
            let is_exec = (error & (1 << 4)) != 0;
            let vma = {
                let info = self.process_info(pid, "page fault: process missing")?;
                info.memory_map
                    .as_ref()
                    .and_then(|map| map.find_vma(fault_addr))
                    .cloned()
            };
            let Some(vma) = vma else {
                return Ok(false);
            };

            if is_exec && !vma.flags.contains(VmaFlags::EXEC) {
                return Err("page fault: execute permission denied");
            }
            if is_write && !vma.flags.contains(VmaFlags::WRITE) && !vma.flags.contains(VmaFlags::COW) {
                return Err("page fault: write permission denied");
            }
            if !is_write && !vma.flags.contains(VmaFlags::READ) && !is_exec {
                return Err("page fault: read permission denied");
            }

            if is_write && vma.flags.contains(VmaFlags::COW) {
                return Ok(crate::arch::mmu::handle_page_fault(fault_addr, error));
            }

            match vma.kind {
                VmaKind::Anonymous | VmaKind::Heap | VmaKind::Stack => {
                    let info = self.process_info_mut(pid, "page fault: process missing")?;
                    let space = info
                        .address_space
                        .as_mut()
                        .ok_or("page fault: no address space")?;
                    if !space.is_mapped(page_addr) {
                        crate::arch::mmu::alloc_user_pages(
                            space,
                            page_addr,
                            1,
                            vma.flags.contains(VmaFlags::WRITE),
                        )?;
                    }
                    Ok(true)
                }
                VmaKind::File { source, offset } => {
                    let file_page_offset = offset
                        .checked_add(page_addr.saturating_sub(vma.start) as u64)
                        .ok_or("page fault: file offset overflow")? as usize;
                    let writable = vma.flags.contains(VmaFlags::WRITE);
                    let cached_phys = if vma.flags.contains(VmaFlags::SHARED) {
                        self.retain_shared_file_page(&source, file_page_offset)
                    } else {
                        None
                    };
                    let info = self.process_info_mut(pid, "page fault: process missing")?;
                    let space = info
                        .address_space
                        .as_mut()
                        .ok_or("page fault: no address space")?;
                    if let Some(phys_addr) = cached_phys {
                        space.map_page(page_addr, phys_addr, writable, true)?;
                        return Ok(true);
                    }

                    let phys_addr = crate::memory::allocate_frame()?;
                    space.map_page(page_addr, phys_addr, writable, true)?;

                    let mut page_buf = alloc::vec![0u8; page];
                    let _ =
                        crate::fs::vfs::read_mapped_file_at(&source, file_page_offset, &mut page_buf)?;

                    let old = crate::arch::mmu::current_page_table_root_addr();
                    unsafe {
                        space.activate();
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(page_buf.as_ptr(), page_addr as *mut u8, page);
                    }
                    crate::arch::mmu::set_page_table_root(old)?;
                    if vma.flags.contains(VmaFlags::SHARED) {
                        self.install_shared_file_page(source.clone(), file_page_offset, phys_addr);
                    }
                    Ok(true)
                }
                VmaKind::PhysicalMap { .. } | VmaKind::KernelSynthetic => Ok(false),
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (fault_addr, error);
            Ok(false)
        }
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

        self.remove_from_ready_queues(pid);
        self.remove_from_wait_queues(pid);

        #[cfg(target_arch = "x86_64")]
        {
            let shared_keys = if let Some(info) = self.processes[idx].as_mut() {
                if let (Some(memory_map), Some(space)) =
                    (info.memory_map.as_ref(), info.address_space.as_mut())
                {
                    let mut shared_keys = Vec::new();
                    for vma in &memory_map.vmas {
                        let _ = Self::flush_shared_file_vma(space, vma);
                        shared_keys.extend(Self::collect_shared_file_vma_keys(space, vma));
                    }
                    shared_keys
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            for key in shared_keys {
                self.release_shared_file_page_ref(&key.source, key.file_page_offset);
            }
        }

        #[cfg(target_arch = "aarch64")]
        if let Some(info) = self.processes[idx].as_ref() {
            if let Some(shared_pid) = info.shared_runtime_pid {
                let _ = crate::process::process_manager().terminate(shared_pid);
                crate::vfs::clear_process_capability(shared_pid);
                if crate::process::current_pid() == Some(shared_pid) {
                    let _ = crate::process::set_current_runtime_pid(Pid::new(0));
                }
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
    /// The child's FD table is fully duplicated: each open VFS handle is cloned
    /// via `vfs::dup_fds_for_fork` so parent and child have independent handles
    /// that share the same initial file offset.  AArch64 is fully supported.
    pub fn fork_current_cow(&mut self) -> Result<Pid, &'static str> {
        #[cfg(target_arch = "x86")]
        {
            let parent_pid = self
                .current_pid
                .ok_or("fork_current_cow: no current process")?;
            let parent_idx = parent_pid.0 as usize;

            let child_pid = (0..MAX_PROCESSES)
                .map(|i| Pid(i as u32))
                .find(|&p| self.processes[p.0 as usize].is_none())
                .ok_or("fork_current_cow: process table full")?;
            let child_idx = child_pid.0 as usize;

            let (parent_process_clone, parent_ctx, parent_priority, child_memory_map) = {
                let info = self
                    .process_slot(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                (
                    info.process.clone(),
                    info.context,
                    info.process.priority,
                    info.memory_map.clone(),
                )
            };

            let mut child_process = parent_process_clone;
            child_process.pid = child_pid;
            child_process.parent = Some(parent_pid);
            child_process.state = ProcessState::Ready;
            child_process.cpu_time = 0;
            child_process.has_used_fpu = false;
            child_process.fpu_state = crate::process::FpuState([0u8; 512]);
            // Duplicate VFS handles so parent and child each hold independent
            // handle entries that share the same initial file offset.
            child_process.fd_table =
                crate::fs::vfs::dup_fds_for_fork(child_pid, &child_process.fd_table);

            let child_address_space: Box<crate::arch::mmu::AddressSpace>;
            let child_cr3: PhysAddr;
            let child_cr3_u32: u32;
            {
                let parent_info = self
                    .process_slot_mut(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                if let Some(memory_map) = parent_info.memory_map.as_mut() {
                    memory_map.mark_cow_regions();
                }
                let child_space = parent_info
                    .address_space
                    .as_mut()
                    .ok_or("fork_current_cow: parent has no owned address space")
                    .and_then(|space| {
                        space
                            .clone_cow()
                            .map_err(|_| "fork_current_cow: clone_cow failed")
                    })?;

                child_cr3 = PhysAddr::new(child_space.phys_addr());
                child_cr3_u32 = child_cr3
                    .try_as_u32()
                    .map_err(|_| "fork_current_cow: child CR3 exceeds u32")?;
                child_address_space = Box::new(child_space);
                child_process.page_dir_phys = child_cr3;
            }

            let mut child_ctx = parent_ctx;
            child_ctx.cr3 = child_cr3_u32;

            // Non-IRQ process fork path: child kernel stack allocation is expected here.
            let child_kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);

            let quantum = base_quantum_for_priority(parent_priority);

            let now = scheduler_platform::ticks_now();
            let child_info = ProcessInfo {
                process: child_process,
                context: child_ctx,
                shared_runtime_pid: None,
                kernel_stack_top: (child_kernel_stack.as_ptr() as usize
                    + crate::process::STACK_SIZE)
                    & !15usize,
                stack: Some(child_kernel_stack),
                address_space: Some(child_address_space),
                memory_map: child_memory_map.map(|mut map| {
                    map.mark_cow_regions();
                    map
                }),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            crate::process_platform::on_process_spawn(child_pid, Some(parent_pid), "forked");
            self.processes[child_idx] = Some(child_info);
            self.enqueue_ready(child_pid, parent_priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] fork_current_cow: parent={} -> child={} cr3={:#010x}",
                parent_pid.0, child_pid.0, child_cr3_u32,
            ));

            Ok(child_pid)
        }

        #[cfg(target_arch = "x86_64")]
        {
            let parent_pid = self
                .current_pid
                .ok_or("fork_current_cow: no current process")?;
            let parent_idx = parent_pid.0 as usize;

            let child_pid = (0..MAX_PROCESSES)
                .map(|i| Pid(i as u32))
                .find(|&p| self.processes[p.0 as usize].is_none())
                .ok_or("fork_current_cow: process table full")?;
            let child_idx = child_pid.0 as usize;

            let (parent_priority, child_memory_map) = {
                let parent_info = self
                    .process_slot(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                (parent_info.process.priority, parent_info.memory_map.clone())
            };

            let child_space = {
                let parent_info = self
                    .process_slot_mut(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                if let Some(memory_map) = parent_info.memory_map.as_mut() {
                    memory_map.mark_cow_regions();
                }
                parent_info
                    .address_space
                    .as_mut()
                    .ok_or("fork_current_cow: parent has no owned address space")
                    .and_then(|space| {
                        space
                            .clone_cow()
                            .map_err(|_| "fork_current_cow: clone_cow failed")
                    })?
            };

            let child_cr3 = PhysAddr::new(child_space.phys_addr());
            // Non-IRQ process fork path: child kernel stack allocation is expected here.
            let child_kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);
            let child_stack_top =
                (child_kernel_stack.as_ptr() as usize + crate::process::STACK_SIZE) & !15usize;
            let child_rsp = crate::syscall::clone_current_syscall_return_frame(child_stack_top, 0)?;

            let mut child_process = match crate::process::process_manager()
                .fork_process_with_pid(parent_pid, child_pid)
            {
                Ok(process) => process,
                Err(_) => return Err("fork_current_cow: process clone failed"),
            };

            child_process.page_dir_phys = child_cr3;
            child_process.has_used_fpu = false;
            child_process.fpu_state = crate::process::FpuState([0u8; 512]);
            // Duplicate VFS handles for the child.
            child_process.fd_table =
                crate::fs::vfs::dup_fds_for_fork(child_pid, &child_process.fd_table);

            if crate::process::process_manager()
                .set_process_page_dir(child_pid, child_cr3)
                .is_err()
            {
                let _ = crate::process::process_manager().terminate(child_pid);
                return Err("fork_current_cow: child page-dir sync failed");
            }

            let mut child_ctx = scheduler_platform::context_new();
            child_ctx.rip = crate::syscall::x86_64_syscall_resume_rip() as u64;
            child_ctx.rsp = child_rsp as u64;
            child_ctx.rbp = 0;
            child_ctx.cr3 = child_cr3.as_u64();
            child_ctx.rflags = 0x0000_0002;

            let quantum = base_quantum_for_priority(parent_priority);

            let now = scheduler_platform::ticks_now();
            let child_info = ProcessInfo {
                process: child_process,
                context: child_ctx,
                shared_runtime_pid: None,
                kernel_stack_top: child_stack_top,
                stack: Some(child_kernel_stack),
                address_space: Some(Box::new(child_space)),
                memory_map: child_memory_map.map(|mut map| {
                    map.mark_cow_regions();
                    map
                }),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            self.processes[child_idx] = Some(child_info);
            self.enqueue_ready(child_pid, parent_priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] fork_current_cow(x64): parent={} -> child={} cr3={:#018x}",
                parent_pid.0,
                child_pid.0,
                child_cr3.as_u64(),
            ));

            Ok(child_pid)
        }

        #[cfg(target_arch = "aarch64")]
        {
            let parent_pid = self
                .current_pid
                .ok_or("fork_current_cow: no current process")?;
            let parent_idx = parent_pid.0 as usize;

            let child_pid = (0..MAX_PROCESSES)
                .map(|i| Pid(i as u32))
                .find(|&p| self.processes[p.0 as usize].is_none())
                .ok_or("fork_current_cow: process table full")?;
            let child_idx = child_pid.0 as usize;

            let (parent_process_clone, parent_priority, child_memory_map) = {
                let info = self
                    .process_slot(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                (
                    info.process.clone(),
                    info.process.priority,
                    info.memory_map.clone(),
                )
            };

            // Clone address space COW — must happen before we borrow child_process.
            let child_space = {
                let parent_info = self
                    .process_slot_mut(parent_idx)
                    .map_err(|_| "fork_current_cow: parent info missing")?;
                if let Some(memory_map) = parent_info.memory_map.as_mut() {
                    memory_map.mark_cow_regions();
                }
                parent_info
                    .address_space
                    .as_mut()
                    .ok_or("fork_current_cow: parent has no owned address space")
                    .and_then(|space| {
                        space
                            .clone_cow()
                            .map_err(|_| "fork_current_cow: clone_cow failed")
                    })?
            };

            let child_cr3 = PhysAddr::new(child_space.phys_addr());

            // Allocate child kernel stack.
            let child_kernel_stack: Box<[u8; crate::process::STACK_SIZE]> =
                Box::new([0u8; crate::process::STACK_SIZE]);
            let child_stack_top = (child_kernel_stack.as_ptr() as usize
                + crate::process::STACK_SIZE)
                & !15usize;

            // Copy the parent's SVC exception frame onto the child's kernel stack
            // with x0 = 0 (fork returns 0 in child).
            let child_sp =
                crate::syscall::clone_current_aarch64_syscall_return_frame(child_stack_top)?;

            // Build child PCB.
            let mut child_process = parent_process_clone;
            child_process.pid = child_pid;
            child_process.parent = Some(parent_pid);
            child_process.state = ProcessState::Ready;
            child_process.cpu_time = 0;
            child_process.has_used_fpu = false;
            child_process.fpu_state = crate::process::FpuState([0u8; 512]);
            child_process.page_dir_phys = child_cr3;
            // Duplicate VFS handles for the child.
            child_process.fd_table =
                crate::fs::vfs::dup_fds_for_fork(child_pid, &child_process.fd_table);

            // Build child kernel context:
            //   pc  = aarch64_fork_child_trampoline
            //   sp  = base of the copied exception frame on child's kernel stack
            //   x19 = ELR_EL1 + 4   (user PC past the SVC instruction)
            //   x20 = SPSR_EL1      (user processor state)
            //   x21 = SP_EL0        (user stack pointer)
            let elr = crate::arch::aarch64_vectors::last_elr_el1().wrapping_add(4);
            let spsr = crate::arch::aarch64_vectors::last_spsr_el1();
            let sp_el0 = crate::arch::aarch64_vectors::last_sp_el0();

            let mut child_ctx = scheduler_platform::context_new();
            child_ctx.pc = crate::syscall::aarch64_fork_child_resume_rip() as u64;
            child_ctx.sp = child_sp as u64;
            child_ctx.x19 = elr;
            child_ctx.x20 = spsr;
            child_ctx.x21 = sp_el0;
            child_ctx.ttbr0_el1 = child_cr3.as_u64();
            child_ctx.daif = 0;

            let quantum = base_quantum_for_priority(parent_priority);
            let now = scheduler_platform::ticks_now();
            let child_info = ProcessInfo {
                process: child_process,
                context: child_ctx,
                shared_runtime_pid: None,
                kernel_stack_top: child_stack_top,
                stack: Some(child_kernel_stack),
                address_space: Some(Box::new(child_space)),
                memory_map: child_memory_map.map(|mut map| {
                    map.mark_cow_regions();
                    map
                }),
                quantum_remaining: quantum,
                total_cpu_time: 0,
                total_wait_time: 0,
                last_scheduled: now,
                switches: 0,
                yield_count: 0,
                pagefault_count: 0,
                ewma_yield: 0,
                ewma_fault: 0,
                has_used_fpu: false,
                fpu_dirty: false,
                fpu_state: crate::arch::fpu::ExtFpuState::new(),
            };

            crate::process_platform::on_process_spawn(child_pid, Some(parent_pid), "forked");
            self.processes[child_idx] = Some(child_info);
            self.enqueue_ready(child_pid, parent_priority);
            self.record_temporal_state_snapshot_locked(
                scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE,
            );

            scheduler_rt::logf(format_args!(
                "[SCHED] fork_current_cow(aa64): parent={} -> child={} ttbr0={:#018x}",
                parent_pid.0,
                child_pid.0,
                child_cr3.as_u64(),
            ));

            Ok(child_pid)
        }
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
        let current_pid = self.require_current_pid(ERR_BLOCK_PROCESS_NO_CURRENT_PROCESS)?;
        if current_pid != pid {
            return Err(ERR_BLOCK_PROCESS_PID_NOT_CURRENT);
        }
        let _ = self.process_info(current_pid, ERR_BLOCK_PROCESS_CURRENT_PROCESS_MISSING)?;

        let prev = Some(current_pid);
        let queue_idx = self.find_or_create_sleep_queue(wake_time)?;
        self.wait_queues[queue_idx].waiting.push_back(current_pid);

        let info = self.process_info_mut(current_pid, ERR_BLOCK_PROCESS_CURRENT_PROCESS_MISSING)?;
        info.process.state = ProcessState::Blocked;
        info.last_scheduled = scheduler_platform::ticks_now();

        self.current_pid = None;
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        Ok(self.plan_switch(prev))
    }

    /// Execute WASM in current process
    pub fn exec_current_wasm(&mut self, module_id: u32) -> Result<(), &'static str> {
        let current_pid = self.require_current_pid(ERR_EXEC_CURRENT_WASM_NO_CURRENT_PROCESS)?;
        let info =
            self.process_info_mut(current_pid, ERR_EXEC_CURRENT_WASM_CURRENT_PROCESS_MISSING)?;

        // Until usermode WASM replaces the whole process image, treat exec as
        // rebinding the current task to a new module entry. The actual module
        // execution happens outside the scheduler lock in the syscall path.
        info.process.set_program_counter_token(module_id as usize);
        info.process.state = ProcessState::Running;
        info.quantum_remaining = base_quantum_for_priority(info.process.priority);
        self.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
        scheduler_rt::logf(format_args!(
            "[SCHED] exec_current_wasm: pid={} module_id={}",
            current_pid.0, module_id
        ));
        Ok(())
    }

    #[cfg(not(target_arch = "aarch64"))]
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
        #[cfg(target_arch = "aarch64")]
        {
            let _ = event;
            return;
        }

        #[cfg(not(target_arch = "aarch64"))]
        if scheduler_rt::temporal_is_replay_active() {
            return;
        }

        #[cfg(not(target_arch = "aarch64"))]
        let payload = match self.encode_temporal_state_payload_locked(event) {
            Some(v) => v,
            None => return,
        };

        #[cfg(not(target_arch = "aarch64"))]
        let _ = scheduler_rt::temporal_record_scheduler_state_event(&payload);
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

pub fn handle_current_user_page_fault(fault_addr: usize, error: u64) -> Result<bool, &'static str> {
    QUANTUM_SCHEDULER
        .lock()
        .handle_current_user_page_fault(fault_addr, error)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn selftest_shared_file_mapping_live() -> Result<(usize, usize, u8), &'static str> {
    let path = "/shared-mmap-selftest";
    let page = crate::arch::mmu::page_size();
    let map_addr = 0x2000_0000usize;
    let entry_a = 0x0040_0000u32;
    let entry_b = 0x0040_1000u32;
    let user_stack_a = (crate::paging::USER_TOP - page) as u32;
    let user_stack_b = (crate::paging::USER_TOP - (page * 2)) as u32;
    let pid_a = Pid(40);
    let pid_b = Pid(41);

    crate::vfs::write_path(path, &[0u8; 16])?;
    let source = crate::fs::vfs::mmap_source_for_path(path)?;

    let mut sched = QuantumScheduler::new();
    let mut proc_a = Process::new(pid_a, "sharedmmap-a", None);
    proc_a.priority = ProcessPriority::Normal;
    let mut proc_b = Process::new(pid_b, "sharedmmap-b", None);
    proc_b.priority = ProcessPriority::Normal;

    sched.add_user_process(
        proc_a,
        Box::new(crate::arch::mmu::AddressSpace::new()?),
        entry_a,
        user_stack_a,
    )?;
    sched.add_user_process(
        proc_b,
        Box::new(crate::arch::mmu::AddressSpace::new()?),
        entry_b,
        user_stack_b,
    )?;

    let flags = VmaFlags::READ | VmaFlags::WRITE | VmaFlags::SHARED;
    sched.map_file_for_pid(pid_a, Some(map_addr), page, flags, source.clone(), 0)?;
    sched.map_file_for_pid(pid_b, Some(map_addr), page, flags, source.clone(), 0)?;

    sched.current_pid = Some(pid_a);
    if !sched.handle_current_user_page_fault(map_addr, 0)? {
        return Err("sharedmmap: first file fault was not handled");
    }
    sched.current_pid = Some(pid_b);
    if !sched.handle_current_user_page_fault(map_addr, 0)? {
        return Err("sharedmmap: second file fault was not handled");
    }

    let phys_a = sched
        .process_info(pid_a, "sharedmmap: process A missing")?
        .address_space
        .as_ref()
        .and_then(|space| space.virt_to_phys(map_addr))
        .ok_or("sharedmmap: process A phys lookup failed")?;
    let phys_b = sched
        .process_info(pid_b, "sharedmmap: process B missing")?
        .address_space
        .as_ref()
        .and_then(|space| space.virt_to_phys(map_addr))
        .ok_or("sharedmmap: process B phys lookup failed")?;
    if phys_a != phys_b {
        return Err("sharedmmap: processes did not share one physical page");
    }

    let old_root = crate::arch::mmu::current_page_table_root_addr();
    let observed = (|| -> Result<u8, &'static str> {
        {
            let info = sched.process_info(pid_a, "sharedmmap: process A missing")?;
            let space = info
                .address_space
                .as_ref()
                .ok_or("sharedmmap: process A address space missing")?;
            unsafe {
                space.activate();
            }
            unsafe {
                (map_addr as *mut u8).write(0x5A);
            }
        }

        {
            let info = sched.process_info(pid_b, "sharedmmap: process B missing")?;
            let space = info
                .address_space
                .as_ref()
                .ok_or("sharedmmap: process B address space missing")?;
            unsafe {
                space.activate();
            }
            Ok(unsafe { (map_addr as *const u8).read() })
        }
    })();
    let restore_result = crate::arch::mmu::set_page_table_root(old_root);
    let observed = observed?;
    restore_result?;

    if observed != 0x5A {
        return Err("sharedmmap: write not visible in second process");
    }

    Ok((phys_a, phys_b, observed))
}

pub fn terminate_current_from_fault() -> ! {
    let flags = unsafe { scheduler_platform::irq_save_disable() };
    let (ctx_ptr, runtime_pid_raw, kernel_stack_top) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let current = sched
            .get_current_pid()
            .expect("terminate_current_from_fault: no current pid");
        let _ = sched.remove_process(current);
        sched.prepare_start_locked()
    };
    let _ = flags;
    QuantumScheduler::launch_prepared_context(ctx_ptr, runtime_pid_raw, kernel_stack_top)
}

pub fn memory_alloc_current(
    requested_addr: Option<usize>,
    size: usize,
    flags: VmaFlags,
) -> Result<usize, &'static str> {
    QUANTUM_SCHEDULER
        .lock()
        .alloc_current_anonymous(requested_addr, size, flags)
}

pub fn memory_free_current(addr: usize, size: usize) -> Result<(), &'static str> {
    QUANTUM_SCHEDULER.lock().free_current_mapping(addr, size)
}

pub fn memory_map_file_current(
    requested_addr: Option<usize>,
    size: usize,
    flags: VmaFlags,
    source: crate::fs::vfs::MappedFileSource,
    offset: usize,
) -> Result<usize, &'static str> {
    QUANTUM_SCHEDULER
        .lock()
        .map_current_file(requested_addr, size, flags, source, offset)
}

pub fn entropy_bench_results() -> [EntropyBenchResult; 3] {
    [
        entropy_bench_result(
            "yield-heavy",
            ProcessPriority::Normal,
            EntropyWindowState {
                ewma_yield: 20,
                ewma_fault: 2,
            },
            24,
            0,
        ),
        entropy_bench_result(
            "fault-heavy",
            ProcessPriority::Normal,
            EntropyWindowState {
                ewma_yield: 2,
                ewma_fault: 20,
            },
            1,
            18,
        ),
        entropy_bench_result(
            "mixed",
            ProcessPriority::Normal,
            EntropyWindowState {
                ewma_yield: 8,
                ewma_fault: 8,
            },
            6,
            5,
        ),
    ]
}

#[cfg(test)]
mod vma_tests {
    use super::{ProcessMemoryMap, Vma, VmaFlags, VmaKind};

    #[test]
    fn vma_insert_preserves_order_and_rejects_overlap() {
        let mut map = ProcessMemoryMap::new(0x4000, 0x4000, 0x8000, 0x20_0000);
        map.insert_vma(Vma {
            start: 0x5000,
            end: 0x6000,
            flags: VmaFlags::READ | VmaFlags::USER,
            kind: VmaKind::Anonymous,
        })
        .unwrap();
        map.insert_vma(Vma {
            start: 0x3000,
            end: 0x4000,
            flags: VmaFlags::READ | VmaFlags::EXEC | VmaFlags::USER,
            kind: VmaKind::KernelSynthetic,
        })
        .unwrap();

        assert_eq!(map.vmas[0].start, 0x3000);
        assert_eq!(map.vmas[1].start, 0x5000);
        assert!(map
            .insert_vma(Vma {
                start: 0x3800,
                end: 0x4800,
                flags: VmaFlags::READ | VmaFlags::USER,
                kind: VmaKind::Anonymous,
            })
            .is_err());
    }

    #[test]
    fn vma_lookup_and_remove_exact_range_work() {
        let mut map = ProcessMemoryMap::new(0x4000, 0x4000, 0x8000, 0x20_0000);
        map.insert_vma(Vma {
            start: 0x7000,
            end: 0x9000,
            flags: VmaFlags::READ | VmaFlags::WRITE | VmaFlags::USER,
            kind: VmaKind::Heap,
        })
        .unwrap();

        assert_eq!(map.find_vma(0x7000).unwrap().end, 0x9000);
        assert_eq!(map.find_vma(0x8fff).unwrap().start, 0x7000);
        assert!(map.find_vma(0x9000).is_none());

        let removed = map.remove_exact_vma(0x7000, 0x9000).unwrap();
        assert_eq!(removed.kind, VmaKind::Heap);
        assert!(map.find_vma(0x7000).is_none());
    }

    #[test]
    fn mark_cow_regions_only_marks_private_writable_memory() {
        let mut map = ProcessMemoryMap::new(0x4000, 0x4000, 0x8000, 0x20_0000);
        map.insert_vma(Vma {
            start: 0x1000,
            end: 0x2000,
            flags: VmaFlags::READ | VmaFlags::WRITE | VmaFlags::USER,
            kind: VmaKind::Anonymous,
        })
        .unwrap();
        map.insert_vma(Vma {
            start: 0x3000,
            end: 0x4000,
            flags: VmaFlags::READ | VmaFlags::WRITE | VmaFlags::USER | VmaFlags::SHARED,
            kind: VmaKind::Anonymous,
        })
        .unwrap();
        map.insert_vma(Vma {
            start: 0x5000,
            end: 0x6000,
            flags: VmaFlags::READ | VmaFlags::EXEC | VmaFlags::USER,
            kind: VmaKind::KernelSynthetic,
        })
        .unwrap();

        map.mark_cow_regions();

        assert!(map.vmas[0].flags.contains(VmaFlags::COW));
        assert!(!map.vmas[1].flags.contains(VmaFlags::COW));
        assert!(!map.vmas[2].flags.contains(VmaFlags::COW));
    }
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
pub fn kernel_stack_bounds() -> [(usize, usize); 4] {
    unsafe {
        let s0 = core::ptr::addr_of!(KERNEL_STACK_0.data) as *const u8 as usize;
        let e0 = s0 + KERNEL_THREAD_STACK_BYTES;
        let s1 = core::ptr::addr_of!(KERNEL_STACK_1.data) as *const u8 as usize;
        let e1 = s1 + KERNEL_THREAD_STACK_BYTES;
        let s2 = core::ptr::addr_of!(KERNEL_STACK_2.data) as *const u8 as usize;
        let e2 = s2 + KERNEL_THREAD_STACK_BYTES;
        let s3 = core::ptr::addr_of!(KERNEL_STACK_3.data) as *const u8 as usize;
        let e3 = s3 + KERNEL_THREAD_STACK_BYTES;
        [(s0, e0), (s1, e1), (s2, e2), (s3, e3)]
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

/// Perform a deferred reschedule from normal kernel context.
///
/// The timer IRQ only marks that scheduling work is needed. Architectures that
/// do not switch directly from the interrupt frame can call this at safe points
/// inside long-running kernel loops to honor preemption requests.
pub fn maybe_reschedule() {
    if !SCHEDULER_STARTED.load(Ordering::Acquire) {
        return;
    }
    if !RESCHED_REQUEST.swap(false, Ordering::AcqRel) {
        return;
    }

    let flags = unsafe { scheduler_platform::irq_save_disable() };
    let (switch, next_runtime_pid, next_kernel_stack_top) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let switch = sched.schedule();
        let next_runtime_pid = sched.current_runtime_pid_raw();
        let next_kernel_stack_top = sched.current_kernel_stack_top();
        (switch, next_runtime_pid, next_kernel_stack_top)
    };

    if let Some((from_ptr, to_ptr)) = switch {
        if let Some(pid_raw) = next_runtime_pid {
            scheduler_platform::runtime_pid_sync(pid_raw);
        }
        if let Some(stack_top) = next_kernel_stack_top {
            scheduler_platform::runtime_kernel_stack_sync(stack_top);
        }
        unsafe {
            // The scheduler lock is dropped and interrupts are masked, so the arch backend
            // can atomically swap register sets using the prepared raw context pointers.
            scheduler_platform::switch_context(from_ptr, to_ptr);
        }
        unsafe { scheduler_platform::irq_restore(flags) };
    } else {
        unsafe { scheduler_platform::irq_restore(flags) };
    }
}

/// Block the current process until `wake_time` and switch away immediately.
pub fn sleep_until(pid: Pid, wake_time: u64) -> Result<(), &'static str> {
    let flags = unsafe { scheduler_platform::irq_save_disable() };
    let (result, next_runtime_pid, next_kernel_stack_top) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let result = sched.block_process(pid, wake_time);
        let next_runtime_pid = sched.current_runtime_pid_raw();
        let next_kernel_stack_top = sched.current_kernel_stack_top();
        (result, next_runtime_pid, next_kernel_stack_top)
    };
    match result {
        Ok(Some((from_ptr, to_ptr))) => {
            if let Some(pid_raw) = next_runtime_pid {
                scheduler_platform::runtime_pid_sync(pid_raw);
            }
            if let Some(stack_top) = next_kernel_stack_top {
                scheduler_platform::runtime_kernel_stack_sync(stack_top);
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                let mut cr0: u32;
                core::arch::asm!("mov {0}, cr0", out(reg) cr0);
                cr0 |= 8;
                core::arch::asm!("mov cr0, {0}", in(reg) cr0);
            }
            unsafe {
                // The sleep queue state is already committed under the scheduler lock, so
                // this raw switch only transfers execution to the selected runnable task.
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
    let (switch, next_runtime_pid, next_kernel_stack_top) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let switch = sched.yield_cpu();
        let next_runtime_pid = sched.current_runtime_pid_raw();
        let next_kernel_stack_top = sched.current_kernel_stack_top();
        (switch, next_runtime_pid, next_kernel_stack_top)
    };
    if let Some((from_ptr, to_ptr)) = switch {
        if let Some(pid_raw) = next_runtime_pid {
            scheduler_platform::runtime_pid_sync(pid_raw);
        }
        if let Some(stack_top) = next_kernel_stack_top {
            scheduler_platform::runtime_kernel_stack_sync(stack_top);
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
            // Yield has already published the outgoing task as Ready; the arch switch only
            // consumes the raw contexts selected by the scheduler core.
            scheduler_platform::switch_context(from_ptr, to_ptr);
        }
        // When this thread is resumed, restore its original interrupt state.
        unsafe { scheduler_platform::irq_restore(flags) };
    } else {
        unsafe { scheduler_platform::irq_restore(flags) };
    }
}

/// Re-enqueue a PID into the ready queues (used by job control `fg`).
pub fn enqueue_ready_pid(pid: Pid, priority: ProcessPriority) {
    let mut sched = QUANTUM_SCHEDULER.lock();
    if let Some(info) = sched.get_process_info_mut(pid) {
        info.process.state = ProcessState::Ready;
    }
    sched.enqueue_ready(pid, priority);
}

/// Block on address (futex-like)
pub fn block_on(addr: usize) -> Result<(), &'static str> {
    let plan = prepare_block_on(addr, ProcessState::Blocked)?;
    commit_block(plan);
    Ok(())
}

pub fn prepare_block_custom(wait_state: ProcessState) -> Result<(Pid, BlockOnPlan), &'static str> {
    let irq_flags = unsafe { scheduler_platform::irq_save_disable() };
    let pid = {
        let sched = QUANTUM_SCHEDULER.lock();
        if let Some(pid) = sched.current_pid {
            // Also might want to check if process exists and wait state is valid?
            pid
        } else {
            unsafe { scheduler_platform::irq_restore(irq_flags) };
            return Err("No current process");
        }
    };

    Ok((
        pid,
        BlockOnPlan {
            irq_flags,
            action: BlockAction::Custom(wait_state),
            is_committed: false,
        },
    ))
}

pub fn prepare_block_on(
    addr: usize,
    wait_state: ProcessState,
) -> Result<BlockOnPlan, &'static str> {
    let irq_flags = unsafe { scheduler_platform::irq_save_disable() };
    {
        let sched = QUANTUM_SCHEDULER.lock();
        if sched.current_pid.is_none() {
            unsafe { scheduler_platform::irq_restore(irq_flags) };
            return Err("No current process");
        }
    }

    Ok(BlockOnPlan {
        irq_flags,
        action: BlockAction::OnAddr(addr, wait_state),
        is_committed: false,
    })
}

pub fn commit_block(mut plan: BlockOnPlan) {
    plan.is_committed = true;

    let (switch_opt, next_runtime_pid, next_kernel_stack_top) = {
        let mut sched = QUANTUM_SCHEDULER.lock();
        let result = match plan.action {
            BlockAction::Custom(state) => sched.block_current_process_custom(state),
            BlockAction::OnAddr(addr, state) => sched.block_on_with_state(addr, state),
        };
        match result {
            Ok(switch) => (
                switch,
                sched.current_runtime_pid_raw(),
                sched.current_kernel_stack_top(),
            ),
            Err(_) => (
                None,
                sched.current_runtime_pid_raw(),
                sched.current_kernel_stack_top(),
            ),
        }
    };

    match switch_opt {
        Some((from_ptr, to_ptr)) => {
            if let Some(pid_raw) = next_runtime_pid {
                scheduler_platform::runtime_pid_sync(pid_raw);
            }
            if let Some(stack_top) = next_kernel_stack_top {
                scheduler_platform::runtime_kernel_stack_sync(stack_top);
            }
            #[cfg(target_arch = "x86")]
            unsafe {
                let mut cr0: u32;
                core::arch::asm!("mov {0}, cr0", out(reg) cr0);
                cr0 |= 8; // Set TS bit
                core::arch::asm!("mov cr0, {0}", in(reg) cr0);
            }
            unsafe {
                // Blocking state is committed before we leave the scheduler; the backend now
                // owns both raw context pointers for the actual architectural swap.
                scheduler_platform::switch_context(from_ptr, to_ptr);
            }
            unsafe { scheduler_platform::irq_restore(plan.irq_flags) };
        }
        None => unsafe { scheduler_platform::irq_restore(plan.irq_flags) },
    }
}

pub fn wake_process(pid: Pid) -> Result<bool, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_process(pid)
}

/// Wake one waiter on address
pub fn wake_one(addr: usize) -> Result<bool, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_one(addr)
}

/// Wake all waiters on address
pub fn wake_all(addr: usize) -> Result<usize, &'static str> {
    QUANTUM_SCHEDULER.lock().wake_all(addr)
}

/// Count non-sleep waiters on an address.
pub fn waiter_count(addr: usize) -> usize {
    QUANTUM_SCHEDULER.lock().waiter_count(addr)
}

/// Stage a synthetic waiting process for deterministic runtime selftests.
pub(crate) fn selftest_stage_waiter_process(
    name: &str,
    addr: usize,
    wait_state: ProcessState,
) -> Result<Pid, &'static str> {
    let mut sched = QUANTUM_SCHEDULER.lock();
    let pid = (1..MAX_PROCESSES)
        .rev()
        .find_map(|idx| {
            if sched.processes[idx].is_none() {
                Some(Pid(idx as u32))
            } else {
                None
            }
        })
        .ok_or("No free process slots for synthetic waiter")?;

    let mut process = Process::new(pid, name, None);
    process.priority = ProcessPriority::Low;
    sched.add_process(process)?;
    sched.remove_from_ready_queues(pid);
    sched.remove_from_wait_queues(pid);
    if sched.current_pid == Some(pid) {
        sched.current_pid = None;
    }
    let queue_idx = sched.find_or_create_wait_queue(addr)?;
    sched.wait_queues[queue_idx].waiting.push_back(pid);
    if let Some(info) = sched.processes[pid.0 as usize].as_mut() {
        info.process.state = wait_state;
    }
    sched.record_temporal_state_snapshot_locked(scheduler_rt::TEMPORAL_SCHEDULER_EVENT_STATE);
    Ok(pid)
}

/// Remove a synthetic process previously staged for runtime selftests.
pub(crate) fn selftest_remove_process(pid: Pid) -> Result<(), &'static str> {
    QUANTUM_SCHEDULER.lock().remove_process(pid)
}

/// Inspect the scheduler-visible state of a synthetic selftest process.
pub(crate) fn selftest_process_state(pid: Pid) -> Option<ProcessState> {
    let sched = QUANTUM_SCHEDULER.lock();
    sched
        .processes
        .get(pid.0 as usize)
        .and_then(|info| info.as_ref().map(|info| info.process.state))
}

#[cfg(test)]
pub fn test_reset() {
    let mut sched = QUANTUM_SCHEDULER.lock();
    *sched = QuantumScheduler::new();
    SCHEDULER_STARTED.store(false, Ordering::Release);
    RESCHED_REQUEST.store(false, Ordering::Release);
}

#[cfg(test)]
pub fn test_add_process(pid_raw: u32, name: &str) -> Result<(), &'static str> {
    let mut process = Process::new(Pid(pid_raw), name, None);
    process.priority = ProcessPriority::Normal;
    QUANTUM_SCHEDULER.lock().add_process(process)
}

#[cfg(test)]
pub fn test_stage_waiter(
    pid_raw: u32,
    addr: usize,
    wait_state: ProcessState,
) -> Result<(), &'static str> {
    let mut sched = QUANTUM_SCHEDULER.lock();
    let pid = Pid(pid_raw);
    let idx = pid.0 as usize;
    if sched.processes[idx].is_none() {
        return Err("test_stage_waiter: process missing");
    }
    sched.remove_from_ready_queues(pid);
    sched.remove_from_wait_queues(pid);
    if sched.current_pid == Some(pid) {
        sched.current_pid = None;
    }
    let queue_idx = sched.find_or_create_wait_queue(addr)?;
    sched.wait_queues[queue_idx].waiting.push_back(pid);
    if let Some(info) = sched.processes[idx].as_mut() {
        info.process.state = wait_state;
    }
    Ok(())
}

#[cfg(test)]
pub fn test_process_state(pid_raw: u32) -> Option<ProcessState> {
    selftest_process_state(Pid(pid_raw))
}

/// Global hook for Device Not Available (FPU) trap
pub fn handle_fpu_trap() {
    unsafe {
        QUANTUM_SCHEDULER.lock().handle_fpu_trap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_helpers_are_canonical() {
        assert_eq!(priority_to_queue_idx(ProcessPriority::High), 0);
        assert_eq!(priority_to_queue_idx(ProcessPriority::Normal), 1);
        assert_eq!(priority_to_queue_idx(ProcessPriority::Low), 2);

        assert_eq!(
            base_quantum_for_priority(ProcessPriority::High),
            QUANTUM_HIGH
        );
        assert_eq!(
            base_quantum_for_priority(ProcessPriority::Normal),
            QUANTUM_NORMAL
        );
        assert_eq!(base_quantum_for_priority(ProcessPriority::Low), QUANTUM_LOW);
    }

    #[test]
    fn ready_queue_wraparound_and_full_behavior() {
        let mut queue = ReadyQueue::new();
        assert!(queue.push_back(Pid(1)));
        assert!(queue.push_back(Pid(2)));
        assert_eq!(queue.pop_front(), Some(Pid(1)));
        assert!(queue.push_back(Pid(3)));
        assert_eq!(queue.pop_front(), Some(Pid(2)));
        assert_eq!(queue.pop_front(), Some(Pid(3)));
        assert_eq!(queue.pop_front(), None);

        let mut full = ReadyQueue::new();
        for i in 0..MAX_PROCESSES {
            assert!(full.push_back(Pid(i as u32)));
        }
        assert!(!full.push_back(Pid(MAX_PROCESSES as u32)));
        for i in 0..MAX_PROCESSES {
            assert_eq!(full.pop_front(), Some(Pid(i as u32)));
        }
        assert_eq!(full.pop_front(), None);
    }

    #[test]
    fn kernel_thread_frame_top_accepts_valid_range() {
        assert_eq!(kernel_thread_frame_top(0x2000, 0x3000, 16).unwrap(), 0x2ff0);
    }

    #[test]
    fn kernel_thread_frame_top_rejects_underflow() {
        assert_eq!(
            kernel_thread_frame_top(0x2000, 8, 16),
            Err("Stack address invalid")
        );
    }

    #[test]
    fn kernel_thread_frame_top_rejects_frame_below_stack_base() {
        assert_eq!(
            kernel_thread_frame_top(0x2000, 0x2008, 16),
            Err("Stack address invalid")
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "kernel_thread_frame_top requires 16-byte aligned stack_top")]
    fn kernel_thread_frame_top_requires_aligned_stack_top() {
        let _ = kernel_thread_frame_top(0x2000, 0x2fff, 16);
    }

    #[test]
    #[should_panic(expected = "ReadyQueue invariant violated")]
    fn ready_queue_panics_on_corruption() {
        let mut queue = ReadyQueue::new();
        queue.len = MAX_PROCESSES + 1;
        let _ = queue.len();
    }

    #[test]
    fn entropy_roll_zero_inputs_stays_zero() {
        let rolled = roll_entropy_window(
            EntropyWindowState {
                ewma_yield: 0,
                ewma_fault: 0,
            },
            0,
            0,
        );
        assert_eq!(
            rolled,
            EntropyWindowState {
                ewma_yield: 0,
                ewma_fault: 0,
            }
        );
        assert_eq!(
            entropy_adjusted_quantum(ProcessPriority::Normal, rolled),
            QUANTUM_NORMAL
        );
    }

    #[test]
    fn entropy_high_yield_low_fault_rewards_quantum() {
        let rolled = roll_entropy_window(
            EntropyWindowState {
                ewma_yield: 40,
                ewma_fault: 0,
            },
            24,
            0,
        );
        let adjusted = entropy_adjusted_quantum(ProcessPriority::Normal, rolled);
        assert!(adjusted > QUANTUM_NORMAL);
        assert!(adjusted <= QUANTUM_HIGH);
    }

    #[test]
    fn entropy_low_yield_high_fault_penalizes_quantum() {
        let rolled = roll_entropy_window(
            EntropyWindowState {
                ewma_yield: 0,
                ewma_fault: 48,
            },
            0,
            24,
        );
        let adjusted = entropy_adjusted_quantum(ProcessPriority::Normal, rolled);
        assert!(adjusted < QUANTUM_NORMAL);
        assert!(adjusted >= QUANTUM_LOW);
    }

    #[test]
    fn entropy_quantum_clamps_to_bounds() {
        let reward_clamped = compute_entropy_quantum(512, 0, QUANTUM_NORMAL);
        let penalty_clamped = compute_entropy_quantum(0, 512, QUANTUM_NORMAL);
        assert_eq!(reward_clamped, QUANTUM_HIGH);
        assert_eq!(penalty_clamped, QUANTUM_LOW);
    }

    #[test]
    fn entropy_rolls_repeated_windows_consistently() {
        let first = roll_entropy_window(
            EntropyWindowState {
                ewma_yield: 0,
                ewma_fault: 0,
            },
            64,
            16,
        );
        let second = roll_entropy_window(first, 64, 16);
        assert_eq!(
            first,
            EntropyWindowState {
                ewma_yield: 8,
                ewma_fault: 2,
            }
        );
        assert_eq!(
            second,
            EntropyWindowState {
                ewma_yield: 15,
                ewma_fault: 3,
            }
        );
    }

    #[test]
    fn entropy_adjustment_uses_rolled_fault_ewma_consistently() {
        let rolled = roll_entropy_window(
            EntropyWindowState {
                ewma_yield: 32,
                ewma_fault: 64,
            },
            4,
            0,
        );
        let adjusted = entropy_adjusted_quantum(ProcessPriority::Normal, rolled);
        let mixed_source = compute_entropy_quantum(
            rolled.ewma_yield,
            0,
            base_quantum_for_priority(ProcessPriority::Normal),
        );
        assert_eq!(
            adjusted,
            compute_entropy_quantum(
                rolled.ewma_yield,
                rolled.ewma_fault,
                base_quantum_for_priority(ProcessPriority::Normal),
            )
        );
        assert_ne!(adjusted, mixed_source);
    }

    #[test]
    fn block_process_requires_existing_current_process() {
        let mut scheduler = QuantumScheduler::new();
        scheduler.current_pid = Some(Pid(7));
        assert_eq!(
            scheduler.block_process(Pid(7), 42),
            Err(ERR_BLOCK_PROCESS_CURRENT_PROCESS_MISSING)
        );
        assert_eq!(scheduler.wait_queue_count, 0);
    }

    #[test]
    fn exec_current_wasm_requires_existing_current_process() {
        let mut scheduler = QuantumScheduler::new();
        scheduler.current_pid = Some(Pid(3));
        assert_eq!(
            scheduler.exec_current_wasm(99),
            Err(ERR_EXEC_CURRENT_WASM_CURRENT_PROCESS_MISSING)
        );
    }
}
