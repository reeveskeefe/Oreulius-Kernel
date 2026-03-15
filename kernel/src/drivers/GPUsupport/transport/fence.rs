/*!
 * GPU fence — allocation, signaling, polling, and cooperative wait.
 *
 * # Design
 * Fences are lightweight 16-byte structs that carry an ID and a state.
 * The ID is allocated from a global monotonically-increasing counter so
 * IDs are never reused.
 *
 * Two wait strategies are provided:
 *
 * - `poll()` — returns the current state without blocking (use from IRQ
 *   context or when the caller already expects the fence to be done).
 *
 * - `spin_wait(max_ticks)` — spins for up to `max_ticks` iterations
 *   checking the fence table.  This is the correct strategy in kernel
 *   cooperative contexts where IRQs are not yet fully operational.
 *
 * The global `FenceTable` stores the mutable state for all outstanding
 * fences.  `GpuFence` itself is `Copy` (it is a snapshot); canonical state
 * always lives in the table.
 */

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use crate::drivers::gpu_support::telemetry::counters;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_LIVE_FENCES: usize = 128;

/// Number of spin iterations per "tick" in `spin_wait`.
const SPIN_ITER_PER_TICK: usize = 1_000;

// ---------------------------------------------------------------------------
// ID allocator
// ---------------------------------------------------------------------------

static NEXT_FENCE_ID: AtomicU32 = AtomicU32::new(1);

fn alloc_fence_id() -> u64 {
    NEXT_FENCE_ID.fetch_add(1, Ordering::Relaxed) as u64
}

// ---------------------------------------------------------------------------
// FenceState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceState {
    Pending,
    Signaled,
    Error,
}

// ---------------------------------------------------------------------------
// GpuFence — value type (snapshot of state)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuFence {
    pub id:    u64,
    pub state: FenceState,
}

impl GpuFence {
    /// Allocate a new pending fence and register it in the global table.
    pub fn alloc() -> Self {
        let id = alloc_fence_id();
        let fence = GpuFence { id, state: FenceState::Pending };
        FENCE_TABLE.lock().register(fence);
        fence
    }

    /// Construct a pre-signaled fence with the given ID (for testing /
    /// cache-hit paths where work is already complete).
    pub const fn signaled(id: u64) -> Self {
        GpuFence { id, state: FenceState::Signaled }
    }

    // -----------------------------------------------------------------------
    // State queries
    // -----------------------------------------------------------------------

    pub fn is_pending(&self)  -> bool { self.state == FenceState::Pending  }
    pub fn is_signaled(&self) -> bool { self.state == FenceState::Signaled }
    pub fn is_error(&self)    -> bool { self.state == FenceState::Error    }

    // -----------------------------------------------------------------------
    // Polling — reads current state from the global table
    // -----------------------------------------------------------------------

    /// Return the current state of this fence from the global table.
    pub fn poll(&self) -> FenceState {
        FENCE_TABLE.lock().state(self.id)
    }

    // -----------------------------------------------------------------------
    // Signaling (called by the driver / IRQ path)
    // -----------------------------------------------------------------------

    /// Signal this fence as complete.
    pub fn signal(&self) {
        FENCE_TABLE.lock().signal(self.id);
    }

    /// Mark this fence as errored (e.g. engine hang).
    pub fn mark_error(&self) {
        FENCE_TABLE.lock().error(self.id);
    }

    // -----------------------------------------------------------------------
    // Cooperative wait
    // -----------------------------------------------------------------------

    /// Spin-wait for up to `max_ticks` cooperative ticks.
    ///
    /// Each tick performs `SPIN_ITER_PER_TICK` busy-wait iterations while
    /// polling the fence table.  Returns the final state.
    ///
    /// In a fully interrupt-driven kernel the caller should use a scheduler
    /// yield instead; this cooperative spin is the correct approach while
    /// the timer subsystem is still initializing.
    pub fn spin_wait(&self, max_ticks: usize) -> FenceState {
        for _ in 0..max_ticks {
            for _ in 0..SPIN_ITER_PER_TICK {
                core::hint::spin_loop();
            }
            let state = self.poll();
            if state != FenceState::Pending {
                return state;
            }
        }
        // Timed out — still pending; record a stall.
        counters::GPU_FENCE_STALLS.fetch_add(1, Ordering::Relaxed);
        FenceState::Pending
    }
}

// ---------------------------------------------------------------------------
// FenceTable — global mutable state for all outstanding fences
// ---------------------------------------------------------------------------

struct FenceEntry {
    id:     u64,
    state:  FenceState,
    active: bool,
}

struct FenceTable {
    slots: [FenceEntry; MAX_LIVE_FENCES],
    count: usize,
}

impl FenceTable {
    const fn new() -> Self {
        const EMPTY: FenceEntry = FenceEntry { id: 0, state: FenceState::Pending, active: false };
        FenceTable {
            slots: [EMPTY; MAX_LIVE_FENCES],
            count: 0,
        }
    }

    fn register(&mut self, fence: GpuFence) {
        // Evict old signaled/errored entries if full.
        if self.count >= MAX_LIVE_FENCES {
            self.gc();
        }
        for slot in self.slots.iter_mut() {
            if !slot.active {
                slot.id     = fence.id;
                slot.state  = fence.state;
                slot.active = true;
                self.count += 1;
                return;
            }
        }
        // Table completely full of pending fences — this is a resource leak
        // in the caller; drop the registration (fence stays pending forever).
    }

    fn state(&self, id: u64) -> FenceState {
        for slot in self.slots.iter() {
            if slot.active && slot.id == id {
                return slot.state;
            }
        }
        // Unknown fence — treat as signaled to avoid deadlock.
        FenceState::Signaled
    }

    fn signal(&mut self, id: u64) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.id == id {
                slot.state = FenceState::Signaled;
                return;
            }
        }
    }

    fn error(&mut self, id: u64) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.id == id {
                slot.state = FenceState::Error;
                return;
            }
        }
    }

    /// Garbage-collect completed (Signaled / Error) entries.
    fn gc(&mut self) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.state != FenceState::Pending {
                slot.active = false;
                if self.count > 0 { self.count -= 1; }
            }
        }
    }

    fn live_count(&self) -> usize { self.count }
}

static FENCE_TABLE: Mutex<FenceTable> = Mutex::new(FenceTable::new());

/// Return the number of live (pending) fence registrations.
pub fn live_fence_count() -> usize {
    FENCE_TABLE.lock().live_count()
}

/// Manually signal a fence by ID (for use by interrupt handlers that hold no
/// `GpuFence` value).
pub fn signal_by_id(id: u64) {
    FENCE_TABLE.lock().signal(id);
}

/// Mark a fence as errored by ID (for engine-hang recovery paths).
pub fn error_by_id(id: u64) {
    FENCE_TABLE.lock().error(id);
}


