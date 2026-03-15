/*!
 * GPU engine scheduler — fixed-capacity submission ring.
 *
 * The scheduler manages an ordered ring of pending `CommandPacket`s with
 * associated `GpuFence` handles.  It enforces a hard cap on in-flight work
 * (`max_inflight`) and exposes a simple cooperative drain model: the driver
 * tick calls `drain_one()` to retire completed work when the fence signals.
 *
 * # Design
 * - No heap: ring is a fixed-size array of `Option<SchedulerSlot>`.
 * - Single-owner: the GPU service holds one `GpuScheduler` per engine.
 * - No thread safety primitives inside — the owning service is responsible
 *   for external locking (spin::Mutex at the service level).
 *
 * # Priorities
 * Packets carry a `SchedulerPriority`.  Higher-priority slots are drained
 * before lower-priority ones.  Within the same priority level the ring is
 * FIFO.
 */

use super::packets::CommandPacket;
use crate::drivers::gpu_support::errors::GpuError;
use crate::drivers::gpu_support::transport::fence::{FenceState, GpuFence};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_SCHEDULER_SLOTS: usize = 64;

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchedulerPriority {
    Low    = 0,
    Normal = 1,
    High   = 2,
}

// ---------------------------------------------------------------------------
// Slot
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SchedulerSlot {
    packet:   CommandPacket,
    fence:    GpuFence,
    priority: SchedulerPriority,
    active:   bool,
}

impl SchedulerSlot {
    const EMPTY: Self = Self {
        packet:   CommandPacket::Transfer(super::packets::TransferPacket {
            src_bo: 0,
            dst_bo: 0,
            bytes:  0,
        }),
        fence:    GpuFence { id: 0, state: FenceState::Signaled },
        priority: SchedulerPriority::Normal,
        active:   false,
    };
}

// ---------------------------------------------------------------------------
// Drain result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    /// A slot was retired; its fence is returned.
    Retired(GpuFence),
    /// All slots are still pending.
    NothingReady,
    /// The ring is empty.
    Empty,
}

// ---------------------------------------------------------------------------
// GpuScheduler
// ---------------------------------------------------------------------------

pub struct GpuScheduler {
    pub max_inflight: u16,
    ring:     [SchedulerSlot; MAX_SCHEDULER_SLOTS],
    len:      usize,
    head:     usize,   // next write position
    inflight: u16,
}

impl GpuScheduler {
    pub const fn new(max_inflight: u16) -> Self {
        GpuScheduler {
            max_inflight,
            ring:     [SchedulerSlot::EMPTY; MAX_SCHEDULER_SLOTS],
            len:      0,
            head:     0,
            inflight: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Submission
    // -----------------------------------------------------------------------

    /// Enqueue a packet with the given priority.
    ///
    /// Returns the fence that will be signaled when the packet is retired, or
    /// `GpuError::InvalidPacket` if the ring is full or the inflight cap is
    /// reached.
    pub fn enqueue(
        &mut self,
        packet: CommandPacket,
        priority: SchedulerPriority,
        fence: GpuFence,
    ) -> Result<GpuFence, GpuError> {
        if self.inflight >= self.max_inflight {
            return Err(GpuError::InvalidPacket);
        }
        if self.len >= MAX_SCHEDULER_SLOTS {
            return Err(GpuError::InvalidPacket);
        }
        // Insert into ring — maintain priority ordering by scanning from head
        // backwards to find the insertion point for this priority level.
        let insert = self.find_insert_pos(priority);
        // Shift entries up to make room at `insert`.
        for i in (insert..self.head).rev() {
            let next = (i + 1) % MAX_SCHEDULER_SLOTS;
            self.ring[next] = self.ring[i];
        }
        self.ring[insert] = SchedulerSlot { packet, fence, priority, active: true };
        self.head = (self.head + 1) % MAX_SCHEDULER_SLOTS;
        self.len += 1;
        self.inflight += 1;
        Ok(fence)
    }

    // -----------------------------------------------------------------------
    // Draining
    // -----------------------------------------------------------------------

    /// Retire the next ready slot (highest-priority, oldest FIFO within tier).
    ///
    /// A slot is "ready" when its fence is in `Signaled` or `Error` state.
    /// Call this periodically from the driver tick.
    pub fn drain_one(&mut self) -> DrainResult {
        if self.len == 0 {
            return DrainResult::Empty;
        }
        // Scan from the start of the ring for the first signaled slot.
        let start = (self.head + MAX_SCHEDULER_SLOTS - self.len) % MAX_SCHEDULER_SLOTS;
        for i in 0..self.len {
            let idx = (start + i) % MAX_SCHEDULER_SLOTS;
            if !self.ring[idx].active {
                continue;
            }
            match self.ring[idx].fence.state {
                FenceState::Signaled | FenceState::Error => {
                    let fence = self.ring[idx].fence;
                    self.ring[idx].active = false;
                    self.len -= 1;
                    if self.inflight > 0 {
                        self.inflight -= 1;
                    }
                    return DrainResult::Retired(fence);
                }
                FenceState::Pending => {}
            }
        }
        DrainResult::NothingReady
    }

    /// Signal a fence by ID and mark the corresponding slot as complete.
    ///
    /// Called by the interrupt handler or the driver tick after hardware
    /// reports completion.
    pub fn signal_fence(&mut self, fence_id: u64) {
        let start = (self.head + MAX_SCHEDULER_SLOTS - self.len) % MAX_SCHEDULER_SLOTS;
        for i in 0..self.len {
            let idx = (start + i) % MAX_SCHEDULER_SLOTS;
            if self.ring[idx].active && self.ring[idx].fence.id == fence_id {
                self.ring[idx].fence.state = FenceState::Signaled;
                return;
            }
        }
    }

    /// Mark a fence as errored (e.g. on engine hang detection).
    pub fn error_fence(&mut self, fence_id: u64) {
        let start = (self.head + MAX_SCHEDULER_SLOTS - self.len) % MAX_SCHEDULER_SLOTS;
        for i in 0..self.len {
            let idx = (start + i) % MAX_SCHEDULER_SLOTS;
            if self.ring[idx].active && self.ring[idx].fence.id == fence_id {
                self.ring[idx].fence.state = FenceState::Error;
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    pub fn inflight_count(&self) -> u16 { self.inflight }
    pub fn pending_count(&self)  -> usize { self.len }
    pub fn is_full(&self)        -> bool { self.inflight >= self.max_inflight }
    pub fn is_empty(&self)       -> bool { self.len == 0 }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Find the ring index at which a new packet of `priority` should be
    /// inserted to maintain descending priority ordering.
    fn find_insert_pos(&self, priority: SchedulerPriority) -> usize {
        if self.len == 0 {
            return self.head % MAX_SCHEDULER_SLOTS;
        }
        // The active window runs from `tail` to `head` in ring order.
        let tail = (self.head + MAX_SCHEDULER_SLOTS - self.len) % MAX_SCHEDULER_SLOTS;
        // Scan for the first slot whose priority is strictly less than ours.
        for i in 0..self.len {
            let idx = (tail + i) % MAX_SCHEDULER_SLOTS;
            if self.ring[idx].active && self.ring[idx].priority < priority {
                return idx;
            }
        }
        // Insert at the current head (end of the ring window).
        self.head % MAX_SCHEDULER_SLOTS
    }
}


