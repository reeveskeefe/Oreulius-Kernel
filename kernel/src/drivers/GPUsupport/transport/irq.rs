/*!
 * GPU interrupt bookkeeping — handler registration and dispatch.
 *
 * The GPU subsystem registers a single top-half handler per IRQ line.
 * When the platform interrupt dispatcher fires, it calls `dispatch(irq_line)`
 * which finds the registered handler and invokes it.
 *
 * Each handler returns a `GpuInterruptStatus` indicating which events
 * occurred; the caller is responsible for signaling affected fences.
 *
 * # Design
 * - Fixed-capacity table of `MAX_GPU_IRQ_HANDLERS` entries.
 * - One entry per registered GPU IRQ line (GPUs rarely use more than 2).
 * - The table is protected by a `spin::Mutex`; handlers must be short
 *   (signal fences, update counters — not blocking operations).
 */

use spin::Mutex;

use super::fence;
use crate::drivers::gpu_support::telemetry::counters;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MAX_GPU_IRQ_HANDLERS: usize = 8;

// ---------------------------------------------------------------------------
// GpuInterruptStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuInterruptStatus {
    pub fence_complete:   bool,
    pub page_fault:       bool,
    pub engine_hang:      bool,
    pub completed_fence:  Option<u64>,   // fence ID if fence_complete
    pub hung_fence:       Option<u64>,   // fence ID if engine_hang
}

impl GpuInterruptStatus {
    pub const fn empty() -> Self {
        GpuInterruptStatus {
            fence_complete:  false,
            page_fault:      false,
            engine_hang:     false,
            completed_fence: None,
            hung_fence:      None,
        }
    }

    pub fn with_fence_complete(fence_id: u64) -> Self {
        GpuInterruptStatus {
            fence_complete:  true,
            completed_fence: Some(fence_id),
            ..Self::empty()
        }
    }

    pub fn with_engine_hang(fence_id: u64) -> Self {
        GpuInterruptStatus {
            engine_hang:  true,
            hung_fence:   Some(fence_id),
            ..Self::empty()
        }
    }

    pub fn with_page_fault() -> Self {
        GpuInterruptStatus {
            page_fault: true,
            ..Self::empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Handler type
// ---------------------------------------------------------------------------

/// Top-half GPU IRQ handler signature.
///
/// Implementations should:
/// 1. Read the device's interrupt status register to determine cause.
/// 2. Clear the interrupt in hardware.
/// 3. Return a `GpuInterruptStatus` summary.
///
/// The IRQ dispatcher will translate the returned status into fence signals
/// and telemetry updates automatically.
pub type GpuIrqHandler = fn(irq_line: u8) -> GpuInterruptStatus;

// ---------------------------------------------------------------------------
// Handler table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct IrqEntry {
    irq_line: u8,
    handler:  GpuIrqHandler,
    active:   bool,
}

impl IrqEntry {
    const EMPTY: Self = IrqEntry {
        irq_line: 0,
        handler:  default_handler,
        active:   false,
    };
}

fn default_handler(_irq: u8) -> GpuInterruptStatus {
    GpuInterruptStatus::empty()
}

struct IrqTable {
    entries: [IrqEntry; MAX_GPU_IRQ_HANDLERS],
    count:   usize,
}

impl IrqTable {
    const fn new() -> Self {
        IrqTable {
            entries: [IrqEntry::EMPTY; MAX_GPU_IRQ_HANDLERS],
            count:   0,
        }
    }

    fn register(&mut self, irq_line: u8, handler: GpuIrqHandler) -> bool {
        // Update existing registration for this IRQ line.
        for entry in self.entries.iter_mut() {
            if entry.active && entry.irq_line == irq_line {
                entry.handler = handler;
                return true;
            }
        }
        // New registration.
        if self.count >= MAX_GPU_IRQ_HANDLERS {
            return false;
        }
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.irq_line = irq_line;
                entry.handler  = handler;
                entry.active   = true;
                self.count += 1;
                return true;
            }
        }
        false
    }

    fn unregister(&mut self, irq_line: u8) {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.irq_line == irq_line {
                entry.active = false;
                if self.count > 0 { self.count -= 1; }
                return;
            }
        }
    }

    fn dispatch(&self, irq_line: u8) -> GpuInterruptStatus {
        for entry in self.entries.iter() {
            if entry.active && entry.irq_line == irq_line {
                return (entry.handler)(irq_line);
            }
        }
        GpuInterruptStatus::empty()
    }
}

static IRQ_TABLE: Mutex<IrqTable> = Mutex::new(IrqTable::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register a top-half GPU IRQ handler for `irq_line`.
///
/// Returns `true` on success, `false` if the table is full.
pub fn register_handler(irq_line: u8, handler: GpuIrqHandler) -> bool {
    IRQ_TABLE.lock().register(irq_line, handler)
}

/// Unregister the handler for `irq_line`.
pub fn unregister_handler(irq_line: u8) {
    IRQ_TABLE.lock().unregister(irq_line);
}

/// Platform IRQ dispatcher entry point.
///
/// Called from the platform interrupt path with the IRQ line number.
/// Invokes the registered handler, then translates the status into fence
/// signals and telemetry updates.
pub fn dispatch(irq_line: u8) {
    let status = IRQ_TABLE.lock().dispatch(irq_line);
    process_status(status);
}

/// Process a `GpuInterruptStatus` — signal fences and update counters.
///
/// Also callable directly from soft-IRQ / polling paths.
pub fn process_status(status: GpuInterruptStatus) {
    if status.fence_complete {
        counters::GPU_QUEUE_SUBMITS.fetch_add(0, core::sync::atomic::Ordering::Relaxed);
        if let Some(id) = status.completed_fence {
            fence::signal_by_id(id);
        }
    }
    if status.engine_hang {
        counters::GPU_FAULT_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if let Some(id) = status.hung_fence {
            fence::error_by_id(id);
        }
    }
    if status.page_fault {
        counters::GPU_FAULT_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Signal a specific fence and update telemetry — convenience wrapper for
/// drivers that manage their own completion bookkeeping.
pub fn complete_fence(fence_id: u64) {
    fence::signal_by_id(fence_id);
    counters::GPU_QUEUE_SUBMITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}


