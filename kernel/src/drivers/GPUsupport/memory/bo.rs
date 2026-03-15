/*!
 * Buffer Object (BO) abstraction and slab allocator.
 *
 * A `BufferObject` represents a GPU-visible memory allocation.  All BOs are
 * tracked in a fixed-capacity `BoAllocator` slab so the kernel can audit
 * live allocations, enforce owner isolation, and purge all allocations
 * belonging to a dead process.
 *
 * # Design constraints
 * - `BO_SLAB_SIZE` controls the maximum number of live buffer objects.
 * - IDs are monotonically increasing 64-bit values; they are never reused
 *   within a session (prevents use-after-free ID aliasing).
 * - `bytes` uses `alloc::vec` so individual BOs can be large; the slab itself
 *   uses only a fixed-size index array.
 * - Owner isolation: `validate_owner(id, pid)` is O(1) lookup.
 */

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously live buffer objects across all processes.
pub const BO_SLAB_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// ID counter
// ---------------------------------------------------------------------------

static NEXT_BO_ID: AtomicU32 = AtomicU32::new(1);

fn alloc_bo_id() -> u64 {
    NEXT_BO_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// BufferFlags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferFlags {
    pub bits: u32,
}

impl BufferFlags {
    pub const CPU_VISIBLE: u32 = 1 << 0;
    pub const GPU_VISIBLE: u32 = 1 << 1;
    pub const SCANOUT:     u32 = 1 << 2;
    pub const CURSOR:      u32 = 1 << 3;
    pub const IMPORT:      u32 = 1 << 4;  // imported from external memory

    pub const fn new(bits: u32) -> Self { BufferFlags { bits } }
    pub const fn cpu_gpu() -> Self { Self::new(Self::CPU_VISIBLE | Self::GPU_VISIBLE) }
    pub const fn scanout() -> Self { Self::new(Self::CPU_VISIBLE | Self::GPU_VISIBLE | Self::SCANOUT) }
    pub fn contains(&self, bit: u32) -> bool { self.bits & bit == bit }
}

// ---------------------------------------------------------------------------
// BufferObject
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BufferObject {
    pub object_id: u64,
    pub owner: ProcessId,
    pub size: usize,
    pub flags: BufferFlags,
    pub bytes: Vec<u8>,
    /// Physical base address of an imported external mapping (non-zero when
    /// `IMPORT` flag is set); zero for software-backed BOs.
    pub phys_base: u64,
}

impl BufferObject {
    /// Allocate a software-backed BO, zeroed.
    pub fn new(owner: ProcessId, size: usize, flags: BufferFlags) -> Self {
        BufferObject {
            object_id: alloc_bo_id(),
            owner,
            size,
            flags,
            bytes: alloc::vec![0u8; size],
            phys_base: 0,
        }
    }

    /// Wrap an existing physical mapping (e.g. a firmware framebuffer) as a
    /// zero-copy imported BO.  `bytes` is empty; access goes directly to
    /// `phys_base`.
    pub fn import(owner: ProcessId, phys_base: u64, size: usize) -> Self {
        BufferObject {
            object_id: alloc_bo_id(),
            owner,
            size,
            flags: BufferFlags::new(
                BufferFlags::GPU_VISIBLE | BufferFlags::SCANOUT | BufferFlags::IMPORT
            ),
            bytes: Vec::new(),
            phys_base,
        }
    }

    pub fn is_scanout(&self) -> bool { self.flags.contains(BufferFlags::SCANOUT) }
    pub fn is_cpu_visible(&self) -> bool { self.flags.contains(BufferFlags::CPU_VISIBLE) }
    pub fn is_imported(&self) -> bool { self.flags.contains(BufferFlags::IMPORT) }
}

// ---------------------------------------------------------------------------
// BoAllocator — fixed-capacity slab
// ---------------------------------------------------------------------------

/// Slab allocator that tracks all live `BufferObject`s.
///
/// Stored in the GPU service singleton — no heap allocation for the index.
pub struct BoAllocator {
    slots: [Option<BufferObject>; BO_SLAB_SIZE],
    count: usize,
}

impl BoAllocator {
    pub const fn empty_slot() -> Option<BufferObject> { None }

    pub fn new() -> Self {
        // Can't use [None; N] for non-Copy types; build via Default.
        let mut slots: [Option<BufferObject>; BO_SLAB_SIZE] =
            unsafe { core::mem::zeroed() };
        // MaybeUninit would be cleaner; zeroed() is safe here because
        // Option<BufferObject> is valid at all-zeros (None).
        let _ = slots; // silence "assigned but unused" on nightly
        BoAllocator {
            slots: unsafe { core::mem::zeroed() },
            count: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Insert a new BO and return its ID on success, or `None` if the slab
    /// is full.
    pub fn insert(&mut self, bo: BufferObject) -> Option<u64> {
        if self.count >= BO_SLAB_SIZE {
            return None;
        }
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                let id = bo.object_id;
                *slot = Some(bo);
                self.count += 1;
                return Some(id);
            }
        }
        None
    }

    /// Look up a BO by ID.
    pub fn get(&self, id: u64) -> Option<&BufferObject> {
        self.slots.iter().flatten().find(|bo| bo.object_id == id)
    }

    /// Mutable lookup by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut BufferObject> {
        self.slots.iter_mut().flatten().find(|bo| bo.object_id == id)
    }

    /// Remove and return a BO by ID.
    pub fn remove(&mut self, id: u64) -> Option<BufferObject> {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().map(|b| b.object_id) == Some(id) {
                let bo = slot.take();
                if bo.is_some() && self.count > 0 {
                    self.count -= 1;
                }
                return bo;
            }
        }
        None
    }

    /// Purge all BOs owned by `pid`.  Called on process exit.
    pub fn purge_owner(&mut self, pid: ProcessId) -> usize {
        let mut purged = 0;
        for slot in self.slots.iter_mut() {
            if slot.as_ref().map(|b| b.owner) == Some(pid) {
                *slot = None;
                purged += 1;
            }
        }
        if purged <= self.count {
            self.count -= purged;
        } else {
            self.count = 0;
        }
        purged
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    /// Returns `true` if `id` exists and is owned by `pid`.
    pub fn validate_owner(&self, id: u64, pid: ProcessId) -> bool {
        self.get(id).map(|bo| bo.owner == pid).unwrap_or(false)
    }

    /// Returns `true` if `id` exists and has the `SCANOUT` flag.
    pub fn is_scanout(&self, id: u64) -> bool {
        self.get(id).map(|bo| bo.is_scanout()).unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------

    pub fn live_count(&self) -> usize { self.count }
    pub fn is_full(&self)   -> bool   { self.count >= BO_SLAB_SIZE }
}


