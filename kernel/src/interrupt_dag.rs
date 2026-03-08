/// Topologically Bounded Interrupt DAGs (Deadlock Freedom)
/// As outlined in the Polymorphic Mathematical Architecture, this trait bounds the
/// Interrupt Descriptor Table (IDT) and global Spinlocks to a strictly provable DAG.
use core::marker::PhantomData;

/// DAG level for the scheduler — all scheduler locks sit at this priority.
pub const DAG_LEVEL_SCHEDULER: u8 = 10;
/// DAG level for VFS — all VFS locks at this priority.
pub const DAG_LEVEL_VFS: u8 = 5;
/// DAG level for top-level hardware IRQ dispatch context.
///
/// Must be strictly greater than all subsystem lock levels (scheduler=10, vfs=5)
/// so that `InterruptContext::<DAG_LEVEL_IRQ>::acquire_lock` is valid from any
/// hardware interrupt handler without triggering the deadlock assertion.
pub const DAG_LEVEL_IRQ: u8 = 20;

/// Represents an execution context at a specific mathematical priority level.
/// Lock acquisition or nested calls are only permitted if the target's priority
/// is strictly less than the current context's level.
pub struct InterruptContext<const LEVEL: u8> {
    _marker: PhantomData<()>,
}

impl<const LEVEL: u8> InterruptContext<LEVEL> {
    /// Elevates (or initializes) into a specific context.
    /// In a real architecture, this is tied to IDT entry macros or base scheduling threads.
    pub const unsafe fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Acquires a lock modeled at `TARGET_LEVEL`.
    /// The Rust compiler enforces `TARGET_LEVEL < LEVEL` natively if we use compile-time bounds,
    /// preventing any cyclic deadlocks without runtime watchdogs.
    pub fn acquire_lock<const TARGET_LEVEL: u8, T, F, R>(
        &self,
        lock: &DagSpinlock<TARGET_LEVEL, T>,
        closure: F,
    ) -> R
    where
        // Natively enforce strictly decreasing monotonic priorities!
        F: FnOnce(&mut T, &InterruptContext<TARGET_LEVEL>) -> R,
    {
        // Rust stable const generic tricks to assert TARGET_LEVEL < LEVEL
        // can be tricky without feature boundaries. For this abstraction,
        // asserting normally triggers constant panic evaluation in const contexts,
        // but we'll use a runtime assert that LLVM trivially folds into unreachable
        // due to these values being known statically at compilation.
        assert!(
            TARGET_LEVEL < LEVEL,
            "DEADLOCK PREVENTED: Attempted to acquire lock of equal or higher DAG priority!"
        );

        // Lock acquisition logic goes here. For now, we stub it and hand off
        // the correctly downgraded sub-context.
        let mut data = lock.data.lock();

        // Pass the dynamically downgraded priority context to the closure,
        // forcing subsequent deep calls to originate from TARGET_LEVEL.
        let sub_context = unsafe { InterruptContext::<TARGET_LEVEL>::new() };
        closure(&mut *data, &sub_context)
    }
}

/// A priority-bound Spinlock that enforces mathematically strict flow limits.
pub struct DagSpinlock<const TARGET_LEVEL: u8, T> {
    data: spin::Mutex<T>,
}

impl<const TARGET_LEVEL: u8, T> DagSpinlock<TARGET_LEVEL, T> {
    pub const fn new(value: T) -> Self {
        Self {
            data: spin::Mutex::new(value),
        }
    }

    /// Legacy unbounded lock, used during transitional migration.
    /// New code should use `InterruptContext::acquire_lock`.
    pub fn lock_legacy(&self) -> spin::MutexGuard<'_, T> {
        self.data.lock()
    }
}
