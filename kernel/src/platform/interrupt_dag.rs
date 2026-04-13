/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


/// Topologically Bounded Interrupt DAGs (Deadlock Freedom)
///
/// Every kernel spinlock carries a compile-time priority level.  A context at
/// level L may only acquire a lock at level < L, forming a strict DAG that
/// eliminates the whole class of lock-ordering deadlocks at compile time.
///
/// `acquire_lock` also disables hardware interrupts for the duration of the
/// closure, preventing interrupt handlers from re-entering a spinlock already
/// held on the same CPU core (the classic spin-deadlock scenario).
use core::marker::PhantomData;

pub const DAG_LEVEL_VFS: u8 = 5;
pub const DAG_LEVEL_SCHEDULER: u8 = 10;
pub const DAG_LEVEL_THREAD: u8 = 8;
pub const DAG_LEVEL_SYSCALL: u8 = 15;
pub const DAG_LEVEL_IRQ: u8 = 20;

// ---------------------------------------------------------------------------
// Compile-time level ordering check
// ---------------------------------------------------------------------------

/// Statically asserts `A < B` at monomorphization time.
///
/// Writing `let _ = AssertLt::<A, B>::VALID;` anywhere the const-generics are
/// concrete causes a hard compile error — not a runtime panic — when A >= B.
/// This works because associated consts in generic impls are evaluated eagerly
/// during monomorphization on all recent Rust releases.
struct AssertLt<const A: u8, const B: u8>;

impl<const A: u8, const B: u8> AssertLt<A, B> {
    const VALID: () = assert!(
        A < B,
        "DEADLOCK PREVENTED: acquire_lock target level must be strictly less than context level"
    );
}

// ---------------------------------------------------------------------------
// IRQ save/restore guard
// ---------------------------------------------------------------------------

/// Disables hardware interrupts on construction and restores the saved state on
/// drop, providing a bounded critical section independent of the spinlock itself.
struct IrqGuard {
    saved: crate::scheduler::scheduler_platform::IrqFlags,
}

impl IrqGuard {
    fn acquire() -> Self {
        // SAFETY: reads the interrupt-flag register (RFLAGS on x86, DAIF on
        // AArch64) then masks IRQs.  The saved value is unconditionally restored
        // in Drop, so the critical section is always bounded by the guard lifetime.
        let saved = unsafe { crate::scheduler::scheduler_platform::irq_save_disable() };
        Self { saved }
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        // SAFETY: restores the interrupt state captured in acquire().  If
        // interrupts were enabled before, they are re-enabled; if they were
        // already masked, they remain masked.
        unsafe { crate::scheduler::scheduler_platform::irq_restore(self.saved) };
    }
}

// ---------------------------------------------------------------------------
// Context type
// ---------------------------------------------------------------------------

/// An execution context at DAG priority `LEVEL`.
///
/// Holding a reference to one of these is proof that the current code is
/// executing at the corresponding priority, which is enforced by only ever
/// constructing the root context in arch-level interrupt entry points and
/// scheduler initialization code.
pub struct InterruptContext<const LEVEL: u8> {
    _marker: PhantomData<()>,
}

impl<const LEVEL: u8> InterruptContext<LEVEL> {
    /// Creates a context token for this priority level.
    ///
    /// # Safety
    /// The caller must genuinely be executing at `LEVEL`.  In practice the root
    /// contexts are only created in arch-level interrupt entry points
    /// (`irq_context()`) and scheduler/VFS bootstrap helpers (`syscall_context()`,
    /// `thread_context()`), never by arbitrary kernel code.
    ///
    /// In debug builds, creating a context at `DAG_LEVEL_IRQ` or above asserts
    /// that hardware interrupts are currently masked, catching accidental
    /// construction outside a real interrupt handler.
    pub unsafe fn new() -> Self {
        debug_assert!(
            LEVEL < crate::platform::interrupt_dag::DAG_LEVEL_IRQ
                || crate::scheduler::scheduler_platform::irqs_disabled(),
            "InterruptContext at IRQ level constructed while IRQs are enabled — \
             only call irq_context() from a hardware interrupt handler"
        );
        Self {
            _marker: PhantomData,
        }
    }

    /// Acquires `lock` (at `TARGET_LEVEL`), runs `closure` with exclusive access
    /// to the protected data, releases the lock, and returns the closure result.
    ///
    /// **Compile-time DAG enforcement** — `AssertLt::<TARGET_LEVEL, LEVEL>::VALID`
    /// is evaluated during monomorphization.  If `TARGET_LEVEL >= LEVEL` the crate
    /// will not compile, eliminating the entire lock-inversion deadlock class.
    ///
    /// **Interrupt safety** — interrupts are disabled before the spinlock is
    /// acquired and restored to their prior state after it is released, preventing
    /// interrupt handlers from spinning on a lock already held on this CPU core.
    #[inline]
    pub fn acquire_lock<const TARGET_LEVEL: u8, T, F, R>(
        &self,
        lock: &DagSpinlock<TARGET_LEVEL, T>,
        closure: F,
    ) -> R
    where
        F: FnOnce(&mut T, &InterruptContext<TARGET_LEVEL>) -> R,
    {
        // Compile-time DAG check — does not compile if TARGET_LEVEL >= LEVEL.
        let _ = AssertLt::<TARGET_LEVEL, LEVEL>::VALID;

        // Mask interrupts before spinning: an IRQ handler that tries to acquire
        // the same lock on this core would spin forever.
        let _irq = IrqGuard::acquire();

        let mut data = lock.data.lock();
        let sub_context = unsafe { InterruptContext::<TARGET_LEVEL>::new() };
        closure(&mut *data, &sub_context)
        // Drop order: sub_context (trivial), data (releases spinlock), _irq (restores IRQs).
    }
}

// ---------------------------------------------------------------------------
// Lock type
// ---------------------------------------------------------------------------

/// A spinlock whose level is part of its type, enforcing DAG ordering via
/// [`InterruptContext::acquire_lock`].
pub struct DagSpinlock<const LEVEL: u8, T> {
    data: spin::Mutex<T>,
}

impl<const LEVEL: u8, T> DagSpinlock<LEVEL, T> {
    pub const fn new(value: T) -> Self {
        Self {
            data: spin::Mutex::new(value),
        }
    }

    /// Acquires the raw spinlock, bypassing DAG ordering and IRQ masking.
    ///
    /// Exists only for incremental migration of pre-existing call sites.
    /// All new code must use [`InterruptContext::acquire_lock`].
    #[deprecated(
        note = "bypasses DAG ordering and IRQ masking — use InterruptContext::acquire_lock"
    )]
    pub fn lock_legacy(&self) -> spin::MutexGuard<'_, T> {
        self.data.lock()
    }
}
