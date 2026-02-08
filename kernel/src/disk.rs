use core::sync::atomic::{AtomicU32, Ordering};

static PRIMARY_IRQS: AtomicU32 = AtomicU32::new(0);
static SECONDARY_IRQS: AtomicU32 = AtomicU32::new(0);

/// Handle primary ATA IRQ (IRQ14)
pub fn handle_primary_irq() {
    PRIMARY_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// Handle secondary ATA IRQ (IRQ15)
pub fn handle_secondary_irq() {
    SECONDARY_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// Get ATA IRQ counts (primary, secondary)
pub fn irq_counts() -> (u32, u32) {
    (
        PRIMARY_IRQS.load(Ordering::Relaxed),
        SECONDARY_IRQS.load(Ordering::Relaxed),
    )
}
