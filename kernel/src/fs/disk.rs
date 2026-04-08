/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

/// Handle primary ATA IRQ (IRQ14).
///
/// Delegates to [`crate::fs::ata::on_primary_irq`] which increments the ATA driver's
/// own atomic counter.  This shim is kept so that existing interrupt-dispatch
/// tables that already reference `disk::handle_primary_irq` continue to compile
/// without change.
pub fn handle_primary_irq() {
    crate::fs::ata::on_primary_irq();
}

/// Handle secondary ATA IRQ (IRQ15).
///
/// Delegates to [`crate::fs::ata::on_secondary_irq`].
pub fn handle_secondary_irq() {
    crate::fs::ata::on_secondary_irq();
}

/// Get ATA IRQ counts (primary, secondary).
///
/// Reads the counters maintained by the ATA driver.
pub fn irq_counts() -> (u32, u32) {
    let h = crate::fs::ata::health();
    (h.primary_irqs, h.secondary_irqs)
}
