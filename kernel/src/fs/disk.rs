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

/// Handle primary ATA IRQ (IRQ14).
///
/// Delegates to [`crate::ata::on_primary_irq`] which increments the ATA driver's
/// own atomic counter.  This shim is kept so that existing interrupt-dispatch
/// tables that already reference `disk::handle_primary_irq` continue to compile
/// without change.
pub fn handle_primary_irq() {
    crate::ata::on_primary_irq();
}

/// Handle secondary ATA IRQ (IRQ15).
///
/// Delegates to [`crate::ata::on_secondary_irq`].
pub fn handle_secondary_irq() {
    crate::ata::on_secondary_irq();
}

/// Get ATA IRQ counts (primary, secondary).
///
/// Reads the counters maintained by the ATA driver.
pub fn irq_counts() -> (u32, u32) {
    let h = crate::ata::health();
    (h.primary_irqs, h.secondary_irqs)
}
