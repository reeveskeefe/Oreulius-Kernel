// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

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
