/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
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
