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
