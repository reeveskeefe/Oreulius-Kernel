/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
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

use super::{ArchPlatform, BootInfo};

pub(super) struct UnsupportedPlatform;

pub(super) static PLATFORM: UnsupportedPlatform = UnsupportedPlatform;

impl ArchPlatform for UnsupportedPlatform {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn boot_info(&self) -> BootInfo {
        BootInfo::default()
    }

    fn init_cpu_tables(&self) {}

    fn init_trap_table(&self) {}

    fn init_interrupt_controller(&self) {}

    fn init_timer(&self) {}

    fn enable_interrupts(&self) {}

    fn halt_loop(&self) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}
