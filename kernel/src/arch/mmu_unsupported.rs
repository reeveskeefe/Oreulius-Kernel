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

use super::{ArchMmu, PageAttribute};

pub(super) struct UnsupportedMmu;

pub(super) static MMU: UnsupportedMmu = UnsupportedMmu;

impl ArchMmu for UnsupportedMmu {
    type AddressSpace = ();
    type PageTable = ();

    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn init(&self) -> Result<(), &'static str> {
        Err("MMU backend not implemented for this architecture")
    }

    fn page_size(&self) -> usize {
        4096
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        None
    }

    fn current_page_table_root_addr(&self) -> usize {
        0
    }

    fn set_page_table_root(&self, _phys_addr: usize) -> Result<(), &'static str> {
        Err("MMU backend not implemented for this architecture")
    }

    fn flush_tlb_page(&self, _virt_addr: usize) {}

    fn flush_tlb_all(&self) {}

    fn set_page_attribute_range(
        &self,
        _virt_addr: usize,
        _size: usize,
        _attr: PageAttribute,
        _enabled: bool,
    ) -> Result<(), &'static str> {
        Err("MMU backend not implemented for this architecture")
    }

    fn set_page_writable_range(
        &self,
        _virt_addr: usize,
        _size: usize,
        _writable: bool,
    ) -> Result<(), &'static str> {
        Err("MMU backend not implemented for this architecture")
    }
}
