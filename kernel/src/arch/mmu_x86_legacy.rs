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

pub(super) struct X86LegacyMmu;

pub(super) static MMU: X86LegacyMmu = X86LegacyMmu;

impl ArchMmu for X86LegacyMmu {
    fn name(&self) -> &'static str {
        "i686-paging"
    }

    fn init(&self) -> Result<(), &'static str> {
        crate::paging::init()
    }

    fn page_size(&self) -> usize {
        crate::paging::PAGE_SIZE
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        crate::paging::kernel_page_directory_addr().map(|v| v as usize)
    }

    fn current_page_table_root_addr(&self) -> usize {
        crate::paging::current_page_directory_addr() as usize
    }

    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str> {
        if phys_addr > u32::MAX as usize {
            return Err("CR3 root address out of 32-bit range");
        }
        unsafe {
            crate::paging::set_page_directory(phys_addr as u32);
        }
        Ok(())
    }

    fn flush_tlb_page(&self, virt_addr: usize) {
        crate::paging::flush_tlb_page(virt_addr as u32)
    }

    fn flush_tlb_all(&self) {
        crate::paging::flush_all_tlb()
    }

    fn set_page_attribute_range(
        &self,
        virt_addr: usize,
        size: usize,
        attr: PageAttribute,
        enabled: bool,
    ) -> Result<(), &'static str> {
        match attr {
            PageAttribute::Writable => {
                crate::paging::set_page_writable_range(virt_addr, size, enabled)
            }
        }
    }

    fn set_page_writable_range(
        &self,
        virt_addr: usize,
        size: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        self.set_page_attribute_range(virt_addr, size, PageAttribute::Writable, writable)
    }
}
