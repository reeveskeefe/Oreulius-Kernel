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

use super::{ArchMmu, PageAttribute};

pub(super) struct X86LegacyMmu;

pub(super) static MMU: X86LegacyMmu = X86LegacyMmu;

impl ArchMmu for X86LegacyMmu {
    type AddressSpace = crate::fs::paging::AddressSpace;
    type PageTable = crate::fs::paging::AddressSpace;

    fn name(&self) -> &'static str {
        "i686-paging"
    }

    fn init(&self) -> Result<(), &'static str> {
        crate::fs::paging::init()
    }

    fn page_size(&self) -> usize {
        crate::fs::paging::PAGE_SIZE
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        crate::fs::paging::kernel_page_directory_addr().map(|v| v as usize)
    }

    fn current_page_table_root_addr(&self) -> usize {
        crate::fs::paging::current_page_directory_addr() as usize
    }

    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str> {
        if phys_addr > u32::MAX as usize {
            return Err("CR3 root address out of 32-bit range");
        }
        unsafe {
            crate::fs::paging::set_page_directory(phys_addr as u32);
        }
        Ok(())
    }

    fn flush_tlb_page(&self, virt_addr: usize) {
        crate::fs::paging::flush_tlb_page(virt_addr as u32)
    }

    fn flush_tlb_all(&self) {
        crate::fs::paging::flush_all_tlb()
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
                crate::fs::paging::set_page_writable_range(virt_addr, size, enabled)
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
