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
