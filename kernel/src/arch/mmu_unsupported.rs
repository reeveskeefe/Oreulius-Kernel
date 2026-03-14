/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
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
