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


//! Architecture MMU shim.
//!
//! This starts as a thin wrapper over the existing i686 paging subsystem so
//! callers can migrate away from directly depending on `crate::paging`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageAttribute {
    Writable,
}

pub trait ArchMmu {
    fn name(&self) -> &'static str;
    fn init(&self) -> Result<(), &'static str>;
    fn page_size(&self) -> usize;
    fn kernel_page_table_root_addr(&self) -> Option<usize>;
    fn current_page_table_root_addr(&self) -> usize;
    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str>;
    fn flush_tlb_page(&self, virt_addr: usize);
    fn flush_tlb_all(&self);
    fn set_page_attribute_range(
        &self,
        virt_addr: usize,
        size: usize,
        attr: PageAttribute,
        enabled: bool,
    ) -> Result<(), &'static str>;
    fn set_page_writable_range(
        &self,
        virt_addr: usize,
        size: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        self.set_page_attribute_range(virt_addr, size, PageAttribute::Writable, writable)
    }
}

#[cfg(target_arch = "x86")]
#[path = "mmu_x86_legacy.rs"]
mod mmu_x86_legacy;
#[cfg(target_arch = "x86_64")]
#[path = "mmu_x86_64.rs"]
mod mmu_x86_64;
#[cfg(target_arch = "aarch64")]
#[path = "mmu_aarch64.rs"]
mod mmu_aarch64;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
#[path = "mmu_unsupported.rs"]
mod mmu_unsupported;

#[cfg(target_arch = "x86")]
use mmu_x86_legacy::MMU;
#[cfg(target_arch = "x86_64")]
use mmu_x86_64::MMU;
#[cfg(target_arch = "aarch64")]
use mmu_aarch64::MMU;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
use mmu_unsupported::MMU;

#[cfg(target_arch = "x86")]
pub type AddressSpace = crate::paging::AddressSpace;
#[cfg(target_arch = "x86_64")]
pub use mmu_x86_64::AddressSpace;
#[cfg(target_arch = "aarch64")]
pub use mmu_aarch64::AddressSpace;

#[inline]
fn active() -> &'static dyn ArchMmu {
    &MMU
}

#[inline]
pub fn backend_name() -> &'static str {
    active().name()
}

#[inline]
pub fn init() -> Result<(), &'static str> {
    active().init()
}

#[inline]
pub fn page_size() -> usize {
    active().page_size()
}

#[inline]
pub fn kernel_page_table_root_addr() -> Option<usize> {
    active().kernel_page_table_root_addr()
}

#[inline]
pub fn current_page_table_root_addr() -> usize {
    active().current_page_table_root_addr()
}

#[inline]
pub fn set_page_table_root(phys_addr: usize) -> Result<(), &'static str> {
    active().set_page_table_root(phys_addr)
}

#[inline]
pub fn flush_tlb_page(virt_addr: usize) {
    active().flush_tlb_page(virt_addr)
}

#[inline]
pub fn flush_tlb_all() {
    active().flush_tlb_all()
}

#[inline]
pub fn set_page_attribute_range(
    virt_addr: usize,
    size: usize,
    attr: PageAttribute,
    enabled: bool,
) -> Result<(), &'static str> {
    active().set_page_attribute_range(virt_addr, size, attr, enabled)
}

#[inline]
pub fn set_page_writable_range(
    virt_addr: usize,
    size: usize,
    writable: bool,
) -> Result<(), &'static str> {
    active().set_page_writable_range(virt_addr, size, writable)
}

#[cfg(target_arch = "x86")]
pub fn new_jit_sandbox() -> Result<AddressSpace, &'static str> {
    crate::paging::AddressSpace::new_jit_sandbox()
}

#[cfg(target_arch = "x86_64")]
pub fn new_jit_sandbox() -> Result<AddressSpace, &'static str> {
    AddressSpace::new_jit_sandbox()
}

#[cfg(target_arch = "aarch64")]
pub fn new_jit_sandbox() -> Result<AddressSpace, &'static str> {
    AddressSpace::new_jit_sandbox()
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn new_jit_sandbox() -> Result<(), &'static str> {
    Err("arch mmu address spaces not supported")
}

#[cfg(target_arch = "x86")]
pub fn alloc_user_pages(
    space: &mut AddressSpace,
    virt_addr: usize,
    count: usize,
    writable: bool,
) -> Result<(), &'static str> {
    crate::paging::alloc_user_pages(space, virt_addr, count, writable)
}

#[cfg(target_arch = "x86_64")]
pub fn alloc_user_pages(
    space: &mut AddressSpace,
    virt_addr: usize,
    count: usize,
    writable: bool,
) -> Result<(), &'static str> {
    space.alloc_user_pages(virt_addr, count, writable)
}

#[cfg(target_arch = "aarch64")]
pub fn alloc_user_pages(
    space: &mut AddressSpace,
    virt_addr: usize,
    count: usize,
    writable: bool,
) -> Result<(), &'static str> {
    space.alloc_user_pages(virt_addr, count, writable)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub fn alloc_user_pages(
    _space: &mut (),
    _virt_addr: usize,
    _count: usize,
    _writable: bool,
) -> Result<(), &'static str> {
    Err("arch mmu address spaces not supported")
}

#[cfg(target_arch = "x86")]
pub fn map_user_range_phys(
    space: &mut AddressSpace,
    virt_start: usize,
    phys_start: usize,
    size: usize,
    writable: bool,
) -> Result<(), &'static str> {
    space.map_user_range_phys(virt_start, phys_start, size, writable)
}

#[cfg(target_arch = "x86_64")]
pub fn map_user_range_phys(
    space: &mut AddressSpace,
    virt_start: usize,
    phys_start: usize,
    size: usize,
    writable: bool,
) -> Result<(), &'static str> {
    space.map_user_range_phys(virt_start, phys_start, size, writable)
}

#[cfg(target_arch = "aarch64")]
pub fn map_user_range_phys(
    space: &mut AddressSpace,
    virt_start: usize,
    phys_start: usize,
    size: usize,
    writable: bool,
) -> Result<(), &'static str> {
    space.map_user_range_phys(virt_start, phys_start, size, writable)
}

#[cfg(target_arch = "x86")]
pub fn unmap_page(space: &mut AddressSpace, virt_addr: usize) -> Result<(), &'static str> {
    space.unmap_page(virt_addr)
}

#[cfg(target_arch = "x86_64")]
pub fn unmap_page(space: &mut AddressSpace, virt_addr: usize) -> Result<(), &'static str> {
    space.unmap_page(virt_addr)
}

#[cfg(target_arch = "aarch64")]
pub fn unmap_page(space: &mut AddressSpace, virt_addr: usize) -> Result<(), &'static str> {
    space.unmap_page(virt_addr)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn handle_page_fault(fault_addr: usize, error: u64) -> bool {
    mmu_x86_64::handle_page_fault(fault_addr, error)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn handle_page_fault(_fault_addr: usize, _error: u64) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_mark_page_cow(virt_addr: usize) -> Result<(), &'static str> {
    mmu_x86_64::debug_mark_page_cow(virt_addr)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn x86_64_debug_mark_page_cow(_virt_addr: usize) -> Result<(), &'static str> {
    Err("x86_64 MMU backend not active")
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    mmu_x86_64::debug_virt_to_phys(virt_addr)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn x86_64_debug_virt_to_phys(_virt_addr: usize) -> Option<usize> {
    None
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_pf_stats() -> (u64, u64, u64) {
    mmu_x86_64::debug_pf_stats()
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn x86_64_debug_pf_stats() -> (u64, u64, u64) {
    (0, 0, 0)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_alloc_debug_page() -> Result<usize, &'static str> {
    mmu_aarch64::debug_alloc_page()
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn aarch64_alloc_debug_page() -> Result<usize, &'static str> {
    Err("aarch64 MMU backend not active")
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    mmu_aarch64::debug_translate_current(virt_addr)
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn aarch64_debug_virt_to_phys(_virt_addr: usize) -> Option<usize> {
    None
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_debug_walk(virt_addr: usize) -> (usize, u64, u64, u64, u64, Option<usize>) {
    let w = mmu_aarch64::debug_walk_current(virt_addr);
    (w.root_phys, w.l0_desc, w.l1_desc, w.l2_desc, w.l3_desc, w.phys_addr)
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn aarch64_debug_walk(_virt_addr: usize) -> (usize, u64, u64, u64, u64, Option<usize>) {
    (0, 0, 0, 0, 0, None)
}
