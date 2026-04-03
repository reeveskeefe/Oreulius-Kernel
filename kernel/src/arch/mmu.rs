/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Architecture MMU shim.
//!
//! This starts as a thin wrapper over the existing i686 paging subsystem so
//! callers can migrate away from directly depending on `crate::paging`.

/// Physical address newtype used for page-table roots and MMU handoff.
///
/// `PhysAddr::new(0)` is the internal "unset / no physical root recorded"
/// sentinel in the current kernel. Callers should prefer [`PhysAddr::is_zero`]
/// over open-coded raw `0` comparisons.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysAddr(usize);

impl PhysAddr {
    #[inline]
    pub const fn new(raw: usize) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub fn try_as_u32(self) -> Result<u32, &'static str> {
        u32::try_from(self.0).map_err(|_| "physical address exceeds u32")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageAttribute {
    Writable,
}

pub trait ArchMmu {
    /// Architecture-specific virtual address space descriptor.
    type AddressSpace: Send + Sync + 'static;
    /// Architecture-specific page-table root struct.
    type PageTable: Send + Sync + 'static;

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

#[cfg(target_arch = "aarch64")]
#[path = "mmu_aarch64.rs"]
mod mmu_aarch64;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
#[path = "mmu_unsupported.rs"]
mod mmu_unsupported;
#[cfg(target_arch = "x86_64")]
#[path = "mmu_x86_64.rs"]
mod mmu_x86_64;
#[cfg(target_arch = "x86")]
#[path = "mmu_x86_legacy.rs"]
mod mmu_x86_legacy;

#[cfg(target_arch = "aarch64")]
use mmu_aarch64::MMU;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
use mmu_unsupported::MMU;
#[cfg(target_arch = "x86_64")]
use mmu_x86_64::MMU;
#[cfg(target_arch = "x86")]
use mmu_x86_legacy::MMU;

#[cfg(target_arch = "x86")]
pub type AddressSpace = crate::paging::AddressSpace;
#[cfg(target_arch = "aarch64")]
pub use mmu_aarch64::AddressSpace;
#[cfg(target_arch = "x86_64")]
pub use mmu_x86_64::AddressSpace;

#[inline]
#[cfg(target_arch = "x86")]
fn active() -> &'static mmu_x86_legacy::X86LegacyMmu {
    &MMU
}

#[inline]
#[cfg(target_arch = "x86_64")]
fn active() -> &'static mmu_x86_64::X86_64Mmu {
    &MMU
}

#[inline]
#[cfg(target_arch = "aarch64")]
fn active() -> &'static mmu_aarch64::AArch64Mmu {
    &MMU
}

#[inline]
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
fn active() -> &'static mmu_unsupported::UnsupportedMmu {
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

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_mark_page_cow(virt_addr: usize) -> Result<(), &'static str> {
    mmu_x86_64::debug_mark_page_cow(virt_addr)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    mmu_x86_64::debug_virt_to_phys(virt_addr)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_pf_stats() -> (u64, u64, u64) {
    mmu_x86_64::debug_pf_stats()
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn x86_64_debug_recover_stats() -> (usize, usize, u64, usize, u64, u8) {
    mmu_x86_64::debug_recover_stats()
}

/// Identity-map a physical MMIO range into the kernel page tables so device
/// memory is accessible before the first write.  On x86_64 this installs
/// writable identity PTEs in the live CR3.  On other architectures (or when
/// the paging module owns the mapping on x86) this is a no-op — callers are
/// expected to use the arch-appropriate path for those targets.
#[cfg(target_arch = "x86_64")]
pub fn map_mmio_identity_range(phys: usize, size: usize) {
    mmu_x86_64::map_mmio_identity_range(phys, size);
}

#[cfg(not(target_arch = "x86_64"))]
pub fn map_mmio_identity_range(_phys: usize, _size: usize) {}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
pub(crate) fn aarch64_alloc_debug_page() -> Result<usize, &'static str> {
    mmu_aarch64::debug_alloc_page()
}

#[cfg(not(target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) fn aarch64_alloc_debug_page() -> Result<usize, &'static str> {
    Err("aarch64 MMU backend not active")
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
pub(crate) fn aarch64_debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    mmu_aarch64::debug_translate_current(virt_addr)
}

#[cfg(not(target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) fn aarch64_debug_virt_to_phys(_virt_addr: usize) -> Option<usize> {
    None
}

#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
pub(crate) fn aarch64_debug_walk(virt_addr: usize) -> (usize, u64, u64, u64, u64, Option<usize>) {
    let w = mmu_aarch64::debug_walk_current(virt_addr);
    (
        w.root_phys,
        w.l0_desc,
        w.l1_desc,
        w.l2_desc,
        w.l3_desc,
        w.phys_addr,
    )
}

#[cfg(not(target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) fn aarch64_debug_walk(_virt_addr: usize) -> (usize, u64, u64, u64, u64, Option<usize>) {
    (0, 0, 0, 0, 0, None)
}

#[cfg(test)]
mod tests {
    use super::PhysAddr;

    #[test]
    fn phys_addr_round_trips_small_values() {
        let addr = PhysAddr::new(0x1234);
        assert_eq!(addr.as_usize(), 0x1234);
        assert_eq!(addr.as_u64(), 0x1234);
        assert!(!addr.is_zero());
        assert_eq!(addr.try_as_u32().unwrap(), 0x1234);
    }

    #[test]
    fn phys_addr_zero_is_sentinel() {
        let addr = PhysAddr::new(0);
        assert!(addr.is_zero());
        assert_eq!(addr.as_usize(), 0);
        assert_eq!(addr.as_u64(), 0);
        assert_eq!(addr.try_as_u32().unwrap(), 0);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn phys_addr_rejects_u32_overflow() {
        let addr = PhysAddr::new((u32::MAX as usize) + 1);
        assert_eq!(addr.as_u64(), (u32::MAX as u64) + 1);
        assert!(addr.try_as_u32().is_err());
    }
}
