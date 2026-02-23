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
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[path = "mmu_unsupported.rs"]
mod mmu_unsupported;

#[cfg(target_arch = "x86")]
use mmu_x86_legacy::MMU;
#[cfg(target_arch = "x86_64")]
use mmu_x86_64::MMU;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use mmu_unsupported::MMU;

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
