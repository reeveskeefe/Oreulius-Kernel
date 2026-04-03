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

use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use super::{ArchMmu, PageAttribute};

pub(super) struct X86_64Mmu;

pub(super) static MMU: X86_64Mmu = X86_64Mmu;

const PAGE_SIZE: usize = 4096;
const HUGE_PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
const ENTRIES_PER_TABLE: usize = 512;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_PS: u64 = 1 << 7;
const PTE_COW_SOFT: u64 = 1 << 9; // software-available bit (matches legacy 32-bit bit 9)
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const PTE_FLAGS_LOW_MASK: u64 = 0xFFF;
const PTE_NX: u64 = 1 << 63;

const PF_ERR_PRESENT: u64 = 1 << 0;
const PF_ERR_WRITE: u64 = 1 << 1;

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct PageTablePage {
    entries: [u64; ENTRIES_PER_TABLE],
}

impl PageTablePage {
    const fn zeroed() -> Self {
        Self {
            entries: [0; ENTRIES_PER_TABLE],
        }
    }
}

// Emergency page-table pool used by fault-time recovery paths where heap
// allocation is unsafe (allocator lock may already be held).
//
// Keep this comfortably above the number of 2MiB regions we may split during
// long fuzz/bring-up sessions to avoid recovery starvation.
const BOOT_PT_POOL_PAGES: usize = 1024;

static PT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);
static PAGE_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static COW_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_COPY_COUNT: AtomicU64 = AtomicU64::new(0);
static KERNEL_ROOT_CR3: AtomicUsize = AtomicUsize::new(0);
static RECOVER_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static RECOVER_LAST_ADDR: AtomicUsize = AtomicUsize::new(0);
static RECOVER_LAST_ERROR: AtomicU64 = AtomicU64::new(0);
static RECOVER_LAST_REASON: AtomicU8 = AtomicU8::new(0);

static mut PT_POOL: [PageTablePage; BOOT_PT_POOL_PAGES] =
    [PageTablePage::zeroed(); BOOT_PT_POOL_PAGES];

#[inline]
fn align_down(v: usize, align: usize) -> usize {
    v & !(align - 1)
}

#[inline]
fn indices_for(virt: usize) -> (usize, usize, usize, usize) {
    (
        (virt >> 39) & 0x1FF,
        (virt >> 30) & 0x1FF,
        (virt >> 21) & 0x1FF,
        (virt >> 12) & 0x1FF,
    )
}

#[inline]
fn is_present(entry: u64) -> bool {
    (entry & PTE_PRESENT) != 0
}

#[inline]
fn is_huge_2m(entry: u64) -> bool {
    (entry & (PTE_PRESENT | PTE_PS)) == (PTE_PRESENT | PTE_PS)
}

#[inline]
fn entry_addr(entry: u64) -> usize {
    (entry & PTE_ADDR_MASK) as usize
}

unsafe fn alloc_boot_pt_page() -> Option<*mut PageTablePage> {
    let idx = PT_POOL_NEXT.fetch_add(1, Ordering::Relaxed);
    if idx >= BOOT_PT_POOL_PAGES {
        return None;
    }
    let base = core::ptr::addr_of_mut!(PT_POOL) as *mut PageTablePage;
    let page = base.add(idx);
    ptr::write_bytes(page as *mut u8, 0, core::mem::size_of::<PageTablePage>());
    Some(page)
}

fn alloc_runtime_pt_page() -> Result<usize, &'static str> {
    crate::memory::allocate_frame()
}

impl X86_64Mmu {
    #[inline]
    fn read_cr3(&self) -> usize {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        cr3 as usize
    }

    unsafe fn pml4_ptr(&self) -> *mut u64 {
        (self.read_cr3() as u64 & PTE_ADDR_MASK) as *mut u64
    }

    unsafe fn pml4_ptr_from_root(root_phys: usize) -> *mut u64 {
        ((root_phys as u64) & PTE_ADDR_MASK) as *mut u64
    }

    unsafe fn split_2m_page(pd_entry_ptr: *mut u64) -> Result<*mut u64, &'static str> {
        let pd_entry = ptr::read_volatile(pd_entry_ptr);
        if !is_huge_2m(pd_entry) {
            return Err("not a 2MiB page");
        }

        let pt_page = alloc_boot_pt_page().ok_or("x86_64 PT pool exhausted")?;
        let pt_ptr = (*pt_page).entries.as_mut_ptr();

        let base_phys = pd_entry & PTE_ADDR_MASK;
        let mut pte_flags = (pd_entry & PTE_FLAGS_LOW_MASK) | (pd_entry & PTE_NX);
        pte_flags &= !PTE_PS;
        pte_flags |= PTE_PRESENT;

        for i in 0..ENTRIES_PER_TABLE {
            let phys = base_phys + ((i * PAGE_SIZE) as u64);
            ptr::write(pt_ptr.add(i), (phys & PTE_ADDR_MASK) | pte_flags);
        }

        let pd_flags = (pd_entry & PTE_FLAGS_LOW_MASK) & !PTE_PS;
        let new_pd_entry = ((pt_ptr as usize as u64) & PTE_ADDR_MASK) | pd_flags | PTE_PRESENT;
        ptr::write_volatile(pd_entry_ptr, new_pd_entry);
        MMU.flush_tlb_all();

        Ok(pt_ptr)
    }

    unsafe fn split_2m_page_runtime(
        pd_entry_ptr: *mut u64,
        force_user_accessible: bool,
    ) -> Result<*mut u64, &'static str> {
        let pd_entry = ptr::read_volatile(pd_entry_ptr);
        if !is_huge_2m(pd_entry) {
            return Err("not a 2MiB page");
        }

        let pt_phys = alloc_runtime_pt_page()?;
        let pt_ptr = pt_phys as *mut u64;
        ptr::write_bytes(pt_ptr as *mut u8, 0, PAGE_SIZE);

        let base_phys = pd_entry & PTE_ADDR_MASK;
        let mut pte_flags = (pd_entry & PTE_FLAGS_LOW_MASK) | (pd_entry & PTE_NX);
        pte_flags &= !PTE_PS;
        pte_flags |= PTE_PRESENT;
        if force_user_accessible {
            pte_flags |= PTE_USER | PTE_WRITABLE;
        }

        for i in 0..ENTRIES_PER_TABLE {
            let phys = base_phys + ((i * PAGE_SIZE) as u64);
            ptr::write(pt_ptr.add(i), (phys & PTE_ADDR_MASK) | pte_flags);
        }

        let mut pd_flags = (pd_entry & PTE_FLAGS_LOW_MASK) & !PTE_PS;
        pd_flags |= PTE_PRESENT;
        if force_user_accessible {
            pd_flags |= PTE_USER | PTE_WRITABLE;
        }
        let new_pd_entry = ((pt_phys as u64) & PTE_ADDR_MASK) | pd_flags;
        ptr::write_volatile(pd_entry_ptr, new_pd_entry);
        Ok(pt_ptr)
    }

    unsafe fn get_pd_entry_ptr(&self, virt: usize) -> Result<*mut u64, &'static str> {
        let (i4, i3, i2, _) = indices_for(virt);

        let pml4 = self.pml4_ptr();
        let pml4e = ptr::read_volatile(pml4.add(i4));
        if !is_present(pml4e) {
            return Err("PML4 entry not present");
        }

        let pdpt = entry_addr(pml4e) as *mut u64;
        let pdpte = ptr::read_volatile(pdpt.add(i3));
        if !is_present(pdpte) {
            return Err("PDPT entry not present");
        }
        if (pdpte & PTE_PS) != 0 {
            return Err("1GiB pages not supported by x86_64 mmu walker");
        }

        let pd = entry_addr(pdpte) as *mut u64;
        Ok(pd.add(i2))
    }

    unsafe fn pte_ptr_for_virt(
        &self,
        virt: usize,
        split_huge_pages: bool,
    ) -> Result<*mut u64, &'static str> {
        let (_, _, _, i1) = indices_for(virt);
        let pd_entry_ptr = self.get_pd_entry_ptr(virt)?;
        let mut pd_entry = ptr::read_volatile(pd_entry_ptr);
        if !is_present(pd_entry) {
            return Err("PD entry not present");
        }

        if is_huge_2m(pd_entry) {
            if !split_huge_pages {
                return Err("virt maps through 2MiB page");
            }
            let pt_ptr = Self::split_2m_page(pd_entry_ptr)?;
            return Ok(pt_ptr.add(i1));
        }

        let pt = entry_addr(pd_entry) as *mut u64;
        pd_entry = ptr::read_volatile(pd_entry_ptr);
        if !is_present(pd_entry) {
            return Err("PD entry lost during split");
        }
        Ok(pt.add(i1))
    }

    unsafe fn ensure_table_entry(
        entry_ptr: *mut u64,
        user_accessible: bool,
    ) -> Result<*mut u64, &'static str> {
        let mut entry = ptr::read_volatile(entry_ptr);
        if !is_present(entry) {
            let table_phys = alloc_runtime_pt_page()?;
            ptr::write_bytes(table_phys as *mut u8, 0, PAGE_SIZE);
            let mut flags = PTE_PRESENT | PTE_WRITABLE;
            if user_accessible {
                flags |= PTE_USER;
            }
            entry = ((table_phys as u64) & PTE_ADDR_MASK) | flags;
            ptr::write_volatile(entry_ptr, entry);
            return Ok(table_phys as *mut u64);
        }

        if (entry & PTE_PS) != 0 {
            return Err("unexpected huge page at upper page-table level");
        }

        if user_accessible && (entry & PTE_USER) == 0 {
            entry |= PTE_USER | PTE_WRITABLE;
            ptr::write_volatile(entry_ptr, entry);
        }

        Ok(entry_addr(entry) as *mut u64)
    }

    unsafe fn ensure_table_entry_boot(entry_ptr: *mut u64) -> Result<*mut u64, &'static str> {
        let mut entry = ptr::read_volatile(entry_ptr);
        if !is_present(entry) {
            let table_page = alloc_boot_pt_page().ok_or("x86_64 PT pool exhausted")?;
            let table_ptr = (*table_page).entries.as_mut_ptr();
            entry = ((table_ptr as usize as u64) & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE;
            ptr::write_volatile(entry_ptr, entry);
            return Ok(table_ptr);
        }
        if (entry & PTE_PS) != 0 {
            return Err("unexpected huge page at upper page-table level");
        }
        Ok(entry_addr(entry) as *mut u64)
    }

    unsafe fn map_identity_page_boot(
        root_phys: usize,
        virt_addr: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        let virt_page = align_down(virt_addr, PAGE_SIZE);
        let (i4, i3, i2, i1) = indices_for(virt_page);

        let pml4 = Self::pml4_ptr_from_root(root_phys);
        let pdpt = Self::ensure_table_entry_boot(pml4.add(i4))?;
        let pd = Self::ensure_table_entry_boot(pdpt.add(i3))?;

        let pde_ptr = pd.add(i2);
        let pde = ptr::read_volatile(pde_ptr);
        let pt = if !is_present(pde) {
            let pt_page = alloc_boot_pt_page().ok_or("x86_64 PT pool exhausted")?;
            let pt_ptr = (*pt_page).entries.as_mut_ptr();
            let new_pde = ((pt_ptr as usize as u64) & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE;
            ptr::write_volatile(pde_ptr, new_pde);
            pt_ptr
        } else if is_huge_2m(pde) {
            Self::split_2m_page(pde_ptr)?
        } else {
            entry_addr(pde) as *mut u64
        };

        let pte_ptr = pt.add(i1);
        let old = ptr::read_volatile(pte_ptr);
        let mut new_pte = ((virt_page as u64) & PTE_ADDR_MASK) | PTE_PRESENT;
        if writable {
            new_pte |= PTE_WRITABLE;
        }
        if !is_present(old) || old != new_pte {
            ptr::write_volatile(pte_ptr, new_pte);
        }
        MMU.flush_tlb_page(virt_page);
        Ok(())
    }

    unsafe fn pte_ptr_for_root(
        root_phys: usize,
        virt: usize,
        split_huge_pages: bool,
        create_missing: bool,
        user_accessible: bool,
    ) -> Result<*mut u64, &'static str> {
        let (i4, i3, i2, i1) = indices_for(virt);

        let pml4 = Self::pml4_ptr_from_root(root_phys);
        let pml4e_ptr = pml4.add(i4);
        let pdpt = if create_missing {
            Self::ensure_table_entry(pml4e_ptr, user_accessible)?
        } else {
            let entry = ptr::read_volatile(pml4e_ptr);
            if !is_present(entry) {
                return Err("PML4 entry not present");
            }
            if user_accessible && (entry & PTE_USER) == 0 {
                let updated = entry | PTE_USER | PTE_WRITABLE;
                ptr::write_volatile(pml4e_ptr, updated);
            }
            entry_addr(entry) as *mut u64
        };

        let pdpte_ptr = pdpt.add(i3);
        let pd = if create_missing {
            Self::ensure_table_entry(pdpte_ptr, user_accessible)?
        } else {
            let entry = ptr::read_volatile(pdpte_ptr);
            if !is_present(entry) {
                return Err("PDPT entry not present");
            }
            if (entry & PTE_PS) != 0 {
                return Err("1GiB pages not supported");
            }
            if user_accessible && (entry & PTE_USER) == 0 {
                let updated = entry | PTE_USER | PTE_WRITABLE;
                ptr::write_volatile(pdpte_ptr, updated);
            }
            entry_addr(entry) as *mut u64
        };

        let pde_ptr = pd.add(i2);
        let mut pde = ptr::read_volatile(pde_ptr);
        if !is_present(pde) {
            if !create_missing {
                return Err("PD entry not present");
            }
            let pt_phys = alloc_runtime_pt_page()?;
            ptr::write_bytes(pt_phys as *mut u8, 0, PAGE_SIZE);
            let mut flags = PTE_PRESENT | PTE_WRITABLE;
            if user_accessible {
                flags |= PTE_USER;
            }
            pde = ((pt_phys as u64) & PTE_ADDR_MASK) | flags;
            ptr::write_volatile(pde_ptr, pde);
        } else if is_huge_2m(pde) {
            if !split_huge_pages {
                return Err("virt maps through 2MiB page");
            }
            let _ = Self::split_2m_page_runtime(pde_ptr, user_accessible)?;
            pde = ptr::read_volatile(pde_ptr);
        } else if user_accessible && (pde & PTE_USER) == 0 {
            pde |= PTE_USER | PTE_WRITABLE;
            ptr::write_volatile(pde_ptr, pde);
        }

        if !is_present(pde) || (pde & PTE_PS) != 0 {
            return Err("PDE did not resolve to PT");
        }
        let pt = entry_addr(pde) as *mut u64;
        Ok(pt.add(i1))
    }

    unsafe fn update_entry_low_flags(entry_low_ptr: *mut u32, set_mask: u32, clear_mask: u32) {
        let lo = ptr::read_volatile(entry_low_ptr);
        let hi = ptr::read_volatile(entry_low_ptr.add(1));
        let mut full = ((hi as u64) << 32) | (lo as u64);
        full |= set_mask as u64;
        full &= !(clear_mask as u64);
        ptr::write_volatile(entry_low_ptr, full as u32);
        ptr::write_volatile(entry_low_ptr.add(1), (full >> 32) as u32);
    }

    unsafe fn update_entry64_flags(entry_ptr: *mut u64, set_mask: u64, clear_mask: u64) -> u64 {
        let mut entry = ptr::read_volatile(entry_ptr);
        entry |= set_mask;
        entry &= !clear_mask;
        ptr::write_volatile(entry_ptr, entry);
        entry
    }

    unsafe fn virt_to_phys_with_root(root_phys: usize, virt_addr: usize) -> Option<usize> {
        let virt_page = align_down(virt_addr, PAGE_SIZE);
        let page_off = virt_addr & (PAGE_SIZE - 1);
        let (i4, i3, i2, i1) = indices_for(virt_page);

        let pml4 = Self::pml4_ptr_from_root(root_phys);
        let pml4e = ptr::read_volatile(pml4.add(i4));
        if !is_present(pml4e) {
            return None;
        }

        let pdpt = entry_addr(pml4e) as *mut u64;
        let pdpte = ptr::read_volatile(pdpt.add(i3));
        if !is_present(pdpte) {
            return None;
        }
        if (pdpte & PTE_PS) != 0 {
            return None;
        }

        let pd = entry_addr(pdpte) as *mut u64;
        let pde = ptr::read_volatile(pd.add(i2));
        if !is_present(pde) {
            return None;
        }
        if is_huge_2m(pde) {
            let base = entry_addr(pde);
            let off = virt_addr & (HUGE_PAGE_SIZE_2M - 1);
            return Some(base + off);
        }

        let pt = entry_addr(pde) as *mut u64;
        let pte = ptr::read_volatile(pt.add(i1));
        if !is_present(pte) {
            return None;
        }
        Some(entry_addr(pte) + page_off)
    }
}

pub struct AddressSpace {
    cr3_phys: usize,
}

impl AddressSpace {
    pub fn current() -> Self {
        Self {
            cr3_phys: MMU.read_cr3(),
        }
    }

    pub fn new() -> Result<Self, &'static str> {
        let current_root = MMU.read_cr3();
        let new_root = alloc_runtime_pt_page()?;

        unsafe {
            ptr::copy_nonoverlapping(current_root as *const u8, new_root as *mut u8, PAGE_SIZE);

            let new_pml4 = X86_64Mmu::pml4_ptr_from_root(new_root);
            let pml4e0 = ptr::read_volatile(new_pml4.add(0));
            if is_present(pml4e0) {
                let old_pdpt_phys = entry_addr(pml4e0);
                let new_pdpt_phys = alloc_runtime_pt_page()?;
                ptr::copy_nonoverlapping(
                    old_pdpt_phys as *const u8,
                    new_pdpt_phys as *mut u8,
                    PAGE_SIZE,
                );
                let pml4e0_new =
                    (pml4e0 & !PTE_ADDR_MASK) | ((new_pdpt_phys as u64) & PTE_ADDR_MASK);
                ptr::write_volatile(new_pml4.add(0), pml4e0_new);

                let new_pdpt = new_pdpt_phys as *mut u64;
                let pdpte0 = ptr::read_volatile(new_pdpt.add(0));
                if is_present(pdpte0) && (pdpte0 & PTE_PS) == 0 {
                    let old_pd_phys = entry_addr(pdpte0);
                    let new_pd_phys = alloc_runtime_pt_page()?;
                    ptr::copy_nonoverlapping(
                        old_pd_phys as *const u8,
                        new_pd_phys as *mut u8,
                        PAGE_SIZE,
                    );
                    let pdpte0_new =
                        (pdpte0 & !PTE_ADDR_MASK) | ((new_pd_phys as u64) & PTE_ADDR_MASK);
                    ptr::write_volatile(new_pdpt.add(0), pdpte0_new);
                }
            }
        }

        Ok(Self { cr3_phys: new_root })
    }

    pub fn new_jit_sandbox() -> Result<Self, &'static str> {
        // For x86_64 bring-up, cloning the active root preserves the kernel
        // mappings needed to continue executing Rust after the sandbox CR3 switch.
        Self::new()
    }

    /// Clone this address space with copy-on-write semantics for writable user pages.
    ///
    /// The x86_64 runtime keeps a low identity-mapped kernel image under the same
    /// PML4 slot as user mappings. To avoid aliasing parent/child page-table edits,
    /// clone the complete user-visible 0..USER_TOP page-table structure while
    /// keeping physical user data pages shared and COW-tagged.
    pub fn clone_cow(&mut self) -> Result<Self, &'static str> {
        let parent_root = self.cr3_phys;
        let child_root = alloc_runtime_pt_page()?;

        unsafe {
            ptr::copy_nonoverlapping(parent_root as *const u8, child_root as *mut u8, PAGE_SIZE);

            let parent_pml4 = X86_64Mmu::pml4_ptr_from_root(parent_root);
            let child_pml4 = X86_64Mmu::pml4_ptr_from_root(child_root);
            let user_top = crate::paging::USER_TOP;
            if user_top == 0 {
                return Ok(Self {
                    cr3_phys: child_root,
                });
            }

            let user_end = user_top.saturating_sub(1);
            let last_pml4 = (user_end >> 39) & 0x1FF;

            for pml4_idx in 0..=last_pml4 {
                let parent_pml4e = ptr::read_volatile(parent_pml4.add(pml4_idx));
                if !is_present(parent_pml4e) {
                    continue;
                }
                if (parent_pml4e & PTE_PS) != 0 {
                    return Err("x86_64 clone_cow: huge PML4 entry unsupported");
                }

                let parent_pdpt_phys = entry_addr(parent_pml4e);
                let child_pdpt_phys = alloc_runtime_pt_page()?;
                ptr::copy_nonoverlapping(
                    parent_pdpt_phys as *const u8,
                    child_pdpt_phys as *mut u8,
                    PAGE_SIZE,
                );
                let child_pml4e =
                    (parent_pml4e & !PTE_ADDR_MASK) | ((child_pdpt_phys as u64) & PTE_ADDR_MASK);
                ptr::write_volatile(child_pml4.add(pml4_idx), child_pml4e);

                let parent_pdpt = parent_pdpt_phys as *mut u64;
                let child_pdpt = child_pdpt_phys as *mut u64;
                let pml4_base = pml4_idx << 39;

                for pdpt_idx in 0..ENTRIES_PER_TABLE {
                    let region_base = pml4_base | (pdpt_idx << 30);
                    if region_base >= user_top {
                        break;
                    }

                    let parent_pdpte = ptr::read_volatile(parent_pdpt.add(pdpt_idx));
                    if !is_present(parent_pdpte) {
                        continue;
                    }
                    if (parent_pdpte & PTE_PS) != 0 {
                        if (parent_pdpte & PTE_USER) != 0 {
                            return Err("x86_64 clone_cow: 1GiB user pages unsupported");
                        }
                        continue;
                    }

                    let parent_pd_phys = entry_addr(parent_pdpte);
                    let child_pd_phys = alloc_runtime_pt_page()?;
                    ptr::copy_nonoverlapping(
                        parent_pd_phys as *const u8,
                        child_pd_phys as *mut u8,
                        PAGE_SIZE,
                    );
                    let child_pdpte =
                        (parent_pdpte & !PTE_ADDR_MASK) | ((child_pd_phys as u64) & PTE_ADDR_MASK);
                    ptr::write_volatile(child_pdpt.add(pdpt_idx), child_pdpte);

                    let parent_pd = parent_pd_phys as *mut u64;
                    let child_pd = child_pd_phys as *mut u64;

                    for pde_idx in 0..ENTRIES_PER_TABLE {
                        let page_dir_base = region_base | (pde_idx << 21);
                        if page_dir_base >= user_top {
                            break;
                        }

                        let parent_pde = ptr::read_volatile(parent_pd.add(pde_idx));
                        if !is_present(parent_pde) {
                            continue;
                        }

                        if is_huge_2m(parent_pde) {
                            if (parent_pde & PTE_USER) != 0 {
                                return Err("x86_64 clone_cow: 2MiB user pages unsupported");
                            }
                            continue;
                        }

                        let parent_pt_phys = entry_addr(parent_pde);
                        let child_pt_phys = alloc_runtime_pt_page()?;
                        ptr::copy_nonoverlapping(
                            parent_pt_phys as *const u8,
                            child_pt_phys as *mut u8,
                            PAGE_SIZE,
                        );
                        let child_pde = (parent_pde & !PTE_ADDR_MASK)
                            | ((child_pt_phys as u64) & PTE_ADDR_MASK);
                        ptr::write_volatile(child_pd.add(pde_idx), child_pde);

                        let parent_pt = parent_pt_phys as *mut u64;
                        let child_pt = child_pt_phys as *mut u64;

                        for pte_idx in 0..ENTRIES_PER_TABLE {
                            let virt = page_dir_base | (pte_idx << 12);
                            if virt >= user_top {
                                break;
                            }

                            let parent_pte_ptr = parent_pt.add(pte_idx);
                            let pte = ptr::read_volatile(parent_pte_ptr);
                            if !is_present(pte) {
                                continue;
                            }
                            if (pte & PTE_USER) == 0 || (pte & PTE_WRITABLE) == 0 {
                                continue;
                            }

                            let cow_pte = (pte | PTE_COW_SOFT) & !PTE_WRITABLE;
                            ptr::write_volatile(parent_pte_ptr, cow_pte);
                            ptr::write_volatile(child_pt.add(pte_idx), cow_pte);
                        }
                    }
                }
            }
        }

        if MMU.read_cr3() == self.cr3_phys {
            MMU.flush_tlb_all();
        }

        Ok(Self {
            cr3_phys: child_root,
        })
    }

    pub fn page_table_root_addr(&self) -> usize {
        self.cr3_phys
    }

    pub fn phys_addr(&self) -> usize {
        self.cr3_phys
    }

    pub unsafe fn activate(&self) {
        let _ = MMU.set_page_table_root(self.cr3_phys);
    }

    pub fn virt_to_phys(&self, virt_addr: usize) -> Option<usize> {
        unsafe { X86_64Mmu::virt_to_phys_with_root(self.cr3_phys, virt_addr) }
    }

    pub fn is_mapped(&self, virt_addr: usize) -> bool {
        self.virt_to_phys(virt_addr).is_some()
    }

    pub fn map_user_range_phys(
        &mut self,
        virt_start: usize,
        phys_start: usize,
        size: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }
        let mut virt = align_down(virt_start, PAGE_SIZE);
        let mut phys = align_down(phys_start, PAGE_SIZE);
        let end = virt_start
            .checked_add(size)
            .and_then(|v| v.checked_add(PAGE_SIZE - 1))
            .map(|v| align_down(v, PAGE_SIZE))
            .ok_or("range overflow")?;
        while virt < end {
            self.map_page(virt, phys, writable, true)?;
            virt = virt.saturating_add(PAGE_SIZE);
            phys = phys.saturating_add(PAGE_SIZE);
        }
        Ok(())
    }

    pub fn alloc_user_pages(
        &mut self,
        virt_addr: usize,
        count: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        if count == 0 {
            return Ok(());
        }
        if virt_addr >= crate::paging::USER_TOP {
            return Err("User mapping into kernel space");
        }
        for i in 0..count {
            let vaddr = virt_addr
                .checked_add(i.checked_mul(PAGE_SIZE).ok_or("virt overflow")?)
                .ok_or("virt overflow")?;
            if vaddr >= crate::paging::USER_TOP {
                return Err("User mapping into kernel space");
            }
            let phys = crate::memory::allocate_frame()?;
            self.map_page(vaddr, phys, writable, true)?;
        }
        Ok(())
    }

    pub fn map_page(
        &mut self,
        virt_addr: usize,
        phys_addr: usize,
        writable: bool,
        user_accessible: bool,
    ) -> Result<(), &'static str> {
        let virt_aligned = align_down(virt_addr, PAGE_SIZE);
        let phys_aligned = align_down(phys_addr, PAGE_SIZE);

        if user_accessible && virt_aligned >= crate::paging::USER_TOP {
            return Err("User mapping into kernel space");
        }
        if user_accessible {
            crate::memory_isolation::validate_mapping_request(
                phys_aligned,
                PAGE_SIZE,
                writable,
                true,
            )?;
        }

        let pte_ptr = unsafe {
            X86_64Mmu::pte_ptr_for_root(self.cr3_phys, virt_aligned, true, true, user_accessible)?
        };

        let mut flags = PTE_PRESENT;
        if writable {
            flags |= PTE_WRITABLE;
        }
        if user_accessible {
            flags |= PTE_USER;
        }

        unsafe {
            ptr::write_volatile(pte_ptr, ((phys_aligned as u64) & PTE_ADDR_MASK) | flags);
        }

        if MMU.read_cr3() == self.cr3_phys {
            MMU.flush_tlb_page(virt_aligned);
        }
        Ok(())
    }

    pub fn unmap_page(&mut self, virt_addr: usize) -> Result<(), &'static str> {
        let virt_aligned = align_down(virt_addr, PAGE_SIZE);
        let pte_ptr = unsafe {
            X86_64Mmu::pte_ptr_for_root(self.cr3_phys, virt_aligned, false, false, false)?
        };
        let pte = unsafe { ptr::read_volatile(pte_ptr) };
        if !is_present(pte) {
            return Err("Page not mapped");
        }
        unsafe {
            ptr::write_volatile(pte_ptr, 0);
        }
        if MMU.read_cr3() == self.cr3_phys {
            MMU.flush_tlb_page(virt_aligned);
        }
        Ok(())
    }
}

impl ArchMmu for X86_64Mmu {
    type AddressSpace = AddressSpace;
    type PageTable = AddressSpace;

    fn name(&self) -> &'static str {
        "x86_64-longmode"
    }

    fn init(&self) -> Result<(), &'static str> {
        // Paging is already enabled by the x86_64 Multiboot2 boot stub before Rust entry.
        // Enable CR0.WP so supervisor writes honor read-only PTEs (required for COW/protection).
        let mut cr0: u64;
        unsafe {
            core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        }
        cr0 |= 1 << 16;
        unsafe {
            core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        }
        let _ = KERNEL_ROOT_CR3.compare_exchange(
            0,
            self.read_cr3(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        Ok(())
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        let root = KERNEL_ROOT_CR3.load(Ordering::SeqCst);
        if root != 0 {
            Some(root)
        } else {
            Some(self.read_cr3())
        }
    }

    fn current_page_table_root_addr(&self) -> usize {
        self.read_cr3()
    }

    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str> {
        let phys = phys_addr as u64;
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) phys, options(nostack, preserves_flags));
        }
        Ok(())
    }

    fn flush_tlb_page(&self, virt_addr: usize) {
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) virt_addr, options(nostack, preserves_flags));
        }
    }

    fn flush_tlb_all(&self) {
        let cr3 = self.read_cr3() as u64;
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
        }
    }

    fn set_page_attribute_range(
        &self,
        virt_addr: usize,
        size: usize,
        attr: PageAttribute,
        enabled: bool,
    ) -> Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }

        let start = align_down(virt_addr, PAGE_SIZE);
        let end = virt_addr
            .checked_add(size)
            .and_then(|v| v.checked_add(PAGE_SIZE - 1))
            .map(|v| align_down(v, PAGE_SIZE))
            .ok_or("range overflow")?;

        let (set_mask, clear_mask) = match (attr, enabled) {
            (PageAttribute::Writable, true) => (PTE_WRITABLE, 0),
            (PageAttribute::Writable, false) => (0, PTE_WRITABLE),
        };

        let mut addr = start;
        while addr < end {
            let pte_ptr = unsafe { self.pte_ptr_for_virt(addr, true)? };
            unsafe {
                let _ = Self::update_entry64_flags(pte_ptr, set_mask, clear_mask);
            }
            self.flush_tlb_page(addr);
            addr = addr.saturating_add(PAGE_SIZE);
        }
        Ok(())
    }
}

/// Identity-map a physical MMIO range into the current x86_64 page tables so
/// that device memory (e.g. the Bochs/VBE LFB at 0xFD000000) is accessible
/// to the kernel before the first write.  Each page in [phys, phys+size) is
/// installed as a writable, non-user-accessible identity PTE in the live CR3.
/// Safe to call from init context before the heap is active (uses the static
/// boot PT pool).  Silently ignores failures so boot can continue.
pub(crate) fn map_mmio_identity_range(phys: usize, size: usize) {
    if size == 0 {
        return;
    }
    let start = align_down(phys, PAGE_SIZE);
    // align_up: round phys+size up to the next page boundary
    let end_raw = phys.saturating_add(size);
    let end = (end_raw.wrapping_add(PAGE_SIZE - 1)) & !(PAGE_SIZE - 1);
    let root = MMU.read_cr3();
    let mut page = start;
    while page < end {
        let _ = unsafe { X86_64Mmu::map_identity_page_boot(root, page, true) };
        page = page.saturating_add(PAGE_SIZE);
    }
}

pub(crate) fn debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    unsafe { X86_64Mmu::virt_to_phys_with_root(MMU.read_cr3(), virt_addr) }
}

pub(crate) fn debug_mark_page_cow(virt_addr: usize) -> Result<(), &'static str> {
    let virt_page = align_down(virt_addr, PAGE_SIZE);
    let pte_ptr = unsafe { MMU.pte_ptr_for_virt(virt_page, true)? };
    unsafe {
        let _ = X86_64Mmu::update_entry64_flags(pte_ptr, PTE_COW_SOFT, PTE_WRITABLE);
    }
    MMU.flush_tlb_page(virt_page);
    Ok(())
}

pub(crate) fn debug_pf_stats() -> (u64, u64, u64) {
    (
        PAGE_FAULT_COUNT.load(Ordering::Relaxed),
        COW_FAULT_COUNT.load(Ordering::Relaxed),
        PAGE_COPY_COUNT.load(Ordering::Relaxed),
    )
}

pub(crate) fn debug_recover_stats() -> (usize, usize, u64, usize, u64, u8) {
    (
        PT_POOL_NEXT.load(Ordering::Relaxed),
        BOOT_PT_POOL_PAGES,
        RECOVER_FAIL_COUNT.load(Ordering::Relaxed),
        RECOVER_LAST_ADDR.load(Ordering::Relaxed),
        RECOVER_LAST_ERROR.load(Ordering::Relaxed),
        RECOVER_LAST_REASON.load(Ordering::Relaxed),
    )
}

#[inline]
fn range_contains(range: (usize, usize), addr: usize) -> bool {
    let (start, end) = range;
    start != 0 && end > start && addr >= start && addr < end
}

#[inline]
fn recoverable_kernel_identity_page(addr: usize) -> bool {
    // x86_64 bring-up currently runs with an identity-mapped low kernel image
    // (text/data/bss + jit arena + heap). Recover PFs in this low-kernel window
    // so long fuzz/JIT runs can repair transient page-table damage in-place.
    const KERNEL_LOW_BASE: usize = 0x0010_0000;
    let (_heap_start, heap_end) = crate::memory::heap_range();
    if heap_end > KERNEL_LOW_BASE && addr >= KERNEL_LOW_BASE && addr < heap_end {
        return true;
    }

    let (jit_start, jit_end) = crate::memory::jit_arena_range();
    if jit_start != 0 {
        let jitter_guard_start = jit_start.saturating_sub(PAGE_SIZE);
        if range_contains((jitter_guard_start, jit_end), addr) {
            return true;
        }
    }
    false
}

fn recover_nonpresent_kernel_data_page(fault_addr: usize, error: u64) -> bool {
    // Non-present write/read faults in managed kernel data regions can occur after
    // page-table corruption during bring-up stress. Reinstall an identity PTE so
    // the kernel can continue and report higher-level diagnostics.
    if (error & PF_ERR_PRESENT) != 0 {
        return false;
    }

    let fault_page = align_down(fault_addr, PAGE_SIZE);
    if !recoverable_kernel_identity_page(fault_page) {
        return false;
    }

    // Fault handlers must avoid heap-allocating page-table paths (can deadlock
    // if the fault happened while allocator locks were held).
    let recover = unsafe { X86_64Mmu::map_identity_page_boot(MMU.read_cr3(), fault_page, true) };
    if recover.is_err() {
        RECOVER_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        RECOVER_LAST_ADDR.store(fault_page, Ordering::Relaxed);
        RECOVER_LAST_ERROR.store(error, Ordering::Relaxed);
        RECOVER_LAST_REASON.store(1, Ordering::Relaxed);
        return false;
    }
    true
}

fn recover_kernel_data_write_fault(fault_addr: usize, error: u64) -> bool {
    // Recover write faults on managed mutable kernel regions that are mapped but
    // temporarily writable-cleared outside the COW path.
    if (error & (PF_ERR_PRESENT | PF_ERR_WRITE)) != (PF_ERR_PRESENT | PF_ERR_WRITE) {
        return false;
    }

    let fault_page = align_down(fault_addr, PAGE_SIZE);
    if !recoverable_kernel_identity_page(fault_page) {
        return false;
    }

    // Do not consume COW write faults in the generic recovery path.
    // Those must flow through the COW handler so remap/counter semantics stay correct.
    let pte_ptr = unsafe { MMU.pte_ptr_for_virt(fault_page, false) };
    if let Ok(p) = pte_ptr {
        let pte = unsafe { ptr::read_volatile(p) };
        if is_present(pte) && (pte & PTE_COW_SOFT) != 0 {
            return false;
        }
    }

    let recover = unsafe { X86_64Mmu::map_identity_page_boot(MMU.read_cr3(), fault_page, true) };
    if recover.is_err() {
        RECOVER_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        RECOVER_LAST_ADDR.store(fault_page, Ordering::Relaxed);
        RECOVER_LAST_ERROR.store(error, Ordering::Relaxed);
        RECOVER_LAST_REASON.store(2, Ordering::Relaxed);
        return false;
    }
    true
}

pub(crate) fn handle_page_fault(fault_addr: usize, error: u64) -> bool {
    PAGE_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);

    if recover_nonpresent_kernel_data_page(fault_addr, error) {
        return true;
    }
    if recover_kernel_data_write_fault(fault_addr, error) {
        return true;
    }

    if (error & (PF_ERR_PRESENT | PF_ERR_WRITE)) != (PF_ERR_PRESENT | PF_ERR_WRITE) {
        return false;
    }

    let fault_page = align_down(fault_addr, PAGE_SIZE);
    let pte_ptr = unsafe {
        match MMU.pte_ptr_for_virt(fault_page, false) {
            Ok(p) => p,
            Err(_) => return false,
        }
    };
    let pte = unsafe { ptr::read_volatile(pte_ptr) };
    if !is_present(pte) || (pte & PTE_COW_SOFT) == 0 {
        return false;
    }

    let old_phys = entry_addr(pte);
    let new_phys = match crate::memory::allocate_frame() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    unsafe {
        ptr::copy_nonoverlapping(old_phys as *const u8, new_phys as *mut u8, PAGE_SIZE);
        let mut new_pte = pte;
        new_pte &= !PTE_ADDR_MASK;
        new_pte |= (new_phys as u64) & PTE_ADDR_MASK;
        new_pte |= PTE_WRITABLE;
        new_pte &= !PTE_COW_SOFT;
        ptr::write_volatile(pte_ptr, new_pte);
    }
    MMU.flush_tlb_page(fault_page);

    COW_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
    PAGE_COPY_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

// -----------------------------------------------------------------------------
// Legacy paging helper symbol exports (x86_64 implementations)
// -----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn set_page_flags(pte_addr: *mut u32, flags: u32) {
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, flags, 0) }
}

#[no_mangle]
pub extern "C" fn clear_page_flags(pte_addr: *mut u32, flags: u32) {
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, 0, flags) }
}

#[no_mangle]
pub extern "C" fn mark_page_cow(pte_addr: *mut u32) {
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, PTE_COW_SOFT as u32, PTE_WRITABLE as u32) }
}

#[no_mangle]
pub extern "C" fn is_page_cow(pte_value: u32) -> u32 {
    if (pte_value & (PTE_COW_SOFT as u32)) != 0 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn clear_page_cow(pte_addr: *mut u32) {
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, 0, PTE_COW_SOFT as u32) }
}

#[no_mangle]
pub extern "C" fn atomic_set_page_flags(pte_addr: *mut u32, flags: u32) {
    compiler_fence(Ordering::Acquire);
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, flags, 0) }
    compiler_fence(Ordering::Release);
}

#[no_mangle]
pub extern "C" fn atomic_clear_page_flags(pte_addr: *mut u32, flags: u32) {
    compiler_fence(Ordering::Acquire);
    unsafe { X86_64Mmu::update_entry_low_flags(pte_addr, 0, flags) }
    compiler_fence(Ordering::Release);
}

#[no_mangle]
pub extern "C" fn copy_page_fast(src: *const u8, dst: *mut u8) {
    unsafe {
        ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
    }
}

#[no_mangle]
pub extern "C" fn copy_page_physical(src_phys: u32, dst_phys: u32) {
    unsafe {
        ptr::copy_nonoverlapping(
            src_phys as usize as *const u8,
            dst_phys as usize as *mut u8,
            PAGE_SIZE,
        );
    }
}

#[no_mangle]
pub extern "C" fn zero_page(addr: *mut u8) {
    unsafe { ptr::write_bytes(addr, 0, PAGE_SIZE) }
}

#[no_mangle]
pub extern "C" fn zero_page_fast(addr: *mut u8) {
    unsafe { ptr::write_bytes(addr, 0, PAGE_SIZE) }
}

#[no_mangle]
pub extern "C" fn page_fault_handler() {
    // No-op on x86_64 bring-up path: the x86_64 IDT is installed via arch::x86_64_runtime.
}

#[no_mangle]
pub extern "C" fn disable_paging() {
    // Intentionally a no-op on x86_64 bring-up builds.
}

#[no_mangle]
pub extern "C" fn get_page_fault_count() -> u32 {
    PAGE_FAULT_COUNT.load(Ordering::Relaxed) as u32
}

#[no_mangle]
pub extern "C" fn get_cow_fault_count() -> u32 {
    COW_FAULT_COUNT.load(Ordering::Relaxed) as u32
}

#[no_mangle]
pub extern "C" fn get_page_copy_count() -> u32 {
    PAGE_COPY_COUNT.load(Ordering::Relaxed) as u32
}

#[no_mangle]
pub extern "C" fn increment_page_fault_count() {
    PAGE_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn increment_cow_fault_count() {
    COW_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn increment_page_copy_count() {
    PAGE_COPY_COUNT.fetch_add(1, Ordering::Relaxed);
}
