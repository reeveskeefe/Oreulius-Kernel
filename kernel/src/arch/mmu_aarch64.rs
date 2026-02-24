/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 */

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{ArchMmu, PageAttribute};
use crate::arch::{aarch64_pl011, aarch64_virt};
use crate::aarch64_alloc::AARCH64_MMU_PT_RESERVE_BYTES;

pub(super) struct AArch64Mmu;

pub(super) static MMU: AArch64Mmu = AArch64Mmu;

const PAGE_SIZE_4K: usize = 4096;
const PAGE_MASK_4K: usize = PAGE_SIZE_4K - 1;
const ENTRIES_PER_TABLE: usize = 512;
const L2_BLOCK_SIZE: usize = 2 * 1024 * 1024;
const L2_BLOCK_MASK: usize = L2_BLOCK_SIZE - 1;

const DESC_VALID: u64 = 1 << 0;
const DESC_TABLE_OR_PAGE: u64 = 1 << 1;
const DESC_AF: u64 = 1 << 10;
const DESC_SH_INNER: u64 = 0b11 << 8;
const DESC_AP_EL1_RW: u64 = 0b00 << 6;
const DESC_AP_EL0_RW: u64 = 0b01 << 6;
const DESC_AP_EL1_RO: u64 = 0b10 << 6;
const DESC_AP_EL0_RO: u64 = 0b11 << 6;
const DESC_ATTRIDX_NORMAL: u64 = 0 << 2;
const DESC_ATTRIDX_DEVICE: u64 = 1 << 2;
const DESC_PXN: u64 = 1 << 53;
const DESC_UXN: u64 = 1 << 54;
const DESC_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

const MAIR_ATTR_NORMAL_WBWA: u64 = 0xFF;
const MAIR_ATTR_DEVICE_nGnRnE: u64 = 0x00;
const MAIR_VALUE: u64 = (MAIR_ATTR_NORMAL_WBWA << 0) | (MAIR_ATTR_DEVICE_nGnRnE << 8);

const TCR_T0SZ: u64 = 16; // 48-bit VA
const TCR_T1SZ: u64 = 16;
const TCR_IRGN_WBWA: u64 = 0b01;
const TCR_ORGN_WBWA: u64 = 0b01;
const TCR_SH_INNER: u64 = 0b11;
const TCR_TG0_4K: u64 = 0b00;
const TCR_TG1_4K: u64 = 0b10;
const TCR_IPS_40BIT: u64 = 0b010;
const TCR_VALUE: u64 =
    (TCR_T0SZ << 0)
    | (TCR_IRGN_WBWA << 8)
    | (TCR_ORGN_WBWA << 10)
    | (TCR_SH_INNER << 12)
    | (TCR_TG0_4K << 14)
    | (TCR_T1SZ << 16)
    | (TCR_IRGN_WBWA << 24)
    | (TCR_ORGN_WBWA << 26)
    | (TCR_SH_INNER << 28)
    | (TCR_TG1_4K << 30)
    | (TCR_IPS_40BIT << 32);
const MAX_LIVE_PT_SCAN_TABLES: usize = 2048;

static MMU_INITIALIZED: AtomicBool = AtomicBool::new(false);
static KERNEL_ROOT_PHYS: AtomicUsize = AtomicUsize::new(0);
static PAGE_ALLOC_NEXT: AtomicUsize = AtomicUsize::new(0);
static PAGE_ALLOC_END: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug)]
pub struct AddressSpace {
    ttbr0_el1: usize,
}

impl AddressSpace {
    fn clone_from_root_phys(root: usize) -> Result<Self, &'static str> {
        if root == 0 {
            return Err("AArch64 TTBR0_EL1 is not initialized");
        }
        init_page_allocator_if_needed();
        let cloned = clone_table_recursive(root, 0)?;
        Ok(Self { ttbr0_el1: cloned })
    }

    pub fn new() -> Result<Self, &'static str> {
        let mut root = ttbr_phys_addr(read_ttbr0_el1());
        if root == 0 {
            root = KERNEL_ROOT_PHYS.load(Ordering::Relaxed);
        }
        Self::clone_from_root_phys(root)
    }

    pub fn new_from_kernel_root() -> Result<Self, &'static str> {
        let mut root = KERNEL_ROOT_PHYS.load(Ordering::Relaxed);
        if root == 0 {
            root = ttbr_phys_addr(read_ttbr1_el1());
        }
        if root == 0 {
            root = ttbr_phys_addr(read_ttbr0_el1());
        }
        if root != 0 && KERNEL_ROOT_PHYS.load(Ordering::Relaxed) == 0 {
            KERNEL_ROOT_PHYS.store(root, Ordering::Relaxed);
        }
        Self::clone_from_root_phys(root)
    }

    pub fn new_kernel_template() -> Result<Self, &'static str> {
        init_page_allocator_if_needed();
        let root = alloc_page_raw()?;
        populate_kernel_mappings(root)?;
        Ok(Self { ttbr0_el1: root })
    }

    pub fn new_jit_sandbox() -> Result<Self, &'static str> {
        Self::new()
    }

    pub fn page_table_root_addr(&self) -> usize {
        self.ttbr0_el1
    }

    pub fn phys_addr(&self) -> usize {
        self.ttbr0_el1
    }

    pub unsafe fn activate(&self) {
        let _ = AArch64Mmu.set_page_table_root(self.ttbr0_el1);
    }

    pub fn virt_to_phys(&self, virt_addr: usize) -> Option<usize> {
        translate(self.ttbr0_el1, virt_addr)
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
        if (virt_start & PAGE_MASK_4K) != 0 || (phys_start & PAGE_MASK_4K) != 0 {
            return Err("AArch64 map_user_range_phys requires 4K alignment");
        }
        if size == 0 {
            return Ok(());
        }
        let pages = (size + PAGE_MASK_4K) / PAGE_SIZE_4K;
        for i in 0..pages {
            self.map_page(
                virt_start + i * PAGE_SIZE_4K,
                phys_start + i * PAGE_SIZE_4K,
                writable,
                true,
            )?;
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
            return Err("Invalid page count");
        }
        if (virt_addr & PAGE_MASK_4K) != 0 {
            return Err("AArch64 alloc_user_pages requires 4K alignment");
        }
        for i in 0..count {
            let phys = alloc_phys_page()?;
            self.map_page(
                virt_addr + i * PAGE_SIZE_4K,
                phys,
                writable,
                true,
            )?;
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
        map_page_4k(self.ttbr0_el1, virt_addr, phys_addr, writable, user_accessible)
    }

    pub fn unmap_page(&mut self, virt_addr: usize) -> Result<(), &'static str> {
        unmap_page_4k(self.ttbr0_el1, virt_addr)
    }
}

extern "C" {
    static _heap_start: usize;
    static _heap_end: usize;
}

#[derive(Clone, Copy)]
enum MemType {
    Normal,
    Device,
}

#[inline]
fn ttbr_phys_addr(raw: usize) -> usize {
    raw & (DESC_ADDR_MASK as usize)
}

#[inline]
fn read_ttbr0_el1() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("mrs {out}, TTBR0_EL1", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
fn read_ttbr1_el1() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("mrs {out}, TTBR1_EL1", out = out(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
fn table_mut(table_phys: usize) -> &'static mut [u64; ENTRIES_PER_TABLE] {
    unsafe { &mut *(table_phys as *mut [u64; ENTRIES_PER_TABLE]) }
}

#[inline]
fn table_ref(table_phys: usize) -> &'static [u64; ENTRIES_PER_TABLE] {
    unsafe { &*(table_phys as *const [u64; ENTRIES_PER_TABLE]) }
}

fn scan_live_table_tree_max(
    table_phys: usize,
    level: usize,
    seen: &mut [usize; MAX_LIVE_PT_SCAN_TABLES],
    seen_len: &mut usize,
    max_phys: &mut usize,
) {
    if table_phys == 0 || level > 3 {
        return;
    }
    for i in 0..*seen_len {
        if seen[i] == table_phys {
            return;
        }
    }
    if *seen_len < MAX_LIVE_PT_SCAN_TABLES {
        seen[*seen_len] = table_phys;
        *seen_len += 1;
    } else {
        return;
    }
    if table_phys > *max_phys {
        *max_phys = table_phys;
    }
    if level == 3 {
        return;
    }
    let table = table_ref(table_phys);
    for &desc in table.iter() {
        if desc_is_table(desc) {
            scan_live_table_tree_max(desc_addr(desc), level + 1, seen, seen_len, max_phys);
        }
    }
}

fn live_page_table_high_water() -> usize {
    let mut seen = [0usize; MAX_LIVE_PT_SCAN_TABLES];
    let mut seen_len = 0usize;
    let mut max_phys = 0usize;

    let mut roots = [0usize; 3];
    roots[0] = KERNEL_ROOT_PHYS.load(Ordering::Relaxed);
    roots[1] = ttbr_phys_addr(read_ttbr0_el1());
    roots[2] = ttbr_phys_addr(read_ttbr1_el1());

    for root in roots {
        if root != 0 {
            scan_live_table_tree_max(root, 0, &mut seen, &mut seen_len, &mut max_phys);
        }
    }
    max_phys
}

fn repair_page_allocator_cursor_if_stale() {
    let end = PAGE_ALLOC_END.load(Ordering::Relaxed);
    if end == 0 {
        return;
    }
    let high_water = live_page_table_high_water();
    if high_water == 0 {
        return;
    }
    let min_next = high_water
        .saturating_add(PAGE_SIZE_4K)
        .saturating_add(PAGE_MASK_4K)
        & !PAGE_MASK_4K;
    if min_next == 0 || min_next > end {
        return;
    }
    loop {
        let cur = PAGE_ALLOC_NEXT.load(Ordering::Relaxed);
        if cur >= min_next && cur != 0 {
            break;
        }
        if PAGE_ALLOC_NEXT
            .compare_exchange(cur, min_next, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
}

#[inline]
fn alloc_page_raw() -> Result<usize, &'static str> {
    repair_page_allocator_cursor_if_stale();
    let next = PAGE_ALLOC_NEXT.load(Ordering::Relaxed);
    let end = PAGE_ALLOC_END.load(Ordering::Relaxed);
    if next == 0 || end == 0 {
        return Err("AArch64 MMU allocator not initialized");
    }

    loop {
        let cur = PAGE_ALLOC_NEXT.load(Ordering::Relaxed);
        let aligned = (cur + PAGE_MASK_4K) & !PAGE_MASK_4K;
        let new = aligned.checked_add(PAGE_SIZE_4K).ok_or("AArch64 MMU allocator overflow")?;
        if new > end {
            return Err("AArch64 MMU allocator exhausted");
        }
        if PAGE_ALLOC_NEXT
            .compare_exchange(cur, new, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            unsafe { ptr::write_bytes(aligned as *mut u8, 0, PAGE_SIZE_4K); }
            return Ok(aligned);
        }
    }
}

fn alloc_phys_page() -> Result<usize, &'static str> {
    alloc_page_raw()
}

pub(crate) fn debug_alloc_page() -> Result<usize, &'static str> {
    alloc_phys_page()
}

fn init_page_allocator_if_needed() {
    if PAGE_ALLOC_NEXT.load(Ordering::Relaxed) != 0 {
        return;
    }
    let start = unsafe { (&_heap_start as *const usize) as usize };
    let heap_end = unsafe { (&_heap_end as *const usize) as usize };
    let end = start
        .saturating_add(AARCH64_MMU_PT_RESERVE_BYTES)
        .min(heap_end);
    if start == 0 || end <= start {
        return;
    }
    PAGE_ALLOC_NEXT.store(start, Ordering::Relaxed);
    PAGE_ALLOC_END.store(end, Ordering::Relaxed);
}

#[inline]
fn make_table_desc(next_table_phys: usize) -> u64 {
    ((next_table_phys as u64) & DESC_ADDR_MASK) | DESC_VALID | DESC_TABLE_OR_PAGE
}

fn clone_table_recursive(src_table_phys: usize, level: usize) -> Result<usize, &'static str> {
    if level > 3 {
        return Err("AArch64 MMU clone depth overflow");
    }
    let dst_table_phys = alloc_page_raw()?;
    if dst_table_phys == src_table_phys {
        return Err("AArch64 MMU clone allocator alias with source table");
    }
    let src = table_mut(src_table_phys);
    let dst = table_mut(dst_table_phys);
    for i in 0..ENTRIES_PER_TABLE {
        let desc = src[i];
        if level < 3 && desc_is_table(desc) {
            let child_src = desc_addr(desc);
            let child_dst = clone_table_recursive(child_src, level + 1)?;
            dst[i] = (desc & !DESC_ADDR_MASK) | (((child_dst as u64) & DESC_ADDR_MASK));
        } else {
            dst[i] = desc;
        }
    }
    Ok(dst_table_phys)
}

#[inline]
fn make_leaf_attrs(writable: bool, user: bool, mem: MemType, executable: bool) -> u64 {
    let ap = match (user, writable) {
        (false, true) => DESC_AP_EL1_RW,
        (false, false) => DESC_AP_EL1_RO,
        (true, true) => DESC_AP_EL0_RW,
        (true, false) => DESC_AP_EL0_RO,
    };
    let attr = match mem {
        MemType::Normal => DESC_ATTRIDX_NORMAL,
        MemType::Device => DESC_ATTRIDX_DEVICE,
    };
    let sh = match mem {
        MemType::Normal => DESC_SH_INNER,
        MemType::Device => DESC_SH_INNER,
    };
    let xn = if executable { 0 } else { DESC_PXN | DESC_UXN };
    attr | ap | sh | DESC_AF | xn
}

#[inline]
fn make_l2_block_desc(
    phys_addr: usize,
    writable: bool,
    user: bool,
    mem: MemType,
    executable: bool,
) -> u64 {
    ((phys_addr as u64) & DESC_ADDR_MASK) | make_leaf_attrs(writable, user, mem, executable) | DESC_VALID
}

#[inline]
fn make_l3_page_desc(
    phys_addr: usize,
    writable: bool,
    user: bool,
    mem: MemType,
    executable: bool,
) -> u64 {
    ((phys_addr as u64) & DESC_ADDR_MASK)
        | make_leaf_attrs(writable, user, mem, executable)
        | DESC_VALID
        | DESC_TABLE_OR_PAGE
}

#[inline]
fn desc_is_valid(desc: u64) -> bool {
    (desc & DESC_VALID) != 0
}

#[inline]
fn desc_is_table(desc: u64) -> bool {
    desc_is_valid(desc) && (desc & DESC_TABLE_OR_PAGE) != 0
}

#[inline]
fn desc_addr(desc: u64) -> usize {
    (desc & DESC_ADDR_MASK) as usize
}

#[inline]
fn l0_index(va: usize) -> usize { (va >> 39) & 0x1FF }
#[inline]
fn l1_index(va: usize) -> usize { (va >> 30) & 0x1FF }
#[inline]
fn l2_index(va: usize) -> usize { (va >> 21) & 0x1FF }
#[inline]
fn l3_index(va: usize) -> usize { (va >> 12) & 0x1FF }

fn ensure_next_table(table_phys: usize, index: usize) -> Result<usize, &'static str> {
    let table = table_mut(table_phys);
    let desc = table[index];
    if desc_is_valid(desc) {
        if desc_is_table(desc) {
            return Ok(desc_addr(desc));
        }
        return Err("AArch64 MMU mapping conflict (block descriptor present)");
    }
    let next = alloc_page_raw()?;
    table[index] = make_table_desc(next);
    Ok(next)
}

fn l3_entry_mut(root_phys: usize, va: usize, create: bool) -> Result<Option<&'static mut u64>, &'static str> {
    let l0 = root_phys;
    let l1 = if create {
        ensure_next_table(l0, l0_index(va))?
    } else {
        let d = table_mut(l0)[l0_index(va)];
        if !desc_is_table(d) { return Ok(None); }
        desc_addr(d)
    };

    let l2 = if create {
        ensure_next_table(l1, l1_index(va))?
    } else {
        let d = table_mut(l1)[l1_index(va)];
        if !desc_is_table(d) { return Ok(None); }
        desc_addr(d)
    };

    let l2e_idx = l2_index(va);
    let l2e = table_mut(l2)[l2e_idx];
    let l3 = if desc_is_valid(l2e) {
        if desc_is_table(l2e) {
            desc_addr(l2e)
        } else {
            return Err("AArch64 MMU cannot insert 4K page under existing 2MB block");
        }
    } else if create {
        let next = alloc_page_raw()?;
        table_mut(l2)[l2e_idx] = make_table_desc(next);
        next
    } else {
        return Ok(None);
    };

    Ok(Some(&mut table_mut(l3)[l3_index(va)]))
}

fn map_page_4k(
    root_phys: usize,
    virt_addr: usize,
    phys_addr: usize,
    writable: bool,
    user_accessible: bool,
) -> Result<(), &'static str> {
    if (virt_addr & PAGE_MASK_4K) != 0 || (phys_addr & PAGE_MASK_4K) != 0 {
        return Err("AArch64 map_page requires 4K alignment");
    }
    let Some(entry) = l3_entry_mut(root_phys, virt_addr, true)? else {
        return Err("AArch64 L3 entry creation failed");
    };
    *entry = make_l3_page_desc(phys_addr, writable, user_accessible, MemType::Normal, false);
    AArch64Mmu.flush_tlb_page(virt_addr);
    Ok(())
}

fn unmap_page_4k(root_phys: usize, virt_addr: usize) -> Result<(), &'static str> {
    if (virt_addr & PAGE_MASK_4K) != 0 {
        return Err("AArch64 unmap_page requires 4K alignment");
    }
    let Some(entry) = l3_entry_mut(root_phys, virt_addr, false)? else {
        return Err("AArch64 unmap_page: page not mapped");
    };
    if !desc_is_valid(*entry) {
        return Err("AArch64 unmap_page: page not mapped");
    }
    *entry = 0;
    AArch64Mmu.flush_tlb_page(virt_addr);
    Ok(())
}

fn map_range_l2_blocks(
    root_phys: usize,
    virt_start: usize,
    phys_start: usize,
    size: usize,
    mem: MemType,
    executable: bool,
) -> Result<(), &'static str> {
    if size == 0 {
        return Ok(());
    }
    let start = virt_start & !L2_BLOCK_MASK;
    let pstart = phys_start & !L2_BLOCK_MASK;
    let end = (virt_start + size + L2_BLOCK_MASK) & !L2_BLOCK_MASK;
    let mut va = start;
    let mut pa = pstart;
    while va < end {
        let l0 = ensure_next_table(root_phys, l0_index(va))?;
        let l1 = ensure_next_table(l0, l1_index(va))?;
        let idx2 = l2_index(va);
        let l2 = table_mut(l1);
        let desc = l2[idx2];
        if desc_is_valid(desc) && !desc_is_table(desc) {
            // Already mapped as a block; keep the existing entry.
        } else if desc_is_valid(desc) && desc_is_table(desc) {
            return Err("AArch64 MMU init conflict (expected block-capable L2 slot)");
        } else {
            l2[idx2] = make_l2_block_desc(pa, true, false, mem, executable);
        }
        va = va.saturating_add(L2_BLOCK_SIZE);
        pa = pa.saturating_add(L2_BLOCK_SIZE);
    }
    Ok(())
}

fn translate(root_phys: usize, virt_addr: usize) -> Option<usize> {
    if root_phys == 0 {
        return None;
    }

    let l0 = table_mut(root_phys);
    let d0 = l0[l0_index(virt_addr)];
    if !desc_is_table(d0) {
        return None;
    }
    let l1 = table_mut(desc_addr(d0));
    let d1 = l1[l1_index(virt_addr)];
    if !desc_is_table(d1) {
        return None;
    }
    let l2 = table_mut(desc_addr(d1));
    let d2 = l2[l2_index(virt_addr)];
    if !desc_is_valid(d2) {
        return None;
    }
    if !desc_is_table(d2) {
        let base = desc_addr(d2);
        return Some(base + (virt_addr & L2_BLOCK_MASK));
    }
    let l3 = table_mut(desc_addr(d2));
    let d3 = l3[l3_index(virt_addr)];
    if !desc_is_valid(d3) {
        return None;
    }
    Some(desc_addr(d3) + (virt_addr & PAGE_MASK_4K))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DebugWalk {
    pub root_phys: usize,
    pub l0_desc: u64,
    pub l1_desc: u64,
    pub l2_desc: u64,
    pub l3_desc: u64,
    pub phys_addr: Option<usize>,
}

pub(crate) fn debug_translate_current(virt_addr: usize) -> Option<usize> {
    let mut root = ttbr_phys_addr(read_ttbr0_el1());
    if root == 0 {
        root = KERNEL_ROOT_PHYS.load(Ordering::Relaxed);
    }
    if root == 0 {
        return None;
    }
    translate(root, virt_addr)
}

pub(crate) fn debug_walk_current(virt_addr: usize) -> DebugWalk {
    let mut root = ttbr_phys_addr(read_ttbr0_el1());
    if root == 0 {
        root = KERNEL_ROOT_PHYS.load(Ordering::Relaxed);
    }
    let mut out = DebugWalk {
        root_phys: root,
        l0_desc: 0,
        l1_desc: 0,
        l2_desc: 0,
        l3_desc: 0,
        phys_addr: None,
    };
    if root == 0 {
        return out;
    }
    let l0 = table_mut(root);
    let l0d = l0[l0_index(virt_addr)];
    out.l0_desc = l0d;
    if !desc_is_valid(l0d) || !desc_is_table(l0d) {
        return out;
    }
    let l1_phys = desc_addr(l0d);
    let l1 = table_mut(l1_phys);
    let l1d = l1[l1_index(virt_addr)];
    out.l1_desc = l1d;
    if !desc_is_valid(l1d) || !desc_is_table(l1d) {
        return out;
    }
    let l2_phys = desc_addr(l1d);
    let l2 = table_mut(l2_phys);
    let l2d = l2[l2_index(virt_addr)];
    out.l2_desc = l2d;
    if !desc_is_valid(l2d) {
        return out;
    }
    if !desc_is_table(l2d) {
        let block_base = desc_addr(l2d);
        out.phys_addr = Some(block_base + (virt_addr & L2_BLOCK_MASK));
        return out;
    }
    let l3_phys = desc_addr(l2d);
    let l3 = table_mut(l3_phys);
    let l3d = l3[l3_index(virt_addr)];
    out.l3_desc = l3d;
    if !desc_is_valid(l3d) {
        return out;
    }
    out.phys_addr = Some(desc_addr(l3d) + (virt_addr & PAGE_MASK_4K));
    out
}

fn set_pte_writable(root_phys: usize, virt_addr: usize, writable: bool) -> Result<(), &'static str> {
    let Some(entry) = l3_entry_mut(root_phys, virt_addr, false)? else {
        return Err("AArch64 MMU set_page_attribute_range: page not mapped");
    };
    if !desc_is_valid(*entry) {
        return Err("AArch64 MMU set_page_attribute_range: page not mapped");
    }

    let ap_mask = 0b11u64 << 6;
    let user = ((*entry >> 6) & 0b01) != 0 || ((*entry >> 6) & 0b11) == 0b11;
    let ap = match (user, writable) {
        (false, true) => DESC_AP_EL1_RW,
        (false, false) => DESC_AP_EL1_RO,
        (true, true) => DESC_AP_EL0_RW,
        (true, false) => DESC_AP_EL0_RO,
    };
    *entry = (*entry & !ap_mask) | ap;
    AArch64Mmu.flush_tlb_page(virt_addr);
    Ok(())
}

fn write_mair_tcr_ttbrs_and_enable(root_phys: usize) {
    unsafe {
        core::arch::asm!(
            "msr MAIR_EL1, {mair}",
            "msr TCR_EL1, {tcr}",
            "msr TTBR0_EL1, {ttbr}",
            "msr TTBR1_EL1, {ttbr}",
            "dsb ish",
            "isb",
            mair = in(reg) MAIR_VALUE,
            tcr = in(reg) TCR_VALUE,
            ttbr = in(reg) (root_phys as u64),
            options(nostack),
        );

        let mut sctlr: u64;
        core::arch::asm!("mrs {out}, SCTLR_EL1", out = out(reg) sctlr, options(nomem, nostack));
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12); // M, C, I
        core::arch::asm!(
            "msr SCTLR_EL1, {val}",
            "isb",
            val = in(reg) sctlr,
            options(nostack),
        );
    }
}

fn populate_kernel_mappings(root: usize) -> Result<(), &'static str> {
    // Map DRAM from DTB (or fallback), plus key MMIO regions.
    let (mem_base, mem_size) = aarch64_virt::discovered_memory_range()
        .unwrap_or((0x4000_0000, 512 * 1024 * 1024));
    map_range_l2_blocks(root, mem_base, mem_base, mem_size, MemType::Normal, true)?;

    let uart_base = aarch64_pl011::early_uart().base();
    map_range_l2_blocks(root, uart_base, uart_base, PAGE_SIZE_4K, MemType::Device, false)?;

    if let Some((gicd, gicc)) = aarch64_virt::discovered_gicv2_bases() {
        map_range_l2_blocks(root, gicd, gicd, PAGE_SIZE_4K * 64, MemType::Device, false)?;
        map_range_l2_blocks(root, gicc, gicc, PAGE_SIZE_4K * 64, MemType::Device, false)?;
    } else {
        map_range_l2_blocks(root, 0x0800_0000, 0x0800_0000, PAGE_SIZE_4K * 64, MemType::Device, false)?;
        map_range_l2_blocks(root, 0x0801_0000, 0x0801_0000, PAGE_SIZE_4K * 64, MemType::Device, false)?;
    }

    aarch64_virt::for_each_discovered_virtio_mmio(|base, size, _irq| {
        let _ = map_range_l2_blocks(root, base, base, size.max(PAGE_SIZE_4K), MemType::Device, false);
    });

    if let Some(dtb_ptr) = aarch64_virt::discovered_dtb_ptr() {
        if translate(root, dtb_ptr).is_none() {
            map_range_l2_blocks(root, dtb_ptr, dtb_ptr, 2 * 1024 * 1024, MemType::Normal, false)?;
        }
    }

    Ok(())
}

fn mmu_bootstrap_init() -> Result<(), &'static str> {
    if MMU_INITIALIZED.load(Ordering::Relaxed) {
        return Ok(());
    }

    init_page_allocator_if_needed();

    let root = alloc_page_raw()?;
    KERNEL_ROOT_PHYS.store(root, Ordering::Relaxed);

    populate_kernel_mappings(root)?;

    write_mair_tcr_ttbrs_and_enable(root);
    MMU_INITIALIZED.store(true, Ordering::Relaxed);
    Ok(())
}

impl ArchMmu for AArch64Mmu {
    fn name(&self) -> &'static str {
        "aarch64-4k-lpae"
    }

    fn init(&self) -> Result<(), &'static str> {
        mmu_bootstrap_init()
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE_4K
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        let raw = read_ttbr1_el1();
        let root = ttbr_phys_addr(raw);
        if root == 0 {
            nonzero_usize(KERNEL_ROOT_PHYS.load(Ordering::Relaxed))
        } else {
            Some(root)
        }
    }

    fn current_page_table_root_addr(&self) -> usize {
        let raw = read_ttbr0_el1();
        let root = ttbr_phys_addr(raw);
        if root == 0 {
            KERNEL_ROOT_PHYS.load(Ordering::Relaxed)
        } else {
            root
        }
    }

    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str> {
        if phys_addr == 0 {
            return Err("AArch64 TTBR0 root cannot be zero");
        }
        unsafe {
            core::arch::asm!(
                "msr TTBR0_EL1, {ttbr}",
                "dsb ish",
                "isb",
                ttbr = in(reg) (phys_addr as u64),
                options(nostack),
            );
        }
        Ok(())
    }

    fn flush_tlb_page(&self, virt_addr: usize) {
        let va = (virt_addr >> 12) as u64;
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vae1is, {va}",
                "dsb ish",
                "isb",
                va = in(reg) va,
                options(nostack),
            );
        }
    }

    fn flush_tlb_all(&self) {
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack),
            );
        }
    }

    fn set_page_attribute_range(
        &self,
        virt_addr: usize,
        size: usize,
        attr: PageAttribute,
        enabled: bool,
    ) -> Result<(), &'static str> {
        if attr != PageAttribute::Writable {
            return Err("AArch64 MMU unsupported page attribute");
        }
        if size == 0 {
            return Ok(());
        }
        let root = self.current_page_table_root_addr();
        let start = virt_addr & !PAGE_MASK_4K;
        let end = (virt_addr + size + PAGE_MASK_4K) & !PAGE_MASK_4K;
        let mut va = start;
        while va < end {
            set_pte_writable(root, va, enabled)?;
            va = va.saturating_add(PAGE_SIZE_4K);
        }
        Ok(())
    }
}

#[inline]
fn nonzero_usize(v: usize) -> Option<usize> {
    if v == 0 { None } else { Some(v) }
}
