use core::ptr;
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicUsize, Ordering};

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

const MAX_LOW32: u64 = u32::MAX as u64;

#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct PageTablePage {
    entries: [u64; ENTRIES_PER_TABLE],
}

impl PageTablePage {
    const fn zeroed() -> Self {
        Self { entries: [0; ENTRIES_PER_TABLE] }
    }
}

const BOOT_PT_POOL_PAGES: usize = 128;

static PT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);
static PAGE_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static COW_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static PAGE_COPY_COUNT: AtomicU64 = AtomicU64::new(0);

static mut PT_POOL: [PageTablePage; BOOT_PT_POOL_PAGES] = [PageTablePage::zeroed(); BOOT_PT_POOL_PAGES];

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

    unsafe fn update_entry_low_flags(
        entry_low_ptr: *mut u32,
        set_mask: u32,
        clear_mask: u32,
    ) {
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
}

impl ArchMmu for X86_64Mmu {
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
        Ok(())
    }

    fn page_size(&self) -> usize {
        PAGE_SIZE
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        Some(self.read_cr3())
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

pub(crate) fn debug_virt_to_phys(virt_addr: usize) -> Option<usize> {
    let virt_page = align_down(virt_addr, PAGE_SIZE);
    let page_off = virt_addr & (PAGE_SIZE - 1);
    unsafe {
        let pd_entry_ptr = MMU.get_pd_entry_ptr(virt_page).ok()?;
        let pd_entry = ptr::read_volatile(pd_entry_ptr);
        if !is_present(pd_entry) {
            return None;
        }
        if is_huge_2m(pd_entry) {
            let base = entry_addr(pd_entry);
            let off = virt_addr & (HUGE_PAGE_SIZE_2M - 1);
            return Some(base + off);
        }
        let pte_ptr = MMU.pte_ptr_for_virt(virt_page, false).ok()?;
        let pte = ptr::read_volatile(pte_ptr);
        if !is_present(pte) {
            return None;
        }
        Some(entry_addr(pte) + page_off)
    }
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

pub(crate) fn handle_page_fault(fault_addr: usize, error: u64) -> bool {
    PAGE_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);

    if (error & (PF_ERR_PRESENT | PF_ERR_WRITE)) != (PF_ERR_PRESENT | PF_ERR_WRITE) {
        return false;
    }

    let fault_page = align_down(fault_addr, PAGE_SIZE);
    let pte_ptr = unsafe { match MMU.pte_ptr_for_virt(fault_page, false) {
        Ok(p) => p,
        Err(_) => return false,
    }};
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
    unsafe {
        X86_64Mmu::update_entry_low_flags(
            pte_addr,
            PTE_COW_SOFT as u32,
            PTE_WRITABLE as u32,
        )
    }
}

#[no_mangle]
pub extern "C" fn is_page_cow(pte_value: u32) -> u32 {
    if (pte_value & (PTE_COW_SOFT as u32)) != 0 { 1 } else { 0 }
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
        ptr::copy_nonoverlapping(src_phys as usize as *const u8, dst_phys as usize as *mut u8, PAGE_SIZE);
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
