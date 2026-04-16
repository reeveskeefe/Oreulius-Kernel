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

//! Virtual Memory Management with Paging
//!
//! Features:
//! - 4KB page tables (x86 two-level paging)
//! - User/kernel mode separation (ring 3/ring 0)
//! - Copy-on-write (COW) support
//! - Memory protection (read/write/execute permissions)
//! - Page fault handling
//! - Lazy allocation

use alloc::boxed::Box;
use core::ptr;
use spin::Mutex;

use crate::arch::mmu::PhysAddr;

extern "C" {
    static _heap_end: usize;
    static _text_start: usize;
    static _text_end: usize;
    static _rodata_start: usize;
    static _rodata_end: usize;
    static _data_start: usize;
    static _data_end: usize;
    static _bss_start: usize;
    static _bss_end: usize;
    static _jit_arena_start: usize;
    static _jit_arena_end: usize;
}

// ============================================================================
// Assembly Function Bindings (from asm/cow.asm)
// ============================================================================

// ptr and memory module used for low-level page operations
extern "C" {
    // Page fault handler
    fn page_fault_handler();

    // Page copying
    fn copy_page_physical(src_phys: u32, dst_phys: u32);
    fn copy_page_fast(src: *const u8, dst: *mut u8);
    fn zero_page(addr: *mut u8);
    fn zero_page_fast(addr: *mut u8);

    // TLB operations
    fn flush_tlb_single(virt_addr: u32);
    fn flush_tlb_all();

    // CR3 operations
    fn load_page_directory(phys_addr: u32);
    fn get_page_directory() -> u32;

    // Paging control
    fn enable_paging();
    fn disable_paging();
    fn is_paging_enabled() -> u32;

    // PTE manipulation
    fn set_page_flags(pte_addr: *mut u32, flags: u32);
    fn clear_page_flags(pte_addr: *mut u32, flags: u32);

    // COW operations
    fn mark_page_cow(pte_addr: *mut u32);
    fn is_page_cow(pte_value: u32) -> u32;
    fn clear_page_cow(pte_addr: *mut u32);

    // Atomic operations
    fn atomic_set_page_flags(pte_addr: *mut u32, flags: u32);
    fn atomic_clear_page_flags(pte_addr: *mut u32, flags: u32);

    // Memory barriers
    fn memory_barrier();
    fn load_barrier();
    fn store_barrier();

    // Statistics
    fn get_page_fault_count() -> u32;
    fn get_cow_fault_count() -> u32;
    fn get_page_copy_count() -> u32;
    fn increment_page_fault_count();
    fn increment_cow_fault_count();
    fn increment_page_copy_count();
}

// ============================================================================
// Public Wrapper Functions
// ============================================================================

/// Set PTE flags without atomic operations (for single-threaded boot-time use only)
/// SAFETY: Only safe during boot before multicore is active
pub unsafe fn modify_pte_set_flags_init(pte_addr: *mut u32, flags: u32) {
    set_page_flags(pte_addr, flags);
}

/// Clear PTE flags without atomic operations (for single-threaded boot-time use only)
/// SAFETY: Only safe during boot before multicore is active
pub unsafe fn modify_pte_clear_flags_init(pte_addr: *mut u32, flags: u32) {
    clear_page_flags(pte_addr, flags);
}

/// Clear COW flag from a PTE atomically
/// SAFETY: Caller must ensure pte_addr is valid and aligned
pub unsafe fn clear_pte_cow_flag(pte_addr: *mut u32) {
    clear_page_cow(pte_addr);
    store_barrier();
}

/// Read memory barrier - ensures all loads before this point complete before any loads after
/// Use before reading shared data structures in multicore contexts
pub unsafe fn read_barrier() {
    load_barrier();
}

/// Initialize page fault handler (for IDT setup)
pub fn init_page_fault_handler() {
    unsafe {
        page_fault_handler();
    }
}

/// Copy one physical page to another
pub fn copy_physical_page(src_phys: u32, dst_phys: u32) {
    unsafe {
        copy_page_physical(src_phys, dst_phys);
    }
}

/// Self-test for copy_page_physical.
///
/// Allocates two page-aligned frames from the kernel bump allocator (which is
/// identity-mapped, so virtual addr == physical addr), writes a recognisable
/// pattern to the source page, copies it via `copy_page_physical`, and
/// verifies every dword in the destination page.
///
/// Returns `true` on pass, `false` on any mismatch or allocation failure.
#[cfg(target_arch = "x86")]
pub fn test_copy_page_physical() -> bool {
    let src_phys = match crate::memory::allocate_frame() {
        Ok(a) => a as u32,
        Err(_) => return false,
    };
    let dst_phys = match crate::memory::allocate_frame() {
        Ok(a) => a as u32,
        Err(_) => return false,
    };

    unsafe {
        // Fill src with a recognisable pattern.
        // allocate_frame() zeroes the page, so dst is already zero — no
        // separate zeroing step needed.
        let src_ptr = src_phys as *mut u32;
        for i in 0..1024_usize {
            src_ptr.add(i).write_volatile(0xDEAD_0000_u32 | i as u32);
        }

        // Perform the physical page copy via temporary virtual mappings.
        copy_page_physical(src_phys, dst_phys);

        // Verify every dword.
        let dst_ptr = dst_phys as *const u32;
        for i in 0..1024_usize {
            let expected = 0xDEAD_0000_u32 | i as u32;
            if dst_ptr.add(i).read_volatile() != expected {
                return false;
            }
        }
    }
    true
}

pub fn disable_paging_temp() {
    unsafe {
        disable_paging();
    }
}

/// Flush TLB for single page
pub fn flush_tlb_page(virt_addr: u32) {
    unsafe {
        flush_tlb_single(virt_addr);
    }
}

/// Flush entire TLB
pub fn flush_all_tlb() {
    unsafe {
        flush_tlb_all();
    }
}

/// Get current page directory physical address
pub fn current_page_directory() -> u32 {
    unsafe { get_page_directory() }
}

// ============================================================================
// Atomic PTE Operations for Multicore Safety
// ============================================================================

/// Atomically set page table entry flags (multicore-safe)
pub unsafe fn atomic_modify_pte_set_flags(pte_addr: *mut u32, flags: u32) {
    atomic_set_page_flags(pte_addr, flags);
    store_barrier(); // Ensure write completes before TLB operations
}

/// Atomically clear page table entry flags (multicore-safe)
pub unsafe fn atomic_modify_pte_clear_flags(pte_addr: *mut u32, flags: u32) {
    atomic_clear_page_flags(pte_addr, flags);
    store_barrier(); // Ensure write completes before TLB operations
}

/// Check if CPU has SSE support for fast page operations
fn has_sse_support() -> bool {
    unsafe {
        let mut edx: u32;
        core::arch::asm!(
            "push ebx",           // Save ebx (used by LLVM)
            "mov eax, 1",
            "cpuid",
            "pop ebx",            // Restore ebx
            out("edx") edx,
            out("eax") _,
            out("ecx") _,
            options(nostack),
        );
        // SSE support is bit 25 of EDX
        (edx & (1 << 25)) != 0
    }
}

/// Page size (4KB standard for x86)
pub const PAGE_SIZE: usize = 4096;

/// Kernel virtual base (higher-half)
pub const KERNEL_BASE: usize = 0xC0000000;

/// User space upper bound (exclusive)
pub const USER_TOP: usize = KERNEL_BASE;

/// Number of entries in page directory/table
const PAGE_ENTRIES: usize = 1024;

#[inline]
fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}

#[inline]
fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[inline]
fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

fn section_range(start: &usize, end: &usize) -> (usize, usize) {
    let s = start as *const usize as usize;
    let e = end as *const usize as usize;
    (s, e)
}

fn page_is_read_only(phys_start: usize, phys_end: usize) -> bool {
    let (text_start, text_end) = unsafe { section_range(&_text_start, &_text_end) };
    let (ro_start, ro_end) = unsafe { section_range(&_rodata_start, &_rodata_end) };
    ranges_overlap(phys_start, phys_end, text_start, text_end)
        || ranges_overlap(phys_start, phys_end, ro_start, ro_end)
}

/// Page table entry flags
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PageFlags {
    Present = 1 << 0,        // Page is present in memory
    Writable = 1 << 1,       // Page is writable
    UserAccessible = 1 << 2, // Page accessible from user mode (ring 3)
    WriteThrough = 1 << 3,   // Write-through caching
    CacheDisable = 1 << 4,   // Disable caching for this page
    Accessed = 1 << 5,       // CPU sets this when page is accessed
    Dirty = 1 << 6,          // CPU sets this when page is written to
    Huge = 1 << 7,           // 4MB page (only in PDE)
    Global = 1 << 8,         // Don't flush from TLB on CR3 reload
    CopyOnWrite = 1 << 9,    // Custom flag: page is copy-on-write
    Allocated = 1 << 10,     // Custom flag: page has been allocated
}

/// Page directory entry (points to page table)
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageDirEntry(u32);

/// Page table entry (points to physical page)
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PageTableEntry(u32);

/// Page directory (1024 entries, each points to a page table)
#[repr(align(4096))]
pub struct PageDirectory {
    entries: [PageDirEntry; PAGE_ENTRIES],
}

/// Page table (1024 entries, each points to a 4KB page)
#[repr(align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; PAGE_ENTRIES],
}

impl PageDirEntry {
    pub const fn empty() -> Self {
        PageDirEntry(0)
    }

    pub fn new(table_phys_addr: usize, flags: u32) -> Self {
        PageDirEntry(((table_phys_addr as u32) & 0xFFFFF000) | (flags & 0xFFF))
    }

    pub fn set_present(&mut self, present: bool) {
        if present {
            self.0 |= PageFlags::Present as u32;
        } else {
            self.0 &= !(PageFlags::Present as u32);
        }
    }

    pub fn is_present(&self) -> bool {
        (self.0 & PageFlags::Present as u32) != 0
    }

    pub fn table_addr(&self) -> usize {
        (self.0 & 0xFFFFF000) as usize
    }

    pub fn flags(&self) -> u32 {
        self.0 & 0xFFF
    }
}

impl PageTableEntry {
    pub const fn empty() -> Self {
        PageTableEntry(0)
    }

    pub fn new(phys_addr: usize, flags: u32) -> Self {
        PageTableEntry(((phys_addr as u32) & 0xFFFFF000) | (flags & 0xFFF))
    }

    pub fn set_present(&mut self, present: bool) {
        if present {
            self.0 |= PageFlags::Present as u32;
        } else {
            self.0 &= !(PageFlags::Present as u32);
        }
    }

    pub fn is_present(&self) -> bool {
        (self.0 & PageFlags::Present as u32) != 0
    }

    pub fn is_writable(&self) -> bool {
        (self.0 & PageFlags::Writable as u32) != 0
    }

    pub fn is_user_accessible(&self) -> bool {
        (self.0 & PageFlags::UserAccessible as u32) != 0
    }

    pub fn is_copy_on_write(&self) -> bool {
        (self.0 & PageFlags::CopyOnWrite as u32) != 0
    }

    pub fn is_dirty(&self) -> bool {
        (self.0 & PageFlags::Dirty as u32) != 0
    }

    pub fn is_accessed(&self) -> bool {
        (self.0 & PageFlags::Accessed as u32) != 0
    }

    pub fn phys_addr(&self) -> usize {
        (self.0 & 0xFFFFF000) as usize
    }

    pub fn flags(&self) -> u32 {
        self.0 & 0xFFF
    }

    pub fn set_writable(&mut self, writable: bool) {
        if writable {
            self.0 |= PageFlags::Writable as u32;
        } else {
            self.0 &= !(PageFlags::Writable as u32);
        }
    }

    pub fn set_copy_on_write(&mut self, cow: bool) {
        if cow {
            self.0 |= PageFlags::CopyOnWrite as u32;
        } else {
            self.0 &= !(PageFlags::CopyOnWrite as u32);
        }
    }
}

impl PageDirectory {
    pub const fn new() -> Self {
        PageDirectory {
            entries: [PageDirEntry::empty(); PAGE_ENTRIES],
        }
    }

    /// Get page directory entry for a virtual address
    pub fn entry(&self, virt_addr: usize) -> &PageDirEntry {
        let index = (virt_addr >> 22) & 0x3FF;
        &self.entries[index]
    }

    /// Get mutable page directory entry
    pub fn entry_mut(&mut self, virt_addr: usize) -> &mut PageDirEntry {
        let index = (virt_addr >> 22) & 0x3FF;
        &mut self.entries[index]
    }

    /// Allocate a new page table for this directory entry
    pub fn alloc_table(
        &mut self,
        virt_addr: usize,
        user_accessible: bool,
    ) -> Result<*mut PageTable, &'static str> {
        let entry = self.entry_mut(virt_addr);
        if entry.is_present() {
            return Err("Page table already exists");
        }

        // Allocate aligned page table
        let table = Box::new(PageTable::new());
        let table_ptr = Box::into_raw(table);
        let phys_addr = table_ptr as usize;

        let mut flags = PageFlags::Present as u32 | PageFlags::Writable as u32;
        if user_accessible {
            flags |= PageFlags::UserAccessible as u32;
        }

        *entry = PageDirEntry::new(phys_addr, flags);
        Ok(table_ptr)
    }

    /// Get page table for a virtual address
    pub unsafe fn get_table(&self, virt_addr: usize) -> Option<&PageTable> {
        let entry = self.entry(virt_addr);
        if entry.is_present() {
            Some(&*(entry.table_addr() as *const PageTable))
        } else {
            None
        }
    }

    /// Get mutable page table
    pub unsafe fn get_table_mut(&mut self, virt_addr: usize) -> Option<&mut PageTable> {
        let entry = self.entry(virt_addr);
        if entry.is_present() {
            Some(&mut *(entry.table_addr() as *mut PageTable))
        } else {
            None
        }
    }
}

impl Drop for PageDirectory {
    fn drop(&mut self) {
        let mut i = 0usize;
        while i < PAGE_ENTRIES {
            let entry = self.entries[i];
            if entry.is_present() {
                let table_addr = entry.table_addr();
                if table_addr != 0 {
                    unsafe {
                        drop(Box::from_raw(table_addr as *mut PageTable));
                    }
                    self.entries[i] = PageDirEntry::empty();
                }
            }
            i += 1;
        }
    }
}

impl PageTable {
    pub const fn new() -> Self {
        PageTable {
            entries: [PageTableEntry::empty(); PAGE_ENTRIES],
        }
    }

    /// Get page table entry for a virtual address
    pub fn entry(&self, virt_addr: usize) -> &PageTableEntry {
        let index = (virt_addr >> 12) & 0x3FF;
        &self.entries[index]
    }

    /// Get mutable page table entry
    pub fn entry_mut(&mut self, virt_addr: usize) -> &mut PageTableEntry {
        let index = (virt_addr >> 12) & 0x3FF;
        &mut self.entries[index]
    }
}

/// Address space for a process
pub struct AddressSpace {
    page_directory: Box<PageDirectory>,
    phys_addr: usize, // Physical address of page directory (for CR3)
}

impl AddressSpace {
    /// Return the physical (= kernel-virtual on identity-mapped x86) address of
    /// the page directory root.  Used by the scheduler to populate CR3.
    pub fn phys_addr(&self) -> usize {
        self.phys_addr
    }

    /// Create a new address space
    pub fn new() -> Result<Self, &'static str> {
        crate::drivers::x86::vga::print_str("[PAGING] Building kernel address space...\n");
        let mut page_dir = Box::new(PageDirectory::new());

        // Map kernel space (identity + higher-half)
        Self::setup_kernel_mapping(&mut page_dir)?;
        crate::drivers::x86::vga::print_str("[PAGING] Kernel mappings complete\n");

        let phys_addr = &*page_dir as *const _ as usize;

        Ok(AddressSpace {
            page_directory: page_dir,
            phys_addr,
        })
    }

    /// Create an empty address space with no kernel mappings (for KPTI user mode).
    pub fn new_user_minimal() -> Result<Self, &'static str> {
        let page_dir = Box::new(PageDirectory::new());
        let phys_addr = &*page_dir as *const _ as usize;
        Ok(AddressSpace {
            page_directory: page_dir,
            phys_addr,
        })
    }

    /// Setup kernel mapping (lower 3GB identity mapped)
    fn setup_kernel_mapping(page_dir: &mut PageDirectory) -> Result<(), &'static str> {
        const CHUNK_MB: usize = 4;
        const CHUNK_BYTES: usize = CHUNK_MB * 1024 * 1024;
        let heap_end = unsafe { &_heap_end as *const usize as usize };
        // Map at least 32MB to ensure allocator has space (64MB was too much)
        let map_bytes = align_up(core::cmp::max(heap_end, 32 * 1024 * 1024), CHUNK_BYTES);
        Self::setup_kernel_mapping_range(page_dir, map_bytes)
    }

    /// Setup kernel mapping for a specific range (identity + higher-half mirror).
    fn setup_kernel_mapping_range(
        page_dir: &mut PageDirectory,
        map_bytes: usize,
    ) -> Result<(), &'static str> {
        const CHUNK_MB: usize = 4;
        const CHUNK_BYTES: usize = CHUNK_MB * 1024 * 1024;
        if map_bytes == 0 {
            return Err("Invalid kernel map size");
        }
        let map_bytes = align_up(map_bytes, CHUNK_BYTES);
        let tables = core::cmp::max(1, map_bytes / CHUNK_BYTES);

        crate::drivers::x86::vga::print_str("[PAGING] Mapping kernel memory (0 to ");
        crate::shell::advanced_commands::print_hex(map_bytes);
        crate::drivers::x86::vga::print_str(")...\n");

        for i in 0..tables {
            let phys_base = i * CHUNK_MB * 1024 * 1024;

            crate::drivers::x86::vga::print_str("[PAGING] Mapping chunk...\n");

            // Identity map low memory for early boot and kernel access
            let identity_table = page_dir.alloc_table(phys_base, false)?;
            unsafe {
                let table_ref = &mut *identity_table;
                for j in 0..PAGE_ENTRIES {
                    let phys_addr = phys_base + (j * PAGE_SIZE);
                    let ro = page_is_read_only(phys_addr, phys_addr + PAGE_SIZE);
                    let mut flags = PageFlags::Present as u32;
                    if !ro {
                        flags |= PageFlags::Writable as u32;
                    }
                    table_ref.entries[j] = PageTableEntry::new(phys_addr, flags);
                    // Use non-atomic operation during single-threaded boot for performance
                    let pte_addr = &mut table_ref.entries[j].0 as *mut u32;
                    modify_pte_set_flags_init(pte_addr, flags);
                }
            }

            // Map the same physical memory into the higher half (0xC0000000)
            let high_virt = KERNEL_BASE + phys_base;
            let high_table = page_dir.alloc_table(high_virt, false)?;
            unsafe {
                let table_ref = &mut *high_table;
                for j in 0..PAGE_ENTRIES {
                    let phys_addr = phys_base + (j * PAGE_SIZE);
                    let ro = page_is_read_only(phys_addr, phys_addr + PAGE_SIZE);
                    let mut flags = PageFlags::Present as u32;
                    if !ro {
                        flags |= PageFlags::Writable as u32;
                    }
                    table_ref.entries[j] = PageTableEntry::new(phys_addr, flags);
                    // Use non-atomic operation during single-threaded boot for performance
                    let pte_addr = &mut table_ref.entries[j].0 as *mut u32;
                    modify_pte_set_flags_init(pte_addr, flags);
                }
            }
        }

        Ok(())
    }

    fn map_page_in_dir(
        page_dir: &mut PageDirectory,
        virt_addr: usize,
        phys_addr: usize,
        writable: bool,
        user_accessible: bool,
    ) -> Result<(), &'static str> {
        let virt_aligned = virt_addr & !0xFFF;
        let phys_aligned = phys_addr & !0xFFF;

        if user_accessible && virt_aligned >= USER_TOP {
            return Err("User mapping into kernel space");
        }
        if user_accessible {
            crate::security::memory_isolation::validate_mapping_request(
                phys_aligned,
                PAGE_SIZE,
                writable,
                true,
            )?;
        }

        let table = unsafe {
            if page_dir.entry(virt_aligned).is_present() {
                page_dir.get_table_mut(virt_aligned).unwrap()
            } else {
                &mut *page_dir.alloc_table(virt_aligned, user_accessible)?
            }
        };

        let mut flags = PageFlags::Present as u32;
        if writable {
            flags |= PageFlags::Writable as u32;
        }
        if user_accessible {
            flags |= PageFlags::UserAccessible as u32;
        }

        let entry = table.entry_mut(virt_aligned);
        *entry = PageTableEntry::new(phys_aligned, flags);
        Ok(())
    }

    fn map_range_identity_high(
        page_dir: &mut PageDirectory,
        start: usize,
        end: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        if end <= start {
            return Ok(());
        }
        let start = align_down(start, PAGE_SIZE);
        let end = align_up(end, PAGE_SIZE);
        let mut addr = start;
        while addr < end {
            Self::map_page_in_dir(page_dir, addr, addr, writable, false)?;
            Self::map_page_in_dir(page_dir, KERNEL_BASE + addr, addr, writable, false)?;
            addr += PAGE_SIZE;
        }
        Ok(())
    }

    /// Identity-map a physical MMIO range into the kernel address space (writable, not
    /// user-accessible).  Use this to make device MMIO regions (e.g. a GPU framebuffer)
    /// accessible to the kernel before the first write.
    pub fn map_mmio_range(&mut self, phys_start: usize, size: usize) -> Result<(), &'static str> {
        if size == 0 {
            return Ok(());
        }
        let start = align_down(phys_start, PAGE_SIZE);
        let end = align_up(
            phys_start.checked_add(size).ok_or("MMIO range overflow")?,
            PAGE_SIZE,
        );
        Self::map_range_identity_high(&mut self.page_directory, start, end, true)
    }

    /// Map a physical range into user virtual memory (user-accessible pages).
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
        let end = align_up(
            virt_start.checked_add(size).ok_or("Range overflow")?,
            PAGE_SIZE,
        );
        while virt < end {
            Self::map_page_in_dir(&mut self.page_directory, virt, phys, writable, true)?;
            virt += PAGE_SIZE;
            phys += PAGE_SIZE;
        }
        Ok(())
    }

    /// Create a minimal kernel-only address space for JIT sandboxing.
    pub fn new_jit_sandbox() -> Result<Self, &'static str> {
        let mut page_dir = Box::new(PageDirectory::new());
        let (text_start, text_end) = unsafe { section_range(&_text_start, &_text_end) };
        let (ro_start, ro_end) = unsafe { section_range(&_rodata_start, &_rodata_end) };
        let (data_start, data_end) = unsafe { section_range(&_data_start, &_data_end) };
        let (bss_start, bss_end) = unsafe { section_range(&_bss_start, &_bss_end) };
        let (jit_start, jit_end) = unsafe { section_range(&_jit_arena_start, &_jit_arena_end) };

        Self::map_range_identity_high(&mut page_dir, text_start, text_end, false)?;
        Self::map_range_identity_high(&mut page_dir, ro_start, ro_end, false)?;
        Self::map_range_identity_high(&mut page_dir, data_start, data_end, true)?;
        Self::map_range_identity_high(&mut page_dir, bss_start, bss_end, true)?;
        // JIT arena must be writable for JIT state/memory and trap handling.
        Self::map_range_identity_high(&mut page_dir, jit_start, jit_end, true)?;
        let phys_addr = &*page_dir as *const _ as usize;
        Ok(AddressSpace {
            page_directory: page_dir,
            phys_addr,
        })
    }

    /// Clone this address space with copy-on-write semantics (user space only)
    pub fn clone_cow(&mut self) -> Result<AddressSpace, &'static str> {
        let mut new_dir = Box::new(PageDirectory::new());

        // Map kernel space for child
        Self::setup_kernel_mapping(&mut new_dir)?;

        let user_dir_entries = USER_TOP >> 22;

        for dir_idx in 0..user_dir_entries {
            let virt_addr = dir_idx << 22;
            let parent_entry = self.page_directory.entries[dir_idx];
            if !parent_entry.is_present() {
                continue;
            }

            // Allocate child page table for this directory entry
            let child_table_ptr = new_dir.alloc_table(virt_addr, true)?;
            let child_table = unsafe { &mut *child_table_ptr };

            let parent_table = unsafe {
                self.page_directory
                    .get_table_mut(virt_addr)
                    .ok_or("Parent table missing")?
            };

            for i in 0..PAGE_ENTRIES {
                let entry = parent_table.entries[i];
                if !entry.is_present() {
                    continue;
                }

                // Mark parent entry as COW (clears writable)
                unsafe {
                    mark_page_cow(&mut parent_table.entries[i] as *mut PageTableEntry as *mut u32);
                }

                // Copy entry value into child (with COW flag set)
                let val = parent_table.entries[i].0;
                child_table.entries[i] = PageTableEntry(val);
            }
        }

        Self::flush_tlb_all();

        let phys_addr = &*new_dir as *const _ as usize;
        Ok(AddressSpace {
            page_directory: new_dir,
            phys_addr,
        })
    }

    /// Map a virtual address to a physical address
    pub fn map_page(
        &mut self,
        virt_addr: usize,
        phys_addr: usize,
        writable: bool,
        user_accessible: bool,
    ) -> Result<(), &'static str> {
        // Align addresses
        let virt_aligned = virt_addr & !0xFFF;
        let phys_aligned = phys_addr & !0xFFF;

        if user_accessible && virt_aligned >= USER_TOP {
            return Err("User mapping into kernel space");
        }
        if user_accessible {
            crate::security::memory_isolation::validate_mapping_request(
                phys_aligned,
                PAGE_SIZE,
                writable,
                true,
            )?;
        }

        // Get or create page table
        let table = unsafe {
            if self.page_directory.entry(virt_aligned).is_present() {
                self.page_directory.get_table_mut(virt_aligned).unwrap()
            } else {
                &mut *self
                    .page_directory
                    .alloc_table(virt_aligned, user_accessible)?
            }
        };

        // Set up page table entry
        let mut flags = PageFlags::Present as u32;
        if writable {
            flags |= PageFlags::Writable as u32;
        }
        if user_accessible {
            flags |= PageFlags::UserAccessible as u32;
        }

        let entry = table.entry_mut(virt_aligned);
        *entry = PageTableEntry::new(phys_aligned, flags);

        // Flush TLB for this page
        Self::flush_tlb(virt_aligned);

        Ok(())
    }

    /// Unmap a virtual address
    pub fn unmap_page(&mut self, virt_addr: usize) -> Result<(), &'static str> {
        let virt_aligned = virt_addr & !0xFFF;

        let table = unsafe {
            self.page_directory
                .get_table_mut(virt_aligned)
                .ok_or("Page table not present")?
        };

        let entry = table.entry_mut(virt_aligned);
        if !entry.is_present() {
            return Err("Page not mapped");
        }

        // Get physical address before unmapping (for potential memory::free)
        let _phys_addr = entry.phys_addr();

        // Use ptr::write to ensure the zero is written atomically
        unsafe {
            ptr::write(entry as *mut PageTableEntry, PageTableEntry::empty());
        }

        Self::flush_tlb(virt_aligned);

        // Note: Could call memory::free(_phys_addr) here if tracking allocations
        Ok(())
    }

    /// Set a page as copy-on-write
    pub fn mark_copy_on_write(&mut self, virt_addr: usize) -> Result<(), &'static str> {
        let virt_aligned = virt_addr & !0xFFF;

        let table = unsafe {
            self.page_directory
                .get_table_mut(virt_aligned)
                .ok_or("Page table not present")?
        };

        let entry = table.entry_mut(virt_aligned);
        if !entry.is_present() {
            return Err("Page not mapped");
        }

        // Use assembly function to mark as COW
        unsafe {
            mark_page_cow(entry as *mut PageTableEntry as *mut u32);
        }

        Self::flush_tlb(virt_aligned);

        Ok(())
    }

    /// Handle copy-on-write page fault
    pub fn handle_cow_fault(&mut self, virt_addr: usize) -> Result<(), &'static str> {
        let virt_aligned = virt_addr & !0xFFF;

        let table = unsafe {
            self.page_directory
                .get_table_mut(virt_aligned)
                .ok_or("Page table not present")?
        };

        let entry = table.entry_mut(virt_aligned);
        if !entry.is_present() {
            return Err("Page not present");
        }

        // Check if this is actually a COW page using assembly
        let pte_value = unsafe { *(entry as *const PageTableEntry as *const u32) };
        if unsafe { is_page_cow(pte_value) } == 0 {
            return Err("Not a COW page");
        }

        // Update statistics
        unsafe {
            increment_cow_fault_count();
            increment_page_copy_count();
        }

        // Allocate new physical page
        use alloc::alloc::{alloc, Layout};
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let new_page = unsafe { alloc(layout) };
        if new_page.is_null() {
            return Err("Failed to allocate new page");
        }

        // Get old physical address
        let old_phys = entry.phys_addr();

        // Use fast assembly copy
        unsafe {
            copy_page_fast(old_phys as *const u8, new_page);
        }

        // Update page table entry with new physical address (atomic operation)
        let mut flags = PageFlags::Present as u32 | PageFlags::Allocated as u32;
        flags |= PageFlags::Writable as u32;
        if entry.is_user_accessible() {
            flags |= PageFlags::UserAccessible as u32;
        }

        // Use atomic operations for multicore safety
        unsafe {
            let pte_addr = entry as *mut PageTableEntry as *mut u32;
            // First clear COW flag
            atomic_modify_pte_clear_flags(pte_addr, PageFlags::CopyOnWrite as u32);
            // Then set new flags (Present + Writable + UserAccessible)
            atomic_modify_pte_set_flags(pte_addr, flags);
            // Update physical address (requires reconstructing full PTE value)
            core::ptr::write_volatile(pte_addr, ((new_page as u32) & 0xFFFFF000) | flags);
            memory_barrier(); // Ensure all writes visible before TLB flush
        }

        Self::flush_tlb(virt_aligned);

        Ok(())
    }

    /// Get physical address for a virtual address
    pub fn virt_to_phys(&self, virt_addr: usize) -> Option<usize> {
        let virt_aligned = virt_addr & !0xFFF;
        let offset = virt_addr & 0xFFF;

        unsafe {
            let table = self.page_directory.get_table(virt_aligned)?;
            let entry = table.entry(virt_aligned);

            // Ensure we read the latest PTE value in multicore context
            read_barrier();

            if entry.is_present() {
                Some(entry.phys_addr() + offset)
            } else {
                None
            }
        }
    }

    /// Check if a virtual address is mapped
    pub fn is_mapped(&self, virt_addr: usize) -> bool {
        self.virt_to_phys(virt_addr).is_some()
    }

    /// Activate this address space (load into CR3)
    pub unsafe fn activate(&self) {
        let phys_addr = PhysAddr::new(self.phys_addr)
            .try_as_u32()
            .expect("page directory exceeds u32");
        load_page_directory(phys_addr);
    }

    /// Flush TLB for a single page (uses assembly implementation)
    fn flush_tlb(virt_addr: usize) {
        unsafe {
            flush_tlb_single(virt_addr as u32);
        }
    }

    /// Flush entire TLB (uses assembly implementation)
    pub fn flush_tlb_all() {
        unsafe {
            flush_tlb_all();
        }
    }
}

// Note: These inline assembly functions are now replaced by external assembly
// but kept for reference/fallback

/// Page fault error code bits
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    pub present: bool,     // 0 = not present, 1 = protection violation
    pub write: bool,       // 0 = read, 1 = write
    pub user: bool,        // 0 = kernel, 1 = user mode
    pub reserved: bool,    // 1 = reserved bit set
    pub instruction: bool, // 1 = instruction fetch
}

impl PageFaultError {
    pub fn from_code(code: u32) -> Self {
        PageFaultError {
            present: (code & 0x1) != 0,
            write: (code & 0x2) != 0,
            user: (code & 0x4) != 0,
            reserved: (code & 0x8) != 0,
            instruction: (code & 0x10) != 0,
        }
    }
}

/// Page fault handler called from assembly
#[no_mangle]
pub extern "C" fn rust_page_fault_handler(error_code: u32, fault_addr: usize) {
    // Legacy entry point (assembly calls this). EIP unknown in this path.
    rust_page_fault_handler_ex(error_code, fault_addr, 0, 0);
}

#[no_mangle]
pub extern "C" fn rust_page_fault_handler_ex(
    error_code: u32,
    fault_addr: usize,
    eip: usize,
    esp: usize,
) {
    use crate::drivers::x86::vga;

    // Update statistics
    unsafe {
        increment_page_fault_count();
    }

    let error = PageFaultError::from_code(error_code);

    // Check if this is a COW fault
    if error.present && error.write && !error.user {
        // Potential COW fault
        let mut space_opt = KERNEL_ADDRESS_SPACE.lock();
        if let Some(ref mut space) = *space_opt {
            match space.handle_cow_fault(fault_addr) {
                Ok(()) => {
                    // COW fault handled successfully
                    return;
                }
                Err(_) => {
                    // Not a COW fault, fall through to error
                }
            }
        }
    }

    // Unhandled page fault - print error and halt
    vga::print_str("\n\n!!! PAGE FAULT !!!\n");
    vga::print_str("Fault address: 0x");

    // Print fault address
    let digits = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        let nibble = ((fault_addr >> (i * 4)) & 0xF) as usize;
        vga::print_char(digits[nibble] as char);
    }
    vga::print_str("\n");

    vga::print_str("Error code: 0x");
    for i in (0..8).rev() {
        let nibble = ((error_code >> (i * 4)) & 0xF) as usize;
        vga::print_char(digits[nibble] as char);
    }
    vga::print_str("\n");

    vga::print_str("Present: ");
    vga::print_str(if error.present { "yes" } else { "no" });
    vga::print_str("\n");

    vga::print_str("Write: ");
    vga::print_str(if error.write { "yes" } else { "no" });
    vga::print_str("\n");

    vga::print_str("User mode: ");
    vga::print_str(if error.user { "yes" } else { "no" });
    vga::print_str("\n");

    if eip != 0 {
        vga::print_str("EIP: 0x");
        crate::shell::advanced_commands::print_hex(eip);
        vga::print_str("\n");
    } else {
        vga::print_str("EIP: (unknown)\n");
    }

    if esp != 0 {
        vga::print_str("ESP: 0x");
        crate::shell::advanced_commands::print_hex(esp);
        vga::print_str("\n");
    } else {
        vga::print_str("ESP: (unknown)\n");
    }

    let stacks = crate::scheduler::slice_scheduler::kernel_stack_bounds();
    let mut esp_in_known_stack = false;
    for (idx, (start, end)) in stacks.iter().enumerate() {
        vga::print_str("KSTACK");
        crate::shell::commands::print_u32(idx as u32);
        vga::print_str(": 0x");
        crate::shell::advanced_commands::print_hex(*start);
        vga::print_str(" - 0x");
        crate::shell::advanced_commands::print_hex(*end);
        vga::print_str("\n");
        vga::print_str("ESP in KSTACK");
        crate::shell::commands::print_u32(idx as u32);
        vga::print_str(": ");
        let in_stack = esp >= *start && esp < *end;
        if in_stack {
            esp_in_known_stack = true;
        }
        vga::print_str(if in_stack { "yes" } else { "no" });
        vga::print_str("\n");
    }

    if esp != 0 && esp_in_known_stack {
        vga::print_str("Stack words:\n");
        for word_idx in 0..7usize {
            let addr = esp + (word_idx * core::mem::size_of::<u32>());
            let value = unsafe { core::ptr::read_volatile(addr as *const u32) };
            vga::print_str("  [ESP+0x");
            crate::shell::advanced_commands::print_hex(word_idx * core::mem::size_of::<u32>());
            vga::print_str("] @ 0x");
            crate::shell::advanced_commands::print_hex(addr);
            vga::print_str(" = 0x");
            crate::shell::advanced_commands::print_hex(value as usize);
            vga::print_str("\n");
        }
    }

    let mmio_base = crate::net::e1000::mmio_base() as usize;
    if mmio_base != 0 {
        let mmio_end = mmio_base + 128 * 1024;
        vga::print_str("E1000 MMIO: 0x");
        crate::shell::advanced_commands::print_hex(mmio_base);
        vga::print_str(" - 0x");
        crate::shell::advanced_commands::print_hex(mmio_end);
        vga::print_str("\n");
        vga::print_str("Fault in MMIO range: ");
        let in_range = fault_addr >= mmio_base && fault_addr < mmio_end;
        vga::print_str(if in_range { "yes" } else { "no" });
        vga::print_str("\n");
    }

    // Halt
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

/// Global kernel address space
pub static KERNEL_ADDRESS_SPACE: Mutex<Option<AddressSpace>> = Mutex::new(None);

/// Initialize paging subsystem
pub fn init() -> Result<(), &'static str> {
    use crate::drivers::x86::vga;

    vga::print_str("[PAGING] Initializing virtual memory...\n");

    // Create kernel address space
    let kernel_space = AddressSpace::new()?;

    vga::print_str("[PAGING] Loading CR3...\n");
    unsafe {
        kernel_space.activate();
    }
    vga::print_str("[PAGING] CR3 loaded\n");
    vga::print_str("[PAGING] Enabling paging (CR0.PG)...\n");
    unsafe {
        enable_paging();
    }
    vga::print_str("[PAGING] Paging enabled\n");

    // Enforce write-protect in Ring 0 (CR0.WP) to honor read-only pages.
    let mut cr0 = crate::memory::asm_bindings::read_cr0();
    cr0 |= 1 << 16;
    crate::memory::asm_bindings::write_cr0(cr0);
    vga::print_str("[PAGING] CR0.WP enabled (kernel W^X enforced)\n");

    *KERNEL_ADDRESS_SPACE.lock() = Some(kernel_space);

    vga::print_str("[PAGING] Virtual memory enabled\n");
    Ok(())
}

/// Get reference to kernel address space
pub fn kernel_space() -> &'static Mutex<Option<AddressSpace>> {
    &KERNEL_ADDRESS_SPACE
}

/// Get the kernel page directory physical address (CR3).
pub fn kernel_page_directory_addr() -> Option<u32> {
    let guard = KERNEL_ADDRESS_SPACE.lock();
    guard
        .as_ref()
        .and_then(|space| PhysAddr::new(space.phys_addr()).try_as_u32().ok())
}

/// Set writable flag for a range of kernel-mapped pages.
/// This is used to enforce W^X policy for JIT code pages (policy-level on 32-bit).
pub fn set_page_writable_range(
    virt_addr: usize,
    size: usize,
    writable: bool,
) -> Result<(), &'static str> {
    if size == 0 {
        return Ok(());
    }
    let start = virt_addr & !(PAGE_SIZE - 1);
    let end = virt_addr
        .checked_add(size)
        .ok_or("Range overflow")?
        .checked_add(PAGE_SIZE - 1)
        .ok_or("Range overflow")?
        & !(PAGE_SIZE - 1);

    let mut space_guard = KERNEL_ADDRESS_SPACE.lock();
    let space = space_guard
        .as_mut()
        .ok_or("Kernel address space not initialized")?;

    let mut addr = start;
    while addr < end {
        let entry = unsafe {
            let table = space
                .page_directory
                .get_table_mut(addr)
                .ok_or("Missing page table")?;
            let pte = table.entry_mut(addr);
            if !pte.is_present() {
                return Err("Page not mapped");
            }
            pte
        };
        let pte_addr = entry as *mut PageTableEntry as *mut u32;
        unsafe {
            if writable {
                atomic_modify_pte_set_flags(pte_addr, PageFlags::Writable as u32);
            } else {
                atomic_modify_pte_clear_flags(pte_addr, PageFlags::Writable as u32);
            }
        }
        unsafe { flush_tlb_single(addr as u32) };
        addr += PAGE_SIZE;
    }

    Ok(())
}

/// Best-effort validation that a kernel virtual range is currently mapped.
/// Returns `false` if paging is not initialized, overflow is detected, or any page is unmapped.
pub fn is_kernel_range_mapped(virt_addr: usize, size: usize) -> bool {
    if size == 0 {
        return true;
    }
    let last = match virt_addr.checked_add(size - 1) {
        Some(v) => v,
        None => return false,
    };
    let start_page = virt_addr & !(PAGE_SIZE - 1);
    let end_page = last & !(PAGE_SIZE - 1);

    let guard = KERNEL_ADDRESS_SPACE.lock();
    let space = match guard.as_ref() {
        Some(space) => space,
        None => return false,
    };

    let mut page = start_page;
    loop {
        if !space.is_mapped(page) {
            return false;
        }
        if page == end_page {
            break;
        }
        page = match page.checked_add(PAGE_SIZE) {
            Some(next) => next,
            None => return false,
        };
    }
    true
}

/// Handle page fault interrupt
pub fn handle_page_fault(virt_addr: usize, error_code: u32) -> Result<(), &'static str> {
    let error = PageFaultError::from_code(error_code);

    // Try to handle COW fault
    if error.write && error.present {
        let mut space_guard = KERNEL_ADDRESS_SPACE.lock();
        if let Some(ref mut space) = *space_guard {
            if let Ok(_) = space.handle_cow_fault(virt_addr) {
                return Ok(()); // COW handled successfully
            }
        }
    }

    // Unhandled page fault
    Err("Unhandled page fault")
}

/// Allocate and map user pages (for user process)
pub fn alloc_user_pages(
    space: &mut AddressSpace,
    virt_addr: usize,
    count: usize,
    writable: bool,
) -> Result<(), &'static str> {
    use alloc::alloc::{alloc_zeroed, Layout};

    if virt_addr >= USER_TOP {
        return Err("User mapping into kernel space");
    }

    for i in 0..count {
        let vaddr = virt_addr + (i * PAGE_SIZE);

        // Allocate physical page
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let phys_page = unsafe { alloc_zeroed(layout) };
        if phys_page.is_null() {
            return Err("Failed to allocate page");
        }

        // Map it
        space.map_page(vaddr, phys_page as usize, writable, true)?;
    }

    Ok(())
}

// ============================================================================
// COW Statistics and Helper Functions
// ============================================================================

/// Get page fault statistics
pub struct PagingStats {
    pub page_faults: u32,
    pub cow_faults: u32,
    pub page_copies: u32,
}

pub fn get_paging_stats() -> PagingStats {
    unsafe {
        PagingStats {
            page_faults: get_page_fault_count(),
            cow_faults: get_cow_fault_count(),
            page_copies: get_page_copy_count(),
        }
    }
}

/// Zero out a page using fast assembly implementation
pub fn zero_page_at(addr: *mut u8) {
    unsafe {
        // Use SSE version if available, otherwise use slow fallback
        if has_sse_support() {
            zero_page_fast(addr);
        } else {
            zero_page(addr);
        }
    }
}

/// Copy a page using fast assembly implementation
pub fn copy_page(src: *const u8, dst: *mut u8) {
    unsafe {
        copy_page_fast(src, dst);
    }
}

/// Check if paging is currently enabled
pub fn paging_enabled() -> bool {
    unsafe { is_paging_enabled() != 0 }
}

/// Get current CR3 value
pub fn current_page_directory_addr() -> u32 {
    unsafe { get_page_directory() }
}

/// Set CR3 to a page directory physical address
pub unsafe fn set_page_directory(phys_addr: u32) {
    load_page_directory(phys_addr);
}

use crate::memory;
use crate::scheduler::process::{process_manager, Pid};

#[no_mangle]
pub extern "C" fn rust_copy_page_table(parent_pid_raw: u32, child_pid_raw: u32) -> i32 {
    let parent_pid = Pid(parent_pid_raw);
    let child_pid = Pid(child_pid_raw);
    let pm = process_manager();

    // 1. Get Parent PD (Physical Address)
    // If parent has no PD recorded (e.g. init), use current CR3
    let parent_pd_phys = match pm.get_process_page_dir(parent_pid) {
        Some(addr) if !addr.is_zero() => addr.as_usize(),
        _ => unsafe { get_page_directory() as usize },
    };

    // 2. Allocate Child PD
    let child_pd_phys = match memory::allocate_frame() {
        Ok(addr) => addr,
        Err(_) => return -1,
    };

    // 3. Loop over directories
    // unsafe: accessing physical memory directly (identity mapping assumed for kernel heap)
    let parent_pd = parent_pd_phys as *mut PageDirectory;
    let child_pd = child_pd_phys as *mut PageDirectory;

    unsafe {
        // Init child PD (empty) - assuming valid pointer
        let child_pd_ref = &mut *child_pd;
        // Zero it out effectively (or rely on allocate_frame zeroing)
        // We will overwrite entries anyway or leave them empty.

        // Note: We must recursively map page tables
        for i in 0..PAGE_ENTRIES {
            let pde = &mut (*parent_pd).entries[i];

            if !pde.is_present() {
                child_pd_ref.entries[i] = PageDirEntry::empty();
                continue;
            }

            // Strategies:
            // A. Kernel Space (>= 768 for 3GB split, or based on policy): Share Page Table
            // B. User Space: Copy Page Table (for COW)

            // Simplify: If it's a kernel mapping, we share the Page Table directly.
            // Warning: logic assumes standard higher-half split or defined kernel range.
            // If we don't know, we might COW everything. But COW on kernel stack is bad.
            // Let's assume > 0xC0000000 (entry 768) is kernel.
            if i >= 768 {
                child_pd_ref.entries[i] = *pde;
                continue;
            }

            // User space mapping found.
            // Allocate new Page Table for child
            let child_pt_phys = match memory::allocate_frame() {
                Ok(a) => a,
                Err(_) => return -1, // Should cleanup allocated child_pd... ignoring for MVP
            };

            let parent_pt_phys = pde.table_addr();
            let parent_pt = parent_pt_phys as *mut PageTable;
            let child_pt = child_pt_phys as *mut PageTable;
            let child_pt_ref = &mut *child_pt;

            // Link the new PT into Child PD
            child_pd_ref.entries[i] = PageDirEntry::new(child_pt_phys, pde.flags());

            // Copy/COW PTEs
            for j in 0..PAGE_ENTRIES {
                let pte = &mut (*parent_pt).entries[j];

                if !pte.is_present() {
                    child_pt_ref.entries[j] = PageTableEntry::empty();
                    continue;
                }

                let phys_frame = pte.phys_addr();
                let mut flags = pte.flags();

                // Logic: If Writable -> COW. If ReadOnly -> Shared.
                if pte.is_writable() {
                    // Mark Parent Read-Only + COW (atomic operations for multicore safety)
                    let pte_addr = pte as *mut PageTableEntry as *mut u32;
                    atomic_modify_pte_clear_flags(pte_addr, PageFlags::Writable as u32);
                    atomic_modify_pte_set_flags(pte_addr, PageFlags::CopyOnWrite as u32);

                    // Mark Child Read-Only + COW
                    // Remove Write bit from flags for child too
                    flags &= !(PageFlags::Writable as u32);
                    flags |= PageFlags::CopyOnWrite as u32;

                    child_pt_ref.entries[j] = PageTableEntry::new(phys_frame, flags);

                    // Increment refcount (original owner + new owner)
                    // If it was 1, it becomes 2.
                    // Note: We increment for EACH new reference.
                    memory::inc_refcount(phys_frame);

                    // Use invlpg if we could. Since we iterate many, flush_all at end is better.
                } else {
                    // Just share it
                    child_pt_ref.entries[j] = *pte;
                    memory::inc_refcount(phys_frame);
                }
            }
        }
    }

    // Memory barrier before saving page directory
    unsafe {
        memory_barrier();
    }

    // Save to process manager
    if let Err(_) = pm.set_process_page_dir(child_pid, PhysAddr::new(child_pd_phys)) {
        return -1;
    }

    // Flush TLB in parent because we might have marked pages as Read-Only/COW
    unsafe {
        flush_tlb_all();
    }

    0 // Success
}
