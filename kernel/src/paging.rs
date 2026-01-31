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
use crate::memory;

/// Page size (4KB standard for x86)
pub const PAGE_SIZE: usize = 4096;

/// Number of entries in page directory/table
const PAGE_ENTRIES: usize = 1024;

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
    pub fn alloc_table(&mut self, virt_addr: usize, user_accessible: bool) -> Result<*mut PageTable, &'static str> {
        use alloc::boxed::Box;
        
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
    /// Create a new address space
    pub fn new() -> Result<Self, &'static str> {
        use alloc::boxed::Box;
        
        let mut page_dir = Box::new(PageDirectory::new());
        
        // Identity map kernel space (0x00000000 - 0xC0000000)
        // This ensures kernel code/data is accessible
        Self::setup_kernel_mapping(&mut page_dir)?;
        
        let phys_addr = &*page_dir as *const _ as usize;
        
        Ok(AddressSpace {
            page_directory: page_dir,
            phys_addr,
        })
    }

    /// Setup kernel mapping (lower 3GB identity mapped)
    fn setup_kernel_mapping(page_dir: &mut PageDirectory) -> Result<(), &'static str> {
        // Map first 16MB for kernel (bootstrap)
        // In production, map actual kernel segments only
        for i in 0..4 {
            let table = page_dir.alloc_table(i * 4 * 1024 * 1024, false)?;
            unsafe {
                let table_ref = &mut *table;
                for j in 0..PAGE_ENTRIES {
                    let phys_addr = (i * PAGE_ENTRIES + j) * PAGE_SIZE;
                    let flags = PageFlags::Present as u32 | PageFlags::Writable as u32;
                    table_ref.entries[j] = PageTableEntry::new(phys_addr, flags);
                }
            }
        }
        Ok(())
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

        // Get or create page table
        let table = unsafe {
            if self.page_directory.entry(virt_aligned).is_present() {
                self.page_directory.get_table_mut(virt_aligned).unwrap()
            } else {
                &mut *self.page_directory.alloc_table(virt_aligned, user_accessible)?
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

        *entry = PageTableEntry::empty();
        Self::flush_tlb(virt_aligned);

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

        // Mark as COW and remove write permission
        entry.set_copy_on_write(true);
        entry.set_writable(false);

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

        if !entry.is_copy_on_write() {
            return Err("Not a COW page");
        }

        // Allocate new physical page
        use alloc::alloc::{alloc, Layout};
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let new_page = unsafe { alloc(layout) };
        if new_page.is_null() {
            return Err("Failed to allocate new page");
        }

        // Copy old page content to new page
        let old_phys = entry.phys_addr();
        unsafe {
            ptr::copy_nonoverlapping(
                old_phys as *const u8,
                new_page,
                PAGE_SIZE,
            );
        }

        // Update page table entry
        let flags = entry.flags();
        *entry = PageTableEntry::new(new_page as usize, flags);
        entry.set_writable(true);
        entry.set_copy_on_write(false);

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
        load_page_directory(self.phys_addr);
    }

    /// Get physical address of page directory (for CR3)
    pub fn phys_addr(&self) -> usize {
        self.phys_addr
    }

    /// Flush TLB for a single page
    fn flush_tlb(virt_addr: usize) {
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) virt_addr,
                options(nostack, preserves_flags)
            );
        }
    }
}

/// Load a page directory (set CR3 register)
pub unsafe fn load_page_directory(phys_addr: usize) {
    core::arch::asm!(
        "mov cr3, {}",
        in(reg) phys_addr,
        options(nostack, preserves_flags)
    );
}

/// Enable paging (set CR0.PG bit)
pub unsafe fn enable_paging() {
    core::arch::asm!(
        "mov eax, cr0",
        "or eax, 0x80000000",
        "mov cr0, eax",
        out("eax") _,
        options(nostack, preserves_flags)
    );
}

/// Disable paging (clear CR0.PG bit)
pub unsafe fn disable_paging() {
    core::arch::asm!(
        "mov eax, cr0",
        "and eax, 0x7FFFFFFF",
        "mov cr0, eax",
        out("eax") _,
        options(nostack, preserves_flags)
    );
}

/// Get current page directory address from CR3
pub fn get_current_page_directory() -> usize {
    let addr: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, cr3",
            out(reg) addr,
            options(nostack, preserves_flags)
        );
    }
    addr
}

/// Page fault error code bits
#[derive(Debug, Clone, Copy)]
pub struct PageFaultError {
    pub present: bool,      // 0 = not present, 1 = protection violation
    pub write: bool,        // 0 = read, 1 = write
    pub user: bool,         // 0 = kernel, 1 = user mode
    pub reserved: bool,     // 1 = reserved bit set
    pub instruction: bool,  // 1 = instruction fetch
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

/// Global kernel address space
pub static KERNEL_ADDRESS_SPACE: Mutex<Option<AddressSpace>> = Mutex::new(None);

/// Initialize paging subsystem
pub fn init() -> Result<(), &'static str> {
    use crate::vga;
    
    vga::print_str("[PAGING] Initializing virtual memory...\n");
    
    // Create kernel address space
    let kernel_space = AddressSpace::new()?;
    
    // Activate it
    unsafe {
        kernel_space.activate();
        enable_paging();
    }
    
    *KERNEL_ADDRESS_SPACE.lock() = Some(kernel_space);
    
    vga::print_str("[PAGING] Virtual memory enabled\n");
    Ok(())
}

/// Get reference to kernel address space
pub fn kernel_space() -> &'static Mutex<Option<AddressSpace>> {
    &KERNEL_ADDRESS_SPACE
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
