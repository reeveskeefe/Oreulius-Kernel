use super::{ArchMmu, PageAttribute};

pub(super) struct X86LegacyMmu;

pub(super) static MMU: X86LegacyMmu = X86LegacyMmu;

impl ArchMmu for X86LegacyMmu {
    fn name(&self) -> &'static str {
        "i686-paging"
    }

    fn init(&self) -> Result<(), &'static str> {
        crate::paging::init()
    }

    fn page_size(&self) -> usize {
        crate::paging::PAGE_SIZE
    }

    fn kernel_page_table_root_addr(&self) -> Option<usize> {
        crate::paging::kernel_page_directory_addr().map(|v| v as usize)
    }

    fn current_page_table_root_addr(&self) -> usize {
        crate::paging::current_page_directory_addr() as usize
    }

    fn set_page_table_root(&self, phys_addr: usize) -> Result<(), &'static str> {
        if phys_addr > u32::MAX as usize {
            return Err("CR3 root address out of 32-bit range");
        }
        unsafe {
            crate::paging::set_page_directory(phys_addr as u32);
        }
        Ok(())
    }

    fn flush_tlb_page(&self, virt_addr: usize) {
        crate::paging::flush_tlb_page(virt_addr as u32)
    }

    fn flush_tlb_all(&self) {
        crate::paging::flush_all_tlb()
    }

    fn set_page_attribute_range(
        &self,
        virt_addr: usize,
        size: usize,
        attr: PageAttribute,
        enabled: bool,
    ) -> Result<(), &'static str> {
        match attr {
            PageAttribute::Writable => crate::paging::set_page_writable_range(
                virt_addr,
                size,
                enabled,
            ),
        }
    }

    fn set_page_writable_range(
        &self,
        virt_addr: usize,
        size: usize,
        writable: bool,
    ) -> Result<(), &'static str> {
        self.set_page_attribute_range(virt_addr, size, PageAttribute::Writable, writable)
    }
}
