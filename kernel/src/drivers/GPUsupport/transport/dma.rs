/*!
 * Generic GPU DMA descriptor helpers.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuDmaDescriptor {
    pub src_addr: u64,
    pub dst_addr: u64,
    pub len: u32,
    pub flags: u32,
}

impl GpuDmaDescriptor {
    pub const fn new(src_addr: u64, dst_addr: u64, len: u32, flags: u32) -> Self {
        GpuDmaDescriptor {
            src_addr,
            dst_addr,
            len,
            flags,
        }
    }
}

