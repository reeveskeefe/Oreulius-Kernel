/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

// DMA Controller Assembly Bindings
// High-speed I/O transfers bypassing CPU

/// DMA transfer modes
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum DmaMode {
    Read = 0x04,  // Memory to I/O
    Write = 0x08, // I/O to Memory
    AutoInit = 0x10,
    AddressDecrement = 0x20,
    Demand = 0x00,
    Single = 0x40,
    Block = 0x80,
    Cascade = 0xC0,
}

/// DMA channel (0-7)
#[derive(Debug, Clone, Copy)]
pub struct DmaChannel(pub u8);

impl DmaChannel {
    pub const fn new(channel: u8) -> Option<Self> {
        if channel < 8 {
            Some(Self(channel))
        } else {
            None
        }
    }
}

/// DMA descriptor for scatter-gather
#[repr(C)]
pub struct DmaDescriptor {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub length: u32,
    pub next: *mut DmaDescriptor,
}

/// DMA statistics
#[derive(Debug, Default)]
pub struct DmaStats {
    pub transfers: u32,
    pub bytes_transferred: u32,
    pub errors: u32,
}

extern "C" {
    // Channel management
    pub fn dma_init_channel(channel: u8, buffer: u32, count: u16, mode: u8);
    pub fn dma_start_transfer(channel: u8);
    pub fn dma_stop_transfer(channel: u8);
    pub fn dma_is_complete(channel: u8) -> u32;
    pub fn dma_get_remaining_count(channel: u8) -> u16;

    // Scatter-gather DMA
    pub fn dma_setup_descriptor_list(desc_list: *mut DmaDescriptor, desc_count: u32);
    pub fn dma_scatter_gather(desc_list: *const DmaDescriptor, channel: u8) -> u32;

    // Statistics
    pub fn get_dma_stats(transfers: *mut u32, bytes: *mut u32, errors: *mut u32);
    pub fn reset_dma_stats();

    // Controller management
    pub fn dma_reset_controller(controller: u8);
}

/// Safe DMA channel wrapper
pub struct Dma {
    channel: DmaChannel,
}

impl Dma {
    pub const fn new(channel: DmaChannel) -> Self {
        Self { channel }
    }

    pub fn init(&self, buffer: u32, count: u16, mode: DmaMode) {
        unsafe {
            dma_init_channel(self.channel.0, buffer, count, mode as u8);
        }
    }

    pub fn start(&self) {
        unsafe { dma_start_transfer(self.channel.0) }
    }

    pub fn stop(&self) {
        unsafe { dma_stop_transfer(self.channel.0) }
    }

    pub fn is_complete(&self) -> bool {
        unsafe { dma_is_complete(self.channel.0) != 0 }
    }

    pub fn remaining_count(&self) -> u16 {
        unsafe { dma_get_remaining_count(self.channel.0) }
    }
}

/// DMA statistics accessor
pub struct DmaStatsAccessor;

impl DmaStatsAccessor {
    pub fn get() -> DmaStats {
        let mut stats = DmaStats::default();
        unsafe {
            get_dma_stats(
                &mut stats.transfers,
                &mut stats.bytes_transferred,
                &mut stats.errors,
            );
        }
        stats
    }

    pub fn reset() {
        unsafe { reset_dma_stats() }
    }
}
