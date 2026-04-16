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


/*!
 * Backend traits for GPU device classes.
 */

use super::caps::GpuCapabilities;
use super::core::{GpuProbeReport, GpuTier};
use super::engines::packets::{CommandPacket, ComputePacket, TransferPacket};
use super::errors::GpuError;
use super::transport::fence::GpuFence;

pub trait GpuDeviceOps {
    fn report(&self) -> GpuProbeReport;
    fn capabilities(&self) -> GpuCapabilities;
    fn tier(&self) -> GpuTier;
}

pub trait ScanoutOps {
    fn put_pixel(&self, x: u32, y: u32, r: u8, g: u8, b: u8);
    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8);
    fn flush(&self);
    fn width(&self) -> u32;
    fn height(&self) -> u32;
    fn is_available(&self) -> bool;
}

pub trait TransferOps {
    fn submit_transfer(&self, packet: &TransferPacket) -> Result<GpuFence, GpuError>;
}

pub trait ComputeOps {
    fn submit_compute(&self, packet: &ComputePacket) -> Result<GpuFence, GpuError>;
}

pub trait CommandOps {
    fn submit_packet(&self, packet: &CommandPacket) -> Result<GpuFence, GpuError>;
}
