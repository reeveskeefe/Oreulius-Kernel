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
