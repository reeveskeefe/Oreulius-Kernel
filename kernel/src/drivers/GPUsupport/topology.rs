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
 * GPU resource graph and aperture descriptors.
 */

use super::caps::GpuEngineMask;
use super::core::GpuBarInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApertureKind {
    Mmio,
    Framebuffer,
    Doorbell,
    CommandQueue,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuAperture {
    pub kind: ApertureKind,
    pub bar: GpuBarInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuResourceGraph {
    pub apertures: [Option<GpuAperture>; 8],
    pub engines: GpuEngineMask,
}

impl GpuResourceGraph {
    pub const fn new(engines: GpuEngineMask) -> Self {
        GpuResourceGraph {
            apertures: [None, None, None, None, None, None, None, None],
            engines,
        }
    }
}
