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
 * Engine packet model.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferPacket {
    pub src_bo: u64,
    pub dst_bo: u64,
    pub bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputePacket {
    pub kernel_bo: u64,
    pub grid_x: u32,
    pub grid_y: u32,
    pub grid_z: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPacket {
    Transfer(TransferPacket),
    Compute(ComputePacket),
}
