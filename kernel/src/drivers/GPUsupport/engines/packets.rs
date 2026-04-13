/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


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
