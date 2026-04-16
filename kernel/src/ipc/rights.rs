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


use crate::math::linear_capability::LinearCapability;

use super::types::{ChannelId, ProcessId};

/// Channel rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRights {
    bits: u32,
}

impl ChannelRights {
    pub const NONE: u32 = 0;
    pub const SEND: u32 = 1 << 0;
    pub const RECEIVE: u32 = 1 << 1;
    pub const CLOSE: u32 = 1 << 2;
    pub const ALL: u32 = Self::SEND | Self::RECEIVE | Self::CLOSE;

    pub const fn new(bits: u32) -> Self {
        ChannelRights { bits }
    }

    pub const fn bits(&self) -> u32 {
        self.bits
    }

    pub const fn has(&self, right: u32) -> bool {
        (self.bits & right) != 0
    }

    pub const fn send_only() -> Self {
        ChannelRights { bits: Self::SEND }
    }

    pub const fn receive_only() -> Self {
        ChannelRights {
            bits: Self::RECEIVE,
        }
    }

    pub const fn send_receive() -> Self {
        ChannelRights {
            bits: Self::SEND | Self::RECEIVE,
        }
    }

    pub const fn all() -> Self {
        ChannelRights { bits: Self::ALL }
    }

    pub const fn full() -> Self {
        Self::all()
    }
}

/// A capability to access a channel.
#[derive(Debug, Clone, Copy)]
pub struct ChannelCapability {
    pub cap_id: u32,
    pub channel_id: ChannelId,
    pub rights: ChannelRights,
    pub owner: ProcessId,
}

/// Singularity-style affine endpoint for bounded capability message consumption.
pub struct AffineEndpoint<const CAPACITY: usize> {
    pub cap: LinearCapability<ChannelCapability, CAPACITY>,
}

impl<const CAPACITY: usize> AffineEndpoint<CAPACITY> {
    pub fn new(cap: ChannelCapability) -> Self {
        Self {
            cap: LinearCapability::new(cap),
        }
    }

    /// Split the endpoint enforcing exact zero-sum delegation capacities.
    pub fn delegate_zero_sum<const A: usize, const B: usize>(
        self,
    ) -> Result<(AffineEndpoint<A>, AffineEndpoint<B>), &'static str> {
        let (cap_a, cap_b) = self.cap.affine_split::<A, B>()?;
        Ok((AffineEndpoint { cap: cap_a }, AffineEndpoint { cap: cap_b }))
    }

    pub fn inner_cap(&self) -> &ChannelCapability {
        &self.cap.resource
    }
}

impl ChannelCapability {
    pub fn new(
        cap_id: u32,
        channel_id: ChannelId,
        rights: ChannelRights,
        owner: ProcessId,
    ) -> Self {
        ChannelCapability {
            cap_id,
            channel_id,
            rights,
            owner,
        }
    }

    pub fn can_send(&self) -> bool {
        self.rights.has(ChannelRights::SEND)
    }

    pub fn can_receive(&self) -> bool {
        self.rights.has(ChannelRights::RECEIVE)
    }

    pub fn can_close(&self) -> bool {
        self.rights.has(ChannelRights::CLOSE)
    }
}
