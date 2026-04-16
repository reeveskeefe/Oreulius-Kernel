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


use super::{Channel, ChannelFlags, ChannelId, IpcError, ProcessId, MAX_CHANNELS};
use alloc::collections::BTreeMap;

/// Global channel table.
pub struct ChannelTable {
    pub(crate) channels: BTreeMap<ChannelId, Channel>,
    next_id: u32,
}

impl ChannelTable {
    pub const fn new() -> Self {
        ChannelTable {
            channels: BTreeMap::new(),
            next_id: 1,
        }
    }

    pub fn create_channel(&mut self, creator: ProcessId) -> Result<ChannelId, IpcError> {
        self.create_channel_with_flags(
            creator,
            ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE),
            128,
        )
    }

    pub fn create_channel_with_flags(
        &mut self,
        creator: ProcessId,
        flags: ChannelFlags,
        priority: u8,
    ) -> Result<ChannelId, IpcError> {
        if self.channels.len() >= MAX_CHANNELS {
            return Err(IpcError::TooManyChannels);
        }

        let id = ChannelId::new(self.next_id);
        self.next_id += 1;
        self.channels
            .insert(id, Channel::new_with_flags(id, creator, flags, priority));
        Ok(id)
    }

    pub(crate) fn ensure_channel_with_id(
        &mut self,
        id: ChannelId,
        creator: ProcessId,
    ) -> Result<&mut Channel, IpcError> {
        if !self.channels.contains_key(&id) {
            if self.channels.len() >= MAX_CHANNELS {
                return Err(IpcError::TooManyChannels);
            }
            self.channels.insert(id, Channel::new(id, creator));
            if self.next_id <= id.0 {
                self.next_id = id.0.saturating_add(1);
            }
        }
        self.channels.get_mut(&id).ok_or(IpcError::TooManyChannels)
    }

    pub fn get_mut(&mut self, id: ChannelId) -> Option<&mut Channel> {
        self.channels.get_mut(&id)
    }

    pub fn get(&self, id: ChannelId) -> Option<&Channel> {
        self.channels.get(&id)
    }

    pub fn delete_channel(&mut self, id: ChannelId) -> Result<(), IpcError> {
        self.channels
            .remove(&id)
            .ok_or(IpcError::InvalidCap)
            .map(|_| ())
    }

    pub fn delete_channels_by_creator(&mut self, creator: ProcessId) -> usize {
        let before = self.channels.len();
        self.channels.retain(|_, ch| ch.creator != creator);
        before.saturating_sub(self.channels.len())
    }

    pub fn count(&self) -> usize {
        self.channels.len()
    }
}
