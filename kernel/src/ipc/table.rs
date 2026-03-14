use super::{Channel, ChannelFlags, ChannelId, IpcError, ProcessId, MAX_CHANNELS};

/// Global channel table.
pub struct ChannelTable {
    pub(crate) channels: [Option<Channel>; MAX_CHANNELS],
    next_id: u32,
}

impl ChannelTable {
    pub const fn new() -> Self {
        ChannelTable {
            channels: [None; MAX_CHANNELS],
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
        for slot in &mut self.channels {
            if slot.is_none() {
                let id = ChannelId::new(self.next_id);
                self.next_id += 1;
                *slot = Some(Channel::new_with_flags(id, creator, flags, priority));
                return Ok(id);
            }
        }

        Err(IpcError::TooManyChannels)
    }

    fn find_slot_index(&self, id: ChannelId) -> Option<usize> {
        self.channels
            .iter()
            .position(|slot| slot.as_ref().map_or(false, |ch| ch.id == id))
    }

    fn find_empty_slot_index(&self) -> Option<usize> {
        self.channels.iter().position(|slot| slot.is_none())
    }

    pub(crate) fn ensure_channel_with_id(
        &mut self,
        id: ChannelId,
        creator: ProcessId,
    ) -> Result<&mut Channel, IpcError> {
        let idx = if let Some(existing_idx) = self.find_slot_index(id) {
            existing_idx
        } else {
            let slot_idx = self
                .find_empty_slot_index()
                .ok_or(IpcError::TooManyChannels)?;
            self.channels[slot_idx] = Some(Channel::new(id, creator));
            if self.next_id <= id.0 {
                self.next_id = id.0.saturating_add(1);
            }
            slot_idx
        };
        self.channels[idx].as_mut().ok_or(IpcError::TooManyChannels)
    }

    pub fn get_mut(&mut self, id: ChannelId) -> Option<&mut Channel> {
        self.channels
            .iter_mut()
            .find_map(|c| c.as_mut().filter(|ch| ch.id == id))
    }

    pub fn get(&self, id: ChannelId) -> Option<&Channel> {
        self.channels
            .iter()
            .find_map(|c| c.as_ref().filter(|ch| ch.id == id))
    }

    pub fn delete_channel(&mut self, id: ChannelId) -> Result<(), IpcError> {
        for slot in &mut self.channels {
            if let Some(channel) = slot {
                if channel.id == id {
                    *slot = None;
                    return Ok(());
                }
            }
        }

        Err(IpcError::InvalidCap)
    }

    pub fn delete_channels_by_creator(&mut self, creator: ProcessId) -> usize {
        let mut removed = 0usize;
        for slot in &mut self.channels {
            let should_remove = match slot.as_ref() {
                Some(channel) => channel.creator == creator,
                None => false,
            };
            if should_remove {
                *slot = None;
                removed = removed.saturating_add(1);
            }
        }
        removed
    }

    pub fn count(&self) -> usize {
        self.channels.iter().filter(|c| c.is_some()).count()
    }
}
