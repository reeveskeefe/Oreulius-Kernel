use super::{
    channel_capacity_wait_addr, channel_message_wait_addr, BackpressureAction, BackpressureLevel,
    Channel, ChannelId, ChannelTable, IpcError, IpcService, ProcessId, CHANNEL_CAPACITY,
    MAX_CHANNELS,
};

#[derive(Debug, Clone, Copy)]
pub struct ChannelDiagnostics {
    pub id: ChannelId,
    pub creator: ProcessId,
    pub pending: usize,
    pub capacity: usize,
    pub closure: super::ClosureState,
    pub empty: bool,
    pub full: bool,
    pub priority: u8,
    pub flags_bits: u32,
    pub send_refusals: u32,
    pub recv_refusals: u32,
    pub pressure: BackpressureLevel,
    pub pressure_action: BackpressureAction,
    pub high_watermark: usize,
    pub high_pressure_hits: u32,
    pub saturated_hits: u32,
    pub sender_wakeups: u32,
    pub receiver_wakeups: u32,
    pub waiting_receivers: usize,
    pub waiting_senders: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct IpcDiagnostics {
    pub active_channels: usize,
    pub max_channels: usize,
    pub channels: [Option<ChannelDiagnostics>; MAX_CHANNELS],
}

impl Channel {
    fn diagnostics(&self) -> ChannelDiagnostics {
        ChannelDiagnostics {
            id: self.id,
            creator: self.creator,
            pending: self.pending(),
            capacity: CHANNEL_CAPACITY,
            closure: self.closure,
            empty: self.is_empty(),
            full: self.is_full(),
            priority: self.priority,
            flags_bits: self.flags.bits(),
            send_refusals: self.send_refusals,
            recv_refusals: self.recv_refusals,
            pressure: self.pressure_level(),
            pressure_action: self.pressure_action(),
            high_watermark: self.high_watermark,
            high_pressure_hits: self.high_pressure_hits,
            saturated_hits: self.saturated_hits,
            sender_wakeups: self.sender_wakeups,
            receiver_wakeups: self.receiver_wakeups,
            waiting_receivers: crate::quantum_scheduler::waiter_count(channel_message_wait_addr(
                self.id,
            )),
            waiting_senders: crate::quantum_scheduler::waiter_count(channel_capacity_wait_addr(
                self.id,
            )),
        }
    }
}

impl ChannelTable {
    fn diagnostics(&self) -> IpcDiagnostics {
        let mut channels = [None; MAX_CHANNELS];
        let mut write_idx = 0usize;

        for channel in self.channels.values() {
            if write_idx < channels.len() {
                channels[write_idx] = Some(channel.diagnostics());
                write_idx += 1;
            }
        }

        IpcDiagnostics {
            active_channels: write_idx,
            max_channels: MAX_CHANNELS,
            channels,
        }
    }
}

impl IpcService {
    pub fn diagnostics(&self) -> IpcDiagnostics {
        self.channels.lock().diagnostics()
    }

    pub fn inspect_channel(&self, id: ChannelId) -> Result<ChannelDiagnostics, IpcError> {
        let table = self.channels.lock();
        let channel = table.get(id).ok_or(IpcError::InvalidCap)?;
        Ok(channel.diagnostics())
    }
}
