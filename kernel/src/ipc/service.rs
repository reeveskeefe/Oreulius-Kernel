/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


use core::sync::atomic::{AtomicU32, Ordering};

use spin::{Mutex, Once};

use super::{
    admission, backpressure, Capability, ChannelCapability, ChannelFlags, ChannelId, ChannelRights,
    ChannelTable, IpcDefer, IpcError, Message, ProcessId, RecvDecision, SendDecision,
    CHANNEL_CAPACITY, MAX_CAPS_PER_MESSAGE, MAX_CHANNELS,
};

/// The main IPC service.
pub struct IpcService {
    pub(crate) channels: Mutex<ChannelTable>,
    next_cap_id: AtomicU32,
}

impl IpcService {
    pub const fn new() -> Self {
        IpcService {
            channels: Mutex::new(ChannelTable::new()),
            next_cap_id: AtomicU32::new(1),
        }
    }

    fn alloc_channel_cap_id(&self) -> u32 {
        let id = self.next_cap_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            self.next_cap_id.fetch_add(1, Ordering::Relaxed)
        } else {
            id
        }
    }

    pub fn create_channel(
        &self,
        creator: ProcessId,
    ) -> Result<(ChannelCapability, ChannelCapability), IpcError> {
        let mut table = self.channels.lock();
        let channel_id = table.create_channel(creator)?;
        let send_cap_id = self.alloc_channel_cap_id();
        let recv_cap_id = self.alloc_channel_cap_id();

        let send_cap =
            ChannelCapability::new(send_cap_id, channel_id, ChannelRights::send_only(), creator);

        let recv_cap = ChannelCapability::new(
            recv_cap_id,
            channel_id,
            ChannelRights::receive_only(),
            creator,
        );

        Ok((send_cap, recv_cap))
    }

    pub fn send(&self, msg: Message, capability: &ChannelCapability) -> Result<(), IpcError> {
        loop {
            let send_msg = msg;
            let plan = {
                let mut table = self.channels.lock();
                let channel = table
                    .get_mut(capability.channel_id)
                    .ok_or(IpcError::InvalidCap)?;
                backpressure::observe_send_attempt(channel);

                match admission::evaluate_send(channel, capability, &send_msg) {
                    SendDecision::Commit => {
                        return channel.send_with_observed_pressure(send_msg, capability);
                    }
                    SendDecision::Refuse(refusal) => {
                        return channel.reject_send(refusal, capability, &send_msg);
                    }
                    SendDecision::Defer(IpcDefer::WaitForCapacity) => {
                        match crate::scheduler::quantum_scheduler::prepare_block_on(
                            channel.capacity_wait_addr(),
                            crate::scheduler::process::ProcessState::WaitingOnChannel,
                        ) {
                            Ok(plan) => {
                                if let Some(pid) = crate::scheduler::process::current_pid() {
                                    channel
                                        .waiting_senders
                                        .push_back(crate::ipc::ProcessId(pid.0));
                                }
                                plan
                            }
                            Err(_) => {
                                return channel.defer_send(
                                    IpcDefer::WaitForCapacity,
                                    capability,
                                    &send_msg,
                                )
                            }
                        }
                    }
                    SendDecision::Defer(defer) => {
                        return channel.defer_send(defer, capability, &send_msg);
                    }
                }
            };

            crate::scheduler::quantum_scheduler::commit_block(plan);
        }
    }

    pub fn try_recv(&self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.try_recv(capability)
    }

    pub fn recv(&self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        loop {
            let plan = {
                let mut table = self.channels.lock();
                let channel = table
                    .get_mut(capability.channel_id)
                    .ok_or(IpcError::InvalidCap)?;

                match admission::evaluate_recv(channel, capability) {
                    RecvDecision::Deliver => return channel.try_recv(capability),
                    RecvDecision::Refuse(refusal) => {
                        return channel.reject_recv(refusal, capability)
                    }
                    RecvDecision::Defer(IpcDefer::WaitForMessage) => {
                        match crate::scheduler::quantum_scheduler::prepare_block_on(
                            channel.message_wait_addr(),
                            crate::scheduler::process::ProcessState::WaitingOnChannel,
                        ) {
                            Ok(plan) => {
                                if let Some(pid) = crate::scheduler::process::current_pid() {
                                    channel
                                        .waiting_receivers
                                        .push_back(crate::ipc::ProcessId(pid.0));
                                }
                                plan
                            }
                            Err(_) => return Err(IpcError::WouldBlock),
                        }
                    }
                    RecvDecision::Defer(defer) => return channel.defer_recv(defer, capability),
                }
            };

            crate::scheduler::quantum_scheduler::commit_block(plan);
        }
    }

    pub fn close(&self, capability: &ChannelCapability) -> Result<(), IpcError> {
        let mut table = self.channels.lock();
        let channel = table
            .get_mut(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        channel.close(capability)
    }

    pub fn channel_stats(
        &self,
        capability: &ChannelCapability,
    ) -> Result<(usize, usize, bool), IpcError> {
        let table = self.channels.lock();
        let channel = table
            .get(capability.channel_id)
            .ok_or(IpcError::InvalidCap)?;

        Ok((channel.pending(), CHANNEL_CAPACITY, channel.is_closed()))
    }

    pub fn stats(&self) -> (usize, usize) {
        let table = self.channels.lock();
        (table.count(), MAX_CHANNELS)
    }
}

static IPC: Once<IpcService> = Once::new();

pub fn ipc() -> &'static IpcService {
    if let Some(ipc) = IPC.get() {
        ipc
    } else {
        IPC.call_once(IpcService::new)
    }
}

pub fn init() {
    let _ = IPC.call_once(IpcService::new);
}

pub fn create_channel() -> Result<usize, &'static str> {
    create_channel_for_process(ProcessId::KERNEL)
}

pub fn create_channel_for_process(creator: ProcessId) -> Result<usize, &'static str> {
    create_channel_for_process_with_flags(
        creator,
        ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE),
        128,
    )
}

pub fn create_channel_for_process_with_flags(
    creator: ProcessId,
    flags: ChannelFlags,
    priority: u8,
) -> Result<usize, &'static str> {
    let mut channels = ipc().channels.lock();

    match channels.create_channel_with_flags(creator, flags, priority) {
        Ok(channel_id) => {
            let rights = crate::capability::Rights::new(
                crate::capability::Rights::CHANNEL_SEND
                    | crate::capability::Rights::CHANNEL_RECEIVE
                    | crate::capability::Rights::CHANNEL_CLONE_SENDER
                    | crate::capability::Rights::CHANNEL_CREATE,
            );
            let cap_result = crate::capability::capability_manager().grant_capability(
                creator,
                channel_id.0 as u64,
                crate::capability::CapabilityType::Channel,
                rights,
                creator,
            );
            if cap_result.is_err() {
                let _ = channels.delete_channel(channel_id);
                return Err("Failed to grant channel capability");
            }
            Ok(channel_id.0 as usize)
        }
        Err(_) => Err("Failed to create channel"),
    }
}

pub fn send_message(channel_id: ChannelId, data: &[u8]) -> Result<(), &'static str> {
    send_message_for_process(ProcessId(0), channel_id, data)
}

pub fn send_message_for_process(
    source: ProcessId,
    channel_id: ChannelId,
    data: &[u8],
) -> Result<(), &'static str> {
    let msg = Message::with_data(source, data).map_err(|_| "Message too large")?;

    let cap = crate::capability::resolve_channel_capability(
        source,
        channel_id,
        crate::capability::ChannelAccess::Send,
    )
    .map_err(|_| "Missing channel capability")?;

    ipc().send(msg, &cap).map_err(|_| "Failed to send message")
}

pub fn send_message_with_caps_for_process(
    source: ProcessId,
    channel_id: ChannelId,
    data: &[u8],
    caps: &[Capability],
) -> Result<(), &'static str> {
    if caps.len() > MAX_CAPS_PER_MESSAGE {
        return Err("Too many capabilities");
    }

    let mut msg = Message::with_data(source, data).map_err(|_| "Message too large")?;
    for cap in caps.iter() {
        msg.add_capability(*cap)
            .map_err(|_| "Failed to attach capability")?;
    }

    let channel_cap = crate::capability::resolve_channel_capability(
        source,
        channel_id,
        crate::capability::ChannelAccess::Send,
    )
    .map_err(|_| "Missing channel capability")?;

    ipc()
        .send(msg, &channel_cap)
        .map_err(|_| "Failed to send message")
}

pub fn receive_message(channel_id: ChannelId, buffer: &mut [u8]) -> Result<usize, &'static str> {
    receive_message_for_process(ProcessId(0), channel_id, buffer)
}

pub fn receive_message_for_process(
    owner: ProcessId,
    channel_id: ChannelId,
    buffer: &mut [u8],
) -> Result<usize, &'static str> {
    let cap = crate::capability::resolve_channel_capability(
        owner,
        channel_id,
        crate::capability::ChannelAccess::Receive,
    )
    .map_err(|_| "Missing channel capability")?;

    match ipc().try_recv(&cap) {
        Ok(msg) => {
            let copy_len = msg.payload_len.min(buffer.len());
            buffer[..copy_len].copy_from_slice(&msg.payload[..copy_len]);
            Ok(copy_len)
        }
        Err(_) => Err("No message available"),
    }
}

pub fn receive_message_with_caps_for_process(
    owner: ProcessId,
    channel_id: ChannelId,
    buffer: &mut [u8],
    caps_out: &mut [Capability],
) -> Result<(usize, usize), &'static str> {
    let cap = crate::capability::resolve_channel_capability(
        owner,
        channel_id,
        crate::capability::ChannelAccess::Receive,
    )
    .map_err(|_| "Missing channel capability")?;

    match ipc().try_recv(&cap) {
        Ok(msg) => {
            let copy_len = msg.payload_len.min(buffer.len());
            buffer[..copy_len].copy_from_slice(&msg.payload[..copy_len]);

            let mut copied_caps = 0usize;
            for mcap in msg.capabilities() {
                if copied_caps >= caps_out.len() {
                    break;
                }
                caps_out[copied_caps] = *mcap;
                copied_caps += 1;
            }
            Ok((copy_len, copied_caps))
        }
        Err(_) => Err("No message available"),
    }
}

pub fn close_channel(channel_id: ChannelId) -> Result<(), &'static str> {
    close_channel_for_process(ProcessId(0), channel_id)
}

pub fn close_channel_for_process(
    owner: ProcessId,
    channel_id: ChannelId,
) -> Result<(), &'static str> {
    let cap = crate::capability::resolve_channel_capability(
        owner,
        channel_id,
        crate::capability::ChannelAccess::Close,
    )
    .map_err(|_| "Missing channel capability")?;

    ipc().close(&cap).map_err(|_| "Failed to close channel")
}

pub fn purge_channels_for_process(owner: ProcessId) -> usize {
    ipc().channels.lock().delete_channels_by_creator(owner)
}

pub fn temporal_apply_channel_event(
    channel_id: u32,
    event: u8,
    owner_pid: u32,
    payload_len: usize,
    _caps_len: usize,
    queue_depth: usize,
) -> Result<(), &'static str> {
    let channel_id = ChannelId(channel_id);
    let owner = ProcessId(owner_pid);
    let closed = event == crate::temporal::TEMPORAL_CHANNEL_EVENT_CLOSE;

    let mut table = ipc().channels.lock();
    let channel = table
        .ensure_channel_with_id(channel_id, owner)
        .map_err(|_| "Failed to ensure temporal channel")?;
    channel.temporal_restore_queue(owner, queue_depth, payload_len, closed);
    Ok(())
}

pub fn temporal_apply_channel_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < 28 {
        return Err("Temporal channel payload too short");
    }
    if payload[0] != crate::temporal::TEMPORAL_OBJECT_ENCODING_V1 {
        return Err("Temporal channel payload encoding mismatch");
    }
    if payload[1] != crate::temporal::TEMPORAL_CHANNEL_OBJECT {
        return Err("Temporal channel payload object mismatch");
    }

    if payload[3] == 2 {
        let channel_id = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let owner_pid = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let mut table = ipc().channels.lock();
        let channel = table
            .ensure_channel_with_id(ChannelId(channel_id), ProcessId(owner_pid))
            .map_err(|_| "Failed to ensure temporal channel")?;
        return channel.restore_temporal_snapshot_payload(payload);
    }

    let event = payload[2];
    let channel_id = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let owner_pid = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let payload_len =
        u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]) as usize;
    let caps_len = u16::from_le_bytes([payload[16], payload[17]]) as usize;
    let queue_depth = u16::from_le_bytes([payload[18], payload[19]]) as usize;

    temporal_apply_channel_event(
        channel_id,
        event,
        owner_pid,
        payload_len,
        caps_len,
        queue_depth,
    )
}
