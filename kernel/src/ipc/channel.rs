/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


use alloc::vec::Vec;

use super::ring::RingBuffer;
use super::{
    admission, backpressure, channel_capacity_wait_addr, channel_message_wait_addr, AffineEndpoint,
    BackpressureAction, BackpressureLevel, Capability, ChannelCapability, ChannelId, EventId,
    IpcDefer, IpcError, IpcRefusal, Message, ProcessId, RecvDecision, SendDecision,
    CHANNEL_CAPACITY, MAX_CAPS_PER_MESSAGE, MAX_MESSAGE_SIZE,
};
use super::types::{
    temporal_ipc_append_u16, temporal_ipc_append_u32, temporal_ipc_append_u64,
    temporal_ipc_parse_request_payload, temporal_ipc_parse_response_payload, temporal_ipc_read_u16,
    temporal_ipc_read_u32, temporal_ipc_read_u64, ChannelProtocolState, TemporalIpcFrameKind,
    TemporalIpcPhase, TemporalRequestFrame, TemporalResponseFrame, TemporalSessionState,
};

// ============================================================================
// ClosureState — Def A.31 graceful closure protocol
// ============================================================================

/// Explicit state machine for channel lifecycle (Def A.31).
///
/// ```text
///  Open ──close()──► Draining ──last_msg_drained──► Sealed
///                        │
///               new sends → Err(ChannelDraining)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureState {
    /// Normal operating state.
    Open,
    /// `close()` was called while in-flight messages remain.
    /// New sends are rejected with `IpcError::ChannelDraining`.
    /// Receivers may still dequeue pending messages.
    /// Transitions to `Sealed` when the ring buffer reaches zero.
    Draining {
        /// Process that initiated the close.
        initiator: ProcessId,
        /// Tick at which `close()` was called.
        initiated_at: u64,
    },
    /// Ring is empty and close is complete.
    /// All further sends *and* recvs return `IpcError::Closed`.
    Sealed,
}

impl ClosureState {
    /// Returns `true` if no new sends should be accepted.
    #[inline]
    pub const fn is_closing(&self) -> bool {
        matches!(self, ClosureState::Draining { .. })
    }

    /// Returns `true` if the channel is fully sealed.
    #[inline]
    pub const fn is_closed(&self) -> bool {
        matches!(self, ClosureState::Sealed)
    }

    /// Returns `true` if the channel is either draining or sealed.
    #[inline]
    pub const fn is_shutting_down(&self) -> bool {
        !matches!(self, ClosureState::Open)
    }
}

/// Result of an explicit `drain()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainResult {
    /// All in-flight messages have been consumed; the channel is now `Sealed`.
    Complete,
    /// Messages remain; `pending` is how many are still in the ring.
    Pending(usize),
    /// Channel was already sealed before `drain()` was called.
    AlreadySealed,
}

/// Channel configuration flags (bitfield)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelFlags {
    bits: u32,
}

impl ChannelFlags {
    pub const NONE: u32 = 0;
    pub const BOUNDED: u32 = 1 << 0;
    pub const UNBOUNDED: u32 = 1 << 1;
    pub const HIGH_PRIORITY: u32 = 1 << 2;
    pub const RELIABLE: u32 = 1 << 3;
    pub const ASYNC: u32 = 1 << 4;

    pub const fn new(bits: u32) -> Self {
        ChannelFlags { bits }
    }

    pub const fn bits(&self) -> u32 {
        self.bits
    }

    pub const fn is_bounded(&self) -> bool {
        (self.bits & Self::UNBOUNDED) == 0
    }

    pub const fn is_high_priority(&self) -> bool {
        (self.bits & Self::HIGH_PRIORITY) != 0
    }

    pub const fn is_reliable(&self) -> bool {
        (self.bits & Self::RELIABLE) != 0
    }

    pub const fn is_async(&self) -> bool {
        (self.bits & Self::ASYNC) != 0
    }
}

/// A bidirectional channel for message passing.
pub struct Channel {
    pub id: ChannelId,
    pub(crate) buffer: RingBuffer,
    /// Closure protocol state (Def A.31).
    pub(crate) closure: ClosureState,
    pub(crate) creator: ProcessId,
    pub(crate) flags: ChannelFlags,
    pub(crate) priority: u8,
    pub(crate) send_refusals: u32,
    pub(crate) recv_refusals: u32,
    pub(crate) high_watermark: usize,
    pub(crate) high_pressure_hits: u32,
    pub(crate) saturated_hits: u32,
    pub(crate) sender_wakeups: u32,
    pub(crate) receiver_wakeups: u32,
    pub(crate) waiting_receivers: WaitQueue,
    pub(crate) waiting_senders: WaitQueue,
    pub(crate) protocol: ChannelProtocolState,
}

impl Channel {
    pub fn new(id: ChannelId, creator: ProcessId) -> Self {
        Channel {
            id,
            buffer: RingBuffer::new(),
            closure: ClosureState::Open,
            creator,
            flags: ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::RELIABLE),
            priority: 128,
            send_refusals: 0,
            recv_refusals: 0,
            high_watermark: 0,
            high_pressure_hits: 0,
            saturated_hits: 0,
            sender_wakeups: 0,
            receiver_wakeups: 0,
            waiting_receivers: WaitQueue::new(),
            waiting_senders: WaitQueue::new(),
            protocol: ChannelProtocolState::unbound(),
        }
    }

    pub fn new_with_flags(
        id: ChannelId,
        creator: ProcessId,
        flags: ChannelFlags,
        priority: u8,
    ) -> Self {
        Channel {
            id,
            buffer: RingBuffer::new(),
            closure: ClosureState::Open,
            creator,
            flags,
            priority,
            send_refusals: 0,
            recv_refusals: 0,
            high_watermark: 0,
            high_pressure_hits: 0,
            saturated_hits: 0,
            sender_wakeups: 0,
            receiver_wakeups: 0,
            waiting_receivers: WaitQueue::new(),
            waiting_senders: WaitQueue::new(),
            protocol: ChannelProtocolState::unbound(),
        }
    }

    pub(crate) fn message_wait_addr(&self) -> usize {
        channel_message_wait_addr(self.id)
    }

    pub(crate) fn capacity_wait_addr(&self) -> usize {
        channel_capacity_wait_addr(self.id)
    }

    fn note_receiver_wakeups(&mut self, count: usize) {
        let count = core::cmp::min(count, u32::MAX as usize) as u32;
        self.receiver_wakeups = self.receiver_wakeups.saturating_add(count);
    }

    fn note_sender_wakeups(&mut self, count: usize) {
        let count = core::cmp::min(count, u32::MAX as usize) as u32;
        self.sender_wakeups = self.sender_wakeups.saturating_add(count);
    }

    fn wake_one_receiver(&mut self) {
        let mut woke = false;
        while let Some(pid) = self.waiting_receivers.pop_front() {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_process(crate::scheduler::process::Pid(pid.0)) {
                self.note_receiver_wakeups(1);
                woke = true;
                break;
            }
        }
        if !woke {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_one(self.message_wait_addr()) {
                self.note_receiver_wakeups(1);
            }
        }
    }

    fn wake_all_receivers(&mut self) {
        let mut count = 0;
        while let Some(pid) = self.waiting_receivers.pop_front() {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_process(crate::scheduler::process::Pid(pid.0)) {
                count += 1;
            }
        }
        if count > 0 {
            self.note_receiver_wakeups(count);
        } else {
            if let Ok(woken) = crate::scheduler::quantum_scheduler::wake_all(self.message_wait_addr()) {
                if woken > 0 {
                    self.note_receiver_wakeups(woken);
                }
            }
        }
    }

    fn wake_one_sender(&mut self) {
        let mut woke = false;
        while let Some(pid) = self.waiting_senders.pop_front() {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_process(crate::scheduler::process::Pid(pid.0)) {
                self.note_sender_wakeups(1);
                woke = true;
                break;
            }
        }
        if !woke {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_one(self.capacity_wait_addr()) {
                self.note_sender_wakeups(1);
            }
        }
    }

    fn wake_all_senders(&mut self) {
        let mut count = 0;
        while let Some(pid) = self.waiting_senders.pop_front() {
            if let Ok(true) = crate::scheduler::quantum_scheduler::wake_process(crate::scheduler::process::Pid(pid.0)) {
                count += 1;
            }
        }
        if count > 0 {
            self.note_sender_wakeups(count);
        } else {
            if let Ok(woken) = crate::scheduler::quantum_scheduler::wake_all(self.capacity_wait_addr()) {
                if woken > 0 {
                    self.note_sender_wakeups(woken);
                }
            }
        }
    }

    fn note_queue_occupancy(&mut self) {
        self.high_watermark = self.high_watermark.max(self.buffer.len());
    }

    fn rollback_ticketed_caps(&self, msg: &Message) {
        for cap in msg.capabilities() {
            if cap.ticket_id != 0 {
                let _ = crate::capability::capability_manager()
                    .rollback_ipc_transfer(cap.owner_pid, cap.ticket_id);
            }
        }
    }

    pub(crate) fn bind_temporal_protocol(&mut self, session_id: u64) {
        self.protocol = ChannelProtocolState::temporal(session_id);
    }

    pub(crate) fn bind_temporal_protocol_state(&mut self, state: TemporalSessionState) {
        self.protocol = ChannelProtocolState::Temporal(state);
    }

    pub(crate) fn protocol_state(&self) -> ChannelProtocolState {
        self.protocol
    }

    fn temporal_request_frame<'a>(&self, msg: &'a Message) -> Result<TemporalRequestFrame<'a>, IpcError> {
        temporal_ipc_parse_request_payload(msg.payload())
    }

    fn temporal_response_frame<'a>(
        &self,
        msg: &'a Message,
    ) -> Result<TemporalResponseFrame<'a>, IpcError> {
        temporal_ipc_parse_response_payload(msg.payload())
    }

    pub(crate) fn validate_temporal_send(&self, msg: &Message) -> Result<TemporalIpcFrameKind, IpcError> {
        let state = match self.protocol {
            ChannelProtocolState::Unbound => return Ok(TemporalIpcFrameKind::Request),
            ChannelProtocolState::Temporal(state) => state,
        };

        match state.phase {
            TemporalIpcPhase::AwaitRequestSend => {
                let frame = self.temporal_request_frame(msg)?;
                if frame.session_id != state.session_id || frame.request_id != state.next_request_id {
                    return Err(IpcError::ProtocolMismatch);
                }
                Ok(TemporalIpcFrameKind::Request)
            }
            TemporalIpcPhase::AwaitResponseSend => {
                let frame = self.temporal_response_frame(msg)?;
                if frame.session_id != state.session_id
                    || frame.request_id != state.last_request_id
                    || frame.opcode != state.last_opcode
                {
                    return Err(IpcError::ProtocolMismatch);
                }
                Ok(TemporalIpcFrameKind::Response)
            }
            TemporalIpcPhase::AwaitRequestRecv | TemporalIpcPhase::AwaitResponseRecv => {
                Err(IpcError::ProtocolMismatch)
            }
        }
    }

    pub(crate) fn validate_temporal_recv(&self, msg: &Message) -> Result<TemporalIpcFrameKind, IpcError> {
        let state = match self.protocol {
            ChannelProtocolState::Unbound => return Ok(TemporalIpcFrameKind::Request),
            ChannelProtocolState::Temporal(state) => state,
        };

        match state.phase {
            TemporalIpcPhase::AwaitRequestRecv => {
                let frame = self.temporal_request_frame(msg)?;
                if frame.session_id != state.session_id
                    || frame.request_id != state.last_request_id
                    || frame.opcode != state.last_opcode
                {
                    return Err(IpcError::ProtocolMismatch);
                }
                Ok(TemporalIpcFrameKind::Request)
            }
            TemporalIpcPhase::AwaitResponseRecv => {
                let frame = self.temporal_response_frame(msg)?;
                if frame.session_id != state.session_id
                    || frame.request_id != state.last_request_id
                    || frame.opcode != state.last_opcode
                {
                    return Err(IpcError::ProtocolMismatch);
                }
                Ok(TemporalIpcFrameKind::Response)
            }
            TemporalIpcPhase::AwaitRequestSend | TemporalIpcPhase::AwaitResponseSend => {
                Err(IpcError::ProtocolMismatch)
            }
        }
    }

    fn advance_protocol_after_send(&mut self, msg: &Message) {
        let state = match self.protocol {
            ChannelProtocolState::Temporal(state) => state,
            ChannelProtocolState::Unbound => return,
        };

        match state.phase {
            TemporalIpcPhase::AwaitRequestSend => {
                if let Ok(frame) = self.temporal_request_frame(msg) {
                    let mut next = state;
                    next.phase = TemporalIpcPhase::AwaitRequestRecv;
                    next.last_request_id = frame.request_id;
                    next.last_opcode = frame.opcode;
                    next.next_request_id = frame.request_id.wrapping_add(1);
                    self.protocol = ChannelProtocolState::Temporal(next);
                }
            }
            TemporalIpcPhase::AwaitResponseSend => {
                if self.temporal_response_frame(msg).is_ok() {
                    let mut next = state;
                    next.phase = TemporalIpcPhase::AwaitResponseRecv;
                    self.protocol = ChannelProtocolState::Temporal(next);
                }
            }
            TemporalIpcPhase::AwaitRequestRecv | TemporalIpcPhase::AwaitResponseRecv => {}
        }
    }

    fn advance_protocol_after_recv(&mut self, msg: &Message) {
        let state = match self.protocol {
            ChannelProtocolState::Temporal(state) => state,
            ChannelProtocolState::Unbound => return,
        };

        match state.phase {
            TemporalIpcPhase::AwaitRequestRecv => {
                if self.temporal_request_frame(msg).is_ok() {
                    let mut next = state;
                    next.phase = TemporalIpcPhase::AwaitResponseSend;
                    self.protocol = ChannelProtocolState::Temporal(next);
                }
            }
            TemporalIpcPhase::AwaitResponseRecv => {
                if self.temporal_response_frame(msg).is_ok() {
                    let mut next = state;
                    next.phase = TemporalIpcPhase::AwaitRequestSend;
                    next.last_request_id = 0;
                    next.last_opcode = 0;
                    self.protocol = ChannelProtocolState::Temporal(next);
                }
            }
            TemporalIpcPhase::AwaitRequestSend | TemporalIpcPhase::AwaitResponseSend => {}
        }
    }

    fn encode_temporal_snapshot_payload(
        &self,
        event: u8,
        owner: ProcessId,
        payload_len: usize,
        caps_len: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.reserve(512);
        out.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
        out.push(crate::temporal::TEMPORAL_CHANNEL_OBJECT);
        out.push(event);
        out.push(2);
        temporal_ipc_append_u32(&mut out, self.id.0);
        temporal_ipc_append_u32(&mut out, owner.0);
        temporal_ipc_append_u32(&mut out, payload_len as u32);
        temporal_ipc_append_u16(&mut out, caps_len as u16);
        temporal_ipc_append_u16(&mut out, self.buffer.len() as u16);
        temporal_ipc_append_u64(&mut out, crate::scheduler::pit::get_ticks() as u64);

        match self.closure {
            ClosureState::Open => {
                out.push(0);
                out.extend_from_slice(&[0u8; 3]);
                temporal_ipc_append_u32(&mut out, 0);
                temporal_ipc_append_u64(&mut out, 0);
            }
            ClosureState::Draining {
                initiator,
                initiated_at,
            } => {
                out.push(1);
                out.extend_from_slice(&[0u8; 3]);
                temporal_ipc_append_u32(&mut out, initiator.0);
                temporal_ipc_append_u64(&mut out, initiated_at);
            }
            ClosureState::Sealed => {
                out.push(2);
                out.extend_from_slice(&[0u8; 3]);
                temporal_ipc_append_u32(&mut out, 0);
                temporal_ipc_append_u64(&mut out, 0);
            }
        }

        match self.protocol {
            ChannelProtocolState::Unbound => {
                out.push(0);
                out.push(0);
                out.extend_from_slice(&[0u8; 2]);
                temporal_ipc_append_u64(&mut out, 0);
                temporal_ipc_append_u32(&mut out, 0);
                temporal_ipc_append_u32(&mut out, 0);
                out.push(0);
                out.extend_from_slice(&[0u8; 3]);
            }
            ChannelProtocolState::Temporal(state) => {
                out.push(1);
                out.push(match state.phase {
                    TemporalIpcPhase::AwaitRequestSend => 0,
                    TemporalIpcPhase::AwaitRequestRecv => 1,
                    TemporalIpcPhase::AwaitResponseSend => 2,
                    TemporalIpcPhase::AwaitResponseRecv => 3,
                });
                out.extend_from_slice(&[0u8; 2]);
                temporal_ipc_append_u64(&mut out, state.session_id);
                temporal_ipc_append_u32(&mut out, state.next_request_id);
                temporal_ipc_append_u32(&mut out, state.last_request_id);
                out.push(state.last_opcode);
                out.extend_from_slice(&[0u8; 3]);
            }
        }

        temporal_ipc_append_u32(&mut out, self.send_refusals);
        temporal_ipc_append_u32(&mut out, self.recv_refusals);
        temporal_ipc_append_u32(&mut out, self.high_watermark as u32);
        temporal_ipc_append_u32(&mut out, self.high_pressure_hits);
        temporal_ipc_append_u32(&mut out, self.saturated_hits);
        temporal_ipc_append_u32(&mut out, self.sender_wakeups);
        temporal_ipc_append_u32(&mut out, self.receiver_wakeups);

        out.push(self.waiting_receivers.len() as u8);
        out.push(self.waiting_senders.len() as u8);
        out.extend_from_slice(&[0u8; 2]);
        let mut receivers = [ProcessId(0); 16];
        let mut senders = [ProcessId(0); 16];
        let mut recv_count = 0usize;
        let mut send_count = 0usize;
        let mut recv_queue = self.waiting_receivers.clone();
        while let Some(pid) = recv_queue.pop_front() {
            if recv_count < receivers.len() {
                receivers[recv_count] = pid;
                recv_count += 1;
            }
        }
        let mut send_queue = self.waiting_senders.clone();
        while let Some(pid) = send_queue.pop_front() {
            if send_count < senders.len() {
                senders[send_count] = pid;
                send_count += 1;
            }
        }
        temporal_ipc_append_u16(&mut out, recv_count as u16);
        temporal_ipc_append_u16(&mut out, send_count as u16);
        let mut i = 0usize;
        while i < recv_count {
            temporal_ipc_append_u32(&mut out, receivers[i].0);
            i += 1;
        }
        i = 0;
        while i < send_count {
            temporal_ipc_append_u32(&mut out, senders[i].0);
            i += 1;
        }

        temporal_ipc_append_u16(&mut out, self.buffer.len() as u16);
        for msg in self.buffer.iter() {
            temporal_snapshot_append_message(&mut out, &msg);
        }

        out
    }

    pub(crate) fn persist_temporal_snapshot(
        &self,
        event: u8,
        owner: ProcessId,
        payload_len: usize,
        caps_len: usize,
    ) -> Result<u64, crate::temporal::TemporalError> {
        let payload = self.encode_temporal_snapshot_payload(event, owner, payload_len, caps_len);
        crate::temporal::record_object_write(&crate::temporal::ipc_channel_object_key(self.id.0), &payload)
    }

    pub(crate) fn restore_temporal_snapshot_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        if payload.len() < 28 {
            return Err("temporal ipc channel snapshot too short");
        }
        if payload[0] != crate::temporal::TEMPORAL_OBJECT_ENCODING_V1
            || payload[1] != crate::temporal::TEMPORAL_CHANNEL_OBJECT
            || payload[3] != 2
        {
            return Err("temporal ipc channel snapshot type mismatch");
        }

        let channel_id = temporal_ipc_read_u32(payload, 4).ok_or("temporal ipc channel snapshot missing id")?;
        if channel_id != self.id.0 {
            return Err("temporal ipc channel snapshot id mismatch");
        }

        let owner_pid = temporal_ipc_read_u32(payload, 8).ok_or("temporal ipc channel snapshot missing owner")?;
        let payload_len = temporal_ipc_read_u32(payload, 12).ok_or("temporal ipc channel snapshot missing payload length")? as usize;
        let caps_len = temporal_ipc_read_u16(payload, 16).ok_or("temporal ipc channel snapshot missing caps length")? as usize;
        let queue_depth = temporal_ipc_read_u16(payload, 18).ok_or("temporal ipc channel snapshot missing queue depth")? as usize;
        if owner_pid != self.creator.0 {
            return Err("temporal ipc channel snapshot owner mismatch");
        }

        let mut cursor = 28usize;
        let closure_tag = *payload.get(cursor).ok_or("temporal ipc channel snapshot missing closure tag")?;
        cursor = cursor.saturating_add(4);
        let initiator = ProcessId(
            temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot missing closure initiator")?,
        );
        cursor = cursor.saturating_add(4);
        let initiated_at = temporal_ipc_read_u64(payload, cursor).ok_or("temporal ipc channel snapshot missing closure tick")?;
        cursor = cursor.saturating_add(8);
        self.closure = match closure_tag {
            0 => ClosureState::Open,
            1 => ClosureState::Draining {
                initiator,
                initiated_at,
            },
            2 => ClosureState::Sealed,
            _ => return Err("temporal ipc channel snapshot closure mismatch"),
        };

        let protocol_kind = *payload.get(cursor).ok_or("temporal ipc channel snapshot missing protocol kind")?;
        cursor = cursor.saturating_add(1);
        let phase_raw = *payload.get(cursor).ok_or("temporal ipc channel snapshot missing protocol phase")?;
        cursor = cursor.saturating_add(1);
        cursor = cursor.saturating_add(2);
        let session_id = temporal_ipc_read_u64(payload, cursor).ok_or("temporal ipc channel snapshot missing session id")?;
        cursor = cursor.saturating_add(8);
        let next_request_id = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot missing next request id")?;
        cursor = cursor.saturating_add(4);
        let last_request_id = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot missing last request id")?;
        cursor = cursor.saturating_add(4);
        let last_opcode = *payload.get(cursor).ok_or("temporal ipc channel snapshot missing last opcode")?;
        cursor = cursor.saturating_add(4);
        self.protocol = match protocol_kind {
            0 => ChannelProtocolState::Unbound,
            1 => {
                let phase = match phase_raw {
                    0 => TemporalIpcPhase::AwaitRequestSend,
                    1 => TemporalIpcPhase::AwaitRequestRecv,
                    2 => TemporalIpcPhase::AwaitResponseSend,
                    3 => TemporalIpcPhase::AwaitResponseRecv,
                    _ => return Err("temporal ipc channel snapshot phase mismatch"),
                };
                ChannelProtocolState::Temporal(super::types::TemporalSessionState {
                    session_id,
                    phase,
                    next_request_id,
                    last_request_id,
                    last_opcode,
                })
            }
            _ => return Err("temporal ipc channel snapshot protocol mismatch"),
        };

        self.send_refusals = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot send refusals missing")?;
        cursor = cursor.saturating_add(4);
        self.recv_refusals = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot recv refusals missing")?;
        cursor = cursor.saturating_add(4);
        self.high_watermark = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot high watermark missing")? as usize;
        cursor = cursor.saturating_add(4);
        self.high_pressure_hits = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot high pressure hits missing")?;
        cursor = cursor.saturating_add(4);
        self.saturated_hits = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot saturated hits missing")?;
        cursor = cursor.saturating_add(4);
        self.sender_wakeups = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot sender wakeups missing")?;
        cursor = cursor.saturating_add(4);
        self.receiver_wakeups = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot receiver wakeups missing")?;
        cursor = cursor.saturating_add(4);

        let receiver_count = *payload.get(cursor).ok_or("temporal ipc channel snapshot receiver count missing")? as usize;
        cursor = cursor.saturating_add(1);
        let sender_count = *payload.get(cursor).ok_or("temporal ipc channel snapshot sender count missing")? as usize;
        cursor = cursor.saturating_add(1);
        cursor = cursor.saturating_add(2);
        let stored_receiver_count = temporal_ipc_read_u16(payload, cursor).ok_or("temporal ipc channel snapshot stored receiver count missing")? as usize;
        cursor = cursor.saturating_add(2);
        let stored_sender_count = temporal_ipc_read_u16(payload, cursor).ok_or("temporal ipc channel snapshot stored sender count missing")? as usize;
        cursor = cursor.saturating_add(2);
        let mut recv_queue = WaitQueue::new();
        let mut sender_queue = WaitQueue::new();
        let mut i = 0usize;
        while i < stored_receiver_count {
            let pid = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot receiver pid missing")?;
            cursor = cursor.saturating_add(4);
            recv_queue.push_back(ProcessId(pid));
            i += 1;
        }
        i = 0;
        while i < stored_sender_count {
            let pid = temporal_ipc_read_u32(payload, cursor).ok_or("temporal ipc channel snapshot sender pid missing")?;
            cursor = cursor.saturating_add(4);
            sender_queue.push_back(ProcessId(pid));
            i += 1;
        }
        self.waiting_receivers = recv_queue;
        self.waiting_senders = sender_queue;
        if self.waiting_receivers.len() != receiver_count || self.waiting_senders.len() != sender_count {
            return Err("temporal ipc channel snapshot wait queue mismatch");
        }

        let restored_messages = temporal_ipc_read_u16(payload, cursor).ok_or("temporal ipc channel snapshot message count missing")? as usize;
        cursor = cursor.saturating_add(2);
        self.buffer.clear();
        let mut restored_max_seq = 0u16;
        i = 0;
        while i < restored_messages {
            let msg = temporal_snapshot_read_message(payload, &mut cursor)?;
            restored_max_seq = restored_max_seq.max(msg.id.msg_seq());
            if let Some(cause) = msg.cause {
                restored_max_seq = restored_max_seq.max(cause.msg_seq());
            }
            if self.buffer.push(msg).is_err() {
                return Err("temporal ipc channel snapshot buffer overflow");
            }
            i += 1;
        }

        if restored_messages != queue_depth || self.buffer.len() != queue_depth {
            return Err("temporal ipc channel snapshot queue depth mismatch");
        }

        self.note_queue_occupancy();
        let _ = payload_len;
        let _ = caps_len;

        let next_seq = restored_max_seq.wrapping_add(1);
        crate::ipc::message::set_next_msg_seq(next_seq);

        // Rehydrate pending IPC tickets from restored message caps.
        for msg in self.buffer.iter() {
            for cap in msg.capabilities() {
                if cap.ticket_id != 0 {
                    crate::capability::capability_manager()
                        .restore_ipc_transfer_from_snapshot(msg.source, cap.cap_id, *cap)
                        .map_err(|_| "temporal ipc channel snapshot capability restore failed")?;
                }
            }
        }

        Ok(())
    }

    pub fn send_affine<const C: usize>(
        &mut self,
        msg: Message,
        endpoint: &AffineEndpoint<C>,
    ) -> Result<(), IpcError> {
        self.send(msg, endpoint.inner_cap())
    }

    pub fn receive_affine<const C: usize>(
        &mut self,
        endpoint: &AffineEndpoint<C>,
    ) -> Result<Message, IpcError> {
        self.recv(endpoint.inner_cap())
    }

    fn record_send_refusal(&mut self, owner: ProcessId, payload_len: usize, caps_len: usize) {
        self.send_refusals = self.send_refusals.saturating_add(1);
        let _ = crate::temporal::record_ipc_channel_event(
            self.id.0,
            crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND_REFUSED,
            owner.0,
            payload_len,
            caps_len,
            self.buffer.len(),
        );
        let _ = self.persist_temporal_snapshot(
            crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND_REFUSED,
            owner,
            payload_len,
            caps_len,
        );
    }

    fn record_recv_refusal(&mut self, owner: ProcessId) {
        self.recv_refusals = self.recv_refusals.saturating_add(1);
        let _ = crate::temporal::record_ipc_channel_event(
            self.id.0,
            crate::temporal::TEMPORAL_CHANNEL_EVENT_RECV_REFUSED,
            owner.0,
            0,
            0,
            self.buffer.len(),
        );
        let _ = self.persist_temporal_snapshot(
            crate::temporal::TEMPORAL_CHANNEL_EVENT_RECV_REFUSED,
            owner,
            0,
            0,
        );
    }

    pub(crate) fn reject_send(
        &mut self,
        refusal: IpcRefusal,
        capability: &ChannelCapability,
        msg: &Message,
    ) -> Result<(), IpcError> {
        let sec = crate::security::security();
        match refusal {
            IpcRefusal::PredictiveRestriction => {
                let restore_at = sec.restriction_until_tick(capability.owner);
                let _ = crate::capability::capability_manager().predictive_revoke_capabilities(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_SEND,
                    restore_at,
                );
                sec.intent_capability_denied(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_SEND,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::PermissionDenied,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::PermissionDenied)
            }
            IpcRefusal::PermissionDenied => {
                sec.intent_capability_denied(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_SEND,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::PermissionDenied,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::PermissionDenied)
            }
            IpcRefusal::InvalidCapability => {
                sec.intent_invalid_capability(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_SEND,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::InvalidCapability,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::InvalidCap)
            }
            IpcRefusal::Closed => {
                self.rollback_ticketed_caps(msg);
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::Closed)
            }
            IpcRefusal::ChannelDraining => {
                self.rollback_ticketed_caps(msg);
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::ChannelDraining)
            }
            IpcRefusal::Backpressure | IpcRefusal::QueueFull | IpcRefusal::QueueEmpty => {
                self.rollback_ticketed_caps(msg);
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::WouldBlock)
            }
            IpcRefusal::ProtocolMismatch => {
                self.rollback_ticketed_caps(msg);
                self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
                Err(IpcError::ProtocolMismatch)
            }
        }
    }

    pub(crate) fn defer_send(
        &mut self,
        _defer: IpcDefer,
        capability: &ChannelCapability,
        msg: &Message,
    ) -> Result<(), IpcError> {
        self.rollback_ticketed_caps(msg);
        self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
        Err(IpcError::WouldBlock)
    }

    pub(crate) fn reject_recv(
        &mut self,
        refusal: IpcRefusal,
        capability: &ChannelCapability,
    ) -> Result<Message, IpcError> {
        let sec = crate::security::security();
        match refusal {
            IpcRefusal::PredictiveRestriction => {
                let restore_at = sec.restriction_until_tick(capability.owner);
                let _ = crate::capability::capability_manager().predictive_revoke_capabilities(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_RECEIVE,
                    restore_at,
                );
                sec.intent_capability_denied(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_RECEIVE,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::PermissionDenied,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_recv_refusal(capability.owner);
                Err(IpcError::PermissionDenied)
            }
            IpcRefusal::PermissionDenied => {
                sec.intent_capability_denied(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_RECEIVE,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::PermissionDenied,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_recv_refusal(capability.owner);
                Err(IpcError::PermissionDenied)
            }
            IpcRefusal::InvalidCapability => {
                sec.intent_invalid_capability(
                    capability.owner,
                    crate::capability::CapabilityType::Channel,
                    crate::capability::Rights::CHANNEL_RECEIVE,
                    self.id.0 as u64,
                );
                sec.log_event(
                    crate::security::AuditEntry::new(
                        crate::security::SecurityEvent::InvalidCapability,
                        capability.owner,
                        capability.cap_id,
                    )
                    .with_context(self.id.0 as u64),
                );
                self.record_recv_refusal(capability.owner);
                Err(IpcError::InvalidCap)
            }
            IpcRefusal::ProtocolMismatch => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::ProtocolMismatch)
            }
            IpcRefusal::Closed => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::Closed)
            }
            IpcRefusal::ChannelDraining => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::ChannelDraining)
            }
            IpcRefusal::Backpressure | IpcRefusal::QueueFull | IpcRefusal::QueueEmpty => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::WouldBlock)
            }
        }
    }

    pub(crate) fn defer_recv(
        &mut self,
        _defer: IpcDefer,
        capability: &ChannelCapability,
    ) -> Result<Message, IpcError> {
        self.record_recv_refusal(capability.owner);
        Err(IpcError::WouldBlock)
    }

    pub(crate) fn send_with_observed_pressure(
        &mut self,
        msg: Message,
        capability: &ChannelCapability,
    ) -> Result<(), IpcError> {
        match admission::evaluate_send(self, capability, &msg) {
            SendDecision::Commit => {}
            SendDecision::Refuse(refusal) => return self.reject_send(refusal, capability, &msg),
            SendDecision::Defer(defer) => return self.defer_send(defer, capability, &msg),
        }

        if let Err(err) = self.validate_temporal_send(&msg) {
            self.rollback_ticketed_caps(&msg);
            self.record_send_refusal(capability.owner, msg.payload.len(), msg.caps_len);
            return Err(err);
        }
        let msg_for_protocol = msg;
        let payload_len = msg.payload.len();
        let caps_len = msg.caps_len;
        let result = self.buffer.push(msg);
        if result.is_ok() {
            self.advance_protocol_after_send(&msg_for_protocol);
            self.note_queue_occupancy();
            let sec = crate::security::security();
            let _ = crate::temporal::record_ipc_channel_event(
                self.id.0,
                crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND,
                capability.owner.0,
                payload_len,
                caps_len,
                self.buffer.len(),
            );
            sec.intent_ipc_send(capability.owner, self.id.0 as u64);
            self.wake_one_receiver();
            let _ = self.persist_temporal_snapshot(
                crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND,
                capability.owner,
                payload_len,
                caps_len,
            );
        } else {
            self.rollback_ticketed_caps(&msg);
            self.record_send_refusal(capability.owner, payload_len, caps_len);
        }
        result
    }

    pub fn send(&mut self, msg: Message, capability: &ChannelCapability) -> Result<(), IpcError> {
        backpressure::observe_send_attempt(self);
        self.send_with_observed_pressure(msg, capability)
    }

    pub fn try_recv(&mut self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        match admission::evaluate_recv(self, capability) {
            RecvDecision::Deliver => {}
            RecvDecision::Refuse(refusal) => return self.reject_recv(refusal, capability),
            RecvDecision::Defer(defer) => return self.defer_recv(defer, capability),
        }

        let peeked = match self.buffer.peek() {
            Some(msg) => {
                if let Err(err) = self.validate_temporal_recv(&msg) {
                    self.record_recv_refusal(capability.owner);
                    return Err(err);
                }
                msg
            }
            None => {
                self.record_recv_refusal(capability.owner);
                return Err(IpcError::WouldBlock);
            }
        };

        match self.buffer.pop() {
            Some(msg) => {
                let became_sealed = self.closure.is_closing() && self.buffer.len() == 0;
                let sec = crate::security::security();
                let _ = crate::temporal::record_ipc_channel_event(
                    self.id.0,
                    crate::temporal::TEMPORAL_CHANNEL_EVENT_RECV,
                    capability.owner.0,
                    msg.payload.len(),
                    msg.caps_len,
                    self.buffer.len(),
                );
                sec.intent_ipc_recv(capability.owner, self.id.0 as u64);
                self.advance_protocol_after_recv(&msg);
                if became_sealed {
                    self.closure = ClosureState::Sealed;
                    // Emit audit event: drain complete → sealed.
                    sec.log_event(
                        crate::security::AuditEntry::new(
                            crate::security::SecurityEvent::ClosureSealed,
                            capability.owner,
                            0,
                        )
                        .with_context(self.id.0 as u64),
                    );
                }
                self.wake_one_sender();
                if became_sealed {
                    self.wake_all_receivers();
                    self.wake_all_senders();
                }
                let _ = self.persist_temporal_snapshot(
                    crate::temporal::TEMPORAL_CHANNEL_EVENT_RECV,
                    capability.owner,
                    peeked.payload.len(),
                    peeked.caps_len,
                );
                Ok(msg)
            }
            None => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::WouldBlock)
            }
        }
    }

    pub fn recv(&mut self, capability: &ChannelCapability) -> Result<Message, IpcError> {
        self.try_recv(capability)
    }

    pub fn close(&mut self, capability: &ChannelCapability) -> Result<(), IpcError> {
        let sec = crate::security::security();
        if !capability.can_close() {
            sec.intent_capability_denied(
                capability.owner,
                crate::capability::CapabilityType::Channel,
                crate::capability::Rights::ALL,
                self.id.0 as u64,
            );
            return Err(IpcError::PermissionDenied);
        }

        if capability.channel_id != self.id {
            sec.intent_invalid_capability(
                capability.owner,
                crate::capability::CapabilityType::Channel,
                crate::capability::Rights::ALL,
                self.id.0 as u64,
            );
            return Err(IpcError::InvalidCap);
        }

        if self.closure.is_shutting_down() {
            return Ok(());
        }

        let now_ticks = crate::scheduler::pit::get_ticks() as u64;
        if self.buffer.is_empty() {
            self.closure = ClosureState::Sealed;
            sec.log_event(
                crate::security::AuditEntry::new(
                    crate::security::SecurityEvent::ClosureSealed,
                    capability.owner,
                    0,
                )
                .with_context(self.id.0 as u64),
            );
        } else {
            self.closure = ClosureState::Draining {
                initiator: capability.owner,
                initiated_at: now_ticks,
            };
            sec.log_event(
                crate::security::AuditEntry::new(
                    crate::security::SecurityEvent::ClosureDraining,
                    capability.owner,
                    0,
                )
                .with_context(self.id.0 as u64),
            );
        }
        let _ = crate::temporal::record_ipc_channel_event(
            self.id.0,
            crate::temporal::TEMPORAL_CHANNEL_EVENT_CLOSE,
            capability.owner.0,
            0,
            0,
            self.buffer.len(),
        );
        if self.closure.is_closed() {
            self.wake_all_receivers();
        } else {
            self.wake_one_receiver();
        }
        self.wake_all_senders();
        let _ = self.persist_temporal_snapshot(
            crate::temporal::TEMPORAL_CHANNEL_EVENT_CLOSE,
            capability.owner,
            0,
            0,
        );
        Ok(())
    }

    /// Explicit drain API (Def A.31).
    ///
    /// Attempt to consume the next in-flight message from a `Draining` channel
    /// using the supplied receiver capability.  Returns:
    ///
    /// - `Ok(DrainResult::Pending(n))` — one message was consumed, `n` remain.
    /// - `Ok(DrainResult::Complete)` — last message consumed, channel is now `Sealed`.
    /// - `Ok(DrainResult::AlreadySealed)` — nothing to drain.
    /// - `Err(_)` — permission error or invalid capability.
    pub fn drain(&mut self, capability: &ChannelCapability) -> Result<DrainResult, IpcError> {
        if self.closure.is_closed() {
            return Ok(DrainResult::AlreadySealed);
        }
        if !self.closure.is_closing() {
            // Open channel — nothing to drain.
            return Ok(DrainResult::AlreadySealed);
        }
        match self.try_recv(capability) {
            Ok(_) => {
                if self.closure.is_closed() {
                    Ok(DrainResult::Complete)
                } else {
                    Ok(DrainResult::Pending(self.buffer.len()))
                }
            }
            Err(IpcError::WouldBlock) => Ok(DrainResult::AlreadySealed),
            Err(e) => Err(e),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closure.is_closed()
    }

    pub fn is_closing(&self) -> bool {
        self.closure.is_closing()
    }

    pub fn closure_state(&self) -> ClosureState {
        self.closure
    }

    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn flags(&self) -> ChannelFlags {
        self.flags
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.buffer.is_full()
    }

    pub fn send_refusals(&self) -> u32 {
        self.send_refusals
    }

    pub fn recv_refusals(&self) -> u32 {
        self.recv_refusals
    }

    pub fn high_watermark(&self) -> usize {
        self.high_watermark
    }

    pub fn high_pressure_hits(&self) -> u32 {
        self.high_pressure_hits
    }

    pub fn saturated_hits(&self) -> u32 {
        self.saturated_hits
    }

    pub fn sender_wakeups(&self) -> u32 {
        self.sender_wakeups
    }

    pub fn receiver_wakeups(&self) -> u32 {
        self.receiver_wakeups
    }

    pub fn pressure_level(&self) -> BackpressureLevel {
        backpressure::level(self)
    }

    pub fn pressure_action(&self) -> BackpressureAction {
        backpressure::recommended_send_action(self)
    }

    pub(crate) fn temporal_restore_queue(
        &mut self,
        owner: ProcessId,
        queue_depth: usize,
        payload_len_hint: usize,
        closed: bool,
    ) {
        self.closure = if closed && queue_depth == 0 {
            ClosureState::Sealed
        } else if closed && queue_depth > 0 {
            ClosureState::Draining {
                initiator: owner,
                initiated_at: 0,
            }
        } else {
            ClosureState::Open
        };
        self.buffer.clear();
        self.send_refusals = 0;
        self.recv_refusals = 0;
        self.high_watermark = 0;
        self.high_pressure_hits = 0;
        self.saturated_hits = 0;
        self.sender_wakeups = 0;
        self.receiver_wakeups = 0;
        if closed && queue_depth == 0 {
            return;
        }

        let synth_depth = core::cmp::min(queue_depth, CHANNEL_CAPACITY);
        let synth_payload_len = core::cmp::min(payload_len_hint, MAX_MESSAGE_SIZE);
        let mut remaining = synth_depth;
        while remaining > 0 {
            let mut msg = Message::new(owner);
            msg.payload_len = synth_payload_len;
            let _ = self.buffer.push(msg);
            self.note_queue_occupancy();
            remaining -= 1;
        }
    }
}
#[derive(Debug, Clone)]
pub struct WaitQueue {
    items: [ProcessId; 16],
    head: usize,
    tail: usize,
    len: usize,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            items: [ProcessId(0); 16],
            head: 0,
            tail: 0,
            len: 0,
        }
    }
    pub fn push_back(&mut self, pid: ProcessId) {
        if self.len < 16 {
            self.items[self.tail] = pid;
            self.tail = (self.tail + 1) % 16;
            self.len += 1;
        }
    }
    pub fn pop_front(&mut self) -> Option<ProcessId> {
        if self.len == 0 {
            None
        } else {
            let pid = self.items[self.head];
            self.head = (self.head + 1) % 16;
            self.len -= 1;
            Some(pid)
        }
    }
    pub fn len(&self) -> usize {
        self.len
    }
}

fn temporal_snapshot_append_capability(out: &mut Vec<u8>, cap: &Capability) {
    temporal_ipc_append_u32(out, cap.cap_id);
    temporal_ipc_append_u64(out, cap.ticket_id);
    temporal_ipc_append_u64(out, cap.object_id);
    temporal_ipc_append_u32(out, cap.rights.bits());
    temporal_ipc_append_u32(out, cap.cap_type as u32);
    temporal_ipc_append_u32(out, cap.owner_pid.0);
    temporal_ipc_append_u64(out, cap.issued_at);
    temporal_ipc_append_u64(out, cap.expires_at);
    temporal_ipc_append_u32(out, cap.flags);
    for word in &cap.extra {
        temporal_ipc_append_u32(out, *word);
    }
    temporal_ipc_append_u64(out, cap.token);
}

fn temporal_snapshot_cap_type(raw: u32) -> crate::ipc::CapabilityType {
    match raw {
        1 => crate::ipc::CapabilityType::Channel,
        2 => crate::ipc::CapabilityType::Filesystem,
        3 => crate::ipc::CapabilityType::Store,
        4 => crate::ipc::CapabilityType::ServicePointer,
        _ => crate::ipc::CapabilityType::Generic,
    }
}

fn temporal_snapshot_read_capability(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<Capability, &'static str> {
    let cap_id = temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot capability id missing")?;
    *cursor = (*cursor).saturating_add(4);
    let ticket_id = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot ticket id missing")?;
    *cursor = (*cursor).saturating_add(8);
    let object_id = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot object id missing")?;
    *cursor = (*cursor).saturating_add(8);
    let rights = temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot rights missing")?;
    *cursor = (*cursor).saturating_add(4);
    let cap_type_raw = temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot cap type missing")?;
    *cursor = (*cursor).saturating_add(4);
    let owner_pid = temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot owner missing")?;
    *cursor = (*cursor).saturating_add(4);
    let issued_at = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot issued_at missing")?;
    *cursor = (*cursor).saturating_add(8);
    let expires_at = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot expires_at missing")?;
    *cursor = (*cursor).saturating_add(8);
    let flags = temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot flags missing")?;
    *cursor = (*cursor).saturating_add(4);
    let mut extra = [0u32; 4];
    let mut idx = 0usize;
    while idx < extra.len() {
        extra[idx] = temporal_ipc_read_u32(payload, *cursor)
            .ok_or("temporal ipc snapshot capability extra missing")?;
        *cursor = (*cursor).saturating_add(4);
        idx += 1;
    }
    let token = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot token missing")?;
    *cursor = (*cursor).saturating_add(8);

    let mut cap = Capability::with_type(
        cap_id,
        object_id,
        crate::capability::Rights::new(rights),
        temporal_snapshot_cap_type(cap_type_raw),
    )
    .with_owner(ProcessId(owner_pid))
    .with_validity(issued_at, expires_at)
    .with_flags(flags)
    .with_ticket_id(ticket_id);
    cap.extra = extra;
    cap.token = token;
    Ok(cap)
}

fn temporal_snapshot_append_message(out: &mut Vec<u8>, msg: &Message) {
    temporal_ipc_append_u64(out, msg.id.raw());
    out.push(msg.cause.is_some() as u8);
    out.extend_from_slice(&[0u8; 3]);
    temporal_ipc_append_u32(out, msg.source.0);
    temporal_ipc_append_u16(out, msg.payload_len as u16);
    temporal_ipc_append_u16(out, msg.caps_len as u16);
    temporal_ipc_append_u16(out, 0);
    if let Some(cause) = msg.cause {
        temporal_ipc_append_u64(out, cause.raw());
    }
    out.extend_from_slice(&msg.payload[..msg.payload_len]);
    for cap in msg.capabilities() {
        temporal_snapshot_append_capability(out, cap);
    }
}

fn temporal_snapshot_read_message(
    payload: &[u8],
    cursor: &mut usize,
) -> Result<Message, &'static str> {
    let msg_id = temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot message id missing")?;
    *cursor = (*cursor).saturating_add(8);
    let has_cause = *payload.get(*cursor).ok_or("temporal ipc snapshot message cause flag missing")? != 0;
    *cursor = (*cursor).saturating_add(4);
    let source = ProcessId(
        temporal_ipc_read_u32(payload, *cursor).ok_or("temporal ipc snapshot message source missing")?,
    );
    *cursor = (*cursor).saturating_add(4);
    let payload_len = temporal_ipc_read_u16(payload, *cursor).ok_or("temporal ipc snapshot message payload length missing")? as usize;
    *cursor = (*cursor).saturating_add(2);
    let caps_len = temporal_ipc_read_u16(payload, *cursor).ok_or("temporal ipc snapshot message caps length missing")? as usize;
    *cursor = (*cursor).saturating_add(2);
    *cursor = (*cursor).saturating_add(2);
    let cause = if has_cause {
        Some(EventId(
            temporal_ipc_read_u64(payload, *cursor).ok_or("temporal ipc snapshot message cause missing")?,
        ))
    } else {
        None
    };
    if has_cause {
        *cursor = (*cursor).saturating_add(8);
    }
    if payload_len > MAX_MESSAGE_SIZE || caps_len > MAX_CAPS_PER_MESSAGE {
        return Err("temporal ipc snapshot message bounds invalid");
    }
    let end = (*cursor).saturating_add(payload_len);
    if end > payload.len() {
        return Err("temporal ipc snapshot message payload truncated");
    }

    let mut payload_bytes = [0u8; MAX_MESSAGE_SIZE];
    payload_bytes[..payload_len].copy_from_slice(&payload[*cursor..end]);
    *cursor = end;

    let mut caps: [Option<Capability>; MAX_CAPS_PER_MESSAGE] = [None; MAX_CAPS_PER_MESSAGE];
    let mut idx = 0usize;
    while idx < caps_len {
        let cap = temporal_snapshot_read_capability(payload, cursor)?;
        caps[idx] = Some(cap);
        idx += 1;
    }

    Ok(Message {
        id: EventId(msg_id),
        cause,
        payload: payload_bytes,
        payload_len,
        caps,
        caps_len,
        source,
    })
}
