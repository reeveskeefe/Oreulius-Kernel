use super::ring::RingBuffer;
use super::{
    admission, backpressure, channel_capacity_wait_addr, channel_message_wait_addr,
    AffineEndpoint, BackpressureAction, BackpressureLevel, ChannelCapability, ChannelId,
    IpcDefer, IpcError, IpcRefusal, Message, ProcessId, RecvDecision, SendDecision,
    CHANNEL_CAPACITY, MAX_MESSAGE_SIZE,
};

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
#[derive(Clone, Copy)]
pub struct Channel {
    pub id: ChannelId,
    pub(crate) buffer: RingBuffer,
    pub(crate) closing: bool,
    pub(crate) closed: bool,
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
}

impl Channel {
    pub fn new(id: ChannelId, creator: ProcessId) -> Self {
        Channel {
            id,
            buffer: RingBuffer::new(),
            closing: false,
            closed: false,
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
            closing: false,
            closed: false,
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
        if let Ok(true) = crate::quantum_scheduler::wake_one(self.message_wait_addr()) {
            self.note_receiver_wakeups(1);
        }
    }

    fn wake_all_receivers(&mut self) {
        if let Ok(count) = crate::quantum_scheduler::wake_all(self.message_wait_addr()) {
            self.note_receiver_wakeups(count);
        }
    }

    fn wake_one_sender(&mut self) {
        if let Ok(true) = crate::quantum_scheduler::wake_one(self.capacity_wait_addr()) {
            self.note_sender_wakeups(1);
        }
    }

    fn wake_all_senders(&mut self) {
        if let Ok(count) = crate::quantum_scheduler::wake_all(self.capacity_wait_addr()) {
            self.note_sender_wakeups(count);
        }
    }

    fn note_queue_occupancy(&mut self) {
        self.high_watermark = self.high_watermark.max(self.buffer.len());
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

    fn record_send_refusal(
        &mut self,
        owner: ProcessId,
        payload_len: usize,
        caps_len: usize,
    ) {
        self.send_refusals = self.send_refusals.saturating_add(1);
        let _ = crate::temporal::record_ipc_channel_event(
            self.id.0,
            crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND_REFUSED,
            owner.0,
            payload_len,
            caps_len,
            self.buffer.len(),
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
                self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
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
                self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
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
                self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
                Err(IpcError::InvalidCap)
            }
            IpcRefusal::Closed => {
                self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
                Err(IpcError::Closed)
            }
            IpcRefusal::Backpressure | IpcRefusal::QueueFull | IpcRefusal::QueueEmpty => {
                self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
                Err(IpcError::WouldBlock)
            }
        }
    }

    pub(crate) fn defer_send(
        &mut self,
        _defer: IpcDefer,
        capability: &ChannelCapability,
        msg: &Message,
    ) -> Result<(), IpcError> {
        self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
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
            IpcRefusal::Closed => {
                self.record_recv_refusal(capability.owner);
                Err(IpcError::Closed)
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
        match admission::evaluate_send(self, capability) {
            SendDecision::Commit => {}
            SendDecision::Refuse(refusal) => return self.reject_send(refusal, capability, &msg),
            SendDecision::Defer(defer) => return self.defer_send(defer, capability, &msg),
        }

        let result = self.buffer.push(msg);
        if result.is_ok() {
            self.note_queue_occupancy();
            let sec = crate::security::security();
            let _ = crate::temporal::record_ipc_channel_event(
                self.id.0,
                crate::temporal::TEMPORAL_CHANNEL_EVENT_SEND,
                capability.owner.0,
                msg.payload_len,
                msg.caps_len,
                self.buffer.len(),
            );
            sec.intent_ipc_send(capability.owner, self.id.0 as u64);
            self.wake_one_receiver();
        } else {
            self.record_send_refusal(capability.owner, msg.payload_len, msg.caps_len);
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

        match self.buffer.pop() {
            Some(msg) => {
                let became_closed = self.closing && self.buffer.len() == 0;
                let sec = crate::security::security();
                let _ = crate::temporal::record_ipc_channel_event(
                    self.id.0,
                    crate::temporal::TEMPORAL_CHANNEL_EVENT_RECV,
                    capability.owner.0,
                    msg.payload_len,
                    msg.caps_len,
                    self.buffer.len(),
                );
                sec.intent_ipc_recv(capability.owner, self.id.0 as u64);
                if became_closed {
                    self.closing = false;
                    self.closed = true;
                }
                self.wake_one_sender();
                if became_closed {
                    self.wake_all_receivers();
                    self.wake_all_senders();
                }
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

        if self.closed || self.closing {
            return Ok(());
        }

        if self.buffer.is_empty() {
            self.closed = true;
        } else {
            self.closing = true;
        }
        let _ = crate::temporal::record_ipc_channel_event(
            self.id.0,
            crate::temporal::TEMPORAL_CHANNEL_EVENT_CLOSE,
            capability.owner.0,
            0,
            0,
            self.buffer.len(),
        );
        if self.closed {
            self.wake_all_receivers();
        } else {
            self.wake_one_receiver();
        }
        self.wake_all_senders();
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.closed || self.closing
    }

    pub fn is_closing(&self) -> bool {
        self.closing
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
        self.closed = closed && queue_depth == 0;
        self.closing = closed && queue_depth > 0;
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
