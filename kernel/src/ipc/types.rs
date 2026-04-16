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


use alloc::vec::Vec;

use crate::capability::Rights;
use super::errors::IpcError;
use crate::security::security;

/// Errors returned by typed IPC argument codecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedArgCodecError {
    BufferTooSmall,
    InvalidLength,
}

/// Marker trait for values that may be passed as typed service arguments over
/// IPC channels.
pub trait TypedServiceArg: Send {
    /// Stable runtime tag identifying this argument type.
    /// Values 0x0000-0x00FF are reserved for kernel primitives.
    fn type_tag() -> u32
    where
        Self: Sized;

    /// Number of bytes required to encode this value on the IPC wire.
    fn encoded_len(&self) -> usize;

    /// Encode this value into the provided output buffer.
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, TypedArgCodecError>;

    /// Decode a value of this type from the provided input buffer.
    fn decode_from(input: &[u8]) -> Result<Self, TypedArgCodecError>
    where
        Self: Sized;
}

impl TypedServiceArg for u8 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0001
    }

    #[inline(always)]
    fn encoded_len(&self) -> usize {
        1
    }

    #[inline(always)]
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, TypedArgCodecError> {
        if out.is_empty() {
            return Err(TypedArgCodecError::BufferTooSmall);
        }
        out[0] = *self;
        Ok(1)
    }

    #[inline(always)]
    fn decode_from(input: &[u8]) -> Result<Self, TypedArgCodecError> {
        if input.len() != 1 {
            return Err(TypedArgCodecError::InvalidLength);
        }
        Ok(input[0])
    }
}

impl TypedServiceArg for u32 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0004
    }

    #[inline(always)]
    fn encoded_len(&self) -> usize {
        4
    }

    #[inline(always)]
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, TypedArgCodecError> {
        if out.len() < 4 {
            return Err(TypedArgCodecError::BufferTooSmall);
        }
        out[..4].copy_from_slice(&self.to_le_bytes());
        Ok(4)
    }

    #[inline(always)]
    fn decode_from(input: &[u8]) -> Result<Self, TypedArgCodecError> {
        if input.len() != 4 {
            return Err(TypedArgCodecError::InvalidLength);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(input);
        Ok(u32::from_le_bytes(bytes))
    }
}

impl TypedServiceArg for u64 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0008
    }

    #[inline(always)]
    fn encoded_len(&self) -> usize {
        8
    }

    #[inline(always)]
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, TypedArgCodecError> {
        if out.len() < 8 {
            return Err(TypedArgCodecError::BufferTooSmall);
        }
        out[..8].copy_from_slice(&self.to_le_bytes());
        Ok(8)
    }

    #[inline(always)]
    fn decode_from(input: &[u8]) -> Result<Self, TypedArgCodecError> {
        if input.len() != 8 {
            return Err(TypedArgCodecError::InvalidLength);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(input);
        Ok(u64::from_le_bytes(bytes))
    }
}

impl<const N: usize> TypedServiceArg for [u8; N] {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0100 | (N as u32 & 0xFFFF)
    }

    #[inline(always)]
    fn encoded_len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, TypedArgCodecError> {
        if out.len() < N {
            return Err(TypedArgCodecError::BufferTooSmall);
        }
        out[..N].copy_from_slice(self);
        Ok(N)
    }

    #[inline(always)]
    fn decode_from(input: &[u8]) -> Result<Self, TypedArgCodecError> {
        if input.len() != N {
            return Err(TypedArgCodecError::InvalidLength);
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(input);
        Ok(bytes)
    }
}

/// Maximum message data size.
pub const MAX_MESSAGE_SIZE: usize = 512;

/// Maximum capabilities per message.
pub const MAX_CAPS_PER_MESSAGE: usize = 16;

/// Channel capacity.
pub const CHANNEL_CAPACITY: usize = 4;

/// Maximum number of channels.
pub const MAX_CHANNELS: usize = 16;

// ============================================================================
// EventId — causal message identity (Def A.7)
// ============================================================================

/// An opaque, globally unique identifier stamped on every IPC message.
///
/// Format (packed into 64 bits):
/// ```text
/// [63..32]  source ProcessId (32 bits)
/// [31..16]  channel sequence counter lower 16 bits
/// [15..0]   per-process message counter lower 16 bits
/// ```
///
/// Constructed via [`EventId::new`]; never created by user code.
/// The `cause` field on [`Message`] carries the `EventId` of the message
/// that causally preceded this one (if any), enabling causal chain reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId(pub u64);

impl EventId {
    /// Combine a source pid, a channel-scoped sequence, and a per-process
    /// counter into a unique 64-bit identifier.
    #[inline]
    pub const fn new(source_pid: u32, channel_seq: u16, msg_seq: u16) -> Self {
        let v = ((source_pid as u64) << 32) | ((channel_seq as u64) << 16) | (msg_seq as u64);
        EventId(v)
    }

    /// Decompose back into constituent parts.
    #[inline]
    pub const fn parts(self) -> (u32, u16, u16) {
        let pid = (self.0 >> 32) as u32;
        let chan_seq = ((self.0 >> 16) & 0xFFFF) as u16;
        let msg_seq = (self.0 & 0xFFFF) as u16;
        (pid, chan_seq, msg_seq)
    }

    /// Source process that emitted this event.
    #[inline]
    pub const fn source_pid(self) -> u32 {
        self.parts().0
    }

    /// Channel-local sequence encoded into this event id.
    #[inline]
    pub const fn channel_seq(self) -> u16 {
        self.parts().1
    }

    /// Per-process message sequence encoded into this event id.
    #[inline]
    pub const fn msg_seq(self) -> u16 {
        self.parts().2
    }

    /// The raw u64 value (for embedding into `AuditEntry::context`).
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub fn new(id: u32) -> Self {
        ChannelId(id)
    }
}

/// Process identifier (placeholder for v0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessId(pub u32);

impl ProcessId {
    pub fn new(id: u32) -> Self {
        ProcessId(id)
    }

    pub const KERNEL: ProcessId = ProcessId(0);
}

/// Type of capability being transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CapabilityType {
    Generic = 0,
    Channel = 1,
    Filesystem = 2,
    Store = 3,
    ServicePointer = 4,
}

impl CapabilityType {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(CapabilityType::Generic),
            1 => Some(CapabilityType::Channel),
            2 => Some(CapabilityType::Filesystem),
            3 => Some(CapabilityType::Store),
            4 => Some(CapabilityType::ServicePointer),
            _ => None,
        }
    }
}

/// Temporal IPC frame kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalIpcFrameKind {
    Request,
    Response,
}

/// Temporal IPC channel phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalIpcPhase {
    AwaitRequestSend,
    AwaitRequestRecv,
    AwaitResponseSend,
    AwaitResponseRecv,
}

/// Temporal IPC session state bound to a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalSessionState {
    pub session_id: u64,
    pub phase: TemporalIpcPhase,
    pub next_request_id: u32,
    pub last_request_id: u32,
    pub last_opcode: u8,
}

impl TemporalSessionState {
    pub const fn new(session_id: u64) -> Self {
        TemporalSessionState {
            session_id,
            phase: TemporalIpcPhase::AwaitRequestSend,
            next_request_id: 1,
            last_request_id: 0,
            last_opcode: 0,
        }
    }
}

/// Per-channel protocol binding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelProtocolState {
    Unbound,
    Temporal(TemporalSessionState),
}

impl ChannelProtocolState {
    pub const fn unbound() -> Self {
        ChannelProtocolState::Unbound
    }

    pub const fn temporal(session_id: u64) -> Self {
        ChannelProtocolState::Temporal(TemporalSessionState::new(session_id))
    }

    pub const fn is_unbound(&self) -> bool {
        matches!(self, ChannelProtocolState::Unbound)
    }

    pub const fn session_id(&self) -> Option<u64> {
        match self {
            ChannelProtocolState::Temporal(state) => Some(state.session_id),
            ChannelProtocolState::Unbound => None,
        }
    }
}

/// Temporal IPC request payload header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalRequestFrame<'a> {
    pub session_id: u64,
    pub opcode: u8,
    pub flags: u16,
    pub request_id: u32,
    pub payload: &'a [u8],
}

/// Temporal IPC response payload header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalResponseFrame<'a> {
    pub session_id: u64,
    pub opcode: u8,
    pub flags: u16,
    pub request_id: u32,
    pub status: i32,
    pub payload: &'a [u8],
}

pub const TEMPORAL_IPC_MAGIC: u32 = 0x3150_4D54; // "TMP1" in little-endian byte order
pub const TEMPORAL_IPC_VERSION: u8 = 1;
pub const TEMPORAL_IPC_SESSION_BYTES: usize = 8;
pub const TEMPORAL_IPC_REQUEST_HEADER_BYTES: usize = 16;
pub const TEMPORAL_IPC_RESPONSE_HEADER_BYTES: usize = 20;

pub(crate) fn temporal_ipc_append_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn temporal_ipc_append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn temporal_ipc_append_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn temporal_ipc_read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = buf.get(offset..end)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn temporal_ipc_read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = buf.get(offset..end)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn temporal_ipc_read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes = buf.get(offset..end)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn temporal_ipc_session_id(payload: &[u8]) -> Result<u64, IpcError> {
    if payload.len() < TEMPORAL_IPC_SESSION_BYTES {
        return Err(IpcError::ProtocolMismatch);
    }
    Ok(u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]))
}

pub(crate) fn temporal_ipc_parse_request_payload(
    payload: &[u8],
) -> Result<TemporalRequestFrame<'_>, IpcError> {
    if payload.len() < TEMPORAL_IPC_SESSION_BYTES + TEMPORAL_IPC_REQUEST_HEADER_BYTES {
        return Err(IpcError::ProtocolMismatch);
    }

    let session_id = temporal_ipc_session_id(payload)?;
    let frame = &payload[TEMPORAL_IPC_SESSION_BYTES..];
    let magic = temporal_ipc_read_u32(frame, 0).ok_or(IpcError::ProtocolMismatch)?;
    if magic != TEMPORAL_IPC_MAGIC || frame[4] != TEMPORAL_IPC_VERSION {
        return Err(IpcError::ProtocolMismatch);
    }

    let opcode = frame[5];
    let flags = temporal_ipc_read_u16(frame, 6).ok_or(IpcError::ProtocolMismatch)?;
    let request_id = temporal_ipc_read_u32(frame, 8).ok_or(IpcError::ProtocolMismatch)?;
    let payload_len = temporal_ipc_read_u16(frame, 12).ok_or(IpcError::ProtocolMismatch)? as usize;
    let expected_len = TEMPORAL_IPC_REQUEST_HEADER_BYTES.saturating_add(payload_len);
    if frame.len() != expected_len {
        return Err(IpcError::ProtocolMismatch);
    }

    Ok(TemporalRequestFrame {
        session_id,
        opcode,
        flags,
        request_id,
        payload: &frame[TEMPORAL_IPC_REQUEST_HEADER_BYTES..],
    })
}

pub(crate) fn temporal_ipc_parse_response_payload(
    payload: &[u8],
) -> Result<TemporalResponseFrame<'_>, IpcError> {
    if payload.len() < TEMPORAL_IPC_SESSION_BYTES + TEMPORAL_IPC_RESPONSE_HEADER_BYTES {
        return Err(IpcError::ProtocolMismatch);
    }

    let session_id = temporal_ipc_session_id(payload)?;
    let frame = &payload[TEMPORAL_IPC_SESSION_BYTES..];
    let magic = temporal_ipc_read_u32(frame, 0).ok_or(IpcError::ProtocolMismatch)?;
    if magic != TEMPORAL_IPC_MAGIC || frame[4] != TEMPORAL_IPC_VERSION {
        return Err(IpcError::ProtocolMismatch);
    }

    let opcode = frame[5];
    let flags = temporal_ipc_read_u16(frame, 6).ok_or(IpcError::ProtocolMismatch)?;
    let request_id = temporal_ipc_read_u32(frame, 8).ok_or(IpcError::ProtocolMismatch)?;
    let status = i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);
    let payload_len = temporal_ipc_read_u16(frame, 16).ok_or(IpcError::ProtocolMismatch)? as usize;
    let expected_len = TEMPORAL_IPC_RESPONSE_HEADER_BYTES.saturating_add(payload_len);
    if frame.len() != expected_len {
        return Err(IpcError::ProtocolMismatch);
    }

    Ok(TemporalResponseFrame {
        session_id,
        opcode,
        flags,
        request_id,
        status,
        payload: &frame[TEMPORAL_IPC_RESPONSE_HEADER_BYTES..],
    })
}

/// IPC capability transfer envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub cap_id: u32,
    /// One-time ticket identifier for zero-sum IPC transfers. `0` means the
    /// capability is not part of the ticketed kernel transfer ledger.
    pub ticket_id: u64,
    /// Full 64-bit kernel object identity.
    pub object_id: u64,
    pub rights: Rights,
    pub cap_type: CapabilityType,
    /// Issuer/owner binding for authenticated transfers.
    pub owner_pid: ProcessId,
    /// Logical issue timestamp for replay detection and auditing.
    pub issued_at: u64,
    /// Optional expiry timestamp (0 = no explicit expiry).
    pub expires_at: u64,
    /// Wire-level capability flags.
    pub flags: u32,
    /// Extra data (e.g. filesystem metadata).
    pub extra: [u32; 4],
    /// Cryptographic token (SipHash-2-4 MAC).
    pub token: u64,
}

impl Capability {
    pub const fn new(cap_id: u32, object_id: u64, rights: Rights) -> Self {
        Capability {
            cap_id,
            ticket_id: 0,
            object_id,
            rights,
            cap_type: CapabilityType::Generic,
            owner_pid: ProcessId::KERNEL,
            issued_at: 0,
            expires_at: 0,
            flags: 0,
            extra: [0; 4],
            token: 0,
        }
    }

    pub const fn with_type(
        cap_id: u32,
        object_id: u64,
        rights: Rights,
        cap_type: CapabilityType,
    ) -> Self {
        Capability {
            cap_id,
            ticket_id: 0,
            object_id,
            rights,
            cap_type,
            owner_pid: ProcessId::KERNEL,
            issued_at: 0,
            expires_at: 0,
            flags: 0,
            extra: [0; 4],
            token: 0,
        }
    }

    pub const fn with_owner(mut self, owner_pid: ProcessId) -> Self {
        self.owner_pid = owner_pid;
        self
    }

    pub const fn with_ticket_id(mut self, ticket_id: u64) -> Self {
        self.ticket_id = ticket_id;
        self
    }

    pub const fn with_validity(mut self, issued_at: u64, expires_at: u64) -> Self {
        self.issued_at = issued_at;
        self.expires_at = expires_at;
        self
    }

    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn sign(&mut self) {
        let payload = self.token_payload();
        self.token = security().cap_token_sign(&payload);
    }

    pub fn verify(&self) -> bool {
        let payload = self.token_payload();
        security().cap_token_verify(&payload, self.token)
    }

    pub const fn rights_bits(&self) -> u32 {
        self.rights.bits()
    }

    pub const fn has_rights(&self, required: Rights) -> bool {
        required.is_subset_of(&self.rights)
    }

    fn token_payload(&self) -> [u8; 80] {
        const TOKEN_CONTEXT: u32 = 0x4F43_4150; // "OCAP"
        const TOKEN_WIRE_VERSION: u32 = 1;
        let mut buf = [0u8; 80];
        let mut offset = 0usize;
        write_u32(&mut buf, &mut offset, TOKEN_CONTEXT);
        write_u32(&mut buf, &mut offset, TOKEN_WIRE_VERSION);
        write_u32(&mut buf, &mut offset, self.cap_id);
        write_u64(&mut buf, &mut offset, self.ticket_id);
        write_u64(&mut buf, &mut offset, self.object_id);
        write_u32(&mut buf, &mut offset, self.rights.bits());
        write_u32(&mut buf, &mut offset, self.cap_type as u32);
        write_u32(&mut buf, &mut offset, self.owner_pid.0);
        write_u64(&mut buf, &mut offset, self.issued_at);
        write_u64(&mut buf, &mut offset, self.expires_at);
        write_u32(&mut buf, &mut offset, self.flags);
        for word in &self.extra {
            write_u32(&mut buf, &mut offset, *word);
        }
        buf
    }
}

fn write_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 4].copy_from_slice(&bytes);
    *offset += 4;
}

fn write_u64(buf: &mut [u8], offset: &mut usize, value: u64) {
    let bytes = value.to_le_bytes();
    buf[*offset..*offset + 8].copy_from_slice(&bytes);
    *offset += 8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_round_trips_parts() {
        let id = EventId::new(0xCAFE_BABE, 0x1234, 0xABCD);
        assert_eq!(id.parts(), (0xCAFE_BABE, 0x1234, 0xABCD));
        assert_eq!(id.source_pid(), 0xCAFE_BABE);
        assert_eq!(id.channel_seq(), 0x1234);
        assert_eq!(id.msg_seq(), 0xABCD);
    }

    #[test]
    fn typed_arg_round_trip_u32() {
        let value = 0xDEAD_BEEF_u32;
        let mut buf = [0u8; 4];
        assert_eq!(value.encode_into(&mut buf), Ok(4));
        assert_eq!(u32::decode_from(&buf), Ok(value));
    }

    #[test]
    fn typed_arg_round_trip_bytes() {
        let value = *b"oreu";
        let mut buf = [0u8; 4];
        assert_eq!(value.encode_into(&mut buf), Ok(4));
        assert_eq!(<[u8; 4]>::decode_from(&buf), Ok(value));
    }

    #[test]
    fn capability_token_changes_when_context_changes() {
        let mut base = Capability::with_type(
            7,
            11,
            Rights::new(0xAA55),
            CapabilityType::Filesystem,
        );
        base.extra = [0x10, 0x20, 0x30, 0x40];
        let original = base.token_payload();

        let mut changed = base;
        changed.extra[1] ^= 1;
        assert_ne!(original, changed.token_payload());

        changed = base;
        changed.rights = Rights::new(0xAA54);
        assert_ne!(original, changed.token_payload());
    }
}
