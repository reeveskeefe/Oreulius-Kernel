use crate::capability::Rights;
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

/// IPC capability transfer envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub cap_id: u32,
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
