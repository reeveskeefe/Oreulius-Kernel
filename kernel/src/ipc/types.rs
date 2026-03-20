use crate::security::security;

/// Marker trait for values that may be passed as typed service arguments over
/// IPC channels.
pub trait TypedServiceArg: Send {
    /// Stable runtime tag identifying this argument type.
    /// Values 0x0000-0x00FF are reserved for kernel primitives.
    fn type_tag() -> u32
    where
        Self: Sized;
}

impl TypedServiceArg for u8 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0001
    }
}

impl TypedServiceArg for u32 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0004
    }
}

impl TypedServiceArg for u64 {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0008
    }
}

impl<const N: usize> TypedServiceArg for [u8; N] {
    #[inline(always)]
    fn type_tag() -> u32 {
        0x0100 | (N as u32 & 0xFFFF)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// The raw u64 value (for embedding into `AuditEntry::context`).
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Generic capability (simplified for v0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub cap_id: u32,
    pub object_id: u32,
    pub rights: u32,
    pub cap_type: CapabilityType,
    /// Extra data (e.g. filesystem metadata).
    pub extra: [u32; 4],
    /// Cryptographic token (SipHash-2-4 MAC).
    pub token: u64,
}

impl Capability {
    pub fn new(cap_id: u32, object_id: u32, rights: u32) -> Self {
        Capability {
            cap_id,
            object_id,
            rights,
            cap_type: CapabilityType::Generic,
            extra: [0; 4],
            token: 0,
        }
    }

    pub fn with_type(cap_id: u32, object_id: u32, rights: u32, cap_type: CapabilityType) -> Self {
        Capability {
            cap_id,
            object_id,
            rights,
            cap_type,
            extra: [0; 4],
            token: 0,
        }
    }

    pub fn sign(&mut self) {
        let payload = self.token_payload();
        self.token = security().cap_token_sign(&payload);
    }

    pub fn verify(&self) -> bool {
        let payload = self.token_payload();
        security().cap_token_verify(&payload, self.token)
    }

    fn token_payload(&self) -> [u8; 40] {
        const TOKEN_CONTEXT: u32 = 0x4F43_4150; // "OCAP"
        let mut buf = [0u8; 40];
        let mut offset = 0usize;
        write_u32(&mut buf, &mut offset, TOKEN_CONTEXT);
        write_u32(&mut buf, &mut offset, self.cap_id);
        write_u32(&mut buf, &mut offset, self.object_id);
        write_u32(&mut buf, &mut offset, self.rights);
        write_u32(&mut buf, &mut offset, self.cap_type as u32);
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
