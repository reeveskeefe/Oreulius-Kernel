use core::fmt;

use super::errors::IpcError;
use super::types::{Capability, EventId, ProcessId, MAX_CAPS_PER_MESSAGE, MAX_MESSAGE_SIZE};

/// Per-channel message sequence counter — wraps at u16 max.
/// Updated atomically inside `Message::with_id`.
///
/// In the current single-CPU kernel this is a plain cell; on SMP it would
/// need to be an `AtomicU16`.
static mut MSG_SEQ: u16 = 0;

#[inline]
fn next_msg_seq() -> u16 {
    // SAFETY: single-threaded kernel; no concurrent mutation.
    unsafe {
        let v = MSG_SEQ;
        MSG_SEQ = MSG_SEQ.wrapping_add(1);
        v
    }
}

/// A message sent through a channel.
#[derive(Clone, Copy)]
pub struct Message {
    /// Unique identifier for this message (Def A.7 — causal event identity).
    pub id: EventId,
    /// Causal predecessor — the `id` of the message that triggered this one,
    /// or `None` for root (causally unlinked) messages.
    pub cause: Option<EventId>,
    /// Message payload data.
    pub payload: [u8; MAX_MESSAGE_SIZE],
    /// Actual payload length.
    pub payload_len: usize,
    /// Capabilities being transferred.
    pub caps: [Option<Capability>; MAX_CAPS_PER_MESSAGE],
    /// Number of capabilities.
    pub caps_len: usize,
    /// Source process ID.
    pub source: ProcessId,
}

impl Message {
    /// Create a new empty message with a fresh causal identity and no cause.
    pub fn new(source: ProcessId) -> Self {
        let seq = next_msg_seq();
        Message {
            id: EventId::new(source.0, 0, seq),
            cause: None,
            payload: [0u8; MAX_MESSAGE_SIZE],
            payload_len: 0,
            caps: [None; MAX_CAPS_PER_MESSAGE],
            caps_len: 0,
            source,
        }
    }

    /// Create a message with data and no causal predecessor.
    pub fn with_data(source: ProcessId, data: &[u8]) -> Result<Self, IpcError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge);
        }

        let mut msg = Message::new(source);
        msg.payload[..data.len()].copy_from_slice(data);
        msg.payload_len = data.len();
        Ok(msg)
    }

    /// Create a message that is causally linked to `predecessor`.
    ///
    /// Use this when the message is a direct response to or consequence of
    /// a previously received message, to allow causal chain reconstruction.
    pub fn with_cause(source: ProcessId, cause: EventId) -> Self {
        let mut msg = Message::new(source);
        msg.cause = Some(cause);
        msg
    }

    /// Create a message with data that is causally linked to `predecessor`.
    pub fn with_data_and_cause(
        source: ProcessId,
        data: &[u8],
        cause: EventId,
    ) -> Result<Self, IpcError> {
        let mut msg = Message::with_data(source, data)?;
        msg.cause = Some(cause);
        Ok(msg)
    }

    /// Add a capability to this message.
    pub fn add_capability(&mut self, cap: Capability) -> Result<(), IpcError> {
        if self.caps_len >= MAX_CAPS_PER_MESSAGE {
            return Err(IpcError::TooManyCaps);
        }

        let mut signed = cap;
        signed.sign();
        self.caps[self.caps_len] = Some(signed);
        self.caps_len += 1;
        Ok(())
    }

    /// Get the payload as a slice.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// Get the capabilities.
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.caps[..self.caps_len].iter().filter_map(|c| c.as_ref())
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("cause", &self.cause)
            .field("payload_len", &self.payload_len)
            .field("caps_len", &self.caps_len)
            .field("source", &self.source)
            .finish()
    }
}
