use core::fmt;

use super::errors::IpcError;
use super::types::{
    Capability, ProcessId, MAX_CAPS_PER_MESSAGE, MAX_MESSAGE_SIZE,
};

/// A message sent through a channel.
#[derive(Clone, Copy)]
pub struct Message {
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
    /// Create a new empty message.
    pub fn new(source: ProcessId) -> Self {
        Message {
            payload: [0u8; MAX_MESSAGE_SIZE],
            payload_len: 0,
            caps: [None; MAX_CAPS_PER_MESSAGE],
            caps_len: 0,
            source,
        }
    }

    /// Create a message with data.
    pub fn with_data(source: ProcessId, data: &[u8]) -> Result<Self, IpcError> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge);
        }

        let mut msg = Message::new(source);
        msg.payload[..data.len()].copy_from_slice(data);
        msg.payload_len = data.len();
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
            .field("payload_len", &self.payload_len)
            .field("caps_len", &self.caps_len)
            .field("source", &self.source)
            .finish()
    }
}
