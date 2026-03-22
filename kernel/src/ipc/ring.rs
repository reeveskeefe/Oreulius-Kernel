use super::errors::IpcError;
use super::message::Message;
use super::types::CHANNEL_CAPACITY;
use alloc::collections::VecDeque;

/// A bounded ring buffer for messages.
pub(crate) struct RingBuffer {
    buffer: VecDeque<Message>,
}

impl RingBuffer {
    pub(crate) fn new() -> Self {
        RingBuffer {
            buffer: VecDeque::with_capacity(CHANNEL_CAPACITY),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.buffer.len() >= CHANNEL_CAPACITY
    }

    pub(crate) fn push(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.is_full() {
            return Err(IpcError::WouldBlock);
        }

        self.buffer.push_back(msg);
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Message> {
        self.buffer.pop_front()
    }

    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
    }
}
