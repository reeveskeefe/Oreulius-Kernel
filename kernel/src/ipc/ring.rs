use super::errors::IpcError;
use super::message::Message;
use super::types::CHANNEL_CAPACITY;

/// A bounded ring buffer for messages.
#[derive(Clone, Copy)]
pub(crate) struct RingBuffer {
    buffer: [Option<Message>; CHANNEL_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}

impl RingBuffer {
    pub(crate) const fn new() -> Self {
        RingBuffer {
            buffer: [None; CHANNEL_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub(crate) fn is_full(&self) -> bool {
        self.count >= CHANNEL_CAPACITY
    }

    pub(crate) fn push(&mut self, msg: Message) -> Result<(), IpcError> {
        if self.is_full() {
            return Err(IpcError::WouldBlock);
        }

        self.buffer[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % CHANNEL_CAPACITY;
        self.count += 1;
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<Message> {
        if self.is_empty() {
            return None;
        }

        let msg = self.buffer[self.head].take();
        self.head = (self.head + 1) % CHANNEL_CAPACITY;
        self.count -= 1;
        msg
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }

    pub(crate) fn clear(&mut self) {
        self.buffer = [None; CHANNEL_CAPACITY];
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}
