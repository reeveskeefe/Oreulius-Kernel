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

    pub(crate) fn peek(&self) -> Option<Message> {
        self.buffer.front().copied()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Message> + '_ {
        self.buffer.iter().copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
    }
}
