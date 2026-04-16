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


use super::{backpressure, Channel, ChannelCapability, Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcRefusal {
    PredictiveRestriction,
    PermissionDenied,
    InvalidCapability,
    ProtocolMismatch,
    Closed,
    /// Channel is in `Draining` state: close initiated, messages still in flight.
    /// Distinguishable from `Closed` (fully sealed) so callers can adapt.
    ChannelDraining,
    Backpressure,
    QueueFull,
    QueueEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcDefer {
    WaitForCapacity,
    WaitForMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendDecision {
    Commit,
    Refuse(IpcRefusal),
    Defer(IpcDefer),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvDecision {
    Deliver,
    Refuse(IpcRefusal),
    Defer(IpcDefer),
}

pub(crate) fn evaluate_send(
    channel: &Channel,
    capability: &ChannelCapability,
    msg: &Message,
) -> SendDecision {
    let sec = crate::security::security();
    if sec.is_predictively_restricted(
        capability.owner,
        crate::capability::CapabilityType::Channel,
        crate::capability::Rights::CHANNEL_SEND,
    ) {
        return SendDecision::Refuse(IpcRefusal::PredictiveRestriction);
    }

    if !capability.can_send() {
        return SendDecision::Refuse(IpcRefusal::PermissionDenied);
    }

    if capability.channel_id != channel.id {
        return SendDecision::Refuse(IpcRefusal::InvalidCapability);
    }

    if channel.validate_temporal_send(msg).is_err() {
        return SendDecision::Refuse(IpcRefusal::ProtocolMismatch);
    }

    if channel.closure.is_closed() {
        return SendDecision::Refuse(IpcRefusal::Closed);
    }
    if channel.closure.is_closing() {
        return SendDecision::Refuse(IpcRefusal::ChannelDraining);
    }

    if let Some(decision) = backpressure::send_decision(channel) {
        return decision;
    }

    SendDecision::Commit
}

pub(crate) fn evaluate_recv(channel: &Channel, capability: &ChannelCapability) -> RecvDecision {
    let sec = crate::security::security();
    if sec.is_predictively_restricted(
        capability.owner,
        crate::capability::CapabilityType::Channel,
        crate::capability::Rights::CHANNEL_RECEIVE,
    ) {
        return RecvDecision::Refuse(IpcRefusal::PredictiveRestriction);
    }

    if !capability.can_receive() {
        return RecvDecision::Refuse(IpcRefusal::PermissionDenied);
    }

    if capability.channel_id != channel.id {
        return RecvDecision::Refuse(IpcRefusal::InvalidCapability);
    }

    if channel.closure.is_closed() && channel.buffer.is_empty() {
        return RecvDecision::Refuse(IpcRefusal::Closed);
    }

    if channel.buffer.is_empty() {
        return RecvDecision::Defer(IpcDefer::WaitForMessage);
    }

    RecvDecision::Deliver
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ChannelFlags, ChannelId, ChannelRights, ProcessId};
    use std::thread;

    fn run_on_large_stack<F>(f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let _serial = crate::test_serial_lock().lock().unwrap();
        thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn reliable_full_channel_defers_send() {
        run_on_large_stack(|| {
            let id = ChannelId::new(100);
            let owner = ProcessId::new(1);
            let mut channel = Channel::new(id, owner);
            let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), owner);
            for _ in 0..crate::ipc::CHANNEL_CAPACITY {
                let msg = crate::ipc::Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }
            let msg = crate::ipc::Message::with_data(owner, b"x").unwrap();
            assert_eq!(
                evaluate_send(&channel, &send_cap, &msg),
                SendDecision::Defer(IpcDefer::WaitForCapacity)
            );
        });
    }

    #[test]
    fn async_full_channel_refuses_send() {
        run_on_large_stack(|| {
            let id = ChannelId::new(101);
            let owner = ProcessId::new(2);
            let mut channel = Channel::new_with_flags(
                id,
                owner,
                ChannelFlags::new(
                    ChannelFlags::BOUNDED | ChannelFlags::ASYNC | ChannelFlags::HIGH_PRIORITY,
                ),
                128,
            );
            let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), owner);
            for _ in 0..crate::ipc::CHANNEL_CAPACITY {
                let msg = crate::ipc::Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }
            let msg = crate::ipc::Message::with_data(owner, b"x").unwrap();
            assert_eq!(
                evaluate_send(&channel, &send_cap, &msg),
                SendDecision::Refuse(IpcRefusal::QueueFull)
            );
        });
    }

    #[test]
    fn empty_channel_defers_recv() {
        run_on_large_stack(|| {
            let id = ChannelId::new(102);
            let owner = ProcessId::new(3);
            let channel = Channel::new(id, owner);
            let recv_cap = ChannelCapability::new(1, id, ChannelRights::receive_only(), owner);
            assert_eq!(
                evaluate_recv(&channel, &recv_cap),
                RecvDecision::Defer(IpcDefer::WaitForMessage)
            );
        });
    }
}
