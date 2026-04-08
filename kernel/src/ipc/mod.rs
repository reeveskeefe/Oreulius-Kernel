/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Oreulius IPC v0
//!
//! Channel-based inter-process communication with capability transfer.
//!
//! Key principles:
//! - Channels are kernel objects with Send/Receive rights
//! - Messages carry data + capabilities
//! - Bounded queues make backpressure explicit
//! - No shared memory - only message passing
//!
//! Implementation note:
//! - This module root is now the IPC facade.
//! - Core implementation lives in `kernel/src/ipc/channel.rs`,
//!   `kernel/src/ipc/table.rs`, and `kernel/src/ipc/service.rs`.
//! - Supporting policy, diagnostics, message, rights, and ring logic live in
//!   sibling files under `kernel/src/ipc/`.

#![allow(dead_code)]

mod admission;
mod backpressure;
mod channel;
mod diagnostics;
mod errors;
mod message;
mod rights;
mod ring;
mod selftest;
mod service;
mod table;
mod types;

#[cfg(test)]
use ring::RingBuffer;

pub use admission::{IpcDefer, IpcRefusal, RecvDecision, SendDecision};
pub use backpressure::{BackpressureAction, BackpressureLevel, BackpressureSnapshot};
pub use channel::{Channel, ChannelFlags, ClosureState, DrainResult};
pub use diagnostics::{ChannelDiagnostics, IpcDiagnostics};
pub use errors::IpcError;
pub use message::Message;
pub use rights::{AffineEndpoint, ChannelCapability, ChannelRights};
pub use selftest::{run_selftest, IpcSelftestCase, IpcSelftestReport, IPC_SELFTEST_CASES};
pub use service::{
    close_channel, close_channel_for_process, create_channel, create_channel_for_process,
    create_channel_for_process_with_flags, init, ipc, purge_channels_for_process, receive_message,
    receive_message_for_process, receive_message_with_caps_for_process, send_message,
    send_message_for_process, send_message_with_caps_for_process, temporal_apply_channel_event,
    temporal_apply_channel_payload, IpcService,
};
pub use table::ChannelTable;
pub use types::{
    Capability, CapabilityType, ChannelId, EventId, ProcessId, TypedServiceArg, CHANNEL_CAPACITY,
    MAX_CAPS_PER_MESSAGE, MAX_CHANNELS, MAX_MESSAGE_SIZE,
};

const IPC_WAIT_KIND_MESSAGE: usize = 0x1;
const IPC_WAIT_KIND_CAPACITY: usize = 0x2;

const fn channel_wait_addr(id: ChannelId, kind: usize) -> usize {
    ((id.0 as usize) << 2) | kind
}

const fn channel_message_wait_addr(id: ChannelId) -> usize {
    channel_wait_addr(id, IPC_WAIT_KIND_MESSAGE)
}

const fn channel_capacity_wait_addr(id: ChannelId) -> usize {
    channel_wait_addr(id, IPC_WAIT_KIND_CAPACITY)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::process::ProcessState;

    struct SchedulerResetGuard;

    impl SchedulerResetGuard {
        fn new() -> Self {
            crate::scheduler::quantum_scheduler::test_reset();
            SchedulerResetGuard
        }
    }

    impl Drop for SchedulerResetGuard {
        fn drop(&mut self) {
            crate::scheduler::quantum_scheduler::test_reset();
        }
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::with_data(ProcessId::new(1), b"hello").unwrap();
        assert_eq!(msg.payload(), b"hello");
        assert_eq!(msg.caps_len, 0);
    }

    #[test]
    fn test_ring_buffer() {
        let mut buffer = RingBuffer::new();
        assert!(buffer.is_empty());

        let msg = Message::new(ProcessId::new(1));
        buffer.push(msg).unwrap();
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);

        let _ = buffer.pop().unwrap();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_channel_send_recv() {
        let id = ChannelId::new(1);
        let mut channel = Channel::new(id, ProcessId::new(1));

        let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), ProcessId::new(1));

        let recv_cap =
            ChannelCapability::new(2, id, ChannelRights::receive_only(), ProcessId::new(1));

        let msg = Message::with_data(ProcessId::new(1), b"test").unwrap();
        channel.send(msg, &send_cap).unwrap();

        let received = channel.try_recv(&recv_cap).unwrap();
        assert_eq!(received.payload(), b"test");
    }

    #[test]
    fn test_runtime_selftest_report() {
        let report = run_selftest();
        assert_eq!(report.passed, report.total);
    }

    #[test]
    fn test_service_recv_falls_back_without_scheduler_context() {
        let service = IpcService::new();
        let (_send_cap, recv_cap) = service.create_channel(ProcessId::new(42)).unwrap();
        assert!(matches!(service.recv(&recv_cap), Err(IpcError::WouldBlock)));
    }

    #[test]
    fn test_service_send_falls_back_without_scheduler_context() {
        let service = IpcService::new();
        let (send_cap, _recv_cap) = service.create_channel(ProcessId::new(43)).unwrap();

        for _ in 0..CHANNEL_CAPACITY {
            let msg = Message::with_data(ProcessId::new(43), b"x").unwrap();
            service.send(msg, &send_cap).unwrap();
        }

        let msg = Message::with_data(ProcessId::new(43), b"overflow").unwrap();
        assert!(matches!(
            service.send(msg, &send_cap),
            Err(IpcError::WouldBlock)
        ));
    }

    #[test]
    fn test_send_wakes_waiting_receiver() {
        let _guard = SchedulerResetGuard::new();
        crate::scheduler::quantum_scheduler::test_add_process(1, "ipc-recv").unwrap();
        crate::scheduler::quantum_scheduler::test_add_process(2, "ipc-send").unwrap();

        let id = ChannelId::new(77);
        let owner = ProcessId::new(50);
        let mut channel = Channel::new(id, owner);
        let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), owner);

        crate::scheduler::quantum_scheduler::test_stage_waiter(
            1,
            channel.message_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.message_wait_addr()),
            1
        );

        let msg = Message::with_data(owner, b"wake").unwrap();
        channel.send(msg, &send_cap).unwrap();

        assert_eq!(channel.receiver_wakeups(), 1);
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.message_wait_addr()),
            0
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(1),
            Some(ProcessState::Ready)
        );
    }

    #[test]
    fn test_recv_wakes_waiting_sender() {
        let _guard = SchedulerResetGuard::new();
        crate::scheduler::quantum_scheduler::test_add_process(3, "ipc-send").unwrap();
        crate::scheduler::quantum_scheduler::test_add_process(4, "ipc-recv").unwrap();

        let id = ChannelId::new(78);
        let owner = ProcessId::new(51);
        let mut channel = Channel::new(id, owner);
        let send_cap = ChannelCapability::new(1, id, ChannelRights::send_only(), owner);
        let recv_cap = ChannelCapability::new(2, id, ChannelRights::receive_only(), owner);

        for _ in 0..CHANNEL_CAPACITY {
            let msg = Message::with_data(owner, b"x").unwrap();
            channel.send(msg, &send_cap).unwrap();
        }

        crate::scheduler::quantum_scheduler::test_stage_waiter(
            3,
            channel.capacity_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.capacity_wait_addr()),
            1
        );

        let _ = channel.try_recv(&recv_cap).unwrap();

        assert_eq!(channel.sender_wakeups(), 1);
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.capacity_wait_addr()),
            0
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(3),
            Some(ProcessState::Ready)
        );
    }

    #[test]
    fn test_close_wakes_all_waiters() {
        let _guard = SchedulerResetGuard::new();
        crate::scheduler::quantum_scheduler::test_add_process(5, "ipc-rx-a").unwrap();
        crate::scheduler::quantum_scheduler::test_add_process(6, "ipc-rx-b").unwrap();
        crate::scheduler::quantum_scheduler::test_add_process(7, "ipc-tx-a").unwrap();
        crate::scheduler::quantum_scheduler::test_add_process(8, "ipc-tx-b").unwrap();

        let id = ChannelId::new(79);
        let owner = ProcessId::new(52);
        let mut channel = Channel::new(id, owner);
        let close_cap = ChannelCapability::new(3, id, ChannelRights::full(), owner);

        crate::scheduler::quantum_scheduler::test_stage_waiter(
            5,
            channel.message_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();
        crate::scheduler::quantum_scheduler::test_stage_waiter(
            6,
            channel.message_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();
        crate::scheduler::quantum_scheduler::test_stage_waiter(
            7,
            channel.capacity_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();
        crate::scheduler::quantum_scheduler::test_stage_waiter(
            8,
            channel.capacity_wait_addr(),
            ProcessState::WaitingOnChannel,
        )
        .unwrap();

        channel.close(&close_cap).unwrap();

        assert_eq!(channel.receiver_wakeups(), 2);
        assert_eq!(channel.sender_wakeups(), 2);
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.message_wait_addr()),
            0
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::waiter_count(channel.capacity_wait_addr()),
            0
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(5),
            Some(ProcessState::Ready)
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(6),
            Some(ProcessState::Ready)
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(7),
            Some(ProcessState::Ready)
        );
        assert_eq!(
            crate::scheduler::quantum_scheduler::test_process_state(8),
            Some(ProcessState::Ready)
        );
    }
}
