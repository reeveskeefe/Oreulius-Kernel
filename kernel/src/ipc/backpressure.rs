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


use super::{Channel, IpcDefer, IpcRefusal, SendDecision, CHANNEL_CAPACITY};

const HIGH_PRESSURE_NUMERATOR: usize = 3;
const HIGH_PRESSURE_DENOMINATOR: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureLevel {
    Idle,
    Available,
    High,
    Saturated,
}

impl BackpressureLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackpressureLevel::Idle => "idle",
            BackpressureLevel::Available => "available",
            BackpressureLevel::High => "high",
            BackpressureLevel::Saturated => "saturated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureAction {
    Commit,
    Defer,
    Refuse,
}

impl BackpressureAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackpressureAction::Commit => "commit",
            BackpressureAction::Defer => "defer",
            BackpressureAction::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackpressureSnapshot {
    pub pending: usize,
    pub capacity: usize,
    pub high_watermark: usize,
    pub high_pressure_hits: u32,
    pub saturated_hits: u32,
    pub level: BackpressureLevel,
    pub recommended_action: BackpressureAction,
}

pub(crate) fn observe_send_attempt(channel: &mut Channel) -> BackpressureLevel {
    let level = level(channel);
    match level {
        BackpressureLevel::High => {
            channel.high_pressure_hits = channel.high_pressure_hits.saturating_add(1);
        }
        BackpressureLevel::Saturated => {
            channel.saturated_hits = channel.saturated_hits.saturating_add(1);
        }
        BackpressureLevel::Idle | BackpressureLevel::Available => {}
    }
    level
}

pub(crate) fn send_decision(channel: &Channel) -> Option<SendDecision> {
    match recommended_send_action(channel) {
        BackpressureAction::Commit => None,
        BackpressureAction::Defer => Some(SendDecision::Defer(IpcDefer::WaitForCapacity)),
        BackpressureAction::Refuse => Some(SendDecision::Refuse(if channel.buffer.is_full() {
            IpcRefusal::QueueFull
        } else {
            IpcRefusal::Backpressure
        })),
    }
}

pub(crate) fn recommended_send_action(channel: &Channel) -> BackpressureAction {
    match level(channel) {
        BackpressureLevel::Idle | BackpressureLevel::Available => BackpressureAction::Commit,
        BackpressureLevel::High => {
            if channel.flags.is_async()
                && channel.flags.is_bounded()
                && !channel.flags.is_high_priority()
            {
                BackpressureAction::Refuse
            } else {
                BackpressureAction::Commit
            }
        }
        BackpressureLevel::Saturated => {
            if channel.flags.is_async() {
                BackpressureAction::Refuse
            } else {
                BackpressureAction::Defer
            }
        }
    }
}

pub(crate) fn level(channel: &Channel) -> BackpressureLevel {
    let pending = channel.buffer.len();
    if pending == 0 {
        return BackpressureLevel::Idle;
    }
    if channel.buffer.is_full() {
        return BackpressureLevel::Saturated;
    }
    if pending >= high_pressure_threshold() {
        return BackpressureLevel::High;
    }
    BackpressureLevel::Available
}

pub(crate) fn snapshot(channel: &Channel) -> BackpressureSnapshot {
    BackpressureSnapshot {
        pending: channel.buffer.len(),
        capacity: CHANNEL_CAPACITY,
        high_watermark: channel.high_watermark,
        high_pressure_hits: channel.high_pressure_hits,
        saturated_hits: channel.saturated_hits,
        level: level(channel),
        recommended_action: recommended_send_action(channel),
    }
}

const fn high_pressure_threshold() -> usize {
    let threshold = (CHANNEL_CAPACITY * HIGH_PRESSURE_NUMERATOR) / HIGH_PRESSURE_DENOMINATOR;
    if threshold == 0 {
        1
    } else {
        threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ChannelFlags, ChannelId, ChannelRights, Message, ProcessId};
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
    fn pressure_level_tracks_thresholds() {
        run_on_large_stack(|| {
            let id = ChannelId::new(200);
            let owner = ProcessId::new(1);
            let mut channel = Channel::new(id, owner);
            let send_cap =
                crate::ipc::ChannelCapability::new(1, id, ChannelRights::send_only(), owner);

            assert_eq!(level(&channel), BackpressureLevel::Idle);

            let msg = Message::with_data(owner, b"a").unwrap();
            channel.send(msg, &send_cap).unwrap();
            assert_eq!(level(&channel), BackpressureLevel::Available);

            while channel.pending() < high_pressure_threshold() {
                let msg = Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }
            assert_eq!(level(&channel), BackpressureLevel::High);
        });
    }

    #[test]
    fn async_mode_refuses_full_channel() {
        run_on_large_stack(|| {
            let id = ChannelId::new(201);
            let owner = ProcessId::new(2);
            let mut channel = Channel::new_with_flags(
                id,
                owner,
                ChannelFlags::new(
                    ChannelFlags::BOUNDED | ChannelFlags::ASYNC | ChannelFlags::HIGH_PRIORITY,
                ),
                128,
            );
            let send_cap =
                crate::ipc::ChannelCapability::new(1, id, ChannelRights::send_only(), owner);

            while !channel.is_full() {
                let msg = Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }

            assert_eq!(
                send_decision(&channel),
                Some(SendDecision::Refuse(IpcRefusal::QueueFull))
            );
        });
    }

    #[test]
    fn async_mode_refuses_at_high_pressure_before_saturation() {
        run_on_large_stack(|| {
            let id = ChannelId::new(203);
            let owner = ProcessId::new(4);
            let mut channel = Channel::new_with_flags(
                id,
                owner,
                ChannelFlags::new(ChannelFlags::BOUNDED | ChannelFlags::ASYNC),
                128,
            );
            let send_cap =
                crate::ipc::ChannelCapability::new(1, id, ChannelRights::send_only(), owner);

            while level(&channel) != BackpressureLevel::High {
                let msg = Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }

            assert!(!channel.is_full());
            assert_eq!(
                recommended_send_action(&channel),
                BackpressureAction::Refuse
            );
            assert_eq!(
                send_decision(&channel),
                Some(SendDecision::Refuse(IpcRefusal::Backpressure))
            );
        });
    }

    #[test]
    fn observed_send_attempts_track_pressure_hits() {
        run_on_large_stack(|| {
            let id = ChannelId::new(202);
            let owner = ProcessId::new(3);
            let mut channel = Channel::new(id, owner);
            let send_cap =
                crate::ipc::ChannelCapability::new(1, id, ChannelRights::send_only(), owner);

            while level(&channel) != BackpressureLevel::High {
                let msg = Message::with_data(owner, b"x").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }

            let msg = Message::with_data(owner, b"y").unwrap();
            channel.send(msg, &send_cap).unwrap();
            assert!(channel.high_pressure_hits() > 0);

            while !channel.is_full() {
                let msg = Message::with_data(owner, b"z").unwrap();
                channel.send(msg, &send_cap).unwrap();
            }

            let overflow = Message::with_data(owner, b"!").unwrap();
            assert!(matches!(
                channel.send(overflow, &send_cap),
                Err(crate::ipc::IpcError::WouldBlock)
            ));
            assert!(channel.saturated_hits() > 0);
        });
    }
}
