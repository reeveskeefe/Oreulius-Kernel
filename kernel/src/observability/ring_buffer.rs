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

//! Lock-free overwrite-safe event ring buffer.

use crate::observability::event::{
    EventLevel, EventRecord, EventType, Subsystem, EVENT_PAYLOAD_BYTES, EVENT_SCHEMA_VERSION,
};
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU8, AtomicUsize, Ordering};

const RING_CAPACITY: usize = 256;
const INVALID_SEQ: usize = usize::MAX;

#[repr(transparent)]
pub struct AtomicU8Byte(AtomicU8);

impl AtomicU8Byte {
    pub const fn new(value: u8) -> Self {
        Self(AtomicU8::new(value))
    }

    #[inline]
    pub fn store(&self, value: u8) {
        self.0.store(value, Ordering::SeqCst);
    }

    #[inline]
    pub fn load(&self) -> u8 {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct AtomicEventSlot {
    seq: AtomicUsize,
    schema_version: AtomicU16,
    timestamp: AtomicUsize,
    subsystem: AtomicU8,
    level: AtomicU8,
    event_type: AtomicU8,
    payload_len: AtomicU8,
    code: AtomicU16,
    payload: [AtomicU8Byte; EVENT_PAYLOAD_BYTES],
}

impl AtomicEventSlot {
    const fn new() -> Self {
        Self {
            seq: AtomicUsize::new(INVALID_SEQ),
            schema_version: AtomicU16::new(EVENT_SCHEMA_VERSION),
            timestamp: AtomicUsize::new(0),
            subsystem: AtomicU8::new(Subsystem::Core as u8),
            level: AtomicU8::new(EventLevel::Info as u8),
            event_type: AtomicU8::new(EventType::Generic as u8),
            payload_len: AtomicU8::new(0),
            code: AtomicU16::new(0),
            payload: {
                const Z: AtomicU8Byte = AtomicU8Byte::new(0);
                [Z; EVENT_PAYLOAD_BYTES]
            },
        }
    }

    fn write(&self, seq: usize, record: &EventRecord) {
        self.seq.store(INVALID_SEQ, Ordering::SeqCst);
        self.schema_version
            .store(record.schema_version, Ordering::SeqCst);
        self.timestamp.store(record.timestamp as usize, Ordering::SeqCst);
        self.subsystem
            .store(record.subsystem.to_u8(), Ordering::SeqCst);
        self.level.store(record.level.to_u8(), Ordering::SeqCst);
        self.event_type
            .store(record.event_type.to_u8(), Ordering::SeqCst);
        self.code.store(record.code, Ordering::SeqCst);
        self.payload_len.store(record.payload_len, Ordering::SeqCst);
        for idx in 0..EVENT_PAYLOAD_BYTES {
            self.payload[idx].store(record.payload[idx]);
        }
        self.seq.store(seq, Ordering::SeqCst);
    }

    fn snapshot_if_seq(&self, expected_seq: usize) -> Option<EventRecord> {
        let seq_before = self.seq.load(Ordering::SeqCst);
        if seq_before != expected_seq {
            return None;
        }
        let mut out = EventRecord::empty();
        out.schema_version = self.schema_version.load(Ordering::SeqCst);
        out.timestamp = self.timestamp.load(Ordering::SeqCst) as u64;
        out.subsystem = decode_subsystem(self.subsystem.load(Ordering::SeqCst));
        out.level = decode_level(self.level.load(Ordering::SeqCst));
        out.event_type = decode_event_type(self.event_type.load(Ordering::SeqCst));
        out.code = self.code.load(Ordering::SeqCst);
        out.payload_len = self.payload_len.load(Ordering::SeqCst).min(EVENT_PAYLOAD_BYTES as u8);
        for idx in 0..EVENT_PAYLOAD_BYTES {
            out.payload[idx] = self.payload[idx].load();
        }
        let seq_after = self.seq.load(Ordering::SeqCst);
        if seq_after == expected_seq {
            Some(out)
        } else {
            None
        }
    }
}

static EVENT_RING: [AtomicEventSlot; RING_CAPACITY] = {
    const SLOT: AtomicEventSlot = AtomicEventSlot::new();
    [SLOT; RING_CAPACITY]
};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static WRITE_SEQ: AtomicUsize = AtomicUsize::new(0);
static OVERWRITE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[inline]
pub fn mark_initialized() {
    INITIALIZED.store(true, Ordering::SeqCst);
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

#[inline]
pub fn write(record: &EventRecord) {
    let seq = WRITE_SEQ.fetch_add(1, Ordering::SeqCst);
    if seq >= RING_CAPACITY {
        OVERWRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    let idx = seq & (RING_CAPACITY - 1);
    EVENT_RING[idx].write(seq, record);
}

pub fn latest_snapshot() -> Option<EventRecord> {
    let write_seq = WRITE_SEQ.load(Ordering::SeqCst);
    if write_seq == 0 {
        return None;
    }
    let latest = write_seq.wrapping_sub(1);
    let idx = latest & (RING_CAPACITY - 1);
    EVENT_RING[idx].snapshot_if_seq(latest)
}

pub fn snapshot_seq(seq: usize) -> Option<EventRecord> {
    let write_seq = WRITE_SEQ.load(Ordering::SeqCst);
    if write_seq == 0 || seq >= write_seq {
        return None;
    }
    if write_seq > RING_CAPACITY && seq < write_seq - RING_CAPACITY {
        return None;
    }
    let idx = seq & (RING_CAPACITY - 1);
    EVENT_RING[idx].snapshot_if_seq(seq)
}

#[inline]
pub fn overwrite_count() -> usize {
    OVERWRITE_COUNT.load(Ordering::Relaxed)
}

#[inline]
pub fn write_count() -> usize {
    WRITE_SEQ.load(Ordering::Relaxed)
}

fn decode_level(raw: u8) -> EventLevel {
    match raw {
        2 => EventLevel::Warn,
        3 => EventLevel::Error,
        4 => EventLevel::InvariantViolation,
        _ => EventLevel::Info,
    }
}

fn decode_subsystem(raw: u8) -> Subsystem {
    match raw {
        1 => Subsystem::Scheduler,
        2 => Subsystem::Syscall,
        3 => Subsystem::Mmu,
        4 => Subsystem::TrapVector,
        5 => Subsystem::Dtb,
        6 => Subsystem::Capability,
        7 => Subsystem::Security,
        8 => Subsystem::Invariant,
        9 => Subsystem::Failure,
        10 => Subsystem::Observability,
        _ => Subsystem::Core,
    }
}

fn decode_event_type(raw: u8) -> EventType {
    match raw {
        1 => EventType::SchedulerBoundary,
        2 => EventType::SyscallBoundary,
        3 => EventType::MmuBoundary,
        4 => EventType::TrapBoundary,
        5 => EventType::DtbBoundary,
        6 => EventType::SecurityViolation,
        7 => EventType::InvariantViolation,
        8 => EventType::FailurePolicyAction,
        9 => EventType::TerminalFailure,
        _ => EventType::Generic,
    }
}