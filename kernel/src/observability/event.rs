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

//! Versioned runtime event schema.

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const EVENT_PAYLOAD_BYTES: usize = 48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventLevel {
    Info = 1,
    Warn = 2,
    Error = 3,
    InvariantViolation = 4,
}

impl EventLevel {
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Subsystem {
    Core = 0,
    Scheduler = 1,
    Syscall = 2,
    Mmu = 3,
    TrapVector = 4,
    Dtb = 5,
    Capability = 6,
    Security = 7,
    Invariant = 8,
    Failure = 9,
    Observability = 10,
}

impl Subsystem {
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventType {
    Generic = 0,
    SchedulerBoundary = 1,
    SyscallBoundary = 2,
    MmuBoundary = 3,
    TrapBoundary = 4,
    DtbBoundary = 5,
    SecurityViolation = 6,
    InvariantViolation = 7,
    FailurePolicyAction = 8,
    TerminalFailure = 9,
}

impl EventType {
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy)]
pub struct EventRecord {
    pub schema_version: u16,
    pub timestamp: u64,
    pub subsystem: Subsystem,
    pub level: EventLevel,
    pub event_type: EventType,
    pub code: u16,
    pub payload_len: u8,
    pub payload: [u8; EVENT_PAYLOAD_BYTES],
}

impl EventRecord {
    pub const fn empty() -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            timestamp: 0,
            subsystem: Subsystem::Core,
            level: EventLevel::Info,
            event_type: EventType::Generic,
            code: 0,
            payload_len: 0,
            payload: [0; EVENT_PAYLOAD_BYTES],
        }
    }

    #[inline]
    pub fn with_payload(mut self, payload: &[u8]) -> Self {
        let len = payload.len().min(EVENT_PAYLOAD_BYTES);
        self.payload[..len].copy_from_slice(&payload[..len]);
        self.payload_len = len as u8;
        self
    }
}