/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Structured logger backed by the observability ring buffer.

use crate::observability::event::{
    EventLevel, EventRecord, EventType, Subsystem, EVENT_PAYLOAD_BYTES, EVENT_SCHEMA_VERSION,
};
use crate::observability::ring_buffer;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

static SECURITY_VIOLATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static INVARIANT_VIOLATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static TERMINAL_FAILURE_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_TERMINAL_FAILURE_CODE: AtomicU16 = AtomicU16::new(0);

pub struct ObservabilityCounters {
    pub security_violations: usize,
    pub invariant_violations: usize,
    pub terminal_failures: usize,
    pub last_terminal_failure_code: u16,
}

impl ObservabilityCounters {
    pub fn snapshot() -> Self {
        Self {
            security_violations: SECURITY_VIOLATION_COUNT.load(Ordering::Relaxed),
            invariant_violations: INVARIANT_VIOLATION_COUNT.load(Ordering::Relaxed),
            terminal_failures: TERMINAL_FAILURE_COUNT.load(Ordering::Relaxed),
            last_terminal_failure_code: LAST_TERMINAL_FAILURE_CODE.load(Ordering::Relaxed),
        }
    }
}

struct PayloadBuf {
    data: [u8; EVENT_PAYLOAD_BYTES],
    len: usize,
}

impl PayloadBuf {
    fn new() -> Self {
        Self {
            data: [0; EVENT_PAYLOAD_BYTES],
            len: 0,
        }
    }
}

impl Write for PayloadBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let available = EVENT_PAYLOAD_BYTES.saturating_sub(self.len);
        if available == 0 {
            return Ok(());
        }
        let copy_len = bytes.len().min(available);
        self.data[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
        self.len += copy_len;
        Ok(())
    }
}

#[inline]
pub fn emit_structured(
    level: EventLevel,
    subsystem: Subsystem,
    event_type: EventType,
    code: u16,
    payload: &[u8],
) {
    update_floor_counters(event_type, code);
    if !should_emit(level, event_type) {
        return;
    }
    let record = EventRecord {
        schema_version: EVENT_SCHEMA_VERSION,
        timestamp: monotonic_timestamp(),
        subsystem,
        level,
        event_type,
        code,
        payload_len: payload.len().min(EVENT_PAYLOAD_BYTES) as u8,
        payload: {
            let mut p = [0u8; EVENT_PAYLOAD_BYTES];
            let copy_len = payload.len().min(EVENT_PAYLOAD_BYTES);
            p[..copy_len].copy_from_slice(&payload[..copy_len]);
            p
        },
    };
    ring_buffer::write(&record);
}

#[inline]
pub fn emit_fmt(
    level: EventLevel,
    subsystem: Subsystem,
    event_type: EventType,
    code: u16,
    args: fmt::Arguments,
) {
    let mut payload = PayloadBuf::new();
    let _ = payload.write_fmt(args);
    emit_structured(level, subsystem, event_type, code, &payload.data[..payload.len]);
}

#[inline]
pub fn log_info(subsystem: Subsystem, event_type: EventType, code: u16, args: fmt::Arguments) {
    emit_fmt(EventLevel::Info, subsystem, event_type, code, args);
}

#[inline]
pub fn log_warn(subsystem: Subsystem, event_type: EventType, code: u16, args: fmt::Arguments) {
    emit_fmt(EventLevel::Warn, subsystem, event_type, code, args);
}

#[inline]
pub fn log_error(subsystem: Subsystem, event_type: EventType, code: u16, args: fmt::Arguments) {
    emit_fmt(EventLevel::Error, subsystem, event_type, code, args);
}

#[inline]
pub fn log_invariant_violation(subsystem: Subsystem, code: u16, args: fmt::Arguments) {
    emit_fmt(
        EventLevel::InvariantViolation,
        subsystem,
        EventType::InvariantViolation,
        code,
        args,
    );
}

#[inline]
pub fn mark_terminal_failure(code: u16, subsystem: Subsystem, args: fmt::Arguments) {
    emit_fmt(
        EventLevel::Error,
        subsystem,
        EventType::TerminalFailure,
        code,
        args,
    );
}

#[inline]
fn should_emit(level: EventLevel, event_type: EventType) -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    // Minimum release observability floor for production forensics.
    matches!(
        event_type,
        EventType::SecurityViolation | EventType::InvariantViolation | EventType::TerminalFailure
    ) || matches!(level, EventLevel::Warn | EventLevel::Error | EventLevel::InvariantViolation)
}

fn update_floor_counters(event_type: EventType, code: u16) {
    match event_type {
        EventType::SecurityViolation => {
            SECURITY_VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        EventType::InvariantViolation => {
            INVARIANT_VIOLATION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        EventType::TerminalFailure => {
            TERMINAL_FAILURE_COUNT.fetch_add(1, Ordering::Relaxed);
            LAST_TERMINAL_FAILURE_CODE.store(code, Ordering::Relaxed);
        }
        _ => {}
    }
}

#[inline]
fn monotonic_timestamp() -> u64 {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::scheduler::pit::get_ticks() as u64
    }
    #[cfg(target_arch = "aarch64")]
    {
        0
    }
}

#[macro_export]
macro_rules! log_info {
    ($subsystem:expr, $event_type:expr, $code:expr, $($arg:tt)*) => {
        $crate::observability::logger::log_info($subsystem, $event_type, $code, format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        $crate::observability::logger::log_info(
            $crate::observability::Subsystem::Core,
            $crate::observability::EventType::Generic,
            0,
            format_args!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! log_warn {
    ($subsystem:expr, $event_type:expr, $code:expr, $($arg:tt)*) => {
        $crate::observability::logger::log_warn($subsystem, $event_type, $code, format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        $crate::observability::logger::log_warn(
            $crate::observability::Subsystem::Core,
            $crate::observability::EventType::Generic,
            0,
            format_args!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! log_error {
    ($subsystem:expr, $event_type:expr, $code:expr, $($arg:tt)*) => {
        $crate::observability::logger::log_error($subsystem, $event_type, $code, format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        $crate::observability::logger::log_error(
            $crate::observability::Subsystem::Core,
            $crate::observability::EventType::Generic,
            0,
            format_args!($($arg)*)
        )
    };
}

#[macro_export]
macro_rules! log_invariant_violation {
    ($subsystem:expr, $code:expr, $($arg:tt)*) => {
        $crate::observability::logger::log_invariant_violation($subsystem, $code, format_args!($($arg)*))
    };
    ($($arg:tt)*) => {
        $crate::observability::logger::log_invariant_violation(
            $crate::observability::Subsystem::Invariant,
            0,
            format_args!($($arg)*)
        )
    };
}