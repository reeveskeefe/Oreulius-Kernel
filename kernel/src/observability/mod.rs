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

//! Kernel observability substrate.
//!
//! Phase 1A provides the versioned event contract, interrupt-safe ring storage,
//! and logger entry points. Phase 1B wires subsystem boundary emitters.

pub mod event;
pub mod logger;
pub mod ring_buffer;
#[cfg(test)]
pub mod test_helpers;

pub use event::{
    EventLevel, EventRecord, EventType, Subsystem, EVENT_PAYLOAD_BYTES, EVENT_SCHEMA_VERSION,
};
#[cfg(test)]
pub use test_helpers::assert_closure_chain_closure;

#[inline]
pub fn init() {
    ring_buffer::mark_initialized();
}

#[inline]
pub fn emit_scheduler_boundary(event_type: EventType, code: u16, payload: &[u8]) {
    logger::emit_structured(EventLevel::Info, Subsystem::Scheduler, event_type, code, payload);
}

#[inline]
pub fn emit_syscall_boundary(event_type: EventType, code: u16, payload: &[u8]) {
    logger::emit_structured(EventLevel::Info, Subsystem::Syscall, event_type, code, payload);
}

#[inline]
pub fn emit_mmu_boundary(event_type: EventType, code: u16, payload: &[u8]) {
    logger::emit_structured(EventLevel::Info, Subsystem::Mmu, event_type, code, payload);
}

#[inline]
pub fn emit_trap_boundary(event_type: EventType, code: u16, payload: &[u8]) {
    logger::emit_structured(EventLevel::Info, Subsystem::TrapVector, event_type, code, payload);
}

#[inline]
pub fn emit_dtb_boundary(event_type: EventType, code: u16, payload: &[u8]) {
    logger::emit_structured(EventLevel::Info, Subsystem::Dtb, event_type, code, payload);
}