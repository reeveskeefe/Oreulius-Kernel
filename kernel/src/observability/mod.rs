/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

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