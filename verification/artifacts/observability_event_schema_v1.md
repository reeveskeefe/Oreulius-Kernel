# Observability Event Schema v1

Status: Active runtime artifact

This document defines the versioned runtime event contract for kernel
observability events emitted by the Phase 1A substrate.

## Contract

- Schema version: `1`
- Source: [kernel/src/observability/event.rs](kernel/src/observability/event.rs)
- Ring transport: [kernel/src/observability/ring_buffer.rs](kernel/src/observability/ring_buffer.rs)
- Logger API: [kernel/src/observability/logger.rs](kernel/src/observability/logger.rs)

## Event Record Fields

- `schema_version: u16`
- `timestamp: u64`
- `subsystem: u8`
- `level: u8`
- `event_type: u8`
- `code: u16`
- `payload_len: u8`
- `payload: [u8; 48]`

## Release Observability Floor

Release builds must preserve at least these event classes:

- `SecurityViolation`
- `InvariantViolation`
- `TerminalFailure`

Additionally, runtime must maintain:

- terminal failure reason code
- security violation counter
- invariant violation counter
- terminal failure counter

Source: [kernel/src/observability/logger.rs](kernel/src/observability/logger.rs)

## Notes

- This schema is part of the proof-runtime traceability surface.
- Any field layout or semantics changes require a new schema version document.