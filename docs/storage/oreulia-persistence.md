# Oreulia — Persistence (Logs, Snapshots, Recovery)

**Status:** Implemented / Core (Feb 8, 2026)

Oreulia is **persistence-first**: durable state is a core OS concern, not just a property of the filesystem.

This document specifies the persistence model based on:
- Append-only logs
- Log-structured storage
- Deterministic replay support

---

## 1. Goals

- **Crash Recovery**: The system can recover its state by replaying logs from the last snapshot.
- **Determinism**: By logging external inputs (network packets, user input), execution can be replayed for debugging.
- **Simplicity**: Using a log-structured approach simplifies consistency (no complex locking needed for atomicity).

---

## 2. Core Durable Primitives

### 2.1 Append-Only Log

The primary storage abstraction is a **Log**.
- **Sequential**: Data is always written to the end.
- **Immutable**: Once written, data cannot be modified in place.
- **Capability-Gated**: A process needs `Append` rights to write to a log.

### 2.2 Snapshot

A snapshot is a point-in-time image of a component's state.
- **Optimization**: To avoid replaying infinite logs, components periodically serialize their state to a snapshot.
- **Recovery**: On boot/restart, a component loads the latest snapshot and then replays valid log entries after it.

---

## 3. Authority Model

Persistence is managed by the kernel and exposed via capabilities.

- `LogCapability`: Represents a handle to a specific append-only stream.
- `SnapshotCapability`: Represents a handle to a storage blob for state images.

---

## 4. Record Structure

Log records follow a robust format to ensure data integrity:

```rust
struct LogRecord {
    magic: u32,       // 0xDEADBEEF
    version: u16,     // 1
    type_id: u16,     // Event Type (Input, Net, Timer)
    length: u32,      // Payload Length
    checksum: u32,    // CRC32 of payload
    payload: [u8],    // Data
}
```

This structure allows the kernel to identify corruption and truncate logs safely during recovery.


1. Supervisor obtains `Store.ReadSnapshot` and `Store.ReadLog`.
2. Supervisor loads the latest snapshot.
3. Supervisor replays log records from `last_offset`.
4. Supervisor reconstructs component graph and resumes.

### 5.2 Replay semantics

v0 replay is **at-least-once** at the record level.

To make this workable, components should:

- design event handlers to be idempotent, or
- keep a replay cursor/sequence number in durable state.

v1 can evolve toward exactly-once semantics with stronger constraints.

See also: `docs/oreulia-mvp.md` → “Risks & mitigations” for the MVP impact of at-least-once replay.

See also: `docs/oreulia-filesystem.md` for how the filesystem service uses logs/snapshots for durable file storage.

---

## 6. Determinism integration

Determinism record/replay uses the same persistence substrate.

### 6.1 What gets recorded (MVP)

- clock reads (or periodic ticks)
- console input (optional)

### 6.2 How replay works

- In record mode, `Clock` service reads from hardware timer and appends records.
- In replay mode, `Clock` service reads from the log and returns recorded values.

This makes nondeterminism explicit and replayable.

---

## 7. Storage backends

### 7.1 RAM-backed (bring-up)

- easiest early implementation
- persistence does not survive reboot
- still useful to validate APIs and replay flow

### 7.2 Virtio block (QEMU)

- target backend for “real” persistence in QEMU
- implement a simple block allocator for log + snapshot regions

---

## 8. Compaction and retention (later)

v0 can ignore compaction.

v1 goals:

- periodic snapshot
- truncate log before snapshot point
- retention policies

---

## 9. Open questions

- Do we use one global system log or per-component logs?
- Do snapshots live beside logs or in a separate namespace?
- How do we enforce storage quotas (capabilities with limits)?
