# Oreulia — Persistence (Logs, Snapshots, Recovery)

**Status:** Draft (Jan 24, 2026)

Oreulia is persistence-first: durable state is a core OS concern.

This document specifies a v0 persistence model based on:

- append-only logs
- periodic snapshots
- replay-based recovery

---

## 1. Goals

- Provide a minimal durable substrate for:
  - crash recovery
  - determinism record/replay
  - auditability
- Keep v0 simple enough to implement early.
- Keep the model compatible with capability-based authority.

Non-goals (v0):

- general-purpose POSIX filesystem
- distributed replication
- complex transactional semantics

---

## 2. Core durable primitives

### 2.1 Append-only log

A log is an ordered sequence of records.

Operations (capability-gated):

- `AppendLog(record) -> offset`
- `ReadLog(from_offset, max_bytes) -> records`

Constraints (v0):

- records are bytes with a small header
- maximum record size (e.g., 64 KiB)

### 2.2 Snapshot

A snapshot is a point-in-time state image associated with a log.

Operations:

- `WriteSnapshot(bytes, last_offset)`
- `ReadSnapshot() -> (bytes, last_offset)`

---

## 3. Authority model

Persistence is provided by a service (user space) with capabilities.

### 3.1 Capabilities

- `Store.AppendLog`
- `Store.ReadLog`
- `Store.WriteSnapshot`
- `Store.ReadSnapshot`

Optional refinements:

- per-log capabilities (each log is a different object)
- quota-limited capabilities

---

## 4. Record structure (v0)

A log record format (suggested):

- `magic` (u32)
- `version` (u16)
- `type` (u16)
- `len` (u32)
- `payload` (bytes)
- `crc32` (u32)

Record `type` examples:

- `ExternalInput.ClockRead`
- `ExternalInput.ConsoleIn`
- `Component.Event`
- `Supervisor.Checkpoint`

---

## 5. Recovery model

### 5.1 Boot flow

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
