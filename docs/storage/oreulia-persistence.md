# Oreulius - Persistence (Logs, Snapshots, Recovery)

**Status:** Implemented / Core (updated for current main)

This document describes the persistence subsystem that exists today in
`kernel/src/temporal/persistence.rs`.

The old description of Oreulius as a generic "append-only durable log with
replay-based recovery for everything" is no longer accurate. The current design
is more specific:

- there is still a bounded append-only log API
- the durable recovery path is snapshot-oriented
- the persistence layer primarily serves the temporal store, VFS state, and
  generic kernel snapshot consumers
- snapshot durability includes on-disk versioning and integrity protection

Related documents:

- `docs/storage/oreulius-filesystem.md`
- `docs/storage/oreulius-temporal-adapters-durable-persistence.md`
- `kernel/src/temporal/README.md`

---

## 1. What exists today

Oreulius currently exposes one global `PersistenceService` with four pieces of
state:

- an in-memory append log
- a generic snapshot slot
- a dedicated temporal snapshot slot
- a dedicated VFS snapshot slot

This gives the kernel two different persistence modes:

1. **Append-only records** for bounded event capture and service-level use.
2. **Durable snapshots** for boot-time recovery of important kernel state.

That distinction matters:

- the append log exists and is capability-gated
- the durable boot recovery path currently restores snapshots, not a full
  durable write-ahead log of every kernel event

---

## 2. Authority model

Persistence access is gated by `StoreCapability` and `StoreRights`.

Current store rights are:

| Right | Meaning |
|---|---|
| `APPEND_LOG` | Append a record to the in-memory log |
| `READ_LOG` | Read records back from the in-memory log |
| `WRITE_SNAPSHOT` | Write snapshot bytes |
| `READ_SNAPSHOT` | Read snapshot bytes |

The current convenience shell/service paths often construct a full-rights
capability for testing or internal service use, but the persistence layer
itself checks rights on every entrypoint and returns `PermissionDenied` if the
required right is absent.

---

## 3. Append-only log

### 3.1 Purpose

The append log is a bounded in-memory record stream used by the persistence
service and related command/service surfaces.

Current hard bounds:

- `MAX_RECORD_SIZE = 64 KiB`
- `MAX_LOG_RECORDS = 64` on legacy x86
- `MAX_LOG_RECORDS = 1024` on non-x86 targets

### 3.2 Record structure

Each record consists of:

- `RecordHeader`
  - `magic = 0x4F524555` (`"OREU"`)
  - `version = 1`
  - `record_type`
  - `len`
- payload bytes
- `crc32`

The CRC is checked on verification and is used for local corruption detection.

### 3.3 Current record taxonomy

The current `RecordType` set includes:

- external clock input
- console input
- generic component event
- supervisor checkpoint
- filesystem operation
- crash report
- OTA update event
- boot event
- attestation record
- health snapshot

### 3.4 Current limitation

The append log is **not** currently the main durable boot-recovery engine. It is
a bounded service API and internal substrate, but the actual recovery path on
startup is snapshot-based.

So the correct description today is:

- **append-only log API exists**
- **durable snapshot recovery exists**
- **full log-replay crash recovery for all kernel state is not the current
  system boundary**

---

## 4. Snapshot model

### 4.1 Snapshot object

Each snapshot currently stores:

- raw bytes
- `data_len`
- `last_offset`
- `timestamp`

`last_offset` links the snapshot back to the log position visible at the time of
capture, but the recovery path is still snapshot-first.

### 4.2 Snapshot classes

The current persistence service tracks three durable snapshot classes:

| Slot | Purpose |
|---|---|
| generic | general snapshot payloads |
| temporal | serialized temporal object store |
| VFS | serialized VFS state |

This is why the persistence subsystem now sits under the temporal layer in
practice: the temporal store and VFS are first-class persistence consumers.

---

## 5. Durable snapshot formats

### 5.1 On-disk framing

Durable snapshots use the on-disk magic:

- `SNAPSHOT_DISK_MAGIC = "ORSP"`

The current disk header format has two versions:

- `v1`
- `v2`

The persistence layer includes decode paths for both.

### 5.2 v1 header

The v1 header stores:

- magic
- version
- slot id
- data length
- last offset
- timestamp
- CRC32

### 5.3 v2 header

The v2 header extends this with:

- flags
- nonce
- 16-byte MAC field

Current v2 flags include:

- sealed
- encrypted

### 5.4 Integrity and confidentiality

Current durable snapshot protection is materially stronger than the old doc
claimed.

The snapshot path now uses:

- AES-128 CTR for payload encryption
- HMAC-SHA256-derived authentication material for integrity
- a monotonic snapshot nonce that is reseeded and advanced across recovery

This means the persistence layer is not just CRC-based append logging anymore.
Durable snapshots are sealed, versioned blobs with explicit integrity failure
reporting (`IntegrityMismatch`).

---

## 6. Backends and write order

### 6.1 Available backend classes

The current persistence code can write/read snapshots through three backend
styles:

- **virtio-blk reserved disk slots**
- **external snapshot backend** registered through `register_snapshot_backend`
- **file fallback** through internal VFS paths for selected slots

### 6.2 Reserved disk slots

When virtio block is present, snapshot slots are placed at reserved LBAs near
the end of the disk image. The current slot layout is:

- generic slot
- temporal slot
- VFS slot

Each slot is sector-aligned and bounded by `MAX_SNAPSHOT_SIZE`.

### 6.3 Fallback behavior

The current implementation does not use one identical fallback chain for every
slot.

#### Generic snapshot

Generic snapshot writes use:

1. disk
2. external backend
3. file fallback

#### Temporal snapshot

Temporal snapshot writes prefer:

1. disk
2. external backend

They intentionally avoid the file fallback on this path because temporal writes
may happen while the caller already holds VFS state, and the file fallback would
re-enter VFS.

#### VFS snapshot

VFS snapshot writes also use the preferred durable path:

1. disk
2. external backend

No file fallback is used there either.

---

## 7. Boot-time recovery

Persistence recovery happens during `persistence::init()`.

The current boot sequence does the following:

1. seed the snapshot nonce
2. attempt durable snapshot recovery
3. expose the recovered snapshot state to consumers

### 7.1 What gets recovered

If a durable backend is available, the service attempts to recover:

- generic snapshot
- temporal snapshot
- VFS snapshot

### 7.2 Recovery gating

This path is intentionally gated. Recovery is only attempted automatically when
one of these is available:

- `virtio_blk`
- an externally registered snapshot backend

That means the presence of the file fallback helpers does **not** imply
unconditional file-backed recovery on every boot path.

### 7.3 Recovery semantics

The service performs recovery only once per boot via
`durable_recovery_attempted`, preventing repeated backend probing or duplicate
restores.

---

## 8. Error model

The current persistence error surface is:

| Error | Meaning |
|---|---|
| `RecordTooLarge` | append payload exceeded `MAX_RECORD_SIZE` |
| `LogFull` | bounded append log is out of slots |
| `SnapshotTooLarge` | snapshot exceeded `MAX_SNAPSHOT_SIZE` |
| `PermissionDenied` | missing store right |
| `InvalidRecord` | malformed durable record/header |
| `CrcMismatch` | CRC check failed |
| `IntegrityMismatch` | cryptographic snapshot integrity validation failed |
| `BackendUnavailable` | durable backend not present |

This is another place where the older doc was stale: the real implementation
has an explicit cryptographic integrity-failure state now, not just generic log
corruption language.

---

## 9. Temporal and VFS integration

Persistence is now tightly coupled to the temporal subsystem and VFS rather than
being a standalone "future storage service."

Current integration points:

- temporal object store serialization uses the dedicated temporal snapshot slot
- VFS serialization uses the dedicated VFS snapshot slot
- temporal hardening and recovery self-checks explicitly validate persistence
  behavior

Relevant current verification surfaces include:

- `temporal-hardening-selftest`
- `persistence_recovery_self_check()`
- the temporal IPC and branch/merge self-check family

For the broader universal-object and adapter model, see:

- `docs/storage/oreulius-temporal-adapters-durable-persistence.md`

---

## 10. What this document does not claim

This document deliberately does **not** claim that Oreulius currently has:

- a universal durable write-ahead log for every kernel subsystem
- exactly-once replay of all persisted records
- production-grade compaction/retention for the append log
- non-QEMU physical hardware validation of the persistence path
- arbitrary filesystem journaling semantics independent of the temporal store

The accurate current boundary is narrower and stronger:

- bounded append-log API
- durable sealed snapshot persistence
- boot-time recovery for generic, temporal, and VFS snapshot state
- explicit backend fallback behavior
- active hardening around decode compatibility and integrity failures
