# `kernel/src/temporal` — Versioned State & Temporal Object System

## Purpose

The `temporal` module is Oreulia's **kernel-level version control system for live OS state**. Every kernel object that matters — IPC channels, TCP sockets, processes, capability tokens, the scheduler, the service registry, security policies, CapNet, WASM service pointers, and more — can be tracked as a *temporal object*, receiving a discrete, immutable, content-addressed version every time its state changes.

This is not journalling. It is not crash recovery alone. The temporal system provides a **branching, mergeable, rollback-capable audit trail** over all kernel-managed state, enforced at the object level, so that any moment in the history of the operating system can be reconstructed with mathematical integrity guarantees, without ever touching external storage APIs.

The design principles follow from category theory: states are objects, transitions are morphisms, and the functor composition law `F(f ∘ g) = F(f) ∘ F(g)` is formally enforced via `TemporalFunctor::verify_composition_law`. Any violation is a hard error, not a warning.

---

## Why This Exists in the Kernel (Not Userspace)

Temporal tracking must reside in the kernel because:

1. **Every kernel object transition must be observable.** Capability grants, revocations, socket events, process spawns and terminations — these are trust-boundary crossings that cannot be left unwitnessed.
2. **Integrity must be tamper-evident.** Each version carries a Merkle root derived from FNV-1a hashes computed by dedicated assembly routines (`temporal_asm.rs`). No userspace process can retroactively alter a committed version chain.
3. **Rollback must be atomic.** If a partially-applied configuration change corrupts IPC state, restoring a prior snapshot cannot involve user-level coordination. The temporal engine controls the revert entirely inside Ring-0.
4. **Zero heap allocation per fast path.** The global store uses a `Mutex`-wrapped flat array pool — no `Vec`/`BTreeMap` growth, no dealloc panics from the `LockedBumpAllocator`.

---

## Source Layout

| File | Role |
|---|---|
| `mod.rs` | Core engine: `TemporalObject` pool, versioning, branching, rollback, merge, GC, all global `record_*` and `read_*` functions. |
| `persistence.rs` | Append-only log and snapshot serialization/deserialization with binary format versioning (v1 / v2 / v3). Drives replay-based recovery on boot. |
| `temporal_asm.rs` | Platform assembly bindings for `fnv1a32`, `temporal_hash_pair`, `temporal_merkle_root_u32`, with pure-Rust `aarch64` fallbacks. |

---

## Core Capacity Constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_TEMPORAL_OBJECTS` | `128` | Total object keys tracked simultaneously |
| `MAX_VERSIONS_PER_OBJECT` | `64` | Maximum retained history depth per object |
| `MAX_TEMPORAL_VERSION_BYTES` | `256 KiB` | Maximum payload size per version |
| `MERKLE_CHUNK_BYTES` | `64` | Bytes per Merkle leaf before hashing |
| `TEMPORAL_HASH_SEED` | `0x811C9DC5` | FNV-1a offset basis |
| `MAX_BRANCHES_PER_OBJECT` | `32` | Concurrent branches per tracked object |
| `MAX_BRANCH_NAME_BYTES` | `48` | Branch name string limit |

---

## Tracked Object Types

Every kernel subsystem registers a typed object kind. The discriminant is a `u8` tag stored in each version header.

| Constant | Tag | Object Scope |
|---|---|---|
| `TEMPORAL_SOCKET_OBJECT_TCP_CONN` | `1` | Per-connection TCP socket |
| `TEMPORAL_SOCKET_OBJECT_TCP_LISTENER` | `2` | TCP listener socket |
| `TEMPORAL_CHANNEL_OBJECT` | `3` | IPC channel |
| `TEMPORAL_PROCESS_OBJECT` | `4` | Process lifecycle |
| `TEMPORAL_CAPABILITY_OBJECT` | `5` | Capability token |
| `TEMPORAL_REGISTRY_OBJECT` | `6` | Service registry entry |
| `TEMPORAL_CONSOLE_OBJECT` | `7` | Console stream |
| `TEMPORAL_SECURITY_OBJECT` | `8` | Intent policy |
| `TEMPORAL_CAPNET_OBJECT` | `9` | CapNet peer state |
| `TEMPORAL_WASM_SERVICE_POINTER_OBJECT` | `10` | WASM service pointer |
| `TEMPORAL_NETWORK_CONFIG_OBJECT` | `11` | Network configuration |
| `TEMPORAL_WASM_SYSCALL_MODULE_TABLE_OBJECT` | `12` | WASM syscall module table |
| `TEMPORAL_SCHEDULER_OBJECT` | `13` | Scheduler state |
| `TEMPORAL_REPLAY_MANAGER_OBJECT` | `14` | Replay manager |
| `TEMPORAL_NETWORK_LEGACY_OBJECT` | `15` | Legacy network layer |
| `TEMPORAL_WIFI_OBJECT` | `16` | Wi-Fi state |
| `TEMPORAL_ENCLAVE_OBJECT` | `17` | SGX enclave state |

---

## Key Public Types

### `TemporalVersionMeta`
Metadata attached to every committed version. Immutable after write.

| Field | Type | Description |
|---|---|---|
| `version_id` | `u64` | Monotonically increasing version number |
| `parent_version_id` | `Option<u64>` | Previous version on this branch |
| `rollback_from_version_id` | `Option<u64>` | If this was a rollback, the reverted version |
| `branch_id` | `u32` | Which branch this version belongs to |
| `tick` | `u64` | Kernel scheduler tick at commit time |
| `data_len` | `usize` | Byte count of the payload |
| `content_hash` | `u32` | FNV-1a hash of raw payload bytes |
| `merkle_root` | `u32` | Root of the Merkle tree over `MERKLE_CHUNK_BYTES` leaves |
| `integrity_tag` | `u64` | Combined tamper-detection tag |
| `operation` | `TemporalOperation` | The action that created this version |

### `TemporalOperation`
```rust
pub enum TemporalOperation { Snapshot, Write, Rollback, Merge }
```

### `TemporalMergeStrategy`
```rust
pub enum TemporalMergeStrategy { FastForwardOnly, Ours, Theirs }
```

---

## Primary API Surface

### Recording State Changes
All `record_*` functions are thin wrappers over the internal engine. They obtain the global store lock, locate or create the object's version chain, compute the Merkle root via `temporal_asm`, and commit a new `TemporalVersionEntry`.

| Function | Scope |
|---|---|
| `record_object_event(key, obj_type, event_type, payload)` | Generic single event |
| `record_object_write(key, payload)` | Raw write version |
| `record_object_snapshot(key, payload)` | Full snapshot |
| `record_tcp_socket_listener_event(...)` | TCP listener lifecycle |
| `record_tcp_socket_state_event(...)` | TCP connection state machine |
| `record_tcp_socket_data_event(...)` | TCP data transfer |
| `record_ipc_channel_event(...)` | IPC channel send/recv/close |
| `record_process_event(pid, event_type, payload)` | Process spawn/terminate |
| `record_capability_event(pid, cap_type, object_id, event_type, payload)` | Capability grant/revoke |
| `record_registry_service_event(...)` | Service registration |
| `record_console_event(object_id, event_type, payload)` | Console create/state |
| `record_intent_policy_event(payload)` | Security intent policy change |
| `record_scheduler_state_event(payload)` | Scheduler state snapshot |

### Reading State History

| Function | Returns |
|---|---|
| `read_version(path, version_id)` | `Result<Vec<u8>, TemporalError>` — raw payload of a specific version |
| `list_versions(path)` | `Result<Vec<TemporalVersionMeta>, TemporalError>` |
| `latest_version(path)` | `Result<TemporalVersionMeta, TemporalError>` |
| `history_window(path, start, end)` | Versions within a tick range |

### Rollback & Branching

| Function | Description |
|---|---|
| `rollback_path(path, target_version_id)` | Resets an object to a previous version, creating a new `Rollback` version |
| `create_branch(path, branch_name, from_version_id)` | Forks the version history at a given version |
| `list_branches(path)` | Returns all `TemporalBranchInfo` for an object |
| `checkout_branch(path, branch_name)` | Switches the active branch head |
| `merge_branch(path, source, target, strategy)` | Merges branch history using the specified `TemporalMergeStrategy` |

### Garbage Collection & Retention

| Function | Description |
|---|---|
| `stats()` | Returns `TemporalStats` — total objects, versions, bytes used |
| `set_retention_policy(max_versions, max_bytes)` | Configures GC watermarks |
| `gc_for_persistence_budget()` | Runs one GC pass, returns `(versions_dropped, bytes_freed)` |

---

## Persistence Layer (`persistence.rs`)

The persistence submodule implements an **append-only binary log** with snapshot compaction. Persistence records are written sequentially to an in-kernel log buffer. On boot, the replay engine reads back the log and re-instantiates all living temporal objects, providing crash recovery without a traditional filesystem.

The binary format has evolved across three versions:

| Version | Magic | Changes |
|---|---|---|
| v1 | `0x54505354` ("TPST") | Initial layout |
| v2 | `0x54505354` | Added Merkle root field |
| v3 | `0x54505354` | Added integrity tag and v3 sentinel |

The module includes backward-compat decode paths for v2 → v3 and v1 → v2 snapshot promotion, tested by `hardening_v2_decode_compat_self_check()`.

---

## Assembly Backend (`temporal_asm.rs`)

Hashing performance is critical because every version commit recomputes the Merkle tree. The assembly layer provides direct bindings to:

| Function | Description |
|---|---|
| `fnv1a32(data, seed)` | FNV-1a 32-bit hash over an arbitrary byte slice |
| `temporal_hash_pair(left, right)` | Combines two 32-bit hashes into one (Merkle node) |
| `temporal_merkle_root_u32(words, count)` | Full Merkle root computation over a word array |
| `temporal_copy_bytes` / `temporal_zero_bytes` | SIMD-friendly bulk memory operations |

On `aarch64`, pure-Rust fallbacks replace the assembly bindings since the Oreulia `aarch64-virt` target does not ship the `temporal.S` assembly file.

---

## Self-Check Tests

The module ships an extensive suite of in-kernel self-check functions exercised at build time and during boot smoke tests:

| Function | What It Verifies |
|---|---|
| `vfs_fd_capture_self_check()` | VFS file descriptor capture and round-trip |
| `object_scope_self_check()` | Per-object isolation between separate temporal keys |
| `persistence_recovery_self_check()` | Full serialize → crash → replay → verify round-trip |
| `branch_merge_self_check()` | Branch create, diverge, merge under all three strategies |
| `audit_emission_self_check()` | Audit event emission and retrieval |
| `hardening_v2_decode_compat_self_check()` | v2 snapshot downgrade and decode compatibility |
| `hardening_integrity_tamper_self_check()` | Tamper detection (modified payload detected) |
| `hardening_deterministic_merge_self_check()` | Merge idempotency and determinism |
