# Oreulia — Temporal Objects: Universal Adapter Coverage + Durable Persistence

**Status:** Implemented / Universal Coverage for Current Kernel Object Classes (Feb 16, 2026)

Oreulia’s **Temporal Objects** subsystem turns mutable kernel state into an explicit, versioned history:

- Every temporal object is keyed by a canonical path (e.g. `/data/file`, `/socket/tcp/conn/7`, `/enclave/state`).
- Each write/snapshot/rollback/merge produces an **immutable version** with metadata and an integrity hash.
- **Branching and merging** are first-class, Git-like operations inside the kernel.
- A **universal adapter layer** makes non-file kernel object classes (sockets, IPC, scheduler, WASM runtime tables, replay, WiFi, enclave control-plane state, etc.) participate in the same time-travel semantics without VFS path hacks.
- **Durable persistence** is integrated: the temporal store periodically serializes itself into the persistence subsystem and recovers on boot when a backing store is present.

This document is written to be read by systems engineers. It includes the formal model, payload schemas, adapter architecture, and correctness lemmas with full proofs (relative to stated assumptions and the implemented algorithms).

---

## 1. High-Level Architecture

### 1.1 The Two-Layer Model

Temporal Objects separates concerns into:

1. **Temporal Store (universal, path-keyed, immutable versions)**
   - Records byte payloads under keys.
   - Maintains a per-key version DAG with branch heads.
   - Provides snapshot/read/rollback/branch/merge primitives.
2. **Object Adapters (domain-specific, typed apply)**
   - Encode domain state into a stable byte schema for recording.
   - Decode + apply a historical payload back into the live kernel subsystem.

The adapter layer is what makes the system “universal”: new kernel object classes can plug in by registering an adapter for a key prefix.

### 1.2 State Machine (Kernel-Internal)

```text
                    +-----------------------+
                    |   Live Kernel State  |
                    +-----------+-----------+
                                |
                                | encode + record (write/snapshot)
                                v
 +------------------------------+-------------------------------+
 |                 Temporal Store (path-keyed)                  |
 |  - versions: immutable payload bytes + TemporalVersionMeta   |
 |  - branches: name -> head version                            |
 |  - persistence: encode snapshot to store backend             |
 +----------------------+-------------------------+-------------+
                        |                         |
                        | read/version/history    | recover snapshot
                        v                         v
                 (user/WASM APIs)          (boot-time recovery)
                        |
                        | rollback/checkout/merge => choose version payload
                        v
              +---------+----------+
              | Object Adapter     |
              | (longest-prefix)   |
              +---------+----------+
                        |
                        | apply(payload, mode)
                        v
              +--------------------+
              | Live Kernel State  |
              +--------------------+
```

### 1.3 Call Flow (Rollback / Checkout / Merge)

```text
request(path, version/branch, mode)
  -> TemporalStore.select_payload(path, version/branch)
  -> TemporalStore.apply_temporal_payload_to_object(path, payload, mode)
       -> find_object_adapter(path)  // longest prefix match
       -> TemporalReplayGuard        // prevents recursive re-recording
       -> adapter.apply(path, payload, mode)
             -> decode + validate schema
             -> apply to subsystem (net_reactor/ipc/scheduler/wasm/...)
```

---

## 2. Formal Model

### 2.1 Core Sets and Functions

Let:

- `P` be the set of canonical object paths (strings beginning with `/`).
- For each `p in P`, `V_p` is the finite set of versions stored for `p`.
- Each version `v in V_p` has:
  - `payload(v)` : a byte string in `{0,1}^*`
  - `meta(v)` : a record `TemporalVersionMeta`
- Each object `p` has a finite set of branches `B_p`, each with a name and an optional head.

We model the temporal store as a partial function:

- `Store : P -> ObjectHistory`

where `ObjectHistory` contains:

- a sequence of version entries (bounded),
- a set of branches (bounded),
- and the currently active branch id.

### 2.2 Version Meta Record

Each version entry contains:

```text
meta(v) = (
  version_id: u64,
  parent_version_id: Option<u64>,
  rollback_from_version_id: Option<u64>,
  branch_id: u32,
  tick: u64,
  data_len: usize,
  leaf_count: u32,
  content_hash: u32,
  merkle_root: u32,
  operation: {Snapshot, Write, Rollback, Merge}
)
```

### 2.3 Hard Bounds (Kernel-Enforced)

The temporal store is bounded by compile-time constants:

| Constant | Meaning | Value |
|---|---|---:|
| `MAX_TEMPORAL_OBJECTS` | max distinct keys in the store | 128 |
| `MAX_VERSIONS_PER_OBJECT` | max versions per key | 64 |
| `MAX_TEMPORAL_VERSION_BYTES` | max payload bytes per version | 256 KiB |
| `MAX_BRANCHES_PER_OBJECT` | max branches per key | 32 |
| `MAX_BRANCH_NAME_BYTES` | max branch name length | 48 |
| `MERKLE_CHUNK_BYTES` | payload chunk size for Merkle leaves | 64 |
| `MAX_TEMPORAL_ADAPTERS` | adapter registry slots | 24 |

These are not documentation-level “limits”; they are enforced in the core recording and decoding logic.

---

## 3. Integrity Metadata (Hashes + Merkle Root)

### 3.1 Content Hash

Oreulia uses a 32-bit FNV-1a-style hash (not cryptographic) implemented in `temporal_asm`.

Define:

- `H(data, seed) : {0,1}^* x {0..2^32-1} -> {0..2^32-1}` as the implemented hash.

Then:

- `content_hash(v) = H(payload(v), TEMPORAL_HASH_SEED)`

### 3.2 Merkle Leaf Hashes

Split the payload into chunks:

- `payload = c_0 || c_1 || ... || c_{k-1}`
- where each `c_i` is at most `MERKLE_CHUNK_BYTES` bytes.

Define leaf seeds:

- `seed_i = TEMPORAL_HASH_SEED XOR (i * 0x9E3779B1 mod 2^32)`

Define leaves:

- `leaf_i = H(c_i, seed_i)`

Then:

- `leaf_count(v) = k`

### 3.3 Merkle Root

Let `R(leaves)` be the implemented reduction `temporal_asm::merkle_root` which combines leaves into a single root (pairwise hashing; details are implementation-defined but deterministic).

Then:

- `merkle_root(v) = R([leaf_0, ..., leaf_{k-1}])`

### 3.4 Security Note

FNV-1a and the Merkle construction here provide **fast corruption detection** and stable replay metadata. They do not provide cryptographic tamper-proofing against an adversary with write access to the persistence medium.

---

## 4. Universal Object Adapter Layer

### 4.1 Adapter Definition

An adapter is a function:

```text
apply: (path: &str, payload: &[u8], mode: TemporalRestoreMode) -> Result<(), &'static str>
```

Adapters are registered by path prefix:

- `register_object_adapter(prefix, apply_fn)`

### 4.2 Longest-Prefix Dispatch (Deterministic)

Given a restore target path `p`, the dispatcher selects the adapter `a` with maximal prefix length:

- `a = argmax_{adapter in Registry, p starts_with adapter.prefix} |adapter.prefix|`

This allows a safe fallback adapter for files at prefix `/`, while more specific adapters (e.g. `/socket/tcp/conn/`) override it.

### 4.3 Recursion Guard (No Re-entrancy Recording)

During adapter apply, the kernel enters a “temporal replay” region guarded by `TemporalReplayGuard`. While active:

- `record_object_event(...)` returns `Ok(0)` without recording,

preventing feedback loops where an apply operation would re-trigger capture.

---

## 5. “Universal Coverage” Defined and Proven (Current Kernel Object Classes)

### 5.1 Definition (Kernel Object Class Coverage)

Define the **kernel object class set** `C` for Oreulia as the set of temporal object encodings and/or keys the kernel treats as first-class temporal objects (either typed or file-backed).

In the current kernel, `C` is enumerated by the object type ids in `kernel/src/temporal.rs` and the explicit singleton keys used for subsystem state.

### 5.2 Adapter Coverage Table (All Registered Prefixes)

The adapter registry contains the following prefixes:

| Prefix / Key | Object Class | Encoding ID | Apply Implementation |
|---|---|---:|---|
| `/` | VFS file payloads (raw bytes) | (untyped) | `vfs::write_path_untracked` / `vfs::temporal_try_apply_backend_payload` |
| `/socket/tcp/listener/` | TCP listener events | `2` | `net_reactor::temporal_apply_tcp_listener_event` |
| `/socket/tcp/conn/` | TCP connection events | `1` | `net_reactor::temporal_apply_tcp_connection_event` |
| `/ipc/channel/` | IPC channels | `3` | `ipc::temporal_apply_channel_payload` |
| `/process/` | Process table | `4` | adapter decode + `process::temporal_apply_process_event` |
| `/capability/` | Capability tables | `5` | adapter decode + `capability::temporal_apply_capability_event` |
| `/registry/service/` | Service registry entries | `6` | adapter decode + `registry::temporal_apply_service_event` |
| `/console/object/` | Console objects | `7` | adapter decode + `console_service::temporal_apply_console_event` |
| `/security/intent/policy` | Security intent policy | `8` | `security::temporal_apply_intent_policy` |
| `/capnet/state` | CapNet state | `9` | `capnet::temporal_apply_state_payload` |
| `/wasm/service-pointers` | WASM service pointer registry | `10` | `wasm::temporal_apply_service_pointer_registry_payload` |
| `/network/config` | Net reactor config | `11` | `net_reactor::temporal_apply_network_config_payload` |
| `/wasm/syscall-modules` | WASM syscall module table | `12` | `wasm::temporal_apply_syscall_module_table_payload` |
| `/scheduler/state` | Quantum scheduler runtime state | `13` | `quantum_scheduler::temporal_apply_scheduler_payload` |
| `/replay/state` | Replay manager state | `14` | `replay::temporal_apply_replay_manager_payload` |
| `/network/legacy/state` | Legacy network service state | `15` | `net::temporal_apply_network_service_payload` |
| `/wifi/state` | WiFi driver state | `16` | `wifi::temporal_apply_wifi_driver_payload` |
| `/enclave/state` | Enclave control-plane state | `17` | `enclave::temporal_apply_enclave_state_payload` |

### 5.3 Theorem: Adapter Completeness for Enumerated Classes

**Theorem 1 (Adapter Completeness).** For every object class in `C` as enumerated above, there exists a registered adapter prefix whose apply function can consume the corresponding temporal payloads and restore the live subsystem state (subject to payload validity checks).

**Proof.**

1. The registry is initialized once via `ensure_object_adapters_initialized()` which registers exactly the prefixes listed in Table 5.2.
2. Each prefix registration points to an `apply` function.
3. For typed classes (IDs 1..17 except files), each `apply` function validates:
   - the key (exact match for singleton keys or parsed object id for keyed objects),
   - the encoding version (`TEMPORAL_OBJECT_ENCODING_V1`),
   - the object type id (the class id),
   - and the event/schema markers where applicable.
4. Each `apply` function then calls into the owning subsystem’s `temporal_apply_*` function which assigns the decoded state into the subsystem’s live state variables under a lock or atomic stores.

Therefore each enumerated object class has a concrete adapter restore path. QED.

### 5.4 Corollary: No Path Hacks Required for Non-File Objects

**Corollary 1.** For any non-file temporal key in Table 5.2, restoration is performed via its object-specific adapter, not via the generic VFS file write path.

**Proof.** The generic adapter has prefix `/`. Every non-file key/prefix in Table 5.2 is strictly longer than `/`, and the dispatcher selects the longest matching prefix. Therefore the object-specific adapter is chosen. QED.

---

## 6. Payload Schemas (Selected)

All typed temporal payloads begin with:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | `encoding = TEMPORAL_OBJECT_ENCODING_V1` |
| 1 | 1 | `object_type_id` |
| 2 | 1 | `event` |
| 3 | 1 | `schema` (class-specific) |

File payloads (adapter `/`) are raw file bytes and have no typed header.

### 6.1 Replay Manager (`/replay/state`, type 14)

The replay manager payload captures up to 8 sessions. Transcripts are stored out-of-line as chunk objects.

Header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | encoding |
| 1 | 1 | `14` |
| 2 | 1 | `TEMPORAL_REPLAY_MANAGER_EVENT_STATE` |
| 3 | 1 | `TEMPORAL_REPLAY_SCHEMA_V1` |
| 4 | 2 | `slots` (must be 8) |
| 6 | 2 | reserved |

Per-slot descriptor (40 bytes), repeated `slots` times:

| Field | Type | Meaning |
|---|---|---|
| `present` | `u8` | 0 = empty slot |
| `mode` | `u8` | 0/1/2 = off/record/replay |
| reserved | `u16` | 0 |
| `module_hash` | `u64` | module identity |
| `module_len` | `u32` | module size |
| `cursor` | `u32` | replay cursor |
| `event_hash` | `u64` | transcript hash |
| `event_count` | `u32` | number of events |
| `transcript_len` | `u32` | transcript bytes |
| `chunk_count` | `u16` | number of transcript chunks |
| reserved | `u16` | 0 |

Per-chunk descriptor (16 bytes), repeated `chunk_count` times:

| Field | Type | Meaning |
|---|---|---|
| `chunk_idx` | `u16` | 0.. |
| reserved | `u16` | 0 |
| `chunk_len` | `u32` | bytes in this chunk |
| `version_id` | `u64` | version id of `/replay/transcript/<slot>/<chunk>` |

Transcript chunk keys:

```text
/replay/transcript/<slot>/<chunk>
```

Chunk bytes are recorded as raw payloads under those keys (still bounded by `MAX_TEMPORAL_VERSION_BYTES`), with a per-chunk target size of 240 KiB to keep the replay manager header under the 256 KiB limit.

### 6.2 Legacy Network Service (`/network/legacy/state`, type 15)

Captures the state of the legacy `net.rs` network service (separate from the net reactor’s config/sockets).

Conceptual fields:

| Category | Contents |
|---|---|
| Scalars | wifi enabled, ip/gateway/dns, `next_conn_id` |
| TCP table | fixed-size array, truncated to `tcp_count` |
| DNS cache | fixed-size array, truncated to `dns_count` |

Important invariants:

- `tcp_count <= MAX_CONNECTIONS`
- `dns_count <= MAX_DNS_CACHE`
- Each TCP entry includes a stable `TcpState <-> u8` encoding.

### 6.3 WiFi Driver (`/wifi/state`, type 16)

Captures the kernel WiFi driver control-plane:

- PCI device identity (if present)
- enabled flag
- connection state + network metadata
- scan result list (bounded)
- MAC address

The payload uses fixed-size `WifiNetwork` entries so decode is bounded and allocation-free except for the outer buffer.

### 6.4 Enclave Control-Plane (`/enclave/state`, type 17)

Captures enclave manager state, trustzone contract, certificate chain, provisioned keys, and remote verifier list.

Safety-hardening rule:

- Physical pointers and EPC memory addresses are **not restored** from temporal state. They are explicitly sanitized to zero during apply, and the EPC manager is cleared.

This prevents resurrecting stale physical memory mappings across reboot or across incompatible hardware.

---

## 7. Durable Persistence and Recovery

### 7.1 Temporal Store Snapshot Encoding

The temporal store can serialize the entire in-memory temporal graph to a persistence snapshot:

```text
snapshot = MAGIC || VERSION || next_version_id || object_count || objects[]
```

Each object encodes:

- path bytes
- branch heads (name + head version id)
- version entries, each including:
  - full `TemporalVersionMeta`
  - payload bytes

This is a state snapshot, not an append-only event log. It trades write amplification for fast recovery.

### 7.2 Recovery Semantics

On boot (during `temporal::init()`):

1. The persistence subsystem is queried for the last temporal snapshot.
2. If present and decodable, it is loaded into the temporal store.
3. The live kernel subsystems are then able to restore individual objects by checkout/rollback operations (or via policy-driven restore flows).

### 7.3 Hardware Dependence

Durability depends on the configured persistence backend:

- With a VirtIO block device: temporal snapshots persist across reboot.
- Without a durable backend: persistence is RAM-backed and does not survive reboot.

The temporal store still works and remains useful for *in-session* branching/rollback and auditing even without durable storage.

---

## 8. APIs Exposed to Services (WASM + IPC)

### 8.1 WASM Host ABI

Oreulia’s WASM ABI exposes temporal primitives (names may be prefixed with `oreulia_`):

| Function | Purpose |
|---|---|
| `temporal_snapshot` | record snapshot of a path |
| `temporal_latest` | return latest version meta |
| `temporal_read` | read payload bytes for a version |
| `temporal_rollback` | restore a version to live state |
| `temporal_history` | list version metadata window |
| `temporal_stats` | store-wide stats |
| `temporal_branch_create` | create a named branch |
| `temporal_branch_checkout` | activate branch head |
| `temporal_branch_list` | list branches |
| `temporal_merge` | merge branches with strategy |

These allow user-mode services to perform time-travel without any string-parsing command layer.

### 8.2 IPC Binary Protocol

Temporal traffic over IPC uses a binary framed protocol (see `docs/oreulia-ipc.md`, “Temporal IPC Binary Protocol (v1)”).

---

## 9. Correctness Lemmas, Corollaries, and Proofs

All proofs below are with respect to the implemented algorithms and their stated preconditions. Where the hardware or persistence medium may be adversarial, additional cryptographic measures are required (outside this document).

### 9.1 Lemma: Payload Size Bound Is Preserved

**Lemma 2 (Bounded Version Payload).** For any recorded version `v`, `meta(v).data_len <= MAX_TEMPORAL_VERSION_BYTES`.

**Proof.**

1. The only way to create a new version is through `record_version_locked(path, payload, operation)`.
2. `record_version_locked` checks `payload.len() > MAX_TEMPORAL_VERSION_BYTES` and rejects if true.
3. On success, the stored payload length is exactly `payload.len()` (copied into `data`), and `meta.data_len = data.len()`.

Therefore `meta.data_len <= MAX_TEMPORAL_VERSION_BYTES` for all stored versions. QED.

### 9.2 Lemma: Hash Metadata Is Deterministic

**Lemma 3 (Deterministic Hashes).** For a fixed payload byte string `x`, `compute_version_hashes(x)` always returns the same triple `(content_hash, merkle_root, leaf_count)`.

**Proof.**

1. `content_hash = H(x, TEMPORAL_HASH_SEED)`. `H` is a deterministic function of its inputs.
2. The chunking of `x` into `x.chunks(MERKLE_CHUNK_BYTES)` is deterministic.
3. Each `seed_i` is deterministic in `i`, and each leaf `leaf_i = H(c_i, seed_i)` is deterministic.
4. `merkle_root = R(leaves)` where `R` is deterministic.

Thus the triple is deterministic. QED.

### 9.3 Lemma: Adapter Dispatch Is Well-Defined

**Lemma 4 (Longest-Prefix Uniqueness).** For a fixed registry state and a fixed path `p`, `find_object_adapter(p)` returns either:

- the unique adapter whose prefix length is maximal among matching prefixes, or
- `None` if no prefixes match.

**Proof.**

1. The algorithm scans all registry slots in a fixed order.
2. It maintains `(best, best_len)` and updates only when a candidate prefix matches and `prefix_len >= best_len`.
3. Since `best_len` is a scalar and the final update set is deterministic, the final `best` is the adapter with maximal prefix length.
4. If multiple adapters have identical maximal prefix lengths (which implies identical prefix strings in a correct registry), the later one overwrites the earlier one; the registry itself maintains uniqueness by updating existing entries for the same prefix.

Therefore the selected adapter is well-defined. QED.

### 9.4 Lemma: Typed Adapters Refuse Miskeyed Payloads

**Lemma 5 (Key/Type Safety).** For any typed adapter in Table 5.2 (all non-file entries), if either:

- the path does not match the adapter’s expected singleton key or parsed object id, or
- the payload’s `(encoding, object_type_id, event/schema)` markers are invalid for that adapter,

then the adapter returns an error and does not apply state.

**Proof.**

Each typed adapter begins with:

1. A path validation:
   - singleton keys (e.g. `/wifi/state`) require exact equality, or
   - keyed prefixes parse the object id from the path and compare against the id encoded in the payload.
2. A payload header validation (`encoding == V1`, `object_type_id == expected`, `event` constraints, schema constraints).

If any check fails, the adapter returns `Err(...)` before calling into the subsystem apply function.
Therefore, miskeyed or mistyped payloads are rejected. QED.

### 9.5 Lemma: Replay Transcript Reconstruction Correctness

**Lemma 6 (Replay Transcript Reconstruction).** Let a replay session descriptor contain chunk descriptors

- `(idx_j, len_j, ver_j)` for `j = 0..m-1`,

and let `read_version(key(idx_j), ver_j)` return exactly the recorded bytes for that chunk.

If the replay apply function returns `Ok(())`, then the reconstructed transcript equals the concatenation of all chunk bytes in descriptor order and has length `transcript_len`.

**Proof.**

During apply:

1. The algorithm initializes `transcript = empty`.
2. For each chunk descriptor in order, it reads `data_j = read_version(key(idx_j), ver_j)`.
3. It checks `|data_j| == len_j` and appends bytes: `transcript := transcript || data_j`.
4. After processing all chunks, it checks `|transcript| == transcript_len`.

Since all checks succeeded (function returned `Ok(())`), we have:

- `transcript = data_0 || data_1 || ... || data_{m-1}`
- `|transcript| = transcript_len`

which is exactly the statement. QED.

### 9.6 Lemma: Enclave Restore Cannot Reintroduce Stale Physical Pointers

**Lemma 7 (Enclave Pointer Sanitization).** After applying `/enclave/state`, all restored enclave sessions satisfy:

- `code_phys = data_phys = mem_phys = epc_base = 0`
- `code_len = data_len = mem_len = epc_pages = 0`

regardless of their values at the time of capture.

**Proof.**

In the enclave adapter decode, each restored `EnclaveSession` is constructed with those fields set to `0` as literal constants. No subsequent assignment in the apply path overwrites those fields with decoded payload data. Additionally, the EPC manager is cleared. Therefore the post-apply sessions satisfy the stated equalities. QED.

---

## 10. Extension Guidelines (Adding New Kernel Object Classes)

To add a new temporal object class:

1. Choose a stable key namespace:
   - singleton: `/subsystem/state`
   - keyed objects: `/subsystem/object/<id>`
2. Add a typed payload schema with:
   - versioned schema byte (`schema = 1,2,...`)
   - explicit counts and fixed-size bounds
3. Add `record_*` hooks in the subsystem at mutation points.
4. Implement `temporal_apply_*_payload(payload)` in the owning module.
5. Register the adapter prefix in `ensure_object_adapters_initialized()` (or via runtime registration).

Design rules:

- Apply functions should be idempotent for the same payload.
- Payloads should be self-describing enough to reject malformed data quickly.
- Avoid embedding raw pointers; store stable identifiers instead.

---

## 11. Known Limitations (By Design or Deferred)

- **Not cryptographic integrity.** Hashes are for fast detection and metadata, not adversarial tamper-proofing.
- **Secret-at-rest policy.** If temporal persistence is backed by durable storage, enclave key material is persisted as bytes; production deployments should add sealing/encryption and policy-driven redaction.
- **Hardware-coupled resources.** For devices (WiFi/EPC), temporal restore is control-plane restore; actual hardware re-init may still be required on first use.
- **Global snapshot size.** The persistence snapshot includes full payload bytes for all stored versions; retention/compaction policies are future work.
