# Oreulia Temporal Adapters and Durable Persistence

## Formal Architecture for Object Replay and Backend-Independent Recovery

**Status:** Implemented for current object classes and durability backends  
**Primary implementation:** `kernel/src/temporal.rs`, `kernel/src/vfs.rs`, `kernel/src/persistence.rs`, `kernel/src/netstack.rs`, `kernel/src/net_reactor.rs`, `kernel/src/ipc.rs`

## 1. Executive Summary

This document formalizes two completed upgrades in Oreulia's Temporal Objects subsystem:

1. **Concrete adapter coverage expansion** beyond plain file replay by adding replay-aware backend object application (mounted raw block backend writes), while preserving existing TCP listener/connection and IPC channel adapters.
2. **Backend-independent durability** by replacing strict VirtIO-only snapshot persistence with a **durable backend cascade**:
   1. block-device snapshot slot,
   2. optional externally registered backend,
   3. file-backed fallback mirror.

The result is a temporal replay system that is:
- prefix-routed and type-aware,
- fail-closed on unsafe partial backend payloads,
- non-recursive with respect to temporal history generation during replay,
- no longer hard-gated on VirtIO presence for snapshot persistence logic.

## 2. Scope and Completion Statement

### 2.1 What is complete in this implementation slice

| Requirement | Status | Mechanism |
|---|---|---|
| Object restore path not limited to naive file write | Complete | Adapter path now first attempts backend payload replay (`temporal_try_apply_backend_payload`) before plain file restore |
| Mounted raw backend writes replayable | Complete | VFS temporal backend payload decoder + offset write apply |
| Temporal replay avoids recording another temporal write | Complete | `write_path_untracked` path used for replay writes |
| Durability not strictly dependent on VirtIO presence | Complete | Durable backend chain (`disk -> external -> file`) |
| Runtime pluggability of persistence backend | Complete | `SnapshotBackend` registration API |

### 2.2 Explicit boundaries (still true)

| Boundary | Current state |
|---|---|
| Universal kernel object coverage | Not universal; concrete replay handlers exist for files, TCP listener/conn, IPC channel, and mounted raw block backend write payloads |
| Physical durability guarantee with no durable medium | Impossible by construction; if all durable media fail/unavailable, persistence cannot survive power loss |

## 3. Formal Model

Let:
- \(\mathcal{P}\) be normalized object-key paths.
- \(\mathcal{A} = \{(q_i, f_i)\}\) be registered temporal adapters where \(q_i\) is a path-prefix and \(f_i\) is an apply function.
- \(\mathcal{B}\) be persistence backends ordered by priority.

### 3.1 Adapter dispatch

Dispatch uses longest-prefix match:

\[
f^\*(p) = \arg\max_{(q,f)\in\mathcal{A},\ p \text{ starts with } q} |q|
\]

If no \(q\) matches, replay fails closed (`AdapterApplyFailed`).

### 3.2 Replay application semantics

For path \(p\), payload \(x\), restore mode \(m\):

\[
\text{Apply}(p,x,m)=
\begin{cases}
f^\*(p)(p,x,m) & \text{if } f^\*(p)\ \text{exists}\\
\bot & \text{otherwise}
\end{cases}
\]

Where \(\bot\) denotes fail-closed rejection.

### 3.3 Durable write/read selection

Define ordered backends:
\[
\mathcal{B} = [B_{\text{disk}}, B_{\text{ext}}, B_{\text{file}}]
\]

Write and read are left-biased success operators:

\[
W(s) = B_{\text{disk}}(s)\ \triangleright\ B_{\text{ext}}(s)\ \triangleright\ B_{\text{file}}(s)
\]
\[
R(k) = B_{\text{disk}}(k)\ \triangleright\ B_{\text{ext}}(k)\ \triangleright\ B_{\text{file}}(k)
\]

where \(a \triangleright b\) means "use \(a\) if successful/present, else fallback to \(b\)".

## 4. Adapter and Object Coverage

### 4.1 Registered adapter prefixes

| Prefix | Domain | Replay target |
|---|---|---|
| `/` | VFS and mounted backend paths | backend-aware apply first, else untracked file write |
| `/socket/tcp/listener/` | TCP listeners | net reactor temporal apply |
| `/socket/tcp/conn/` | TCP connections | net reactor temporal apply |
| `/ipc/channel/` | IPC channels | IPC temporal apply |

### 4.2 Concrete object payload formats

| Object class | Encoding | Key fields |
|---|---|---|
| File object | raw bytes | payload is file content |
| TCP listener | temporal object V1 | object type, listener id, port, event, tick |
| TCP connection | temporal object V1 | object type, conn id, state, local/remote endpoint, event, aux, optional preview |
| IPC channel | temporal object V1 | object type, channel id, owner pid, payload/cap lengths, queue depth, tick |
| Mounted raw backend write | device payload V1/V2 | encoding, object type, event, flags, offset, write length, stored length, tick, data |

## 5. Backend Replay Semantics (Mounted Raw Device)

### 5.1 Decoding rule

For backend payload \(x\):
- reject if object/event tags mismatch,
- decode \((\text{offset}, \text{write\_len}, \text{stored\_len}, \text{flags})\),
- require non-truncated payload bytes.

### 5.2 Safety gates

Replay is rejected if:
- partial-capture flag is set,
- stored length does not equal logical write length,
- offset conversion overflows host usize,
- backend short write occurs.

These are fail-closed constraints that prevent speculative reconstruction of missing bytes.

## 6. Persistence Architecture

### 6.1 Data objects

| Structure | Purpose |
|---|---|
| `Snapshot` | in-memory snapshot buffer + metadata |
| `SnapshotDiskHeader` | stable on-media header (magic/version/slot/len/offset/time/crc) |
| `SnapshotBackend` | pluggable external write/read function pair |

### 6.2 Durable backend order

| Order | Backend | Trigger to use |
|---|---|---|
| 1 | Disk snapshot slot | VirtIO available and disk path succeeds |
| 2 | External backend | Disk unavailable or not selected; external backend registered |
| 3 | File fallback | Prior backend unavailable/fails; writes to internal VFS mirror path |

### 6.3 Recovery procedure

Recovery is single-shot per boot (`durable_recovery_attempted`):
1. If generic snapshot empty, attempt durable read for generic slot.
2. If temporal snapshot empty, attempt durable read for temporal slot.
3. Mark recovery attempted.

## 7. Lemmas and Corollaries

### Lemma 1 (Deterministic Adapter Resolution)
For fixed adapter registry state and path \(p\), adapter selection is deterministic.

**Sketch.** Selection is a total scan with maximal-prefix-length tie rule. Given fixed insertion state and fixed \(p\), chosen adapter is unique under this deterministic order.

### Lemma 2 (Replay Non-Recursion for File Apply)
Applying historical file payloads through the root adapter does not recursively create new temporal history entries.

**Sketch.** Root adapter uses untracked write path for plain file restores (`write_path_untracked`), bypassing temporal record emission.

### Lemma 3 (Fail-Closed Incomplete Backend Restore)
If backend payload capture is partial, restore is rejected rather than approximated.

**Sketch.** Partial-capture flag implies explicit error; no implicit reconstruction path exists.

### Lemma 4 (Backend Availability Independence)
Snapshot write/read control flow is no longer equivalent to predicate `virtio_blk::is_present()`.

**Sketch.** Durable operations attempt disk, then external backend, then file fallback; disk unavailability does not terminate operation path.

### Lemma 5 (Header-Integrity Preservation)
Any accepted snapshot read satisfies CRC consistency over payload bytes.

**Sketch.** Both disk and file readers validate encoded CRC before accepting snapshot payload.

### Corollary 1 (Replay Soundness for Captured Backend Writes)
For fully captured raw backend write payloads, replay reproduces the same byte sequence at the same offset.

### Corollary 2 (Temporal Recovery Portability)
Systems without VirtIO can still execute persistence protocol logic via file or external backend paths, subject to underlying medium durability.

### Corollary 3 (Extensibility Without Core Rewrite)
Adding a new object class can be achieved by registering a new adapter prefix + apply function pair, without editing rollback/checkout/merge core dispatch logic.

## 8. Complexity and Cost

| Operation | Time complexity | Space notes |
|---|---|---|
| Adapter lookup | \(O(N_a)\) where \(N_a\) is adapter count | bounded table (`MAX_TEMPORAL_ADAPTERS`) |
| Backend payload decode/apply | \(O(|x|)\) | linear in payload size |
| Snapshot write/read | \(O(S)\) | linear in snapshot byte length |
| Recovery attempt | \(O(S)\) per slot | single-shot per boot attempt |

## 9. Fault Model and Fail-Closed Behavior

| Fault | Detection | Result |
|---|---|---|
| Adapter not found | no prefix match | restore fails (`AdapterApplyFailed`) |
| Payload type mismatch | tag/length checks | restore rejected |
| Partial backend payload | flag check | restore rejected |
| Snapshot corruption | CRC mismatch | snapshot rejected |
| Backend unavailable | backend error mapping | fallback backend attempted |

## 10. Practical Interpretation

These changes convert temporal replay and persistence from a narrow-path implementation into a **multi-domain, typed, fallback-capable subsystem**:
- object replay can target both in-memory logical objects and mounted backend raw writes,
- persistence no longer dead-ends on absent block hardware,
- replay path avoids self-induced version inflation.

In short: the architecture is now operationally closer to a production-grade temporal substrate while preserving strict fail-closed semantics.

## 11. Future Work

1. Add additional concrete adapters for more kernel object classes (beyond current TCP/IPC/file/backend-raw set).
2. Add authenticated encryption for file-fallback snapshots if threat model requires at-rest confidentiality/integrity beyond CRC.
3. Add end-to-end recovery telemetry counters for backend selection outcomes.
4. Add fault-injection tests for all fallback transitions (`disk -> ext -> file`) under CI.

