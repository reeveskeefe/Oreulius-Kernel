# Oreulius IPC — Current State and Remaining Roadmap

**Status:** Core IPC architecture is implemented. The remaining roadmap is now about broadening protocol coverage, refining proof posture, and keeping secondary surfaces aligned, not about creating the basic subsystem from scratch.

This document replaces the older milestone plan that still described the `kernel/src/ipc/` split, admission layer, blocking service path, diagnostics, and selftests as future work. Those pieces are already in tree.

---

## 1. Current State

Oreulius IPC already provides:

- modularized implementation under [`kernel/src/ipc`](../../kernel/src/ipc)
- bounded channels with fixed queue capacity
- explicit channel rights and channel capabilities
- message payloads with attached capabilities
- causal `EventId` stamping and optional `cause` linkage
- admission control for send and receive
- first-class backpressure levels and counters
- scheduler-backed blocking send/receive at the `IpcService` layer
- draining-aware close semantics
- runtime diagnostics and deterministic selftests
- service-registry introduction flows built on top of IPC
- temporal binary protocols that already use IPC as a transport
- ticketed zero-sum message-carried capability transfer
- Temporal session-typed channels for the typed Temporal IPC pilot
- replayable channel snapshots that restore queue, wait queues, closure, protocol, and counter state

This means the roadmap is now about **semantic strengthening**, not initial implementation.

---

## 2. What Is Already Landed

### 2.1 Module split is complete

The following implementation pieces already exist:

- `types.rs`
- `message.rs`
- `rights.rs`
- `errors.rs`
- `ring.rs`
- `channel.rs`
- `admission.rs`
- `backpressure.rs`
- `table.rs`
- `service.rs`
- `diagnostics.rs`
- `selftest.rs`

`mod.rs` is already a façade and re-export layer rather than the old monolith.

### 2.2 Admission and backpressure are real

Admission is now expressed through:

- `SendDecision`
- `RecvDecision`
- `IpcRefusal`
- `IpcDefer`

Backpressure is no longer just "queue full or not." The implementation already tracks:

- threshold transitions
- recommended pressure actions
- high-water marks
- sender/receiver wake counters
- pressure-hit counters

### 2.3 Blocking service semantics are real

The service-facing IPC API already stages scheduler blocking when possible:

- `IpcService::recv()` blocks on message arrival
- `IpcService::send()` can block on capacity for reliable bounded channels

Low-level channel helpers still expose nonblocking behavior, which is intentional. The blocking contract lives at the service layer today.

### 2.4 Close is no longer abrupt

The system already has a meaningful draining phase:

- accepted queued messages remain deliverable
- new sends are refused during drain
- waiters are woken so closure becomes observable

This is still not the final target for replay-complete graceful closure, but it is already much better than the older abrupt-close model.

### 2.5 Developer tooling exists

The shell already exposes:

- `ipc-list`
- `ipc-inspect`
- `ipc-stats`
- `ipc-selftest`

The roadmap no longer needs to treat inspectability as a missing foundation.

---

## 3. Remaining Gaps

The main unfinished work falls into three categories.

### 3.1 Broader protocol coverage

Temporal is now the first protocol that enforces a typed session machine on channels.

What remains:

- apply protocol/session typing to additional IPC services, not just the Temporal pilot
- document and exercise protocol/session state transitions for each typed service
- keep the channel validator and service-level protocol descriptions aligned as additional protocols land

### 3.2 Refinement and proof coverage

The runtime semantics now exist, but the proof posture still lags the implementation.

What remains:

- capture the new IPC semantics in the verification workspace as explicit invariants
- add proof/refinement trace coverage where the project wants stronger than runtime-only guarantees
- keep the self-check report, theorem index, and runtime evidence synchronized with the kernel cases

### 3.3 Secondary surface alignment

The kernel is ahead of several secondary documentation and wrapper surfaces.

What remains:

- keep public docs aligned with the real IPC implementation
- keep Wasm/raw ABI wrapper docs aligned with actual host function ids
- keep shell/runtime diagnostic docs aligned with the commands in tree

This is lower risk than the proof gap above, but it matters for public correctness.

---

## 4. Recommended Next Sequence

The remaining work should proceed in this order.

### Phase 1: verify and trace the implemented semantics

Priority:

- highest

Why first:

- it preserves the new authority, protocol, and snapshot semantics before broader protocol rollout
- it turns the runtime self-checks into documented verification targets
- it reduces the risk of docs or wrappers drifting behind the implementation again

Concrete work:

- add the new IPC invariants to the verification workspace
- keep the self-check report and evidence records synchronized with the kernel tests
- decide which IPC semantics, if any, should be raised above runtime-only claims later

### Phase 2: broaden protocol coverage

Priority:

- high

Why second:

- the Temporal pilot now exists; additional protocols can reuse the same pattern
- protocol typing should expand only after the semantics are traceable and documented

Concrete work:

- apply typed channels to one additional IPC service path
- reject invalid protocol transitions deterministically in that path
- update the relevant docs and shell help text as the protocol surface grows

### Phase 3: ongoing doc and SDK cleanup

Priority:

- medium

Why third:

- docs and wrappers should stay aligned with the implementation that now exists

Concrete work:

- keep docs in `docs/ipc/` aligned with the kernel source
- remove stale ABI numbering/comments from secondary wrapper surfaces
- keep shell command docs synchronized with real commands

---

## 5. Verification Gates

Every remaining phase should preserve the current behavior that is already landed.

### 5.1 Must-not-regress invariants

- bounded queue occupancy remains correct
- no committed send bypasses admission
- draining channels do not silently drop accepted messages
- blocking service semantics continue to work through scheduler wait keys
- diagnostics remain able to explain queue/wait/backpressure state at runtime

### 5.2 Tests that should stay authoritative

- `ipc-selftest`
- channel inspection and stats commands
- deterministic wakeup scenarios in `selftest.rs`
- capability attachment limit tests
- backpressure threshold tests

### 5.3 New tests to add

- IPC self-check coverage for ticketed transfer, Temporal typing, and snapshot restore
- verification workspace checks for the new IPC invariants
- protocol-state expansion tests if a second typed IPC protocol is added

---

## 6. Definition of Done for the Remaining Roadmap

The IPC subsystem should be considered materially complete for this roadmap when all of the following are true:

1. the implemented IPC semantics are represented as verification invariants and evidence records
2. at least one additional typed IPC protocol path exists beyond Temporal, if the project wants to keep extending the pattern
3. docs and ABI wrappers no longer materially lag the kernel implementation
4. the `ipc-selftest` and `formal-verify` surfaces continue to gate the runtime checks that matter

Oreulius does **not** need to wait for that full end state to claim it already has a real IPC subsystem. It does need that end state to claim the IPC model fully matches the stronger long-range capability and replay design.

## 7. At-a-Glance Status

Completed:

- modular IPC implementation split into dedicated files
- bounded channels with admission control and backpressure
- scheduler-backed blocking at the service layer
- draining-aware close semantics
- service registry and introduction flows built on IPC
- temporal IPC transport, diagnostics, and selftests
- ticketed zero-sum message-carried capability transfer
- Temporal session-typed channels for the typed Temporal pilot
- replayable channel snapshots for committed IPC state, including wait queues

Remaining:

- broader protocol coverage beyond the Temporal pilot
- verification/proof trace coverage for the implemented IPC semantics
- final docs and wrapper parity cleanup
