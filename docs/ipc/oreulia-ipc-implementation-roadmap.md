# Oreulia IPC — Current State and Remaining Roadmap

**Status:** Core IPC architecture is implemented. The remaining roadmap is about tightening semantics, finishing stronger transfer guarantees, and deepening replay/protocol fidelity, not about creating the basic subsystem from scratch.

This document replaces the older milestone plan that still described the `kernel/src/ipc/` split, admission layer, blocking service path, diagnostics, and selftests as future work. Those pieces are already in tree.

---

## 1. Current State

Oreulia IPC already provides:

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

The main unfinished work falls into four categories.

### 3.1 Zero-sum capability transfer

Current message-carried capability transfer is signed, validated, and installable, but it is not yet **ownership-consuming by construction**.

What remains:

- sender-side authority should be consumed or attenuated explicitly when the zero-sum path is used
- receiver installation should be represented as a first-class transfer outcome rather than a copy-style attachment story
- selftests should prove that no duplicated live authority remains after a zero-sum transfer

This is the biggest semantic gap between the current implementation and the stronger capability model Oreulia aims for.

### 3.2 Protocol/session typing

Channels are still general-purpose payload pipes.

What remains:

- optional session/protocol state per channel
- explicit protocol progression checks
- at least one real kernel or Wasm service that runs on a protocol-constrained channel instead of a convention-only pipe

`TypedServiceArg` and the service registry are already useful building blocks, but they do not yet amount to protocol-typed IPC.

### 3.3 Replay completeness

Temporal capture exists, but IPC replay is still partial.

What remains:

- richer event vocabulary for refusal, draining, transfer, and terminal closure transitions
- replayable channel-state reconstruction rather than partial restoration placeholders
- selftests that round-trip a nontrivial multi-message scenario

The current system records enough for inspection and partial restore, not yet enough for a fully replay-complete IPC state machine.

### 3.4 Secondary surface alignment

The kernel is ahead of several secondary documentation and wrapper surfaces.

What remains:

- keep public docs aligned with the real IPC implementation
- keep Wasm/raw ABI wrapper docs aligned with actual host function ids
- keep shell/runtime diagnostic docs aligned with the commands in tree

This is lower risk than the semantic gaps above, but it matters for public correctness.

---

## 4. Recommended Next Sequence

The remaining work should proceed in this order.

### Phase 1: zero-sum transfer path

Priority:

- highest

Why first:

- it strengthens the authority model directly
- it is a cleaner foundation for future replay and protocol typing
- it removes the largest mismatch between Oreulia's current theory and message-carried capability behavior

Concrete work:

- extend capability-manager support for consuming transfer/install flows
- represent transfer outcomes explicitly in IPC message handling
- add selftests for consume/install/attenuate behavior

### Phase 2: replay-complete event vocabulary

Priority:

- high

Why second:

- replay needs stable semantics from transfer and closure before it becomes worth deepening

Concrete work:

- extend IPC temporal events beyond send/recv/count placeholders
- encode refusal, drain, transfer, and terminal close transitions
- add reconstruction tests for realistic scenarios

### Phase 3: optional protocol/session state

Priority:

- medium

Why third:

- protocol state should build on already-stable admission, transfer, and closure semantics

Concrete work:

- define a minimal channel session enum
- reject invalid protocol transitions deterministically
- migrate one real service path to a constrained protocol channel

### Phase 4: ongoing doc and SDK cleanup

Priority:

- continuous

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

- zero-sum transfer consume/install cases
- replay of a nontrivial multi-message multi-transition scenario
- protocol-state acceptance and rejection cases

---

## 6. Definition of Done for the Remaining Roadmap

The IPC subsystem should be considered materially complete for this roadmap when all of the following are true:

1. message-carried capability transfer has a real zero-sum path
2. draining and terminal closure are replayable as explicit state transitions
3. at least one real service uses optional protocol/session state successfully
4. temporal replay can reconstruct materially meaningful IPC state
5. docs and ABI wrappers no longer materially lag the kernel implementation

Oreulia does **not** need to wait for that full end state to claim it already has a real IPC subsystem. It does need that end state to claim the IPC model fully matches the stronger long-range capability and replay design.
