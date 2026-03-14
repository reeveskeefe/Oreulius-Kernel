# Oreulia IPC Full Implementation Roadmap

**Status:** In progress  
**Scope:** Full implementation roadmap derived from the current `kernel/src/ipc/mod.rs` codebase, not from the theory paper alone.

This roadmap is the concrete bridge between the current Oreulia IPC v0 implementation and the target IPC system described by the recent capability, liveness, temporal, and linearity work. It is intentionally file-oriented, milestone-based, and test-gated so the implementation can proceed without losing coherence.

## 1. Current State

The current IPC implementation is concentrated in `kernel/src/ipc/mod.rs` and already provides useful primitives:

- `ChannelId`, `ProcessId`, `Capability`, `Message`, `ChannelCapability`, `ChannelRights`
- bounded per-channel ring buffers
- `send`, `try_recv`, `recv`, `close`, `create_channel`
- capability attachment to messages
- predictive restriction checks through the security subsystem
- temporal event recording for send, receive, and close
- a global `IpcService` wrapper and syscall-friendly helper functions
- Wasm host integration through `kernel/src/wasm.rs`

The current implementation also has clear gaps that block the target IPC architecture:

- the core `Channel::recv()` helper is still the same as `try_recv()`, but `IpcService::recv()` now performs scheduler-backed blocking in real process context
- `close()` now has an initial draining state and rejects new sends during drain, but it is not yet a full graceful-closure/archive state machine
- capability attachment signs message-carried capabilities but does not enforce zero-sum linear transfer
- send and receive admission now go through an explicit decision layer, and the service-layer send/recv APIs now block through scheduler wait queues in real process context
- backpressure now has explicit pressure levels, recommended actions, and counters, with threshold-driven async refusal at high pressure and saturated reliable defer behavior
- temporal replay restores queue depth placeholders, not a replayable event-complete channel state
- protocol/session state is absent; channels are pipes, not protocol-constrained endpoints
- diagnostics and selftests now exist, including blocked sender/receiver visibility, but they are still thinner than the later milestones require

Implemented so far:

- Milestone 0 foundation is in tree: `ipc-selftest`, `ipc-list`, and `ipc-inspect`
- Milestone 1 foundation is in tree: stable IPC data structures have been extracted into `kernel/src/ipc/`
- early Milestone 2 / 4 scaffolding is in tree: explicit admission decisions, refusal accounting hooks, and a `closing` drain state
- Milestone 3 is partially in tree: per-channel scheduler wait keys, service-layer blocking send/receive, wakeups on send/recv/close, and runtime waiter diagnostics
- Milestone 5 is partially in tree: explicit backpressure levels, recommended actions, queue high-water tracking, threshold-hit counters, sender/receiver wake counters, and deterministic threshold-crossing tests

## 2. Target End State

The target IPC system has the following concrete properties:

1. `ipc/mod.rs` becomes a facade and compatibility layer rather than a monolithic implementation file.
2. Send admission is centralized, decidable, and reusable across kernel callers, Wasm host calls, and future proofs.
3. Receive and reliable-send paths can actually block and wake through the scheduler.
4. Closure is graceful: accepted messages are delivered, explicitly refused, or archived before final closure.
5. Capability transfer is zero-sum in the target path and auditable in the current path.
6. Channels can optionally carry protocol/session state.
7. Temporal capture and replay preserve enough structure for channel-state reconstruction.
8. Commands, selftests, and diagnostics can prove each milestone before the next one starts.

## 3. File Plan

The implementation should keep `kernel/src/ipc/mod.rs` as the module root and progressively move logic into `kernel/src/ipc/`.

### 3.1 `kernel/src/ipc/mod.rs`

Final role:

- module root
- re-export stable public types and helper functions
- retain compatibility wrappers used by the rest of the kernel and Wasm host layer
- no longer own the full channel implementation

What remains here:

- `pub use` re-exports
- top-level `ipc()` singleton
- public syscall-facing helpers
- backwards-compatible wrappers during migration

### 3.2 New `kernel/src/ipc/` files

Create the following files in order:

| Path | Responsibility | Notes |
| --- | --- | --- |
| `kernel/src/ipc/types.rs` | `ChannelId`, `ProcessId`, common constants, shared scalar types | Pull pure types out first. |
| `kernel/src/ipc/errors.rs` | `IpcError`, refusal/status enums, display/debug impls | Expand here as semantics get richer. |
| `kernel/src/ipc/rights.rs` | `ChannelRights`, future attenuation helpers, rights masks | Bridge to `capability.rs`. |
| `kernel/src/ipc/message.rs` | `Message`, capability attachments, payload helpers | Later split current vs linear attachment path. |
| `kernel/src/ipc/ring.rs` | `RingBuffer` | Pure data structure, easy first extraction. |
| `kernel/src/ipc/channel.rs` | `Channel`, core queue mutation logic | Starts thin, grows as admission and closure move out. |
| `kernel/src/ipc/admission.rs` | send/receive admission predicates and decision enum | This is the proof-bearing heart of the refactor. |
| `kernel/src/ipc/backpressure.rs` | queue-pressure policy, thresholds, refusal/defer behavior | Required before real liveness semantics are believable. |
| `kernel/src/ipc/closure.rs` | graceful closure state machine and drain/refuse/archive transitions | Removes abrupt close semantics. |
| `kernel/src/ipc/session.rs` | optional protocol/session state for channels | Implement only after admission/closure are stable. |
| `kernel/src/ipc/audit.rs` | audit event creation and security/intent logging glue | Keeps channel code smaller. |
| `kernel/src/ipc/temporal_bridge.rs` | temporal event encoding, replay, reconstruction helpers | Extends the current queue-depth-only replay. |
| `kernel/src/ipc/service.rs` | `IpcService`, global table access, compatibility wrappers | Shrinks root file substantially. |
| `kernel/src/ipc/selftest.rs` | deterministic IPC selftests and scenario drivers | Required before deeper changes. |

### 3.3 Existing files that must change

| Path | Required change |
| --- | --- |
| `kernel/src/capability.rs` | add or expose zero-sum transfer primitives, export/import helpers, ownership-consuming remove/install path |
| `kernel/src/temporal.rs` | add richer IPC event forms: refusal, graceful-close, drain-complete, replay metadata |
| `kernel/src/security.rs` | keep predictive restriction logic but route through central admission decisions |
| `kernel/src/process.rs` | add wait-state integration for blocking send/recv |
| `kernel/src/scheduler.rs` | wake blocked receivers/senders, handle channel wait queues |
| `kernel/src/scheduler_platform.rs` | keep scheduler state compatible with IPC wait/wake hooks |
| `kernel/src/commands.rs` / `kernel/src/commands_shared.rs` | add inspect, selftest, and liveness diagnostics commands |
| `kernel/src/wasm.rs` | align host channel send/recv/capability import-export with new admission and transfer semantics |
| `kernel/src/lib.rs` | initialize any new IPC selftest/diagnostic registration if needed |
| `docs/oreulia-ipc.md` | keep user-facing design docs aligned with actual milestone state |

## 4. Milestones

Implementation should proceed in the following order. Do not skip ahead. Later milestones assume invariants introduced earlier.

### Milestone 0: Freeze and Characterize Current Behavior

Goal:

- capture what the current v0 code actually does before changing it

Required work:

- add deterministic selftests for current `send`, `try_recv`, `recv`, `close`, capability attachments, and temporal event recording
- add a diagnostic command that prints channel occupancy, flags, priority, and closed state
- record current gaps explicitly: nonblocking `recv`, abrupt `close`, copyable capability attachments

Files:

- `kernel/src/ipc/mod.rs`
- `kernel/src/commands.rs`
- `kernel/src/commands_shared.rs`
- `kernel/src/ipc/selftest.rs`

Exit criteria:

- one command can run IPC selftests inside the kernel
- one command can inspect a live channel
- the current semantics are frozen in tests before refactoring

### Milestone 1: Refactor Without Behavior Change

Goal:

- split `ipc/mod.rs` into modules while keeping runtime behavior identical

Required work:

- extract pure types, errors, rights, message, ring buffer, and `IpcService`
- keep `ipc/mod.rs` as a thin facade
- add compile-time and runtime parity checks

Files:

- `kernel/src/ipc/mod.rs`
- `kernel/src/ipc/types.rs`
- `kernel/src/ipc/errors.rs`
- `kernel/src/ipc/rights.rs`
- `kernel/src/ipc/message.rs`
- `kernel/src/ipc/ring.rs`
- `kernel/src/ipc/service.rs`

Exit criteria:

- `cargo check` still passes for the active targets
- IPC selftests from Milestone 0 still pass unchanged
- no public caller outside `ipc/mod.rs` needs to know the internals moved

### Milestone 2: Centralize Admission and Refusal

Goal:

- make send/receive validity explicit, local, and testable

Required work:

- introduce `SendDecision` and `RecvDecision` enums, for example:

```rust
pub enum SendDecision {
    Commit,
    Refuse(IpcRefusal),
    Defer(IpcDefer),
}
```

- move capability checks, channel-id checks, closure-state checks, predictive restriction checks, queue-capacity checks, and flag-policy checks into `ipc/admission.rs`
- make `Channel::send` and `Channel::try_recv` dispatch on decisions instead of reimplementing policy inline
- record explicit refusal events through audit and temporal hooks

Files:

- `kernel/src/ipc/admission.rs`
- `kernel/src/ipc/channel.rs`
- `kernel/src/ipc/errors.rs`
- `kernel/src/ipc/audit.rs`
- `kernel/src/ipc/temporal_bridge.rs`

Exit criteria:

- `send` policy is expressed in one place
- refusal outcomes are explicit and logged
- unit tests cover every refusal branch independently

### Milestone 3: Real Blocking and Wakeups

Goal:

- make `recv` and reliable-send semantics match the documented blocking model

Required work:

- add per-channel wait queues for receivers and reliable senders
- block tasks in the scheduler instead of returning `WouldBlock` from the blocking API
- wake the correct blocked task on enqueue, dequeue, close, and refusal transitions
- keep nonblocking APIs for callers that need them

Files:

- `kernel/src/ipc/channel.rs`
- `kernel/src/ipc/service.rs`
- `kernel/src/process.rs`
- `kernel/src/scheduler.rs`
- `kernel/src/scheduler_platform.rs`

Exit criteria:

- `recv()` blocks instead of aliasing `try_recv()`
- reliable send can wait for capacity when policy requires it
- selftests show producer/consumer wakeup works repeatedly

Current status note:

- implemented: service-layer `send()` and `recv()` now block through the scheduler, channel transitions wake the relevant wait queues, and the runtime `ipc-selftest` path now stages deterministic receiver/sender wakeup cycles
- unit-level wakeup regressions still exist for send, receive, and close queue wake behavior
- still missing: broader policy refinement beyond the current high-pressure async refusal and saturated reliable defer matrix, especially for future unbounded and priority-sensitive modes

### Milestone 4: Graceful Closure

Goal:

- remove abrupt-close semantics

Required work:

- introduce `CloseState`, for example `Open`, `Draining`, `Closed`
- define what happens to in-flight messages during closure
- make accepted messages drain, refuse with explicit terminal status, or archive for replay before final closure
- update commands and diagnostics to show close state

Files:

- `kernel/src/ipc/closure.rs`
- `kernel/src/ipc/channel.rs`
- `kernel/src/ipc/errors.rs`
- `kernel/src/ipc/temporal_bridge.rs`
- `kernel/src/commands.rs`

Exit criteria:

- no already-accepted message silently disappears because of `close()`
- close behavior is deterministic and test-covered
- temporal replay captures closure state transitions

### Milestone 5: Backpressure as a First-Class Policy

Goal:

- turn `WouldBlock` from a bare error into an admission/backpressure policy

Required work:

- add occupancy thresholds and backpressure actions in `ipc/backpressure.rs`
- distinguish commit, defer, and refuse outcomes
- add per-channel stats for occupancy history, refusal count, and wake count
- make async, reliable, bounded, and future unbounded modes all use the same policy surface

Files:

- `kernel/src/ipc/backpressure.rs`
- `kernel/src/ipc/admission.rs`
- `kernel/src/ipc/channel.rs`
- `kernel/src/ipc/selftest.rs`

Exit criteria:

- every enqueue path goes through a clear backpressure policy
- liveness-related counters exist and are inspectable
- there are deterministic tests for threshold crossings and recovery

### Milestone 6: Zero-Sum Capability Transfer

Goal:

- implement the target-model capability path instead of only attaching signed copies

Required work:

- add a capability-transfer path that consumes sender ownership and installs receiver ownership explicitly
- represent message-carried capabilities as transfer descriptors or staged transfer entries rather than as unconstrained copied capability values
- preserve a compatibility path if needed during migration, but keep it clearly marked as legacy
- ensure capability transfer can be audited and replayed

Files:

- `kernel/src/ipc/message.rs`
- `kernel/src/ipc/channel.rs`
- `kernel/src/capability.rs`
- `kernel/src/ipc/audit.rs`
- `kernel/src/ipc/temporal_bridge.rs`

Exit criteria:

- successful capability send removes or attenuates sender-side authority as designed
- receiver installation is explicit and testable
- zero-sum selftests prove no duplicate live authority remains after transfer

### Milestone 7: Protocol and Session State

Goal:

- let channels optionally carry protocol state instead of being raw payload pipes

Required work:

- define a minimal protocol/session enum
- require protocol-state advancement on send/recv for typed channels
- integrate existing `TypedServiceArg` and service pointer patterns into explicit protocol state
- keep plain channels as the fallback mode

Files:

- `kernel/src/ipc/session.rs`
- `kernel/src/ipc/channel.rs`
- `kernel/src/ipc/message.rs`
- `kernel/src/wasm.rs`

Exit criteria:

- at least one real kernel or Wasm service runs on a protocol-constrained channel
- invalid protocol progression is rejected deterministically

### Milestone 8: Temporal and Audit Completeness

Goal:

- make replay and audit sufficient for real IPC-state reconstruction

Required work:

- extend IPC temporal events beyond send/recv/close counts
- capture refusal events, closure state, and transfer metadata
- restore more than synthetic queue depth
- add a replay selftest that round-trips a nontrivial IPC scenario

Files:

- `kernel/src/ipc/temporal_bridge.rs`
- `kernel/src/temporal.rs`
- `kernel/src/ipc/selftest.rs`

Exit criteria:

- replay reconstructs a channel state richer than queue-depth placeholders
- audit and temporal records agree on the same transition sequence

### Milestone 9: Command Surface and Developer Tooling

Goal:

- make the IPC system inspectable and debuggable

Required work:

- add commands for channel listing, channel inspect, wait queue inspect, refusal stats, and replay selftest
- expose a compact status snapshot for scripting and smoke tests
- update `docs/oreulia-ipc.md` with the real current milestone state

Files:

- `kernel/src/commands.rs`
- `kernel/src/commands_shared.rs`
- `docs/oreulia-ipc.md`

Exit criteria:

- a developer can inspect live IPC state from the kernel shell
- the documentation matches the actual code behavior

## 5. Recommended Type and API Additions

The following API shapes should exist before Milestone 6 is complete.

```rust
pub enum IpcRefusal {
    PermissionDenied,
    InvalidCapability,
    Closed,
    Full,
    Restricted,
    ProtocolViolation,
}

pub enum SendDecision {
    Commit,
    Refuse(IpcRefusal),
    Defer,
}

pub enum RecvDecision {
    Deliver,
    Refuse(IpcRefusal),
    Block,
}

pub enum CloseState {
    Open,
    Draining,
    Closed,
}
```

These types should live in `kernel/src/ipc/errors.rs` or `kernel/src/ipc/channel.rs`, not in callers.

## 6. Tests and Verification Gates

Every milestone should add tests before it adds complexity.

### 6.1 Unit tests

- message encode/decode and capability attachment limits
- ring buffer occupancy, wraparound, and full/empty behavior
- rights and capability checks
- send-admission and refusal decision table
- graceful closure state transitions

### 6.2 Integration tests

- producer/consumer with real scheduler wakeups
- reliable send under full buffer pressure
- capability transfer with sender ownership consumed
- close-while-buffer-nonempty
- temporal replay of a multi-message scenario

### 6.3 Command-driven selftests

- `ipc-selftest`
- `ipc-selftest-transfer`
- `ipc-selftest-close`
- `ipc-selftest-replay`

### 6.4 Proof-friendly invariants to preserve in code

- queue count matches actual occupied slots
- no committed send bypasses admission
- no accepted message is dropped during graceful closure
- transfer either consumes, attenuates, or explicitly preserves sender authority by rule
- refusal outcomes are explicit events, not silent fallthrough

## 7. Sequencing Rules

These rules matter.

1. Do not implement session types before admission and graceful closure exist.
2. Do not claim zero-sum capability transfer until `capability.rs` supports consuming transfer semantics.
3. Do not make replay more detailed until the event vocabulary is stable enough to keep.
4. Do not update docs to promise reliable-send blocking semantics until the capacity-wait path actually lands.
5. Do not remove compatibility wrappers from `ipc/mod.rs` until `wasm.rs`, commands, and callers are migrated.

## 8. Definition of Done

The IPC system counts as fully implemented for this roadmap when all of the following are true:

1. `kernel/src/ipc/mod.rs` is a stable facade rather than a monolith.
2. blocking and nonblocking receive/send semantics are both real and test-covered.
3. graceful closure is implemented and no accepted message is silently lost.
4. capability transfer has a target zero-sum path backed by `capability.rs`.
5. temporal replay can reconstruct materially meaningful IPC state.
6. commands and selftests can expose and validate live IPC behavior.
7. documentation reflects the actual implementation state.

At that point, the system is ready for a second pass focused on stronger formal alignment and possible mechanized proofs.
