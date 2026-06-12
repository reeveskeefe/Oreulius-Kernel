# Oreulius IPC Comprehensive Audit Checklist

## 1. IPC Architecture and Trust Boundary

### 1.1 IPC module purpose and security role

### 1.2 Kernel/user boundary assumptions

### 1.3 Message-passing-only design, no shared-memory IPC

### 1.4 IPC object ownership model

### 1.5 Interaction with scheduler, capability manager, temporal storage, security module, and syscall layer

### 1.6 Global singleton service model

### 1.7 Single-lock IPC service risks

### 1.8 Public API surface versus internal-only API surface

### 1.9 Kernel-facing facade consistency

### 1.10 Panic-free and allocation-bounded kernel behavior

The repo’s IPC README explicitly describes IPC as the “communication backbone” with capability-gated message passing, bounded queues, backpressure, affine endpoint delegation, admission control, closure states, and temporal session typing.

---

## 2. IPC File and Component Coverage

### 2.1 `kernel/src/ipc/mod.rs` facade audit

### 2.2 `types.rs` primitive type audit

### 2.3 `message.rs` message object audit

### 2.4 `rights.rs` channel rights and endpoint capability audit

### 2.5 `ring.rs` fixed queue audit

### 2.6 `channel.rs` channel state machine audit

### 2.7 `admission.rs` send/receive gate audit

### 2.8 `backpressure.rs` pressure algebra audit

### 2.9 `table.rs` channel registry audit

### 2.10 `service.rs` IPC service facade audit

### 2.11 `diagnostics.rs` introspection audit

### 2.12 `selftest.rs` runtime validation audit

### 2.13 `kernel/src/platform/syscall.rs` syscall adapter audit

### 2.14 `docs/ipc/oreulia-ipc.md` specification alignment audit

### 2.15 Verification mapping and proof document alignment audit

The README’s file map lists the intended role of each IPC file, including channel state, admission, backpressure, table, service, diagnostics, and self-test coverage.

---

## 3. IPC Constants, Limits, and Capacity Invariants

### 3.1 `MAX_MESSAGE_SIZE` correctness

### 3.2 `MAX_CAPS_PER_MESSAGE` correctness

### 3.3 `CHANNEL_CAPACITY` correctness

### 3.4 `MAX_CHANNELS` correctness

### 3.5 High-pressure threshold correctness

### 3.6 Queue occupancy invariant

### 3.7 Maximum in-flight memory per channel

### 3.8 Maximum global IPC memory footprint

### 3.9 Saturation behavior

### 3.10 Zero-capacity and overflow impossibility

### 3.11 Integer narrowing risks

### 3.12 Compile-time versus runtime capacity enforcement

Current constants are `MAX_MESSAGE_SIZE = 512`, `MAX_CAPS_PER_MESSAGE = 16`, `CHANNEL_CAPACITY = 4`, and `MAX_CHANNELS = 16`.

---

## 4. Syscall Boundary Audit

### 4.1 Syscall number validity

### 4.2 Syscall argument ABI layout

### 4.3 User pointer validation

### 4.4 User buffer read safety

### 4.5 User buffer write safety

### 4.6 Capability struct ABI stability

### 4.7 32-bit and 64-bit field reconstruction

### 4.8 Endianness assumptions

### 4.9 Syscall error mapping

### 4.10 Syscall audit logging

### 4.11 Syscall policy blocking

### 4.12 Invalid syscall handling

### 4.13 Cross-architecture syscall consistency

### 4.14 IPC syscall privilege enforcement

### 4.15 IPC syscall fuzzing targets

The syscall handler checks syscall numbers, audits arguments, checks syscall policy blocking, and dispatches IPC calls through the syscall match table.

---

## 5. Channel Creation Audit

### 5.1 Channel ID allocation

### 5.2 Maximum live-channel enforcement

### 5.3 Duplicate channel ID prevention

### 5.4 Creator PID binding

### 5.5 Default flags

### 5.6 Custom flags

### 5.7 Priority handling

### 5.8 Send capability creation

### 5.9 Receive capability creation

### 5.10 Capability ID allocation

### 5.11 Capability grant rollback on channel creation failure

### 5.12 Channel table insertion atomicity

### 5.13 Channel creation race safety

### 5.14 Channel deletion on partial failure

### 5.15 Temporal restore interaction with channel creation

The service creates channels under a mutex, allocates separate send/receive capability IDs, and returns send-only and receive-only channel capabilities to the creator.

---

## 6. Message Object Audit

### 6.1 Fixed-size payload storage

### 6.2 Payload length validation

### 6.3 Payload copy correctness

### 6.4 Zero-initialization of unused payload bytes

### 6.5 Capability array initialization

### 6.6 Capability count tracking

### 6.7 Source PID binding

### 6.8 Message cloning risks

### 6.9 Debug formatting information leakage

### 6.10 Message construction failure modes

### 6.11 Message size denial-of-service resistance

### 6.12 ABI-safe message layout concerns

### 6.13 Send path ownership semantics

### 6.14 Receive path copy-out semantics

### 6.15 Stale data exposure prevention

`Message::with_data` rejects payloads above `MAX_MESSAGE_SIZE`, copies only the provided bytes, stores `payload_len`, and exposes payload through a slice bounded by that length.

---

## 7. Causal Event Identity Audit

### 7.1 `EventId` bit layout

### 7.2 Source PID encoding

### 7.3 Channel sequence encoding

### 7.4 Message sequence encoding

### 7.5 Sequence wraparound behavior

### 7.6 Uniqueness within process lifetime

### 7.7 Uniqueness across reboot/session epochs

### 7.8 Relaxed atomic ordering correctness

### 7.9 Causal predecessor field validation

### 7.10 Causal DAG reconstruction

### 7.11 Forged causal linkage detection

### 7.12 Temporal log correlation

### 7.13 Audit trail replay correctness

### 7.14 Message injection detection

### 7.15 Formal invariant coverage

`EventId` packs source PID, channel sequence, and message sequence into a 64-bit value, and messages can carry a causal predecessor through `cause: Option<EventId>`. The current message sequence uses a global `AtomicU16` with relaxed ordering.

---

## 8. Capability-Carrying Message Audit

### 8.1 Maximum capability count enforcement

### 8.2 Capability insertion bounds checking

### 8.3 Capability signing before insertion

### 8.4 Capability transfer rollback on insertion failure

### 8.5 Ticketed capability rollback

### 8.6 Capability token freshness

### 8.7 Capability owner preservation

### 8.8 Capability type preservation

### 8.9 Capability rights attenuation

### 8.10 Capability substitution attack resistance

### 8.11 Capability replay resistance

### 8.12 Capability duplication risk

### 8.13 One-time transfer semantics

### 8.14 Receive-side capability validation

### 8.15 Partial copy-out behavior for caps

`Message::add_capability` rejects capability overflow, rolls back ticketed transfers on failure, signs the capability, and then inserts it into the message’s fixed capability array.

---

## 9. Channel Rights and Authorization Audit

### 9.1 `SEND` right

### 9.2 `RECEIVE` right

### 9.3 `CLOSE` right

### 9.4 All-rights capability risks

### 9.5 Send-only capability correctness

### 9.6 Receive-only capability correctness

### 9.7 Close-capability enforcement

### 9.8 Channel ID binding inside capability

### 9.9 Owner PID binding inside capability

### 9.10 Stale capability rejection

### 9.11 Cross-process capability use

### 9.12 Capability cloning and delegation

### 9.13 Affine endpoint delegation

### 9.14 Zero-sum delegation property

### 9.15 Rights downgrade and attenuation tests

The admission layer checks predictive restriction, send/receive rights, and channel ID match before accepting operations.

---

## 10. Admission Control Audit

### 10.1 Send admission pipeline

### 10.2 Receive admission pipeline

### 10.3 Predictive restriction enforcement

### 10.4 Permission denied behavior

### 10.5 Invalid capability behavior

### 10.6 Protocol mismatch behavior

### 10.7 Closed channel behavior

### 10.8 Draining channel behavior

### 10.9 Empty queue behavior

### 10.10 Full queue behavior

### 10.11 Reliable channel defer behavior

### 10.12 Async channel refusal behavior

### 10.13 Admission ordering correctness

### 10.14 Side-channel leakage through refusal reason

### 10.15 Auditability of admission decisions

The send path currently evaluates predictive restriction, send rights, channel ID match, temporal protocol validity, closure state, and backpressure before committing. The receive path checks predictive restriction, receive rights, channel ID match, closed-and-empty state, and empty-buffer defer behavior.

---

## 11. Ring Buffer and Queue Semantics Audit

### 11.1 Fixed-size FIFO correctness

### 11.2 Enqueue behavior

### 11.3 Dequeue behavior

### 11.4 Empty/full detection

### 11.5 Wraparound correctness

### 11.6 High watermark tracking

### 11.7 Memory initialization

### 11.8 Message copy semantics

### 11.9 Queue depth invariant

### 11.10 No dynamic allocation guarantee

### 11.11 Fairness under contention

### 11.12 Starvation risk

### 11.13 Queue inspection diagnostics

### 11.14 Formal boundedness proof

### 11.15 Fuzzing boundary cases

---

## 12. Channel State Machine Audit

### 12.1 `Open` state

### 12.2 `Draining` state

### 12.3 `Sealed` state

### 12.4 Close transition correctness

### 12.5 Drain transition correctness

### 12.6 Send rejection during draining

### 12.7 Receive allowance during draining

### 12.8 Sealed send behavior

### 12.9 Sealed receive behavior

### 12.10 Double-close behavior

### 12.11 Close with pending messages

### 12.12 Close with empty queue

### 12.13 Wakeup behavior on close

### 12.14 Failure atomicity during close

### 12.15 Temporal persistence during close

The channel lifecycle is explicitly modeled as `Open -> Draining -> Sealed`; new sends are rejected while draining, pending messages may still be received, and sealed channels reject both sends and receives.

---

## 13. Send Path Audit

### 13.1 Syscall send entry

### 13.2 Service send API

### 13.3 Capability resolution

### 13.4 Message construction

### 13.5 Payload validation

### 13.6 Capability attachment

### 13.7 Admission decision

### 13.8 Backpressure observation

### 13.9 Channel lock scope

### 13.10 Scheduler block preparation

### 13.11 Sender wait-queue insertion

### 13.12 Block commit after lock release

### 13.13 Retry loop correctness

### 13.14 Send wakeup of receiver

### 13.15 Temporal snapshot/persistence after send

### 13.16 Rollback on send failure

### 13.17 Reliable send semantics

### 13.18 Async send semantics

### 13.19 Error propagation quality

### 13.20 Syscall return value correctness

`IpcService::send` loops, locks the table, evaluates admission, commits/refuses/defers, prepares scheduler blocking when capacity is unavailable, inserts the current PID into the waiting sender queue, releases the lock, and then commits the block plan.

---

## 14. Receive Path Audit

### 14.1 Syscall receive entry

### 14.2 Service receive API

### 14.3 Capability resolution

### 14.4 Receive admission

### 14.5 Blocking receive behavior

### 14.6 Nonblocking try-receive behavior

### 14.7 Receiver wait-queue insertion

### 14.8 Block commit after lock release

### 14.9 Retry loop correctness

### 14.10 Message copy-out behavior

### 14.11 Partial payload copy behavior

### 14.12 Capability copy-out behavior

### 14.13 Partial capability output buffer behavior

### 14.14 Sender wakeup after receive

### 14.15 Sealed empty channel behavior

### 14.16 Draining channel receive behavior

### 14.17 Temporal protocol advancement after receive

### 14.18 Stale message exposure prevention

### 14.19 Syscall return value correctness

### 14.20 User buffer fault handling

`IpcService::recv` mirrors the send path: it evaluates receive admission, blocks on message availability when needed, records waiting receivers, releases the lock, and commits the scheduler block plan.

---

## 15. Backpressure Audit

### 15.1 Pressure level calculation

### 15.2 Low pressure behavior

### 15.3 High pressure behavior

### 15.4 Saturated behavior

### 15.5 High-pressure hit accounting

### 15.6 Saturated hit accounting

### 15.7 Reliable channel defer behavior

### 15.8 Async channel refusal behavior

### 15.9 High-priority channel behavior

### 15.10 Pressure threshold correctness

### 15.11 Queue occupancy race safety

### 15.12 Denial-of-service resistance

### 15.13 Sender starvation under pressure

### 15.14 Receiver starvation under pressure

### 15.15 Diagnostics correlation

The documented pressure threshold enters `High` when pending messages are at least 3 for capacity 4, and `Saturated` when the queue is full.

---

## 16. Scheduler Integration Audit

### 16.1 Wait address derivation

### 16.2 Message wait address

### 16.3 Capacity wait address

### 16.4 Waiting receiver queue

### 16.5 Waiting sender queue

### 16.6 Wake-one receiver behavior

### 16.7 Wake-all receiver behavior

### 16.8 Wake-one sender behavior

### 16.9 Wake-all sender behavior

### 16.10 Stale waiter cleanup

### 16.11 PID reuse hazards

### 16.12 Missed wakeups

### 16.13 Thundering herd behavior

### 16.14 Scheduler failure fallback

### 16.15 Lock ordering with scheduler calls

### 16.16 Blocking while holding locks

### 16.17 Fairness and priority behavior

### 16.18 Tests for wait/wakeup correctness

The IPC facade derives separate wait addresses for message availability and channel capacity by shifting the channel ID and OR-ing a wait kind.

---

## 17. Locking and Concurrency Audit

### 17.1 Global IPC table mutex

### 17.2 Channel mutation under table lock

### 17.3 Lock scope minimization

### 17.4 Blocking without holding IPC lock

### 17.5 Lock ordering with scheduler

### 17.6 Lock ordering with capability manager

### 17.7 Lock ordering with temporal subsystem

### 17.8 Lock ordering with security subsystem

### 17.9 Deadlock scenarios

### 17.10 Priority inversion

### 17.11 Interrupt context safety

### 17.12 Reentrancy concerns

### 17.13 Atomic ID allocation ordering

### 17.14 Relaxed atomic correctness

### 17.15 Concurrent close/send/recv behavior

---

## 18. Temporal IPC Protocol Audit

### 18.1 Unbound protocol state

### 18.2 Temporal session binding

### 18.3 Request frame parsing

### 18.4 Response frame parsing

### 18.5 Request send validation

### 18.6 Response send validation

### 18.7 Request receive validation

### 18.8 Response receive validation

### 18.9 Request ID sequencing

### 18.10 Opcode matching

### 18.11 Session ID matching

### 18.12 Phase transition after send

### 18.13 Phase transition after receive

### 18.14 Protocol mismatch behavior

### 18.15 Snapshot encoding

### 18.16 Snapshot restore

### 18.17 Temporal replay safety

### 18.18 Persistence failure handling

### 18.19 Temporal object corruption handling

### 18.20 Formal session typing proof targets

The channel stores a `ChannelProtocolState` and validates temporal send/receive frames against session ID, request ID, opcode, and expected phase.

---

## 19. Channel Table Audit

### 19.1 Channel registry storage

### 19.2 Channel insertion

### 19.3 Channel lookup

### 19.4 Mutable lookup

### 19.5 Channel deletion

### 19.6 Delete-by-creator behavior

### 19.7 Ensure-channel-with-ID behavior

### 19.8 Temporal restore channel creation

### 19.9 Maximum channel enforcement

### 19.10 ID reuse policy

### 19.11 Stale capability after deletion

### 19.12 Registry consistency under failure

### 19.13 Table diagnostics

### 19.14 Table iteration safety

### 19.15 Fuzzing create/delete cycles

---

## 20. Capability Manager Integration Audit

### 20.1 Channel capability grant

### 20.2 Channel capability resolution

### 20.3 Send access resolution

### 20.4 Receive access resolution

### 20.5 Close access resolution

### 20.6 IPC capability type mapping

### 20.7 Kernel capability type versus IPC capability type

### 20.8 Capability token signing

### 20.9 Capability token verification

### 20.10 IPC transfer tickets

### 20.11 Rollback on failed transfer

### 20.12 Revocation during queued transfer

### 20.13 Revocation during blocked send

### 20.14 Revocation during blocked receive

### 20.15 Owner PID mismatch

### 20.16 Rights mismatch

### 20.17 Capability expiration

### 20.18 Replayed transferred capability

### 20.19 Forged transferred capability

### 20.20 Confused deputy cases

The service-level send/receive helpers resolve channel capabilities through `crate::capability::resolve_channel_capability` before using IPC.

---

## 21. Security Module Integration Audit

### 21.1 Syscall audit logging

### 21.2 Syscall policy blocking

### 21.3 Predictive restriction check

### 21.4 Channel capability type restriction

### 21.5 Send-right restriction

### 21.6 Receive-right restriction

### 21.7 Security denial error mapping

### 21.8 Audit event completeness

### 21.9 Causal chain audit correlation

### 21.10 Anomaly response path

### 21.11 Restriction revocation race

### 21.12 Malicious IPC flooding

### 21.13 Covert channel analysis

### 21.14 Capability exfiltration by IPC

### 21.15 Confused deputy through service IPC

---

## 22. Error Taxonomy and Error Mapping Audit

### 22.1 Internal `IpcError` coverage

### 22.2 `IpcRefusal` coverage

### 22.3 `IpcDefer` coverage

### 22.4 Syscall `errno` mapping

### 22.5 String error degradation in public wrappers

### 22.6 Loss of diagnostic specificity

### 22.7 Security-sensitive error detail leakage

### 22.8 Retryable versus fatal errors

### 22.9 Close/drain/sealed distinction

### 22.10 Queue full versus backpressure distinction

### 22.11 Protocol mismatch mapping

### 22.12 Invalid capability mapping

### 22.13 User fault mapping

### 22.14 Out-of-memory mapping

### 22.15 Consistency across syscall and in-kernel API

The admission layer distinguishes predictive restriction, permission denied, invalid capability, protocol mismatch, closed, draining, backpressure, queue full, and queue empty.

---

## 23. Diagnostics and Observability Audit

### 23.1 Channel pending count

### 23.2 Channel capacity reporting

### 23.3 Closed state reporting

### 23.4 High watermark reporting

### 23.5 Refusal counters

### 23.6 Backpressure counters

### 23.7 Wakeup counters

### 23.8 Waiting sender count

### 23.9 Waiting receiver count

### 23.10 Temporal protocol state reporting

### 23.11 Causal event reporting

### 23.12 Syscall boundary events

### 23.13 IPC admission refusal events

### 23.14 Panic/failure event paths

### 23.15 Diagnostic consistency under concurrency

---

## 24. Self-Test and Unit Test Audit

### 24.1 Message creation test

### 24.2 Ring buffer test

### 24.3 Channel send/receive test

### 24.4 Service receive without scheduler context

### 24.5 Service send without scheduler context

### 24.6 Send wakes waiting receiver

### 24.7 Receive wakes waiting sender

### 24.8 Full reliable channel defers send

### 24.9 Full async channel refuses send

### 24.10 Empty channel defers receive

### 24.11 Closure state tests

### 24.12 Capability transfer tests

### 24.13 Temporal protocol tests

### 24.14 Syscall IPC tests

### 24.15 Fuzz/property tests

### 24.16 Negative/security tests

### 24.17 Architecture-specific tests

### 24.18 QEMU regression tests

### 24.19 Formal proof regression tests

### 24.20 Coverage gaps

The module root already includes tests for message creation, ring buffer behavior, channel send/receive, service fallback behavior, and scheduler wakeups.

---

## 25. Formal Verification and Invariant Audit

### 25.1 Capability subset preservation

### 25.2 Message queue capacity invariant

### 25.3 No-send-without-send-right invariant

### 25.4 No-recv-without-receive-right invariant

### 25.5 No-close-without-close-right invariant

### 25.6 No-send-after-seal invariant

### 25.7 Drain-before-seal invariant

### 25.8 FIFO ordering invariant

### 25.9 Causal identity uniqueness invariant

### 25.10 Temporal session phase invariant

### 25.11 Capability transfer authenticity invariant

### 25.12 Capability transfer single-use invariant

### 25.13 Backpressure threshold invariant

### 25.14 Wait/wakeup liveness invariant

### 25.15 No lost wakeup invariant

### 25.16 No deadlock invariant

### 25.17 Bounded memory invariant

### 25.18 Syscall boundary validation invariant

### 25.19 Channel table consistency invariant

### 25.20 Process cleanup invariant

---

## 26. Attack Surface Audit

### 26.1 Malicious sender flooding

### 26.2 Malicious receiver starvation

### 26.3 Capability forgery

### 26.4 Capability replay

### 26.5 Capability substitution

### 26.6 Stale capability after channel deletion

### 26.7 PID reuse confusion

### 26.8 Channel ID reuse confusion

### 26.9 Forced protocol mismatch

### 26.10 Temporal replay injection

### 26.11 Close/drain abuse

### 26.12 Wait queue poisoning

### 26.13 Missed wakeup exploitation

### 26.14 Syscall pointer abuse

### 26.15 Malformed capability ABI struct

### 26.16 Oversized message attempt

### 26.17 Too-many-caps attempt

### 26.18 Partial receive buffer truncation

### 26.19 Covert timing channel through backpressure

### 26.20 Denial of service through channel exhaustion

---

## 27. Memory Safety Audit

### 27.1 Fixed-array bounds

### 27.2 Payload copy bounds

### 27.3 Capability array bounds

### 27.4 Ring buffer indexing

### 27.5 `usize` to `u32` truncation

### 27.6 `usize` to `u16` truncation

### 27.7 `u64` split/recombine correctness

### 27.8 Temporal payload parsing bounds

### 27.9 Snapshot restore bounds

### 27.10 Output buffer bounds

### 27.11 Zeroing unused payload space

### 27.12 No uninitialized memory exposure

### 27.13 No use-after-delete channel references

### 27.14 No dangling wait queue PIDs

### 27.15 Panic-free parsing

---

## 28. ABI and Cross-Architecture Audit

### 28.1 Syscall register ABI

### 28.2 `SyscallArgs` layout

### 28.3 `SyscallResult` layout

### 28.4 `SysIpcCapability` layout

### 28.5 32-bit userspace compatibility

### 28.6 64-bit kernel object IDs

### 28.7 x86 path

### 28.8 x86_64 path

### 28.9 aarch64 path

### 28.10 Endian assumptions

### 28.11 Alignment assumptions

### 28.12 Structure padding assumptions

### 28.13 Stable syscall numbers

### 28.14 Syscall documentation sync

### 28.15 Userspace test harness

The syscall ABI defines register-style arguments and a C-compatible result struct, while IPC capability transfer uses a C-compatible `SysIpcCapability` with split low/high fields for 64-bit values.

---

## 29. Process Lifecycle Audit

### 29.1 Process-owned channel cleanup

### 29.2 `purge_channels_for_process` behavior

### 29.3 Blocked sender on process exit

### 29.4 Blocked receiver on process exit

### 29.5 Creator dies while channel has messages

### 29.6 Sender dies while message queued

### 29.7 Receiver dies while capabilities queued

### 29.8 PID reuse after queued messages

### 29.9 Orphaned channels

### 29.10 Orphaned capabilities

### 29.11 Temporal restore of dead process channels

### 29.12 Scheduler cleanup integration

---

## 30. Service IPC and Higher-Level Protocol Audit

### 30.1 Service registry IPC use

### 30.2 Filesystem IPC use

### 30.3 Compositor IPC use

### 30.4 Fetch service IPC use

### 30.5 WASM runtime IPC use

### 30.6 Service pointer IPC use

### 30.7 Typed service argument encoding

### 30.8 Typed service argument decoding

### 30.9 Service request/response framing

### 30.10 Service confused-deputy risks

### 30.11 Service-level authorization

### 30.12 Service protocol versioning

### 30.13 Service protocol fuzzing

### 30.14 Malformed service argument handling

### 30.15 Cross-service causal audit