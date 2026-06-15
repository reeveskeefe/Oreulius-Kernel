# Oreulius IPC

## IPC Architecture and Trust Boundary

### IPC module purpose and security role

The IPC module located at kernel/src/ipc/ is the exclusive cross-process communication backbone for the Oreulius kernel. It enforces that no process can exchange data with another process except through a capability-gated, kernel-mediated message-passing channel. This makes IPC a primary security enforcement point: every data transfer between processes is visible to the kernel, checked against capability rights, logged to the security audit system, and optionally validated against a protocol state machine.

The module plays five concurrent security roles. As an isolation enforcer it is the only sanctioned IPC mechanism and explicitly prohibits shared memory, ensuring that process address spaces cannot communicate without kernel mediation. As a capability enforcement point, every send, recv, and close operation verifies that the caller holds a valid capability with the appropriate right and that the capability's embedded channel ID and owner PID match the current operation. As an audit emitter, rejected sends, rejected receives, and channel closures each invoke the security module's intent-tracking API, producing a traceable record of all IPC activity including refusals. As a backpressure regulator, admission control and the backpressure subsystem together prevent a rogue sender from forcing unbounded resource consumption. As a protocol type checker, channels may optionally be bound to a temporal session protocol, enforcing that messages conform to a request/response state machine before they are queued.

All five security roles have working implementations. Capability checking, security audit calls, backpressure, and temporal protocol enforcement are present in the critical paths of admission.rs, channel.rs, and service.rs.

For full maturity: The security audit events produced by the intent family of calls are recorded but the audit export mechanism that would surface them to a log or user-readable stream is not yet implemented. The predictive restriction function that admission consults is a stub returning no restriction unconditionally; a mature implementation requires real policy rules wired into that function. Capability token verification via the Capability::verify method is available but not called on the message dequeue path, meaning signed capabilities are not checked on receipt.


### Kernel/user boundary assumptions

The boundary is enforced entirely in kernel/src/platform/syscall.rs. User processes interact with IPC through exactly six syscalls, all of which are the only legitimate entry points into the IPC subsystem from user space.

| Syscall Number | Name | Purpose |
|---|---|---|
| 10 | ChannelCreate | Allocate a new channel and receive both endpoint capabilities |
| 11 | ChannelSend | Send a plain message payload |
| 12 | ChannelRecv | Receive a plain message into a user buffer |
| 13 | ChannelClose | Close a channel endpoint |
| 14 | ChannelSendCaps | Send a message with attached capabilities |
| 15 | ChannelRecvCaps | Receive a message and extract attached capabilities |

Arguments arrive as raw register values and are parsed into typed kernel-side structs before any IPC code is called. The SysIpcCapability struct that user space passes is re-validated through resolve_channel_capability (taking owner PID, channel ID, and access kind) before the capability is used; user space cannot manufacture a valid capability by constructing the struct because the capability manager must have a record of the grant. Message payloads are copied from the user-provided buffer pointer into a kernel-side Message struct before entering the channel, and user pointers are not retained inside IPC objects. The caller PID used throughout is derived from the scheduler's current_pid function and is not supplied by user space.

Active gaps: The syscall handler does not validate user buffer pointers against the calling process's virtual address space before performing the copy. Without an access-ok check, a user process can provide a kernel-space address as the data buffer, which would allow reading kernel memory through an IPC send operation. There is also no TOCTOU guard on the user buffer between the capability resolution step and the data copy step, which is a narrow but real window for a multi-threaded process. The temporal_apply_channel_event and temporal_apply_channel_payload functions bypass capability resolution entirely and are designed for use by the temporal subsystem during replay, but they are publicly callable from any kernel code, which is a trust assumption that should be enforced structurally rather than by convention.


### Message-passing-only design, no shared-memory IPC

All IPC is performed by value copy. There are no shared memory regions, no memory-mapped inter-process buffers, and no unsafe pointer transfers between address spaces. This is a deliberate and enforced architectural invariant, not a convention.

The Message struct carries a fixed 512-byte array and a payload length field. The Message::with_data constructor copies bytes from the caller's slice into this array and does not store the slice reference. The ring buffer in ring.rs stores Message values by move so the enqueuing process loses ownership and the dequeuing process receives a fresh value from the kernel queue, never a reference to the sender's memory. Capabilities embedded in messages are stored by value as plain integer structs containing IDs, rights bitmasks, timestamps, and a token hash with no pointers. There are no unsafe blocks in channel.rs, ring.rs, table.rs, or service.rs that access memory through raw pointers.

The copy-per-message model is safe and simple but imposes a performance ceiling. A 512-byte message requires two copies per hop: user to kernel on send and kernel to user on receive. For high-throughput service calls this becomes measurable overhead.

For full maturity: A zero-copy fast path could be added for large messages using kernel-owned page frames with explicit transfer semantics, where the sending process unmaps the page and the kernel maps it into the receiver. This would require address space management infrastructure that does not yet exist. The current design is correct and complete for the existing system scope and the copy semantics should not be changed without that infrastructure in place.


### IPC object ownership model

Channel ownership: Every channel in ChannelTable records a creator field of type ProcessId, set at creation time and never changed. The channel itself lives in the kernel's table and is not owned by any one process; both endpoints can be delegated to different processes. On process exit, purge_channels_for_process closes and removes all channels whose creator matches the exiting PID.

Two capabilities are issued at channel creation: a send-only capability and a receive-only capability. Both are returned to the creator with the owner PID set to the creator's PID. Each ChannelCapability embeds a channel ID binding it to a specific channel and an owner PID binding it to a specific process. Admission control verifies both fields against the actual caller on every operation.

Capability delegation: Capabilities can be delegated using the AffineEndpoint wrapper, which enforces a zero-sum split where the delegating process's capacity must equal the sum of the two new endpoints' capacities. This prevents capability duplication. Ticketed capabilities inside messages use a ticket ID field; if a send fails after the ticket is issued, rollback_ipc_transfer is called to cancel the ticket atomically, ensuring capability transfer is all-or-nothing.

A Message value is moved into the ring buffer on enqueue and the sending process loses the object. A Message value is moved out of the ring buffer on dequeue and the receiving process takes full ownership including any capabilities embedded in the message.

Active gap: purge_channels_for_process closes channels by creator PID but does not revoke capabilities already delegated to other processes before the creator exited. A capability held by process B for a channel owned by now-exited process A will fail at lookup time once the channel is removed from the table, but there is no proactive revocation signal delivered to the holder. The holder will not know the capability is invalid until it attempts an operation and receives an InvalidCap error.


### Interaction with scheduler, capability manager, temporal storage, security module, and syscall layer

A dedicated process state WaitingOnChannel is used when a sender blocks on a full queue or a receiver blocks on an empty channel. The blocking sequence proceeds in this order:

1. IPC acquires the channel table lock and determines a block is needed.
2. It calls prepare_block_on with the wait address and the WaitingOnChannel state to prepare a block plan while still holding the lock.
3. It inserts the current PID into the channel's local wait queue.
4. It releases the table lock.
5. It calls commit_block with the prepared plan to actually deschedule the process.

Wait addresses are derived by shifting the channel ID left by two bits and OR-ing a kind value, where kind 1 means a message is available and kind 2 means capacity is available. The local WaitQueue holds 16 PIDs; if more than 16 processes block on the same channel, overflow processes fall back to the global scheduler wait address. This fallback is implemented but untested at scale. After a wakeup there is no confirmation that the woken process finds the condition satisfied; it will retry the IPC operation and may block again, which is correct but potentially slow under high contention.

All syscall-layer IPC operations resolve through resolve_channel_capability before calling into the IPC service. This function verifies that the capability exists in the manager's table, that the owner PID matches, that the channel ID matches, and that the requested access right is granted. The IPC service's send, receive, and close methods also re-check the capability's rights field internally as a defense-in-depth measure. Capability revocation is not wired into the IPC blocking path; if a capability is revoked while its holder is blocked in a receive call, the process will not receive a direct wakeup from the revocation event.

Every channel operation that mutates state calls persist_temporal_snapshot, which serializes the full channel including closure state, protocol state, wait queues, and metrics into a byte payload and writes it to the temporal store keyed by channel ID. Individual events are also logged separately via record_ipc_channel_event with operation type, owner PID, payload length, and queue depth. On channel restore, temporal_apply_channel_payload reconstructs the full channel struct including re-issuing capabilities from any in-flight messages. The critical gap here is that persist_temporal_snapshot is called while holding the global IPC mutex, meaning any latency in the temporal write path extends the IPC lock hold time for all concurrent IPC operations system-wide.

Admission control consults security().predictive_restriction as the first check in both the send and receive evaluation functions. On rejection or deferral, the channel calls the security module's intent-tracking functions to record the event. The predictive restriction function is currently a stub that returns no restriction unconditionally, so this integration point exists structurally but has no active enforcement effect.

Syscall numbers 10 through 15 dispatch to IPC-specific handlers that parse raw register arguments into typed values, resolve capabilities, construct messages for sends, call into the IPC facade functions, and map results to errno codes. The errno mapping is: EAGAIN for would-block, EPERM for permission denied, and EINVAL for invalid argument. User buffer pointers are not validated against the calling process's address space before use, which is the primary unresolved gap at this boundary.


### Global singleton service model

Structure: The IPC service is a global singleton accessed via the ipc function in service.rs. It is stored in a spin::Once wrapping an IpcService and initialized on first access or via an explicit init call. The spin::Once type provides lock-free initialization: the first caller initializes the instance and all subsequent callers return the same static reference. The IpcService struct contains a spin::Mutex wrapping a ChannelTable that protects the channel registry, and an AtomicU32 for capability ID allocation.

Why a singleton: The global channel table must be accessible from all processes and all CPUs. A single authoritative table is the correct design at the current system scale of 16 maximum channels. The next_cap_id counter is updated with a relaxed atomic fetch-add independently of the table lock, meaning capability ID allocation does not require holding the table mutex.

For full maturity: At larger scale the global singleton becomes a contention bottleneck. A sharded table design, where the table is split into N shards with each shard protected by its own mutex and channels assigned to shards by ID modulo N, would allow operations on different channels to proceed in parallel. This requires a two-phase lookup (select shard, acquire shard lock) but eliminates the single global contention point. The AtomicU32 ID allocator is already shard-compatible because it operates outside any channel lock.


### Single-lock IPC service risks

The lock: Every send, recv, try_recv, close, and create_channel call acquires the single Mutex<ChannelTable> in IpcService. All channels share this one lock. A slow operation on channel A blocks all operations on channels B through P.

Risk 1: lock held during temporal persistence. persist_temporal_snapshot is called from the send, receive, and close paths while the table mutex is held. This function allocates a growable buffer, serializes the full channel state into it, and writes to the temporal store. If the temporal write path stalls or contends with another subsystem, the IPC mutex is held for the full duration of that stall, blocking all IPC operations system-wide. This is the highest severity current risk because it couples an I/O-like operation to a global spinlock.

Risk 2: priority inversion. spin::Mutex is a spinlock with no priority awareness. A high-priority task spinning on the IPC mutex while a low-priority task holds it will burn CPU cycles without progress and the low-priority task will not receive a priority boost. This becomes acute when any IPC operation has variable latency, which the temporal persistence path already introduces.

Risk 3: prepare-block-on under lock. prepare_block_on is called with the table lock held in order to atomically enqueue the waiting PID before committing the block. The lock is released before commit_block. The pattern is correct but any slowness in the scheduler's prepare step extends the IPC critical section.

Risk 4: no per-channel granularity. There is no mechanism to lock only the specific channel being operated on. A completely unrelated pair of processes communicating on channel 3 and channel 7 respectively will serialize against each other.

For full maturity: Per-channel locking requires replacing the single Mutex<ChannelTable> with a structure where the table uses a read-write lock for lookups and short exclusive locks only for insert and delete, while each Channel carries its own mutex for mutation. Temporal persistence should be decoupled from the IPC critical section by enqueuing snapshots to a write-back ring and flushing them from a dedicated kernel writer thread or interrupt bottom-half. Priority inheritance or a priority ceiling protocol on the table lock is required before the system can make real-time scheduling guarantees about IPC operations.


### Public API surface versus internal-only API surface

Public API surface: The table below covers the full set of functions, methods, and types exported from the IPC module.

| Category | Items |
|---|---|
| Singleton access | init, ipc |
| Facade free functions (kernel/syscall facing) | create_channel_for_process_with_flags, send_message_for_process, send_message_with_caps_for_process, receive_message_for_process, receive_message_with_caps_for_process, close_channel_for_process, purge_channels_for_process, temporal_apply_channel_event, temporal_apply_channel_payload |
| IpcService struct methods | create_channel, send, try_recv, recv, close, channel_stats, stats, diagnostics, inspect_channel |
| Public types | Message, Channel, ChannelTable, ChannelCapability, ChannelRights, ChannelFlags, ClosureState, DrainResult, IpcError, EventId, ProcessId, ChannelId, Capability, CapabilityType, TemporalIpcPhase, ChannelProtocolState, BackpressureLevel, BackpressureAction, BackpressureSnapshot, IpcDiagnostics, ChannelDiagnostics |

Internal-only API surface (crate-visible only): The table below covers the items marked pub(crate) or fully private.

| Category | Items |
|---|---|
| Channel mutation methods | send_with_observed_pressure, reject_send, defer_send, reject_recv, defer_recv |
| Temporal binding and validation | bind_temporal_protocol, validate_temporal_send, validate_temporal_recv, advance_protocol_after_send, advance_protocol_after_recv |
| Snapshot serialization | persist_temporal_snapshot, encode_temporal_snapshot_payload, restore_temporal_snapshot_payload |
| Admission functions | admission::evaluate_send, admission::evaluate_recv |
| Backpressure functions | All functions in the backpressure module |

Active gap: The IpcService struct methods such as send and recv are fully public on the struct, which means any kernel code that can call ipc() can invoke them with an arbitrarily constructed ChannelCapability without going through the capability manager. The facade functions enforce capability resolution; the IpcService methods perform only an internal rights re-check. A mature design would make IpcService::send and IpcService::recv crate-visible only and expose only the facade functions as the public API, ensuring that all external callers must go through capability resolution.


### Kernel-facing facade consistency

The kernel-facing facade is the set of free functions in service.rs called directly by platform/syscall.rs. Their signatures accept a ProcessId, a ChannelId, and raw byte slices, and return a result wrapping either a success value or a static string error rather than a typed IpcError. They are the translation layer between the raw syscall arguments and the typed IPC service API.

Inconsistency 1: error type downgrade. The facade converts the typed IpcError enum (9 variants) to a static string. The syscall handler then re-examines these strings to determine the correct errno code to return to user space. This is fragile because if a new IpcError variant is added and the string mapping in the facade is not updated, it silently falls through to a default mapping that may return the wrong errno. The correct design is for the facade to return IpcError directly and for the syscall handler to match on the enum.

Inconsistency 2: multiple send variants. There are separate facade functions for sends without capabilities (send_message_for_process) and sends with capabilities (send_message_with_caps_for_process) rather than a single function taking an optional capabilities argument. Adding any further send variation requires yet another facade function.

Inconsistency 3: temporal functions bypass capability resolution. temporal_apply_channel_event and temporal_apply_channel_payload are publicly callable but bypass the capability check entirely. They are structurally indistinguishable from the other facade functions in the public API surface, which could mislead kernel code into calling them in non-replay contexts.

Inconsistency 4: purge has no error path. purge_channels_for_process returns a count of purged channels with no error reporting. A failure to purge a specific channel during process cleanup is silently ignored, which could leave orphaned channels in the table.


### Panic-free and allocation-bounded kernel behavior

No unwrap, expect, or panic calls appear in production IPC code. The following files use typed results and options with explicit match arms or the question-mark propagation operator throughout, with no fallible assumptions: channel.rs, ring.rs, table.rs, service.rs, admission.rs, backpressure.rs, types.rs, rights.rs, message.rs, errors.rs, and diagnostics.rs. Unwrap calls exist only in test-gated blocks and in selftest.rs, which runs as a controlled kernel routine rather than in response to arbitrary user input.

Allocation inventory:

| Site | Data structure | Source file | What bounds it |
|---|---|---|---|
| Channel registry | Tree map keyed by ChannelId | table.rs | MAX_CHANNELS = 16 |
| Per-channel message queue | VecDeque with capacity 4 | ring.rs | CHANNEL_CAPACITY = 4 |
| Temporal snapshot encoding | Growable buffer reserved at 512 bytes | channel.rs encode function | Channel state size |
| Per-channel wait queues | Fixed array of 16 ProcessId values | channel.rs | Compile-time constant |

16 channels multiplied by approximately 2.5 KB per channel (ring buffer at 4 message slots of roughly 560 bytes each plus metadata) equals roughly 40 KB total. This is deterministic and does not grow with runtime behavior beyond the act of creating channels.

Active gap 1: VecDeque is not allocation-free. The ring buffer allocates on the heap at channel creation time. The backpressure layer prevents it from ever reallocating beyond that initial capacity by refusing or deferring sends when the queue is full, so in practice no reallocation occurs. However the data structure still depends on the allocator and is not compatible with a hypothetical no-alloc kernel configuration.

Active gap 2: tree map allocates per insert. The channel registry allocates tree nodes on the heap for each channel creation. With MAX_CHANNELS = 16 this is bounded and not a runtime risk, but it creates a dependency on the global allocator functioning correctly at channel creation time.

Active gap 3: growable buffer in temporal encoding. The encode_temporal_snapshot_payload function creates a new growable buffer every time it is called, which is on every send, receive, and close operation. The allocation is freed when the function returns, but it occurs on the hot path while the IPC mutex is held.

For full maturity: Three substitutions together would make the IPC module allocation-free at runtime after kernel initialization. First, replace the VecDeque<Message> ring buffer with a fixed-size array of uninitialized message slots plus head and tail index fields. Second, replace the BTreeMap<ChannelId, Channel> registry with a fixed-size array of optional channel slots indexed by slot number. Third, replace the growable buffer in temporal snapshot encoding with a fixed-size stack buffer whose maximum size can be computed statically from the channel constants.

The repo’s IPC README explicitly describes IPC as the “communication backbone” with capability-gated message passing, bounded queues, backpressure, affine endpoint delegation, admission control, closure states, and temporal session typing.


## IPC File and Component Coverage

### facade audit of the mod

The module root is the IPC facade. It declares all thirteen internal modules as private, re-exports the public surface of each into the top-level crate::ipc namespace, and defines the wait address derivation constants and functions used by both the service layer and the scheduler integration.

All module declarations are present and private. The pub use statements cover every type, constant, and function that external kernel code is expected to reach. The three const fn wait address helpers, channel_wait_addr, channel_message_wait_addr, and channel_capacity_wait_addr, compute the scheduler wait keys by shifting the channel ID left by two bits and OR-ing a kind constant. The kind constants are IPC_WAIT_KIND_MESSAGE = 0x1 and IPC_WAIT_KIND_CAPACITY = 0x2. The test module embedded in mod.rs covers six cases: message construction, ring buffer round-trip, channel send and receive, selftest report structure, and two service-level send and receive fallback cases.

Re-export surface: The following table shows what each sub-module contributes to the public facade.

| Source module | Re-exported items |
|---|---|
| admission | IpcDefer, IpcRefusal, RecvDecision, SendDecision |
| backpressure | BackpressureAction, BackpressureLevel, BackpressureSnapshot |
| channel | Channel, ChannelFlags, ClosureState, DrainResult |
| diagnostics | ChannelDiagnostics, IpcDiagnostics |
| errors | IpcError |
| message | Message |
| rights | AffineEndpoint, ChannelCapability, ChannelRights |
| selftest | run_selftest, IpcSelftestCase, IpcSelftestReport, IPC_SELFTEST_CASES |
| service | All free facade functions, IpcService, init, ipc |
| table | ChannelTable |
| types | All constants, Capability, CapabilityType, ChannelId, ChannelProtocolState, EventId, ProcessId, TemporalIpcFrameKind, TemporalIpcPhase, TemporalSessionState, TypedServiceArg |

Active gaps: The global #![allow(dead_code)] attribute suppresses warnings across the entire IPC module. This means unused items including private helpers and dead code paths are silently tolerated, making it harder to identify dead code during refactoring. RingBuffer is only re-exported under #[cfg(test)], so external diagnostic or inspection code cannot access the ring buffer type directly. The test module is embedded inline in mod.rs rather than in a separate test file, mixing module structure with test infrastructure.


### primitive type audit of the types

This file defines every scalar identifier, capacity constant, enum, and struct that the rest of the IPC module shares. It also owns the temporal wire format helpers and the Capability struct including its cryptographic token logic.

Constants defined:

| Constant | Value | Purpose |
|---|---|---|
| MAX_MESSAGE_SIZE | 512 | Maximum bytes per message payload |
| MAX_CAPS_PER_MESSAGE | 16 | Maximum capabilities per message |
| CHANNEL_CAPACITY | 4 | Maximum queued messages per channel |
| MAX_CHANNELS | 16 | Maximum live channels in the registry |

Core types implemented: EventId packs a 32-bit source PID, a 16-bit channel sequence, and a 16-bit message sequence into a 64-bit value. The EventId::new constructor assembles the value and EventId::parts decomposes it for audit correlation. ChannelId and ProcessId are u32 newtypes. CapabilityType is a repr(u32) enum with five variants: Generic, Channel, Filesystem, Store, and ServicePointer. TemporalIpcPhase defines the four-state temporal protocol phase machine. TemporalSessionState carries the session identifier, current phase, and request tracking fields. ChannelProtocolState is an enum over Unbound and Temporal(TemporalSessionState).

Capability struct: The Capability struct carries cap_id, ticket_id, object_id, rights, cap_type, owner_pid, issued_at, expires_at, flags, extra words, and a SipHash-2-4 token. The sign method computes and stores the token. The verify method recomputes the token and compares it, returning a boolean. The token payload is an 80-byte array encoding all fields in little-endian order with a fixed context tag and wire version.

TypedServiceArg trait: Defines a codec interface with type_tag, encoded_len, encode_into, and decode_from methods. Implementations exist for u8, u32, u64, and [u8; N]. All implementations use little-endian byte order.

Temporal wire helpers: Twelve internal functions prefixed temporal_ipc_ handle appending and reading u16, u32, and u64 values from byte buffers, parsing request and response frame headers, and extracting the session ID. These functions take Vec<u8> mutable references for appending and byte slice references for reading, and all return typed errors on truncated input.

Active gaps: Capability::verify is implemented and correct but is never called on the message dequeue path. Capabilities are signed when added to a message via Message::add_capability but the token is not verified when a message is received. The TypedServiceArg trait is defined and tested in isolation but is not used in any IPC send or receive path, making it preparatory infrastructure without active wire integration. The temporal_ipc_append functions take a &mut Vec<u8> argument, tightly coupling the serialization helpers to heap-backed storage and preventing their use with fixed-size stack buffers. ProcessId and ChannelId accept any u32, including zero, with no validation at construction time.


### message object audit

This file owns the Message struct and its four constructors, the capability attachment logic, the payload accessor, and the global message sequence counter.

Message struct layout:

| Field | Type | Purpose |
|---|---|---|
| id | EventId | Unique causal identity stamped at construction |
| cause | Option<EventId> | Optional link to the causally preceding message |
| payload | [u8; 512] | Fixed-size byte payload |
| payload_len | usize | Number of valid bytes in payload |
| caps | [Option<Capability>; 16] | Capability transfer slots |
| caps_len | usize | Number of occupied capability slots |
| source | ProcessId | Process that created the message |

Message::new allocates a fresh identity using the global MSG_SEQ counter and zero-initializes both the payload array and all capability slots. Message::with_data calls new then copies the provided slice into the payload array, rejecting slices longer than MAX_MESSAGE_SIZE with IpcError::MessageTooLarge. Message::with_cause creates an empty message and sets the cause field. Message::with_data_and_cause combines both.

Message::add_capability rejects insertion beyond MAX_CAPS_PER_MESSAGE. On overflow, if the capability has a nonzero ticket_id it calls rollback_ipc_transfer on the capability manager before returning IpcError::TooManyCaps. On success it clones the capability, calls sign to compute the token, and stores the signed copy in the next slot.

Message::payload returns a slice bounded by payload_len, ensuring that the unused portion of the fixed array is never visible to the caller. The Debug implementation omits the raw payload array and capability values, printing only payload_len, caps_len, id, cause, and source, which prevents accidental data leakage through debug formatting.

Active gaps: The global MSG_SEQ counter uses Ordering::Relaxed for its fetch_add, which is atomically correct for unique ID allocation but does not guarantee that messages created on different cores will have globally ordered sequence numbers relative to other memory operations. Capability slots beyond caps_len in the caps array are not cleared before a Message is created through new because the array is initialized to [None; MAX_CAPS_PER_MESSAGE] at construction. However, since Message derives Clone and Copy, cloning a received message before clearing it could produce two accessible copies of in-flight capabilities. There is no test explicitly verifying that the unused payload bytes beyond payload_len remain zero after construction.


### channel rights and endpoint capability audit

This file defines the three-bit rights system, the kernel-internal channel capability token, and the affine endpoint delegation wrapper.

ChannelRights bitfield:

| Constant | Bit value | Meaning |
|---|---|---|
| NONE | 0 | No rights |
| SEND | 1 | May enqueue messages |
| RECEIVE | 2 | May dequeue messages |
| CLOSE | 4 | May initiate closure |
| ALL | 7 | All three rights |

The factory constructors send_only, receive_only, send_receive, all, and full (alias for all) construct the common access patterns. The has method performs a bitwise AND check.

ChannelCapability struct: Carries cap_id, channel_id, rights, and owner (a ProcessId). The can_send, can_receive, and can_close methods delegate to ChannelRights::has. There is no timestamp, no expiry, and no cryptographic token bound to this struct. It is a lightweight kernel-internal type, not the wire-level Capability from types.rs.

AffineEndpoint wrapper: AffineEndpoint<const CAPACITY> wraps a LinearCapability<ChannelCapability, CAPACITY> from the math module. The delegate_zero_sum<A, B> method enforces that A + B == CAPACITY at the type level via LinearCapability::affine_split, returning an error if the constraint is not satisfied. This makes capacity duplication a compile-time impossibility for properly typed delegation chains.

Active gaps: ChannelCapability can be freely constructed with any rights combination including ChannelRights::all() by any kernel code that knows the channel ID and a ProcessId. There is no signature or token binding the capability struct to a specific grant event, so any code with knowledge of the field values can synthesize a valid-looking ChannelCapability without going through the capability manager. The AffineEndpoint delegation is not tested for the failure case where the two delegated capacities do not sum to the original, nor for the case where a delegated endpoint is used after the delegator has been consumed. No revocation bit exists inside ChannelCapability; revocation must be handled entirely at the table level, meaning a held reference to a ChannelCapability struct remains structurally valid even after the underlying channel is purged.


### fixed queue audit

This file wraps a VecDeque<Message> with a simple bounded FIFO interface that enforces CHANNEL_CAPACITY as the maximum occupancy.

Interface:

| Method | Behavior |
|---|---|
| new | Allocates a VecDeque pre-reserved at CHANNEL_CAPACITY |
| push | Enqueues one message; returns IpcError::WouldBlock if full |
| pop | Dequeues the front message, returning None when empty |
| peek | Returns a copied front message without removing it |
| iter | Yields copied values of all messages in FIFO order |
| clear | Removes all messages |
| len | Current occupancy count |
| is_empty | True when occupancy is zero |
| is_full | True when occupancy is at or above CHANNEL_CAPACITY |

Every method that yields a message returns it by value. peek and iter both use .copied() to avoid holding references to the internal VecDeque, which is correct given that the ring buffer is protected at the channel lock level rather than within RingBuffer itself.

The is_full check is a >= CHANNEL_CAPACITY comparison rather than an equality check. Because VecDeque is pre-reserved at CHANNEL_CAPACITY and push checks fullness before inserting, the VecDeque will never reallocate after the initial reservation. The backpressure layer’s saturation logic independently prevents sends above CHANNEL_CAPACITY via admission control.

Active gaps: VecDeque is heap-allocated at channel creation time and is not compatible with a no-alloc configuration. The buffer depends on the global allocator functioning correctly at the point a new channel is created. peek returns a full copy of Message, which is approximately 600 bytes including the 512-byte payload array and the capability slots. This copy occurs on every admission-control check that peeks before committing to a pop. There is no explicit overflow test for calling push beyond capacity from within the ring buffer itself; the protection relies entirely on callers checking is_full before calling push, which is enforced by the admission and channel layers but not by the ring buffer itself.


### channel state machine audit

This is the largest and most complex file in the IPC module. It owns the Channel struct, the ClosureState machine, the WaitQueue, the full send and receive paths including temporal protocol integration, the temporal snapshot encode and restore logic, and the scheduler wakeup plumbing.

Channel struct fields:

| Field | Type | Purpose |
|---|---|---|
| id | ChannelId | Unique identifier |
| buffer | RingBuffer | Message queue |
| closure | ClosureState | Open/Draining/Sealed lifecycle state |
| creator | ProcessId | Process that created this channel |
| flags | ChannelFlags | Bounded, reliable, async, high-priority bits |
| priority | u8 | Scheduling priority hint |
| send_refusals | u32 | Count of refused send attempts |
| recv_refusals | u32 | Count of refused receive attempts |
| high_watermark | usize | Peak observed queue occupancy |
| high_pressure_hits | u32 | Sends observed at high-pressure level |
| saturated_hits | u32 | Sends observed at saturated level |
| sender_wakeups | u32 | Count of senders woken after a dequeue |
| receiver_wakeups | u32 | Count of receivers woken after an enqueue |
| waiting_receivers | WaitQueue | Local fixed-capacity receiver wait list |
| waiting_senders | WaitQueue | Local fixed-capacity sender wait list |
| protocol | ChannelProtocolState | Unbound or active temporal session |

ClosureState machine: The three states are Open, Draining { initiator: ProcessId, initiated_at: u64 }, and Sealed. A call to Channel::close transitions from Open to Draining if the buffer is non-empty, or directly to Sealed if the buffer is empty. The final transition from Draining to Sealed happens automatically inside try_recv when the last queued message is dequeued while the channel is draining. Both transitions emit security audit events via the security module’s log_event method.

Send path sequence:

1. backpressure::observe_send_attempt records the current pressure level and updates the hit counters.
2. admission::evaluate_send evaluates predictive restriction, rights, channel ID match, temporal protocol, closure state, and backpressure in that order.
3. If the decision is Refuse, reject_send handles the specific refusal reason, emits security module intents, rolls back ticketed capabilities if present, increments the refusal counter, and calls persist_temporal_snapshot.
4. If the decision is Defer, defer_send rolls back ticketed capabilities and returns WouldBlock.
5. If the decision is Commit, validate_temporal_send is called a second time inside send_with_observed_pressure to confirm the protocol state under lock. On success the message is pushed into the ring buffer, the protocol state advances, the queue occupancy is noted for watermark tracking, a temporal event is logged, the security module’s intent_ipc_send is invoked, one waiting receiver is woken, and persist_temporal_snapshot is called.

WaitQueue: A fixed-capacity circular buffer storing up to 16 ProcessId values in a [ProcessId; 16] array with head, tail, and len fields. push_back silently drops entries beyond the 16-item capacity. pop_front returns entries in FIFO order.

encode_temporal_snapshot_payload creates a Vec::new() with a pre-reservation of 512 bytes and serializes the full channel state in a specific binary layout: encoding version, object type, event tag, format version, channel ID, owner PID, payload length, caps length, queue depth, a PIT timestamp, closure state, protocol state with all temporal fields, seven metric counters, two wait queue lengths, all waiting PIDs, the queue depth again, and then each queued message serialized with its full payload and capabilities. This function is called on every mutating operation while the global IPC mutex is held.

Active gaps: validate_temporal_send is called once in admission::evaluate_send and again inside send_with_observed_pressure, meaning the temporal protocol is validated twice per send. While correct, the redundant call is an artifact of the layered design and could be eliminated. The encode_temporal_snapshot_payload function allocates a growable buffer on every call while holding the global IPC mutex. The WaitQueue silently drops entries beyond 16 without signaling the overflow to any caller. The temporal restore path restore_temporal_snapshot_payload manually parses the binary format with a running cursor using saturating_add for all advances, meaning a deliberately crafted short payload could cause the cursor to stall at a saturated offset without returning an error, silently ignoring the remainder of the fields.


### send/receive gate audit

This file implements the send and receive decision pipeline, producing typed SendDecision and RecvDecision values that the channel layer dispatches on without embedding policy logic in the state machine.

Send evaluation pipeline (evaluate_send):

| Step | Check | Outcome on failure |
|---|---|---|
| 1 | security().is_predictively_restricted | Refuse(PredictiveRestriction) |
| 2 | capability.can_send() | Refuse(PermissionDenied) |
| 3 | capability.channel_id != channel.id | Refuse(InvalidCapability) |
| 4 | channel.validate_temporal_send(msg) | Refuse(ProtocolMismatch) |
| 5 | channel.closure.is_closed() | Refuse(Closed) |
| 6 | channel.closure.is_closing() | Refuse(ChannelDraining) |
| 7 | backpressure::send_decision(channel) | Defer(WaitForCapacity) or Refuse(QueueFull/Backpressure) |
| — | None of the above | Commit |

Receive evaluation pipeline (evaluate_recv):

| Step | Check | Outcome on failure |
|---|---|---|
| 1 | security().is_predictively_restricted | Refuse(PredictiveRestriction) |
| 2 | capability.can_receive() | Refuse(PermissionDenied) |
| 3 | capability.channel_id != channel.id | Refuse(InvalidCapability) |
| 4 | channel.closure.is_closed() && channel.buffer.is_empty() | Refuse(Closed) |
| 5 | channel.buffer.is_empty() | Defer(WaitForMessage) |
| — | None of the above | Deliver |

Decision types exported:

| Type | Variants |
|---|---|
| SendDecision | Commit, Refuse(IpcRefusal), Defer(IpcDefer) |
| RecvDecision | Deliver, Refuse(IpcRefusal), Defer(IpcDefer) |
| IpcRefusal | PredictiveRestriction, PermissionDenied, InvalidCapability, ProtocolMismatch, Closed, ChannelDraining, Backpressure, QueueFull, QueueEmpty |
| IpcDefer | WaitForCapacity, WaitForMessage |

Active gaps: The receive pipeline does not include a temporal protocol check. Temporal receive validation (validate_temporal_recv) only happens inside try_recv after the admit decision has already been Deliver, meaning a message that violates the temporal protocol will pass the admission gate and only be rejected at the moment of dequeue. This is functionally correct but means the protocol check is not visible in the admission pipeline summary. evaluate_send calls validate_temporal_send but this check is then repeated inside send_with_observed_pressure, resulting in the temporal send protocol being evaluated twice per send operation. The QueueEmpty refusal variant in IpcRefusal is defined but is never produced by either the send or receive pipeline in the current implementation.


### pressure algebra audit

This file computes the current pressure level of a channel and translates it into a recommended action for the admission layer, and tracks hit counters for diagnostic purposes.

Pressure levels and thresholds:

| Level | Occupancy condition |
|---|---|
| Idle | Zero messages queued |
| Available | At least one message but below high-pressure threshold |
| High | At or above threshold but not full (threshold = 3 for CHANNEL_CAPACITY=4) |
| Saturated | Queue is full |

The high-pressure threshold is computed as (CHANNEL_CAPACITY * 3) / 4, which for the current constant of 4 yields exactly 3.

Action mapping:

| Pressure level | Channel flags | Recommended action |
|---|---|---|
| Idle or Available | Any | Commit |
| High | async + bounded + not high_priority | Refuse |
| High | Any other combination | Commit |
| Saturated | async | Refuse |
| Saturated | Not async | Defer |

Counter tracking: observe_send_attempt is called from the send path before admission and increments high_pressure_hits when the level is High and saturated_hits when the level is Saturated. These counters are available via ChannelDiagnostics. The BackpressureSnapshot struct captures the full instantaneous state including pending count, capacity, watermark, both hit counters, the current level, and the recommended action.

Active gaps: There is no receive-side backpressure. The system has no mechanism to signal a receiver that it is consuming too slowly relative to available capacity, or to rate-limit a process that reads and immediately discards all messages to starve legitimate consumers. The pressure level transitions have no hysteresis: a channel exactly at the high-pressure threshold can oscillate between Available and High on successive send and receive calls, potentially causing alternating Commit and Refuse decisions for an async sender at steady state. The threshold computation uses integer division, which truncates non-integer results; for configurations where CHANNEL_CAPACITY is not divisible by 4, the effective threshold could be lower than 75% by up to one message slot.


### channel registry audit

This file owns ChannelTable, the authoritative map of all live channels in the kernel. All channel creation, lookup, deletion, and batch cleanup go through this type.

ChannelTable interface:

| Method | Behavior |
|---|---|
| create_channel | Delegates to create_channel_with_flags with BOUNDED\|RELIABLE defaults and priority 128 |
| create_channel_with_flags | Enforces MAX_CHANNELS limit, allocates the next sequential ChannelId, inserts a new Channel |
| ensure_channel_with_id | Inserts a channel at a specific ID for temporal restore; advances next_id if the specified ID is ahead |
| get_mut | Mutable lookup by ChannelId |
| get | Immutable lookup by ChannelId |
| delete_channel | Removes a specific channel; returns IpcError::InvalidCap if not found |
| delete_channels_by_creator | Removes all channels whose creator field matches the given ProcessId; returns count removed |
| count | Current number of live channels |

ID allocation: The next_id field starts at 1 and increments by one for each channel created. It is never reset or reused after deletion. ensure_channel_with_id advances next_id using saturating_add(1) if the requested ID is at or above the current counter, which handles temporal restore of channels with specific historical IDs.

Backing structure: The underlying BTreeMap<ChannelId, Channel> requires Ord on ChannelId, which is derived and sorts by the wrapped u32 value. Lookup is O(log n) and deletion is O(log n). For MAX_CHANNELS = 16 the tree has at most four levels.

Active gaps: next_id is a monotonically increasing u32 that is never reset. In a long-running system with rapid channel create-and-destroy cycling, the counter will eventually exhaust the u32 range and overflow. For the current maximum of 16 channels this would require over four billion channel creation events, which is not a practical runtime risk but is structurally unbounded. The ensure_channel_with_id path uses saturating_add(1), meaning if an ID of u32::MAX is restored from a temporal snapshot, the next ID would also be u32::MAX and the next create would fail to advance beyond it. delete_channels_by_creator does not emit temporal persistence events and does not revoke capabilities from the capability manager for the channels it removes. The ChannelTable struct and its channels field are both pub, allowing any code that holds a locked table reference to call any BTreeMap method directly, including bypassing the MAX_CHANNELS guard.


### IPC service facade audit

This file is the integration layer between the raw channel operations and the rest of the kernel. It owns the global singleton, the IpcService struct with its blocking send and receive loops, and the free facade functions called by the syscall layer.

IpcService struct: Contains a spin::Mutex<ChannelTable> for the global channel registry and an AtomicU32 for monotonically allocating capability IDs. The alloc_channel_cap_id method skips zero to prevent the zero ID from ever being issued as a valid capability.

Blocking send loop: The IpcService::send method loops: lock the table, call admission::evaluate_send, if Commit call send_with_observed_pressure and return, if Refuse call reject_send and return, if Defer(WaitForCapacity) call prepare_block_on with the capacity wait address, push the current PID into waiting_senders, release the lock, then call commit_block to deschedule. If prepare_block_on fails (no schedulable context), the method falls back to defer_send returning WouldBlock.

Blocking receive loop: The IpcService::recv method follows the same structure using evaluate_recv, WaitForMessage defer, and the message wait address.

Free facade functions:

| Function | What it does |
|---|---|
| create_channel_for_process_with_flags | Creates a channel, grants a combined capability with all four rights to the capability manager, rolls back the channel on grant failure |
| send_message_for_process | Resolves a SEND capability, constructs a message, calls ipc().send |
| send_message_with_caps_for_process | Same as above but accepts a capability slice and attaches each to the message |
| receive_message_for_process | Resolves a RECEIVE capability, calls ipc().try_recv, copies payload into caller’s buffer |
| receive_message_with_caps_for_process | Same but also copies out the capability array |
| close_channel_for_process | Resolves a CLOSE capability, calls ipc().close |
| purge_channels_for_process | Calls delete_channels_by_creator directly on the locked table; returns count |
| temporal_apply_channel_event | Locks the table, calls ensure_channel_with_id, calls temporal_restore_queue |
| temporal_apply_channel_payload | Locks the table, calls restore_temporal_snapshot_payload or temporal_restore_queue depending on payload format version |

Active gaps: create_channel_for_process_with_flags grants a single capability with SEND | RECEIVE | CLONE_SENDER | CREATE rights combined, while IpcService::create_channel returns separate send-only and receive-only capabilities. These two creation paths produce different capability shapes for the same semantic operation. purge_channels_for_process does not call the capability manager to revoke capabilities, does not emit temporal persistence for the purged channels, and discards any per-channel cleanup errors silently. The receive_message_for_process function collapses the entire error surface of ipc().try_recv into a single string "No message available", losing the distinction between WouldBlock, Closed, PermissionDenied, and InvalidCap at the facade boundary.


### introspection audit

This file provides a complete, immutable snapshot of the current IPC state through two structs, ChannelDiagnostics for a single channel and IpcDiagnostics for the full system, and two query methods on IpcService.

ChannelDiagnostics fields:

| Field | Source |
|---|---|
| id, creator | Channel identity fields |
| pending, capacity, empty, full | Derived from RingBuffer |
| closure | ClosureState enum copy |
| protocol | ChannelProtocolState enum copy |
| priority, flags_bits | Channel configuration |
| send_refusals, recv_refusals | Accumulated counters |
| pressure, pressure_action | Computed by backpressure::level and backpressure::recommended_send_action |
| high_watermark, high_pressure_hits, saturated_hits | Pressure history counters |
| sender_wakeups, receiver_wakeups | Wakeup counters |
| waiting_receivers, waiting_senders | Queried from scheduler::waiter_count using the channel’s wait addresses |

IpcDiagnostics: Wraps an array of up to MAX_CHANNELS optional ChannelDiagnostics entries plus an active_channels count and max_channels constant.

The waiting_receivers and waiting_senders fields in ChannelDiagnostics are populated from the global scheduler wait table via waiter_count, not from the channel’s local WaitQueue. This means the diagnostics report the number of processes registered in the scheduler’s address-keyed wait structure, which may differ from the channel’s internal wait queue length if the overflow fallback path has been used or if the wait queue state is transiently inconsistent.

Active gaps: IpcDiagnostics has no timestamp field, so a consumer receiving two successive snapshots cannot compute rates or determine the time elapsed between observations without maintaining external timestamps. ChannelDiagnostics exposes flags_bits as a raw u32 with no decoded names, requiring consumers to independently know the bit layout of ChannelFlags. Both IpcService::diagnostics and IpcService::inspect_channel acquire the global Mutex<ChannelTable>, meaning taking a full system diagnostic snapshot blocks all concurrent IPC operations for the duration of the iteration over all channels. There is no differential snapshot API for computing deltas between consecutive reads.


### runtime validation audit

This file implements 15 deterministic runtime self-test cases executed at boot via run_selftest. The cases run against synthetic channel instances that do not enter the global channel table, and use unwrap and expect freely, which is acceptable for a controlled boot-time validation routine.

Self-test case inventory:

| Index | Name | What it validates |
|---|---|---|
| 0 | round_trip | Basic send and receive payload fidelity |
| 1 | bounded_queue_backpressure | Queue fill to capacity, overflow returns WouldBlock, refusal counter increments |
| 2 | close_drain_then_closed | Close with queued message, send rejected during drain, final recv transitions to Sealed |
| 3 | recv_aliases_try_recv_on_empty | recv and try_recv both return WouldBlock on an empty channel |
| 4 | cap_attachment_surface | Capability attachment, signed storage, field round-trip through send |
| 5 | backpressure_metrics | Watermark, high-pressure hits, saturated hits, pressure level transitions |
| 6 | async_high_pressure_policy | Async channel refuses at high pressure before saturation, recovers after dequeue |
| 7 | runtime_wakeup_surface | Two send-then-wake cycles and two recv-then-wake cycles, wakeup counters verified |
| 8 | causal_chain | Three-message root, child, grandchild causal chain preserved through channel |
| 9 | closure_drain_state_machine | Full Open → Draining → Sealed progression via drain API |
| 10 | event_id_encodes_source_seq | EventId::new and parts round-trip |
| 11 | channel_draining_admission | Send to draining channel returns IpcError::ChannelDraining |
| 12 | ticketed_capability_transfer_once | Export consumes source, tampered ticket fails import, duplicate import fails |
| 13 | temporal_protocol_typing | Full request-response temporal protocol state machine with mismatched frames rejected |
| 14 | temporal_snapshot_roundtrip | Encode and decode full channel snapshot including protocol state, wait queues, and queued messages |

Infrastructure: SyntheticWaiterGuard stages a synthetic process into the scheduler’s wait structure and removes it on drop. CapabilityTaskGuard initializes and tears down a process context in the capability and security managers around each ticketed transfer test.

Active gaps: No test covers the case where a capability with only SEND rights attempts a close operation and receives IpcError::PermissionDenied. No test exercises the WaitQueue overflow path beyond 16 entries. No test calls purge_channels_for_process and verifies its behavior. No test sends a payload of exactly MAX_MESSAGE_SIZE = 512 bytes or MAX_CAPS_PER_MESSAGE = 16 capabilities to verify boundary conditions. Case 14 does not verify that capabilities embedded inside queued messages are correctly restored with valid token values from the snapshot, only that message payload content is correct.


### syscall adapter audit

The six IPC syscall handlers translate raw register arguments into kernel-typed values, validate pointer and length bounds, copy user data into kernel buffers, call the IPC facade functions, and map the resulting string errors back to errno codes.

IPC handler summary:

| Handler | Syscall | Key validations | Calls |
|---|---|---|---|
| sys_channel_create | 10 | Capability check; allows PIDs 0-2 unconditionally | create_channel_for_process_with_flags |
| sys_channel_send | 11 | msg_len in 1..4096; ptr < 0xC0000000 | send_message_for_process |
| sys_channel_recv | 12 | buf_len in 1..4096; ptr < 0xC0000000; write-back via unsafe ptr copy | receive_message_for_process |
| sys_channel_close | 13 | None beyond routing | close_channel_for_process, then revokes capability |
| sys_channel_send_caps | 14 | msg_len in 1..4096; caps_count <= MAX_CAPS_PER_MESSAGE; all ptrs < 0xC0000000 | send_message_with_caps_for_process |
| sys_channel_recv_caps | 15 | buf_len in 1..4096; all ptrs < 0xC0000000 | receive_message_with_caps_for_process |

Pointer validation model: All six handlers compare user pointers against the constant 0xC0000000 (the x86 kernel base address). This is a fixed architectural constant rather than a dynamic per-process VMA check. Pointers are validated as a single range comparison before the unsafe copy.

Error mapping: The handlers parse string errors from the facade functions. "Missing channel capability" maps to EACCES. All other errors from send handlers map to EIO and from receive handlers map to EAGAIN.

Active gaps: The length validation in sys_channel_send accepts up to 4096 bytes, while MAX_MESSAGE_SIZE is 512 bytes. The kernel allocates a heap vector of the full user-supplied length before the IPC layer rejects the oversized message with IpcError::MessageTooLarge, meaning a malicious user can force a 4 KB heap allocation per failed send attempt. The pointer bounds check uses the x86-specific constant 0xC0000000 and is not a proper per-process VMA validation. Error string matching ("Missing channel capability") is fragile: renaming or changing the error string in a facade function silently breaks the errno mapping without any compile-time warning. The SYSCALL_STATS counter struct uses static mut fields updated via unsafe blocks without any synchronization primitive, which is a data race under multi-core execution. sys_channel_create bypasses the capability check for caller PIDs 0, 1, and 2, a policy exception that is not documented in the capability subsystem and is not enforced by the capability manager.


### specification alignment audit

The primary IPC specification document at docs/ipc/oreulia-ipc.md describes the channel model, the admission control stages, the backpressure policy, the blocking behavior distinction between the service layer and the channel layer, the closure lifecycle, and the file layout. It also describes the capability rights model and the ticketed transfer semantics.

Alignment between spec and implementation:

| Spec claim | Implementation state |
|---|---|
| All IPC is message-passing with no shared memory | Verified: no shared memory mechanism exists in any IPC file |
| Channels have four capacity constants as listed | Verified: constants match in types.rs |
| File layout table with 13 modules | Verified: exact 1:1 match with actual module declarations in mod.rs |
| Admission checks predictive restriction, rights, channel ID, closure, backpressure | Verified: admission.rs implements this order |
| Service layer blocks; channel layer returns WouldBlock | Verified: IpcService::send and IpcService::recv loop with scheduler block; Channel::try_recv is non-blocking |
| Open/Draining/Sealed closure model with specific behavioral guarantees | Verified: ClosureState machine in channel.rs matches |
| Ticketed one-time capability transfer | Verified: export_capability_to_ipc and import_capability_from_ipc with ticket ledger |

Active gaps: The specification does not document the wait address derivation formula used for scheduler integration, which is ((channel_id as usize) << 2) | kind with kind 1 for message availability and kind 2 for capacity. The specification describes AffineEndpoint as "linear endpoint delegation experiments" but the implementation is complete and tested, making the description outdated. The specification does not describe the temporal snapshot encode and restore mechanism, the binary wire format, or the versioning constants. The specification file does not reference any of the known limitations discovered in this audit and would benefit from a gap section linked to the audit checklist.


### Verification mapping and proof document alignment audit

The project maintains a dedicated verification workspace under docs/verification-overview.md which describes a structure under ../verification/ containing a theorem index, invariants specification, assumptions document, and CI gates. The overview explicitly lists what is not claimed to be verified: all architectures, all assembly paths, all MMU and boot boundaries, the full toolchain and hardware stack, and all subsystem composition obligations.

The 15 selftest cases in selftest.rs constitute the primary runtime evidence for IPC correctness. These cases execute at boot and produce a structured IpcSelftestReport indicating pass or fail per case with a detail string. The cases cover the core behavioral properties: FIFO ordering, capacity bounds, closure state transitions, temporal protocol typing, ticketed capability transfer one-time semantics, causal identity preservation, and full snapshot round-trip fidelity.

Properties with runtime coverage:

| Property | Evidence source |
|---|---|
| FIFO message delivery | case_round_trip, case_causal_chain |
| Capacity bound enforcement | case_bounded_queue_backpressure |
| Closure state machine transitions | case_close_drain_then_closed, case_closure_drain_state_machine, case_channel_draining_admission |
| Temporal protocol enforcement | case_temporal_protocol_typing |
| Ticketed transfer one-time semantics | case_ticketed_capability_transfer_once |
| Scheduler wakeup correctness | case_runtime_wakeup_surface |
| Snapshot encode and decode fidelity | case_temporal_snapshot_roundtrip |

Active gaps: The IPC module is not named specifically in docs/verification-overview.md, meaning it is not explicitly in scope or out of scope in the proof governance documents. There are no mechanized proofs for any IPC-specific invariant such as capability isolation (no process can receive a message intended for another), message ownership transfer (a sent message is not accessible to the sender after enqueue), or deadlock freedom for the two-phase block protocol. The selftest cases operate on synthetic channel instances that bypass the global table and the capability manager’s grant path, meaning they do not exercise the full end-to-end path that a syscall-originated IPC operation would follow. The case_temporal_snapshot_roundtrip case does not verify that capabilities embedded in queued messages have valid token values after restoration, leaving the capability token integrity of restored snapshots unverified.

The README’s file map lists the intended role of each IPC file, including channel state, admission, backpressure, table, service, diagnostics, and self-test coverage.


## IPC Constants, Limits, and Capacity Invariants

### MAX_MESSAGE_SIZE correctness

MAX_MESSAGE_SIZE is 512, declared as a const usize in types.rs. The Message struct's payload field is typed [u8; MAX_MESSAGE_SIZE], so the array size is a compile-time structural guarantee and no message can ever physically hold more than 512 bytes regardless of what the length field says. The constructors Message::with_data and Message::with_data_and_cause both reject slices longer than 512 with IpcError::MessageTooLarge before copying any bytes.

The gap is at the syscall boundary. sys_channel_send and sys_channel_send_caps validate the user-supplied length as within 1 to 4096 rather than 1 to 512. A caller sending 513 to 4096 bytes passes syscall validation, the kernel allocates a heap buffer of up to 4 KB and copies the user data into it, and then the IPC layer rejects the oversized message. The allocation and copy are wasted work before the rejection. The fix is to lower the syscall upper bound to MAX_MESSAGE_SIZE so rejection happens at the entry point before any allocation.

No documentation explains the choice of 512 over 256 or 1024. For kernel IPC the size is appropriate for control-plane messages, capability transfers, and small notifications, and it is small enough that a fully populated Message struct fits comfortably on a kernel stack frame.


### MAX_CAPS_PER_MESSAGE correctness

MAX_CAPS_PER_MESSAGE is 16, declared as a const usize in types.rs. The capability array in Message is typed [Option<Capability>; MAX_CAPS_PER_MESSAGE], making the 16-slot bound a compile-time structural constraint. Message::add_capability checks caps_len >= MAX_CAPS_PER_MESSAGE before inserting and returns IpcError::TooManyCaps on overflow. When the overflow is refused and the refused capability carries a nonzero ticket_id, rollback_ipc_transfer is called on the capability manager to release the reserved ticket.

The rollback is conditional on ticket_id != 0. A capability with a zero ticket ID that overflows the array is refused without any rollback side effect. Whether this is correct depends on whether a zero ticket ID means "no ticket reserved" or "unassigned"; this distinction is not documented in the type or in the method.

The syscall handler sys_channel_send_caps validates the user-supplied capability count against MAX_CAPS_PER_MESSAGE before constructing the message, which correctly closes the gap at the entry point. This is one of the few places where the syscall and IPC layer limits are in agreement.


### CHANNEL_CAPACITY correctness

CHANNEL_CAPACITY is 4, declared as a const usize in types.rs. RingBuffer::push checks self.is_full(), defined as buffer.len() >= CHANNEL_CAPACITY, and returns IpcError::WouldBlock before inserting if the check fires. The backing VecDeque is pre-reserved with VecDeque::with_capacity(CHANNEL_CAPACITY) at construction, so it will not reallocate as long as push never exceeds the initial reservation. The backpressure module uses CHANNEL_CAPACITY in its occupancy threshold arithmetic for both the High and Saturated level determinations.

With a capacity of 4, the high-pressure threshold lands at exactly 3, meaning the channel enters High pressure after just one message is enqueued beyond the halfway point. This is aggressive backpressure appropriate for a latency-sensitive control channel. Increasing CHANNEL_CAPACITY without re-tuning HIGH_PRESSURE_NUMERATOR and HIGH_PRESSURE_DENOMINATOR would shift all pressure levels and could make backpressure too permissive for higher-capacity configurations.

VecDeque::with_capacity is a runtime hint and not a hard upper bound enforced by the type system. The VecDeque can physically grow beyond CHANNEL_CAPACITY if the push check were bypassed. The temporal restore path calls temporal_restore_queue outside the normal admission pipeline; whether it re-applies the capacity bound is not structurally guaranteed.


### MAX_CHANNELS correctness

MAX_CHANNELS is 16, declared as a const usize in types.rs. ChannelTable::create_channel_with_flags compares self.channels.len() >= MAX_CHANNELS before allocating a new ID and returns IpcError::TooManyChannels if the table is full. ensure_channel_with_id used by temporal restore applies the same check before insertion. IpcDiagnostics uses MAX_CHANNELS as the compile-time size of its snapshot array, ensuring the diagnostics struct can always hold an entry for every possible live channel.

The channels field on ChannelTable is pub(crate), meaning any code in the kernel crate holding a locked table reference can call BTreeMap::insert directly and bypass the MAX_CHANNELS guard. This is not an external security boundary but is a structural integrity risk for internal callers.

During temporal restore, if a series of channel creation events fills the table to exactly 16 and a subsequent event tries to restore a different channel, that second restore will fail with IpcError::TooManyChannels even though both channels are legitimate. There is no mechanism to temporarily raise the cap or defer creation during a restore sequence.


### High-pressure threshold correctness

The high-pressure threshold is computed at runtime as (CHANNEL_CAPACITY × HIGH_PRESSURE_NUMERATOR) / HIGH_PRESSURE_DENOMINATOR, where HIGH_PRESSURE_NUMERATOR = 3 and HIGH_PRESSURE_DENOMINATOR = 4. For the current CHANNEL_CAPACITY = 4 this yields (4 × 3) / 4 = 3, an exact result at 75% of capacity.

Level assignment for CHANNEL_CAPACITY = 4:

| Occupancy | Pressure level |
|---|---|
| 0 | Idle |
| 1 or 2 | Available |
| 3 | High |
| 4 | Saturated |

The division is integer division, meaning for values of CHANNEL_CAPACITY that are not multiples of 4 the threshold truncates downward. If CHANNEL_CAPACITY were changed to 5, the threshold would be (5 × 3) / 4 = 3, which is 60% of capacity rather than the intended 75%. The current value of 4 divides evenly so the threshold is exact, but no compile-time assertion guards this arithmetic against future constant changes.

The threshold has no hysteresis band. A channel at exactly occupancy 3 is classified as High whether it arrived from occupancy 2 or is draining from occupancy 4. For a sender that produces messages slightly faster than the receiver consumes them, the channel oscillates between Available and High on alternate operations, causing alternating Commit and Refuse decisions for async senders at steady state.


### Queue occupancy invariant

The occupancy of any RingBuffer is always in the range 0 to CHANNEL_CAPACITY inclusive when the IPC mutex is not held. RingBuffer::push guards the upper bound with an is_full check. RingBuffer::pop calls VecDeque::pop_front, which returns None on an empty buffer rather than underflowing. The channel.send_with_observed_pressure path only calls buffer.push after admission::evaluate_send has returned Commit, meaning the full admission pipeline has confirmed the channel is not in a state that would reject the push.

The invariant is stressed by the temporal restore path. temporal_restore_queue enqueues messages outside the normal admission pipeline. If a temporal snapshot records a queue depth greater than CHANNEL_CAPACITY, the restore path may attempt to insert more messages than the ring buffer allows, and the resulting behavior depends on whether the push check fires inside the restore logic. The occupancy invariant is not mechanically guaranteed on the temporal restore path, which is a structural gap.


### Maximum in-flight memory per channel

The Message struct is a fixed-size value type. Its fields and their approximate sizes are:

| Field | Type | Approximate size |
|---|---|---|
| id | EventId (u64 newtype) | 8 bytes |
| cause | Option<EventId> | 16 bytes |
| payload | [u8; 512] | 512 bytes |
| payload_len | usize | 8 bytes |
| caps | [Option<Capability>; 16] | ~1280 bytes |
| caps_len | usize | 8 bytes |
| source | ProcessId (u32 newtype) | 4 bytes |

The Capability struct carries cap_id, ticket_id, rights, cap_type, owner_pid, object_id, issued_at, expires_at, flags, four extra u32 words, and a u64 token, totalling approximately 72 bytes before alignment padding. Option<Capability> adds a discriminant byte padded to alignment, yielding roughly 80 bytes per slot. With 16 slots, the caps array contributes approximately 1280 bytes per message.

A fully populated Message is approximately 1836 bytes including alignment padding. Every message occupies this full size regardless of how many payload bytes are actually used, because both the payload array and the caps array are fixed-size inline fields. With CHANNEL_CAPACITY = 4, the ring buffer holds at most approximately 4 × 1900 = 7600 bytes of message data plus the two fixed WaitQueue arrays at approximately 160 bytes each, bringing the per-channel buffer budget to roughly 8 KB at full occupancy.


### Maximum global IPC memory footprint

At MAX_CHANNELS = 16 and full queue occupancy the cumulative pre-reserved message storage across all ring buffers is approximately 16 × 7600 = 121,600 bytes. Added to this are the BTreeMap tree nodes for 16 channel entries (approximately 2,560 bytes), the WaitQueue pairs across all channels (approximately 5,120 bytes), channel metadata and flag fields (approximately 3,200 bytes), and transient temporal snapshot buffers.

Every mutating IPC operation calls encode_temporal_snapshot_payload, which allocates a Vec<u8> of approximately 512 bytes, serializes the full channel state into it, passes it to the temporal layer, and drops it. This allocation and deallocation occur while the IPC mutex is held. At peak throughput with 16 channels receiving concurrent sends, up to 16 such transient buffers may be in flight simultaneously.

Approximate worst-case footprint:

| Component | Bytes |
|---|---|
| 16 ring buffers at full occupancy | ~121,600 |
| 16 BTreeMap channel entries | ~2,560 |
| 16 WaitQueue pairs | ~5,120 |
| Channel metadata and flags | ~3,200 |
| Temporal snapshot transient buffers (peak) | ~8,192 |
| Total | ~141 KB |


### Saturation behavior

A channel is saturated when buffer.len() >= CHANNEL_CAPACITY and backpressure::level returns Saturated. No further messages can be enqueued until a receiver dequeues at least one.

The response to saturation depends on the sender's channel flags. An async sender receives Refuse(Backpressure), meaning the send fails immediately with IpcError::WouldBlock and send_refusals is incremented. A non-async sender receives Defer(WaitForCapacity), meaning the sender is descheduled and registered at the capacity wait address in the scheduler, and the send will be retried automatically after a wakeup.

Recovery happens through Channel::wake_one_sender, called from try_recv after a message is successfully dequeued. That function first drains the local WaitQueue one entry at a time, calling scheduler::wake_process for each waiting PID, then falls back to scheduler::wake_one on the capacity wait address to cover any senders registered through the global scheduler path. If multiple senders are simultaneously descheduled and only one message is dequeued, all waiters are eligible to wake but only one can commit; the rest re-evaluate admission, find the buffer full again if another sender committed first, and re-block. This is correct but produces contention under sustained saturation.


### Zero-capacity and overflow impossibility

All four capacity constants are const usize with positive literal values and cannot be modified at runtime. No channel creation API accepts a user-supplied capacity, so a zero-capacity channel cannot be created. The is_full check len >= CHANNEL_CAPACITY would trivially fire on every push if CHANNEL_CAPACITY were zero, making such a channel permanently unusable, but this state is structurally unreachable.

Arithmetic overflow on the normal paths is also impossible. RingBuffer push prevents occupancy from exceeding CHANNEL_CAPACITY. ChannelTable creation prevents channel count from exceeding MAX_CHANNELS. Message::with_data prevents payload length from exceeding MAX_MESSAGE_SIZE. Message::add_capability prevents capability count from exceeding MAX_CAPS_PER_MESSAGE. These four guards cover all four constants on every write path.

The temporal restore paths are the exception. temporal_restore_queue and restore_temporal_snapshot_payload populate channel state from persisted data rather than through the admission pipeline. If a persisted snapshot records state that violates one of these constants, the restore path may silently accept it. This is not arithmetic overflow in the Rust sense but is a logical invariant violation: the ring buffer could hold more messages than CHANNEL_CAPACITY if the restore logic does not re-apply the bound checks.


### Integer narrowing risks

The channel wait address is computed as (channel_id.0 as usize) << 2 | kind. On a 64-bit target usize is 64 bits and a u32 channel ID shifted left by two produces a value well within bounds. On a hypothetical 32-bit target a channel ID of 0x4000_0000 or higher would cause the shift to overflow the 32-bit usize. Because MAX_CHANNELS = 16 the maximum channel ID ever allocated is far below this threshold in practice, but no static assertion confirms the shift is safe for the target pointer width.

EventId packing involves no narrowing. The source PID is a ProcessId(u32) widened to u64 before being placed in bits 63:32. The channel sequence and message sequence are u16 values placed in lower bits via widening shifts. All assembly is widening.

The global MSG_SEQ counter is an AtomicU16 that wraps around after 65535 sequence numbers are issued. This is expected behavior and the EventId format treats the sequence field as a rolling counter, but if two messages with the same source PID, channel sequence, and message sequence coexist in the system, their EventIds are identical. Given a channel capacity of 4 and a 16-bit counter, a collision requires 65535 messages to be sent without a single channel sequence advancement, which is not a realistic runtime risk.

payload_len and caps_len are typed as usize (8 bytes on 64-bit) even though they are bounded by 512 and 16 respectively. No narrowing risk exists for storage, but comparisons against these fields should use compatible types to avoid implicit promotion of smaller operands.


### Compile-time versus runtime capacity enforcement

The payload array and capability slot array sizes are enforced at the type level:

| Bound | Compile-time enforcement |
|---|---|
| Payload fits in 512 bytes | [u8; MAX_MESSAGE_SIZE] field type in Message |
| At most 16 capability slots | [Option<Capability>; MAX_CAPS_PER_MESSAGE] field type in Message |
| Diagnostics buffer covers all channels | [Option<ChannelDiagnostics>; MAX_CHANNELS] field type in IpcDiagnostics |

The channel count and queue depth limits are enforced only at runtime:

| Bound | Runtime enforcement location |
|---|---|
| Channel count <= MAX_CHANNELS | Length check in ChannelTable::create_channel_with_flags |
| Queue depth <= CHANNEL_CAPACITY | is_full check in RingBuffer::push |
| Payload length <= MAX_MESSAGE_SIZE | Length check in Message::with_data |
| Cap count <= MAX_CAPS_PER_MESSAGE | Length check in Message::add_capability |

The channel count and queue depth limits are bypassable: ChannelTable::channels is pub(crate), making the channel count guard accessible for bypass by internal kernel code, and the VecDeque inside RingBuffer is private but the push guard is only a convention enforced by callers. No const_assert! expressions exist to verify that the high-pressure threshold arithmetic produces a meaningful result for the configured CHANNEL_CAPACITY, that MAX_CHANNELS is consistent with the diagnostics array size (which it is by construction), or that the wait address shift does not overflow the target usize width. Adding these as static assertions would catch configuration errors at compile time rather than producing silent misbehavior at runtime.


## Syscall Boundary Audit

### Syscall number validity

IPC occupies syscall numbers 10 through 15 in a repr(u32) enum. SyscallNumber::from maps those six values explicitly and maps every unrecognized u32 to Invalid. handle_syscall rejects Invalid with ENOSYS before the IPC handlers run, records a failure event, and emits an invalid-boundary observability event.

The preceding invariant check narrows the u32 number to u16 and tests only whether it is at most 64. It does not recognize the sparse syscall table, treats unused holes below 64 as valid, treats the defined JIT return number 250 as invalid, and can turn some large u32 values into apparently valid low u16 values. Dispatch remains authoritative, but the invariant result is not a correct validity decision.

### Syscall argument ABI layout

SyscallArgs is a repr(C) structure containing one u32 syscall number and five u32 arguments. i686 maps EAX, EBX, ECX, EDX, ESI, and EDI directly. x86-64 narrows RAX, RBX, RCX, RDX, RSI, and RDI to u32, while AArch64 narrows X8 and X0 through X4.

The common layout is stable as a 24-byte 32-bit register ABI, but it cannot carry native 64-bit pointers or scalar arguments. The x86-64 fast dispatcher also accepts a sixth argument and discards it. Architecture entry code and user libraries must therefore agree that every syscall address is below 4 GiB despite running on 64-bit targets.

### User pointer validation

IPC handlers reject zero-length buffers and compare pointer starts and calculated ends against 0xC0000000. Capability send and receive also compute an expected capability-array extent. These checks attempt to keep accesses below the legacy x86 kernel boundary.

They do not query the calling process's page tables, virtual memory areas, read or write permissions, ownership, guard pages, or mapping lifetime. Several additions use ordinary arithmetic and can overflow before comparison. On x86-64 and AArch64 the fixed 3 GiB ceiling is unrelated to the actual user address-space model.

### User buffer read safety

Channel send allocates a kernel vector, creates a user slice with from_raw_parts, and copies the complete requested payload before calling IPC. Capability send similarly creates a typed user slice over SysIpcCapability records and converts each entry. The channel retains only kernel-owned values after these copies.

The unsafe reads are not fault-contained. A numerically low but unmapped, partially mapped, non-readable, or concurrently unmapped range can fault in kernel context. Typed capability reads also assume user alignment suitable for SysIpcCapability. No copy-from-user primitive reports partial access or pins the mapping during the operation.

### User buffer write safety

Channel receive first copies into zeroed kernel staging arrays, then uses copy_nonoverlapping to write the returned payload prefix. Capability receive creates a mutable user slice for sixteen capability records, writes the returned entries, and finally stores the capability count.

The destination is not validated as writable or fully mapped. Payload, capability records, and count are separate unsafe writes, so a fault can expose partial output after the message has already been dequeued. The count pointer is checked only by its starting address, and no transactional copy-out preserves the message on failure.

### Capability struct ABI stability

SysIpcCapability is repr(C) and consists of seventeen u32 fields. It splits 64-bit object identity, issue time, expiry, and token into low and high halves, making its current size and field order deterministic for C-compatible callers.

The structure is private, has no version or size field, and omits Capability::ticket_id. Adding, reordering, or reinterpreting fields silently changes the user ABI. The receive call also assumes capacity for sixteen complete structures without receiving an explicit element count from user space.

### 32-bit and 64-bit field reconstruction

ipc_cap_to_sys writes each 64-bit value as low and high u32 halves. sys_cap_to_ipc reconstructs values by shifting the high half 32 bits and OR-ing the low half. This is arithmetically lossless for object_id, issued_at, expires_at, and token.

ticket_id has no representation and is reset to zero by construction. Native syscall pointers and channel IDs are also narrowed to u32 before handler execution. Tests do not cover all-zero, all-one, high-bit, and mixed-half round trips across the syscall ABI.

### Endianness assumptions

The register ABI passes numeric u32 values, so the low and high fields are interpreted as host integers rather than byte arrays. On the currently supported little-endian targets, user structures compiled with the same field definitions reconstruct values as intended.

The ABI does not declare an endian contract, byte-order conversion, or packed wire encoding. A future big-endian target or cross-endian compatibility layer would need explicit semantics for field order and structure bytes. Temporal serialization uses little-endian explicitly, but SysIpcCapability does not.

### Syscall error mapping

Handlers return SyscallResult with value set to minus one and a separate positive errno on failure. IPC maps invalid lengths to EINVAL, range checks to EFAULT, missing capability text to EACCES, empty receive to EAGAIN, send failures to EIO, close failures to EBADF, and channel creation failure to ENOMEM.

The facade converts typed IpcError values to static strings, and handlers compare selected strings. Distinct errors such as closed, draining, backpressure, protocol mismatch, oversized message, invalid capability, and internal failure collapse into broad errno values. Renaming a string can silently change authorization errors into unrelated results.

### Syscall audit logging

Every recognized syscall is audited before policy evaluation. security.audit_syscall records the caller, syscall number, and a hash of the five u32 arguments, then feeds the intent graph. IPC operations also produce channel-level security and temporal events later in their execution.

Invalid syscall numbers return before audit_syscall, so they use failure and observability records rather than the normal security audit entry. AuditEntry timestamps are currently zero, argument hashes do not preserve exact inputs, and IPC records do not consistently include Message EventId or final typed outcome.

### Syscall policy blocking

After auditing, handle_syscall asks security.syscall_policy_blocked whether predictive restrictions deny the required capability type and rights. A blocked syscall returns EACCES before dispatch. Repeated intent violations can also request process termination after handler execution.

Policy coverage depends on syscall_required_access. Unknown or unclassified calls return no required access and bypass this gate, while individual handlers may apply separate checks. The predictive policy and termination path are not documented as one stable IPC contract, and there is no proof that all six IPC calls are classified with the exact rights they exercise.

### Invalid syscall handling

SyscallNumber::from maps unknown numbers to Invalid. handle_syscall records an invalid-state failure, emits an observability marker, and returns ENOSYS without entering a handler. A negative-path test verifies that u32::MAX triggers the invariant and failure closure chain.

The test covers one value only. Sparse holes, 65 through 249, 251 and above, and values whose low sixteen bits appear valid are not exhaustively checked. Depending on invariant enforcement policy, a routine unknown syscall may also trigger fail-stop behavior before the ENOSYS path completes.

### Cross-architecture syscall consistency

The same Rust dispatcher and IPC handlers compile for i686, x86-64, and AArch64. Each architecture has a saved-register structure and maps its syscall entry registers into SyscallArgs. Results use value and errno, packed into a u64 on x86 paths and returned through X0 and X1 on AArch64.

Consistency is superficial because 64-bit register values are narrowed to u32, the pointer ceiling is x86-specific, several non-IPC syscalls return ENOSYS on AArch64, and calling conventions differ. There is no versioned architecture-neutral userspace ABI specification or cross-target conformance suite for the six IPC calls.

### IPC syscall privilege enforcement

Channel send, receive, close, and their capability variants resolve access through the capability manager using the scheduler-derived caller PID. Channel creation checks CHANNEL_CREATE, but explicitly permits PIDs zero through two when the check fails. Kernel PID zero also receives full channel authority from capability resolution.

These numeric PID exceptions live in syscall and capability code rather than a central policy object. Capability-carrying send accepts user-supplied authority envelopes instead of resolving each attached capability. Close revokes capability ID equal to channel ID, although capability IDs and channel IDs are separate namespaces, and ignores revocation failure.

### IPC syscall fuzzing targets

The repository has a negative invalid-number test and IPC self-tests below the syscall layer. It does not have dedicated fuzz targets for raw SyscallArgs, user pointer ranges, capability arrays, split-field reconstruction, flag combinations, errno mapping, or cross-architecture register adapters.

High-value targets include arithmetic wrap in pointer ranges, zero and maximum lengths, unmapped final pages, misaligned capability arrays, unknown types, contradictory rights, count-pointer aliasing, overlapping input and output, partial copy faults, invalid syscall holes, and repeated policy denials. A useful harness must model user mappings and faults rather than call handlers with host pointers alone.


## Channel Creation Audit

### Identity and capacity

Channel IDs are assigned from a monotonically increasing u32 counter starting at 1. The normal creation path increments it with plain integer addition; the temporal restore path advances the same counter with saturating arithmetic. The asymmetry is not consequential at the current channel limit of 16, but the two paths have inconsistent overflow behavior for no stated reason. Duplicate IDs are structurally impossible through the creation path because the counter only moves forward, and the channel table is a BTreeMap that would silently overwrite an existing entry if the counter ever wrapped back to a live ID. The restore path calls contains_key before inserting, so only the creation path has this theoretical exposure.

The channel count limit is enforced under the IPC mutex in both the normal creation path and the temporal restore path, so no window exists between the check and the insert. The structural risk is that the channels field on ChannelTable is pub(crate), allowing internal kernel code to insert directly through the BTreeMap and bypass the limit. Capability IDs are drawn from a separate AtomicU32 counter in the service, also starting at 1, with a skip-zero guard on wrap. These IDs occupy a distinct namespace from the capability manager's internal IDs.

### Capability ownership and endpoint semantics

The module exposes two channel creation paths with meaningfully different capability models. **IpcService::create_channel** returns two ChannelCapability values: one carrying send-only rights and one carrying receive-only rights, both bound to the same channel ID and creator PID. Neither is registered with the capability manager; the caller receives them as values and is responsible for distributing them. This correctly models separated endpoint ownership.

The facade function **create_channel_for_process_with_flags** takes the opposite approach. It registers a single combined capability through the capability manager with send, receive, clone-sender, and create rights together. Any caller using this path receives full combined access, and the capability manager holds one undivided entry rather than two distinct endpoints. Code built on the facade cannot enforce endpoint separation. The two paths are not interchangeable and have never been reconciled.

Creator PID binding is assertion-based in both paths. No code verifies that the supplied ProcessId corresponds to the actual calling process. Passing ProcessId::KERNEL when acting on behalf of a user process attributes the resulting capabilities to the wrong principal, making per-process capability lookups and audit records miss the entry.

### Flags, priority, and inert configuration

Channel creation accepts a ChannelFlags bitfield and a u8 priority value. Of the five defined flag bits — BOUNDED, UNBOUNDED, HIGH_PRIORITY, RELIABLE, and ASYNC — only ASYNC has any active effect: admission uses it to decide whether a saturated channel immediately refuses a sender or defers the send pending a wakeup. The other four bits are stored in the channel struct and not consulted by admission, backpressure, or scheduling logic.

The default configuration is BOUNDED | RELIABLE at priority 128. No call site in the current codebase passes anything else. RELIABLE is not enforced anywhere. BOUNDED is redundant with the fixed per-channel queue capacity that applies to every channel unconditionally. Priority is equally inert: no scheduling or wakeup path reads the field.

Flag validation is absent. Contradictory combinations are accepted silently. is_bounded returns true whenever the UNBOUNDED bit is absent regardless of the BOUNDED bit, so the BOUNDED flag has no semantic meaning at all.

### Atomicity, rollback, and temporal restore

The normal creation path is atomic within the IPC mutex. Capacity check, ID assignment, table insertion, and capability construction all occur under the same lock guard, with no window where a concurrent accessor can observe partial state. The facade path holds the lock across the table insertion and the subsequent capability manager call. This extended critical section creates a potential lock ordering hazard: if any execution path acquires a capability manager lock before acquiring the IPC channels lock, a deadlock cycle is possible. No lock ordering policy is documented.

Rollback on grant failure is correctly handled. If the capability grant fails in the facade path, the newly inserted channel is removed from the table while the lock is still held. The capability ID counter is not rolled back, which is correct for a monotonic counter.

The temporal restore path bypasses the creation API entirely, producing channels without capability manager registration. Processes that need to communicate over restored channels have no formal mechanism to acquire matching capabilities. Restore also causes ID space fragmentation: when channels are materialized with non-contiguous IDs, the counter advances past the gap and the skipped IDs can never be allocated by the normal creation path.


## Message Object Audit

### Fixed-size payload storage

Message stores payload data in an inline 512-byte array. The storage bound is part of the Rust type, so constructing a larger in-memory payload would require bypassing the normal type and constructor rules. Queue insertion stores the complete Message value in the channel ring rather than retaining a pointer or slice into sender-owned memory.

The fixed representation gives predictable per-message storage and prevents payload allocation inside Message itself. It also makes every queue copy include all 512 payload bytes, even when the logical payload is small.

### Payload length validation

Message::with_data and Message::with_data_and_cause reject input longer than MAX_MESSAGE_SIZE before copying. Empty payloads are valid at the Message layer, although the syscall send handlers reject a zero length. The payload accessor trusts payload_len and slices the array directly, so an invalid value above 512 would panic.

The constructors establish the bound correctly, and temporal snapshot restoration validates the decoded length before rebuilding a message. The fields remain public, however, so kernel code can construct or mutate a Message with an invalid payload_len without passing through either path.

### Payload copy correctness

Message::with_data creates a zeroed message, copies exactly data.len bytes into the beginning of the payload array, and records the same length. The source slice is not retained. Later changes to the sender's source buffer therefore cannot alter the queued message.

Temporal restoration follows the same bounded pattern by checking the encoded length, validating the remaining frame extent, copying only that range into a fresh zeroed array, and advancing the parser cursor to the first capability record.

### Zero-initialization of unused payload bytes

Message::new initializes the complete payload array to zero. Every data-bearing constructor starts from Message::new and overwrites only the valid prefix, leaving bytes after payload_len zero. Temporal restoration also starts with a zeroed array before copying the encoded prefix.

This prevents ordinary constructors and restore from retaining bytes from prior stack or heap contents. The invariant is conventional rather than encapsulated because payload and payload_len are public and a caller may overwrite either field after construction.

### Capability array initialization

Message::new initializes all sixteen capability slots to None. add_capability fills slots from index zero upward, and temporal restoration starts with a new all-None array before decoding the declared number of capability records.

The capability iterator examines only the prefix ending at caps_len and then filters out None entries. A hole inside that prefix is silently skipped rather than rejected, so direct field mutation can produce a count that no longer matches the number of capabilities returned.

### Capability count tracking

add_capability checks caps_len before indexing, signs the incoming capability, stores it in the next slot, and increments the count only after insertion. A seventeenth capability returns TooManyCaps. If the refused capability carries a transfer ticket, the method asks the capability manager to roll that ticket back.

The syscall capability send path also rejects counts above sixteen before constructing the message. As with payload_len, caps_len is public and the capabilities accessor trusts it when slicing the array, so an out-of-range value can panic and an in-range value can misdescribe sparse slots.

### Source PID binding

Message constructors accept a ProcessId and use it both as the source field and as the high-order source component of EventId. The service facade supplies the caller PID received from the syscall layer, so normal user sends are attributed to the invoking process.

Message itself does not authenticate that identity. Any kernel caller can supply another ProcessId, and direct struct construction can make source disagree with EventId::source_pid. Channel send validates endpoint authority but does not compare the capability owner, Message source, and encoded event source as one identity invariant.

### Message cloning risks

Message derives both Clone and Copy. RingBuffer::peek and RingBuffer::iter rely on that property and duplicate the complete message, including every embedded capability and transfer ticket. The send API accepts Message by value, but Copy semantics mean the caller can retain an identical value after the apparent move.

This weakens ownership claims for capability-carrying messages. The capability manager may enforce a ticket ledger independently, but the Message type does not provide affine or one-time transfer semantics and cannot prevent duplicate kernel-side attempts to use or forward the same envelope.

### Debug formatting information leakage

The custom Debug implementation reports the event identity, causal predecessor, payload length, capability count, and source PID. It deliberately omits payload bytes, capability contents, tokens, object identifiers, and rights, preventing the most direct disclosure through routine debug output.

The remaining metadata can still reveal communication relationships, message sizes, process identities, and causal structure. Debug output therefore remains audit-sensitive and should not be exposed indiscriminately to workloads or untrusted logs.

### Message construction failure modes

The data constructors fail only when the payload exceeds 512 bytes. add_capability can fail when the capability array is full, and its ticket rollback is best effort because the rollback result is discarded. Event sequence allocation cannot report exhaustion and wraps naturally at the end of the 16-bit counter.

Construction is not transactional across several capability additions. If a later insertion fails, capabilities already attached to the local message remain present and any associated transfer reservations require caller-controlled cleanup unless each failure path has already rolled them back.

### Message size denial-of-service resistance

The Message representation places hard limits on payload and capability storage, while each channel holds at most four messages. These bounds cap queued payload storage per channel and prevent unbounded growth inside the message object.

The syscall adapters weaken early rejection by accepting payload lengths up to 4096 bytes. They allocate and copy the requested buffer before Message::with_data rejects lengths above 512. Repeated invalid sends can therefore force unnecessary allocation and copying, and receive calls can similarly allocate a 4096-byte temporary buffer even though no message can contain more than 512 payload bytes.

### ABI-safe message layout concerns

Message is an internal Rust structure rather than a declared syscall or persistence ABI. It has no repr(C), contains architecture-sized usize fields, embeds Option<Capability>, and depends on Rust layout and enum niche decisions. Its size and offsets may differ across compiler versions and between 32-bit and 64-bit targets.

The syscall layer correctly uses separate user-facing fields and copies payload and capability data rather than exposing Message directly. Temporal persistence also serializes fields explicitly. That separation must remain strict: raw Message bytes are not a stable wire, disk, foreign-function, or cross-architecture format.

### Send path ownership semantics

The service constructs a Message from copied payload bytes, attaches capability values, resolves a send-capable channel endpoint, and passes the Message by value into the channel. A successful ring insertion places a self-contained value in kernel-owned queue storage. A failed insertion rolls back ticketed capabilities found in the message.

Rust move syntax does not establish exclusive transfer because Message and Capability are Copy. The API also accepts already constructed Capability values rather than a non-copy transfer guard, so ownership, attenuation, replay prevention, and ticket consumption depend on external capability-manager state rather than the message type.

### Receive path copy-out semantics

Receiving pops one Message from the queue and returns it by value. The plain facade copies the smaller of payload_len and the destination length and reports that copied count. The capability facade applies the same payload truncation and copies only as many capabilities as fit in the caller-provided capability array.

Truncation is silent and destructive because the message has already been dequeued. A short payload buffer loses the uncopied suffix, and a short capability buffer loses the remaining capability envelopes. The receive path also does not call Capability::verify before copying embedded capabilities to its output array.

### Stale data exposure prevention

Fresh construction and temporal restoration zero unused payload bytes and initialize unused capability slots to None. Payload copy-out uses only the valid prefix, capability iteration uses only the declared prefix, and syscall receive copies only the number of bytes reported by the facade. These paths do not expose the unused tail under valid metadata.

The protection depends on payload_len and caps_len remaining valid. Public fields, direct struct construction, unchecked metadata mutation, and freely copied messages can violate the invariant. Receive buffers are not cleared beyond the returned length, so callers must treat only the reported prefix as newly written data.



## Causal Event Identity Audit

### Event ID bit layout

EventId is a 64-bit value divided into three fixed-width fields. Bits 63 through 32 hold a 32-bit source process identifier, bits 31 through 16 hold a 16-bit channel sequence, and bits 15 through 0 hold a 16-bit message sequence. EventId::new assembles these fields with widening shifts, while parts, source_pid, channel_seq, and msg_seq recover them with masks and narrowing conversions.

The encoding and decoding arithmetic is internally consistent and covered by a round-trip self-test. EventId remains a public tuple struct, however, so any kernel caller can construct an arbitrary raw value without using EventId::new or satisfying the intended identity rules.

### Source PID encoding

The source process occupies the upper 32 bits without truncation because ProcessId already wraps a u32. Message::new passes source.0 into EventId::new and also stores the same ProcessId in Message::source, so constructors initially produce matching values.

The PID is descriptive rather than authenticated. Message constructors trust the supplied ProcessId, EventId is publicly constructible, and send admission does not require EventId::source_pid, Message::source, and the channel capability owner to match. PID reuse can also give an old event identifier new apparent meaning unless identity includes a process generation or boot epoch.

### Channel sequence encoding

The middle 16-bit field is available in EventId and round-trips correctly when EventId::new is called directly. Normal Message construction always passes zero for this field. No channel code stamps its own ID, local enqueue sequence, or generation into a new message identity.

The current field is therefore reserved space rather than an active channel sequence. Events created by Message::new cannot distinguish which channel carried them, and the field cannot order messages within one channel. The term channel sequence in the type documentation overstates the implemented behavior.

### Message sequence encoding

The low 16 bits come from one global AtomicU16 named MSG_SEQ. Message::new performs fetch_add and encodes the returned value. Despite comments describing a per-channel or per-process counter, the implementation uses one kernel-wide counter shared by every process and channel.

The counter provides distinct values only within one 65,536-allocation interval. Combined with source PID and the currently zero channel field, it usually distinguishes nearby messages from the same PID, but it is not a permanent unique identifier.

### Sequence wraparound behavior

AtomicU16 wraps from 65,535 to zero. No exhaustion check, generation increment, collision search, or audit event accompanies the wrap. A process that creates another message after the counter completes a full cycle can reproduce an earlier EventId because its PID and channel field are unchanged.

Temporal restoration scans restored message identities and causes, selects the largest low-order sequence value, adds one with wrapping arithmetic, and stores that value into the global counter. Numeric maximum is not a correct reconstruction rule for a wrapping sequence, and restoring one channel can move the global allocator backward relative to messages active on another channel.

### Uniqueness within process lifetime

Within fewer than 65,536 global message constructions and without counter reset, messages from the same PID receive different low-order sequence values. Different PIDs remain distinguishable through the upper field. This is enough for short self-tests and bounded local traces.

The guarantee ends at wraparound, PID reuse, direct Message construction, or temporal restore. Because the channel field is always zero and the counter is only 16 bits, uniqueness is not guaranteed for a long-lived process and is not checked before publication.

### Uniqueness across reboot/session epochs

EventId contains no boot identifier, persistence epoch, process generation, channel generation, or random session component. MSG_SEQ begins at zero on boot and may be reset from restored channel data. The same PID and sequence can therefore produce the same EventId across boots or restore sessions.

Persistent logs cannot treat raw EventId as globally unique unless they combine it with external boot and restore metadata. No such compound identity is enforced by the IPC API.

### Relaxed atomic ordering correctness

Ordering::Relaxed is sufficient to make each fetch_add indivisible and to prevent two simultaneous callers from receiving the same counter value before wrap. Event identity allocation does not itself publish shared message memory, so stronger ordering would not automatically make causal relationships valid.

Relaxed ordering does not order EventId allocation against payload writes, queue insertion, temporal records, or audit records. Consumers must use the channel lock and queue synchronization for message visibility. If sequence values are intended to define a global observation order, the present counter and memory ordering do not provide that property.

### Causal predecessor field validation

Message stores an optional EventId named cause. with_cause and with_data_and_cause copy any supplied value directly into that field. Channel admission, send, receive, and temporal restore preserve the value but do not validate it.

There is no requirement that the predecessor exists, was received by the sender, predates the child, belongs to an authorized process, belongs to the same protocol session, or differs from the child's own identity. Self-cycles, forward references, and references to fabricated events are representable.

### Causal DAG reconstruction

The root, child, and grandchild self-test proves that explicit cause links survive construction, queueing, and dequeueing. A consumer that has retained all referenced events can build directed edges from each message to its declared predecessor.

The kernel does not maintain an event index or causal graph. Missing events, overwritten audit records, ID collisions, cross-boot reuse, forged links, and cycles prevent reliable DAG reconstruction. The field provides lineage hints, not a validated directed acyclic graph.

### Forged causal linkage detection

No MAC, capability proof, session token, or event registry authenticates an EventId or cause relationship. Kernel code can construct EventId from raw bits, and a process can indirectly choose arbitrary cause data if a future syscall or service exposes that constructor without additional checks.

The receive path cannot distinguish a genuine response to a previously delivered request from a message that merely names the request's EventId. Temporal protocol validation checks session, request, opcode, and phase in payload frames, but it does not bind those checks structurally to Message::cause.

### Temporal log correlation

Full channel snapshots serialize each message ID and optional cause as explicit 64-bit values and restore them unchanged. This preserves identity metadata for queued messages across snapshot serialization.

The lightweight record_ipc_channel_event stream records channel ID, operation kind, acting process, payload length, capability count, queue depth, and scheduler ticks. It does not record Message ID or cause. A temporal send or receive event therefore cannot be joined unambiguously to a specific causal envelope when several messages share the same channel and dimensions.

### Audit trail replay correctness

Temporal snapshot restore scans queued message and cause sequences and resets MSG_SEQ to one above the largest observed low-order value. It also restores raw EventId values without validating their source, channel field, causal ordering, or uniqueness.

This preserves bytes but does not prove replay correctness. The maximum-sequence algorithm is unsafe around wrap, ignores live messages outside the restored snapshot, and lets restored data alter the global allocator. Security AuditEntry timestamps are currently initialized to zero, and most IPC audit contexts contain channel IDs rather than EventIds, further limiting deterministic replay correlation.

### Message injection detection

Channel send validates endpoint rights, channel binding, closure state, protocol state, and backpressure. These checks restrict who can enqueue a message, but they do not authenticate the message identity fields themselves.

A caller with valid send authority can submit a directly constructed Message containing a forged ID, source, or cause through public service methods. There is no duplicate-ID table, monotonicity check, per-channel origin stamp, or signature over the causal envelope. Injection may be detected by higher-level protocol validation, but EventId supplies no independent protection.

### Formal invariant coverage

Current tests prove field round-trip encoding, inequality for adjacent sequence values, preservation through a channel, and a three-message causal chain. They do not prove uniqueness over wrap, source authenticity, channel binding, acyclicity, restore monotonicity, replay resistance, or audit correlation.

No formal model states the required identity scope or causal invariants. Before EventId can be relied upon for security or persistence, the kernel needs explicit rules for creation authority, uniqueness domain, epoch behavior, predecessor validity, graph consistency, and failure handling.


## Capability-Carrying Message Audit

### Maximum capability count enforcement

Message contains sixteen optional capability slots, and add_capability rejects an insertion when caps_len has reached MAX_CAPS_PER_MESSAGE. The service facade rejects a capability slice longer than sixteen before constructing the message, and sys_channel_send_caps applies the same count limit before reading the user capability array.

The fixed array prevents unbounded attachment growth. The count remains a public usize, so direct kernel construction can still create inconsistent metadata or an out-of-range value that causes capabilities to panic when it slices the array.

### Capability insertion bounds checking

add_capability checks the count before indexing, signs a local copy, writes it into caps[caps_len], and increments caps_len afterward. A successful insertion therefore cannot write beyond the fixed array through this method, and a refused seventeenth attachment does not modify a capability slot.

The method assumes that every preceding slot is valid and that caps_len was produced by earlier calls. It does not reject sparse arrays, populated slots beyond the declared prefix, duplicate capability IDs, duplicate ticket IDs, or repeated object and rights combinations.

### Capability signing before insertion

Capability::sign computes a SipHash-based token over capability ID, ticket ID, object ID, rights, type, owner PID, validity fields, flags, and extra metadata. add_capability always calls sign immediately before storing the envelope, so later mutation of a covered field would make verify fail.

Signing does not establish provenance by itself. The syscall path reconstructs the envelope from user-controlled SysIpcCapability fields and add_capability signs that reconstruction with the kernel key. Because the path does not first resolve the claimed capability against the sender's capability table, signing can authenticate attacker-chosen metadata as a newly valid envelope.

### Capability transfer rollback on insertion failure

If add_capability is called while the message is full and the refused envelope has a nonzero ticket ID, it requests rollback from the capability manager using the envelope owner and ticket. Channel send refusal and ring insertion failure also iterate over attached capabilities and attempt to roll back every nonzero ticket.

Rollback results are discarded. The multi-capability facade attaches capabilities sequentially, so failure while attaching a later capability can leave earlier ticketed attachments reserved in the local message with no facade-level transaction that rolls all of them back.

### Ticketed capability rollback

The capability manager supports a real ticketed transfer path. export_ipc_capability removes the source capability, creates and signs an envelope, stores the original authority in a bounded pending-transfer ledger, and returns a nonzero ticket. rollback_ipc_transfer can restore the original capability and remove the ledger entry when the source PID and ticket match.

This mechanism is not integrated into sys_channel_send_caps. SysIpcCapability has no ticket field, sys_cap_to_ipc creates an envelope with ticket ID zero, and the syscall accepts capability descriptions directly from user memory. Ticketed rollback therefore protects callers that explicitly use export_capability_to_ipc, not ordinary capability-carrying IPC syscalls.

### Capability token freshness

The token covers issued_at, expires_at, ticket ID, owner, object, rights, type, flags, and extra metadata. A changed covered field invalidates an existing token, and self-tests include rejection of a tampered ticket through import_capability_from_ipc.

There is no nonce, receiver binding, channel binding, message identity, or transfer generation in the token. issued_at is copied from the original grant and expires_at is commonly zero. Re-signing in add_capability also replaces any supplied token without checking its previous validity, so the live send path does not prove freshness.

### Capability owner preservation

Capability owner_pid is included in the signed token, serialized in channel snapshots, and copied through syscall conversion. Ticket consumption compares the pending transfer's source PID and the envelope owner against the staged record. The explicit import helper receives the intended destination separately and grants new authority to that process.

The message receive facade merely copies the original envelope into caps_out. It does not replace owner_pid with the receiver, consume a transfer ticket, or install the authority in the receiver's capability table. The syscall output can therefore describe the sender as owner while giving the receiver no manager-recognized capability.

### Capability type preservation

CapabilityType is included in the token and explicit snapshot format. The syscall converter accepts only the five defined raw type values, and the explicit import path maps supported IPC types back to capability-manager types before granting authority.

Temporal snapshot decoding maps every unknown raw type to Generic rather than rejecting it. The ordinary send syscall does not verify that the claimed type matches the sender's actual capability-table entry, and the receive syscall exports the type as metadata without completing an import.

### Capability rights attenuation

The envelope carries a Rights bitmask and the explicit ticketed export path copies the rights held by the removed source capability. import_capability_from_ipc grants exactly the rights contained in a verified envelope. Service-pointer export also requires the source to hold the delegation right.

No general attenuation parameter exists in export_ipc_capability, so the standard ticketed path transfers the complete rights set. More seriously, sys_channel_send_caps accepts the user-supplied rights field and re-signs it without resolving the source grant, allowing the active syscall path to claim arbitrary rights in an envelope even though those rights are not installed for the receiver.

### Capability substitution attack resistance

The ticketed import path verifies the envelope token and compares ticket ID, source PID, source capability ID, owner, object ID, rights, and capability type against the pending ledger before consuming the transfer. This rejects substitution of the principal authority-bearing fields for a staged transfer.

The comparison omits issued_at, expires_at, flags, extra metadata, and token equality, although token verification covers those fields before ledger consumption. The ordinary syscall path bypasses the pending ledger entirely, accepts a user-selected capability identity and object, and has add_capability sign the result. It therefore does not resist substitution at the point where user data becomes a kernel envelope.

### Capability replay resistance

A nonzero ticket can be consumed only once because consume_ipc_transfer removes its pending ledger entry before granting authority. A second import with the same ticket fails because the ticket is no longer present. If destination grant fails, the import path attempts to restore and restage the source transfer.

Zero-ticket envelopes have no one-time ledger state and import_capability_from_ipc grants them after token verification. Message and Capability are Copy, so the same zero-ticket envelope can be duplicated and replayed. The live syscall path produces zero-ticket envelopes, making one-time replay protection absent there.

### Capability duplication risk

The ticketed export path removes the source capability before staging transfer and can install it for one receiver after consuming the ticket. This provides a zero-sum transfer model when callers use the export and import helpers correctly.

Capability and Message both implement Copy. Ring peeking, iteration, local variables, snapshots, and facade output can duplicate envelope values freely. Duplicate bytes are harmless only if every use is mediated by token verification and a one-time ticket ledger, which is not true for zero-ticket envelopes or the ordinary receive facade.

### One-time transfer semantics

The capability manager contains the core elements of one-time transfer: source removal, pending ticket persistence, exact-once ticket consumption, rollback, and destination grant. The transfer ledger is also serialized for temporal recovery.

The channel does not commit or consume a ticket when it enqueues or dequeues a message. Consumption occurs only when import_capability_from_ipc is called explicitly, and receive_message_with_caps_for_process never calls it. A queued capability is therefore an envelope awaiting a separate import operation rather than completed receiver authority.

### Receive-side capability validation

Channel::try_recv validates channel admission and temporal message protocol before returning a Message, but it does not call Capability::verify for attachments. receive_message_with_caps_for_process iterates the declared capability prefix and copies each envelope directly into the caller-provided array.

The syscall then converts those envelopes to SysIpcCapability and writes them to user memory. It does not verify tokens, check expiry, validate owner or source, consume tickets, confirm object existence, attenuate rights, or grant capabilities to the receiver. The secure import_capability_from_ipc helper exists but is not part of this receive path.

### Partial copy-out behavior for caps

The receive facade copies capabilities until either the message iterator ends or caps_out is full, then returns the copied count. sys_channel_recv_caps always supplies an internal sixteen-entry array and writes only caps_received records to user memory, followed by the count.

The message is removed from the queue before output capacity or user copy success is established. A shorter kernel caller buffer silently discards remaining attachments. At the syscall boundary, the handler assumes the user supplied space for sixteen records, has no capability-array length argument, and performs unsafe writes after only a fixed address-ceiling check. A fault or short mapping can lose the dequeued message and its transfer envelopes.



## Channel Rights and Authorization Audit

### Message transmission authority

ChannelRights assigns bit zero to permission to enqueue messages. ChannelCapability::can_send checks that bit, and send admission rejects an endpoint without it before checking channel identity, protocol state, closure, or backpressure. The capability-manager facade separately requires Rights::CHANNEL_SEND before synthesizing the internal endpoint.

The direct ChannelCapability constructor is public and the value is unsigned, copyable, and accepted by public service methods. Internal code can therefore manufacture transmission authority without capability-manager resolution. Admission also does not verify that capability.owner matches Message::source or the currently executing process.

### Message reception authority

ChannelRights assigns bit one to permission to dequeue messages. Receive admission checks can_receive before channel identity and queue state, while the facade resolves Rights::CHANNEL_RECEIVE from the process capability table or a remote lease.

Possession of a receive-capable ChannelCapability is sufficient for direct service calls. The channel does not authenticate the endpoint owner against scheduler identity, and the public constructor allows internal callers to create a receive endpoint for any channel and ProcessId.

### Channel closure authority

ChannelRights assigns bit two to closure permission. Channel::close checks can_close and channel ID before entering the draining or sealed lifecycle. A send-only or receive-only endpoint created by the normal split service path cannot close the channel.

The capability manager has no independent CHANNEL_CLOSE right. resolve_channel_capability requires both CHANNEL_SEND and CHANNEL_RECEIVE, then synthesizes the internal CLOSE bit. This makes closure an inferred privilege and prevents policy from granting bidirectional communication without also granting shutdown authority.

### All-rights capability risks

ChannelRights::all and full contain send, receive, and close bits. Kernel PID zero receives such an endpoint unconditionally from resolve_channel_capability. Remote-lease authorization also returns an ephemeral full endpoint for close after the earlier policy check succeeds.

The main facade channel-creation path grants send, receive, clone-sender, and create rights in one capability-manager entry. Because close is inferred from send plus receive, this combined grant also has closure authority. Compromise or accidental sharing of one all-rights capability therefore exposes the entire channel lifecycle.

### Send-only capability correctness

IpcService::create_channel constructs a ChannelCapability containing only the SEND bit. Admission accepts it for sends and rejects it for receives and closes. Existing round-trip and queue tests repeatedly use send-only endpoints for successful enqueue operations.

Coverage does not include a complete negative matrix proving that send-only endpoints fail receive, close, delegation, and capability-manager operations without state change or misleading audit records.

### Receive-only capability correctness

IpcService::create_channel constructs a separate capability containing only the RECEIVE bit. Receive admission accepts it for dequeue operations, while send admission and close reject it. Existing tests use receive-only endpoints for successful delivery and drain behavior.

As with send-only authority, the test suite lacks a systematic negative matrix. It also does not prove that a receive-only endpoint cannot be synthesized, copied across principals, or used after the underlying manager capability has been revoked.

### Close-capability enforcement

Channel::close checks the internal CLOSE bit and channel ID before changing closure state. Unauthorized close returns PermissionDenied, a mismatched channel returns InvalidCap, and repeated close during shutdown returns success without repeating the transition.

The facade resolves close by requiring send and receive manager rights rather than a distinct close permission. Direct service callers can bypass manager resolution with a constructed full endpoint, and the close method does not verify endpoint owner, token, generation, revocation, or executing principal.

### Channel ID binding inside capability

Every ChannelCapability stores one ChannelId. Send, receive, and close compare it with the target Channel::id, and IpcService uses the stored ID to select the channel table entry. The capability manager also resolves local entries by matching object_id to the requested channel, except that object ID zero acts as a wildcard.

Channel IDs have no generation. Deleting a channel and later reusing an ID can make an old endpoint refer to a different incarnation. Public fields and constructors also permit arbitrary rebinding, while wildcard manager capabilities deliberately authorize more than one channel.

### Owner PID binding inside capability

ChannelCapability records an owner ProcessId, and capability-manager resolution constructs it from the requesting PID. Predictive restriction and audit calls use this owner field when evaluating or recording an operation.

Admission does not compare owner with the channel creator, scheduler current PID, manager table owner, or Message source. Direct callers can choose any owner value, causing authorization policy and audit attribution to operate on untrusted metadata.

### Stale capability rejection

The facade asks the capability manager to verify a live local token or remote authorization before constructing an endpoint. If the channel table no longer contains the stored ChannelId, IpcService returns InvalidCap. These checks reject many revoked or deleted capabilities when callers use the facade.

ChannelCapability itself carries no generation, expiry, revocation epoch, or authentication token. A previously copied endpoint remains structurally valid, and direct service calls do not consult the manager again. ID reuse or channel replacement can therefore resurrect stale authority.

### Cross-process capability use

Local manager lookup is scoped to the requesting PID's capability table, verifies the stored token against that table owner, and returns an endpoint whose owner is the requester. This prevents a process from resolving another process's ordinary local capability through the facade.

The endpoint value is Copy and has public fields. Kernel code can pass it between processes or construct one with a different owner, and direct service methods do not authenticate current execution identity. Delegation through the manager and raw endpoint sharing therefore have different security semantics.

### Capability cloning and delegation

The capability manager defines CHANNEL_CLONE_SENDER and can represent delegation policy in its general Rights set. The main creation facade grants that right alongside send, receive, and create. ChannelCapability itself does not contain a clone-sender bit and derives Clone and Copy.

Copying an endpoint duplicates all of its channel rights without consulting CHANNEL_CLONE_SENDER, attenuating rights, recording a child grant, or updating revocation lineage. The manager's delegation policy is therefore bypassed once a raw ChannelCapability escapes.

### Affine endpoint delegation

AffineEndpoint wraps ChannelCapability in LinearCapability with a const-generic capacity. delegate_zero_sum consumes the wrapper and calls affine_split, which returns two wrappers only when A plus B equals the original capacity. Channel send and receive helpers can accept a reference to the resulting wrapper.

The split clones the underlying ChannelCapability, preserving identical rights, owner, channel ID, and capability ID in both children. Capacity units are not consumed by send or receive, are not recognized by the capability manager, and do not correspond to message quota or delegation authority. The wrapper is a local type discipline, not an authorization boundary.

### Zero-sum delegation property

LinearCapability::affine_split checks A plus B equals C before producing child wrappers, so the compile-time capacity labels conserve their numeric total for successful splits. Consuming self prevents repeated splitting through the same wrapper value.

The check occurs at runtime, A plus B can overflow usize in an extreme instantiation, and both outputs contain cloned authority. The numeric conservation proof does not establish zero-sum security authority because two independently usable full-rights endpoints exist after the split.

### Rights downgrade and attenuation tests

Current tests demonstrate successful use of send-only, receive-only, and full endpoints, and admission tests exercise selected permission failures. Capability-manager code also contains general Rights attenuation functionality.

There is no comprehensive matrix for every source and destination rights combination, no test proving CHANNEL_CLONE_SENDER is enforced for endpoint copying, and no test connecting affine capacity splits to reduced rights. Close inference from send plus receive, wildcard object IDs, remote leases, revocation, stale endpoints, and cross-process misuse require dedicated coverage.


## Admission Control Audit

### Send admission pipeline

evaluate_send applies checks in a fixed order: predictive restriction, send authority, channel ID binding, temporal protocol validity, closed state, draining state, and backpressure. It returns Commit only after every check succeeds. IpcService evaluates this pipeline while holding the channel-table lock before either committing, rejecting, or preparing a scheduler block.

Channel::send_with_observed_pressure evaluates the same pipeline again, and then calls validate_temporal_send a third time before queue insertion. The repeated checks are currently deterministic under the same lock, but they duplicate work and make the true commit contract harder to reason about.

### Receive admission pipeline

evaluate_recv checks predictive restriction, receive authority, channel ID binding, sealed-and-empty state, and empty-queue deferral. A nonempty queue produces Deliver. IpcService uses the decision to return, reject, or prepare blocking on the message wait address.

Temporal receive validation is absent from evaluate_recv. Channel::try_recv peeks the first message and validates it afterward, before pop. The receive decision is therefore incomplete until execution, unlike send admission, and callers that inspect RecvDecision alone cannot know whether delivery will succeed.

### Predictive restriction enforcement

Both pipelines query SecurityManager::is_predictively_restricted with the endpoint owner, channel capability type, and operation-specific right. A restriction produces PredictiveRestriction. Rejection then requests predictive capability revocation, records an intent denial, emits a PermissionDenied audit entry, increments refusal state, persists a snapshot, and returns IpcError::PermissionDenied.

The decision trusts capability.owner rather than authenticated current-process identity. Revocation, audit, and denial all use that field. The result is also indistinguishable from ordinary missing rights at the public error boundary, limiting policy diagnostics.

### Permission denied behavior

A missing SEND or RECEIVE bit yields PermissionDenied before channel ID, protocol, lifecycle, or queue state is examined. reject_send and reject_recv record intent_capability_denied and a PermissionDenied audit event containing the endpoint capability ID and channel context.

This ordering prevents unauthorized callers from learning later channel state through the internal decision. The raw ChannelCapability remains forgeable by kernel code, and facade string conversion collapses PermissionDenied with other failures before syscall errno mapping.

### Invalid capability behavior

A capability whose embedded ChannelId does not equal the selected channel produces InvalidCapability. The rejection path records an invalid-capability intent and audit entry, increments refusal metrics, and returns IpcError::InvalidCap.

IpcService normally selects the table entry using capability.channel_id, so this mismatch is difficult to reach through that API unless a caller invokes Channel methods directly or state is inconsistent. The check does not cover owner, token, generation, expiry, revocation, or current principal, which are more likely stale or forged-capability conditions.

### Protocol mismatch behavior

Temporal-bound send admission validates message framing, session ID, request ID, opcode, and expected phase. A failure becomes ProtocolMismatch, rolls back ticketed attachments, records a send refusal, persists state, and returns IpcError::ProtocolMismatch. Unbound channels accept the message without protocol parsing.

Receive protocol validation occurs after admission while peeking the queued message. A malformed head message remains in the queue after every failed receive and can permanently block access to later messages. Protocol failures have no dedicated security audit event, and send validation is repeated unnecessarily.

### Closed channel behavior

Send admission rejects every sealed channel before backpressure. Receive admission rejects a sealed channel only when its queue is empty, preserving the intended ability to drain pending messages if such a state exists. Closed rejection returns IpcError::Closed and records refusal metrics and temporal state.

Lifecycle checks happen after rights, channel binding, and send protocol validation. An authorized sender can therefore distinguish protocol mismatch from closure, while an unauthorized caller receives permission denial first. The information policy is implicit rather than documented.

### Draining channel behavior

Send admission checks is_closing after is_closed and returns ChannelDraining, preventing new work after close begins. Receive admission does not reject draining channels, allowing queued messages to be consumed until the final dequeue changes the lifecycle to Sealed.

This asymmetry matches graceful shutdown. The public error mapping does not preserve ChannelDraining reliably, and no admission test directly covers every combination of draining state, empty queue, pending queue, protocol mismatch, and capability rights.

### Empty queue behavior

After restriction, rights, channel ID, and sealed checks, an empty receive queue returns Defer(WaitForMessage). Blocking IpcService::recv prepares a scheduler block, records the current PID in the receiver wait queue, releases the IPC lock, and commits the block. Nonblocking try_recv converts the defer decision to IpcError::WouldBlock.

defer_recv records the condition as a receive refusal and persists a snapshot, so ordinary absence contributes to refusal counters. IpcRefusal::QueueEmpty exists but evaluate_recv never produces it. Blocking and nonblocking APIs therefore share metrics that do not distinguish expected waiting from denied delivery.

### Full queue behavior

Backpressure classifies a queue at CHANNEL_CAPACITY as Saturated. Async channels receive Refuse(QueueFull), while non-async channels receive Defer(WaitForCapacity). RingBuffer::push independently checks fullness, providing a final bound if admission and queue state diverge.

QueueFull, Backpressure, and deferred capacity all become IpcError::WouldBlock. Ticketed attachments are rolled back on both refusal and defer. Because IpcService retries the copied Message after blocking, deferred sends can retry envelopes whose pending transfer tickets were already cancelled.

### Reliable channel defer behavior

The default channel is not async, so saturation recommends Defer and the service blocks until a receiver wakes one sender. Admission tests verify that a full default channel produces WaitForCapacity.

The RELIABLE flag itself is never consulted. Every non-async channel defers at saturation whether or not RELIABLE is set. defer_send returns WouldBlock after rolling back capability tickets; IpcService treats that decision specially and blocks, but lower-level callers receive only the error.

### Async channel refusal behavior

At saturation, any async channel is refused immediately. At the High threshold, an async, bounded, non-high-priority channel is also refused before full capacity. Tests cover saturated async refusal and selected high-pressure behavior.

Contradictory bounded and unbounded flags are accepted, is_bounded is derived only from absence of UNBOUNDED, and HIGH_PRIORITY bypasses high-pressure refusal without affecting saturation. The policy is encoded across flags and backpressure helpers rather than one validated channel mode.

### Admission ordering correctness

The send order prioritizes predictive policy and rights before identity, protocol, lifecycle, and capacity. Receive follows the same first three checks, then lifecycle and queue state. This generally prevents unauthorized endpoints from probing protocol and queue details.

The two pipelines are not symmetric: send includes protocol validation while receive defers it, send checks both closed and draining, and receive checks only closed-and-empty. Service and Channel layers also evaluate decisions repeatedly. No table-driven test proves the first returned outcome for overlapping failure conditions.

### Side-channel leakage through refusal reason

Internal decisions and IpcError preserve distinctions among permission denial, invalid capability, protocol mismatch, closed, draining, and would-block. This helps trusted kernel callers recover appropriately. Rights checks occur before most state checks, reducing direct probing by callers lacking operation authority.

Authorized callers can still infer temporal phase, lifecycle, and queue pressure from errors and timing. Facade and syscall layers inconsistently collapse these distinctions, so observable behavior depends on call path. Audit and persistence work also differs by refusal type and can create timing differences.

### Auditability of admission decisions

Permission and invalid-capability refusals emit intent and security audit records. Predictive restrictions additionally request temporary revocation. All refusals and deferrals increment counters, create temporal channel events, and persist channel snapshots. Successful sends and receives emit operation intents and temporal events.

Protocol, lifecycle, queue, and backpressure refusals do not receive distinct SecurityEvent records. Temporal records encode only broad send-refused or receive-refused events, and several internal reasons collapse into WouldBlock. AuditEntry timestamps remain zero, EventId is not correlated, and rollback failure is not recorded.


## Ring Buffer and Queue Semantics Audit

### Fixed-size FIFO correctness

Each channel owns a RingBuffer whose logical capacity is CHANNEL_CAPACITY, currently four messages. RingBuffer appends with VecDeque::push_back and removes with VecDeque::pop_front, so successful operations preserve first-in, first-out order. The backing collection is private, and ordinary channel code cannot insert at the front or remove from the back.

Temporal restoration also rebuilds the queue in serialized order by repeatedly calling the same bounded push operation. FIFO correctness therefore depends on the order of the snapshot records and the standard VecDeque contract rather than custom ring-index arithmetic.

### Enqueue behavior

RingBuffer::push checks is_full before changing the collection. A full queue returns IpcError::WouldBlock and leaves the existing messages unchanged. Channel::send performs admission and temporal-protocol validation before this call, advances protocol state only after a successful insertion, updates occupancy evidence, wakes one receiver, and records temporal and security activity.

The queue accepts Message by value. Once push succeeds, the channel owns the stored copy. When insertion fails, the caller receives only an error because the Message value has already moved into push; the channel path compensates by rolling back ticketed capability transfers before returning.

### Dequeue behavior

RingBuffer::pop removes and returns the oldest message or returns None without mutation when the queue is empty. Channel::try_recv first copies the front message with peek for temporal validation, then pops it while the global channel-table lock remains held. No other IPC operation can change that channel between validation and removal.

After a successful dequeue, the channel advances receive protocol state, may transition a drained channel to sealed, wakes one sender, persists a snapshot, and returns the removed Message by value. An empty queue is converted into IpcError::WouldBlock by the channel layer.

### Empty/full detection

is_empty delegates to VecDeque::is_empty. is_full treats every depth greater than or equal to CHANNEL_CAPACITY as full, which is safer than testing equality if an internal defect ever produces an excessive depth. Diagnostics derive their empty and full fields from these same methods.

The two states are mutually exclusive while CHANNEL_CAPACITY is nonzero and the queue invariant holds. The capacity is currently a positive compile-time constant, but the code has no compile-time assertion preserving that assumption if the constant changes.

### Wraparound correctness

The IPC layer does not maintain head or tail counters. VecDeque manages its own wrapped storage, and push_back plus pop_front continue to preserve logical order when its internal head crosses the end of the allocation. This avoids the usual custom-ring risks involving modulo arithmetic, ambiguous head and tail equality, and counter overflow.

No IPC-specific test deliberately cycles through enough enqueue and dequeue operations to force the backing deque through repeated physical wraparound. Correctness is inherited from the collection implementation rather than demonstrated by the subsystem test suite.

### High watermark tracking

Channel::note_queue_occupancy records the maximum observed queue length. It runs after every successful send, after full snapshot restoration, and while synthesizing legacy restored queue state. Receives do not reduce the value, so the field represents peak occupancy for the current Channel object rather than current depth.

Because bounded insertion prevents a normal depth above CHANNEL_CAPACITY, the high watermark should remain between zero and four. Self-tests verify that filling a channel reaches the configured capacity, but the field has no epoch, reset reason, or timestamp explaining when the peak occurred.

### Memory initialization

RingBuffer::new creates an empty VecDeque with reserved capacity. It does not initialize four resident Message slots because no fixed slot array exists. Message::new initializes its own payload and capability storage before a message can enter the queue, so safe queue reads cannot expose an uninitialized logical entry.

pop and clear remove logical elements but do not scrub the VecDeque allocation. Message is copyable and has no zeroizing drop behavior, so payload bytes and capability material may remain in retired heap storage until the allocator reuses or overwrites that memory. The safe RingBuffer interface cannot read those bytes, but memory disclosure bugs elsewhere in the kernel would encounter avoidable residual data.

### Message copy semantics

Messages are stored and returned by value. Enqueue moves a Message into the deque, dequeue moves it out, while peek and iter copy complete Message values because Message implements Copy. Temporal snapshot serialization and restoration also traverse copied messages.

This behavior simplifies ownership but copies the fixed payload array and all capability slots even when payload_len and caps_len are small. The validation-before-pop path performs one full copy for peek and another move for removal, and queue inspection through iter copies every queued message.

### Queue depth invariant

The intended invariant is zero less than or equal to buffer length less than or equal to CHANNEL_CAPACITY. The private backing collection and the pre-insertion full check enforce the upper bound for normal sends. Empty pop is non-mutating, and clear restores the lower bound directly.

Snapshot restoration clears the queue and replays each serialized message through RingBuffer::push. It rejects overflow and then verifies that both the restored count and actual length equal the recorded queue depth. The older temporal compatibility helper caps synthesized depth at CHANNEL_CAPACITY, so it cannot construct an oversized queue.

### No dynamic allocation guarantee

The queue does not provide a no-allocation guarantee. RingBuffer::new calls VecDeque::with_capacity during channel construction, which requires the kernel allocator. Once capacity has been reserved, the four-message admission bound should prevent push from requiring growth, but this is an implementation consequence rather than an explicit allocator-free contract.

Other work performed around queue mutation can allocate independently. Temporal snapshot encoding creates dynamic storage while channel state is protected, and channel-table insertion also uses an allocating map. The current design is bounded in message count, not statically allocated.

### Fairness under contention

FIFO ordering applies to messages, not to competing senders or receivers. Queue operations are serialized by the IpcService channel-table mutex, so whichever runnable process acquires that lock and passes admission first commits the next operation.

The channel records local waiting process IDs in FIFO WaitQueues and wakes from the front, then falls back to scheduler wait addresses. A woken process must still reacquire locks and repeat admission. Another runnable process can win that race, so wake order does not establish commit order or strict first-waiter service.

### Starvation risk

Sustained contention can starve a sender or receiver even though queue contents remain FIFO. A process may be repeatedly woken, lose the retry race, and block again while other processes continue to commit. Priority fields and HIGH_PRIORITY flags do not currently influence queue admission or wake selection.

WaitQueue has its own fixed capacity, and unsuccessful wake attempts discard stale local entries while searching for a process that can be woken. Scheduler fallback prevents the local queue from being the only wake mechanism, but there is no starvation bound, aging policy, reservation, or per-principal quota.

### Queue inspection diagnostics

ChannelDiagnostics reports current pending depth, configured capacity, empty and full state, pressure classification, peak occupancy, pressure counters, wake counters, and scheduler-visible waiter counts. IpcService::inspect_channel takes the channel-table lock, so the returned depth and queue-state fields form one internally consistent snapshot.

Diagnostics do not expose message contents or queue order, which avoids routine payload disclosure. They also do not report enqueue and dequeue totals, oldest-message age, local WaitQueue depth, per-principal occupancy, dropped wake records, or a generation that lets observers correlate samples across channel deletion and ID reuse.

### Formal boundedness proof

The implementation has a compact informal boundedness argument: the collection is private, push rejects length at or above capacity, pop cannot increase length, clear sets length to zero, and restore uses push. All known mutation paths therefore preserve the depth bound from an initially empty queue.

This argument is not encoded as a proof, model, exhaustive state test, or runtime invariant assertion. It also covers only queued Message count. It does not bound allocator retention, temporal snapshot size, waiting processes, retry work, or the total memory consumed by all channels.

### Fuzzing boundary cases

Existing tests exercise ordinary push and pop behavior, full-queue refusal, backpressure thresholds, and high-watermark updates. They provide useful examples but do not systematically generate operation sequences over push, pop, peek, clear, close, restore, and retry behavior.

There is no dedicated fuzz target comparing RingBuffer against a simple reference FIFO. Repeated physical wraparound, failed insertion preservation, malformed snapshot depth, stale retained bytes, concurrent wake races, and long mixed operation traces therefore lack automated boundary exploration.


## Channel State Machine Audit

### Open channels accepting normal traffic

A newly constructed channel begins open. Send and receive admission allow normal traffic when capability, protocol, and queue checks pass. Open is the only state that accepts new sends.

An empty open channel defers a receiver rather than reporting closure. The explicit drain method currently reports AlreadySealed when called in this state even though the channel remains open and usable.

### Draining channels completing queued traffic

Closing a nonempty channel changes its state to draining and records the closing principal and scheduler tick. New sends are rejected, while authorized receivers may consume messages that were already queued.

The state remains draining until the final successful receive removes the last message. There is no timeout, cancellation, forced-seal policy, or guarantee that a receiver will complete the drain.

### Sealed channels rejecting further traffic

Closing an empty channel enters sealed immediately. A draining channel also becomes sealed when its final queued message is received. Sealed is terminal in the ordinary runtime API, and no method reopens the channel.

Send admission returns a closed refusal. Receive admission returns closed when the queue is empty, which should always hold for a normally reached sealed state. Temporal restoration can reconstruct sealed directly from persisted state.

### Close transition correctness

Channel::close validates close rights and channel identity before changing state. It moves an empty open channel directly to sealed and a nonempty open channel to draining. The service holds the channel-table lock during this decision, so concurrent channel operations cannot observe a partially updated closure field.

Security evidence, wakeups, temporal event recording, and snapshot persistence occur after the state mutation. They do not participate in one atomic transition.

### Drain transition correctness

The draining-to-sealed transition occurs inside try_recv after the last queued message is removed. The path marks the channel sealed, emits closure evidence, wakes blocked parties, and persists the resulting snapshot.

The explicit drain method delegates to try_recv and reports Pending or Complete. It reports AlreadySealed for both sealed and open channels, so the result cannot distinguish completed shutdown from an invalid drain request.

### Send rejection during draining

Send admission checks sealed before draining and returns the distinct ChannelDraining refusal before evaluating backpressure. New messages therefore cannot extend the queue after close begins. Capability-carrying messages follow the ordinary rejection and rollback path.

The refusal does not include the closing principal, initiation time, or remaining depth, and later API layers may collapse it into a broader IPC error.

### Receive allowance during draining

Receive admission permits a draining channel while messages remain. Authorized receivers consume the existing FIFO, and the final successful receive seals the channel automatically.

If a draining queue is unexpectedly empty before sealing, receive admission defers for a message that can never legally arrive. Normal code avoids this state, but malformed restoration or future internal mutation could expose it.

### Sealed send behavior

Every send to a sealed channel is refused before queue pressure is considered. The message is not inserted, protocol state does not advance, and ticketed capabilities are rolled back by the rejection path.

Sealing does not revoke outstanding capabilities. A stale holder can continue making rejected calls until separate cleanup removes the capability or channel.

### Sealed receive behavior

A sealed channel with an empty queue returns closed rather than waiting. This prevents receivers from sleeping for traffic that cannot arrive.

Admission tests sealed together with queue emptiness. If restoration or an internal defect creates a sealed channel containing messages, receive admission will deliver them, weakening the terminal-state invariant.

### Double-close behavior

Calling close after the channel has entered draining or sealed returns success immediately. It does not alter the initiator, timestamp, queue, or lifecycle state, making close idempotent for retrying callers.

The repeated operation creates no event, snapshot, denial, or diagnostic counter. It also does not tell the caller whether shutdown is still draining or complete.

### Close with pending messages

When messages remain, close records the caller and current tick in the draining state, emits a ClosureDraining security event, records a temporal close event with queue depth, wakes one receiver, and wakes all senders. Existing messages remain in FIFO order.

There is no bounded drain deadline or policy for abandoned messages and ticketed capabilities. A missing receiver can retain the channel and queued authority indefinitely.

### Close with empty queue

When no messages remain, close changes the state directly to sealed and emits a ClosureSealed security event. It wakes all receivers and senders so blocked operations can observe terminal closure.

The channel table entry and its capabilities are not automatically reclaimed or revoked. That work depends on separate cleanup or deletion paths.

### Wakeup behavior on close

Closing to draining wakes one receiver and all senders. Closing directly to sealed wakes all receivers and senders. The final drain receive also wakes both groups after sealing.

Wake calls are best effort. Scheduler failures are ignored, stale local waiter entries can be discarded, and close still returns success. Wake counters record successful reports but not failures or stranded waiters.

### Failure atomicity during close

Rights and channel-ID failures occur before lifecycle mutation. Once validation succeeds, closure changes before audit logging, temporal recording, wakeups, and snapshot persistence. No later failure rolls the state back.

This preserves monotonic shutdown but not transactional evidence. Temporal and persistence results are discarded, so close may report success with incomplete durable history or failed wake delivery.

### Temporal persistence during close

The close path records a compact temporal event and serializes the full channel snapshot, including closure state, queue, waiters, protocol state, and metrics. Restoration recognizes all three lifecycle states and restores the draining initiator and timestamp.

Both temporal results are ignored by close. Snapshot serialization and storage also occur while the service-level channel lock is held, allowing persistence latency to delay unrelated IPC operations.

The intended lifecycle begins open, enters draining when pending traffic exists, and becomes sealed after the queue empties. An empty channel skips draining and seals immediately.


## Send Path Audit

### Syscall send entry

Syscall numbers 11 and 14 dispatch plain and capability-carrying sends. Both derive the source process from the scheduler-provided caller PID, parse channel and buffer arguments, copy user data into kernel storage, and call the process-bound IPC facade.

The adapters accept up to 4096 bytes although Message supports only 512. Their fixed 32-bit boundary check does not prove page mapping or permissions and uses unchecked address addition.

### Service send API

The facade constructs a Message, resolves send authority, and calls IpcService::send. The service loops until the operation commits, receives a terminal refusal, or cannot prepare blocking.

Facade functions replace typed service failures with static strings, losing lifecycle, protocol, and backpressure distinctions.

### Capability resolution

resolve_channel_capability checks channel type, object identity, send rights, and security policy, then returns a PID-bound ChannelCapability. Kernel PID zero bypasses the capability table and receives all channel rights.

Resolution precedes the channel lock. Admission rechecks embedded rights and channel identity, but it does not revalidate the capability-manager entry against revocation immediately before commit.

### Message construction

Message::with_data records the source PID, assigns message identity, zero-initializes fixed storage, and copies validated data. It rejects payloads above MAX_MESSAGE_SIZE before channel mutation.

The syscall has already allocated and copied as many as 4096 bytes at that point, so oversized requests consume work before the 512-byte limit rejects them.

### Payload validation

Message construction enforces the actual 512-byte bound. The syscall independently permits 4096 bytes and rejects empty payloads even though Message can represent one.

User-range validation uses a fixed 0xC0000000 boundary. It lacks checked addition, mapped-page validation, permission checks, and an architecture-specific address-space contract.

### Capability attachment

The capability syscall limits the count, converts each ABI record into a kernel Capability, and inserts each value into the Message before resolving channel send authority.

The sequence is not one explicit transaction. Later conversion, insertion, resolution, or send failure relies on ticket rollback, and early facade errors do not prove that every prepared transfer was cancelled.

### Admission decision

Under the channel lock, admission checks predictive policy, send rights, channel identity, temporal protocol, lifecycle, and backpressure in that order. It returns commit, typed refusal, or capacity deferral.

IpcService evaluates admission before calling send_with_observed_pressure, which evaluates it again and repeats temporal validation. One logical attempt can therefore observe mutable policy more than once.

### Backpressure observation

Pressure is observed once per service-loop iteration before admission. High and saturated states increment saturating counters; reliable-style traffic defers at capacity while async traffic refuses.

Retries count as new observations, so counters measure evaluations rather than unique sends and carry no operation or principal identity.

### Channel lock scope

The global channel-table mutex covers lookup, pressure observation, admission, queue commit, protocol advancement, wake selection, audit activity, and temporal persistence. This keeps admission and mutation serialized.

It also serializes unrelated channels. Snapshot allocation, persistence, capability rollback, logging, and scheduler preparation can extend the critical section substantially.

### Scheduler block preparation

For capacity deferral, prepare_block_on runs while the channel lock is held. Registering the wait before releasing the lock prevents a receiver from freeing space in an unprotected decision-to-sleep gap.

Preparation failure becomes WouldBlock and loses scheduler-specific context. Ticketed capabilities are rolled back through the defer path.

### Sender wait-queue insertion

After preparation, the current PID is appended to the channel-local sender queue for targeted wakeup. Scheduler wait-address registration remains the fallback mechanism.

The local queue silently drops inserts after 16 entries, and absence of a current PID is not reported. Neither condition produces loss evidence.

### Block commit after lock release

The channel lock is released before commit_block deschedules the sender. This follows the two-phase scheduler protocol and avoids sleeping while holding the IPC lock.

No commit result is propagated. Correctness depends on the scheduler preserving wake-before-commit events and the prepared plan remaining valid after lock release.

### Retry loop correctness

After wakeup the service reacquires the channel and repeats pressure, capability-field, protocol, lifecycle, and capacity checks. It never assumes that wakeup guarantees available capacity.

Message is Copy, so the same value is reused across iterations. Deferral rollback can invalidate ticketed transfers before a later retry attempts to enqueue copied capability records.

### Send wakeup of receiver

Successful insertion calls wake_one_receiver while the channel lock is held. The channel scans local waiters in FIFO order and falls back to the scheduler message-wait address.

Wake failures are ignored. Send still returns success, and diagnostics record successful wake reports without failed or discarded entries.

### Temporal snapshot/persistence after send

After queue commit, the channel advances temporal protocol state, records a send event, emits a security intent, wakes a receiver, and serializes the full channel snapshot.

Event and persistence results are discarded. Snapshot creation and storage occur under the global IPC lock, and send succeeds even if durable evidence is incomplete.

### Rollback on send failure

Rejection, deferral, repeated temporal validation failure, and ring insertion failure roll back attached capabilities with nonzero ticket IDs. Message attachment also rolls back the capability that exceeds message capacity.

Rollback results are ignored, and no operation ledger proves exactly-once cleanup. Permission and invalid-capability branches in reject_send do not invoke ticket rollback.

### Reliable send semantics

A saturated non-async channel prepares a capacity wait, blocks after releasing the lock, and retries until commit or terminal refusal.

The RELIABLE flag is not consulted. Defer behavior follows absence of ASYNC, so the named reliability flag currently expresses intent rather than a separately enforced guarantee.

### Async send semantics

Async sends refuse immediately at saturation and may refuse at high pressure when bounded and not high priority. They do not prepare scheduler blocking.

High priority bypasses early high-pressure refusal but not saturation. The syscall maps expected async backpressure to EIO rather than a retry-oriented error.

### Error propagation quality

Internally, IpcError distinguishes authority, protocol, capacity, lifecycle, and construction failures.

Facades collapse those values into static strings, and syscalls map most strings to EIO. Rollback, scheduler, wake, and persistence details are also lost.

### Syscall return value correctness

Success returns the requested payload length and represents all-or-nothing queue acceptance. Capability sends do not return a capability count or transfer identity.

Missing authority maps to EACCES. Oversized Message construction, closure, draining, protocol failure, and backpressure generally collapse to EIO.


## Receive Path Audit

### Syscall receive entry

Syscall numbers 12 and 15 handle plain and capability-carrying receives. They derive the receiving principal from the scheduler, validate basic numeric arguments, allocate kernel output buffers, invoke the process-bound facade, and then copy returned data into user memory.

The syscall removes the message before touching the destination pages. Its pointer checks use a fixed 32-bit boundary and unchecked addition rather than a user-copy abstraction that proves writable mappings.

### Service receive API

IpcService exposes try_recv for immediate delivery and recv for blocking delivery. The syscall-facing facades currently call try_recv, so user syscalls receive EAGAIN on an empty channel rather than sleeping.

Facade functions convert every typed receive failure except missing authority into the same static No message available string.

### Capability resolution

The facade resolves receive authority through the capability manager using the caller PID, channel object ID, and receive right. Kernel PID zero receives an all-rights synthesized capability.

Resolution occurs before the channel lock, and dequeue admission checks only the resulting ChannelCapability fields. Revocation racing between resolution and removal is not revalidated against the capability table at commit.

### Receive admission

Admission checks predictive restriction, receive rights, channel identity, sealed-and-empty closure, and queue emptiness. A queued message is deliverable from either open or draining state.

Temporal protocol validation is absent from evaluate_recv and occurs later against a copied front message inside try_recv. This splits admission across two layers.

### Blocking receive behavior

IpcService::recv prepares a message wait while holding the channel lock, records the current PID locally, releases the lock, commits the scheduler block, and retries after wakeup.

The syscall facade does not use this API. Blocking behavior is therefore available to kernel callers but not represented by the current receive syscalls.

### Nonblocking try-receive behavior

IpcService::try_recv locks the channel table and delegates directly to Channel::try_recv. Empty queues return WouldBlock, while sealed empty channels return Closed.

The facade collapses both results into No message available, and the syscall maps them to EAGAIN. A caller cannot distinguish temporary emptiness from permanent closure.

### Receiver wait-queue insertion

Blocking receive appends the current PID to a fixed local receiver queue after scheduler preparation. wake_one_receiver uses this queue before falling back to the scheduler wait address.

Insertion silently fails after 16 entries, and absence of a current PID is ignored. No overflow or loss counter identifies receivers missing from the local queue.

### Block commit after lock release

The service releases the global channel lock before commit_block deschedules the receiver. This prevents sleeping while holding IPC state and closes the decision-to-wait race through prior scheduler preparation.

No commit result reaches IPC. Correctness depends on scheduler handling for cancellation and wake-before-commit races.

### Retry loop correctness

After wakeup, blocking recv reacquires the channel and reevaluates authority fields, lifecycle, and queue state. Competing receivers cannot rely on wakeup alone and must win admission again.

Capability-manager revocation is not re-resolved on each loop, and repeated wake losses have no fairness or starvation bound.

### Message copy-out behavior

Channel::try_recv returns a complete Message by value after removing it from the FIFO. The facade copies payload bytes into a kernel buffer, and the syscall copies those bytes into user memory.

Dequeue commits before either copy-out stage completes. A later user-memory fault cannot restore the message to its original queue position.

### Partial payload copy behavior

The facade copies the minimum of message payload length and caller buffer length and reports only the copied byte count. Excess payload bytes are silently discarded because the Message has already been dequeued.

The syscall allows buffers larger than the message maximum, but an undersized valid buffer receives truncation without an explicit required-length result.

### Capability copy-out behavior

The capability facade iterates attached capabilities and copies them into its output slice. The syscall supplies MAX_CAPS_PER_MESSAGE slots, converts copied values into SysIpcCapability records, and writes the received count separately.

Copying capability records does not visibly complete or rebind transfer tickets to the receiving principal in this path. The raw capability values are returned after message removal.

### Partial capability output buffer behavior

The facade stops when caps_out is full and still returns success with the number copied. Any remaining capabilities in the dequeued Message are dropped with no rollback, revocation, or partial-delivery error.

The current syscall always allocates the maximum kernel array and assumes the user provided room for that maximum, so facade truncation mainly affects kernel callers and future adapters.

### Sender wakeup after receive

Every successful dequeue wakes one sender because one queue slot became available. The final dequeue during draining also wakes all senders and receivers after sealing.

Wake failures are ignored, and successful receive remains committed. Diagnostics do not retain failed wake attempts or prove that a blocked sender observed the new capacity.

### Sealed empty channel behavior

Receive admission returns Closed for a sealed channel whose queue is empty, preventing a wait for impossible future traffic.

The facade and syscall erase this terminal result into No message available and EAGAIN, inviting callers to retry indefinitely.

### Draining channel receive behavior

Draining channels continue delivering queued messages. Removing the final message changes closure to sealed, emits closure evidence, and wakes blocked participants.

An inconsistent empty draining state defers rather than sealing or returning terminal status. There is no drain deadline for abandoned queued messages.

### Temporal protocol advancement after receive

try_recv validates the copied front message against temporal state before pop. After successful removal it advances the protocol using the delivered Message and persists the updated channel snapshot.

Validation is outside admission, and persistence failure is ignored. Protocol advancement cannot be rolled back if later kernel or user copy-out fails.

### Stale message exposure prevention

Message construction zeroes unused payload and capability storage, and copy-out uses payload_len and caps_len rather than the full fixed arrays. Safe receive paths therefore avoid exposing unused Message bytes.

Kernel output vectors are initialized, but retired queue storage and temporary Message values are not explicitly scrubbed. User copy faults can also leave partially written destination memory without a completion marker.

### Syscall return value correctness

Successful receive returns the number of payload bytes copied. Capability receive writes the capability count through a separate pointer and returns payload length in the syscall result.

The return value does not signal payload truncation, capability truncation, closure, or transfer identity. Most non-authority failures become EAGAIN.

### User buffer fault handling

The syscall checks numeric addresses before dequeue but performs raw unsafe writes afterward. It has no recoverable fault boundary, page pinning, copy-to-user helper, or transactional reservation of the message.

A fault during payload, capability-array, or capability-count copy can lose the dequeued message and leave partial user-visible output. The capability syscall also validates only the starting address of caps_count_ptr, not the complete four-byte writable range.


## Backpressure Audit

### Pressure level calculation

The classifier returns Idle at depth zero, Saturated at or above capacity, High at or above the configured threshold, and Available for the remaining nonzero depths. With capacity four, depths zero through four map to Idle, Available, Available, High, and Saturated.

It uses only instantaneous occupancy, not arrival rate, drain rate, message size, waiters, channel age, or principal behavior.

### Low pressure behavior

Idle and Available both recommend Commit. Admission adds no pressure-specific delay or refusal below the high threshold.

No recovery event records when a channel leaves High or Saturated pressure.

### High pressure behavior

High begins at depth three. Most channels still commit the final slot, while bounded async channels without HIGH_PRIORITY refuse early with Backpressure.

There is no hysteresis, so alternating sends and receives can repeatedly cross the threshold.

### Saturated behavior

Saturated means the queue is full. Async channels refuse with QueueFull, while non-async channels defer until a receiver frees capacity. RingBuffer::push independently enforces the bound.

These distinct outcomes are later compressed into WouldBlock or coarse syscall errors.

### High-pressure hit accounting

Each send attempt that observes High increments high_pressure_hits with saturating arithmetic. The value is included in temporal snapshots.

Retries count again, and the counter has no principal, operation, outcome, or time correlation.

### Saturated hit accounting

Each send attempt observing a full queue increments saturated_hits. Deferred and refused sends both contribute.

One logical send can increment repeatedly after losing wakeup races, and silent saturation provides no overflow evidence.

### Reliable channel defer behavior

Every non-async channel defers at saturation. IpcService prepares a capacity wait, releases the IPC lock, blocks, and retries.

The RELIABLE flag is unused, so channels without either RELIABLE or ASYNC receive the same behavior.

### Async channel refusal behavior

Async channels refuse instead of blocking at saturation. Bounded, non-priority async channels also refuse at High, reserving the final slot.

The message is not retained, ticket rollback is attempted, and syscall callers generally receive EIO rather than a retry-specific result.

### High-priority channel behavior

HIGH_PRIORITY only permits bounded async traffic to use the final slot at High pressure.

It does not affect scheduler priority, waiter order, queue share, wakeups, or saturated behavior. The numeric priority field is also unused.

### Pressure threshold correctness

The threshold is capacity multiplied by three and divided by four, with a minimum of one. Capacity four yields the exact intended value of three.

Other capacities can truncate below 75 percent, and no compile-time assertion verifies the resulting policy.

### Queue occupancy race safety

Service operations classify and mutate occupancy while holding the global channel-table mutex, preventing competing IPC mutation between decision and commit.

Direct Channel methods rely on caller synchronization, and the global lock unnecessarily serializes unrelated channels.

### Denial-of-service resistance

Fixed queue depth prevents unbounded message accumulation, and async refusal prevents async waiter growth.

The policy does not bound attempts, blocked waiters, retry frequency, persistence work, audit work, or per-principal queue use. Repeated failures can still consume CPU and global-lock time.

### Sender starvation under pressure

Each dequeue wakes one sender, but the sender must reacquire the global lock and repeat admission. Another runnable sender can take the slot first.

There is no reservation, aging, quota, or retry bound, and priority fields do not influence blocked-sender service.

### Receiver starvation under pressure

Backpressure neither schedules receivers nor reserves messages for waiting consumers. Multiple authorized receivers race after wakeup, and one can repeatedly win.

There is no slow-consumer detection, receive quota, or per-receiver fairness policy.

### Diagnostics correlation

Diagnostics report current pressure, recommended action, depth, capacity, high watermark, pressure counters, flags, refusals, wakeups, and scheduler waiter counts under one lock.

They omit time, channel generation, operation identity, principal attribution, transition counts, overflow evidence, and local WaitQueue occupancy.


## Scheduler Integration Audit

### Wait address derivation

IPC derives wait keys by shifting the 32-bit channel ID left by two bits and OR-ing a small wait kind. The result is used as a scheduler queue key rather than dereferenced as a memory address.

The scheme has no channel generation or boot epoch. Reused channel IDs therefore reuse the same scheduler keys, and the shift has no compile-time overflow assertion for narrower usize targets.

### Message wait address

The message key uses wait kind one. Receivers block on it when admission finds an empty open or draining channel, and successful sends use it for receiver wakeup.

The key identifies only channel ID and condition type. It does not identify the receiver, expected channel generation, or message sequence.

### Capacity wait address

The capacity key uses wait kind two. Non-async senders block on it when the queue is saturated, and each successful receive wakes one sender.

Closing wakes all capacity waiters because no future send can commit. As with the message key, channel-ID reuse can alias old and new channel incarnations.

### Waiting receiver queue

Each Channel also keeps a fixed local FIFO of up to 16 receiver PIDs. The blocking service appends the current PID after scheduler preparation, and wake helpers consult this queue before using the scheduler key.

Insertion silently drops overflow, and the local queue is separate from the scheduler's authoritative wait queue. The two structures can diverge after failure, cancellation, process exit, or restoration.

### Waiting sender queue

Senders have an equivalent 16-entry local FIFO. It provides targeted wake_process calls after capacity becomes available.

The queue has no generation-bearing process identity, overflow result, cancellation API, or automatic removal on process exit. Scheduler registration remains a second source of waiter state.

### Wake-one receiver behavior

wake_one_receiver removes local PIDs until wake_process reports success. If none succeeds, it calls scheduler wake_one on the message key. Successful wakes increment a saturating receiver counter.

Stale local entries are discarded, but wake errors are indistinguishable from absent processes. A locally successful wake skips scheduler-key fallback even if other registrations exist.

### Wake-all receiver behavior

wake_all_receivers drains the local PID queue and wakes every process it can. It calls scheduler wake_all only when no local wake succeeded.

This conditional fallback can leave scheduler-registered receivers blocked when at least one local PID wakes successfully but other waiters were absent from or lost from the local queue.

### Wake-one sender behavior

wake_one_sender mirrors receiver wakeup using the capacity key. It scans local sender PIDs, wakes the first valid blocked process, and otherwise asks the scheduler to wake one keyed waiter.

The selected sender receives no reservation for the newly available slot. Another runnable sender can commit before it.

### Wake-all sender behavior

wake_all_senders drains local sender PIDs and uses scheduler wake_all only if none of those local wakes succeeds. Close and final sealing invoke this path.

As on the receiver side, mixed local and scheduler-only waiters can leave some blocked because any local success suppresses the scheduler-wide wake.

### Stale waiter cleanup

Targeted wake loops remove stale local PIDs as they encounter them. Scheduler wake_process removes a successfully awakened PID from scheduler wait queues.

There is no proactive IPC cleanup when a process exits, cancels a wait, changes state, or when a channel is deleted. Stale entries persist until a later wake or snapshot replacement.

### PID reuse hazards

Local WaitQueue entries store only numeric ProcessId values. wake_process indexes the scheduler process table by that number and checks whether the current occupant is blocked.

If a PID is reused before a stale IPC entry is removed, a different blocked process can be awakened. No process generation, wait token, or channel binding protects targeted wakeup.

### Missed wakeups

IPC calls prepare_block_on while holding the channel lock, releases that lock, and then calls commit_block. Preparation verifies a current process and disables local interrupts, but scheduler queue insertion happens only during commit.

The implementation needs an explicit multiprocessor proof that another CPU cannot change the condition and issue a keyed wake before registration. commit_block suppresses internal errors, so failed registration can also look like a completed block operation.

### Thundering herd behavior

Normal send and receive progress wakes one opposite-side waiter, limiting routine contention. Close, direct sealing, and final drain wake all affected groups so every blocked operation can observe terminal state.

Wake-all can enqueue many processes that immediately contend for the global IPC lock and discover the same closed state. There is no batching, direct terminal result delivery, or wake budget.

### Scheduler failure fallback

If prepare_block_on fails, send converts the defer through channel.defer_send and receive returns WouldBlock. Wake failures are ignored after queue mutation.

commit_block returns no status and internally converts block registration failure into no context switch. IPC cannot distinguish scheduler absence, queue exhaustion, invalid current process, or a cancelled plan.

### Lock ordering with scheduler calls

IPC invokes prepare and wake functions while holding the global channel-table lock. Those functions acquire the scheduler lock. commit_block acquires only the scheduler lock after IPC releases its own lock.

No documented global order proves that scheduler code never calls back into IPC while holding its lock. Diagnostics also hold IPC while acquiring scheduler state for waiter counts.

### Blocking while holding locks

The service does not call commit_block until the channel lock guard is dropped. A process therefore does not intentionally deschedule while holding the IPC table lock.

Preparation still runs under IPC lock with interrupts disabled, and temporal persistence or other work before lock release can lengthen the interval before commit. Failure inside commit is not returned to the retry loop.

### Fairness and priority behavior

Local queues and scheduler wait queues are FIFO at insertion and wake-one selection. Once made ready, processes enter scheduler priority queues and race to reacquire IPC state.

IPC channel priority and HIGH_PRIORITY do not influence waiter selection. FIFO wake order does not guarantee FIFO completion, and no starvation bound exists.

### Tests for wait/wakeup correctness

Unit tests stage scheduler waiters and verify send wakes a receiver, receive wakes a sender, and close wakes all keyed waiters. Runtime self-tests repeat receiver and sender wake cycles with synthetic processes.

Coverage does not combine local and scheduler-only waiters, overflow local queues, PID reuse, process exit, prepare-to-commit interleavings, scheduler errors, SMP wake races, or sustained fairness.


## Locking and Concurrency Audit

### Global IPC table mutex

IpcService protects the complete ChannelTable with one spin Mutex. Creation, lookup, send, receive, close, statistics, diagnostics, cleanup, and temporal application all pass through that lock.

The design makes channel identity and mutation simple to serialize, but contention on any channel delays every other channel. A stalled external call inside one operation becomes a system-wide IPC stall.

### Channel mutation under table lock

Service-facing mutation obtains a mutable Channel reference only while the table guard is held. Queue depth, lifecycle, protocol state, counters, and local waiter lists therefore change atomically with respect to other service calls.

Channel methods remain public and do not encode the lock requirement in their types. Internal callers and tests can mutate a Channel directly, so synchronization depends on convention outside IpcService.

### Lock scope minimization

Read-only statistics hold the table lock only for lookup and copying simple values. Blocking send and receive release it before scheduler commit.

Mutating paths hold it across admission, queue copies, capability rollback, scheduler preparation and wakeup, security policy, audit logging, temporal event recording, snapshot allocation, serialization, and storage. The critical section is much broader than channel-state mutation.

### Blocking without holding IPC lock

The two-phase scheduler path prepares blocking under the IPC lock, then drops the guard before commit_block can switch context. This avoids deliberately sleeping while owning the global IPC mutex.

prepare_block_on disables interrupts, and registration occurs later during commit. If commit fails internally, IPC receives no result and continues its retry model without knowing whether the process actually blocked.

### Lock ordering with scheduler

Send, receive, close, and diagnostics acquire IPC first and then call functions that acquire scheduler state. commit_block acquires scheduler only after IPC is released.

No enforced lock-order declaration proves that scheduler code never enters IPC while holding the scheduler lock. The current direction is therefore an observed pattern rather than a checked invariant.

### Lock ordering with capability manager

Channel creation grants capabilities while holding the IPC table lock. Rejection paths can request predictive revocation, ticket rollback, or restored ticket installation while a Channel is protected by that same lock.

Capability resolution usually occurs before IPC locking, producing both capability-then-IPC and IPC-then-capability paths. Without a documented order, future callbacks or cleanup can create a cycle.

### Lock ordering with temporal subsystem

Send, receive, close, refusal, and some restore operations record temporal events or persist complete snapshots while holding IPC state. Snapshot restore also invokes capability restoration before releasing the table lock.

If temporal storage or replay acquires IPC after holding its own lock, the reverse order can deadlock. Allocation and storage latency also lengthen the global IPC critical section.

### Lock ordering with security subsystem

Admission reads predictive policy under IPC protection, while refusal and success paths emit intents and audit events before releasing the channel lock. Close also reads scheduler time and logs lifecycle evidence under the lock.

Security actions can perform policy, audit, or process-management work whose lock graph is not expressed at the IPC boundary. Reentrant security callbacks into IPC would self-deadlock on the non-reentrant spin mutex.

### Deadlock scenarios

The primary possible cycles are IPC to scheduler to IPC, IPC to capability to IPC, IPC to temporal to IPC, and IPC to security to IPC. Cross-subsystem process cleanup can combine more than two of these locks.

The codebase has no lock-rank assertions or automated lock graph. No confirmed cycle is established by this audit, but absence of a documented reverse path is not a proof of safety.

### Priority inversion

A low-priority process can hold the global IPC lock while serializing a snapshot, logging an event, or interacting with another subsystem. Higher-priority processes needing any channel must spin or wait behind it.

The spin mutex has no priority inheritance, owner diagnostics, hold-time budget, or per-channel partitioning. Channel priority does not affect lock acquisition.

### Interrupt context safety

The IPC lock is a spin mutex, and several operations allocate, access the scheduler, persist temporal state, and call security or capability services. These behaviors are unsuitable for arbitrary interrupt context.

No API-level context guard rejects interrupt handlers, and lock acquisition does not consistently disable interrupts before taking IPC. An interrupt that reenters IPC on a CPU already holding the lock can deadlock.

### Reentrancy concerns

IpcService and the global Once singleton expose synchronous calls into external subsystems while the IPC lock is held. The spin Mutex is not reentrant.

There is no recursion detector or callback boundary forbidding temporal, security, capability, scheduler, or audit code from invoking IPC. Even same-thread indirect reentry would spin forever.

### Atomic ID allocation ordering

Channel capability IDs come from AtomicU32 fetch_add. Message sequence IDs use AtomicU16. Channel IDs are allocated from a table counter under the table mutex rather than atomically.

The atomic counters provide unique fetch positions until wrap, but they do not bind IDs to object publication, revocation, boot epoch, or generation. Capability ID zero is skipped, while message sequence wrapping is accepted.

### Relaxed atomic correctness

Relaxed ordering is sufficient to obtain indivisible counter increments when the returned number is only an identifier. Surrounding Message initialization and channel publication are protected by ordinary ownership or the table lock rather than by the counter.

The code and documentation must not treat these atomics as release or acquire publication barriers. Restore can store the next message sequence with Relaxed, and concurrent creation can observe sequencing without any associated state ordering.

### Concurrent close/send/recv behavior

Service operations on one channel serialize through the global lock. Whichever operation acquires it first establishes the visible order: a committed send can precede close, close can reject a later send, and a receive can drain before or after close begins.

Receive during draining remains allowed, and the final dequeue seals the channel. Tests cover selected sequential lifecycle cases, but systematic concurrent interleavings, capability revocation, process exit, restore, and user copy-out are not exhaustively tested.

## Temporal IPC Protocol Audit

### Unbound protocol state

New channels begin unbound. Temporal send and receive validation return success without parsing the payload, and protocol advancement does nothing.

Unbound therefore means ordinary IPC rather than an unknown temporal phase. Any message shape is accepted if the remaining admission checks pass.

### Temporal session binding

Binding replaces the channel protocol field with a TemporalSessionState containing a session ID, the initial AwaitRequestSend phase, next request ID one, and cleared last-request metadata.

Binding is an internal mutable operation with no lifecycle check, capability proof, uniqueness registry, or guard against replacing an active session while messages remain queued.

### Request frame parsing

A request begins with an eight-byte little-endian session ID followed by a 16-byte header containing magic, version, opcode, flags, request ID, payload length, and reserved bytes. The parser checks minimum length, magic, version, checked scalar reads, and exact total length.

Reserved header bytes and flag semantics are not validated. The parser returns ProtocolMismatch for every structural error, providing no diagnostic reason.

### Response frame parsing

A response uses the same session prefix and a 20-byte header that adds a signed status field. It validates magic, version, length fields, and exact frame size before returning borrowed payload data.

The status range, flags, reserved bytes, and opcode-specific payload shape are not validated by the generic parser.

### Request send validation

AwaitRequestSend requires a valid request frame whose session ID matches and whose request ID equals next_request_id. Other phases reject request sends.

Opcode and flags are accepted without a service schema. Validation is repeated in the current send path before queue insertion.

### Response send validation

AwaitResponseSend requires a valid response with matching session ID, last request ID, and last opcode. This binds the response to the request most recently received.

Only one request can be outstanding. Response status, flags, payload schema, and responder authority beyond ordinary send rights are not part of temporal validation.

### Request receive validation

AwaitRequestRecv parses the queued front message and requires session ID, request ID, and opcode to match the request recorded at send time.

Validation occurs after receive admission and before dequeue. It assumes the same Channel object represents both ends of the request lifecycle and does not authenticate the frame separately from channel authority.

### Response receive validation

AwaitResponseRecv applies the same matching rules to the queued response. A valid response can be dequeued only after the corresponding response send advanced the phase.

The protocol does not validate status semantics, application payload type, capability attachments, or whether the receiving principal is the original requester.

### Request ID sequencing

The initial request ID is one. Successful request send stores that ID as last_request_id and sets next_request_id with wrapping addition. Response receive clears last-request metadata but preserves the incremented next ID.

Wrapping from the maximum u32 value to zero is accepted. There is no session epoch rollover, replay window, exhaustion error, or explicit prohibition on request ID zero.

### Opcode matching

The request opcode is stored on successful request send. Request receive, response send, and response receive all require the same opcode, preventing a response from being relabeled as another operation within the active exchange.

Opcode zero and unknown values are accepted. There is no registry connecting opcodes to allowed flags, payload formats, capability types, or principals.

### Session ID matching

Every bound frame must carry the channel's exact 64-bit session ID. Wrong-session requests and responses return ProtocolMismatch.

Session IDs are supplied by the binding caller rather than allocated or authenticated by IPC. Zero, reuse after restore, collision across channels, and cross-boot continuity are not rejected.

### Phase transition after send

A valid request send advances to AwaitRequestRecv and records request metadata. A valid response send advances to AwaitResponseRecv. Queue insertion must succeed before either transition occurs.

The advancement helper reparses the message and silently leaves state unchanged if parsing unexpectedly fails. Persistence failure after advancement does not roll the phase back.

### Phase transition after receive

Receiving the request advances to AwaitResponseSend. Receiving the response returns the session to AwaitRequestSend and clears last request ID and opcode.

The transition commits at dequeue, before facade and user copy-out complete. A later delivery fault cannot restore the prior phase or message.

### Protocol mismatch behavior

Malformed frames, wrong phase, wrong session, wrong request ID, and wrong opcode all return IpcError::ProtocolMismatch. Send rejection records refusal state and attempts ticket rollback; receive mismatch leaves the message at the queue front.

One invalid front message can permanently block every later message because receive cannot skip, quarantine, or discard it. Outer facades often collapse ProtocolMismatch into generic failure.

### Snapshot encoding

Version two snapshots serialize closure, protocol kind, phase, session ID, request counters, opcode, metrics, local waiters, queue depth, complete messages, causal IDs, and capabilities into a growable byte vector.

Encoding allocates on every mutation while IPC is locked. The format has no checksum, authentication tag, declared total length, schema hash, or canonical maximum-size assertion.

### Snapshot restore

Restore checks encoding, object type, format version, channel ID, owner, enum tags, waiter counts, queue depth, message parsing, and bounded queue insertion. It then restores ticketed capability transfers and advances the global message sequence beyond the largest restored sequence.

Fields are written directly into the live Channel as parsing proceeds. A later parse or capability-restoration failure can leave partial closure, protocol, metrics, waiters, queue, or global sequence changes.

### Temporal replay safety

Replay entry points can ensure a channel exists by persisted ID and owner, restore legacy queue summaries, or apply full snapshots. Full restore rehydrates pending capability tickets from queued messages.

These functions are publicly re-exported inside the kernel and bypass ordinary channel capability resolution. They lack an authenticated replay authority, anti-rollback version check, exclusive replay epoch, and conflict policy for live channels.

### Persistence failure handling

persist_temporal_snapshot returns a TemporalError, but send, receive, close, and refusal paths normally discard it. Runtime operations therefore succeed based on in-memory state even when durable history is missing.

There is no retry queue, degraded channel health, required persistence mode, or correlation between the operation result and failed temporal evidence.

### Temporal object corruption handling

Scalar reads use checked slice access, invalid tags fail, oversized restored queues fail through bounded push, and count mismatches are rejected. These checks prevent many direct out-of-range reads.

The object lacks integrity authentication and restoration is nontransactional. Counts can drive parsing work before semantic validation, trailing bytes are not rejected explicitly, and corrupted capability records can fail only after other state has changed.

### Formal session typing proof targets

The intended invariant is a four-phase, single-flight cycle in which request and response session, ID, and opcode remain equal and only successful queue operations advance state.

No formal model proves phase progress, replay resistance, deadlock freedom, request-ID exhaustion, snapshot equivalence, or atomic restoration. Existing self-tests cover one valid exchange, selected mismatches, and snapshot round trips.


## Channel Table Audit

### Channel registry storage

ChannelTable stores channels in a heap-backed BTreeMap keyed by ChannelId and tracks the next normal ID in a u32 counter. The IpcService mutex serializes access to the map.

The ordered map gives deterministic lookup and iteration but is larger machinery than the maximum of 16 live channels requires. The pub(crate) map field also allows internal callers to bypass table policy.

### Channel insertion

Normal insertion checks the live-channel limit, takes next_id, increments it, constructs a Channel, and inserts it into the map. Creation with default flags delegates to the same path.

Insertion does not check whether the generated ID already exists. After counter wrap, BTreeMap::insert can replace a live channel and silently discard its queue and state.

### Channel lookup

get performs an immutable BTreeMap lookup and returns None for an absent ID. Service methods convert absence into InvalidCap before accessing channel state.

Lookup uses only the numeric ID. It does not verify generation, creator, capability, lifecycle, or whether the ID belongs to the current boot or restore epoch.

### Mutable lookup

get_mut returns a mutable Channel reference while the caller holds mutable table access. IpcService uses it under the global table mutex for send, receive, close, and restoration.

The reference itself carries no guard or lifetime generation beyond Rust borrowing. Direct internal callers can mutate lifecycle, queue, protocol, and counters without ordinary service admission.

### Channel deletion

delete_channel removes one map entry and returns InvalidCap when absent. It does not decrement next_id, so ordinary deletion does not intentionally recycle identifiers.

Removal does not close the channel, wake waiters, cancel queued capability tickets, persist a tombstone, revoke grants, or scrub queued messages before dropping the object.

### Delete-by-creator behavior

delete_channels_by_creator retains every channel whose creator differs from the exiting process and returns the number removed. purge_channels_for_process invokes it under the global table lock.

Creator is not the same as current authority ownership. Delegated users can lose channels created by an exiting process, while channels created by another process can retain resources owned by the exiting process.

### Ensure-channel-with-ID behavior

Temporal restore calls ensure_channel_with_id. Existing IDs return their current Channel without checking that the supplied creator matches. Missing IDs are inserted with default flags and next_id advances beyond the restored ID using saturating addition.

ID zero and arbitrary high IDs are accepted. If next_id saturates at u32 maximum, later normal creation can repeatedly target the same identifier.

### Temporal restore channel creation

Legacy events and full snapshots can create channels directly from persisted channel and owner IDs. This path bypasses normal capability grant, channel publication policy, custom flags, and creation audit.

Full snapshot restore may then overwrite the newly created Channel incrementally. Existing live channels with the same ID are reused rather than replaced through a generation transition.

### Maximum channel enforcement

Both normal creation and missing-ID restore reject insertion when map length reaches MAX_CHANNELS, currently 16. The check and insertion occur under one table lock.

The map field remains pub(crate), so crate-internal code can insert directly. The capacity limit controls live entries but not allocation churn, historical IDs, waiters, snapshots, or delegated capabilities.

### ID reuse policy

Normal operation monotonically advances next_id and does not reuse IDs after deletion. Restore advances it past the highest restored ID, leaving gaps unused.

There is no explicit exhaustion policy. Plain addition can wrap, restore uses saturation, and neither path attaches a generation or boot epoch to the ID.

### Stale capability after deletion

After deletion, service lookup rejects stale channel capabilities because their numeric channel ID is absent. This prevents direct use until an entry with the same ID appears again.

Capabilities are not proactively revoked or notified. If wrap or restore recreates the same numeric ID, a stale ChannelCapability can acquire unintended meaning because it carries no generation.

### Registry consistency under failure

The facade inserts a channel before granting its capability. If grant fails, it removes the new map entry while retaining the table lock. This keeps the channel count consistent in the expected rollback path.

The delete result is ignored, next_id is not restored, and no audit records the abandoned ID. Temporal restore is not transactional and can leave a newly inserted or partially modified channel after later failure.

### Table diagnostics

Diagnostics iterate the map under the table lock and copy at most MAX_CHANNELS ChannelDiagnostics records into a fixed array. active_channels reflects the number copied.

The output has no table generation, next_id, insertion or deletion counters, capacity-loss evidence, tombstones, or indication that capability and waiter cleanup remains pending.

### Table iteration safety

BTreeMap values are traversed while immutable table access is held, so insertion and deletion cannot invalidate the iterator. Ordering is ascending ChannelId and therefore deterministic.

External subsystem calls made while building per-channel diagnostics acquire scheduler state under the IPC lock. Iteration is bounded by MAX_CHANNELS but can still participate in lock-order contention.

### Fuzzing create/delete cycles

The code has focused creation, capacity, restore, and service tests, but no stateful fuzz target drives long create, delete, restore, purge, grant-failure, wrap, and stale-capability sequences.

Counter exhaustion, arbitrary restored IDs, duplicate identities, delegated ownership, concurrent cleanup, and registry/capability divergence therefore lack generated coverage.

## Capability Manager Integration Audit

### Channel capability grant

The process-facing creation path inserts the channel and then grants one kernel capability of type Channel for the channel ID. That grant includes send, receive, clone-sender, and channel-create rights, with the creator recorded as both owner and origin.

This differs from IpcService::create_channel, which returns separate send-only and receive-only ChannelCapability values without registering either endpoint in the capability manager. The two APIs therefore establish different authority models.

### Channel capability resolution

resolve_channel_capability first calls the capability manager's full policy check for the requested process, channel object, type, and right. For a local grant it then verifies the stored token, confirms the object and type, translates kernel rights into IPC channel rights, and returns an operation-specific endpoint value.

PID 0 bypasses the table and receives all channel rights. A successful remote-lease check without a local mapping also produces an ephemeral ChannelCapability with capability ID 0, so not every resolved endpoint corresponds to a durable local table entry.

### Send access resolution

Send resolution requires CHANNEL_SEND. The policy check covers predictive restriction, rate limiting, local token validation, and mapped or remote capability policy before the resolver constructs a ChannelCapability containing the IPC SEND right.

Once returned, that endpoint is an ordinary copied value. Channel admission checks its embedded channel ID and rights but does not repeat the capability-manager lookup.

### Receive access resolution

Receive resolution follows the same path with CHANNEL_RECEIVE as the required kernel right. A matching local grant is translated into an IPC endpoint that carries RECEIVE and may also carry SEND and CLOSE when the underlying grant contains both directional rights.

The receive service resolves once before calling the IPC service. It does not bind the returned endpoint to a capability-table generation or revocation epoch.

### Close access resolution

Close resolution requires both CHANNEL_SEND and CHANNEL_RECEIVE. The IPC CLOSE bit is synthesized only when both rights are present, so a send-only or receive-only local grant cannot close the channel through the resolver.

There is no distinct kernel CHANNEL_CLOSE right. Closing authority is therefore coupled to possession of both communication directions, even when policy might want a separate lifecycle administrator.

### IPC capability type mapping

Ticketed export maps Channel, Filesystem, Store, and ServicePointer directly into the smaller IPC CapabilityType enum. Every other kernel capability type is exported as Generic while its original numeric type is retained in the fourth extra word.

Import reverses this mapping. A Generic envelope is accepted only when the saved kernel type value is recognized, while the four directly represented types bypass that fallback field.

### Kernel capability type versus IPC capability type

The kernel capability enum covers task, spawner, console, clock, cross-language, reserved, and other authorities that have no dedicated IPC enum variant. The IPC enum is a wire model with only Generic, Channel, Filesystem, Store, and ServicePointer.

This is a deliberate translation boundary rather than type identity. Correctness depends on the extra metadata and import conversion remaining synchronized with both enums.

### Capability token signing

Capability attachments contain a SipHash-based authentication token over the capability ID, ticket ID, object ID, rights, IPC type, owner PID, issue and expiry times, flags, and extra words. Export signs the envelope before staging it, and Message::add_capability signs the copied attachment again before insertion.

Signing authenticates the represented fields under the kernel key. It does not by itself prove that the signer obtained the fields from a live capability-table entry unless the export path was used.

### Capability token verification

import_capability_from_ipc verifies the attachment token before translating its type or granting authority. Local channel resolution separately verifies the token stored in the process capability table.

The ordinary receive-with-capabilities path only copies attachments out of the dequeued Message. It does not verify or import them, so callers must explicitly use the capability import path before treating an attachment as authority.

### IPC transfer tickets

export_ipc_capability removes the source grant, allocates a nonzero ticket, creates a signed envelope, and stores the envelope plus the removed authority in a bounded pending-transfer ledger. consume_ipc_transfer matches the ticket, source PID, source capability ID, owner, object, rights, and type, then removes the entry before the destination grant.

This creates one-time transfer semantics only for nonzero tickets processed through import_capability_from_ipc. Unticketed signed envelopes use a grant-by-copy path.

### Rollback on failed transfer

If export cannot stage the transfer, it attempts to reinstall the removed source grant. If destination import consumes a ticket but cannot grant the destination capability, it attempts to restore the source authority and restage the pending transfer.

Message insertion overflow and several send failures call rollback_ipc_transfer for attached tickets. Those rollback results are generally discarded, so failure to restore authority is not propagated to the sender.

### Revocation during queued transfer

A ticketed export removes the original table entry before the message is queued, leaving the pending ledger as the authoritative record until import or rollback. Revoking capabilities for the source process after export does not necessarily remove that pending ticket or the queued envelope.

The receive path can expose the attachment without consuming the ticket. Queue residence is therefore not yet tied to a revocation check or destination grant transaction.

### Revocation during blocked send

The process-facing send helper resolves the channel capability before entering the IPC service. When a reliable send blocks for capacity, retries continue with the same copied ChannelCapability rather than resolving the process's authority again.

A capability revoked while the sender sleeps can therefore remain usable for the eventual retry unless another admission policy independently rejects it.

### Revocation during blocked receive

Receive resolution also occurs before the blocking loop. The scheduler may suspend and wake the process repeatedly while the operation retains the same copied endpoint.

Revocation during that interval is not rechecked against the capability manager before a later dequeue, allowing an authority decision to outlive the grant that justified it.

### Owner PID mismatch

Local resolution searches only the table indexed by the supplied PID and verifies table-owned tokens before returning an endpoint whose owner field is that PID. Ticket consumption also checks the source PID against the pending transfer.

Lower IPC methods accept ChannelCapability values directly and trust their embedded owner. They do not prove that the owner matches the currently executing process, and several public wrappers accept a caller-supplied ProcessId.

### Rights mismatch

The resolver asks the capability manager for the exact operation right and then independently checks the selected local entry. Import grants only the rights carried by the authenticated envelope, preserving the exported rights rather than automatically widening them.

Channel creation grants a combined set that includes communication, sender cloning, and channel creation. There is no creation-time option for least-privilege manager grants or a distinct close right.

### Capability expiration

IPC envelopes carry issue and expiry fields and include them in the authentication token. Current capability export sets the issue time from the source grant and sets expiry to zero, so ordinary exported capabilities do not expire.

Import verifies the token but does not reject an envelope whose nonzero expires_at is in the past. Local channel capabilities also have no per-grant expiry field in the resolver path.

### Replayed transferred capability

For ticketed transfers, consuming the pending ledger entry before destination grant prevents a second successful import with the same ticket. Envelope matching also prevents substitution of a different object, owner, rights set, or IPC type under that ticket.

Unticketed valid envelopes have no one-time ledger state and can be imported repeatedly. A ticketed envelope can also be copied out repeatedly before any recipient attempts import, creating contention rather than immediate replay rejection.

### Forged transferred capability

Changing any authenticated envelope field causes Capability::verify to fail during import. A forged ticket must also match a live pending ledger record and its source and envelope metadata before it can be consumed.

The protection depends on recipients importing rather than trusting raw copied attachments. The temporal restore path reconstructs pending ticket records from snapshots and must therefore protect snapshot authenticity with the same rigor as live transfer state.

### Confused deputy cases

The capability manager provides a strong policy boundary only when callers resolve or import authority through it. Direct IpcService methods, PID 0 helpers, caller-supplied process IDs, temporal restoration, and raw attachment copy-out create paths where surrounding code can act with authority that was not freshly established for the current principal.

The broad channel grant also lets one service hold send, receive, clone, and create rights together. A service operating on another process's behalf must explicitly preserve the principal and requested operation or it can become a deputy for unintended access.


## Security Module Integration Audit

### Syscall audit logging

Every recognized syscall passes through audit_syscall before dispatch. The security manager records a SyscallObserved event containing the syscall number and a hash of the five raw arguments, then feeds a syscall signal with the expected capability type and rights into the intent graph.

The audit record identifies the process and operation class without storing the full arguments. IPC success, failure, queue state, message identity, and transferred capability metadata are recorded through separate paths and are not joined to the syscall entry by one correlation identifier.

### Syscall policy blocking

After the ingress audit, syscall_policy_blocked derives the capability type and right associated with the syscall number. If the process is predictively restricted for that combination, dispatch stops with EACCES before the IPC handler reads user buffers or mutates a channel.

Syscalls absent from the required-access table are not blocked by this gate. Channel creation also contains a later PID 0 through 2 exception that can bypass its explicit CHANNEL_CREATE capability check, although it cannot bypass a restriction already enforced by the common syscall gate.

### Predictive restriction check

Capability resolution checks predictive restriction before searching the process capability table. Channel admission checks it again under the IPC table lock for CHANNEL_SEND or CHANNEL_RECEIVE, reducing the interval between policy evaluation and queue mutation.

When channel rejection observes a restriction, it asks the capability manager to quarantine matching grants until the restriction expiry tick. The operation returns PermissionDenied and records both an intent denial and a security event.

### Channel capability type restriction

The syscall policy table, capability resolver, and admission path consistently identify channel operations as kernel CapabilityType::Channel. Local resolution rejects entries of another type even when their object ID and numeric rights overlap.

Transferred attachments use the smaller IPC capability type model. A received attachment does not become channel authority until the import path verifies and translates it, but the raw receive syscall currently exposes the envelope before that import.

### Send-right restriction

The syscall gate associates channel send operations with CHANNEL_SEND. resolve_channel_capability requires that right from the process's local grant or remote lease, and admission separately requires the translated IPC endpoint to contain SEND.

The admission check reads the copied endpoint rather than the live capability table. Revocation after resolution or during a blocked send can therefore outlive the security decision that produced the endpoint.

### Receive-right restriction

Channel receive and receive-with-capabilities syscalls are classified as CHANNEL_RECEIVE operations. Resolution verifies the manager grant, while admission checks the endpoint's RECEIVE bit and predictive restriction before delivery.

As with send, a blocked receiver retains the resolved endpoint across scheduler sleeps. The final dequeue does not revalidate the manager grant or policy epoch.

### Security denial error mapping

The common syscall policy gate returns EACCES for predictive restriction. The channel facade converts capability-resolution failure to the string Missing channel capability, which syscall handlers also map to EACCES.

Admission-level permission, invalid-capability, protocol, closed, and backpressure errors are collapsed by the string-returning facade into broad EIO or EAGAIN results. The syscall caller therefore cannot reliably distinguish a policy denial from revocation, malformed authority, protocol failure, closure, or transient queue state.

### Audit event completeness

The security module records syscall observation, capability probes and uses, permission denials, invalid capabilities, restrictions, revocations, anomalies, and selected channel closure transitions. Successful enqueue and dequeue also feed IPC send and receive signals into the intent graph.

Several operational failures produce only channel counters or temporal refusal records. Closed channels, backpressure, protocol mismatch, ticket rollback failure, copy-out failure, and raw capability delivery do not all produce durable security events with consistent context.

### Causal chain audit correlation

Messages carry EventId and an optional causal predecessor, and temporal channel events record channel activity. Security AuditEntry instead contains event type, process, capability ID, timestamp, and one context word.

Successful IPC intent events do not store the message EventId, cause, syscall audit identity, or transfer ticket. Reconstructing a complete causal chain across syscall ingress, capability resolution, enqueue, dequeue, and capability import is therefore not deterministic.

### Anomaly response path

Intent signals update per-process counters, transition novelty, object novelty, and a compact scoring model. Crossing the alert threshold records AnomalyDetected; crossing the restriction threshold records revocation-oriented events and establishes temporary restrictions by capability type and rights.

Capability checks and channel rejection perform the actual capability quarantine. The telemetry ring is best effort, and audit insertion uses try_lock, so response evidence can be dropped under contention even while enforcement proceeds.

### Restriction revocation race

The syscall gate, capability resolver, and channel admission evaluate restriction at different points. This layering catches many newly applied restrictions, but a restriction can still race with a commit after the final admission check or with a blocked operation that retains a copied endpoint.

Quarantining matching table entries does not invalidate every endpoint value, queued transfer, waiter, or in-flight operation derived from those entries. Restriction expiry can also restore quarantined grants without proving that all older copied values have disappeared.

### Malicious IPC flooding

The security rate limiter runs during capability validation, and the intent graph counts IPC, syscall, denial, invalid-capability, transition, and object-novelty activity. Fixed channel capacity, maximum channel count, message size limits, capability count limits, and backpressure bound immediate storage growth.

Successful enqueue and dequeue signals occur only after commit, while rejected attempts are represented indirectly through capability and refusal paths. PID 0 bypasses capability checking, syscall handlers allocate up to 4096 bytes before the IPC layer rejects payloads above 512 bytes, and no per-channel or per-destination traffic quota provides comprehensive flood isolation.

### Covert channel analysis

Channel payloads are explicit communication, but observable timing and resource effects create additional channels. Queue occupancy, blocking duration, wake order, refusal class, audit-log contention, restriction timing, shared rate limits, global table locking, and fixed-capacity exhaustion can reveal activity between otherwise separated principals.

The implementation does not define a covert-channel threat model, quantitative bandwidth bounds, deterministic scheduling mode, or partitioned resource policy. Capability checks control intended access but do not eliminate timing and contention leakage.

### Capability exfiltration by IPC

The ticketed export path removes source authority and authenticates the transfer envelope, providing a controlled delegation mechanism. ServicePointer export additionally requires SERVICE_DELEGATE.

The send-with-capabilities syscall accepts user-provided capability envelope fields, Message::add_capability signs them inside the kernel, and receive-with-capabilities copies raw envelopes to user memory without automatic verification or recipient import. Those paths weaken the guarantee that every transferred authority originated from an authorized live grant and reached only an intended recipient.

### Confused deputy through service IPC

Service helpers accept explicit ProcessId values, and lower IPC methods accept ChannelCapability values directly. Kernel PID 0 helpers bypass capability-manager resolution entirely, while the default registered channel grant combines send, receive, clone-sender, and channel-create rights.

A privileged service acting for a workload can therefore select the wrong principal, reuse its own broad endpoint, or forward an attachment without recipient-bound attenuation. The security module cannot reconstruct the intended caller when that identity is lost before capability resolution.


## Error Taxonomy and Error Mapping Audit

### Internal IPC error coverage

IpcError distinguishes invalid capability, permission denial, protocol mismatch, temporary blocking, sealed closure, draining closure, oversized messages, excessive attached capabilities, and channel-table exhaustion. These variants cover the principal channel, message, admission, and registry failures produced by the current implementation.

The enum does not identify capability revocation, transfer-ticket failure, scheduler failure, user-memory fault, allocation failure, temporal persistence failure, audit loss, or device-independent cancellation. Several of those conditions are converted into an existing variant or discarded before reaching the caller.

### Admission refusal coverage

IpcRefusal preserves the reason why admission rejected an operation: predictive restriction, permission denial, invalid capability, protocol mismatch, sealed channel, draining channel, backpressure, full queue, or empty queue. Channel rejection converts these policy outcomes into IpcError and records selected security, temporal, and diagnostic evidence.

QueueEmpty is defined but normal receive admission uses Defer(WaitForMessage) instead. Backpressure, QueueFull, and QueueEmpty all become WouldBlock, while predictive restriction becomes PermissionDenied and loses its distinct origin.

### Admission defer coverage

IpcDefer distinguishes waiting for queue capacity from waiting for a message. IpcService interprets these values as scheduler block requests, releases the IPC lock, commits the block, and retries after wakeup.

The distinction exists only inside admission and service control flow. Scheduler preparation failure, nonblocking operation, and lower-level direct use all surface as WouldBlock, and there is no public timeout, interruption, cancellation, or revocation defer result.

### Syscall errno mapping

IPC syscalls use EINVAL for invalid lengths and capability counts, EFAULT for rejected pointer ranges, EACCES for the string Missing channel capability, EIO for most send failures, EAGAIN for most receive failures, EBADF for most close failures, and ENOMEM for every channel-creation failure.

This mapping is not exhaustive by IpcError variant. MessageTooLarge can become EIO after the syscall accepts a length above the IPC maximum, Closed and ChannelDraining become generic send, receive, or close errors, and TooManyChannels is reported as ENOMEM even though memory allocation did not necessarily fail.

### String error degradation in public wrappers

The process-facing facade converts typed IpcError values into static strings. Send preserves only message construction failure and missing capability before collapsing every channel error into Failed to send message. Receive collapses every channel failure into No message available, and close uses Failed to close channel.

Syscall handlers compare those strings to recognize only Missing channel capability. Renaming a string or adding a typed error cannot produce a compiler-visible requirement to update the errno mapping.

### Loss of diagnostic specificity

The path from admission to syscall repeatedly removes information. PredictiveRestriction becomes PermissionDenied, three pressure outcomes become WouldBlock, scheduler preparation failure becomes WouldBlock, and the facade then collapses most errors into one operation-specific string.

Callers cannot tell whether retry is useful, whether authority was revoked, whether a channel is draining or sealed, whether protocol state is corrupt, or whether a transfer rollback failed. Diagnostics may retain counters, but they are not returned with the failed operation.

### Security-sensitive error detail leakage

Coarse mapping can reduce object-existence leakage because unauthorized callers commonly receive EACCES without learning whether a channel exists. The resolver performs the authority check before channel lookup in the process-facing facade, which supports that behavior.

Other paths expose timing and error-class differences between pointer rejection, capability denial, empty queues, closure, and generic failure. The code has no documented rule defining which distinctions authorized callers may observe and which must be normalized for unauthorized callers.

### Retryable versus fatal errors

WouldBlock is intended to represent temporary queue state, while MessageTooLarge, TooManyCaps, invalid capability, permission denial, and protocol mismatch generally require caller action. Closed is terminal for a channel generation, and ChannelDraining is terminal for new sends while receivers may continue consuming queued messages.

The public facade does not preserve this classification. Receive maps all non-capability failures to EAGAIN, encouraging retries after closure or protocol failure, while send maps temporary pressure and terminal failures alike to EIO.

### Close/drain/sealed distinction

The channel lifecycle distinguishes Open, Draining, and Sealed. New sends to Draining return ChannelDraining, receives remain allowed while messages exist, and the final dequeue changes the channel to Sealed. Operations on a sealed empty channel return Closed.

This distinction is tested internally but does not survive the process facade or syscall mapping. Close also reports generic EBADF for every non-capability failure, and the public API has no explicit end-of-stream result.

### Queue full versus backpressure distinction

Backpressure can refuse an async send before saturation at the high-pressure threshold, while a full async queue produces QueueFull. A non-async full queue produces Defer(WaitForCapacity), causing the blocking service to sleep and retry.

All three conditions eventually use WouldBlock when returned as an error. External callers cannot distinguish early policy throttling, hard capacity exhaustion, and scheduler-backed deferral, even though their appropriate retry behavior differs.

### Protocol mismatch mapping

Temporal frame parsing and channel phase validation return ProtocolMismatch. Admission preserves that refusal, rolls back ticketed attachments on send, and returns IpcError::ProtocolMismatch without mutating the queue.

The process send facade converts it to Failed to send message and the syscall returns EIO. Receive converts it to No message available and EAGAIN, incorrectly presenting a protocol violation as temporary absence.

### Invalid capability mapping

Capability resolution failure is converted to Missing channel capability and then EACCES. If a caller reaches the channel layer with an endpoint bound to the wrong channel, admission returns InvalidCapability and the channel returns IpcError::InvalidCap.

That second path is collapsed by the facade into EIO, EAGAIN, or EBADF depending on the operation. The public result therefore varies according to where the invalidity was detected rather than according to one stable authorization policy.

### User fault mapping

The syscall layer returns EFAULT when its numeric user-range checks reject message, output, capability, or count pointers. Those checks occur before the IPC facade and are not represented by IpcError.

The subsequent unsafe copies have no recoverable fault boundary or per-process VMA validation. A mapping change or inaccessible address after the arithmetic check can fault the kernel rather than return EFAULT, and receive may dequeue a message before output copying proves successful.

### Out-of-memory mapping

Channel creation maps every facade failure to ENOMEM, including table capacity and capability-grant failure. Send and receive allocate vectors sized by the user-requested buffer length, but allocation is not fallible at the call site and no IpcError variant represents allocation exhaustion.

TooManyChannels is a bounded-registry condition, not necessarily memory exhaustion. Capability-table saturation, pending-ticket saturation, and allocator failure also lack distinct syscall outcomes.

### Consistency across syscall and in-kernel API

Direct Channel and IpcService callers receive typed IpcError values and can observe lifecycle and protocol distinctions. Process-facing helpers return static strings, syscall callers receive coarse errno values, and PID 0 helpers bypass capability resolution.

The same operation can therefore have different blocking, authorization, and error semantics depending on which API layer invokes it. There is no single public result type or normative mapping table shared by kernel services and user processes.


## Diagnostics and Observability Audit

### Channel pending count

ChannelDiagnostics reports pending from the queue length while the IPC table lock is held. The same snapshot also reports empty and full, so these fields are internally consistent for that instant.

The value has no observation timestamp, generation, enqueue/dequeue totals, or oldest-message age. Successive samples cannot distinguish turnover from inactivity, and a deleted and reused channel ID could be mistaken for one continuous channel.

### Channel capacity reporting

ChannelDiagnostics reports the compile-time CHANNEL_CAPACITY for every channel, and IpcDiagnostics reports MAX_CHANNELS for the table. BackpressureSnapshot repeats the per-channel message capacity.

The diagnostics do not report aggregate message capacity, current total queued messages, queue memory consumption, waiter capacity, or resource limits for capabilities and temporal snapshots. Capacity is therefore accurate but incomplete as an operational budget.

### Closed state reporting

Diagnostics preserve the full ClosureState rather than a boolean, allowing privileged in-kernel consumers to distinguish Open, Draining, and Sealed. The older channel_stats facade reduces this to a closed boolean and loses the draining state.

Neither interface reports who initiated closure, when it began, how many messages remain to drain, or whether blocked operations were woken successfully. There is also no process-facing diagnostic API for lifecycle state.

### High watermark reporting

Each successful enqueue raises high_watermark to the maximum observed queue depth. Receives do not lower it, and failed sends do not update it. The value is included in channel diagnostics, backpressure snapshots, and temporal channel snapshots.

The watermark has no timestamp, EventId, channel generation, reset epoch, or reason for the peak. Restoration preserves a number without identifying whether it belongs to the current runtime observation period.

### Refusal counters

Channel tracks saturating send_refusals and recv_refusals. Rejection paths increment the directional counter and attempt to record a temporal refusal event and persist a channel snapshot.

The counters do not retain IpcRefusal reason, caller, retryability, first or last occurrence time, or rollback outcome. Expected empty-queue deferral can also be accounted differently from explicit refusal, so the totals cannot explain why operations failed.

### Backpressure counters

Backpressure diagnostics expose current pressure level, recommended action, high-pressure hits, saturated hits, and high watermark. Send attempts observed at High or Saturated increment saturating counters before admission decides whether to commit, defer, or refuse.

The counters measure attempts rather than completed outcomes and are not partitioned by principal, action, message size, or async mode. No transition timestamp or duration reveals how long a channel remained pressured.

### Wakeup counters

Channel records saturating sender_wakeups and receiver_wakeups when local or scheduler waiters are successfully woken. Closure paths wake both directions, and runtime self-tests verify that the counters advance.

The totals omit wake reason, target PID, failed wake attempts, duplicate or stale waiter records, and time from block to wake. A wakeup count does not prove that the process ran, reacquired the channel, or completed its operation.

### Waiting sender count

Channel maintains a bounded local waiting_senders queue, while ChannelDiagnostics currently reports only the scheduler wait-table count for the channel capacity address. The local queue is persisted in temporal channel snapshots.

The displayed count can diverge from local IPC state after queue overflow, stale PIDs, scheduler cleanup, or a wake race. Diagnostics do not expose both counts, dropped waiter records, wait age, priority, or retry count.

### Waiting receiver count

Channel maintains a bounded local waiting_receivers queue, while ChannelDiagnostics reports the scheduler wait-table count for the channel message address. The local queue is persisted and restored with channel state.

As with senders, scheduler and local counts can disagree without being surfaced. No diagnostic identifies stale process generations, overflow, wait duration, priority, or whether a receiver is reserved for the next message.

### Temporal protocol state reporting

ChannelDiagnostics returns ChannelProtocolState, including the full TemporalSessionState for bound channels. Temporal snapshots also encode protocol phase, session identity, operation, flags, sequence, and correlation fields.

The snapshot lacks an observation timestamp and channel generation, and ordinary syscall callers cannot query it. Protocol transition history, last successful frame, last mismatch, and quarantine state are not retained as one inspectable record.

### Causal event reporting

Messages carry EventId and an optional causal predecessor, and temporal snapshots preserve those fields. Tests cover basic encoding and lineage survival through a channel.

ChannelDiagnostics and lightweight temporal IPC events omit EventId and cause, so enqueue, dequeue, refusal, wakeup, syscall, and persistence records cannot be joined reliably to one message. No event index reports duplicates, missing parents, or causal-chain integrity.

### Syscall boundary events

Recognized syscalls pass through security audit_syscall with the caller, number, and arguments. Invalid syscall numbers emit a failure event and a syscall-boundary observability event before returning ENOSYS.

IPC syscall terminal outcomes are not consistently emitted with typed errno cause, channel generation, message EventId, copied byte count, or copy-fault stage. Raw pointer arguments may enter audit hashing, but ingress and completion are not guaranteed to form one correlated operation.

### IPC admission refusal events

Send and receive rejection increment counters, emit selected security events, attempt temporal refusal recording, and persist a channel snapshot. Permission, invalid capability, lifecycle, protocol, pressure, and queue conditions are represented internally by IpcRefusal.

The temporal event records only a broad send-refused or receive-refused type and does not preserve the IpcRefusal variant. Defer, rollback failure, scheduler preparation failure, retry, and final completion are not represented as one structured admission trace.

### Panic/failure event paths

Normal IPC parsing and channel operations primarily return typed errors, while invalid syscall dispatch invokes the failure subsystem. Production IPC code contains few direct panic sites; most unwrap and expect calls are confined to tests.

There is no uniform policy requiring every impossible state, persistence failure, audit failure, scheduler inconsistency, or capability rollback failure to emit a bounded diagnostic before recovery or fail-stop. Several recording results are intentionally discarded, making observability loss silent.

### Diagnostic consistency under concurrency

IpcService obtains the channel-table mutex before constructing diagnostics, so queue, lifecycle, counters, and protocol fields from Channel are mutually consistent at one lock-protected instant. The fixed diagnostics array also bounds snapshot memory.

Scheduler waiter_count calls occur while the IPC lock is held but read a separate subsystem, so the snapshot is not globally atomic. There is no sequence number, timestamp, generation, or retry mechanism for detecting concurrent changes before or after sampling.

## Self-Test and Unit Test Audit

### Message creation test

Unit tests create ordinary messages, verify payload and empty capability state, accept exactly MAX_MESSAGE_SIZE bytes, and reject one byte above the limit with MessageTooLarge. Causal self-tests also exercise EventId and predecessor construction.

They do not exhaustively test every payload length, sequence wraparound, source authentication, zeroization, allocation failure, or malformed restored public fields.

### Ring buffer test

Unit tests cover empty state, push/pop, FIFO order through a full queue, full detection, failed-overflow atomicity, and complete drain. Runtime self-tests exercise bounded backpressure and high watermark behavior through Channel.

There is no repeated wraparound/reference-model test, clear test, stale-storage inspection, malformed restore sequence, or stateful randomized operation stream.

### Channel send/receive test

The basic unit test sends and receives one payload with separate send-only and receive-only endpoints. Additional tests cover FIFO queue behavior, causal lineage, pressure metrics, closure draining, temporal typing, and snapshot restoration.

The suite does not run a broad matrix across flags, rights, principals, channel generations, capability attachments, and simultaneous failure conditions.

### Service receive without scheduler context

IpcService::recv on an empty channel is tested without an active scheduler process. Scheduler block preparation fails safely and the service returns WouldBlock instead of panicking or retaining a waiter.

The test does not distinguish nonblocking intent from scheduler failure, verify diagnostics, or cover timeout, cancellation, close, revocation, and process-exit races.

### Service send without scheduler context

IpcService::send fills a reliable channel and verifies that one additional send returns WouldBlock when no scheduler context can prepare a capacity wait.

It does not verify ticket retention or rollback, diagnostic counters, message preservation after retry, or behavior when scheduler preparation partially succeeds.

### Send wakes waiting receiver

The scheduler test stages a receiver on the channel message wait address, sends one message, and verifies one wakeup, zero remaining scheduler waiters, and Ready process state. Runtime self-tests also exercise local and scheduler wake surfaces.

It does not prove FIFO completion, local/scheduler queue reconciliation, stale PID handling, process generation safety, or freedom from a wake-before-block race under true concurrency.

### Receive wakes waiting sender

The test fills a channel, stages a sender on the capacity wait address, receives one message, and verifies one sender wakeup and Ready state.

It does not prove that the woken sender wins capacity, completes in order, retains transfer tickets, or avoids starvation when several senders compete.

### Full reliable channel defers send

Admission tests fill a default reliable channel and verify Defer(WaitForCapacity). Service fallback tests confirm that the defer becomes WouldBlock when no scheduler context is available.

The RELIABLE flag itself remains behaviorally weak, and no end-to-end test proves eventual delivery, cancellation cleanup, process-exit behavior, or exactly-once capability settlement across the wait.

### Full async channel refuses send

Admission and backpressure tests verify that a full async channel produces QueueFull refusal, and that bounded non-high-priority async channels may refuse early at high pressure.

The tests do not cover every flag combination, priority value, contradictory mode, retry policy, per-principal pressure, or syscall errno result.

### Empty channel defers receive

Admission verifies Defer(WaitForMessage) for an empty open channel, while direct and service tests verify WouldBlock when blocking cannot be committed.

There is no distinct nonblocking QueueEmpty production test and no coverage for timeout, interruption, cancellation, revocation, draining-empty, or closed-empty wake races.

### Closure state tests

Runtime and unit tests cover close with queued messages, Draining rejection of new sends, continued receive, final transition to Sealed, repeated closed behavior, and waking all staged senders and receivers. A new negative test verifies that a send-only endpoint cannot close and leaves ClosureState unchanged.

Coverage does not span every rights set, capability ticket state, temporal phase, repeated close principal, process cleanup, restoration epoch, or concurrent close/send/receive interleaving.

### Capability transfer tests

Self-tests verify attachment visibility and one-time ticketed export/import, including rejection of a duplicate ticket import. Temporal snapshot tests restore pending transfer state.

The live syscall capability path remains disconnected from the secure ticketed transaction. Tests do not prove atomic multi-capability import, receiver-local rebinding, rollback after queue or copy failure, expiry, revocation, substitution, or process-exit settlement.

### Temporal protocol tests

Self-tests reject malformed, wrong-session, wrong-phase, and mismatched frames; accept valid request/response progression; verify phase transitions; and round-trip channel protocol, queue, metrics, waiters, and closure through snapshots.

They do not fuzz frame lengths and fields, test sequence exhaustion, authenticate source and epoch, prove replay rejection across boots, or cover malformed head-message recovery.

### Syscall IPC tests

The syscall suite now verifies that ChannelSend and ChannelRecv reject zero-length buffers with EINVAL. The generic syscall negative test verifies invalid-number failure and observability closure.

There is no successful syscall-level channel round trip, capability transfer, close, pointer fault, partial mapping, native-width pointer, errno matrix, or dispatcher-to-channel conformance test.

### Fuzz/property tests

No dedicated IPC fuzz target or property-test suite exists. Current tests use selected examples and deterministic runtime self-test cases.

The repository's other fuzz infrastructure does not generate IPC operation sequences, malformed snapshots, raw syscall buffers, capability envelopes, or scheduler interleavings.

### Negative/security tests

Tests reject oversized payloads, wrong operation rights, malformed temporal frames, wrong sessions and phases, channel draining sends, duplicate transfer tickets, and invalid syscall numbers. The wrong-rights unit test verifies denied send, receive, and close operations do not mutate queue or lifecycle state.

The suite lacks systematic tests for forged endpoint fields, stale channel IDs, PID reuse, capability substitution, unauthorized timing equivalence, receive-side token validation, user-copy faults, and cross-process misuse.

### Architecture-specific tests

The shared IPC unit and runtime tests compile against the kernel target, and an AArch64 syscall smoke helper exists for GetPid. No IPC-specific architecture adapter suite is present.

i686, x86-64, and AArch64 do not run identical tests for pointer width, register mapping, structure layout, endianness, alignment, and split 64-bit fields.

### QEMU regression tests

The runtime ipc-selftest command and formal-verify shell surface can exercise the fifteen in-kernel self-test cases on a booted system. This provides a manual path for testing scheduler and kernel integration under QEMU.

There is no dedicated automated QEMU IPC regression job with machine-readable pass/fail output across all supported architectures, and no syscall-driven userspace IPC workload is included.

### Formal proof regression tests

Verification documents classify the runtime IPC self-tests as conformance evidence rather than mechanized theorems. No IPC proof artifact currently gates capability isolation, queue boundedness, transfer single-use, no-lost-wakeup, or deadlock freedom.

The formal-verify shell command reruns runtime checks but does not establish mathematical proof of the IPC invariants.

### Coverage gaps

The strongest coverage is concentrated in direct Channel tests and the fifteen-case runtime self-test. The least covered surfaces are syscall user-copy behavior, secure receive-side capability import, process cleanup, architecture ABIs, concurrent scheduler races, fuzzing, QEMU automation, and formal invariants.

Coverage is not measured, there is no maintained test-to-requirement matrix, and several outer API paths still have semantics that differ from the directly tested channel state machine.


## Formal Verification and Invariant Audit

### Capability subset preservation

Capability attenuation rejects requested rights that are not a subset of the source grant, and capability graph operations are intended to preserve monotonic authority. Ticketed transfer helpers also derive their exported authority from an existing capability-manager entry.

This property is not proved across every IPC entry path. Raw channel endpoints remain constructible inside the kernel, and the syscall attachment path can reconstruct authority outside the ticketed export flow. The verification index describes `ipc_flow.v` as scaffolded while the target matrix lists the IPC capability theorem as proved, so the maintained formal status is currently inconsistent.

### Message queue capacity invariant

`RingBuffer` refuses insertion when its depth reaches `CHANNEL_CAPACITY`, and ordinary queue mutation is restricted to bounded push, pop, clear, and restore operations. Unit tests cover exact-capacity insertion and verify that a rejected insertion does not increase queue depth.

There is no machine-checked state model proving the bound across restoration and future internal mutation paths. The entry-count bound also does not prove an aggregate memory bound because messages, channel tables, snapshots, diagnostics, and temporary syscall buffers use separate allocations.

### No-send-without-send-right invariant

Send admission checks `ChannelCapability::can_send` before lifecycle, protocol, and pressure decisions. The process-facing path additionally resolves a process-local capability before reaching the channel, and negative tests verify that a receive-only endpoint cannot enqueue a message.

The channel-level check proves only possession of a SEND bit in a supplied value. `ChannelCapability` does not authenticate the executing process, owner, token, generation, expiry, or revocation state, so direct callers can bypass the stronger capability-manager interpretation. No refinement proof connects the rights-bit check to authentic send authority.

### No-recv-without-receive-right invariant

Receive admission checks `ChannelCapability::can_receive` before inspecting or removing the queue head. Process-facing callers resolve authority through the capability manager, and negative tests verify that a send-only endpoint cannot dequeue a message.

Direct channel and service callers can still present copied or constructed endpoints without proving ownership or current validity. The invariant therefore holds for the local rights-bit predicate, not for complete principal-bound receive authority, and it has no maintained mechanized proof.

### No-close-without-close-right invariant

`Channel::close` rejects endpoints for which `can_close` is false, and tests verify that insufficient rights leave the lifecycle unchanged. Closure is performed while the channel table is locked.

The capability manager does not expose an independent close right consistently; some facade paths infer close authority from combined send and receive rights. Public raw endpoint fields also permit direct construction without token, owner, generation, or revocation validation. The complete close-authority invariant is therefore not established.

### No-send-after-seal invariant

Send admission rejects both `Draining` and `Sealed` channels before queue insertion. Lifecycle tests cover sends after close and verify that the queue is not mutated by the rejected operation.

No formal transition system proves this property across ordinary operation, temporal restoration, forced cleanup, and direct table mutation. Error precedence and restored lifecycle validation also remain runtime conventions rather than proved conditions.

### Drain-before-seal invariant

Closing a channel with queued messages changes it to `Draining`; receives remain permitted, and removal of the final queued message changes it to `Sealed`. Closing an already empty channel seals it immediately. Runtime tests exercise the principal drain transition.

Forced deletion and process cleanup can remove channel state without draining queued messages, so this is an ordinary close-path invariant rather than a universal destruction invariant. There is no liveness proof that a draining channel eventually reaches sealed state.

### FIFO ordering invariant

The queue uses `VecDeque::push_back` and `pop_front`, and focused tests verify insertion and removal order. Snapshot records iterate in queue order and restoration reinserts records in that order.

FIFO preservation is not machine checked across all combinations of refusal, restore, close, and capability-transfer failure. Receive validation peeks before a separate pop and relies on the same channel lock remaining held, an assumption that is not represented in a formal model.

### Causal identity uniqueness invariant

Messages carry an `EventId` and optional predecessor, and basic tests verify field encoding and lineage preservation. The identifiers can support local diagnostic correlation while their component counters remain unique.

The claimed uniqueness invariant does not hold for long-lived or restored systems. The message sequence is a wrapping 16-bit global counter, the channel component is commonly zero, the raw identifier is publicly constructible, and no boot or process generation is encoded. PID reuse, counter wraparound, direct construction, and restore can all create duplicate identities.

### Temporal session phase invariant

Temporal request and response frames are validated against channel session, request, operation, and phase state before commit. Invalid transitions return `ProtocolMismatch`, and runtime tests cover accepted and rejected phase progressions.

The state machine has no mechanized proof of transition completeness, replay resistance, or recovery. Wrapped identifiers, restored epochs, malformed queued heads, and source authenticity are not incorporated into one formal session model.

### Capability transfer authenticity invariant

The ticketed transfer helpers sign exported envelopes, retain immutable pending-transfer state, verify tokens and envelope fields during import, and reject tampered records. Runtime tests exercise token and field substitution failures.

The ordinary capability-carrying syscall is not connected end to end to that transaction. It can reconstruct user-supplied envelope fields, and receive can copy attachments without secure import, receiver grant, or ticket consumption. Authenticity is therefore enforced by selected helpers, not by every delivered capability.

### Capability transfer single-use invariant

Nonzero ticketed transfers are tracked in a pending ledger and consumed during successful import. A second import of a consumed ticket is rejected by the helper path.

Live syscall-created envelopes can use zero tickets and bypass the one-time ledger. Enqueue, dequeue, destination installation, rollback, process exit, and restoration are not one atomic transaction, so single-use authority transfer is not a system-wide invariant.

### Backpressure threshold invariant

Backpressure derives its high-pressure threshold from channel capacity and applies the configured refusal policy before hard saturation. Tests cover low, high, and full pressure decisions for synchronous and asynchronous operations.

There are no compile-time assertions relating capacity and threshold values, and several channel mode and priority flags are not connected to a complete scheduling policy. The threshold behavior is runtime tested but not formally proved across all configurations.

### Wait/wakeup liveness invariant

Blocking service operations prepare a scheduler wait while channel state is locked, release the IPC lock, commit the block, and retry after wakeup. Send, receive, and close paths wake relevant waiters, and unit tests cover representative sender and receiver wakeups.

The implementation promises no fairness bound or eventual scheduler service. A woken process can repeatedly lose the lock and re-enter the wait path, while cancellation, timeout, revocation, and process-exit wake reasons are incomplete. Liveness is therefore not proved.

### No lost wakeup invariant

The two-phase blocking protocol records the operation's wait intent before releasing protected channel state, which is intended to close the ordinary check-then-sleep race. Local waiter records let queue transitions identify a process to wake.

There is no exhaustive interleaving model for the interval between scheduler preparation and committed blocking. A wake concurrent with that interval, waiter overflow, close, revocation, or process cleanup may violate the intended handoff unless scheduler state provides stronger guarantees than the IPC contract documents.

### No deadlock invariant

The service releases the global IPC lock before committing a scheduler block, avoiding the direct case where a sleeping process retains the channel table lock. Queue operations themselves do not block while holding the channel lock.

IPC code invokes scheduler, capability, security, temporal, diagnostic, and persistence facilities from overlapping lock scopes without one documented global lock order. No lock-dependency analysis or mechanized proof excludes cycles across those subsystems.

### Bounded memory invariant

Message payload size, attached capability count, queue depth, channel count, waiter records, and pending transfer records each have explicit limits. These bounds prevent individual live objects from growing without limit through their normal APIs.

The limits do not establish a total IPC memory bound. `Vec`, `VecDeque`, `BTreeMap`, snapshots, audit records, syscall staging buffers, and subsystem diagnostics allocate independently, and allocation failure is not consistently represented as a typed IPC outcome.

### Syscall boundary validation invariant

IPC syscall handlers perform basic length, capability-count, null, and user-address range checks before selected accesses. Tests cover invalid lengths, counts, and representative pointer rejection.

The boundary is not memory-safe by invariant. Validation uses a fixed address ceiling rather than the caller's mappings, native-width pointers can be truncated, pointer-plus-length overflow is not comprehensively checked, and unsafe copies lack a recoverable fault boundary. Receive can also dequeue before all output writes succeed.

### Channel table consistency invariant

The global channel map is protected by a lock, normal creation checks `MAX_CHANNELS`, and lookups, insertion, removal, and creator cleanup occur through table helpers. Channel IDs are checked for occupancy during ordinary creation.

The map remains crate-visible, allowing mutation outside all bounded helpers. ID increment can wrap, endpoints contain no channel generation, restore follows a different admission path, and deletion is not one transaction with capability revocation and transfer cleanup. No formal model proves map and authority-table consistency.

### Process cleanup invariant

Scheduler process cleanup invokes IPC channel purging, and the table removes channels whose recorded creator matches the exiting process. This bounds one class of orphaned creator-owned channel state.

Cleanup does not yet prove removal of all process-owned endpoints, waiter entries, pending tickets, queued transferred capabilities, or channels merely used by the process. PID reuse is not paired with a process generation, and blocked peers are not guaranteed a typed terminal wake result.

## Attack Surface Audit

### Malicious sender flooding

Each channel holds at most four messages, and asynchronous channels can refuse sends at high pressure before becoming full. Message payload and attachment counts are bounded, while refusal and pressure counters provide limited evidence of repeated saturation.

These controls bound one queue but do not impose per-principal rates, global message budgets, CPU quotas, or fair admission. A sender can repeatedly allocate and copy rejected syscall buffers, fill many channels, trigger persistence and audit work, and keep receivers or the global IPC lock busy.

### Malicious receiver starvation

Queued messages are removed in FIFO order, and a successful receive wakes one blocked sender. Receive authority is checked before dequeue, preventing an endpoint without the RECEIVE bit from draining a channel.

There is no receiver fairness policy or ownership handoff. One runnable receiver can repeatedly win the table lock and consume every message while other authorized receivers wake and lose the retry race. The code tracks neither per-receiver service nor starvation duration.

### Capability forgery

Process-facing channel operations resolve process-local grants through the capability manager, whose stored capabilities carry signed tokens. Ticketed transfer import verifies the envelope token and pending ticket fields, and runtime self-checks reject selected token tampering.

Raw `ChannelCapability` fields are public and direct IPC callers validate only rights bits and channel ID. More critically, `sys_channel_send_caps` reconstructs user-selected authority metadata and `Message::add_capability` signs it without first resolving a sender-owned capability. The ordinary syscall path can therefore cause the kernel to authenticate forged envelope contents.

### Capability replay

Nonzero transfer tickets are retained in a pending ledger and consumed once during secure import. The runtime transfer self-test verifies that a second import of the same ticket fails.

`SysIpcCapability` carries no ticket field, so syscall-created attachments use ticket zero. Receive copies these envelopes to user space without consuming a ledger record or installing receiver-local authority. A copied zero-ticket envelope can be presented repeatedly wherever token verification alone is accepted.

### Capability substitution

Ticketed import compares ticket, source, object, owner, type, rights, validity, metadata, and token-relevant envelope state against the pending transfer. The tampered-ticket self-test confirms one substitution class is rejected.

The live syscall path bypasses that comparison and accepts user-provided object IDs, owner PIDs, types, rights, expiry, flags, metadata, and tokens before re-signing. There is no complete substitution test matrix for either ticketed or zero-ticket attachments.

### Stale capability after channel deletion

Process-facing resolution confirms that a capability table contains a matching channel object before an operation. Creator cleanup can remove channels, after which ordinary table lookup fails.

Channel endpoints contain only a reusable numeric `ChannelId`; they have no activation generation or deletion epoch. Copied raw endpoints and surviving manager grants are not transactionally revoked when the table entry is deleted, so future ID reuse could redirect stale authority to a replacement channel.

### PID reuse confusion

Most process-facing calls obtain the caller PID from scheduler context rather than accepting it from user arguments. Capability tables and channel creators are indexed by that PID.

IPC identities, endpoint owners, wait queues, message sources, transfer records, and cleanup use a numeric PID without a process generation. A stale waiter, queued message, endpoint, or restored record can therefore refer to an unrelated process that later receives the same PID.

### Channel ID reuse confusion

Normal creation allocates increasing nonzero IDs and checks current map occupancy. The table is bounded to sixteen live channels, reducing immediate accidental collision.

`next_id` uses unchecked increment, restoration can advance it with saturation, and endpoints encode no channel generation. The table has no documented exhaustion or reuse policy, so wraparound, restoration, or future ID recycling can make stale references ambiguous.

### Forced protocol mismatch

Temporal-bound channels validate session, request ID, opcode, and expected phase before send commit and again before receive completion. Mismatches return `ProtocolMismatch` without advancing protocol state.

A malformed message at the queue head can repeatedly fail receive validation and block later messages. Authorized senders can intentionally desynchronize a session, request IDs wrap, and outer APIs collapse protocol errors into generic results that may encourage pointless retry.

### Temporal replay injection

Temporal frames are checked against the channel's current session and request state, while snapshots preserve selected protocol fields. Runtime tests cover representative valid and invalid phase transitions and snapshot round trips.

Frames contain no authenticated boot, channel-generation, or persistence epoch. Restore accepts historical state without a complete uniqueness and causal-order proof, and wrapping request and event identifiers allow old frames to become numerically plausible again.

### Close/drain abuse

Close requires local close authority, changes nonempty channels to `Draining`, rejects new sends, permits queued receives, and wakes blocked senders and receivers. Repeated lifecycle behavior has direct unit and runtime self-test coverage.

Close authority is inferred inconsistently across capability layers, and raw endpoints can bypass manager validation. An authorized closer can terminate producers, strand blocked operations, or force transfer rollback; forced deletion and process cleanup bypass graceful drain and do not transactionally settle queued capabilities.

### Wait queue poisoning

Channel-local sender and receiver queues have fixed capacity and discard excess entries rather than allocating indefinitely. Wake loops remove PIDs that no longer identify a blocked process and fall back to scheduler keyed waits.

Entries contain only numeric PIDs and are restored from snapshots without process generations. Overflow is silent, duplicate entries are not rejected, and local queues can diverge from scheduler queues. Stale or reused PIDs may cause wake attempts against the wrong process generation.

### Missed wakeup exploitation

IPC prepares a scheduler block while holding channel state, records the local waiter, releases the IPC lock, and then commits the block. Queue transitions and close issue keyed or targeted wakes.

Scheduler registration occurs during `commit_block`, after the IPC lock is released. Another CPU can potentially change the condition and issue a wake during that interval, while `commit_block` reports no failure status. No exhaustive multiprocessor interleaving test or proof closes this race.

### Syscall pointer abuse

Handlers reject zero or excessive lengths and numerically reject ranges crossing the fixed `0xC0000000` boundary. User payloads are copied into kernel-owned messages rather than retained as pointers.

The checks do not validate actual mappings, access permissions, alignment, ownership, or concurrent unmapping, and several additions are not checked for overflow. `from_raw_parts`, typed slices, and `copy_nonoverlapping` can fault the kernel on numerically valid but inaccessible addresses.

### Malformed capability ABI struct

`SysIpcCapability` has a fixed C representation and conversion code reconstructs split 64-bit fields. Capability count is bounded before the input array is read.

The structure is private, unversioned, native-endian, omits transfer tickets, and has no size or feature field. Unknown types are not handled through a forward-compatible contract, typed user reads assume alignment, and attacker-controlled authority fields are re-signed rather than resolved.

### Oversized message attempt

`Message::with_data` rejects payloads larger than `MAX_MESSAGE_SIZE` and queue storage is fixed at 512 payload bytes per message. Unit tests cover exact-limit acceptance and one-byte-over rejection.

Send syscalls accept lengths up to 4096 bytes, allocate a vector, and copy user memory before the IPC layer rejects bytes 513 through 4096. Repeated oversized attempts can consume allocation, copy, audit, and error-path CPU without ever entering the queue.

### Too-many-caps attempt

Messages contain sixteen fixed attachment slots, `add_capability` returns `TooManyCaps`, and `sys_channel_send_caps` rejects counts above `MAX_CAPS_PER_MESSAGE` before reading the array.

The public message fields can be made internally inconsistent, and rollback after partial multi-capability construction is best effort rather than transactional. No syscall-level test covers count arithmetic, malformed arrays, duplicate capabilities, duplicate tickets, or insertion failure after earlier reservations.

### Partial receive buffer truncation

Receive copies at most the caller's payload buffer length and returns the number of bytes written. The capability syscall uses an internal array sized to the maximum attachment count.

Payload truncation is silent: the message is dequeued even when the caller cannot hold the complete payload. Capability output has no caller-supplied capacity field, and payload, capability records, and count are written separately after dequeue, so a fault can produce partial output and permanent message or authority loss.

### Covert timing channel through backpressure

Unauthorized process-facing calls are generally rejected during capability resolution before channel lookup. Queue pressure is bounded and classified into available, high, and saturated states.

Authorized or partially informed callers can distinguish pressure, lifecycle, pointer, protocol, and scheduler states through latency, blocking, wake behavior, and coarse but different errors. Persistence, audit, rollback, and predictive-policy work add state-dependent timing, and no disclosure or timing-normalization policy is defined.

### Denial of service through channel exhaustion

The channel table rejects creation after sixteen live channels, and capability and scheduler tables have independent fixed limits. This prevents unbounded registry growth.

There are no per-process channel quotas, reservations for critical services, reclamation policy, or distinct public capacity error. A permitted process can consume the global table, capability slots, pending tickets, or scheduler wait queues and deny service to unrelated principals; creation failures are often mislabeled as `ENOMEM`.

## Memory Safety Audit

### Fixed-array bounds

Message payload storage has 512 bytes and capability storage has sixteen optional entries. Constructors and normal insertion methods compare requested lengths with those capacities before indexing. Wait queues also use fixed sixteen-entry storage and refuse additional entries by dropping them.

The arrays themselves are bounded, but several associated length fields are public. Internal code can set payload length or capability count beyond the corresponding array, after which slicing and iteration can panic. Fixed storage therefore prevents heap growth but does not make malformed metadata unrepresentable.

### Payload copy bounds

Message construction checks the source length before copying into the payload prefix. Receive helpers select the smaller of the stored payload length and destination length, preventing an ordinary slice copy from writing beyond the supplied output slice.

The stored payload length is trusted when Message payload is exposed, so direct mutation can cause an out-of-range slice. Syscall copies rely on unsafe user pointers after numeric checks and can fault despite using a bounded byte count. Undersized receive buffers silently lose the uncopied suffix after dequeue.

### Capability array bounds

Normal attachment insertion checks the sixteen-capability limit before indexing, and syscall send rejects a larger count before reading the user array. Capability iteration is limited to the declared prefix.

The capability array and count are public and can disagree. A count above sixteen can panic during slicing, while holes inside the declared prefix are silently skipped. Partial multi-capability construction also lacks one atomic validation and rollback operation.

### Ring buffer indexing

The ring buffer delegates storage and indexing to VecDeque, uses push at the back and pop at the front, and checks the fixed logical capacity before insertion. It does not perform manual head or tail arithmetic.

This avoids custom wraparound indexing errors, but the logical bound remains procedural rather than encoded by the container type. Restore and future crate-internal paths must continue using the checked insertion method, and removed storage is retained without zeroization.

### Native-size to 32-bit conversion safety

Several IPC values are narrowed from the platform-native size to 32 bits for channel identifiers, syscall results, serialized payload lengths, and counters. Current payload, capability, queue, and channel limits are far below the 32-bit maximum, so those bounded values convert without loss through normal paths.

Other conversions are not uniformly checked. Native channel identifiers are cast to 32 bits, and 64-bit architecture syscall registers are narrowed into 32-bit argument fields before IPC sees them. Large pointers and scalar values can lose their upper bits.

| Conversion | Current bound or source | Result |
|---|---:|---|
| Message payload length | At most 512 | Safe within 32 bits |
| Capability count | At most 16 | Safe within 32 bits |
| Queue depth | At most 4 | Safe within 32 bits |
| Native syscall argument | Up to native pointer width | Upper bits can be lost |
| Native channel value | Platform-native size | Cast is not checked |

### Native-size to 16-bit conversion safety

Snapshot encoding narrows capability count, queue depth, waiter count, and selected lengths to 16 bits. Their normal limits are sixteen, four, sixteen, and 512, so those values fit under the current configuration.

The safety depends on configuration and prior validation rather than checked conversion. Public metadata and future capacity increases can silently truncate, while message and request sequence counters intentionally wrap at 16 bits.

| Conversion | Current maximum | 16-bit capacity | Current assessment |
|---|---:|---:|---|
| Message payload length | 512 | 65,535 | Fits |
| Capabilities per message | 16 | 65,535 | Fits |
| Messages per channel | 4 | 65,535 | Fits |
| Local waiters per direction | 16 | 65,535 | Fits |
| Message sequence | 65,535 before wrap | 65,535 | Reuse occurs after wrap |

### Split and recombined 64-bit field correctness

The syscall capability structure represents object identity, issue time, expiry time, and token as low and high 32-bit halves. Encoding takes the low half and a right-shifted high half; decoding reconstructs the value by shifting the high half left and combining it with the low half.

The arithmetic is correct for all 64-bit bit patterns, but dedicated boundary tests are absent. Transfer ticket identity is not represented at all, and the structure uses native field byte order rather than an explicit cross-endian encoding.

| Field | Low half | High half | Recombined value |
|---|---|---|---|
| Object identity | Bits 0 through 31 | Bits 32 through 63 | High shifted left 32, then combined with low |
| Issue time | Bits 0 through 31 | Bits 32 through 63 | High shifted left 32, then combined with low |
| Expiry time | Bits 0 through 31 | Bits 32 through 63 | High shifted left 32, then combined with low |
| Token | Bits 0 through 31 | Bits 32 through 63 | High shifted left 32, then combined with low |
| Transfer ticket | Not present | Not present | Lost at the syscall boundary |

### Temporal payload parsing bounds

Temporal request and response parsers verify the minimum header size, magic value, declared payload length, and exact frame extent before returning borrowed payload slices. Integer readers return absence when the requested byte range is unavailable.

Reserved fields are not consistently required to be zero, and parser tests cover selected malformed frames rather than every short length and contradictory field combination. Parsing is bounds-aware but not yet supported by a dedicated malformed-input corpus.

### Snapshot restore bounds

Full channel restore checks minimum structure size, object type, channel identity, owner, lifecycle tag, protocol tag, waiter counts, message counts, payload lengths, capability counts, and queue capacity. Message restoration rejects truncated payloads and counts above fixed message bounds.

Restore applies some state and rehydrates pending capability tickets as it progresses. A later failure can therefore leave external transfer state partially changed even when the restored channel is not published. Snapshot authenticity, trailing-byte policy, generation consistency, and all malformed count combinations are not comprehensively validated.

### Output buffer bounds

Kernel-slice receive helpers copy only the smaller of message length and output length. Syscall receive uses a kernel staging buffer and limits the payload copy to the returned byte count.

User output safety is not established by these length calculations. The destination may be unmapped, read-only, partially mapped, or concurrently removed, and capability records plus the count are written separately. Dequeue occurs before successful completion of all output writes.

### Zeroing unused payload space

Message constructors initialize the entire payload array to zero and then copy only the active prefix. Snapshot message restoration starts from a newly zeroed Message and fills the declared payload bytes, leaving the unused tail zero on those normal paths.

The payload and length remain publicly mutable, so this condition is not preserved structurally. Dequeued and cleared Message values are not scrubbed from retained VecDeque allocation, leaving previous payload bytes in reusable kernel heap storage.

### No uninitialized memory exposure

Message payloads, capability slots, syscall staging arrays, and restored message objects are initialized before their normal safe access. Capability output writes only the number of converted records reported to the caller.

Unsafe user-memory operations are not fault-contained, and public metadata can expose stale initialized bytes outside the logical payload rather than truly uninitialized Rust memory. Retained queue allocation and partially completed user output can disclose previous data unless storage is scrubbed and copy-out is transactional.

### No use-after-delete channel references

The channel table owns Channel values directly and operations hold the global table lock while borrowing a channel. Removing a map entry invalidates no outstanding Rust reference because deletion cannot occur concurrently through that same lock.

Logical references outlive deletion. Channel capabilities store numeric IDs without generations, manager grants are not transactionally revoked with table removal, and restored or copied endpoints can later address a replacement channel if an ID is reused.

### No dangling wait queue PIDs

Wake loops remove local entries whose PID no longer names a process that can be awakened. Process cleanup removes scheduler process state, and fixed wait queues prevent unbounded stale-entry accumulation within one channel.

Local wait queues store only numeric PIDs and are not comprehensively purged on process exit. They lack process generations, permit duplicate entries, and can be restored from snapshots. PID reuse can turn a stale waiter into a reference to a different process.

### Panic-free parsing

Temporal frame and snapshot readers generally use optional checked reads and return typed static errors for missing or inconsistent fields. Normal constructors reject oversized payload and capability counts before slicing.

Panic freedom is not guaranteed for all malformed internal state. Public payload and capability counts can make later slices panic, conversion helpers rely on assumptions not expressed in types, and no fuzz target exhaustively exercises temporal frames, snapshots, capability records, and syscall pointer faults.

## ABI and Cross-Architecture Audit

### Syscall register ABI

All entry paths normalize one syscall number and five arguments before common dispatch. Legacy x86 uses EAX for the number and EBX, ECX, EDX, ESI, and EDI for arguments. The x86-64 and AArch64 paths receive native-width registers but narrow them to 32 bits.

| Architecture | Number | Arguments | Result |
|---|---|---|---|
| x86 | EAX | EBX, ECX, EDX, ESI, EDI | Packed value and error |
| x86-64 | RAX narrowed to 32 bits | Five native registers narrowed to 32 bits | Packed value and error |
| AArch64 | X8 narrowed to 32 bits | X0 through X4 narrowed to 32 bits | Value in X0, error in X1 |

The contract is not versioned, and the x86-64 dispatcher accepts but discards a sixth argument.

### System call argument structure layout

The argument structure has C representation and six consecutive unsigned 32-bit fields. Its expected size is 24 bytes with 4-byte alignment.

It accurately represents x86 but cannot preserve native x86-64 or AArch64 pointers. No compile-time size, alignment, or field-offset assertions bind it to assembly.

| Field | Expected offset |
|---|---:|
| Number | 0 |
| Argument 1 | 4 |
| Argument 2 | 8 |
| Argument 3 | 12 |
| Argument 4 | 16 |
| Argument 5 | 20 |

### System call result structure layout

The result structure has C representation with a signed 32-bit value followed by an unsigned 32-bit error number. Its expected size is 8 bytes.

Hardware return placement differs by architecture, and successful values outside the signed 32-bit range cannot be represented.

### System call IPC capability structure layout

The capability structure has C representation and seventeen consecutive unsigned 32-bit fields. Four 64-bit values are represented as low and high halves, producing an expected size of 68 bytes.

The structure is private, unversioned, native-endian, and missing the transfer ticket. User space must nevertheless know its exact layout and provide space for sixteen records.

| Group | Representation |
|---|---|
| Capability identity | One 32-bit field |
| Object identity | Two 32-bit halves |
| Rights, type, owner, flags | Four 32-bit fields |
| Issue and expiry time | Four 32-bit halves |
| Metadata | Four 32-bit fields |
| Token | Two 32-bit halves |
| Transfer ticket | Absent |

### 32-bit userspace compatibility

The logical ABI naturally matches 32-bit userspace. Pointers, lengths, handles, and capability fields are 32-bit, and the WASM SDK uses the same width.

Compatibility remains implicit rather than versioned and lacks a full userspace conformance program.

### 64-bit kernel object IDs

Object identities, validity times, and tokens retain 64 bits through low and high halves. Reconstruction shifts the high half left by 32 bits and combines it with the low half.

Channel and capability IDs remain 32-bit, transfer tickets are omitted, and native pointers are truncated. Selected 64-bit fields do not make the syscall ABI 64-bit safe.

### x86 path

The x86 path maps saved registers directly into the common argument structure. Interrupt 0x80 and SYSENTER converge on the Rust dispatcher, and the packed result fits the EAX and EDX convention.

Assembly and Rust frame layouts lack generated offset assertions and a complete userspace IPC round-trip test.

### x86_64 path

The x86-64 path supports an interrupt gate and native SYSCALL dispatch. Fork return-frame cloning uses checked stack arithmetic.

Every argument is narrowed to 32 bits, pointers above four gigabytes are corrupted, the sixth argument is ignored, and results remain 32-bit. The assembly entry stub is not mechanized.

### aarch64 path

The AArch64 path reads X8 and X0 through X4, validates the exception-frame pointer, and returns through X0 and X1. Fork frame cloning uses checked subtraction and 16-byte alignment.

Arguments are still narrowed to 32 bits, and no complete AArch64 userspace IPC workload verifies the real entry path.

### Endian assumptions

Temporal serialization explicitly uses little-endian bytes, while syscall structures use native integer layout.

Current targets are little-endian, but the ABI does not declare that requirement or support future big-endian targets.

### Alignment assumptions

The shared structures contain 32-bit fields and require 4-byte alignment. Kernel-owned instances meet that requirement.

Capability send forms a typed slice from a user pointer without checking alignment, which can violate Rust requirements before conversion.

### Structure padding assumptions

Consecutive 32-bit fields require no expected internal padding under current C layouts.

No compile-time size, alignment, or offset assertions enforce this, and no generated userspace header verifies agreement.

### Stable syscall numbers

IPC operations use explicit numbers 10 through 15. Dispatch is sparse and unknown numbers return an unsupported-call error.

The invariant checker narrows numbers to 16 bits and assumes a contiguous maximum of 64, although internal number 250 is recognized. Versioning and reservation policy are absent.

| Number | IPC operation |
|---:|---|
| 10 | Create channel |
| 11 | Send message |
| 12 | Receive message |
| 13 | Close channel |
| 14 | Send with capabilities |
| 15 | Receive with capabilities |

### Syscall documentation sync

Platform and IPC documentation describe parts of the contract, while the WASM SDK defines a smaller 32-bit host-call surface.

There is no generated source of truth shared by the syscall enum, assembly, documentation, userspace declarations, and tests.

### Userspace test harness

Kernel tests cover invalid syscall handling and zero-length IPC rejection. Runtime and QEMU checks exercise selected platform paths.

No userspace program performs full create, send, receive, capability transfer, close, pointer-fault, and boundary workflows through each real architecture entry stub.


## Process Lifecycle Audit

### Process-owned channel cleanup

Process termination calls the platform cleanup hook, which invokes IPC channel purge and then removes the process capability table, remote leases, security state, and architecture-specific runtime state. IPC purge removes channels whose creator field equals the exiting PID.

This is creator-based cleanup rather than complete process-resource cleanup. Channels created by another process but used by the exiting process survive, while delegated endpoints, pending tickets, queued capabilities, and channel-local waiter entries are not settled together.

### Process channel purge behavior

The purge helper locks the global channel table, removes every channel with a matching creator PID, and returns the number removed. The table operation uses retention, so removal is bounded by the sixteen-channel registry.

Purge does not gracefully close channels, wake all peers, revoke matching capabilities in other process tables, roll back queued transfers, zeroize queued data, or emit deletion persistence records. It has no typed failure result and no direct test.

### Blocked sender on process exit

Scheduler process removal deletes the exiting PID from scheduler wait queues. This prevents a terminated sender from remaining in the scheduler's keyed wait registry.

The channel-local waiting-senders queue is separate and is not purged during process exit. Its stale numeric PID remains until a future wake loop removes it, and PID reuse can redirect that wake attempt to an unrelated process.

### Blocked receiver on process exit

Scheduler cleanup likewise removes an exiting receiver from scheduler wait queues. Future channel activity can skip local receiver entries when wake-process reports that the PID cannot be awakened.

Local receiver wait records are not removed synchronously, carry no process generation, and may be persisted in snapshots. A receiver blocked on a channel deleted during another process's exit receives no typed close, cancellation, or revocation outcome.

### Creator dies while channel has messages

Creator termination removes the channel immediately through table retention, regardless of whether it is open, draining, or contains queued messages.

Queued payloads are discarded without graceful drain, peer notification, transfer settlement, deletion audit, or explicit data-loss record. The normal drain-before-seal lifecycle therefore does not apply to process cleanup.

### Sender dies while message queued

A queued Message is kernel-owned and contains copied payload data, so sender address-space destruction does not invalidate the payload bytes. Ordinary messages can still be delivered if the channel survives because its creator is another process.

The message source is only a numeric PID. Sender capability revocation does not cancel queued messages, causal identity has no process generation, and ticketed attachments can retain pending source state after the source capability table is destroyed.

### Receiver dies while capabilities queued

Queued capability envelopes remain inside the channel until a receiver dequeues them or the channel is removed. Destroying one receiver process does not automatically destroy a channel created by another principal.

There is no destination binding in the envelope, no receiver succession policy, and no cleanup transaction that rolls capability transfers back when the intended receiver exits. Another authorized receiver can consume the message, or the ticket can remain pending indefinitely.

### PID reuse after queued messages

Messages, endpoint owners, channel creators, wait queues, audit records, and transfer state all store 32-bit numeric PIDs. The scheduler and capability tables remove current process state during termination.

None of those IPC records includes a process generation. A queued message from an old process can appear to originate from a new process with the same PID, and stale waiter, owner, restore, or transfer records can be associated with the replacement process.

### Orphaned channels

Creator-owned channels are normally removed by the process termination hook, limiting the most direct orphan case.

Cleanup can be bypassed by abnormal paths, temporal restoration can recreate a channel for a dead creator, and direct table mutation can create state outside the normal lifecycle. Channels delegated to other processes are deleted when the creator exits even when a surviving owner might need them, because no explicit channel survival policy exists.

### Orphaned capabilities

Capability teardown revokes all local entries owned by the exiting process and removes owner-bound quarantined capabilities and remote leases.

Capabilities delegated to other processes for deleted channels are not proactively revoked. Pending transfer records are stored in a separate global ledger and are not removed by task teardown. Surviving holders discover invalidity only when later channel lookup fails.

### Temporal restore of dead process channels

Temporal replay can ensure a channel exists for a serialized channel ID and creator PID, then restore queue, lifecycle, waiter, protocol, metric, and capability-transfer state.

Restore does not verify that the creator or queued message principals are live process generations. It can recreate channels and waiter PIDs for dead processes, rehydrate pending tickets after source teardown, and overwrite the practical effect of earlier process cleanup.

### Scheduler cleanup integration

The process manager termination hook calls IPC purge before capability and security teardown. Slice-scheduler process removal also removes the PID from scheduler wait queues, and fault termination uses the scheduler removal path.

The cleanup sequence is not one atomic cross-subsystem transaction. IPC purge acquires IPC state, capability teardown acquires capability state, and scheduler cleanup maintains a separate wait registry, while failures are mostly ignored. No integration test proves cleanup ordering, wake behavior, ticket settlement, or consistency after partial failure.

## Service IPC and Higher-Level Protocol Audit

### Service registry IPC use

The registry stores service offers containing a service type, namespace, provider PID, version, connection limit, and numeric channel ID. Introduction checks a caller-supplied introducer value for service and namespace scope, increments counters, and returns the channel ID and metadata.

Registration and introduction are direct in-kernel method calls rather than messages processed through an IPC endpoint. The registry does not resolve the introducer from the capability manager, authenticate the requester field, transfer an endpoint capability, decrement connection counts, or verify that a registered channel still belongs to the declared provider.

### Filesystem IPC use

The filesystem uses IPC for watch notifications rather than for its main operation interface. A subscriber supplies a channel ID, the VFS resolves kernel send authority, queues bounded watch records, sends one record at a time, and requires an acknowledgement before advancing that subscriber's backlog.

Would-block results retain the record for a later drain attempt, while invalid or closed channels remove the subscription. The subscription is still identified by a generation-free numeric channel ID, notification messages do not bind an authenticated recipient, and several unexpected send failures are ignored without a typed subscriber-visible outcome.

### Compositor IPC use

The compositor has the most complete service wire path. It creates and registers a service channel, processes a bounded number of messages per pump, authenticates session creation with the message source, decodes a fixed little-endian envelope, dispatches typed requests, and encodes typed responses.

The first four payload bytes contain a caller-selected reply channel ID. The compositor constructs kernel send authority for that number instead of receiving a verified reply endpoint capability. Failed decoding and failed replies are silently dropped, input delivery uses separate state, and callers that invoke the compositor service directly bypass the wire envelope and its source binding.

### Fetch service IPC use

The fetch module defines fixed-capacity request, response, and event types and describes them as an IPC protocol. Its public entry point directly passes a FetchRequest value to a global in-kernel service object, and the implementation search finds no channel creation, service registration, wire encoder, wire decoder, or message pump for fetch traffic.

The OpenSession request accepts a PID inside the typed value, and length fields use native usize values. These choices are acceptable for a private Rust call but are not a stable or authenticated userspace protocol. The current implementation therefore provides a service model, not a completed IPC transport.

### WASM runtime IPC use

The WASM runtime exposes channel send, receive, and capability-carrying send host functions. WASM handles are checked against the instance capability table, linear-memory ranges are read through the runtime, and host calls participate in security intent and deterministic record or replay processing.

The runtime then reconstructs raw channel capabilities from stored channel IDs and calls IPC directly. Receive truncates a message to the caller's buffer, converts every receive failure into a zero-length result, and imports service capabilities after dequeue. The SDK uses 32-bit pointers and lengths, and the host path does not preserve typed IPC errors or required output size.

### Service pointer IPC use

Service pointers are a separate capability-mediated call mechanism rather than queued IPC. Invocation checks SERVICE_INVOKE authority, verifies the registered WASM function signature, applies a rate window, enters the target instance exclusively, validates result types, and supports revocation and temporal registry snapshots.

Because calls execute synchronously inside the runtime, service pointers do not inherit channel backpressure, cancellation, message identity, queue isolation, or reply framing. The legacy form narrows arguments and results to 32-bit words, while the typed form uses runtime Value objects that are not the same contract as TypedServiceArg.

### Typed service argument encoding

TypedServiceArg provides bounded encoders for one-byte integers, 32-bit integers, 64-bit integers, and fixed byte arrays. Integer encoding is explicitly little-endian, each encoder checks destination capacity, and fixed arrays avoid allocation.

No active service protocol uses this trait to construct messages. It does not encode its type tag or length into an envelope, has no aggregate argument format, and derives array tags by retaining only sixteen bits of the array length, allowing distinct large array types to share a tag.

### Typed service argument decoding

Primitive decoders require an exact input length and copy through fixed local arrays before little-endian reconstruction. Fixed byte arrays also require an exact length, so the implemented decoders reject truncation and trailing bytes without allocation.

There is no registry that maps an untrusted type tag to an allowed decoder, no sequence decoder, no recursion or aggregate-size policy, and no integration with service authorization. Decode errors distinguish only invalid length, which is insufficient for version, unknown-type, malformed-envelope, and policy failures.

### Service request/response framing

Framing is service-specific. The compositor uses a magic value, version, direction, opcode, reserved byte, and exact trailing-byte check; filesystem notifications use their own payload encoder; fetch exposes Rust enums without a wire format; service pointers use direct typed calls; and temporal IPC defines another independent frame structure.

There is no common service envelope carrying protocol identity, request ID, reply authority, caller generation, payload length, capability count, flags, deadline, or causal predecessor. As a result, routing, cancellation, retries, compatibility, and diagnostics require different logic for every service.

### Service confused-deputy risks

The compositor now replaces the PID in OpenSession with the authenticated message source, which closes one direct identity-substitution path. Capability checks inside compositor and fetch operations also reduce accidental cross-session access.

Other deputy risks remain. Registry requests contain an unauthenticated requester, fetch session creation trusts a supplied PID, filesystem subscriptions are keyed by caller-supplied channel numbers, and the compositor trusts a reply channel number without transferred send authority. Kernel callers can also invoke service methods directly and bypass transport-level identity binding.

### Service-level authorization

Authorization is inconsistent across services. The compositor uses service-local opaque capabilities, fetch uses its own Cap values, filesystem operations use VFS and channel capability checks, service pointers use the central capability manager, and the registry uses copyable introducer structures maintained partly outside its stored table.

There is no shared rule requiring the current principal, service endpoint, object generation, requested operation, and delegated rights to be validated together. Service-local tokens are not uniformly connected to central revocation, expiry, process generations, or capability transfer.

### Service protocol versioning

The compositor wire envelope requires version one, registry metadata advertises a numeric service version, and temporal snapshot formats maintain independent schema versions. These mechanisms show version awareness but do not form one compatibility policy.

Fetch requests, filesystem notifications, WASM channel payloads, and service-pointer calls do not negotiate protocol features or supported ranges. Registry introduction returns metadata but does not prove that clients check it, and no standard error communicates minimum, maximum, deprecated, or incompatible versions.

### Service protocol fuzzing

The codebase contains focused parser and subsystem tests, but no shared stateful harness drives arbitrary service messages through registry introduction, channel delivery, decoding, authorization, dispatch, response encoding, and cleanup. Direct typed dispatch tests cannot expose malformed wire layouts or reply-capability substitution.

Coverage is especially incomplete for compositor frame mutations, filesystem acknowledgement sequences, hypothetical fetch serialization, capability-bearing WASM messages, and cross-service interactions. There is no retained corpus organized by service protocol version and failure class.

### Malformed service argument handling

The compositor decoder uses checked cursor arithmetic, validates magic, version, direction, reserved bits, UTF-8, exact field lengths, and trailing bytes. TypedServiceArg primitive decoders also require exact sizes, and fetch internals use fixed-capacity fields.

Malformed handling is not uniform at service boundaries. The compositor pump discards bad requests without a response or audit reason, fetch length fields can disagree with their arrays when called directly, filesystem acknowledgement errors are static strings, and WASM receive truncates silently. No common rule guarantees that malformed input leaves service, capability, queue, and reply state unchanged.

### Cross-service causal audit

IPC Message carries an EventId and optional predecessor, and several services maintain their own temporal or audit records. These facilities can identify individual low-level events but are not propagated as one service operation context.

Compositor responses and filesystem notifications create new messages without linking them to the triggering request, direct fetch and service-pointer calls do not carry IPC event identities, and registry introductions record state without a caller-visible correlation identifier. A request crossing multiple services therefore cannot be reconstructed reliably as one authenticated causal chain.

## known limitations

### Known issues/TODOS in IPC architecture and trust boundary

Issue: The IPC architecture centralizes process communication, but several trust boundaries remain conventional rather than structurally enforced. Public service methods can bypass capability-manager resolution, temporal replay functions can create state without ordinary authorization, receive-side capability tokens are not verified, and the predictive security restriction hook currently permits every operation.

Required fixes:

1. Make the capability-resolving facade the only externally callable IPC operation surface.
2. Restrict temporal restore entry points to an authenticated replay authority and audit every restored object.
3. Verify transferred capability tokens, ownership, expiry, rights, and ticket state before delivery.
4. Replace the permissive predictive restriction stub with an explicit policy engine and fail closed when policy state is unavailable.
5. Document and test the complete trust transition from user memory through syscall validation, capability resolution, channel admission, queue ownership, and receiver copy-out.


### Known issues/TODOS in IPC file and component coverage

Issue: The module inventory describes the current source files, but component boundaries remain uneven. Message representation, channel state, admission, persistence, scheduler interaction, diagnostics, and facade translation are tightly coupled, while preparatory interfaces such as TypedServiceArg are not connected to live traffic. Broad dead-code suppression also makes it difficult to distinguish active infrastructure from unused scaffolding.

Required fixes:

1. Remove module-wide dead-code suppression and classify every unused item as required infrastructure, test support, future design, or removable code.
2. Separate persistence encoding, scheduler blocking, capability transfer, and syscall translation from the core channel state machine behind narrow interfaces.
3. Connect TypedServiceArg to a versioned service protocol or remove it from the active IPC contract until an implementation exists.
4. Add a maintained component table that names each file's owner, public contract, dependencies, tests, and maturity status.
5. Add dependency checks that prevent low-level message and channel modules from importing higher-level service or platform policy accidentally.


### Known issues/TODOS in IPC constants, limits, and capacity invariants

Issue: Payload, capability, queue, channel, and waiter limits are individually bounded, but their relationships are not verified as one configuration contract. Public channel-table state can bypass the channel limit, temporal restoration can reconstruct state outside normal admission, pressure arithmetic has no compile-time validation, and several counters can wrap or saturate without a uniform exhaustion policy.

Required fixes:

1. Add compile-time assertions for every nonzero capacity, pressure threshold, wait-address calculation, serialization width, and diagnostics-array relationship.
2. Make channel and message storage private so all changes pass through bounded APIs.
3. Revalidate every persisted count and length before restore and reject snapshots that exceed current limits.
4. Define typed overflow and exhaustion behavior for channel IDs, capability IDs, event sequences, metrics, and restore counters.
5. Add boundary tests for zero, exact maximum, one above maximum, arithmetic wrap, full global occupancy, and restore-time saturation.


### Known issues/TODOS in Syscall boundary audit

Issue: IPC syscall handlers perform direct pointer arithmetic and unsafe copies after checking only a fixed x86 address ceiling. They do not validate mappings, permissions, integer overflow, or address-space ownership through the calling process's memory manager. Payload limits disagree with the Message limit, error translation depends on static strings, and the ABI has not been proven consistent across i686, x86-64, and AArch64.

Required fixes:

1. Replace fixed-address checks with checked range validation against the caller's mapped readable or writable user pages.
2. Detect pointer-plus-length overflow before access and use fault-contained copy-from-user and copy-to-user primitives.
3. Enforce MAX_MESSAGE_SIZE before allocation and copy, including capability-carrying sends and receive staging buffers.
4. Propagate typed IpcError values to an exhaustive errno mapping instead of comparing error strings.
5. Define versioned fixed-width syscall structures and test field reconstruction, alignment, endianness, malformed pointers, partial mappings, and all supported architectures.
6. Add syscall-level fuzz and integration tests that exercise the complete dispatcher-to-channel path rather than calling IPC internals directly.


### Known issues/TODOS in Channel creation audit

Issue: Channel creation has two incompatible capability models, trusts a supplied creator PID, accepts contradictory or inert flags, and holds the IPC table lock while calling the capability manager. ID allocation and temporal restoration use different overflow rules, restored channels are not registered through the normal authority path, and internal code can bypass capacity enforcement through direct table access.

Required fixes:

1. Reconcile creation into one transaction that issues a documented endpoint model and registers all resulting authority consistently.
2. Derive the creator identity from authenticated execution context instead of accepting an unchecked ProcessId.
3. Validate flag combinations, remove flags with no semantics, and connect retained priority and reliability settings to real policy.
4. Define and enforce one lock ordering rule between IPC, capability management, scheduling, security, and temporal storage.
5. Make channel-table storage private and allocate nonzero IDs with collision detection and explicit exhaustion handling.
6. Restore channels, endpoint authority, generation state, and capability registrations through one validated transaction with complete rollback.


### Known issues/TODOS in Event ID bit layout

Issue: The 64-bit field layout round-trips correctly, but EventId is publicly constructible from an arbitrary u64 and the field allocation is too small to provide durable uniqueness without external epoch and generation state.

Required fixes:

1. Make the raw tuple field private and require validated constructors.
2. Define the exact uniqueness domain and assign sufficient bits or a wider identity type for that domain.
3. Add compile-time masks and round-trip tests for minimum, maximum, and mixed field values.


### Known issues/TODOS in Event source PID encoding

Issue: Source PID is copied into EventId but is not authenticated against Message::source or the sending capability owner. PID reuse also allows unrelated process generations to share the same source component.

Required fixes:

1. Stamp source identity inside the authenticated send path.
2. Include a process generation or principal identity that survives PID reuse safely.
3. Reject envelopes whose encoded source, message source, and endpoint owner disagree.


### Known issues/TODOS in Event channel sequence encoding

Issue: The middle 16-bit field is always zero for messages created through Message::new, so it carries no channel identity, sequence, or generation despite being documented as a channel sequence.

Required fixes:

1. Decide whether the field represents channel identity, channel-local ordering, or channel generation.
2. Stamp the chosen value when the message is committed to a specific channel.
3. Validate the field during receive and restore, and rename it if its final meaning is not a sequence.


### Known issues/TODOS in Event message sequence encoding

Issue: The low-order sequence comes from one global AtomicU16 rather than a per-process or per-channel counter. The comments and encoded meaning do not match the allocator.

Required fixes:

1. Choose and document a global, per-process, or per-channel allocation scope.
2. Move the counter into the owner of that scope and widen it enough for the required lifetime.
3. Add concurrency tests proving allocation uniqueness before exhaustion.


### Known issues/TODOS in Event sequence wraparound

Issue: The 16-bit allocator silently wraps and can reproduce an earlier EventId. Restore also selects a numeric maximum and adds one, which is not valid for wrapped sequences.

Required fixes:

1. Prevent silent reuse by widening the sequence or pairing it with a generation.
2. Define an explicit exhaustion result if uniqueness cannot be maintained.
3. Replace maximum-based restore with epoch-aware allocator restoration and collision detection.


### Known issues/TODOS in Event uniqueness within a process lifetime

Issue: EventId is unique for one PID only during a limited counter interval and while the allocator is not reset. Long-lived processes, PID reuse, direct construction, and restore can produce collisions.

Required fixes:

1. Track process generation and a nonwrapping per-process event sequence.
2. Check newly allocated identities against active and persisted identity state.
3. Add stress tests that cross the old 65,536-message boundary.


### Known issues/TODOS in Event uniqueness across reboot and session epochs

Issue: EventId contains no boot, restore, or persistence epoch, so identical values can recur across boots and restored sessions.

Required fixes:

1. Add a boot or persistence epoch to the canonical event identity.
2. Persist and authenticate the epoch used by restored messages.
3. Require logs and external APIs to carry the full compound identity rather than a bare u64.


### Known issues/TODOS in Event atomic ordering

Issue: Relaxed allocation provides atomic counter updates but no global ordering relationship with message publication, temporal persistence, or audit logging. The sequence must not be interpreted as a total event order.

Required fixes:

1. Define whether EventId is only an identifier or also an ordering token.
2. If ordering is required, derive it from the synchronized commit point and document the memory-ordering contract.
3. Add multi-CPU tests that compare allocation, enqueue, dequeue, and log order.


### Known issues/TODOS in Causal predecessor validation

Issue: Any EventId can be assigned as a cause without proving that the predecessor exists, was observed by the sender, predates the child, or belongs to the same authorized session.

Required fixes:

1. Issue predecessor references from a kernel-maintained received-event handle rather than accepting raw IDs.
2. Reject self-links, unknown events, forward references, expired references, and unauthorized cross-session links.
3. Define how missing predecessors are represented when history has been intentionally discarded.


### Known issues/TODOS in Causal DAG reconstruction

Issue: The kernel preserves individual cause edges but maintains no complete event index, cycle detection, retention policy, or graph integrity proof. A reliable DAG cannot be reconstructed from the current bounded records.

Required fixes:

1. Maintain an indexed causal record containing event identity, predecessor, channel generation, principal, and commit time.
2. Detect cycles and duplicate identities before accepting an edge.
3. Define retention, pruning, tombstone, and missing-parent semantics for bounded storage.


### Known issues/TODOS in Forged causal linkage detection

Issue: Event identities and predecessor edges have no authentication tag or authoritative issuance record. A valid sender can fabricate causal metadata independently of its channel authority.

Required fixes:

1. Bind the event identity, predecessor, source, channel generation, and protocol session into an authenticated envelope.
2. Verify that envelope before queue insertion and again when restoring persisted state.
3. Audit forged, duplicate, stale, and unauthorized causal references as distinct failures.


### Known issues/TODOS in Temporal event correlation

Issue: Full snapshots preserve EventId and cause, but lightweight temporal IPC events omit both values. Send and receive records therefore cannot be joined reliably to one message.

Required fixes:

1. Include canonical event identity and predecessor identity in temporal operation records.
2. Record channel and process generations alongside the IDs.
3. Add correlation tests covering identical payload sizes, repeated operations, wraparound, and restoration.


### Known issues/TODOS in Causal audit trail replay

Issue: Replay restores raw identities but does not validate uniqueness, causal order, epoch, source binding, or allocator monotonicity. Audit timestamps are disabled and most security events identify only a channel.

Required fixes:

1. Restore causal state through a validated, versioned replay transaction.
2. Preserve authenticated timestamps or logical commit order and reject regressions.
3. Reconcile allocator state across all restored and still-live channels before publishing any message.
4. Include EventId in relevant security audit entries.


### Known issues/TODOS in Causal message injection detection

Issue: Channel authorization limits who may send, but it does not prevent an authorized sender or internal caller from injecting duplicate, forged, or inconsistent EventId metadata.

Required fixes:

1. Generate immutable identity fields only at the channel commit boundary.
2. Maintain duplicate and stale-identity detection for the active generation.
3. Reject direct callers that attempt to override source, identity, epoch, or predecessor fields.


### Known issues/TODOS in Causal identity formal invariants

Issue: Tests cover encoding and simple lineage preservation, but no formal specification defines uniqueness, authenticity, acyclicity, temporal consistency, or replay behavior.

Required fixes:

1. Write explicit invariants for identity allocation, source binding, channel binding, predecessor validity, acyclicity, and epoch separation.
2. Model counter exhaustion, PID reuse, channel replacement, snapshot restore, and concurrent creation.
3. Add property tests or mechanized proofs for every invariant and retain counterexamples as regression fixtures.


### Known issues/TODOS in Maximum capability count enforcement

Issue: The normal APIs enforce the sixteen-capability limit, but caps_len and the storage array remain public and can be made inconsistent by internal callers or restored state.

Required fixes:

1. Make capability storage and count private.
2. Validate the count at construction, enqueue, snapshot restore, dequeue, and copy-out.
3. Add exact-limit, overflow, sparse-array, and malformed-restore tests.


### Known issues/TODOS in Capability insertion bounds checking

Issue: add_capability prevents an out-of-bounds write but does not detect duplicate attachments, sparse prefixes, conflicting ticket IDs, or already populated destination slots.

Required fixes:

1. Represent attachments with a bounded collection whose length cannot diverge from occupancy.
2. Reject duplicate capability IDs and ticket IDs unless an explicit duplication policy permits them.
3. Validate every attachment set as one unit before changing message state.


### Known issues/TODOS in Capability signing before insertion

Issue: add_capability signs any supplied envelope without first proving it came from the sender's capability table. The syscall path can therefore cause the kernel to authenticate user-selected object, rights, type, and ownership metadata.

Required fixes:

1. Accept capability IDs from user space rather than complete authority envelopes.
2. Resolve and export each capability through the capability manager before signing.
3. Remove unconditional re-signing from Message::add_capability and accept only manager-issued transfer objects.


### Known issues/TODOS in Capability transfer rollback on insertion failure

Issue: Rollback is best effort and nontransactional across multiple attachments. Failure after earlier insertions can leave pending transfers reserved, while discarded rollback results conceal incomplete restoration.

Required fixes:

1. Reserve all transfers in one batch before modifying the message.
2. Roll back the complete batch on any attachment, admission, queue, persistence, or copy failure.
3. Return and audit rollback failures with enough information for recovery.


### Known issues/TODOS in Ticketed capability rollback

Issue: The pending-transfer ledger supports rollback, but the ordinary capability-carrying syscall cannot carry or create ticket IDs and therefore bypasses the ticketed transfer transaction.

Required fixes:

1. Have sys_channel_send_caps call export_capability_to_ipc for sender-owned capability IDs.
2. Keep ticket IDs kernel-internal or expose them only through a versioned opaque transfer ABI.
3. Prove that process exit, channel closure, timeout, queue refusal, and restore each settle every pending ticket once.


### Known issues/TODOS in Capability token freshness

Issue: Tokens cover envelope fields but contain no receiver, channel, message, nonce, or transfer generation. Zero expiry is common, and add_capability replaces tokens without validating prior provenance.

Required fixes:

1. Bind tokens to the transfer ticket, source generation, destination, channel generation, and message identity.
2. Enforce issue and expiry policy using a trusted time or logical epoch.
3. Reject re-signing of envelopes that were not issued by the capability manager.


### Known issues/TODOS in Capability owner preservation

Issue: Received envelopes retain the source owner PID and are copied to user space without being imported or rebound to the receiver. The receiver obtains metadata rather than manager-recognized authority.

Required fixes:

1. Import each verified envelope into the receiving process before reporting success.
2. Return receiver-local capability IDs rather than source envelopes.
3. Record both source and destination principals in the transfer audit trail.


### Known issues/TODOS in Capability type preservation

Issue: The syscall path does not prove that a claimed capability type matches the sender's real grant, and temporal decoding converts unknown values to Generic instead of rejecting corrupted or future types.

Required fixes:

1. Derive type from the capability-manager entry during export.
2. Reject unknown serialized type values unless a versioned compatibility rule defines them.
3. Validate object existence and type-specific transfer policy before destination grant.


### Known issues/TODOS in Capability rights attenuation

Issue: Ticketed export transfers the complete source rights set, while the syscall path accepts an arbitrary rights mask supplied by user space. Neither path provides a clear, validated attenuation request.

Required fixes:

1. Let the sender request a rights subset expressed against a resolved source capability.
2. Prove the requested rights are a subset before creating the envelope.
3. Apply type-specific nondelegable and destination-policy restrictions before grant.


### Known issues/TODOS in Capability substitution attack resistance

Issue: Ticketed import compares core authority fields against the ledger, but user-space sends bypass that ledger and obtain a fresh kernel signature over reconstructed fields.

Required fixes:

1. Remove raw authority fields from the send syscall and resolve capabilities by sender-local ID.
2. Compare the complete canonical envelope against immutable pending-transfer state.
3. Add substitution tests for object, owner, type, rights, validity, flags, metadata, token, and ticket.


### Known issues/TODOS in Capability replay resistance

Issue: Ticket consumption prevents replay only for nonzero ticketed transfers. Zero-ticket envelopes can be copied and imported repeatedly after token verification, and the live syscall path creates zero-ticket envelopes.

Required fixes:

1. Require a one-time ticket for every authority-bearing IPC transfer.
2. Reject zero-ticket envelopes at receiver import except for explicitly non-authority metadata types.
3. Persist consumed-ticket tombstones or generations long enough to prevent replay after restart.


### Known issues/TODOS in Capability duplication risk

Issue: Capability and Message are Copy, so envelopes can be duplicated throughout queue inspection, snapshots, facade output, and caller state. Safety depends entirely on every consumer enforcing the ticket ledger.

Required fixes:

1. Remove Copy from transfer-bearing capability and message types.
2. Use affine pending-transfer guards that must be committed or rolled back.
3. Prevent raw envelope use outside the capability transfer module.


### Known issues/TODOS in One-time capability transfer semantics

Issue: Source removal and ticket consumption exist, but channel enqueue and receive do not complete the transaction. The receiver must separately call an import helper that the syscall path never invokes.

Required fixes:

1. Define the commit point as atomic dequeue plus destination capability installation.
2. Keep the message queued if validation or destination installation cannot complete.
3. Restore source authority or retain a recoverable pending state when receiver import fails.


### Known issues/TODOS in Receive-side capability validation

Issue: The receive path copies attachments without token verification, expiry checks, ticket consumption, source validation, object validation, or receiver grant. The secure import helper is disconnected from delivery.

Required fixes:

1. Validate and import all attachments before removing the message from the queue.
2. Fail the entire receive atomically if any attachment is invalid or cannot be granted.
3. Return only receiver-local capability IDs and typed errors to user space.


### Known issues/TODOS in Partial capability copy-out

Issue: Capability output can truncate silently for kernel callers, and syscall receive assumes space for sixteen fixed-size records without an explicit array capacity. Copy faults occur after dequeue and can permanently lose the message and pending authority.

Required fixes:

1. Add explicit payload and capability capacities to the receive ABI.
2. Report required sizes without dequeueing when either destination is too small.
3. Use fault-contained user-copy operations and commit dequeue only after all outputs and capability grants succeed.


### Known issues/TODOS in Message transmission authority

Issue: Send admission checks the SEND bit, but ChannelCapability is a public unsigned value and direct service calls do not authenticate its owner against the current process or Message source.

Required fixes:

1. Make channel endpoint construction private to the capability manager.
2. Verify endpoint token, owner, generation, and revocation state on every send.
3. Require the executing principal, endpoint owner, and message source to match or follow an explicit delegation record.


### Known issues/TODOS in Message reception authority

Issue: Receive admission checks the RECEIVE bit, but a constructed or copied endpoint can be used directly without capability-manager resolution or current-process authentication.

Required fixes:

1. Route every receive through a manager-issued authenticated endpoint handle.
2. Check the scheduler principal and endpoint generation before dequeue.
3. Add negative tests for foreign, revoked, expired, forged, and stale receive endpoints.


### Known issues/TODOS in Channel closure authority

Issue: Close authority is inferred from the combination of send and receive rights because the manager defines no independent CHANNEL_CLOSE right. Bidirectional communication therefore implies permission to shut down the channel.

Required fixes:

1. Add an explicit manager-level close right.
2. Grant close independently from send and receive according to channel policy.
3. Require a live authenticated close grant before beginning the lifecycle transition.


### Known issues/TODOS in All-rights channel capabilities

Issue: Combined capabilities expose send, receive, closure, creation, and clone-sender authority through one compromise point. Kernel PID zero also receives unconditional full authority.

Required fixes:

1. Issue least-privilege endpoint capabilities by default.
2. Separate channel creation, endpoint cloning, communication, and lifecycle administration.
3. Replace unconditional kernel bypass with named service principals and audited policy exceptions.


### Known issues/TODOS in Send-only capability correctness

Issue: Send-only endpoints work on positive paths, but the suite does not prove complete denial of receive, close, unauthorized delegation, and use after revocation.

Required fixes:

1. Add a full negative-operation matrix for send-only endpoints.
2. Verify every denied operation leaves queue, lifecycle, waiters, and audit state correct.
3. Test facade, direct service, remote lease, and restored endpoint paths separately.


### Known issues/TODOS in Receive-only capability correctness

Issue: Receive-only endpoints work on positive paths, but cross-process copying, stale use, close attempts, send attempts, and manager revocation are not comprehensively tested.

Required fixes:

1. Add the complete negative-operation matrix for receive-only endpoints.
2. Prove revocation wakes blocked receivers and prevents later dequeue.
3. Verify copied or forged receiver endpoints fail owner and generation checks.


### Known issues/TODOS in Close-capability enforcement

Issue: Channel::close checks only rights and channel ID on the raw endpoint. It does not verify origin, owner, token, generation, expiry, or current execution identity.

Required fixes:

1. Resolve close authority through the capability manager at the transition point.
2. Bind close grants to channel generation and administrator identity.
3. Audit denial, first close, repeated close, drain completion, and forced cleanup distinctly.


### Known issues/TODOS in Channel ID binding

Issue: ChannelCapability binds a numeric ChannelId without a generation. ID reuse can give stale endpoints authority over a replacement channel, and object ID zero can act as a wildcard manager grant.

Required fixes:

1. Pair every channel ID with a nonrepeating activation generation.
2. Reject stale generations before lookup or mutation.
3. Replace wildcard object grants with explicit scoped authority or a documented namespace capability.


### Known issues/TODOS in Channel endpoint owner binding

Issue: The owner field drives restriction and audit decisions but is not authenticated by ChannelCapability or checked against the executing process.

Required fixes:

1. Make owner immutable and covered by a manager-issued token.
2. Compare owner with authenticated scheduler identity on every operation.
3. Represent on-behalf-of execution through an explicit delegated principal rather than field substitution.


### Known issues/TODOS in Stale channel capability rejection

Issue: Facade resolution rejects many stale manager entries, but copied raw endpoints bypass revalidation and contain no generation, expiry, or revocation epoch.

Required fixes:

1. Replace raw endpoints with opaque handles resolved on each operation.
2. Bind handles to channel generation and capability revocation epoch.
3. Add tests for delete and recreate, restore, driver-style replacement, expiry, and process cleanup.


### Known issues/TODOS in Cross-process channel capability use

Issue: Manager lookup is process-scoped, but raw ChannelCapability values can be copied between kernel contexts without a recorded delegation or recipient binding.

Required fixes:

1. Prohibit raw endpoint transfer outside the capability manager.
2. Require destination-bound delegation with rights attenuation and lineage.
3. Verify current process identity rather than trusting endpoint.owner.


### Known issues/TODOS in Channel capability cloning and delegation

Issue: ChannelCapability implements Clone and Copy, so CHANNEL_CLONE_SENDER is not enforced once an endpoint value exists. Copies retain all rights and have no child identity or revocation lineage.

Required fixes:

1. Remove Clone and Copy from authority-bearing endpoint types.
2. Implement sender cloning through a capability-manager operation that checks CHANNEL_CLONE_SENDER.
3. Assign child capability IDs, attenuated rights, destination owners, and revocation ancestry.


### Known issues/TODOS in Affine endpoint delegation

Issue: AffineEndpoint conserves a const-generic capacity label but clones the same full ChannelCapability into both children. The manager does not recognize the split, and operations do not consume capacity.

Required fixes:

1. Define what affine capacity represents in enforceable kernel policy.
2. Have splits create manager-recognized child grants with explicit rights and quotas.
3. Remove the wrapper if it cannot be connected to authorization, accounting, or lifecycle enforcement.


### Known issues/TODOS in Zero-sum endpoint delegation

Issue: A plus B equals C is checked at runtime, but the resulting children duplicate authority. Numeric capacity conservation is not equivalent to zero-sum capability authority.

Required fixes:

1. Use checked addition and reject zero or otherwise invalid capacity partitions.
2. Consume the parent grant and issue children whose combined enforceable quota and rights do not exceed it.
3. Prove conservation through manager state rather than const-generic labels alone.


### Known issues/TODOS in Channel rights downgrade and attenuation tests

Issue: Tests cover selected positive rights paths but not the complete attenuation lattice, close inference, clone policy, wildcard grants, remote leases, stale handles, or cross-process misuse.

Required fixes:

1. Build a table-driven test for every source rights set, requested operation, and attenuated child set.
2. Include local grants, remote leases, kernel principals, temporal restore, revocation, and ID reuse.
3. Assert typed errors, unchanged state, audit records, and absence of unintended authority after every denial.


### Known issues/TODOS in Syscall number validity

Issue: The invariant narrows the syscall number to u16 and checks a contiguous maximum of 64, while the actual table is sparse and includes syscall 250. Dispatch catches unknown values, but invariant classification is incorrect.

Required fixes:

1. Validate the original u32 against the explicit SyscallNumber mapping.
2. Treat sparse holes as invalid and recognized high numbers as valid.
3. Add exhaustive tests for every defined number, every hole, truncation aliases, and boundary values.


### Known issues/TODOS in Syscall argument ABI layout

Issue: The shared ABI contains only five u32 arguments. x86-64 and AArch64 narrow native registers, preventing full-width pointers and silently discarding high bits.

Required fixes:

1. Define separate native-width architecture entry structures feeding one typed internal request.
2. Preserve 64-bit pointers and scalar arguments on 64-bit targets.
3. Version the userspace ABI and publish register assignments, result convention, and argument count.


### Known issues/TODOS in Syscall user pointer validation

Issue: IPC validates pointers only against a fixed 0xC0000000 ceiling and does not check mappings, permissions, ownership, overflow, or complete range coverage.

Required fixes:

1. Implement checked per-process user-range validation through the active address space.
2. Distinguish readable, writable, aligned, pinned, and faultable ranges.
3. Remove architecture-specific address constants from shared syscall handlers.


### Known issues/TODOS in Syscall user buffer read safety

Issue: from_raw_parts performs unprotected reads from user addresses after numeric checks. Unmapped, misaligned, partially mapped, or concurrently changed memory can fault the kernel.

Required fixes:

1. Add fault-contained copy-from-user primitives for bytes and structured arrays.
2. Validate and copy page by page with checked lengths and alignment.
3. Define behavior for partial faults and concurrent mapping changes.


### Known issues/TODOS in Syscall user buffer write safety

Issue: Receive writes payload, capability records, and count separately after dequeue. A fault can leave partial output and permanently lose the message.

Required fixes:

1. Add fault-contained copy-to-user primitives with writable-range validation.
2. Preflight every destination before dequeue and capability import.
3. Commit message removal only after atomic logical copy-out succeeds.


### Known issues/TODOS in IPC capability ABI stability

Issue: SysIpcCapability is private and unversioned, omits ticket_id, and assumes storage for sixteen records without an explicit caller capacity.

Required fixes:

1. Define a public versioned capability-transfer ABI with size and feature fields.
2. Replace raw authority envelopes with sender-local and receiver-local capability IDs.
3. Add an explicit output capacity and required-count result.


### Known issues/TODOS in Syscall split-field reconstruction

Issue: Four 64-bit fields round-trip through halves, but ticket_id is lost and native pointers are truncated. Boundary reconstruction lacks dedicated tests.

Required fixes:

1. Include every required 64-bit field or keep opaque transfer state entirely in the kernel.
2. Use shared encode and decode helpers with checked conversions.
3. Test zero, maximum, high-only, low-only, and mixed-bit vectors on every target.


### Known issues/TODOS in Syscall endianness assumptions

Issue: The capability structure relies on host-native u32 layout and does not state byte order. It is only implicitly compatible with the current little-endian targets.

Required fixes:

1. Declare the syscall ABI byte-order contract.
2. Use explicit fixed-endian encoding for memory structures or prohibit cross-endian compatibility clearly.
3. Add byte-level golden vectors independent of host struct interpretation.


### Known issues/TODOS in IPC syscall error mapping

Issue: Typed IPC failures are reduced to static strings and then mapped to broad errno values. Error distinctions are lost and string changes can alter behavior silently.

Required fixes:

1. Propagate IpcError directly to the syscall boundary.
2. Define an exhaustive stable mapping for permission, stale handle, closure, draining, backpressure, protocol, size, and removal failures.
3. Add table-driven tests for every internal error and public errno.


### Known issues/TODOS in IPC syscall audit logging

Issue: Recognized calls are audited with hashed arguments, but invalid calls follow a separate path, timestamps are disabled, and final outcomes and message identities are not consistently correlated.

Required fixes:

1. Record ingress and terminal outcome for every syscall, including invalid numbers and copy faults.
2. Restore trusted timestamps or logical sequence values.
3. Correlate IPC audit records with channel generation, EventId, capability IDs, and typed result while redacting sensitive addresses.


### Known issues/TODOS in IPC syscall policy blocking

Issue: Predictive blocking depends on a separate classification table whose completeness and rights accuracy are not proven for all IPC syscalls.

Required fixes:

1. Derive policy requirements from the same typed syscall definitions used by dispatch.
2. Add tests proving every IPC syscall requests the exact minimum rights.
3. Define fail-closed behavior for unclassified security-sensitive calls.


### Known issues/TODOS in Invalid syscall handling

Issue: Unknown syscalls return ENOSYS but may also trigger consistency-invariant fail-stop handling. Coverage tests only u32::MAX and not the sparse number space.

Required fixes:

1. Separate ordinary unsupported input from internal dispatch corruption.
2. Return ENOSYS safely for every unrecognized userspace number while auditing abuse rates.
3. Exhaustively test holes, high values, truncation aliases, and reserved ranges.


### Known issues/TODOS in Cross-architecture IPC syscall consistency

Issue: The shared handler masks major ABI differences: native registers are narrowed, address validation is x86-specific, and no conformance suite proves equivalent IPC behavior on i686, x86-64, and AArch64.

Required fixes:

1. Write an architecture-neutral IPC syscall specification with target-specific register bindings.
2. Preserve native address width and validate through each target's memory manager.
3. Run identical positive and negative IPC syscall suites on all supported QEMU targets.


### Known issues/TODOS in IPC syscall privilege enforcement

Issue: Numeric PID bypasses grant channel creation and kernel PID zero receives full authority. Attached capabilities are not resolved, and close revocation confuses channel and capability ID namespaces.

Required fixes:

1. Express privileged principals and bootstrap rights through the capability manager.
2. Resolve every attached capability from the sender's table and import it for the receiver.
3. Revoke the actual resolved capability ID and surface revocation failure.
4. Remove PID-number policy exceptions from syscall handlers.


### Known issues/TODOS in IPC syscall fuzzing

Issue: No dedicated harness exercises raw IPC syscall arguments against realistic user mappings, faults, capability state, policy state, and architecture adapters.

Required fixes:

1. Build a deterministic fake user-address-space and copy-fault harness.
2. Fuzz numbers, lengths, ranges, alignment, aliases, capability fields, counts, flags, and policy outcomes.
3. Preserve every crash, incorrect errno, partial copy, and authority violation as a permanent regression case.


### Known issues/TODOS in Send admission pipeline

Issue: Send admission is evaluated by IpcService, again by Channel::send_with_observed_pressure, and temporal validation is then repeated once more before insertion.

Required fixes:

1. Evaluate admission exactly once under the lock that protects commit state.
2. Carry a validated admission token into queue insertion rather than rerunning checks.
3. Add tests proving state cannot change between decision and commit.


### Known issues/TODOS in Receive admission pipeline

Issue: evaluate_recv can return Deliver before validating the temporal protocol of the head message. The final delivery decision is split between admission and execution.

Required fixes:

1. Peek and validate the head message inside receive admission.
2. Return one complete decision that guarantees pop can proceed.
3. Define recovery for a malformed head message without blocking the queue forever.


### Known issues/TODOS in Predictive admission restrictions

Issue: Restriction checks and resulting revocation trust the unauthenticated ChannelCapability owner field, and predictive denial is exposed as ordinary PermissionDenied.

Required fixes:

1. Derive the principal from authenticated execution context.
2. Bind predictive revocation to manager-issued capability identity and generation.
3. Preserve a typed policy-restriction outcome for audit and authorized diagnostics.


### Known issues/TODOS in Admission permission denial

Issue: Rights denial is correctly prioritized, but raw endpoints can be forged internally and facade string conversion loses the typed denial reason.

Required fixes:

1. Require authenticated manager-issued endpoints at admission.
2. Propagate IpcError without static-string conversion.
3. Add a complete rights-denial matrix with state and audit assertions.


### Known issues/TODOS in Admission invalid capability handling

Issue: InvalidCapability checks only ChannelId mismatch. It does not detect owner mismatch, stale generation, revocation, expiry, invalid token, or foreign execution identity.

Required fixes:

1. Validate the full endpoint identity and lifecycle before operation-specific policy.
2. Distinguish malformed, stale, revoked, expired, and foreign capabilities.
3. Add tests for each invalidity class and its audit result.


### Known issues/TODOS in Admission protocol mismatch handling

Issue: Send protocol validation is duplicated, while receive validation occurs after admission. A malformed queued head remains in place and can deny service indefinitely.

Required fixes:

1. Validate temporal framing once in each complete admission pipeline.
2. Quarantine, fail, or remove malformed messages according to a documented policy.
3. Emit a dedicated protocol-violation audit event with session and message correlation.


### Known issues/TODOS in Admission closed-channel behavior

Issue: Closed behavior is implemented but its precedence relative to protocol and authorization errors is undocumented, and facade error conversion can hide closure from callers.

Required fixes:

1. Specify the observable precedence of rights, protocol, lifecycle, and capacity failures.
2. Preserve Closed as a typed public result.
3. Test closed channels with empty and nonempty queues across every rights combination.


### Known issues/TODOS in Admission draining-channel behavior

Issue: Draining correctly blocks sends and allows receives, but coverage does not span empty queues, temporal phases, capability attachments, repeated close, and final sealing.

Required fixes:

1. Add a complete draining-state admission matrix.
2. Preserve ChannelDraining through facade and syscall mappings.
3. Prove ticket rollback and waiter wakeup behavior for every refused send during draining.


### Known issues/TODOS in Admission empty-queue behavior

Issue: Expected empty-queue waiting is counted and persisted as a refusal, while the QueueEmpty refusal variant is never produced. Blocking and nonblocking absence share one WouldBlock result.

Required fixes:

1. Separate normal defer metrics from policy and error refusals.
2. Remove QueueEmpty or use it consistently for nonblocking receive.
3. Expose distinct typed outcomes for empty, blocked, timed out, closed, and revoked waits.


### Known issues/TODOS in Admission full-queue behavior

Issue: Full async refusal and synchronous deferral collapse to WouldBlock. Deferred sends roll back transfer tickets before IpcService blocks and retries the copied message.

Required fixes:

1. Retain ticket reservations across a legitimate capacity wait.
2. Roll back only when the send is abandoned or terminally refused.
3. Distinguish immediate queue-full refusal from active blocked deferral in results and metrics.


### Known issues/TODOS in Reliable channel deferral

Issue: Saturation deferral depends only on absence of ASYNC. The RELIABLE flag is inert and does not define retry, delivery, ordering, or loss guarantees.

Required fixes:

1. Define the exact semantics of RELIABLE or remove the flag.
2. Connect reliability policy to blocking, cancellation, process exit, reset, and transfer rollback.
3. Add end-to-end tests for eventual delivery and terminal failure.


### Known issues/TODOS in Async channel refusal

Issue: Async refusal policy depends on unvalidated and partly inert flags. Contradictory bounded modes are accepted, and priority changes high-pressure behavior without scheduler integration.

Required fixes:

1. Validate channel mode combinations at creation.
2. Define async, bounded, and priority policy in one state model.
3. Test every pressure level and flag combination with deterministic outcomes.


### Known issues/TODOS in Admission ordering

Issue: Send and receive ordering are asymmetric, admission is repeated, and no test proves precedence when several failure conditions are simultaneously true.

Required fixes:

1. Specify a common ordered policy framework for both directions.
2. Make differences such as draining receive and protocol phase explicit rules.
3. Add table-driven overlapping-failure tests that assert the first outcome and side effects.


### Known issues/TODOS in Admission refusal side channels

Issue: Error type, timing, audit work, persistence, and blocking behavior reveal different channel states to authorized callers and differ across direct, facade, and syscall paths.

Required fixes:

1. Define which distinctions each caller class is allowed to observe.
2. Normalize external errors and timing where state disclosure is not authorized.
3. Preserve detailed reasons only in privileged audit records with redacted context.


### Known issues/TODOS in Admission decision auditability

Issue: Only permission and invalid-capability decisions receive specific security events. Other refusals collapse into broad temporal events, lack EventId correlation, and do not record ticket rollback failure.

Required fixes:

1. Assign structured audit reason codes to every Commit, Refuse, and Defer decision.
2. Record channel generation, EventId, principal, capability ID, queue state, and terminal result.
3. Restore timestamps and audit rollback, block, wake, retry, and final completion as one correlated operation.


### Known issues/TODOS in Fixed-size FIFO correctness

Issue: FIFO behavior relies on VecDeque and snapshot record order, but the IPC test suite does not independently verify ordering across full queues, drains, restoration, and repeated internal wraparound.

Required fixes:

1. Add a reference-model test that compares every RingBuffer operation with a simple FIFO sequence.
2. Verify that snapshot round trips preserve the exact order and identity of every queued message.
3. Test fill, partial drain, refill, and complete drain sequences across many wraparound cycles.


### Known issues/TODOS in Enqueue behavior

Issue: Full-queue insertion returns only IpcError::WouldBlock after consuming the Message argument, forcing the channel layer to perform separate rollback for ticketed capabilities and making direct RingBuffer callers unable to recover the rejected value.

Required fixes:

1. Return the rejected Message with the enqueue error or keep insertion exclusively behind a channel method that owns rollback.
2. Prove that failed insertion leaves queue depth, order, protocol state, counters, and capability-transfer state unchanged.
3. Add tests for ordinary, capability-carrying, and temporal messages rejected at capacity.


### Known issues/TODOS in Dequeue behavior

Issue: Receive validation copies the front Message and then removes it through a second operation, creating unnecessary work and coupling correctness to the channel lock remaining held across both calls.

Required fixes:

1. Add a borrowed front operation for validation followed by one checked removal under the same guard.
2. Document and test the lock requirement that prevents queue mutation between validation and dequeue.
3. Verify that every dequeue side effect occurs only after a message has actually been removed.


### Known issues/TODOS in Empty and full detection

Issue: Empty and full detection assumes CHANNEL_CAPACITY remains nonzero, but no compile-time assertion or test protects that configuration invariant.

Required fixes:

1. Add a compile-time assertion that CHANNEL_CAPACITY is greater than zero.
2. Test empty, one-below-capacity, capacity, and attempted-over-capacity states.
3. Assert that diagnostic empty and full fields always match pending depth.


### Known issues/TODOS in Queue wraparound correctness

Issue: Physical wraparound is delegated to VecDeque and has no IPC-specific regression coverage, so changes to the backing implementation could introduce head, tail, or ordering defects without a focused test failing.

Required fixes:

1. Run repeated enqueue and dequeue cycles well beyond the physical capacity while checking exact order.
2. Include clear and snapshot restoration at multiple wrapped positions.
3. Preserve the same test suite if VecDeque is replaced by explicit fixed storage.


### Known issues/TODOS in High watermark tracking

Issue: The high watermark records only a peak number and provides no timestamp, event identity, generation, or reset policy, limiting its diagnostic value after restoration or long-lived use.

Required fixes:

1. Associate peak updates with channel generation and an audit or temporal event identity.
2. Define whether restoration preserves historical peaks or begins a new observation epoch.
3. Test that receives never lower the peak and failed sends never raise it.


### Known issues/TODOS in Queue memory initialization

Issue: Removed and cleared Messages are not zeroized from the retained VecDeque allocation, leaving payload and capability bytes in reusable kernel heap storage.

Required fixes:

1. Scrub occupied Message storage before dequeue, clear, channel destruction, and allocation release where the performance policy permits.
2. Prevent compiler removal of security-sensitive clearing operations.
3. Add guarded allocator tests that inspect retired storage for stale payload and capability material.


### Known issues/TODOS in Queue message copy semantics

Issue: peek and iter copy complete fixed-size Message objects, including unused payload bytes and capability slots, during receive validation and temporal persistence.

Required fixes:

1. Return shared references from read-only queue inspection methods.
2. Serialize queued messages from borrowed references without constructing full intermediate copies.
3. Add copy-cost and stack-usage tests for the maximum channel and snapshot paths.


### Known issues/TODOS in Queue depth invariant

Issue: The depth bound is enforced procedurally but is not asserted after every mutation, and future crate-internal access could weaken the private RingBuffer boundary.

Required fixes:

1. Add invariant checks after push, pop, clear, restoration, and channel lifecycle transitions.
2. Keep the backing storage private and expose no unbounded insertion path.
3. Add exhaustive short-sequence tests proving that depth never leaves the inclusive range from zero through CHANNEL_CAPACITY.


### Known issues/TODOS in Queue allocation guarantees

Issue: RingBuffer is bounded but heap allocated, so channel creation can fail or become unavailable before queue semantics are established, and the type cannot satisfy interrupt-safe or no-allocator use cases.

Required fixes:

1. Replace VecDeque with fixed storage and explicit head, tail, and occupancy fields if allocation-free channels are required.
2. Make channel-creation allocation failure explicit and transactional while dynamic storage remains.
3. Separate the queue mutation path from temporal and registry allocations so its allocation contract is measurable.


### Known issues/TODOS in Queue fairness under contention

Issue: FIFO waiter storage does not guarantee FIFO completion because woken processes race with unrelated runnable processes to reacquire locks and repeat admission.

Required fixes:

1. Define whether the IPC contract promises best-effort wakeup, FIFO service, priority service, or another fairness model.
2. Add reservation or handoff tokens if strict waiter order is required.
3. Test many competing senders and receivers under deterministic scheduler interleavings.


### Known issues/TODOS in Queue starvation resistance

Issue: There is no bound on how often a process can lose a wake-and-retry race, and channel priority fields do not affect admission or wake selection.

Required fixes:

1. Add wait duration or retry-count tracking for blocked operations.
2. Introduce aging, quotas, or direct ownership handoff according to the selected scheduling policy.
3. Emit diagnostic evidence when a waiter exceeds a defined starvation threshold.


### Known issues/TODOS in Queue inspection diagnostics

Issue: Queue diagnostics omit operation totals, message age, local waiter occupancy, dropped waiter records, per-principal pressure, and channel generation.

Required fixes:

1. Add monotonic enqueue, dequeue, refusal, retry, and waiter-overflow counters.
2. Report oldest queued-message age and both local and scheduler waiter counts without exposing payload data.
3. Bind every diagnostic sample to channel identity, generation, and observation time.


### Known issues/TODOS in Formal queue boundedness

Issue: Boundedness is supported by code inspection but has no machine-checked model, exhaustive state exploration, or explicit distinction between message-count bounds and total memory bounds.

Required fixes:

1. Model push, pop, clear, close, and restore transitions and prove the message-count invariant.
2. Add exhaustive tests for all short operation sequences at and around capacity.
3. Document separate bounds for queue entries, Message size, waiters, snapshots, channels, and aggregate IPC memory.


### Known issues/TODOS in Queue fuzzing boundary cases

Issue: No dedicated fuzz target compares RingBuffer behavior with a reference FIFO across malformed restore data, repeated wraparound, failure paths, and lifecycle transitions.

Required fixes:

1. Add a stateful fuzz target for push, pop, peek, clear, close, snapshot, and restore operations.
2. Assert order preservation, failed-operation atomicity, bounded depth, and diagnostic consistency after every generated step.
3. Retain minimized corpora for overflow, wraparound, stale-storage, restoration, and wake-race defects.


### Known issues/TODOS in Internal IPC error coverage

Issue: IpcError omits revocation, cancellation, scheduler, transfer, persistence, audit, user-memory, and allocation failures.

Required fixes:

1. Define typed variants for failures that require distinct cleanup or caller behavior.
2. Separate operation outcome from secondary evidence failures such as audit or persistence loss.
3. Add exhaustive conversion tests so every producer has an intentional public mapping.


### Known issues/TODOS in Admission refusal coverage

Issue: Several refusal reasons collapse during channel conversion, and QueueEmpty is defined without a normal production path.

Required fixes:

1. Remove unreachable refusal states or give them precise production semantics.
2. Preserve predictive restriction, pressure, capacity, and emptiness where callers need different responses.
3. Test every refusal through send and receive rejection paths.


### Known issues/TODOS in Admission defer coverage

Issue: Capacity and message waits have no public timeout, interruption, cancellation, revocation, or scheduler-failure result.

Required fixes:

1. Define typed blocking outcomes and wake reasons.
2. Preserve WaitForCapacity and WaitForMessage through diagnostics and cancellation.
3. Test scheduler preparation, wake, timeout, close, and revocation races.


### Known issues/TODOS in Syscall errno mapping

Issue: IPC errno conversion is incomplete and maps semantically unrelated conditions to EIO, EAGAIN, EBADF, or ENOMEM.

Required fixes:

1. Create one exhaustive conversion from typed IPC errors to stable errno values.
2. Map capacity, closure, draining, protocol, authorization, and retry conditions separately.
3. Add ABI tests for every IPC syscall and error variant.


### Known issues/TODOS in String error degradation in public wrappers

Issue: Static string wrappers discard typed errors and make syscall behavior depend on string equality.

Required fixes:

1. Return a typed facade error that retains IPC, capability, scheduler, and copy failures.
2. Remove string comparisons from syscall handlers.
3. Keep human-readable formatting separate from programmatic error identity.


### Known issues/TODOS in Loss of diagnostic specificity

Issue: Callers cannot recover the admission reason, retry policy, lifecycle state, or rollback result from outer API errors.

Required fixes:

1. Preserve a stable reason code through every layer.
2. Attach bounded correlation data for diagnostic lookup without leaking sensitive state.
3. Test that no conversion merges retryable and terminal outcomes.


### Known issues/TODOS in Security-sensitive error detail leakage

Issue: Error normalization and timing behavior are not governed by a documented object-existence and authorization-disclosure policy.

Required fixes:

1. Define which details are visible before and after authorization.
2. Normalize unauthorized lookup timing and results where practical.
3. Add differential tests for nonexistent, inaccessible, revoked, closed, and empty channels.


### Known issues/TODOS in Retryable versus fatal errors

Issue: EAGAIN and EIO currently mix temporary pressure with closure, protocol failure, invalid authority, and other terminal conditions.

Required fixes:

1. Classify every error as retryable, terminal, caller-correctable, or indeterminate.
2. Preserve that classification in the kernel API and syscall ABI.
3. Document retry requirements, backoff, and generation replacement behavior.


### Known issues/TODOS in Close, drain, and sealed distinction

Issue: The internal lifecycle distinction does not survive facade and syscall conversion.

Required fixes:

1. Expose draining, end-of-stream, and permanently closed outcomes distinctly.
2. Preserve queued-message draining without encouraging new sends.
3. Test lifecycle results through direct, facade, and syscall APIs.


### Known issues/TODOS in Queue full versus backpressure distinction

Issue: Early throttling, hard saturation, and scheduler deferral all collapse to WouldBlock or a generic outer error.

Required fixes:

1. Preserve pressure refusal, full capacity, and blocking deferral as separate outcomes.
2. Return retry timing or wake semantics where policy supports them.
3. Test async, synchronous, high-priority, high-pressure, and saturated channels.


### Known issues/TODOS in Protocol mismatch mapping

Issue: Receive syscalls report protocol violations as EAGAIN, while send syscalls report them as generic EIO.

Required fixes:

1. Define a stable protocol-error result for both directions.
2. Prevent automatic retry unless a reset or resynchronization protocol exists.
3. Correlate the failure with channel generation and protocol phase.


### Known issues/TODOS in Invalid capability mapping

Issue: Invalid authority maps differently depending on whether resolution or channel admission detects it.

Required fixes:

1. Define one invalid, revoked, stale, and unauthorized capability taxonomy.
2. Apply it consistently before object lookup and at operation commit.
3. Test wrong type, rights, owner, channel, token, generation, and revoked grants.


### Known issues/TODOS in User fault mapping

Issue: Numeric pointer checks do not create a recoverable user-copy boundary, and receive can consume data before output copy success is established.

Required fixes:

1. Use architecture-aware copy-from-user and copy-to-user helpers with recoverable faults.
2. Validate the caller's actual mappings and checked range arithmetic.
3. Make receive copy-out transactional or provide redelivery after output failure.


### Known issues/TODOS in Out-of-memory mapping

Issue: ENOMEM is used for channel capacity and grant failure, while actual allocation failure has no typed IPC path.

Required fixes:

1. Use fallible allocation for syscall staging buffers.
2. Distinguish allocator exhaustion, registry capacity, capability-table capacity, and ticket-ledger capacity.
3. Add deterministic fault-injection tests for every resource boundary.


### Known issues/TODOS in Consistency across syscall and in-kernel API

Issue: Direct, service, facade, syscall, and PID 0 APIs expose different error, blocking, and authorization semantics.

Required fixes:

1. Define one canonical typed operation contract.
2. Make each outer layer an exhaustive, documented adaptation of that contract.
3. Run shared conformance tests against every public entry path.


### Known issues/TODOS in Syscall audit logging

Issue: Syscall audit records are not correlated with the later IPC message, capability decision, queue mutation, or transfer ticket.

Required fixes:

1. Allocate one audit correlation ID at syscall ingress and propagate it through resolution, admission, queueing, delivery, and import.
2. Record bounded operation metadata without retaining user payloads or raw pointers.
3. Test correlation across success, denial, block, retry, and copy-out failure.


### Known issues/TODOS in Syscall policy blocking

Issue: Policy coverage depends on a manually maintained syscall-to-right table, while additional handler-local privilege exceptions use separate rules.

Required fixes:

1. Make required capability metadata part of the syscall definition itself.
2. Express privileged exceptions through capability policy rather than PID ranges.
3. Add exhaustive tests proving every IPC syscall reaches the intended policy gate.


### Known issues/TODOS in Predictive restriction check

Issue: Restriction checks are repeated but are not bound to one policy generation or atomic authorization commit.

Required fixes:

1. Return a policy epoch with successful authorization.
2. Validate that epoch at the queue mutation or dequeue commit point.
3. Test restrictions applied between syscall entry, resolution, admission, sleep, wake, and commit.


### Known issues/TODOS in Channel capability type restriction

Issue: Raw IPC capability envelopes cross the receive boundary before type translation and authority installation.

Required fixes:

1. Treat received attachments as untrusted envelopes rather than usable capabilities.
2. Verify and translate type through the capability manager before exposure as authority.
3. Reject Generic metadata conflicts and unknown kernel capability types.


### Known issues/TODOS in Send-right restriction

Issue: The final send check trusts a copied endpoint whose underlying CHANNEL_SEND grant may have been revoked.

Required fixes:

1. Bind send endpoints to capability and restriction generations.
2. Revalidate immediately before enqueue and after every blocked wakeup.
3. Add revocation race tests that prove no post-revocation enqueue occurs.


### Known issues/TODOS in Receive-right restriction

Issue: The final receive check trusts a copied endpoint and can deliver after the manager grant has been revoked.

Required fixes:

1. Revalidate receive authority at dequeue commit.
2. Leave the message queued when authorization fails.
3. Wake blocked receivers with a typed revocation result.


### Known issues/TODOS in Security denial error mapping

Issue: String-based facade errors collapse distinct security and lifecycle failures into EACCES, EIO, or EAGAIN.

Required fixes:

1. Preserve typed IPC and security errors through the syscall boundary.
2. Define stable errno mappings for denial, revocation, invalid authority, closure, protocol failure, and retry.
3. Test every internal refusal against its public result.


### Known issues/TODOS in Audit event completeness

Issue: Important IPC failures and transfer outcomes are not represented by one complete structured security event model.

Required fixes:

1. Define events for enqueue, dequeue, close, protocol refusal, flood refusal, transfer, rollback, import, and copy-out failure.
2. Record channel generation, principal, capability, message identity, and outcome where authorized.
3. Document which events are mandatory and how overflow is reported.


### Known issues/TODOS in Causal chain audit correlation

Issue: Security audit records cannot be deterministically joined to message EventId, causal predecessor, temporal event, or transfer ticket.

Required fixes:

1. Carry message and operation correlation identities through every IPC layer.
2. Link causal predecessors without exposing payload contents.
3. Add replay tests that reconstruct complete request, response, and delegated-capability chains.


### Known issues/TODOS in Anomaly response path

Issue: Enforcement can proceed while best-effort telemetry and try-lock audit writes silently lose evidence.

Required fixes:

1. Provide a bounded mandatory record for every applied restriction and destructive response.
2. Report telemetry and audit overflow through monotonic loss counters.
3. Test alert, restriction, isolation, termination, cooldown, and evidence-loss behavior.


### Known issues/TODOS in Restriction revocation race

Issue: Quarantine does not invalidate copied endpoints, queued transfers, blocked waiters, or operations past their final check.

Required fixes:

1. Propagate restriction generations into endpoint and transfer validation.
2. Wake or cancel affected blocked operations and pending transfers.
3. Define atomic commit boundaries for enqueue, dequeue, close, and capability import.


### Known issues/TODOS in Malicious IPC flooding

Issue: Existing bounds and anomaly scoring do not provide complete per-principal, per-channel, or per-destination flood control.

Required fixes:

1. Add quotas for attempts, bytes, capabilities, channels, waiters, and pending tickets.
2. Charge rejected allocations and failed sends to the initiating principal.
3. Test sustained floods, many-source attacks, PID 0 behavior, and recovery after throttling.


### Known issues/TODOS in Covert channel analysis

Issue: Shared queues, locks, waiters, rate limits, audit buffers, and restriction timing expose unmeasured contention and timing channels.

Required fixes:

1. Define the IPC covert-channel threat model and acceptable leakage.
2. Partition sensitive accounting and scheduling resources where practical.
3. Measure timing and occupancy leakage under adversarial workloads.


### Known issues/TODOS in Capability exfiltration by IPC

Issue: User-constructed envelopes can be kernel-signed during message insertion, and raw received attachments are exposed without automatic import validation or recipient binding.

Required fixes:

1. Permit signing only for envelopes exported from a live authorized grant.
2. Bind ticketed transfers to an intended recipient or explicit delegation policy.
3. Verify, attenuate, and install attachments transactionally before exposing authority.


### Known issues/TODOS in Confused deputy through service IPC

Issue: Explicit ProcessId parameters, PID 0 bypasses, broad grants, and direct service methods can separate an operation from its authenticated initiating principal.

Required fixes:

1. Pass an authenticated principal context through every service call.
2. Require explicit delegation when a service exercises authority for another process.
3. Test deputy scenarios involving forged process IDs, broad endpoints, forwarded attachments, and kernel helpers.


### Known issues/TODOS in Channel capability grant

Issue: Channel creation uses two incompatible grant models, and the capability-manager path grants broader authority than every caller requires.

Required fixes:

1. Make one registered endpoint model authoritative for all channel creation APIs.
2. Grant separate send, receive, close, clone, and administration rights according to caller policy.
3. Make channel insertion and capability grant one recoverable transaction with audited rollback failure.


### Known issues/TODOS in Channel capability resolution

Issue: Resolution can return copied or ephemeral endpoint values that are not bound to a live local grant generation.

Required fixes:

1. Return a generation-bearing authorization proof instead of an unrestricted copied endpoint.
2. Represent remote-lease authorization explicitly rather than using capability ID 0.
3. Require every IPC operation to validate that proof at the mutation point.


### Known issues/TODOS in Send access resolution

Issue: Send authority is resolved once and can remain valid after the underlying capability is revoked.

Required fixes:

1. Revalidate send authority immediately before enqueue.
2. Bind resolved send endpoints to capability generation and policy epoch.
3. Add revocation-between-resolution-and-enqueue race tests.


### Known issues/TODOS in Receive access resolution

Issue: Receive authority is represented by a copied endpoint without a revocation or generation check at dequeue.

Required fixes:

1. Revalidate receive authority while committing the dequeue.
2. Reject stale endpoint generations without consuming the message.
3. Test revocation, process exit, and capability-table replacement races.


### Known issues/TODOS in Close access resolution

Issue: Close authority is inferred from combined send and receive rights rather than represented as an independent kernel right.

Required fixes:

1. Add a distinct channel-close right to the kernel capability model.
2. Grant close authority separately from data-plane rights.
3. Test send-only, receive-only, lifecycle-only, and combined grants.


### Known issues/TODOS in IPC capability type mapping

Issue: Most kernel capability types collapse into Generic and depend on an extra word for reconstruction.

Required fixes:

1. Define a versioned, exhaustive wire mapping for every transferable type.
2. Reject inconsistent direct-type and metadata combinations.
3. Add round-trip tests for all current and newly added capability types.


### Known issues/TODOS in Kernel capability type versus IPC capability type

Issue: The two enums can evolve independently and silently change transfer interpretation.

Required fixes:

1. Centralize both conversion directions in one versioned module.
2. Add compile-time or exhaustive tests that detect unmapped variants.
3. Include wire-version migration rules in persisted and cross-kernel transfers.


### Known issues/TODOS in Capability token signing

Issue: Message insertion can sign caller-constructed fields that were not exported from a live capability grant.

Required fixes:

1. Restrict signing to capability-manager export and restoration paths.
2. Make unsigned capability envelopes impossible to authenticate through Message alone.
3. Audit signing provenance and key epoch without exposing secret material.


### Known issues/TODOS in Capability token verification

Issue: Receive-with-capabilities copies attachments to callers without verification or import.

Required fixes:

1. Verify every attachment before exposing it outside the IPC service.
2. Separate untrusted envelope inspection from authority installation.
3. Return a typed per-attachment failure without partially granting authority.


### Known issues/TODOS in IPC transfer tickets

Issue: The pending-transfer ledger is bounded, globally shared, and not integrated atomically with queue insertion and destination import.

Required fixes:

1. Reserve, enqueue, consume, and rollback ticket state through one transaction protocol.
2. Report ledger saturation and ticket age through structured diagnostics.
3. Reclaim abandoned tickets during process exit, channel deletion, and message discard.


### Known issues/TODOS in Rollback on failed transfer

Issue: Several rollback calls discard failure, so a failed send or import can leave authority missing or a ticket stranded.

Required fixes:

1. Propagate rollback failure as a distinct security and consistency error.
2. Make restore and ticket removal atomic or durably recoverable.
3. Add fault injection for table-full, ledger-full, persistence, and concurrent-consumption failures.


### Known issues/TODOS in Revocation during queued transfer

Issue: Revoking the source grant does not necessarily cancel a pending ticket or remove its queued envelope.

Required fixes:

1. Link revocation to every pending transfer derived from the revoked capability.
2. Mark queued envelopes cancelled without trusting device or receiver cooperation.
3. Test revocation before enqueue, during queue residence, and during import.


### Known issues/TODOS in Revocation during blocked send

Issue: A blocked sender retries with the endpoint resolved before sleeping.

Required fixes:

1. Resolve or validate capability authority after every wakeup.
2. Remove stale waiters when process authority is revoked.
3. Return a terminal revocation error rather than retrying indefinitely.


### Known issues/TODOS in Revocation during blocked receive

Issue: A blocked receiver can dequeue after its receive capability has been revoked.

Required fixes:

1. Revalidate authority after wakeup and immediately before dequeue.
2. Preserve the queued message when validation fails.
3. Test revocation, close, process termination, and PID reuse while blocked.


### Known issues/TODOS in Owner PID mismatch

Issue: Direct IPC APIs trust caller-supplied owner fields and process IDs rather than deriving the active principal.

Required fixes:

1. Derive user principals from authenticated scheduler or syscall context.
2. Restrict explicit PID operations to reviewed kernel-internal interfaces.
3. Reject endpoint owner mismatch at every send, receive, close, import, and rollback boundary.


### Known issues/TODOS in Rights mismatch

Issue: Broad default grants and multiple endpoint models make least-privilege rights difficult to prove.

Required fixes:

1. Define one rights lattice shared by the capability manager and IPC endpoint layer.
2. Require explicit attenuation when deriving or transferring endpoints.
3. Add negative tests for every right and prohibited right combination.


### Known issues/TODOS in Capability expiration

Issue: IPC import authenticates expires_at but does not enforce it, and normal exports use no expiry.

Required fixes:

1. Reject envelopes before issue time or after nonzero expiry.
2. Define the trusted clock and behavior across suspend, restore, and reboot epochs.
3. Preserve or intentionally attenuate source expiry during export and destination grant.


### Known issues/TODOS in Replayed transferred capability

Issue: Unticketed authenticated envelopes can be imported repeatedly, while ticketed envelopes may be copied to multiple recipients before first consumption.

Required fixes:

1. Require tickets or an explicit duplicable classification for every transferable capability.
2. Bind tickets to an intended recipient or delegation policy.
3. Audit duplicate import attempts and retain replay regression tests.


### Known issues/TODOS in Forged transferred capability

Issue: Raw receive paths and restored transfer snapshots can bypass the live import verification boundary.

Required fixes:

1. Treat every received or restored envelope as untrusted until token and ledger verification complete.
2. Authenticate temporal snapshots and bind them to boot or persistence epochs.
3. Add bit-flip, field-substitution, stale-key, and fabricated-ticket tests.


### Known issues/TODOS in Confused deputy cases

Issue: Kernel bypasses, broad grants, caller-supplied principals, and direct service methods can let privileged code exercise IPC authority for the wrong process.

Required fixes:

1. Pass an authenticated principal and requested operation through every service boundary.
2. Minimize PID 0 bypasses and isolate restoration-only authority from normal runtime APIs.
3. Add deputy tests where services handle untrusted channel IDs, capabilities, and transfer envelopes.


### Known issues/TODOS in Channel registry storage

Issue: A heap-backed BTreeMap and pub(crate) backing field provide more flexibility and bypass surface than a 16-entry registry requires.

Required fixes:

1. Hide the backing collection behind table methods.
2. Evaluate fixed slots with generation-bearing handles.
3. Make allocation and capacity behavior explicit.


### Known issues/TODOS in Channel insertion

Issue: Generated IDs are inserted without collision checking and can overwrite live channels after wrap.

Required fixes:

1. Use checked ID allocation that rejects exhaustion.
2. Verify vacancy before insertion.
3. Test maximum counter, collision, and rollback behavior.


### Known issues/TODOS in Channel lookup

Issue: Numeric ID lookup cannot reject stale generations or cross-epoch identities.

Required fixes:

1. Require stable identity plus generation in every handle.
2. Validate generation before returning a Channel.
3. Test deletion, recreation, restore, and stale lookup.


### Known issues/TODOS in Mutable channel lookup

Issue: get_mut exposes unrestricted channel mutation to crate-internal callers.

Required fixes:

1. Restrict mutable lookup to lifecycle-aware table operations.
2. Return guard-bound interfaces instead of raw mutable Channel references.
3. Audit every current direct mutation caller.


### Known issues/TODOS in Channel deletion

Issue: Removal drops channel state without coordinated close, waiter wakeup, ticket cancellation, capability revocation, tombstone publication, or zeroization.

Required fixes:

1. Implement a bounded teardown transaction before map removal.
2. Publish a generation tombstone and wake terminal waiters.
3. Resolve queued messages and capability tickets explicitly.


### Known issues/TODOS in Delete-by-creator behavior

Issue: Creator-based deletion ignores delegated ownership and process-owned resources on channels created elsewhere.

Required fixes:

1. Track resource and capability ownership independently of creator.
2. Revoke only authority and objects owned by the exiting process.
3. Define channel survival policy when the creator exits.


### Known issues/TODOS in Ensure-channel-with-ID behavior

Issue: Restore accepts arbitrary IDs, trusts existing creator state, and can saturate next_id permanently.

Required fixes:

1. Reject zero, reserved, exhausted, and conflicting IDs.
2. Verify creator and generation on existing entries.
3. Separate restored identity allocation from normal next_id state.


### Known issues/TODOS in Temporal restore channel creation

Issue: Replay creates channels without normal claims, capabilities, audit, flags, or generation replacement.

Required fixes:

1. Require authenticated restore authority and an unpublished staging registry.
2. Restore capabilities and channel state as one transaction.
3. Atomically publish a new generation after full validation.


### Known issues/TODOS in Maximum channel enforcement

Issue: The live-entry limit is bypassable through crate-visible map access and does not bound related resources.

Required fixes:

1. Make direct insertion impossible.
2. Define aggregate bounds for waiters, snapshots, queued messages, and grants.
3. Report saturation and rejected creation through diagnostics.


### Known issues/TODOS in Channel ID reuse policy

Issue: Normal allocation wraps while restore saturates, and neither path defines exhaustion or generation.

Required fixes:

1. Use one checked monotonic allocation policy.
2. Disable creation on exhaustion rather than aliasing.
3. Include boot or persistence epoch and channel generation.


### Known issues/TODOS in Stale capabilities after channel deletion

Issue: Deleted-channel capabilities remain live records and can regain meaning if the numeric ID reappears.

Required fixes:

1. Revoke all grants bound to the deleted generation.
2. Require generation matching during capability resolution.
3. Notify or audit holders of terminal revocation.


### Known issues/TODOS in Channel registry failure consistency

Issue: Normal grant rollback ignores deletion failure and restore can leave partial registry state.

Required fixes:

1. Stage channel and capability creation before atomic publication.
2. Treat rollback failure as a health and audit event.
3. Parse restore into temporary state before insertion or replacement.


### Known issues/TODOS in Channel table diagnostics

Issue: Diagnostics omit registry generation, allocator state, insertion and deletion history, saturation, and pending cleanup.

Required fixes:

1. Report next allocation state without exposing unsafe reuse controls.
2. Add lifecycle and capacity counters with loss evidence.
3. Correlate channel records with generations and tombstones.


### Known issues/TODOS in Channel table iteration

Issue: Bounded iteration is structurally safe but acquires scheduler state while holding IPC and exposes no snapshot generation.

Required fixes:

1. Copy channel diagnostic state before querying external subsystems.
2. Tag the completed report with one registry generation.
3. Test concurrent creation, deletion, and diagnostics.


### Known issues/TODOS in Channel table fuzzing

Issue: No stateful fuzz target covers creation, deletion, restore, purge, ID exhaustion, stale capabilities, and rollback together.

Required fixes:

1. Compare generated operations against a reference registry model.
2. Assert capacity, uniqueness, generation, and capability consistency after every step.
3. Retain minimized corpora for collision, partial restore, and delegated cleanup defects.


### Known issues/TODOS in Unbound temporal protocol state

Issue: Unbound channels accept every payload without distinguishing ordinary data from accidentally temporal-looking frames.

Required fixes:

1. Define whether protocol binding is mandatory for typed services.
2. Prevent silent downgrade from a required temporal service to unbound IPC.
3. Test binding policy at channel publication and delegation.


### Known issues/TODOS in Temporal session binding

Issue: Binding can replace protocol state without proving an empty queue, fresh session, or authorized transition.

Required fixes:

1. Permit binding only during unpublished or quiescent channel state.
2. Allocate or validate unique session IDs.
3. Audit bind, rebind, restore, and unbind operations.


### Known issues/TODOS in Temporal request frame parsing

Issue: Request parsing ignores reserved bytes, flag validity, and opcode-specific payload structure.

Required fixes:

1. Require reserved bytes to be zero for version one.
2. Validate known flag masks.
3. Dispatch payload validation through the bound service schema.


### Known issues/TODOS in Temporal response frame parsing

Issue: Response parsing accepts arbitrary status, flags, and payload combinations after structural validation.

Required fixes:

1. Define valid status ranges and flag masks.
2. Validate opcode-specific response payloads.
3. Add malformed and boundary parser corpora.


### Known issues/TODOS in Temporal request send validation

Issue: Request send validation is repeated and does not validate opcode or capability schema.

Required fixes:

1. Evaluate temporal admission once and pass a commit token.
2. Bind opcodes to payload and capability contracts.
3. Test unknown opcodes, flags, and attached authority.


### Known issues/TODOS in Temporal response send validation

Issue: Response validation enforces correlation but not responder role, status semantics, or payload contract.

Required fixes:

1. Bind requester and responder roles to session capabilities.
2. Validate status and response schema by opcode.
3. Test response substitution from another authorized sender.


### Known issues/TODOS in Temporal request receive validation

Issue: Request temporal validation occurs after general receive admission and authenticates no sender identity beyond channel access.

Required fixes:

1. Include front-frame validation in one complete admission decision.
2. Bind the expected sender role to the session.
3. Test delegated senders and forged request metadata.


### Known issues/TODOS in Temporal response receive validation

Issue: A matching response can be delivered to any principal with receive rights, regardless of original requester identity.

Required fixes:

1. Record the requesting principal or reply capability.
2. Require response delivery to the authorized requester.
3. Test capability delegation during an active exchange.


### Known issues/TODOS in Temporal request ID sequencing

Issue: Request IDs wrap silently to zero and provide no replay epoch or exhaustion policy.

Required fixes:

1. Reject exhaustion or rotate to a fresh authenticated session.
2. Reserve invalid identifier values explicitly.
3. Test maximum ID, wrap, restore, and stale replay.


### Known issues/TODOS in Temporal opcode matching

Issue: Opcode equality is enforced, but unknown values and incompatible payload or capability combinations remain valid.

Required fixes:

1. Register allowed opcodes per service.
2. Bind each opcode to request, response, and capability schemas.
3. Reject unknown values before queue insertion.


### Known issues/TODOS in Temporal session ID matching

Issue: Session IDs are caller-supplied and can be zero, reused, or collide across channels and boots.

Required fixes:

1. Allocate unpredictable or epoch-qualified session identities.
2. Bind session ID to channel generation and participants.
3. Reject duplicate live sessions and stale restored sessions.


### Known issues/TODOS in Temporal phase transition after send

Issue: Phase advancement reparses frames and can diverge from prior validation, while persistence failure leaves only volatile state.

Required fixes:

1. Carry parsed validated frame data into commit.
2. Advance phase exactly once with queue insertion.
3. Record or retry failed durable transition evidence.


### Known issues/TODOS in Temporal phase transition after receive

Issue: Receive phase advances before payload and capabilities are successfully copied to the caller.

Required fixes:

1. Include delivery completion in the phase transaction.
2. Retain or restore the message on copy-out failure.
3. Test kernel and user delivery faults after dequeue.


### Known issues/TODOS in Temporal protocol mismatch handling

Issue: An invalid front message remains queued and can permanently prevent access to later messages.

Required fixes:

1. Define quarantine, discard, reset, or channel-failure policy.
2. Preserve a typed mismatch reason through outer APIs.
3. Audit poisoned-front-message recovery and data loss.


### Known issues/TODOS in Temporal snapshot encoding

Issue: Snapshot encoding allocates under the global IPC lock and lacks total length, checksum, authentication, and a static size bound.

Required fixes:

1. Encode into bounded storage outside the mutation critical section.
2. Add declared length and authenticated integrity.
3. Version the schema with compatibility tests and maximum-size assertions.


### Known issues/TODOS in Temporal snapshot restoration

Issue: Restore mutates live state incrementally and can fail after partial application.

Required fixes:

1. Parse and validate into a temporary Channel image.
2. Validate all capability tickets before publication.
3. Swap the restored generation atomically only after complete success.


### Known issues/TODOS in Temporal replay safety

Issue: Public replay entry points bypass ordinary authority and can overwrite or create live channel state without anti-rollback protection.

Required fixes:

1. Require authenticated replay authority and an exclusive restore phase.
2. Verify monotonically newer object versions.
3. Reject conflicts with active channel generations.


### Known issues/TODOS in Temporal persistence failure handling

Issue: Runtime operations discard persistence failures and expose no degraded durability state.

Required fixes:

1. Define optional and required persistence modes.
2. Queue bounded retries or return a typed degraded result.
3. Correlate operation, version, retry, and final durability outcome.


### Known issues/TODOS in Temporal object corruption handling

Issue: Corruption detection is structural but unauthenticated and nontransactional.

Required fixes:

1. Authenticate snapshots before parsing mutable fields.
2. Reject trailing bytes, excessive counts, and noncanonical encodings.
3. Fuzz every scalar, count, message, capability, and truncation boundary.


### Known issues/TODOS in Formal temporal session typing

Issue: No formal model proves the four-phase protocol, atomic queue coupling, replay resistance, or restore equivalence.

Required fixes:

1. Model all send, receive, close, failure, and restore transitions.
2. Prove session, request, opcode, and phase invariants.
3. Generate regression traces from counterexamples and fuzz findings.


### Known issues/TODOS in Global IPC table locking

Issue: One spin mutex serializes every channel and makes unrelated IPC operations share the same failure and latency domain.

Required fixes:

1. Separate registry protection from per-channel mutation locks.
2. Preserve atomic lookup and lifetime ownership during the transition.
3. Measure contention and maximum hold time under multi-channel load.


### Known issues/TODOS in Channel mutation locking

Issue: Public Channel mutation methods do not encode or enforce the IpcService lock requirement.

Required fixes:

1. Restrict mutation visibility or require a guard-bearing API.
2. Document synchronization for direct kernel callers.
3. Add race tests for every mutation path.


### Known issues/TODOS in IPC lock scope minimization

Issue: The global lock covers allocation, persistence, logging, rollback, wakeup, and policy work beyond state mutation.

Required fixes:

1. Capture bounded immutable effects while locked.
2. Execute external and fallible work after releasing the lock.
3. Add lock hold-time instrumentation and budgets.


### Known issues/TODOS in Blocking without the IPC lock

Issue: Context switch occurs after unlock, but block registration failure is hidden and preparation leaves a sensitive pre-commit interval.

Required fixes:

1. Return block-commit status.
2. Minimize work between preparation and commit.
3. Test failed, cancelled, and wake-before-commit plans.


### Known issues/TODOS in IPC and scheduler lock ordering

Issue: IPC acquires scheduler state while locked without an enforced rule preventing the reverse order.

Required fixes:

1. Define a global lock rank for IPC and scheduler.
2. Add debug lock-order assertions.
3. Audit scheduler callbacks and cleanup paths for IPC entry.


### Known issues/TODOS in IPC and capability lock ordering

Issue: Both capability-then-IPC and IPC-then-capability paths exist.

Required fixes:

1. Choose one lock order or use staged transactions without nested locks.
2. Move grants, rollback, revocation, and restore outside IPC critical sections.
3. Test concurrent creation, revocation, send failure, and process cleanup.


### Known issues/TODOS in IPC and temporal lock ordering

Issue: Temporal recording and snapshot persistence occur under IPC, while replay paths can enter IPC from temporal code.

Required fixes:

1. Prohibit temporal-to-IPC callbacks while temporal locks are held.
2. Queue persistence work after releasing IPC.
3. Add lock-order and replay concurrency tests.


### Known issues/TODOS in IPC and security lock ordering

Issue: Security policy and audit calls execute under IPC with no non-reentrancy contract.

Required fixes:

1. Define whether security may call IPC and enforce the answer.
2. Stage audit records for emission after unlock.
3. Test policy revocation and process termination during IPC operations.


### Known issues/TODOS in IPC deadlock prevention

Issue: The repository has no machine-checked lock graph covering IPC, scheduler, capability, temporal, and security subsystems.

Required fixes:

1. Assign lock ranks and document allowed nesting.
2. Add runtime assertions in debug builds.
3. Create stress tests for cleanup, replay, close, and revocation cycles.


### Known issues/TODOS in IPC priority inversion

Issue: A low-priority owner can hold the global spin lock through expensive work without priority inheritance.

Required fixes:

1. Reduce critical sections to bounded state changes.
2. Use per-channel locking or priority-aware synchronization where required.
3. Record owner, wait time, and hold time for inversion diagnosis.


### Known issues/TODOS in IPC interrupt context safety

Issue: IPC APIs can allocate and call blocking-adjacent subsystems but do not reject interrupt context or prevent same-CPU reentry.

Required fixes:

1. Mark sleepable IPC entry points as thread-context only.
2. Add nonallocating deferred-event APIs for interrupt producers.
3. Assert context and interrupt state at lock acquisition.


### Known issues/TODOS in IPC reentrancy

Issue: External calls under a non-reentrant IPC mutex can indirectly call IPC and spin forever.

Required fixes:

1. Remove callbacks and external service calls from locked regions.
2. Add per-CPU recursion detection in debug builds.
3. Test audit, temporal, capability, and scheduler callback reentry.


### Known issues/TODOS in IPC atomic ID allocation

Issue: Atomic IDs are unique only until wrap and carry no generation or publication relationship.

Required fixes:

1. Use wider generation-bearing identifiers.
2. Define exhaustion as a terminal allocation error rather than reuse.
3. Bind IDs to boot or persistence epoch where restoration applies.


### Known issues/TODOS in IPC relaxed atomic ordering

Issue: Relaxed counters are correct only as counters, but their narrow contract is not structurally separated from object publication and restore.

Required fixes:

1. Document that counter operations publish no surrounding state.
2. Use explicit locks or release and acquire operations where publication is required.
3. Add concurrency tests around message creation and restored sequence updates.


### Known issues/TODOS in Concurrent channel lifecycle operations

Issue: Selected sequential tests do not exhaust concurrent send, receive, close, revoke, exit, restore, and copy-out interleavings.

Required fixes:

1. Build a state-machine concurrency harness with deterministic schedules.
2. Assert queue, lifecycle, capability, and temporal invariants after every interleaving.
3. Retain minimized regressions for discovered races.


### Known issues/TODOS in IPC wait address derivation

Issue: Wait keys contain channel ID and condition only, with no generation or overflow proof.

Required fixes:

1. Include channel generation in every wait key.
2. Add compile-time checked-width assertions for key construction.
3. Test uniqueness across conditions, deletion, recreation, and maximum IDs.


### Known issues/TODOS in Message wait addresses

Issue: Message wait keys cannot distinguish old channel incarnations or individual wait intents.

Required fixes:

1. Bind keys to channel generation.
2. Associate scheduler entries with a unique wait token.
3. Reject wakes for retired channel generations.


### Known issues/TODOS in Capacity wait addresses

Issue: Capacity waiters on a deleted channel can alias a recreated channel using the same ID.

Required fixes:

1. Tombstone and drain old wait keys before ID reuse.
2. Include generation in capacity keys.
3. Test deletion and recreation with blocked senders.


### Known issues/TODOS in Waiting receiver queues

Issue: The fixed local receiver queue silently overflows and can diverge from scheduler registration.

Required fixes:

1. Return insertion and removal status.
2. Choose one authoritative waiter registry or reconcile both explicitly.
3. Record overflow, cancellation, and stale-entry cleanup.


### Known issues/TODOS in Waiting sender queues

Issue: Local sender entries lack process generation, cancellation, and exit cleanup.

Required fixes:

1. Store generation-bearing process and wait identities.
2. Remove entries on cancellation, exit, and channel destruction.
3. Test overflow and stale sender cleanup.


### Known issues/TODOS in Wake-one receiver behavior

Issue: One successful local wake suppresses scheduler-key fallback even when other scheduler-only receivers exist.

Required fixes:

1. Define whether wake-one targets the local queue or authoritative scheduler queue.
2. Reconcile stale local entries before selecting a waiter.
3. Test mixed local and scheduler-only receiver registrations.


### Known issues/TODOS in Wake-all receiver behavior

Issue: wake_all_receivers skips scheduler wake_all whenever any local wake succeeds, potentially stranding other receivers.

Required fixes:

1. Always drain the authoritative scheduler key during terminal wake-all.
2. Deduplicate processes already awakened locally.
3. Add a regression test with one local waiter and one scheduler-only waiter.


### Known issues/TODOS in Wake-one sender behavior

Issue: A woken sender receives no capacity reservation and can lose the slot before retry.

Required fixes:

1. Define best-effort or reserved-handoff semantics.
2. Add a reservation token if bounded fairness is required.
3. Test competing awakened and newly runnable senders.


### Known issues/TODOS in Wake-all sender behavior

Issue: Any successful local sender wake suppresses scheduler wake_all and can strand capacity waiters during closure.

Required fixes:

1. Always clear the scheduler capacity key on terminal closure.
2. Deduplicate local and scheduler wake records.
3. Test mixed registration sources during close and final drain.


### Known issues/TODOS in Stale waiter cleanup

Issue: IPC has no proactive waiter removal for process exit, cancellation, state change, or channel deletion.

Required fixes:

1. Add lifecycle hooks that cancel channel waits.
2. Purge both local and scheduler registries atomically.
3. Audit stale-entry removal and failure.


### Known issues/TODOS in Waiter PID reuse

Issue: Raw numeric PID entries can wake an unrelated reused process.

Required fixes:

1. Store process generation or a scheduler-issued wait token.
2. Verify channel key and wait state before targeted wake.
3. Test PID reuse while stale IPC entries remain.


### Known issues/TODOS in IPC missed wakeups

Issue: Scheduler registration occurs during commit after IPC unlock, and the SMP safety of this window is not established.

Required fixes:

1. Make preparation publish the waiter before releasing the condition lock or add a sequence-based handshake.
2. Return commit failure to IPC.
3. Model and test condition change, wake, and commit on separate CPUs.


### Known issues/TODOS in IPC thundering herd behavior

Issue: Terminal wake-all can make many processes runnable only to contend on one global IPC lock.

Required fixes:

1. Deliver terminal state directly through wait completion where possible.
2. Batch or budget large wake sets.
3. Measure close behavior with maximum sender and receiver waiters.


### Known issues/TODOS in IPC scheduler failure fallback

Issue: Scheduler preparation and commit failures collapse into WouldBlock or silent continuation.

Required fixes:

1. Preserve typed scheduler failure causes.
2. Return commit status and cancel local waiter entries on failure.
3. Add fault-injection tests for queue exhaustion and missing process state.


### Known issues/TODOS in IPC scheduler lock ordering

Issue: IPC acquires scheduler state while holding the global IPC lock without a documented cross-subsystem order.

Required fixes:

1. Publish and enforce one lock-order graph.
2. Prevent scheduler callbacks into IPC while scheduler state is locked.
3. Add lock-order assertions in test builds.


### Known issues/TODOS in Blocking and IPC locks

Issue: commit occurs after unlock, but preparation disables interrupts and later work can delay the actual block.

Required fixes:

1. Minimize work between preparation and commit.
2. Move persistence and unrelated operations outside that interval.
3. Measure maximum interrupt-disabled and lock-held durations.


### Known issues/TODOS in IPC scheduler fairness

Issue: FIFO waiter selection does not guarantee FIFO completion, and IPC priority fields do not affect scheduling.

Required fixes:

1. Define the fairness and priority contract.
2. Add direct handoff, reservations, or aging if bounded wait is required.
3. Test long-running mixed-priority contention.


### Known issues/TODOS in IPC wait and wake tests

Issue: Existing tests cover simple keyed wakes but not dual registries, lifecycle cleanup, PID reuse, SMP races, or scheduler failures.

Required fixes:

1. Add deterministic interleaving tests around prepare, unlock, wake, and commit.
2. Cover mixed local and scheduler-only waiters and queue overflow.
3. Add process-exit, PID-reuse, close, and fairness regression cases.


### Known issues/TODOS in Pressure level calculation

Issue: Pressure classification uses only queue occupancy and cannot distinguish a transient burst from sustained overload.

Required fixes:

1. Define whether rate, age, waiter count, or message cost belongs in policy.
2. Keep occupancy as the deterministic baseline and add only measured signals.
3. Test every depth and any added signal boundary.


### Known issues/TODOS in Low pressure behavior

Issue: Recovery from High or Saturated pressure has no transition evidence or low-watermark policy.

Required fixes:

1. Record pressure-level transitions and recovery time.
2. Define a low watermark if hysteresis is adopted.
3. Test stable recovery after bursts.


### Known issues/TODOS in High pressure behavior

Issue: High-pressure async refusal can oscillate on every adjacent send and receive because the policy has no hysteresis.

Required fixes:

1. Add separate entry and exit thresholds if oscillation is harmful.
2. Record time spent in High rather than only attempts observed there.
3. Test alternating occupancy around both thresholds.


### Known issues/TODOS in Saturated pressure behavior

Issue: QueueFull refusal and capacity deferral lose their distinct meaning at outer API boundaries.

Required fixes:

1. Preserve refusal versus deferral through service and syscall results.
2. Expose retry guidance without leaking unrelated channel state.
3. Test full-channel behavior for every valid mode.


### Known issues/TODOS in High-pressure hit accounting

Issue: high_pressure_hits counts evaluations, including retries, rather than unique operations.

Required fixes:

1. Assign one operation identity across retries.
2. Separate attempts, unique sends, refusals, and commits.
3. Add timestamp or epoch correlation.


### Known issues/TODOS in Saturated hit accounting

Issue: saturated_hits can overcount one blocked send and silently stops changing at u32 maximum.

Required fixes:

1. Track unique operations and retry counts separately.
2. Publish counter-saturation evidence.
3. Test repeated wake losses and maximum-value behavior.


### Known issues/TODOS in Backpressure reliable deferral

Issue: Deferral depends on absence of ASYNC rather than presence of RELIABLE.

Required fixes:

1. Define valid channel modes and reject contradictory flags.
2. Make RELIABLE explicitly control blocking guarantees or remove it.
3. Test all supported flag combinations.


### Known issues/TODOS in Backpressure async refusal

Issue: Async refusal is mapped to generic EIO and has no stable retry contract.

Required fixes:

1. Map temporary pressure to EAGAIN or an equivalent typed result.
2. Document whether refused messages and capability tickets remain caller-owned.
3. Verify async paths never block.


### Known issues/TODOS in High-priority pressure handling

Issue: HIGH_PRIORITY affects one admission branch but does not provide actual scheduling priority.

Required fixes:

1. Rename the flag to describe admission-reserve access or implement real priority.
2. Integrate priority with quotas and starvation controls before broad use.
3. Test high-priority contention against ordinary senders.


### Known issues/TODOS in Pressure threshold correctness

Issue: Integer truncation can place the High threshold substantially below 75 percent for other capacities.

Required fixes:

1. Use checked ceiling arithmetic for the intended ratio.
2. Add compile-time assertions for positive capacity and valid threshold range.
3. Test representative capacities, including nonmultiples of four.


### Known issues/TODOS in Backpressure occupancy race safety

Issue: Race safety depends on one global lock and direct Channel callers following an undocumented synchronization rule.

Required fixes:

1. Make mutation APIs require or encapsulate the channel guard.
2. Move to per-channel locking without separating admission from commit.
3. Add concurrency tests for send, receive, close, and restore.


### Known issues/TODOS in Backpressure denial-of-service resistance

Issue: Bounded queue memory does not bound rejected attempts, waiters, retries, snapshots, or lock consumption.

Required fixes:

1. Add per-principal attempt budgets or rate limits.
2. Bound waiter and persistence work associated with pressure.
3. Audit repeated pressure abuse without flooding logs.


### Known issues/TODOS in Sender starvation under pressure

Issue: Wakeup does not reserve capacity, so a sender can repeatedly lose the commit race.

Required fixes:

1. Define the sender fairness contract.
2. Add direct handoff, reservation, aging, or quotas if bounded wait is required.
3. Test deterministic multi-sender contention.


### Known issues/TODOS in Receiver starvation under pressure

Issue: One receiver can repeatedly drain traffic while other authorized receivers remain waiting.

Required fixes:

1. Define whether channels support competing consumers and what fairness they receive.
2. Add receiver handoff or quotas where required.
3. Test sustained producer traffic with multiple consumers.


### Known issues/TODOS in Backpressure diagnostics correlation

Issue: Pressure diagnostics lack generation, time, transition history, operation identity, and per-principal attribution.

Required fixes:

1. Bind samples to channel generation and observation time.
2. Add transition, duration, retry, and overflow counters.
3. Correlate pressure, refusal, blocking, wakeup, and terminal result.


### Known issues/TODOS in Syscall receive entry

Issue: Receive syscalls dequeue before using incomplete, architecture-specific user-memory validation for output buffers.

Required fixes:

1. Replace raw boundary checks with checked copy-to-user range validation.
2. Validate every payload, capability, and count destination before dequeue.
3. Test unmapped, read-only, wrapped, cross-page, and kernel-space destinations.


### Known issues/TODOS in Service receive API

Issue: Blocking and nonblocking receive APIs have different callers, while facade errors erase their behavioral distinctions.

Required fixes:

1. Expose explicitly named blocking and nonblocking facade operations.
2. Return typed IpcError values instead of static strings.
3. Test empty, closed, draining, and protocol-refused behavior through both APIs.


### Known issues/TODOS in Receive capability resolution

Issue: Capability authority can be revoked after resolution but before dequeue without a generation check at commit.

Required fixes:

1. Bind resolved capabilities to a revocation epoch.
2. Revalidate the grant immediately before message removal.
3. Test capability revocation racing with blocked and immediate receives.


### Known issues/TODOS in Receive path admission completeness

Issue: Temporal validation occurs after admission, splitting one receive decision across separate checks.

Required fixes:

1. Include front-message temporal validation in the admission result.
2. Pass a validated delivery token to dequeue.
3. Emit one correlated admission decision per receive attempt.


### Known issues/TODOS in Blocking receive behavior

Issue: The blocking service exists, but current syscalls use only nonblocking try-receive behavior.

Required fixes:

1. Define whether syscall receive is blocking, nonblocking, or flag-controlled.
2. Expose cancellation and timeout semantics for blocking callers.
3. Test close, revocation, signal, and wake races while blocked.


### Known issues/TODOS in Nonblocking receive behavior

Issue: Temporary emptiness and permanent sealed closure collapse into the same facade string and EAGAIN result.

Required fixes:

1. Preserve WouldBlock and Closed separately through the syscall boundary.
2. Document retry behavior for each result.
3. Test terminal closure without indefinite caller retries.


### Known issues/TODOS in Receiver wait-queue insertion

Issue: The local receiver queue silently loses entries after 16 waiters or when no current PID is available.

Required fixes:

1. Return insertion status and record overflow.
2. Confirm scheduler fallback registration when local insertion fails.
3. Test more than 16 receivers and absent-current-process handling.


### Known issues/TODOS in Receiver block commit

Issue: Scheduler commit produces no result for cancellation, prior wakeup, or failed descheduling.

Required fixes:

1. Return typed block-commit status.
2. Retry or terminate according to cancelled and already-woken outcomes.
3. Test send-before-commit, close-before-commit, and scheduler failure.


### Known issues/TODOS in Receive retry loop

Issue: Blocking retries reuse a previously resolved capability and provide no starvation bound among competing receivers.

Required fixes:

1. Revalidate capability generation after every wake.
2. Add fairness evidence or direct handoff for waiting receivers.
3. Test repeated lost wake races under deterministic scheduling.


### Known issues/TODOS in Message copy-out behavior

Issue: The message leaves the queue before kernel and user copy-out succeeds, so later faults cause irreversible message loss.

Required fixes:

1. Validate and reserve destinations before dequeue.
2. Use a receive transaction that commits removal only after successful copy-out.
3. Define rollback or terminal loss evidence when faults occur after reservation.


### Known issues/TODOS in Partial payload copy behavior

Issue: An undersized destination silently truncates and discards the remainder of a dequeued payload.

Required fixes:

1. Return the required payload length without dequeuing when capacity is insufficient.
2. Add an explicit truncation option only if callers request destructive partial receive.
3. Test zero, one-byte-short, exact, and oversized destinations.


### Known issues/TODOS in Capability copy-out behavior

Issue: Receive copy-out does not clearly finalize ticket ownership or rebind transferred authority to the receiving principal.

Required fixes:

1. Validate every ticket and atomically grant it to the receiver before exposing records.
2. Commit message removal and capability transfer as one transaction.
3. Reject stale, substituted, expired, or wrong-owner capability records.


### Known issues/TODOS in Partial capability output

Issue: The facade silently drops attached capabilities that do not fit in caps_out after the message is removed.

Required fixes:

1. Check required capability capacity before dequeue.
2. Return a buffer-too-small result containing the required count.
3. Roll back or retain the complete message if capability delivery cannot commit.


### Known issues/TODOS in Sender wakeup after receive

Issue: Failed sender wakeups are ignored after capacity becomes available.

Required fixes:

1. Record failed, stale, and fallback wake attempts.
2. Preserve a scheduler-visible capacity-ready condition until consumed.
3. Test wake failure and multiple blocked senders after one dequeue.


### Known issues/TODOS in Sealed empty receive behavior

Issue: Terminal sealed closure is reported to syscall callers as temporary EAGAIN.

Required fixes:

1. Map Closed to a distinct stable errno.
2. Revoke or tombstone receive capabilities after terminal observation.
3. Test that sealed receivers stop retrying and cannot block again.


### Known issues/TODOS in Draining channel receive behavior

Issue: Empty draining state can wait forever, and nonempty draining state has no completion deadline.

Required fixes:

1. Seal or reject inconsistent empty-draining state.
2. Define forced drain cancellation for abandoned receivers.
3. Audit discarded messages and capabilities during forced sealing.


### Known issues/TODOS in Temporal advancement after receive

Issue: Protocol state advances at dequeue even though later copy-out and persistence can fail.

Required fixes:

1. Include delivery completion in the temporal receive transaction.
2. Persist advancement durably or retain a retry record.
3. Test user-copy and storage faults after protocol validation.


### Known issues/TODOS in Stale message exposure prevention

Issue: Retired queue storage and temporary receive values are not scrubbed, and partial user writes lack completion evidence.

Required fixes:

1. Zeroize sensitive Message storage after committed delivery.
2. Use fault-aware user-copy helpers that report exact progress.
3. Add tests for stale payload, capability, and partial-write exposure.


### Known issues/TODOS in Receive syscall return values

Issue: Payload length alone cannot report truncation, capability count requirements, closure, or transfer completion.

Required fixes:

1. Define a stable structured receive result or companion metadata ABI.
2. Preserve typed errors through errno conversion.
3. Add cross-architecture ABI tests for every result.


### Known issues/TODOS in Receive user buffer faults

Issue: Unsafe output writes have no recoverable fault boundary and can lose a dequeued message after partial delivery.

Required fixes:

1. Introduce checked copy-to-user primitives with fault recovery.
2. Validate the complete four-byte capability-count destination.
3. Reserve or retain the message until every output write commits.


### Known issues/TODOS in Syscall send entry

Issue: Send syscalls use incomplete user-memory validation and permit payloads eight times larger than Message can store.

Required fixes:

1. Enforce MAX_MESSAGE_SIZE before allocation or copying.
2. Replace fixed-boundary checks with overflow-safe architecture-aware user-copy helpers.
3. Test unmapped, read-protected, cross-page, wrapped, and kernel-space ranges.


### Known issues/TODOS in Service send API

Issue: The facade erases typed IPC failures by converting them into static strings.

Required fixes:

1. Return IpcError or a richer service error from every facade.
2. Preserve lifecycle, protocol, authority, and capacity outcomes.
3. Add tests proving error identity across each API layer.


### Known issues/TODOS in Send capability resolution

Issue: Capability-manager authority is resolved before locking and is not revalidated immediately before queue commit.

Required fixes:

1. Bind resolution to a capability generation or revocation epoch.
2. Revalidate the grant under a documented lock order before commit.
3. Test revocation racing with send admission and queue insertion.


### Known issues/TODOS in Send message construction

Issue: The syscall allocates and copies oversized input before the Message constructor applies the real limit.

Required fixes:

1. Share one payload limit across syscall, facade, and Message.
2. Reject invalid length before allocation or user access.
3. Test empty, maximum, and one-byte-over-maximum payloads.


### Known issues/TODOS in Send payload validation

Issue: Payload rules are inconsistent and user-range checks do not prove readable process memory.

Required fixes:

1. Define whether zero-length messages are valid across every entry point.
2. Use checked range construction and page-by-page read validation.
3. Remove target-specific address constants from shared syscall policy.


### Known issues/TODOS in Send capability attachment

Issue: Multi-capability attachment is not represented as one rollback-capable transaction.

Required fixes:

1. Stage all transfer tickets before modifying the Message.
2. Commit tickets only after queue insertion succeeds.
3. Roll back the full staged set on conversion, attachment, resolution, or send failure.


### Known issues/TODOS in Send admission decision

Issue: Admission and temporal validation execute more than once for one service attempt.

Required fixes:

1. Evaluate admission exactly once under the commit lock.
2. Pass a validated decision token into queue mutation.
3. Test time-dependent policy changes and ensure one audit decision per attempt.


### Known issues/TODOS in Send backpressure observation

Issue: Pressure counters count loop evaluations rather than unique logical sends and lack principal correlation.

Required fixes:

1. Assign one operation identity before entering the retry loop.
2. Separate initial attempts, retries, deferrals, and terminal outcomes.
3. Report pressure by channel generation and principal without leaking payload data.


### Known issues/TODOS in Send channel lock scope

Issue: One global lock covers unrelated channels and executes allocation, persistence, logging, rollback, and scheduler preparation.

Required fixes:

1. Split table lookup protection from per-channel mutation locking.
2. Move fallible external work outside the queue critical section.
3. Establish and test a global lock-order policy.


### Known issues/TODOS in Sender block preparation

Issue: Scheduler preparation failures collapse to WouldBlock and provide no retry or health evidence.

Required fixes:

1. Preserve a typed scheduler-preparation failure.
2. Record whether no wait was registered and whether transfer rollback succeeded.
3. Add scheduler fault-injection coverage.


### Known issues/TODOS in Sender wait-queue insertion

Issue: The local sender queue silently drops entries at capacity or when no current PID is available.

Required fixes:

1. Make insertion return a typed result.
2. Record overflow and explicitly rely on scheduler fallback when insertion fails.
3. Test more than 16 waiters and missing-current-process conditions.


### Known issues/TODOS in Sender block commit

Issue: Block commit exposes no result to IPC, leaving failed or invalidated plans without a recoverable outcome.

Required fixes:

1. Return commit status from the scheduler.
2. Handle cancelled, already-woken, and failed plans explicitly.
3. Test wake-before-commit and close-before-commit races.


### Known issues/TODOS in Send retry loop

Issue: Deferral rolls back ticketed capabilities even though the copied Message may be retried later with those ticket records.

Required fixes:

1. Keep staged transfers pending across internal retries or reconstruct them safely.
2. Separate temporary blocking from terminal send failure.
3. Test reliable capability sends through repeated full-queue wake cycles.


### Known issues/TODOS in Receiver wakeup after send

Issue: Receiver wake failure does not affect send success and is not recorded as degraded delivery.

Required fixes:

1. Count failed and stale wake attempts.
2. Guarantee a durable scheduler-visible readiness condition after enqueue.
3. Test local waiter failure and fallback wake behavior.


### Known issues/TODOS in Send temporal persistence

Issue: Send ignores temporal event and snapshot failures while performing persistence under the global lock.

Required fixes:

1. Propagate failure or enqueue a durable retry record.
2. Capture immutable state under lock and persist after releasing it.
3. Test committed sends with event, allocation, and storage failures.


### Known issues/TODOS in Send failure rollback

Issue: Rollback results are ignored, and permission or invalid-capability rejection does not roll back ticketed attachments.

Required fixes:

1. Route every terminal pre-commit failure through one rollback helper.
2. Treat rollback failure as a security-relevant terminal state.
3. Prove each ticket is committed or cancelled exactly once.


### Known issues/TODOS in Reliable send semantics

Issue: Reliable behavior is inferred from absence of ASYNC rather than controlled by the RELIABLE flag.

Required fixes:

1. Define valid flag combinations and reject contradictions.
2. Make RELIABLE explicitly select blocking and retry guarantees.
3. Test closure, revocation, cancellation, and capability transfer during reliable waits.


### Known issues/TODOS in Async send semantics

Issue: Async capacity refusal is surfaced as generic EIO and has no precise retry contract.

Required fixes:

1. Map temporary backpressure to EAGAIN or the kernel's equivalent.
2. Document high-priority behavior at high and saturated pressure.
3. Test that async sends never enter scheduler blocking.


### Known issues/TODOS in Send error propagation

Issue: Typed internal failures become strings and coarse errno values before reaching callers.

Required fixes:

1. Define a stable conversion from every IpcError to syscall errno.
2. Preserve terminal versus retryable classification.
3. Correlate returned errors with audit, rollback, and temporal outcomes.


### Known issues/TODOS in Send syscall return values

Issue: Capability-send success reports only payload length, while most distinct failures map to EIO.

Required fixes:

1. Specify whether success confirms queue acceptance or receiver consumption.
2. Return or expose capability transfer identity through a separate result structure.
3. Add ABI tests for every success and failure mapping on supported architectures.


### Known issues/TODOS in Open channel behavior

Issue: The drain API reports AlreadySealed for an open channel, conflating normal operation with completed shutdown.

Required fixes:

1. Return a NotDraining result or typed invalid-state error for drain on an open channel.
2. Test that the rejected drain request leaves normal send and receive behavior unchanged.
3. Document the permitted operations and invariants of the open state.


### Known issues/TODOS in Draining channel behavior

Issue: A draining channel has no deadline, forced cleanup policy, or guarantee that an authorized receiver will finish consuming queued messages.

Required fixes:

1. Define bounded drain policy for process exit, capability revocation, and abandoned receivers.
2. Add forced cancellation that resolves queued capabilities and records data loss.
3. Expose drain age, initiator, and remaining depth through diagnostics.


### Known issues/TODOS in Sealed channel behavior

Issue: Receive admission rejects a sealed channel only when its queue is empty, allowing delivery if malformed restoration creates a sealed state with residual messages.

Required fixes:

1. Reject all receives when closure is sealed.
2. Validate that sealed snapshots contain no queued messages or active waiters.
3. Add invariant tests preventing sealed channels from retaining traffic.


### Known issues/TODOS in Close transition correctness

Issue: Lifecycle mutation, security logging, temporal recording, wake delivery, and persistence do not form one committed transition.

Required fixes:

1. Define the evidence required before close may report success.
2. Stage and publish the transition with durable evidence or an explicit evidence-loss record.
3. Inject failures after authorization and verify the documented terminal state.


### Known issues/TODOS in Drain transition correctness

Issue: Final sealing is embedded in receive while the explicit drain API uses ambiguous state results.

Required fixes:

1. Centralize final-drain transition logic in one lifecycle helper.
2. Distinguish open, draining, complete, and already sealed outcomes.
3. Test final dequeue, empty-draining corruption, and repeated drain calls.


### Known issues/TODOS in Send rejection during draining

Issue: The draining refusal lacks structured lifecycle context and may collapse into a generic caller-visible error.

Required fixes:

1. Preserve a distinct draining error through service and syscall boundaries.
2. Expose remaining depth and non-sensitive shutdown status through diagnostics.
3. Verify that each rejected capability transfer is rolled back exactly once.


### Known issues/TODOS in Receive allowance during draining

Issue: An empty draining channel causes receive admission to wait even though sends are permanently forbidden.

Required fixes:

1. Seal an empty draining channel before receive admission can defer.
2. Reject inconsistent restored lifecycle and queue combinations.
3. Add a regression test for empty draining state and waiter wakeup.


### Known issues/TODOS in Sealed send behavior

Issue: Sealing rejects operations but does not invalidate outstanding capabilities, permitting unlimited retries from stale holders.

Required fixes:

1. Revoke capability-manager grants when policy declares terminal closure.
2. Bind capabilities to a channel generation and tombstone sealed generations.
3. Audit or rate-limit repeated operations against sealed channels.


### Known issues/TODOS in Sealed receive behavior

Issue: The implementation relies on queue emptiness rather than sealed state alone to prevent delivery.

Required fixes:

1. Make sealed an unconditional receive refusal.
2. Assert queue emptiness at every transition into sealed.
3. Test restored and corrupted sealed states containing residual messages.


### Known issues/TODOS in Double-close behavior

Issue: Repeated close returns success without reporting whether the channel is draining or sealed and without recording the request.

Required fixes:

1. Return an idempotent result containing the current closure state.
2. Add a bounded counter for repeated close requests.
3. Test retries during draining and after sealing from different capability holders.


### Known issues/TODOS in Closing channels with pending messages

Issue: Pending messages and transferred capabilities can remain indefinitely when no receiver completes the drain.

Required fixes:

1. Define ownership and cancellation rules for abandoned queued messages.
2. Add a bounded forced-seal path that rolls back or revokes pending transfers.
3. Audit discarded messages, capabilities, and affected principals.


### Known issues/TODOS in Closing empty channels

Issue: Direct sealing does not reclaim the channel table entry or proactively revoke capabilities.

Required fixes:

1. Define whether sealing and destruction are separate lifecycle operations.
2. Add generation-bearing tombstones before IDs or resources can be reused.
3. Test capability behavior before sealing, after sealing, and after destruction.


### Known issues/TODOS in Close wakeup behavior

Issue: Scheduler wake failures and discarded local waiter entries are ignored, so close can succeed while processes remain blocked.

Required fixes:

1. Record failed wakes and remaining waiter counts.
2. Add reliable terminal notification independent of one wake attempt.
3. Test stale PIDs, waiter overflow, scheduler failure, and concurrent close.


### Known issues/TODOS in Close failure atomicity

Issue: Close is monotonic but not transactionally atomic because logging, persistence, and wake operations can fail after mutation without affecting its successful result.

Required fixes:

1. Classify post-transition failures as fatal, retryable, or evidence-only.
2. Return or retain a typed degraded-close result when required work fails.
3. Add fault-injection tests for audit, temporal, scheduler, and allocator failures.


### Known issues/TODOS in Close temporal persistence

Issue: Temporal failures are discarded, and full snapshot serialization runs while the global IPC lock is held.

Required fixes:

1. Propagate persistence failure or enqueue a durable retry record.
2. Capture bounded immutable state under lock and store it after releasing the lock.
3. Test restoration after draining, direct sealing, final drain, repeated close, and interrupted persistence.


### Known issues/TODOS in Fixed-size payload storage

Issue: Inline storage gives every message a 512-byte payload array, so peeking, iterating, cloning, and moving small messages still copy the full storage object. The queue representation is bounded but not size-efficient.

Required fixes:

1. Change ring inspection APIs to borrow messages instead of copying them.
2. Measure Message size on every supported architecture and add compile-time or unit assertions for the intended storage budget.
3. Consider a fixed pool of payload blocks or size classes if profiling shows that inline storage materially limits channel density.


### Known issues/TODOS in Payload length validation

Issue: Constructors and snapshot restoration validate payload length, but the public payload_len field permits invalid direct construction or mutation. payload then slices with the unchecked value and can panic inside the kernel.

Required fixes:

1. Make payload and payload_len private and expose bounded constructors and mutation methods.
2. Make payload return a typed error or preserve an invariant that makes an invalid length unrepresentable.
3. Add tests for lengths zero, 512, 513, and deliberately malformed internal metadata.


### Known issues/TODOS in Payload copy correctness

Issue: Normal and restored messages copy the declared prefix correctly, but there is no single shared routine that defines and tests the copy invariant across construction, restore, facade receive, and syscall copy-out.

Required fixes:

1. Centralize bounded payload construction and extraction in Message methods.
2. Add known-answer tests for empty, partial, exact-limit, and restored payloads.
3. Add guarded destination tests proving that receive copy-out writes exactly the reported range.


### Known issues/TODOS in Zero-initialization of unused payload bytes

Issue: Current constructors zero the unused payload tail, but public fields allow later mutation and no dedicated regression test proves the tail remains zero after every construction and restoration path.

Required fixes:

1. Encapsulate payload storage so callers cannot replace it independently of the logical length.
2. Add tests that inspect every byte after payload_len for all constructors and temporal restoration.
3. Clear the full object before returning message storage to any future reusable pool.


### Known issues/TODOS in Capability array initialization

Issue: Capability slots begin as None, but a sparse prefix is accepted because capabilities filters missing entries rather than rejecting a mismatch between caps_len and occupied slots.

Required fixes:

1. Make caps and caps_len private and expose insertion and iteration through one validated interface.
2. Reject or repair holes in the declared capability prefix during restoration and receive validation.
3. Add malformed-message tests for holes, trailing populated slots, and inconsistent counts.


### Known issues/TODOS in Capability count tracking

Issue: add_capability maintains the count correctly, but direct mutation can set caps_len above the array bound and cause a panic or can make the declared count disagree with occupied slots.

Required fixes:

1. Replace the public count with a private bounded integer or derive the count from a compact collection.
2. Validate capability count and slot occupancy before enqueue, persistence, and dequeue.
3. Add exact-limit and overflow tests that also verify transfer-ticket rollback.


### Known issues/TODOS in Source PID binding

Issue: The source PID and EventId source component are caller-supplied metadata. The channel does not enforce equality among the sending endpoint owner, Message source, and EventId source.

Required fixes:

1. Stamp source identity inside the authenticated send path instead of accepting it from an arbitrary Message constructor.
2. Reject messages whose source field, event identity, and endpoint owner disagree.
3. Add audit tests for forged source identities and kernel-on-behalf-of-process sends.


### Known issues/TODOS in Message cloning risks

Issue: Message and Capability are Copy, allowing capability envelopes and one-time transfer tickets to be duplicated even after an apparent move into a channel.

Required fixes:

1. Remove Copy from Message and from transfer-bearing capability envelopes.
2. Change RingBuffer::peek and iter to return references and update admission logic to borrow.
3. Represent ticketed transfers with an affine guard that can be consumed once or explicitly rolled back.


### Known issues/TODOS in Debug formatting information leakage

Issue: Debug omits message contents but still exposes process identity, message size, event identity, and causal links, which can reveal communication metadata.

Required fixes:

1. Separate privileged diagnostic formatting from a redacted default Debug view.
2. Gate detailed causal and source metadata behind the kernel audit authority.
3. Add tests that ensure payloads, capability tokens, rights, and object identifiers never appear in default formatting.


### Known issues/TODOS in Message construction failure modes

Issue: Multi-capability construction is not transactional, transfer rollback failures are ignored, and event sequence exhaustion cannot be reported. A partial local message may retain already attached transfer state after a later failure.

Required fixes:

1. Add a builder that reserves and validates all capabilities before committing any attachment.
2. Return rollback failures as typed errors and audit unresolved transfer tickets.
3. Define sequence exhaustion and wrap behavior rather than silently reusing 16-bit values.


### Known issues/TODOS in Message size denial-of-service resistance

Issue: Syscall send and receive handlers permit buffers up to 4096 bytes even though Message payloads are limited to 512, causing avoidable heap allocation and copy work on invalid sends and oversized receives.

Required fixes:

1. Enforce MAX_MESSAGE_SIZE at the syscall boundary before allocation or user-memory access.
2. Use a fixed 512-byte kernel staging buffer for IPC payload transfer.
3. Add rate and allocation tests for repeated oversized sends and receives.


### Known issues/TODOS in ABI-safe message layout

Issue: Message has no stable representation and contains usize and Option fields whose layout varies by target and compiler. Accidental raw serialization or foreign exposure would create an unstable ABI.

Required fixes:

1. Keep Message private to the IPC implementation and prohibit raw byte serialization.
2. Define versioned fixed-width wire structures for syscalls, persistence, tracing, and foreign interfaces.
3. Add cross-target encoding tests that compare i686, x86-64, and AArch64 wire output.


### Known issues/TODOS in Send path ownership semantics

Issue: A successful send stores an independent message value, but the type system does not consume capability authority because Message and Capability remain Copy. External ledger checks carry the full burden of preventing replay.

Required fixes:

1. Introduce a non-copy PendingMessage whose successful send consumes all attached transfer guards.
2. Require rights attenuation and ticket reservation through the capability manager before attachment.
3. Prove that every refusal, timeout, close, and queue failure either commits or rolls back each ticket exactly once.


### Known issues/TODOS in Receive path copy-out semantics

Issue: Receive silently truncates payloads and capability arrays to caller capacity after permanently dequeuing the message. Embedded capability tokens are not verified before copy-out.

Required fixes:

1. Report required payload and capability capacities without dequeuing when output buffers are too small.
2. Verify every capability token, owner binding, expiry, rights, and transfer ticket before delivery.
3. Make payload and capability delivery atomic so a partial copy cannot discard the remainder of the message.


### Known issues/TODOS in Stale data exposure prevention

Issue: Valid construction avoids stale-byte disclosure, but the guarantee relies on mutable public metadata and on callers respecting the returned copy length. Destination bytes beyond that length retain their previous contents.

Required fixes:

1. Encapsulate message metadata and validate it at every trust boundary.
2. Document that receive writes only the returned prefix, or explicitly clear the unused destination range where the ABI requires complete initialization.
3. Add poisoned-buffer tests for construction, queueing, restoration, facade receive, and syscall copy-out.

### Known issues/TODOS in Kernel/user boundary assumptions

Issue: The syscall layer does not validate user-provided buffer pointers against the calling process's address space before copying, a TOCTOU window exists between capability resolution and the data copy, and two temporal facade functions that bypass capability resolution entirely are publicly callable from any kernel code without structural restriction.

Required fixes:

1. Implement an access-ok check in the syscall handler for every user buffer pointer argument before any copy is performed, validating that the pointer range falls within the calling process's user-mode virtual address space.
2. Close the TOCTOU window by either holding a stable reference through the copy operation or re-validating the pointer immediately before use rather than relying on the single resolve step at function entry.
3. Structurally restrict temporal_apply_channel_event and temporal_apply_channel_payload to the temporal subsystem only, either by marking them pub(super) within a tightly scoped module or by adding an explicit subsystem-origin check at the call site.


### Known issues/TODOS in Security enforcement

Issue: Security enforcement is active, but audit export remains limited, copied endpoint values can outlive restrictions and revocation, and signed capability attachments are not verified when copied out by the ordinary receive path.

Required fixes:

1. Implement an audit export path that routes all events emitted by intent_ipc_send, intent_ipc_recv, intent_capability_denied, and intent_invalid_capability to a persistent log stream or a user-readable audit sink accessible to system administrators.
2. Bind predictive restrictions and capability revocation to generation-bearing endpoints, waiters, queued transfers, and operation commit points.
3. Call Capability::verify on every capability dequeued from an incoming message during the receive path before that capability is made available to the receiving process.


### Known issues/TODOS in Locking and concurrency

Issue: The single global Mutex<ChannelTable> is held for the full duration of every temporal snapshot write, meaning any latency in the temporal write path stalls all concurrent IPC operations system-wide. There is no per-channel lock granularity so two unrelated channel pairs always serialize against each other, and the spinlock has no priority awareness creating an inversion risk whenever any IPC operation has variable latency.

Required fixes:

1. Decouple persist_temporal_snapshot from the IPC critical section by serializing snapshots into a write-back ring buffer while the lock is held and flushing them to the temporal store outside the lock from a dedicated kernel writer task or interrupt bottom-half.
2. Replace the single Mutex<ChannelTable> with a structure that uses a read-write lock for table-level lookups combined with per-channel mutexes for individual channel mutation, so operations on independent channels do not serialize against each other.
3. Implement priority inheritance or a priority ceiling protocol on all IPC locks before the system makes any real-time scheduling guarantees about IPC operation latency.
4. Reduce the scope of work done between prepare_block_on and commit_block so the period during which the scheduler is primed but the IPC lock is still transitioning to release is as short as possible.


### Known issues/TODOS in Capability lifecycle and revocation

Issue: When a channel creator process exits, purge_channels_for_process removes channels by creator PID but does not proactively revoke capabilities already delegated to other processes, leaving holders unaware until they attempt an operation and receive an error. Capability revocation is also not wired into the IPC blocking path, so a process blocked in a receive call is not notified if its capability is revoked while it waits.

Required fixes:

1. After calling purge_channels_for_process on process exit, traverse all capabilities delegated to other processes for the exiting process's channels and mark them revoked in the capability manager's table so subsequent lookups fail immediately at the manager level without reaching the channel table.
2. Wire capability revocation into the IPC blocking path so that when a held capability is revoked, the scheduler wakes any process currently blocked on that channel and the woken process receives a revocation-specific error code rather than retrying and finding the channel gone.


### Known issues/TODOS in Facade API consistency

Issue: Four structural inconsistencies make the kernel-facing facade fragile under extension: typed IpcError variants are downgraded to static strings at the facade boundary and re-parsed by the syscall handler creating a silent correctness gap when new variants are added, capability-carrying and plain sends require separate functions, temporal functions are structurally indistinguishable from normal facade functions despite bypassing capability checks, and purge_channels_for_process discards individual channel purge failures silently.

Required fixes:

1. Change all facade function return types to propagate IpcError directly rather than converting to &'static str, and update the syscall handler to match exhaustively on IpcError variants so any newly added variant produces a compile error at the dispatch site rather than a silent fallthrough.
2. Merge send_message_for_process and send_message_with_caps_for_process into one function that accepts an optional capabilities slice, so future send variations do not require a new top-level function.
3. Relocate temporal_apply_channel_event and temporal_apply_channel_payload out of the main facade into a structurally separate temporal-integration module with tighter visibility, preventing them from appearing alongside capability-checked operations in the public API surface.
4. Give purge_channels_for_process a Result return type that collects and surfaces individual channel purge failures so process cleanup code can report or attempt recovery rather than silently succeeding with incomplete cleanup.


### Known issues/TODOS in API visibility and access control

Issue: The IpcService struct methods send, recv, try_recv, and close are fully public, meaning any kernel code that can obtain the IPC singleton reference can call them with an arbitrarily constructed ChannelCapability without going through the capability manager's resolution and verification step that the facade functions enforce.

Required fixes:

1. Mark IpcService::send, IpcService::recv, IpcService::try_recv, and IpcService::close as pub(crate) so they are inaccessible from outside the kernel crate boundary.
2. Designate the facade free functions as the sole external API for IPC operations, enforcing that every external caller must pass through capability resolution before any channel operation is attempted. The IpcService methods become an internal implementation detail of the facade layer.


### Known issues/TODOS in Memory allocation on the hot path

Issue: Three heap allocation sites exist in IPC operation paths. The VecDeque<Message> ring buffer allocates at channel creation time, the BTreeMap<ChannelId, Channel> channel registry allocates tree nodes on every channel create, and encode_temporal_snapshot_payload allocates a growable buffer on every send, receive, and close operation while the IPC mutex is held. The last of these is the most acute because it couples a heap allocation to the global spinlock on the critical path.

Required fixes:

1. Replace VecDeque<Message> in ring.rs with a fixed-size array of message slots and integer head and tail index fields, eliminating the per-channel heap allocation at creation and removing the VecDeque dependency entirely.
2. Replace BTreeMap<ChannelId, Channel> in table.rs with a fixed-size [Option<Channel>; MAX_CHANNELS] array indexed by channel ID modulo MAX_CHANNELS, eliminating all per-insert tree node allocations and removing the BTreeMap dependency.
3. Replace the growable buffer in encode_temporal_snapshot_payload with a fixed-size stack-allocated array whose maximum capacity can be derived statically from MAX_MESSAGE_SIZE, MAX_CAPS_PER_MESSAGE, and CHANNEL_CAPACITY, so no heap allocation occurs on the temporal snapshot path.


### Known issues/TODOS in Scheduler integration edge cases

Issue: The per-channel WaitQueue holds exactly 16 process IDs and overflows to a global wait address for any additional waiters, but this overflow path has never been exercised under load. After a wakeup there is no confirmation that the woken process will find the triggering condition still satisfied, and the retry behavior under high contention is correct but potentially slow.

Required fixes:

1. Implement and test the WaitQueue overflow path end-to-end by creating a scenario with more than 16 concurrent waiters on a single channel and verifying that every waiter receives a correct wakeup signal and eventually unblocks without starvation.
2. After a woken process re-acquires the channel lock, explicitly recheck the condition that caused the block (queue non-empty for receivers, queue non-full for senders) and ensure the retry loop handles spurious wakeups without introducing livelock under sustained contention.
3. Add a self-test case in selftest.rs that saturates the WaitQueue beyond its 16-entry capacity and asserts all waiting processes eventually succeed.


### Known issues/TODOS in Module facade dead code suppression

Issue: The global #![allow(dead_code)] attribute on mod.rs silently suppresses unused-item warnings across the entire IPC module, making it structurally impossible to detect dead code paths without removing the attribute and auditing all resulting warnings.

Required fixes:

1. Remove #![allow(dead_code)] from mod.rs and resolve every resulting warning individually, either by making the item genuinely used, marking it pub with intent, or deleting it.
2. Move the RingBuffer re-export out from behind #[cfg(test)] so external diagnostic and inspection code can reference the type without depending on the test configuration.
3. Extract the inline test module from mod.rs into a dedicated tests submodule file to separate module structure from test infrastructure.


### Known issues/TODOS in Primitive type validation gaps

Issue: The Capability struct's verify method is implemented correctly but is never called when a message is dequeued, leaving cryptographic token validation absent on the receive path despite the signing infrastructure being in place.

Required fixes:

1. Call Capability::verify inside Channel::try_recv for every capability in the dequeued message before the message is returned to the caller, and return IpcError::PermissionDenied if any capability fails verification.
2. Replace all temporal_ipc_append helpers that take &mut Vec<u8> with versions that accept a fixed-size mutable buffer and a cursor, so temporal serialization can operate on stack-allocated storage without requiring a live heap allocator.
3. Add construction-time validation to ProcessId and ChannelId that rejects the zero value, making zero an explicitly unrepresentable ID rather than a silently valid sentinel.
4. Integrate TypedServiceArg into at least one live IPC code path or document it as a future-only interface so its present status is unambiguous.


### Known issues/TODOS in Message sequence ordering and copy semantics

Issue: The global MSG_SEQ counter uses Ordering::Relaxed, which provides atomicity for the counter itself but does not guarantee that messages created on different cores appear in globally consistent sequence-number order relative to surrounding memory operations.

Required fixes:

1. Change MSG_SEQ::fetch_add to use Ordering::AcqRel so that message sequence allocation forms a visible happens-before edge relative to the message fields written after the sequence number is stamped.
2. Add a test that constructs a message with MAX_CAPS_PER_MESSAGE capabilities and a second with MAX_CAPS_PER_MESSAGE + 1 capabilities, verifying the latter returns IpcError::TooManyCaps and that the first capability slot is not partially populated on failure.
3. Add a test that constructs a message and verifies all bytes in payload beyond payload_len are zero immediately after construction.


### Known issues/TODOS in Channel capability synthesis and delegation gaps

Issue: ChannelCapability carries no cryptographic binding to its original grant event, meaning any kernel code that knows a channel ID and a process ID can synthesize a structurally valid capability without going through the capability manager.

Required fixes:

1. Add a HMAC token field to ChannelCapability analogous to the token in the full Capability struct, computed at grant time using a kernel-internal key, and verify the token inside can_send, can_receive, and can_close before any operation proceeds.
2. Add a test that attempts to use a ChannelCapability with only SEND rights to call close and verifies that IpcError::PermissionDenied is returned.
3. Add a test that exercises AffineEndpoint::delegate_zero_sum with mismatched A and B values that do not sum to CAPACITY and verifies the error path.


### Known issues/TODOS in Ring buffer allocation and peek overhead

Issue: RingBuffer wraps a VecDeque<Message> that is heap-allocated at channel creation time, and peek copies a full Message struct of approximately 600 bytes including the unused portion of the 512-byte payload array on every admission-control check.

Required fixes:

1. Replace VecDeque<Message> with a fixed-size [Option<Message>; CHANNEL_CAPACITY] array with integer head, tail, and occupancy fields, eliminating the heap allocation at channel creation and making RingBuffer usable in a no-alloc configuration.
2. Change peek to return a shared reference into the buffer rather than a copied value, so admission-control checks do not pay a 600-byte copy on every invocation.
3. Add an explicit test that calls push on a full RingBuffer and verifies it returns IpcError::WouldBlock without modifying the buffer contents.


### Known issues/TODOS in Channel state machine snapshot integrity

Issue: encode_temporal_snapshot_payload performs a heap allocation and full channel state serialization on every mutating IPC operation while the global IPC mutex is held, coupling allocator latency directly to the spinlock critical path for every send, receive, and close.

Required fixes:

1. Move encode_temporal_snapshot_payload outside the IPC mutex critical section by copying the minimal state needed for serialization while the lock is held and then performing the heap allocation and serialization after the lock is released.
2. Fix restore_temporal_snapshot_payload to return an explicit error when the byte cursor reaches the end of the buffer before all fields have been parsed, rather than silently saturating the cursor and leaving fields at their default values.
3. Change WaitQueue::push_back to return a Result that signals overflow rather than silently dropping the entry, so callers can fall back to the global scheduler wait address explicitly rather than losing the PID.
4. Remove the duplicate call to validate_temporal_send inside send_with_observed_pressure, keeping only the single call in admission::evaluate_send, so the temporal protocol is checked exactly once per send.


### Known issues/TODOS in Admission pipeline coverage gaps

Issue: The receive admission pipeline in admission.rs does not include a temporal protocol check, meaning a message that violates the temporal protocol passes the admission gate and is only rejected at the moment of dequeue inside try_recv, breaking the architectural separation between admission policy and execution.

Required fixes:

1. Add a validate_temporal_recv call to evaluate_recv at the same position as the validate_temporal_send call in evaluate_send, so the receive admission decision is complete without requiring callers to perform a second protocol check after the gate.
2. Remove the QueueEmpty variant from IpcRefusal or implement a code path that produces it, resolving the dead variant that currently exists in the enum without any producer.
3. Document explicitly in a code comment why validate_temporal_send is called in evaluate_send but the analogous check is absent from evaluate_recv, or fix the asymmetry.


### Known issues/TODOS in Backpressure receive-side coverage and hysteresis

Issue: The backpressure system applies pressure-based admission only to senders and has no mechanism for signaling or rate-limiting receivers that consume messages too slowly relative to the arrival rate, leaving half the flow-control surface unimplemented.

Required fixes:

1. Define a receive-side pressure concept that can signal a slow receiver process, for example by recording the number of times a receiver dequeues from a channel that was at the Saturated level, and expose this counter through ChannelDiagnostics.
2. Add hysteresis to the High pressure level by requiring the occupancy to drop below a separate lower threshold before the level resets to Available, preventing alternating Commit and Refuse decisions for a sender operating at exactly the threshold boundary.
3. Document the integer division behavior of the threshold computation and add a compile-time assertion that the effective threshold is at least 50% of CHANNEL_CAPACITY for any value that constant may take.


### Known issues/TODOS in Channel registry ID exhaustion and isolation

Issue: The ChannelTable exposes its internal channels field as pub(crate), allowing any code in the kernel crate with a locked table reference to call BTreeMap methods directly and bypass the MAX_CHANNELS enforcement in create_channel_with_flags.

Required fixes:

1. Change ChannelTable::channels from pub(crate) to private and add any missing accessor methods so all callers use the validated API surface rather than the raw BTreeMap.
2. Add wrap-around protection to the next_id counter so that if it ever reaches u32::MAX, the counter wraps to 1 and skips any ID that is currently in use rather than saturating permanently at u32::MAX and preventing further channel creation.
3. Have delete_channels_by_creator emit a temporal persistence event for each removed channel so the temporal subsystem can record the deletion and restore correctly does not re-create channels for processes that have exited.


### Known issues/TODOS in IPC service facade creation inconsistency

Issue: create_channel_for_process_with_flags grants a single capability with all four rights combined, while IpcService::create_channel issues two separate send-only and receive-only capabilities, meaning the two creation paths produce structurally different access grants for the same semantic operation.

Required fixes:

1. Reconcile the two channel creation paths so both produce the same capability shape: either always issue two separate send and receive capabilities, or always issue a single combined capability with explicit rights, and remove the divergent path.
2. Give purge_channels_for_process a typed return value that includes whether capability manager revocation succeeded for each purged channel, and call the capability manager's revocation API for every channel removed.
3. Change the return types of send_message_for_process, receive_message_for_process, and close_channel_for_process from Result<_, &'static str> to Result<_, IpcError> so the full error type is preserved at the facade boundary without lossy string conversion.


### Known issues/TODOS in IPC diagnostics accuracy and completeness

Issue: The waiting_receivers and waiting_senders fields in ChannelDiagnostics report counts from the global scheduler wait table rather than from the channel's local WaitQueue, which means the diagnostic values can diverge from the channel's actual local wait list under overflow or transient inconsistency conditions.

Required fixes:

1. Change ChannelDiagnostics to populate waiting_receivers and waiting_senders from channel.waiting_receivers.len() and channel.waiting_senders.len() respectively, and add a separate pair of fields for the scheduler-side counts so both values are visible and the discrepancy is surfaced rather than hidden.
2. Add a snapshot_at timestamp field to IpcDiagnostics populated at the moment the mutex is locked so consumers can compute rates and compare successive snapshots without needing an external clock reference.
3. Add a decoded ChannelFlags breakdown alongside the raw flags_bits field in ChannelDiagnostics so consumers do not need to know the bit layout independently.


### Known issues/TODOS in Self-test coverage gaps

Issue: The 15 existing self-test cases do not cover CLOSE-right enforcement, WaitQueue overflow beyond 16 entries, purge_channels_for_process correctness, the exact MAX_MESSAGE_SIZE and MAX_CAPS_PER_MESSAGE boundary conditions, or the integrity of capabilities embedded in messages restored from temporal snapshots.

Required fixes:

1. Add a test that attempts a close operation using a capability with only SEND rights and verifies that IpcError::PermissionDenied is returned without modifying the channel state.
2. Add a test that enqueues 17 or more processes as waiting receivers on a single channel and verifies that all 17 eventually receive a wakeup and complete their receive without any being silently dropped.
3. Add a test that calls purge_channels_for_process for a creator PID that has two live channels, verifies both channels are removed from the table, and verifies the capability manager no longer resolves capabilities for those channel IDs.
4. Add boundary tests that send a payload of exactly 512 bytes and attach exactly 16 capabilities, verifying both succeed, then send 513 bytes and attach a 17th capability, verifying both return the correct error without side effects.
5. Extend case 14 to verify that each Capability restored from a temporal snapshot has a valid token by calling Capability::verify on every capability in every dequeued message after restoration.


### Known issues/TODOS in Syscall adapter length and pointer validation

Issue: The IPC syscall handlers accept message lengths up to 4096 bytes from user space but the kernel IPC layer enforces a 512-byte maximum, causing the kernel to heap-allocate up to 4 KB per malformed send attempt before the oversized message is rejected, creating a denial-of-service amplification vector.

Required fixes:

1. Lower the upper bound check in sys_channel_send and sys_channel_send_caps from 4096 to MAX_MESSAGE_SIZE so the heap allocation for the copy buffer is bounded to the maximum the IPC layer will accept, and the rejection happens at the syscall boundary before any allocation.
2. Replace the hardcoded 0xC0000000 pointer boundary check with a call to a per-process VMA validation function that checks whether the pointer range falls within the calling process's mapped user-mode pages, making the check correct for all architectures and memory layouts.
3. Replace all error-string matching in the syscall dispatch table with match arms over IpcError variants so that adding a new error variant produces a compile-time exhaustiveness error rather than silently mapping to the wrong errno.
4. Protect SYSCALL_STATS with an AtomicU64 or a per-CPU counter rather than a static mut field updated in unsafe blocks, eliminating the data race under multi-core execution.
5. Remove the unconditional privilege bypass for caller PIDs 0 through 2 in sys_channel_create and instead express the same policy through the capability manager so the exception is visible to and enforceable by the access control subsystem.


### Known issues/TODOS in Specification documentation gaps

Issue: The IPC specification document at docs/ipc/oreulia-ipc.md does not document the wait address derivation formula, describes the AffineEndpoint as experimental when the implementation is complete, and omits the temporal snapshot binary format entirely, leaving the specification misaligned with the audited implementation.

Required fixes:

1. Add a section to docs/ipc/oreulia-ipc.md documenting the wait address formula ((channel_id as usize) << 2) | kind with the kind constants for message availability and capacity availability, and explaining why these values must not collide with other scheduler wait addresses.
2. Update the AffineEndpoint description from experimental to production-ready and document the zero-sum delegation invariant and when callers should prefer it over a plain ChannelCapability split.
3. Add a temporal integration section describing the snapshot binary format, the version field, the frame kinds, and the encode and restore lifecycle so the persistence contract is auditable from the specification without requiring readers to reverse-engineer the binary layout from source.
4. Add a known limitations section to docs/ipc/oreulia-ipc.md that links to this audit checklist so the specification and the audit remain cross-referenced.


### Known issues/TODOS in Verification scope gaps for IPC

Issue: The IPC module is not named in docs/verification-overview.md as either in-scope or out-of-scope for formal verification, and no mechanized proofs exist for the three core IPC safety properties: capability isolation, message ownership transfer, and deadlock freedom.

Required fixes:

1. Add the IPC module to docs/verification-overview.md with an explicit scoping statement identifying which properties are verified, which are covered only by runtime selftests, and which remain entirely unverified.
2. Develop a mechanized proof or a structured invariant argument for capability isolation: that no process can receive a message intended for a different process and no process can observe a capability it was not explicitly granted.
3. Develop a mechanized proof or a structured invariant argument for message ownership transfer: that after a message is enqueued via channel.send, the sending process no longer has access to any capability objects that were transferred in that message.
4. Develop a reachability argument for deadlock freedom in the two-phase block protocol: that a process calling IpcService::send or IpcService::recv will always eventually either complete its operation or return an error, with no circular wait possible among the scheduler, the IPC mutex, and the capability manager.
5. Extend the selftest suite to include end-to-end cases that exercise the full syscall-to-channel path including capability resolution, so the verified behavior covers the actual operation path rather than only synthetic channel instances.


### Known issues/TODOS in Channel pending count diagnostics

Issue: Pending depth is an accurate lock-protected point sample, but it has no channel generation, observation time, operation totals, or message-age context.

Required fixes:

1. Bind each sample to channel identity, generation, and a monotonic observation sequence.
2. Add enqueue and dequeue totals plus oldest queued-message age.
3. Test that pending, empty, and full remain mutually consistent across every mutation and restoration.


### Known issues/TODOS in Channel capacity reporting

Issue: Diagnostics expose fixed entry limits but not aggregate occupancy, memory cost, waiter capacity, or related capability and persistence resource ceilings.

Required fixes:

1. Report total queued entries and bounded IPC memory usage across all channels.
2. Publish message, waiter, channel, capability-transfer, and snapshot limits in one resource summary.
3. Add configuration assertions and exact-limit tests for every reported capacity.


### Known issues/TODOS in Closed state reporting

Issue: Detailed diagnostics preserve Open, Draining, and Sealed, but channel_stats and public callers receive a reduced boolean or generic operation error.

Required fixes:

1. Preserve the complete lifecycle state through every diagnostic and public API.
2. Report closure initiator, transition sequence, remaining drain depth, and wakeup result.
3. Test lifecycle observations during concurrent close, send, receive, drain, and process exit.


### Known issues/TODOS in High watermark diagnostics

Issue: The peak depth has no timestamp, EventId, generation, or reset and restoration policy.

Required fixes:

1. Record the observation sequence and message EventId that established each new peak.
2. Define whether restore preserves history or starts a new diagnostic epoch.
3. Test that failed sends and receives never raise the watermark.


### Known issues/TODOS in Refusal counter diagnostics

Issue: Directional totals merge every refusal reason and omit caller, retry classification, timing, and transfer rollback outcome.

Required fixes:

1. Maintain bounded counters by IpcRefusal reason and operation direction.
2. Separate Refuse from Defer, scheduler failure, timeout, cancellation, and retry.
3. Correlate refusal evidence with principal, channel generation, operation ID, and rollback result.


### Known issues/TODOS in Backpressure diagnostics

Issue: High-pressure and saturation counters count attempts but do not show outcomes, duration, responsible principals, or transition history.

Required fixes:

1. Count commit, defer, pressure refusal, and full-queue refusal separately.
2. Record pressure transition sequence and cumulative time spent at each level.
3. Add per-principal or quota-aware pressure evidence without exposing message contents.


### Known issues/TODOS in Wakeup diagnostics

Issue: Wakeup totals do not identify reason, target, failed wake attempts, latency, or eventual operation completion.

Required fixes:

1. Record wake reason, waiter identity and generation, and block-to-wake duration.
2. Count failed, stale, duplicate, local, and scheduler wake attempts separately.
3. Correlate block, wake, retry, and terminal completion under one operation identity.


### Known issues/TODOS in Waiting sender count diagnostics

Issue: The reported sender count comes from scheduler state and can disagree with the channel-local bounded wait queue without exposing the discrepancy.

Required fixes:

1. Report local and scheduler sender counts as separate fields.
2. Track dropped waiter records, oldest wait age, retry count, priority, and process generation.
3. Add deterministic race and overflow tests that assert both views reconcile after wake and cleanup.


### Known issues/TODOS in Waiting receiver count diagnostics

Issue: The reported receiver count hides divergence between scheduler wait state and the channel-local queue and provides no starvation or stale-PID evidence.

Required fixes:

1. Report local and scheduler receiver counts separately.
2. Track overflow, oldest wait age, retry count, priority, and process generation.
3. Test receive, close, revocation, exit, restoration, and missed-wakeup interleavings.


### Known issues/TODOS in Temporal protocol state diagnostics

Issue: Current protocol state is visible only to in-kernel diagnostics and lacks generation, transition history, and last-failure evidence.

Required fixes:

1. Bind protocol state to channel generation and diagnostic observation sequence.
2. Retain bounded last-transition, last-frame, and last-mismatch records.
3. Expose a privilege-controlled process diagnostic that does not leak unauthorized session state.


### Known issues/TODOS in Causal event diagnostics

Issue: Message EventId and cause are absent from channel diagnostics and lightweight operation events, preventing reliable cross-layer correlation.

Required fixes:

1. Include canonical message and predecessor identities in send, receive, refusal, persistence, and syscall outcome records.
2. Maintain bounded duplicate, missing-parent, and stale-identity diagnostics.
3. Test correlation across repeated payloads, concurrency, restoration, and sequence exhaustion.


### Known issues/TODOS in Syscall boundary diagnostics

Issue: Syscall ingress is audited, but IPC completion, copy stage, typed failure, and message identity are not consistently emitted or correlated.

Required fixes:

1. Emit ingress and terminal outcome records for every IPC syscall.
2. Include typed internal result, stable errno, copied byte count, channel generation, and EventId while redacting addresses.
3. Add tests for success, invalid input, policy denial, user fault, protocol failure, closure, and retryable pressure.


### Known issues/TODOS in IPC admission refusal diagnostics

Issue: Broad temporal refusal events discard the exact IpcRefusal variant and do not join defer, rollback, wake, retry, and completion.

Required fixes:

1. Assign stable structured reason codes to every Commit, Refuse, and Defer decision.
2. Preserve queue state, principal, capability identity, channel generation, and message EventId.
3. Record transfer rollback and scheduler preparation outcomes under the same operation correlation ID.


### Known issues/TODOS in Panic and failure diagnostics

Issue: Secondary audit, temporal persistence, rollback, and scheduler evidence failures can be discarded without a uniform diagnostic or fail-stop policy.

Required fixes:

1. Define which evidence failures are recoverable, operation-fatal, or system-fatal.
2. Replace discarded recording results with bounded failure counters and structured events.
3. Add fault-injection tests proving every failure path either reports loss or stops before unsafe continuation.


### Known issues/TODOS in Diagnostic consistency under concurrency

Issue: Channel fields are sampled under one mutex, but scheduler counts come from another subsystem and the result has no sequence or timestamp for detecting a torn cross-subsystem view.

Required fixes:

1. Add observation time, channel generation, and before/after mutation sequence values.
2. Snapshot local IPC state first and obtain scheduler data without holding the IPC mutex under a documented lock-order rule.
3. Mark inconsistent samples explicitly or retry when sequence values show concurrent mutation.


### Known issues/TODOS in Message creation test coverage

Issue: Message tests cover basic and boundary payload construction but not public-field corruption, sequence exhaustion, source authentication, zeroization, or allocation failure.

Required fixes:

1. Add table-driven tests for zero through maximum payload lengths and malformed restored lengths.
2. Test EventId exhaustion, PID reuse, and authenticated source stamping.
3. Add guarded memory tests for unused and retired payload storage.


### Known issues/TODOS in Ring buffer test coverage

Issue: RingBuffer tests prove basic FIFO and full failure atomicity but not repeated wraparound, clear, restoration, stale storage, or randomized sequences.

Required fixes:

1. Compare long generated operation sequences against a reference FIFO.
2. Test clear and snapshot restoration at every queue depth.
3. Inspect retired storage and preserve minimized failure sequences as regressions.


### Known issues/TODOS in Channel send and receive test coverage

Issue: Direct channel tests do not cover the full cross-product of flags, rights, lifecycle, protocol, attachments, principals, and overlapping failures.

Required fixes:

1. Build a table-driven admission and operation matrix.
2. Assert queue, lifecycle, counters, waiters, audit, and transfer state after every denial.
3. Run the same cases through Channel, IpcService, facade, and syscall entry paths.


### Known issues/TODOS in Service receive fallback tests

Issue: Empty receive without scheduler context collapses scheduler failure and ordinary nonblocking absence into WouldBlock.

Required fixes:

1. Add typed scheduler-failure and nonblocking outcomes.
2. Test timeout, cancellation, close, revocation, and process-exit races.
3. Verify waiter and diagnostic state after every fallback.


### Known issues/TODOS in Service send fallback tests

Issue: Full send without scheduler context is tested only for a plain message and does not verify capability tickets or retry preservation.

Required fixes:

1. Test capability-carrying sends across scheduler preparation failure.
2. Verify queue and transfer state remain atomic and recoverable.
3. Test successful retry after capacity becomes available.


### Known issues/TODOS in Receiver wakeup test coverage

Issue: Wake tests prove scheduler state changes but not FIFO completion, local queue reconciliation, stale PID handling, or no-lost-wakeup behavior.

Required fixes:

1. Test multiple receivers under deterministic interleavings.
2. Include stale process generations and local wait-queue overflow.
3. Prove or model the prepare-block, commit-block, send, and wake race.


### Known issues/TODOS in Sender wakeup test coverage

Issue: Sender wake tests do not prove capacity reservation, completion order, transfer-ticket retention, or starvation bounds.

Required fixes:

1. Test competing senders with one freed slot.
2. Verify strict or documented best-effort fairness.
3. Correlate wakeup with successful retry and ticket settlement.


### Known issues/TODOS in Reliable full-channel test coverage

Issue: Deferral is tested, but RELIABLE has no end-to-end eventual-delivery or terminal-failure regression.

Required fixes:

1. Define RELIABLE semantics for cancellation, close, exit, and reset.
2. Test eventual delivery after capacity wakeup.
3. Verify every abandoned reliable send settles attached capabilities exactly once.


### Known issues/TODOS in Async full-channel test coverage

Issue: Async tests cover selected pressure states but not every valid and invalid flag, priority, and retry combination.

Required fixes:

1. Generate all supported channel-mode combinations.
2. Assert exact refusal reason and unchanged state at high pressure and saturation.
3. Test public errno and retry guidance for each outcome.


### Known issues/TODOS in Empty receive test coverage

Issue: Empty receive tests do not distinguish nonblocking absence, active blocking, timeout, interruption, cancellation, revocation, draining, and closure.

Required fixes:

1. Give each empty-channel outcome a typed result.
2. Add deterministic wake-reason race tests.
3. Verify no empty receive mutates queue, protocol, or capability state.


### Known issues/TODOS in Closure state test coverage

Issue: Closure tests do not span every authority, protocol, transfer, restoration, cleanup, and concurrent operation state.

Required fixes:

1. Add a complete lifecycle and rights matrix.
2. Test close against attached pending transfers and temporal phases.
3. Exercise close, send, receive, revocation, and process exit under controlled interleavings.


### Known issues/TODOS in Capability transfer test coverage

Issue: Ticketed helper tests do not cover the live syscall delivery transaction or atomic multi-capability receiver import.

Required fixes:

1. Test export, enqueue, dequeue, destination grant, and ticket consumption end to end.
2. Inject failure at every stage and verify complete rollback.
3. Add substitution, replay, expiry, revocation, and process-exit cases.


### Known issues/TODOS in Temporal protocol test coverage

Issue: Temporal tests use selected frames and do not cover malformed field combinations, exhaustion, boot epochs, replay, or poisoned queue-head recovery.

Required fixes:

1. Add generated frame and state-transition tests.
2. Test request ID exhaustion, restoration collisions, and cross-epoch replay.
3. Define and test quarantine or removal of malformed queued messages.


### Known issues/TODOS in Syscall IPC test coverage

Issue: Syscall testing covers zero-length rejection but no successful IPC operation or realistic user-memory fault boundary.

Required fixes:

1. Add a fake user-address-space harness with readable, writable, partial, and faulting mappings.
2. Test every IPC syscall and every IpcError-to-errno mapping.
3. Run full create, send, receive, capability transfer, and close workflows through dispatch.


### Known issues/TODOS in IPC fuzz and property testing

Issue: No stateful IPC fuzz target or property suite exists.

Required fixes:

1. Fuzz queue, lifecycle, protocol, capability, snapshot, and syscall operations against reference models.
2. Assert boundedness, order, atomicity, authority, and diagnostic invariants after every step.
3. Retain minimized corpora for every discovered failure.


### Known issues/TODOS in IPC negative and security testing

Issue: Negative tests are selective and do not systematically exercise forged, stale, revoked, substituted, replayed, or cross-process authority.

Required fixes:

1. Build a complete capability-invalidity and rights-denial matrix.
2. Add differential timing and result tests for nonexistent and unauthorized objects.
3. Verify every denial leaves state unchanged and emits the intended audit evidence.


### Known issues/TODOS in Architecture-specific IPC testing

Issue: No common IPC ABI suite runs across i686, x86-64, and AArch64.

Required fixes:

1. Publish target-specific register and native-width argument fixtures.
2. Run byte-level layout, pointer, alignment, endianness, and split-field vectors on every target.
3. Require identical semantic results from the shared IPC workflow suite.


### Known issues/TODOS in QEMU IPC regression testing

Issue: IPC self-tests can run manually in QEMU but are not an automated cross-architecture regression gate.

Required fixes:

1. Add deterministic boot commands that run ipc-selftest and return machine-readable status.
2. Include a userspace syscall round-trip workload.
3. Run the suite for every supported QEMU architecture in CI.


### Known issues/TODOS in Formal IPC regression testing

Issue: Runtime conformance checks are exposed through formal-verify, but no IPC property is mechanized or proof-gated.

Required fixes:

1. Model queue boundedness, capability isolation, transfer single-use, and lifecycle transitions.
2. Model scheduler block/wakeup behavior for no-lost-wakeup and deadlock freedom.
3. Run proof artifacts in CI and retain counterexamples as executable regressions.


### Known issues/TODOS in IPC test coverage management

Issue: Coverage is concentrated in direct internals and lacks measurement, a requirement matrix, and conformance across public entry paths.

Required fixes:

1. Maintain a test-to-requirement table for every IPC contract and invariant.
2. Collect line, branch, and state-transition coverage where supported.
3. Prioritize syscall, user-copy, process cleanup, capability import, concurrency, architecture, fuzz, QEMU, and formal gaps.


### Known issues/TODOS in Capability subset preservation invariant

Issue: Subset checks exist in capability helpers, but raw endpoints and the ordinary syscall transfer path are outside one proved attenuation model. Formal status documents also disagree on whether the IPC capability theorem is scaffolded or proved.

Required fixes:

1. Route all endpoint creation and transfer through capability-manager attenuation.
2. Prove that every derived grant is a subset of an authenticated source grant.
3. Reconcile the theorem index, target matrix, proof artifact, and CI status.


### Known issues/TODOS in Message queue capacity invariant

Issue: Runtime queue insertion is bounded, but restoration, future internal mutation, and aggregate IPC allocation are not covered by a machine-checked bound.

Required fixes:

1. Model every queue transition and prove depth remains within capacity.
2. Validate restored depth before publishing channel state.
3. Specify separate entry-count and total-memory bounds.


### Known issues/TODOS in Send-right invariant

Issue: Admission checks the SEND bit but does not prove that a direct caller holds authentic, current, principal-bound send authority.

Required fixes:

1. Make raw endpoint construction private.
2. Resolve owner, generation, token, expiry, and revocation at commit.
3. Prove denied sends leave all queue and transfer state unchanged.


### Known issues/TODOS in Receive-right invariant

Issue: Admission checks the RECEIVE bit, while copied or constructed endpoints can bypass process identity and capability-manager validation.

Required fixes:

1. Require an authenticated endpoint handle for every receive.
2. Validate the executing principal and channel generation before dequeue.
3. Prove denied receives cannot observe or remove queue state.


### Known issues/TODOS in Close-right invariant

Issue: Close authorization is not represented consistently as an independent manager right and direct endpoint values remain forgeable inside the kernel.

Required fixes:

1. Define and issue an explicit close right.
2. Resolve close authority at the lifecycle transition.
3. Prove denial and repeated close preserve the required state.


### Known issues/TODOS in No-send-after-seal invariant

Issue: Ordinary admission rejects sealed channels, but restore, forced cleanup, and direct table paths are not covered by one lifecycle proof.

Required fixes:

1. Define the complete lifecycle transition system.
2. Validate restored lifecycle and queue combinations.
3. Prove no insertion transition exists from draining or sealed state.


### Known issues/TODOS in Drain-before-seal invariant

Issue: Normal close drains queued messages, while forced deletion and process cleanup can destroy a channel without that transition.

Required fixes:

1. Separate graceful close from forced destruction in the contract.
2. Define settlement rules for queued messages and capabilities during destruction.
3. Prove graceful close reaches sealed state under stated liveness assumptions.


### Known issues/TODOS in FIFO ordering invariant

Issue: FIFO order relies on `VecDeque`, lock discipline, and restoration order rather than a model covering failures and lifecycle transitions.

Required fixes:

1. Model enqueue, validation, dequeue, refusal, close, and restore.
2. Prove failed operations cannot reorder or remove messages.
3. Add stateful reference-FIFO and snapshot round-trip tests.


### Known issues/TODOS in Causal identity uniqueness invariant

Issue: A wrapping 16-bit counter, reusable PIDs, a commonly zero channel component, direct construction, and missing boot epochs permit duplicate event identities.

Required fixes:

1. Use a nonwrapping identity containing process, channel, and boot generations.
2. Allocate identity at the authenticated channel commit point.
3. Detect collisions during live allocation and restoration.


### Known issues/TODOS in Temporal session phase invariant

Issue: Runtime phase checks do not prove replay safety, identifier exhaustion behavior, restoration consistency, or recovery from malformed queued frames.

Required fixes:

1. Specify the temporal protocol as a complete transition system.
2. Bind frames to authenticated channel and persistence generations.
3. Prove valid transitions and test every invalid transition and recovery path.


### Known issues/TODOS in Capability transfer authenticity invariant

Issue: Ticketed helpers verify transfers, but the ordinary send and receive syscall path bypasses secure export, import, and destination installation.

Required fixes:

1. Accept sender-local capability IDs rather than raw envelopes.
2. Verify and import all attachments before dequeue commit.
3. Prove envelope fields are derived only from manager state.


### Known issues/TODOS in Capability transfer single-use invariant

Issue: Zero-ticket envelopes and disconnected enqueue, dequeue, import, rollback, exit, and restore operations permit transfer semantics outside the single-use ledger.

Required fixes:

1. Require a nonzero one-time ticket for every authority transfer.
2. Make dequeue and destination installation one transaction.
3. Persist consumed-ticket generations and prove exactly-once settlement.


### Known issues/TODOS in Backpressure threshold invariant

Issue: Threshold behavior is runtime-configured without compile-time relationship checks or a complete model for flags, priorities, and scheduling.

Required fixes:

1. Assert valid capacity and threshold relationships at compile time.
2. Define one state model for asynchronous, reliable, bounded, and priority modes.
3. Prove and test decisions at every pressure boundary.


### Known issues/TODOS in Wait and wakeup liveness invariant

Issue: Wakeups are implemented, but fairness, timeout, cancellation, revocation, exit, and eventual completion are not guaranteed.

Required fixes:

1. Define scheduler fairness and IPC wake-reason contracts.
2. Add bounded retry, aging, reservation, or handoff where required.
3. Model and test eventual progress under competing senders and receivers.


### Known issues/TODOS in No-lost-wakeup invariant

Issue: The two-phase wait protocol has no exhaustive proof for races among preparation, commit, wake, close, revocation, overflow, and process exit.

Required fixes:

1. Specify atomic states for prepared, registered, blocked, woken, and cancelled waits.
2. Make wake-before-block and cancellation outcomes explicit and idempotent.
3. Model-check deterministic interleavings and retain counterexamples.


### Known issues/TODOS in No-deadlock invariant

Issue: IPC overlaps scheduler, capability, security, temporal, diagnostic, and persistence calls without one enforced global lock order.

Required fixes:

1. Publish and enforce a subsystem lock hierarchy.
2. Move external subsystem work outside IPC critical sections where possible.
3. Add lock-dependency tests and a formal wait-for-cycle analysis.


### Known issues/TODOS in Bounded memory invariant

Issue: Per-object limits do not bound aggregate allocations or provide consistent behavior when heap allocation fails.

Required fixes:

1. Define aggregate budgets for channels, messages, waiters, transfers, snapshots, and staging.
2. Use fallible allocation and typed exhaustion results.
3. Add deterministic allocation-failure and maximum-occupancy tests.


### Known issues/TODOS in Syscall boundary validation invariant

Issue: Fixed numeric pointer checks and unsafe copies do not prove mapped access, native-width correctness, overflow safety, or transactional receive output.

Required fixes:

1. Use architecture-aware fault-contained user-copy helpers.
2. Validate complete checked ranges against the caller's address space.
3. Commit dequeue only after output preflight and logical copy completion.


### Known issues/TODOS in Channel table consistency invariant

Issue: Crate-visible storage, wrapping ID allocation, absent generations, restore bypasses, and nontransactional capability cleanup can desynchronize channel and authority state.

Required fixes:

1. Make table storage private and require checked nonreusing IDs with generations.
2. Unify creation, restoration, deletion, and capability updates as transactions.
3. Model and test table, endpoint, transfer, and lifecycle consistency.


### Known issues/TODOS in Process cleanup invariant

Issue: Cleanup removes creator-owned channels but does not settle every endpoint, waiter, ticket, queued attachment, blocked peer, or PID-reuse hazard.

Required fixes:

1. Track all IPC resources by process generation and principal.
2. Atomically revoke endpoints and settle waits, transfers, and queued authority.
3. Test exit during every channel lifecycle and transfer phase.


### Known issues/TODOS in Malicious sender flooding resistance

Issue: Per-channel bounds do not limit per-principal send rate, global IPC work, rejected-buffer copying, persistence, audit, or lock consumption.

Required fixes:

1. Add per-principal message, byte, channel, and failed-attempt quotas.
2. Reject invalid size and authority before allocation, copy, persistence, and audit work.
3. Stress-test sustained floods across many channels and measure service latency.


### Known issues/TODOS in Malicious receiver starvation resistance

Issue: Competing receivers have no fairness guarantee, reservation, aging, or starvation evidence.

Required fixes:

1. Define receiver selection and fairness semantics.
2. Add handoff, aging, or quotas if bounded service is required.
3. Test deterministic lock and scheduler races among many receivers.


### Known issues/TODOS in Capability forgery resistance

Issue: Raw endpoints are constructible and the capability-carrying syscall can obtain a kernel signature over attacker-selected authority fields.

Required fixes:

1. Accept only sender-local capability IDs from user space.
2. Resolve and export every attachment through the capability manager.
3. Make raw endpoint and envelope construction private to authenticated issuance paths.


### Known issues/TODOS in Capability replay attack resistance

Issue: Zero-ticket syscall attachments bypass one-time consumption and can be copied or presented repeatedly.

Required fixes:

1. Require nonzero one-time tickets for authority-bearing attachments.
2. Reject zero-ticket imports except explicitly non-authority metadata.
3. Persist ticket consumption generations across restoration.


### Known issues/TODOS in Capability substitution attack coverage

Issue: Ticketed import compares selected immutable state, but the live syscall path bypasses it and no complete field-substitution matrix exists.

Required fixes:

1. Compare the complete canonical envelope with pending transfer state.
2. Remove user-controlled owner, object, type, rights, validity, and token fields from the ABI.
3. Test substitution of every field independently and in combinations.


### Known issues/TODOS in Stale capability after channel deletion

Issue: Channel deletion is not atomic with capability revocation, and endpoints contain no activation generation.

Required fixes:

1. Bind grants to a nonrepeating channel generation.
2. Revoke all matching grants and settle transfers during deletion.
3. Test delete, recreate, restore, and stale-handle use.


### Known issues/TODOS in PID reuse confusion

Issue: Numeric PIDs identify owners, sources, waiters, and transfer participants without a process generation.

Required fixes:

1. Introduce a principal identity containing PID and generation.
2. Store that identity in endpoints, messages, wait queues, tickets, and snapshots.
3. Test process exit and PID reuse with stale queued state.


### Known issues/TODOS in Channel ID reuse confusion

Issue: Channel IDs can wrap or be restored without a documented exhaustion policy, and stale endpoints cannot distinguish channel activations.

Required fixes:

1. Pair every channel ID with a nonrepeating generation.
2. Use checked allocation with explicit exhaustion and collision handling.
3. Validate IDs and generations during lookup, transfer, restore, and deletion.


### Known issues/TODOS in Forced protocol mismatch handling

Issue: An authorized sender can desynchronize a temporal session, and a malformed queue head can repeatedly deny access to later messages.

Required fixes:

1. Define reset, quarantine, discard, and terminal-close policy for malformed frames.
2. Preserve protocol errors distinctly through facade and syscall mappings.
3. Test poisoned-head recovery and every overlapping lifecycle and phase state.


### Known issues/TODOS in Temporal replay injection resistance

Issue: Temporal frames and restored protocol state lack authenticated boot, channel, process, and persistence generations.

Required fixes:

1. Bind frames to channel generation, principal generation, and persistence epoch.
2. Reject restored identifier and phase regressions before publication.
3. Test replay across close, recreation, reboot, wraparound, and restore.


### Known issues/TODOS in Close and drain abuse resistance

Issue: Close authority and forced destruction can terminate service or discard unsettled messages and capabilities without one consistent policy.

Required fixes:

1. Issue an explicit close-administration right.
2. Separate graceful close, administrative abort, and process cleanup semantics.
3. Atomically settle queued transfers and return typed wake reasons to blocked peers.


### Known issues/TODOS in Wait queue poisoning resistance

Issue: Wait queues accept duplicate generation-free PIDs, silently drop overflow, and can diverge from scheduler registration.

Required fixes:

1. Store unique process-generation wait tokens.
2. Report duplicate, overflow, stale, and restoration failures.
3. Reconcile local and scheduler wait state during wake, exit, and restore.


### Known issues/TODOS in Missed wakeup exploitation resistance

Issue: The condition can change after scheduler preparation but before block registration, and commit failure is not returned to IPC.

Required fixes:

1. Make prepared wait registration visible before releasing channel state.
2. Return typed commit, cancellation, and wake-before-block outcomes.
3. Model-check multiprocessor send, receive, close, exit, and overflow interleavings.


### Known issues/TODOS in IPC syscall pointer abuse resistance

Issue: Numeric address checks permit unmapped, inaccessible, misaligned, overflowing, partially mapped, and concurrently unmapped ranges to reach unsafe memory operations.

Required fixes:

1. Use architecture-aware fault-contained user-copy primitives.
2. Validate checked ranges and permissions against the active process mappings.
3. Add deterministic partial-page, race, alignment, and overflow fault tests.


### Known issues/TODOS in Malformed capability ABI resistance

Issue: `SysIpcCapability` is unversioned, ticketless, native-endian, alignment-sensitive, and exposes raw authority metadata.

Required fixes:

1. Replace raw envelopes with a versioned ID-based transfer ABI.
2. Include size, version, feature, capacity, and explicit byte-order fields where needed.
3. Reject unknown, truncated, oversized, misaligned, and contradictory records before use.


### Known issues/TODOS in Oversized message attack resistance

Issue: Syscalls accept and copy up to 4096 bytes before the 512-byte IPC message limit rejects the operation.

Required fixes:

1. Enforce `MAX_MESSAGE_SIZE` before allocation or user copy.
2. Use fallible bounded staging storage.
3. Test exact limit, one over, maximum syscall length, and repeated rejection load.


### Known issues/TODOS in Too-many-capabilities attack resistance

Issue: Count rejection exists, but malformed internal counts, duplicate attachments, partial reservation, and rollback failures are not handled as one transaction.

Required fixes:

1. Keep attachment storage and count private in a bounded collection.
2. Validate and reserve the complete attachment set before message mutation.
3. Test duplicate IDs, tickets, overflow arithmetic, partial failure, and rollback failure.


### Known issues/TODOS in Partial receive truncation safety

Issue: Receive can silently truncate payloads and dequeue before all payload, capability, and count outputs succeed.

Required fixes:

1. Add explicit payload and capability capacities with required-size reporting.
2. Preflight every writable destination before dequeue and capability import.
3. Commit dequeue only after transactional logical copy-out succeeds.


### Known issues/TODOS in Backpressure timing-channel resistance

Issue: Latency, blocking, wake behavior, error classes, audit, persistence, and rollback reveal queue and lifecycle state without a documented disclosure policy.

Required fixes:

1. Define observable detail for unauthorized and authorized callers.
2. Normalize unauthorized lookup results and timing where practical.
3. Add differential tests across nonexistent, inaccessible, empty, pressured, draining, and sealed channels.


### Known issues/TODOS in Channel exhaustion denial-of-service resistance

Issue: Global channel, capability, ticket, and wait-table limits can be monopolized by one permitted process.

Required fixes:

1. Add per-principal quotas and reserved capacity for critical services.
2. Reclaim resources transactionally on close, exit, timeout, and failed transfer.
3. Return distinct capacity errors and test simultaneous exhaustion of every bounded registry.


### Known issues/TODOS in Fixed-array bounds safety

Issue: Fixed payload, capability, and waiter arrays are bounded, but public length fields can exceed storage or disagree with occupied entries.

Required fixes:

1. Make array storage and logical lengths private.
2. Use bounded constructors and iterators that cannot represent invalid prefixes.
3. Test zero, exact capacity, one over capacity, sparse occupancy, and corrupted metadata.


### Known issues/TODOS in Payload copy bounds safety

Issue: Normal copies are length-limited, but malformed public payload length can panic and syscall copies can fault on inaccessible user ranges.

Required fixes:

1. Centralize payload validation and copying behind one bounded interface.
2. Use fault-contained user-copy primitives with checked mapped ranges.
3. Report required receive size instead of silently truncating after dequeue.


### Known issues/TODOS in Capability array bounds safety

Issue: Public capability storage and count can diverge, and multi-capability validation and rollback are not atomic.

Required fixes:

1. Replace the public array and count with a private bounded collection.
2. Reject holes, duplicates, conflicting tickets, and excessive counts before mutation.
3. Reserve, attach, and roll back the full set as one transaction.


### Known issues/TODOS in Ring buffer indexing safety

Issue: VecDeque prevents manual index errors, but capacity enforcement remains procedural and retired storage is not scrubbed.

Required fixes:

1. Keep all insertion paths behind the checked ring interface.
2. Assert the depth bound after every mutation and restoration.
3. Zeroize removed and cleared message storage where required by policy.


### Known issues/TODOS in Native-size to 32-bit conversion safety

Issue: Bounded IPC counts fit in 32 bits, but native syscall arguments, pointers, and channel values are narrowed without checked conversion.

Required fixes:

1. Preserve native-width syscall arguments on 64-bit architectures.
2. Use checked conversions for every value entering a 32-bit field.
3. Test zero, maximum fitting, one over maximum, and high-bit-only values.


### Known issues/TODOS in Native-size to 16-bit conversion safety

Issue: Current configured limits fit in 16 bits, but serialization uses unchecked casts and sequence values silently wrap.

Required fixes:

1. Add compile-time assertions that every serialized bound fits its field.
2. Use checked conversion during encoding and reject invalid restored values.
3. Define explicit exhaustion or generation behavior for 16-bit sequences.


### Known issues/TODOS in Split and recombined 64-bit field correctness

Issue: Low and high halves reconstruct current fields correctly by inspection, but boundary vectors are absent and transfer ticket identity is omitted.

Required fixes:

1. Use shared encode and decode helpers for every split field.
2. Preserve transfer tickets or keep transfer envelopes entirely kernel-internal.
3. Add byte-level vectors for zero, maximum, high-only, low-only, and mixed values.


### Known issues/TODOS in Temporal payload parsing bounds

Issue: Temporal parsers check frame extents but lack exhaustive malformed-input coverage and strict reserved-field validation.

Required fixes:

1. Require canonical header, flag, and reserved-field values for each version.
2. Test every truncated header length and contradictory declared length.
3. Add a retained fuzz corpus for request and response parsing.


### Known issues/TODOS in Snapshot restore bounds safety

Issue: Restore validates many fields but can change pending transfer state before the complete snapshot has succeeded.

Required fixes:

1. Parse and validate into unpublished temporary state.
2. Authenticate snapshots and reject trailing, contradictory, or generation-stale data.
3. Commit channel and transfer state atomically after complete validation.


### Known issues/TODOS in Output buffer bounds safety

Issue: Copy lengths are bounded, but user destinations are not safely validated and receive commits before all outputs succeed.

Required fixes:

1. Validate every writable output range against current process mappings.
2. Preflight payload, capability, and count destinations before dequeue.
3. Make copy-out and destination capability installation one logical transaction.


### Known issues/TODOS in Unused payload zeroing

Issue: Constructors zero unused payload bytes, but public mutation and retained queue allocation do not preserve erasure after message removal.

Required fixes:

1. Make payload mutation private and preserve a zero-tail invariant.
2. Scrub messages before dequeue, clear, destruction, and allocation release.
3. Inspect retired storage in dedicated allocator-backed tests.


### Known issues/TODOS in Uninitialized memory exposure prevention

Issue: Safe construction initializes fields, but stale initialized storage and partial unsafe copy-out can still disclose data.

Required fixes:

1. Zeroize retired payload and capability storage.
2. Prevent output publication until every destination write can complete.
3. Add tests for partial faults, reused allocations, and inactive array tails.


### Known issues/TODOS in Channel reference lifetime safety

Issue: Rust borrows are lock-scoped, but numeric endpoints and manager grants can logically outlive channel deletion and later target reused IDs.

Required fixes:

1. Add a nonrepeating activation generation to channel references.
2. Revoke grants and settle tickets atomically with deletion.
3. Test deletion, recreation, restoration, and stale endpoint use.


### Known issues/TODOS in Wait queue PID lifetime safety

Issue: Local wait entries use generation-free numeric PIDs and are not completely removed during process cleanup.

Required fixes:

1. Store process-generation wait tokens instead of bare PIDs.
2. Purge local and scheduler wait state during exit and cancellation.
3. Reject duplicate, stale, excessive, and unauthenticated restored waiters.


### Known issues/TODOS in Panic-free IPC parsing

Issue: Checked readers cover normal untrusted byte parsing, but malformed internal metadata and untested parser combinations can still reach panicking slices or assumptions.

Required fixes:

1. Make invalid message lengths and capability counts unrepresentable.
2. Remove unchecked parsing assumptions and return typed errors consistently.
3. Fuzz temporal frames, snapshots, capability records, and conversion boundaries.


### Known issues/TODOS in Syscall register ABI consistency

Issue: Architecture adapters use different register and return conventions while narrowing all common arguments to 32 bits and discarding the sixth x86-64 argument.

Required fixes:

1. Publish one versioned logical ABI with target-specific register bindings.
2. Preserve native-width arguments before typed validation.
3. Test register ingress and result egress through each real entry stub.


### Known issues/TODOS in System call argument structure layout

Issue: The six-field 32-bit structure cannot represent 64-bit pointers and lacks compile-time layout assertions.

Required fixes:

1. Use native-width architecture entry structures feeding a typed internal request.
2. Assert size, alignment, and field offsets at compile time.
3. Generate matching userspace declarations from the canonical definition.


### Known issues/TODOS in System call result structure layout

Issue: The result is limited to a signed 32-bit value and architecture adapters encode it differently.

Required fixes:

1. Define a versioned native-width result convention.
2. Document signedness, error placement, and overflow behavior.
3. Add boundary tests for minimum, maximum, error, and packed returns.


### Known issues/TODOS in System call IPC capability structure layout

Issue: The capability structure is private, unversioned, ticketless, native-endian, and assumed by user memory operations.

Required fixes:

1. Replace raw authority fields with a public versioned ID-based ABI.
2. Include size, version, features, capacity, and required ticket semantics.
3. Generate bindings and byte-level golden layout tests.


### Known issues/TODOS in 32-bit userspace compatibility

Issue: The current ABI fits 32-bit userspace but has no explicit compatibility version or complete conformance suite.

Required fixes:

1. Publish the 32-bit pointer, scalar, register, and return contract.
2. Freeze or version every public structure and syscall number.
3. Run a real 32-bit userspace IPC workflow under QEMU.


### Known issues/TODOS in 64-bit kernel object identity transport

Issue: Selected fields preserve 64 bits, but pointers and results truncate and transfer tickets disappear.

Required fixes:

1. Preserve all native-width pointers and scalar identifiers.
2. Carry complete transfer identity or keep envelopes kernel-internal.
3. Test high-only and mixed-bit object, token, time, ticket, and pointer values.


### Known issues/TODOS in x86 syscall path conformance

Issue: The x86 path matches the common width but lacks generated frame-layout checks and end-to-end IPC ABI testing.

Required fixes:

1. Assert Rust and assembly saved-register offsets.
2. Test interrupt and SYSENTER paths with identical workloads.
3. Verify packed result and fault behavior from ring-three code.


### Known issues/TODOS in x86-64 syscall path conformance

Issue: Native registers are narrowed to 32 bits, the sixth argument is discarded, and assembly entry correctness is not proved.

Required fixes:

1. Preserve 64-bit arguments and pointers through dispatch.
2. Define whether six arguments are supported and handle them consistently.
3. Run high-address IPC and return-value tests through SYSCALL and interrupt entry.


### Known issues/TODOS in AArch64 syscall path conformance

Issue: AArch64 arguments are narrowed to 32 bits and no complete userspace IPC workload exercises the exception entry.

Required fixes:

1. Preserve X-register width through typed dispatch.
2. Publish X8, X0 through X5, X0, and X1 semantics.
3. Run full positive and negative IPC workflows through SVC in QEMU.


### Known issues/TODOS in Syscall endian contract

Issue: Temporal formats are explicitly little-endian while syscall memory structures rely on native byte order.

Required fixes:

1. Declare the syscall ABI little-endian or define explicit conversion.
2. Use byte-level encoding for public memory structures where portability is required.
3. Add host-independent golden vectors.


### Known issues/TODOS in Syscall alignment contract

Issue: Typed capability array reads assume 4-byte user alignment without validating it.

Required fixes:

1. Validate alignment before typed access or decode from bytes.
2. Define alignment requirements in the public ABI.
3. Test aligned and every misaligned pointer offset.


### Known issues/TODOS in Syscall structure padding contract

Issue: Current layouts are expected to contain no padding, but this is not asserted or shared with userspace.

Required fixes:

1. Assert structure size, alignment, and offsets during compilation.
2. Generate public headers or bindings from one definition.
3. Compare byte layouts on every supported target.


### Known issues/TODOS in Stable syscall number policy

Issue: The sparse dispatcher, contiguous invariant check, and internal high syscall number describe conflicting validity rules.

Required fixes:

1. Validate the original number against the explicit mapping.
2. Publish reserved, internal, deprecated, and stable ranges.
3. Exhaustively test defined numbers, holes, aliases, and boundaries.


### Known issues/TODOS in Syscall documentation synchronization

Issue: Syscall definitions, assembly comments, kernel documentation, SDK declarations, and tests can drift independently.

Required fixes:

1. Generate documentation and bindings from the canonical syscall schema.
2. Check generated artifacts in continuous integration.
3. Require ABI version updates for incompatible changes.


### Known issues/TODOS in Userspace IPC ABI test harness

Issue: Existing tests mostly call kernel dispatch or IPC internals and cannot detect real register, structure, pointer, or entry-stub defects.

Required fixes:

1. Build a minimal userspace conformance binary for all IPC syscalls.
2. Exercise success, malformed pointers, boundaries, capabilities, closure, and errors.
3. Run the same workload on i686, x86-64, and AArch64 QEMU targets.


### Known issues/TODOS in Process-owned channel cleanup

Issue: Process termination removes creator-owned channels but does not settle every IPC resource owned or used by the process.

Required fixes:

1. Track channels, endpoints, waits, messages, and transfers by process generation.
2. Define cleanup for creator, sender, receiver, administrator, and delegate roles.
3. Test termination during every channel and transfer state.


### Known issues/TODOS in Process channel purge behavior

Issue: Purge deletes channels directly and reports only a count, without close, wake, revocation, transfer rollback, zeroization, or persistence.

Required fixes:

1. Return a typed per-channel cleanup result.
2. Perform coordinated close, peer wake, capability revocation, and ticket settlement.
3. Record durable deletion and explicit data-loss evidence.


### Known issues/TODOS in Blocked sender exit cleanup

Issue: Scheduler wait state is removed, but stale sender PIDs remain in channel-local queues until a later wake.

Required fixes:

1. Remove local sender wait tokens during process teardown.
2. Store process generations and reject duplicate or stale wait entries.
3. Test exit before preparation, before commit, while blocked, and during wake.


### Known issues/TODOS in Blocked receiver exit cleanup

Issue: Local receiver entries survive process exit and blocked peers receive no typed cancellation or closure result.

Required fixes:

1. Remove local receiver wait tokens synchronously on exit.
2. Define cancellation, close, revocation, and creator-exit wake reasons.
3. Test receiver exit and PID reuse across local and scheduler wait registries.


### Known issues/TODOS in Creator death with queued messages

Issue: Creator cleanup discards queued messages and attachments without the normal draining lifecycle or explicit loss accounting.

Required fixes:

1. Define whether channels survive, drain, abort, or transfer administration after creator exit.
2. Settle every queued capability ticket before destruction.
3. Wake peers and audit each discarded message and authority object.


### Known issues/TODOS in Sender death with queued messages

Issue: Queued payloads survive safely, but source identity, revocation, causal attribution, and pending attachment ownership are not generation-aware.

Required fixes:

1. Bind message source to an immutable principal generation.
2. Define whether sender exit cancels or preserves queued operations.
3. Settle pending source tickets without requiring the destroyed capability table.


### Known issues/TODOS in Receiver death with queued capabilities

Issue: Capability envelopes are not destination-bound and have no policy for receiver death or replacement.

Required fixes:

1. Bind each transfer ticket to an intended receiver principal generation.
2. Roll back, retarget, or cancel transfers when that receiver exits.
3. Prevent another receiver from importing authority without explicit delegation.


### Known issues/TODOS in PID reuse after queued messages

Issue: Queued messages, waiters, endpoint owners, creators, and transfer participants use generation-free numeric PIDs.

Required fixes:

1. Introduce a stable principal identity containing PID and generation.
2. Persist and validate that identity across messages, waits, endpoints, and tickets.
3. Test rapid exit and PID reuse with all stale IPC record types.


### Known issues/TODOS in Orphaned channel prevention

Issue: Normal creator cleanup removes channels, but abnormal cleanup, restore, direct table mutation, and undefined survival policy can leave or incorrectly destroy channel state.

Required fixes:

1. Give every channel an explicit administrator and survival policy.
2. Reconcile live process state before publishing restored channels.
3. Add a registry sweep for channels with invalid owners or generations.


### Known issues/TODOS in Orphaned capability prevention

Issue: Exiting-process tables are revoked, but delegated grants and global pending transfers can outlive deleted channels and source tasks.

Required fixes:

1. Index grants and tickets by channel and source generation.
2. Revoke or settle every dependent object during channel or process deletion.
3. Audit and sweep grants whose target object no longer exists.


### Known issues/TODOS in Temporal restoration of dead process channels

Issue: Replay can recreate channels, waiters, messages, and pending transfers for dead numeric PIDs without generation validation.

Required fixes:

1. Restore only through an authenticated lifecycle authority.
2. Require live or explicitly restorable principal generations.
3. Reject, quarantine, or remap dead-owner state before publication.


### Known issues/TODOS in Scheduler and IPC cleanup integration

Issue: Scheduler, IPC, capability, security, wait, and temporal cleanup are sequential operations with ignored failures rather than one recoverable transaction.

Required fixes:

1. Define and enforce cleanup ordering and lock hierarchy.
2. Propagate typed outcomes and retry or quarantine partial cleanup.
3. Add integration tests for normal exit, fault exit, forced termination, and subsystem failure.


### Known issues/TODOS in Service registry IPC integration

Issue: The registry returns numeric channel IDs through direct method calls and trusts copyable introducer and requester values without central capability resolution.

Required fixes:

1. Resolve introducer authority and requester identity from authenticated execution context.
2. Transfer a generation-bound endpoint capability instead of returning a bare channel number.
3. Track connection release, provider exit, channel replacement, and stale registrations.


### Known issues/TODOS in Filesystem IPC integration

Issue: Filesystem notifications retain generation-free channel IDs and suppress several delivery failures without a stable subscriber outcome.

Required fixes:

1. Store authenticated endpoint capabilities bound to channel and process generations.
2. Define retry, drop, overflow, acknowledgement, and subscriber-removal outcomes.
3. Test closure, revocation, backpressure, malformed acknowledgements, and process exit.


### Known issues/TODOS in Compositor IPC integration

Issue: The compositor accepts a reply channel number from message data and synthesizes kernel send authority for it.

Required fixes:

1. Require a transferred, verified, destination-bound reply endpoint capability.
2. Return or audit structured decode, dispatch, and reply-delivery failures.
3. Route every external compositor operation through the authenticated wire boundary.


### Known issues/TODOS in Fetch service IPC integration

Issue: Fetch defines typed protocol values but has no implemented service channel, registration, wire codec, message pump, or authenticated caller binding.

Required fixes:

1. Define a fixed-width versioned fetch wire format with bounded lengths.
2. Bind session creation to the message source rather than a supplied PID.
3. Add channel registration, request dispatch, event delivery, cancellation, and end-to-end tests.


### Known issues/TODOS in WASM runtime IPC integration

Issue: WASM channel calls reconstruct raw authority, collapse receive failures into empty results, truncate output, and import attachments after dequeue.

Required fixes:

1. Resolve authenticated endpoint handles through the capability manager for every operation.
2. Return typed empty, closed, revoked, truncated, and protocol outcomes to the SDK.
3. Validate and install attached capabilities transactionally before committing receive.


### Known issues/TODOS in Service pointer IPC integration

Issue: Service pointers are synchronous runtime calls but are presented alongside IPC without equivalent isolation, cancellation, backpressure, or causal semantics.

Required fixes:

1. Specify service pointers as a distinct invocation contract and threat boundary.
2. Define cancellation, target failure, reentrancy, busy, timeout, and process-exit behavior.
3. Correlate invocation, capability use, result, revocation, and temporal records.


### Known issues/TODOS in Typed service argument encoding

Issue: TypedServiceArg is disconnected from live protocols and its array type tags can collide after sixteen-bit length truncation.

Required fixes:

1. Define a collision-free type registry and maximum encodable array length.
2. Add a bounded envelope containing type, length, version, and argument count.
3. Connect the codec to one supported service protocol or remove it from the active contract.


### Known issues/TODOS in Typed service argument decoding

Issue: Typed decoding handles isolated primitives but has no untrusted tag dispatcher, aggregate budget, compatibility policy, or authorization integration.

Required fixes:

1. Reject unknown, duplicate, incompatible, and excessive argument descriptions.
2. Enforce total bytes, argument count, nesting, and allocation limits before decoding.
3. Return structured codec errors and test every malformed field and boundary.


### Known issues/TODOS in Service request and response framing

Issue: Each service invents different framing or uses no wire format, preventing shared routing, cancellation, compatibility, and diagnostics.

Required fixes:

1. Define a minimal common envelope for service, version, operation, request identity, payload bounds, and reply authority.
2. Keep service-specific bodies behind bounded codecs with explicit byte order.
3. Test request and response correlation, duplicate delivery, cancellation, and incompatible versions.


### Known issues/TODOS in Service confused-deputy prevention

Issue: Several service paths trust supplied PIDs, channel numbers, or direct kernel callers instead of deriving identity and authority at the operation boundary.

Required fixes:

1. Bind every request to the authenticated message source and process generation.
2. Require explicit delegated authority for reply channels and on-behalf-of operations.
3. Add substitution tests for requester, provider, session, channel, object, and destination identities.


### Known issues/TODOS in Service-level authorization consistency

Issue: Registry, filesystem, compositor, fetch, and service pointers use incompatible authority models with uneven revocation and generation checks.

Required fixes:

1. Define one service authorization contract over principal, endpoint, object, operation, and rights.
2. Adapt service-local capabilities to centrally revocable, generation-bound grants.
3. Run a shared denial and state-preservation test suite against every service.


### Known issues/TODOS in Service protocol versioning

Issue: Version fields exist in selected components but there is no system-wide compatibility negotiation or retirement policy.

Required fixes:

1. Publish supported version ranges and required feature bits for every service.
2. Make registry introduction and service handshake reject incompatible peers explicitly.
3. Add golden vectors and compatibility tests for current, older, newer, and malformed versions.


### Known issues/TODOS in Service protocol fuzzing

Issue: No stateful harness exercises complete service traffic from introduction through parsing, authorization, dispatch, reply, and cleanup.

Required fixes:

1. Build per-service byte-level fuzz targets and one cross-service state-machine harness.
2. Inject capability, lifecycle, queue, allocation, and copy failures at every stage.
3. Retain minimized corpora by protocol version, service, and security property.


### Known issues/TODOS in Malformed service argument handling

Issue: Parser strictness and failure behavior vary by service, and malformed requests can be silently dropped, truncated, or represented by static strings.

Required fixes:

1. Define common malformed, unsupported, unauthorized, and internal failure classes.
2. Guarantee failed decoding has no service, queue, capability, or reply side effects.
3. Audit malformed traffic and test truncation, trailing data, invalid text, length mismatch, and unknown operations.


### Known issues/TODOS in Cross-service causal auditing

Issue: IPC identities, temporal records, registry events, fetch audits, and service-pointer logs do not preserve one authenticated operation chain.

Required fixes:

1. Carry a kernel-issued correlation identity and predecessor through requests, replies, notifications, and direct service calls.
2. Bind correlation records to principal, service, endpoint, object generation, and terminal result.
3. Test multi-service flows, retries, cancellation, replay, dropped replies, and missing-parent retention.
