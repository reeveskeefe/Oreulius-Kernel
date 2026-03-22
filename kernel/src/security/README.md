# `kernel/src/security` — Kernel Security Infrastructure

The `security` module is the **unified security layer of the Oreulia kernel**. It owns every concern that spans hardware enforcement, runtime behaviour analysis, capability lifecycle governance, process isolation, hardware enclave management, and on-device proof verification. No other module may make trust decisions unilaterally — all access denials, violation reports, anomaly scores, and isolation judgements are routed through this module.

---

## Design Philosophy

Oreulia's security model is built on four non-negotiable principles:

1. **No ambient authority.** Every security decision is grounded in a capability token. There are no global names, no implicit filesystem access, no privilege escalation by default.
2. **Observable and auditable.** Every security-relevant event — capability use, denial, rate limit hit, integrity failure, anomaly crossing a threshold — is written to the `AuditLog` ring buffer and exposed to the persistence system. Nothing happens silently.
3. **Predictive as well as reactive.** The `IntentGraph` watches per-process behavioural sequences, builds a continuous-time Markov chain (CTMC) probability vector, and applies restrictions *before* a process commits a serious violation — not just after.
4. **Formally backstopped.** Core security predicates (capability attenuation subset law, JIT memory guard equivalence) are machine-checked at boot and in CI by `formal.rs` using exhaustive bounded-domain exploration.

---

## Source Layout

| File | Architecture | Lines | Role |
|---|---|---|---|
| `mod.rs` | All | 1604 | Audit log, anomaly detection, capability validator, rate limiter, resource quotas, crypto primitives, `SecurityManager` umbrella |
| `intent_graph.rs` | All | 1365 | CTMC-based per-process intent analysis, adaptive restrictions, predictive isolations |
| `enclave.rs` | x86-64 | 3575 | Intel SGX and ARM TrustZone enclave lifecycle, EPC pool, temporal secret redaction, remote attestation |
| `memory_isolation.rs` | x86-64 | 534 | Memory domain tagging, `IsolationDomain` classification, JIT/WASM/enclave region policies |
| `kpti.rs` | x86-64 | 377 | Kernel Page Table Isolation — dual CR3 management, ISR trampoline stubs, IDT remapping |
| `crash_log.rs` | x86-64 | 509 | Panic ring buffer, `CrashClass` categorisation, crash persistence and boot-session tracking |
| `formal.rs` | x86-64 | 121 | Mechanized in-kernel proof obligations for capability and JIT predicates |
| `cpu_security.rs` | x86-64 | 97 | SMEP/SMAP CPU hardening, `with_user_access` STAC/CLAC guard |

`intent_graph.rs` compiles on all architectures. All other non-`mod.rs` files are `#[cfg(not(target_arch = "aarch64"))]`.

---

## `mod.rs` — The SecurityManager

`SecurityManager` is the single global struct that aggregates all runtime security state. It is accessed via `security::security()` which returns a `&'static SecurityManager` guarded by a `spin::Mutex` internally per component.

### Security Constants

| Constant | Value | Meaning |
|---|---|---|
| `MAX_AUDIT_ENTRIES` | `1024` | Ring buffer depth for `AuditLog` |
| `MAX_VIOLATIONS_PER_PROCESS` | `10` | Violations before `should_terminate()` returns true |
| `RATE_LIMIT_OPS_PER_SEC` | `1000` | Token bucket refill rate per process |
| `MAX_CAPABILITY_LIFETIME_MS` | `0` | `0` = unlimited; non-zero enables expiry enforcement |
| `PERSISTENCE_SEAL_KEY_BYTES` | `32` | Byte length of the at-rest snapshot sealing key |
| `ANOMALY_WINDOW_SECONDS` | `10` | Sliding window for anomaly score accumulation |
| `ANOMALY_ALERT_SCORE` | `64` | Score threshold that fires an anomaly alert |
| `ANOMALY_CRITICAL_SCORE` | `160` | Score threshold that marks a critical anomaly |

### `SecurityEvent` Enum

All 19 security event types that flow through the audit log and anomaly detector:

| Variant | Description |
|---|---|
| `CapabilityCreated` | A new capability token was minted |
| `CapabilityTransferred` | A capability was transferred between processes |
| `CapabilityUsed` | A capability was exercised on a resource |
| `CapabilityRevoked` | A capability was explicitly revoked |
| `PermissionDenied` | A rights check failed — scored ×2 in anomaly score |
| `QuotaExceeded` | A resource quota was breached — scored ×2 |
| `RateLimitExceeded` | Token bucket exhausted — scored ×1 |
| `InvalidCapability` | A structurally invalid or tampered token was presented — scored ×4 |
| `IntegrityCheckFailed` | A hash/HMAC verification failed — scored ×16 |
| `AnomalyDetected` | The anomaly detector crossed a threshold |
| `SyscallObserved` | A syscall boundary crossing was observed |
| `ProcessSpawned` | A process was created |
| `ProcessTerminated` | A process exited or was killed |
| `TemporalOperation` | A temporal version operation was observed |
| `ClosureDraining` | An IPC channel entered closure drain state |
| `ClosureSealed` | An IPC channel was fully sealed post-closure |
| `RestrictionApplied` | The intent graph applied a predictive restriction |
| `RestrictionLifted` | A predictive restriction expired or was cleared |
| `CapDelegationChain` | A capability delegation chain was recorded for provenance |

The anomaly scoring weights are not ad hoc — `IntegrityCheckFailed` is weighted 16× because a failed integrity check means active tampering, not benign misconfiguration. `InvalidCapability` is 4× because it indicates an attempt to forge or replay tokens.

### `AuditLog`

A statically allocated circular ring buffer of `1024` entries.

| Method | Description |
|---|---|
| `log(entry)` | Append an `AuditEntry`; wraps when full |
| `recent(limit)` | Iterate the most recent N events in insertion order |
| `count_events(event_type)` | Count all stored entries of a given type |
| `total_count()` | Total events logged (capped at ring capacity) |

Each `AuditEntry` records: `SecurityEvent`, `ProcessId`, `cap_id: u32`, `timestamp: u64`, and optional `context: u64` (arbitrary payload encoded by the caller, e.g. the target capability rights mask).

### `AnomalyDetector`

A **sliding-window time-bucketed anomaly scorer** built from `ANOMALY_BUCKETS = 32` per-second slot structs.

Each bucket tracks five counters mapped from `SecurityEvent` variants: `denied`, `quota`, `rate`, `invalid`, `integrity`. On every relevant event, the bucket for the current second is updated. The score is recomputed over the active `ANOMALY_WINDOW_SECONDS = 10` seconds using the weighted sum:

```
score = (denied × 2) + (quota × 2) + rate + (invalid × 4) + (integrity × 16)
```

When the score crosses `ANOMALY_ALERT_SCORE` a `Some(score)` is returned from `record()` and the kernel logs `SecurityEvent::AnomalyDetected`. When the score crosses `ANOMALY_CRITICAL_SCORE` the `critical_total` counter increments and the system escalates to the intent graph for process restriction.

| Method | Description |
|---|---|
| `record(event, now_ticks)` | Feed an event; returns `Some(score)` if threshold crossed |
| `snapshot(now_ticks)` | Return `AnomalyStats` with per-category window counts |

### `CapabilityValidator`

Per-process violation counter with a fixed-size table of 64 `(ProcessId, violation_count)` pairs.

| Method | Description |
|---|---|
| `validate_rights(proc, required, actual)` | Check `(actual & required) == required`; increments violation count on failure |
| `get_violations(proc)` | Return the violation count for a process |
| `clear_process(proc)` | Remove all violation state on process exit |
| `should_terminate(proc)` | True if violations ≥ `MAX_VIOLATIONS_PER_PROCESS` |
| `is_expired(cap_id, created_at)` | Check capability expiry (future: timestamp + lifetime) |

### `RateLimiter`

Token-bucket rate limiter with one bucket per process (up to 64 concurrent processes tracked).

- Tokens are refilled proportionally to elapsed PIT ticks at `RATE_LIMIT_OPS_PER_SEC` per second.
- New processes start with a full bucket.
- `allow(process)` returns `false` and triggers `SecurityEvent::RateLimitExceeded` when the bucket is empty.

### `ResourceTracker` and `ResourceQuota`

Tracks per-process resource consumption by `ResourceType`:

| `ResourceType` | Description |
|---|---|
| `Memory` | Bytes of memory allocated |
| `FileHandles` | Open file descriptors |
| `Channels` | Open IPC channels |
| `NetworkConnections` | Active TCP/UDP connections |
| `WasmInstances` | Running WASM modules |

`ResourceQuota` defines per-type limits. `ResourceTracker::check_and_update(proc, resource_type, amount)` returns `Err(SecurityError::QuotaExceeded)` and fires a `QuotaExceeded` event when the sum would exceed the quota.

### Cryptographic Primitives

| Function / Type | Description |
|---|---|
| `SecureRandom` | RDTSC-seeded SipHash-2-4 based PRNG (`next_u64()`, `next_bytes()`) |
| `hash_data(data: &[u8]) -> u64` | SipHash-2-4 over arbitrary data using a static kernel seed |
| `verify_integrity(data, expected_hash)` | Returns `true` if `hash_data(data) == expected_hash` |
| `persistence_seal_key()` | Returns the 32-byte at-rest sealing key for snapshot encryption |
| `set_persistence_seal_key(key)` | Override the default dev key (should be called from attested provisioning on production) |

The internal SipHash-2-4 implementation (`siphash24`, `sip_round`, `rotl64`) is fully `#[no_std]`, has no allocation, and operates on a `&[u8]` slice with a 128-bit (two u64) key.

The default sealing key (`oreulia-persist-seal-key-v1 #Eg`) is a development sentinel. Production deployments must override it with a key derived from hardware attestation or a TPM-sealed provisioning flow.

### `SecurityError`

| Variant | Description |
|---|---|
| `InsufficientRights` | Rights bitmask check failed |
| `CapabilityExpired` | Capability lifetime exceeded |
| `QuotaExceeded` | Resource quota breached |
| `RateLimitExceeded` | Token bucket empty |
| `IntegrityCheckFailed` | Hash/HMAC mismatch |
| `InvalidCapability` | Structural token validation failed |

---

## `intent_graph.rs` — CTMC-Backed Behavioural Intent Analysis

This is the **predictive security layer**. Rather than waiting for a process to trip a hard violation, the intent graph watches every capability probe, IPC send, filesystem access, WASM call, and syscall, builds a sequence of `IntentNode` transitions, and maintains a per-process probability state vector using a discrete approximation of a continuous-time Markov chain (CTMC). When the probability mass concentrates in high-risk states, restrictions are applied *before* damage occurs.

### `IntentNode` — Observation Graph Vertices

| Node | Value | Triggers |
|---|---|---|
| `CapabilityProbe` | 0 | Process checked whether it holds a capability |
| `CapabilityDenied` | 1 | Capability check returned denied |
| `InvalidCapability` | 2 | A structurally invalid token was presented |
| `IpcSend` | 3 | An IPC channel write was issued |
| `IpcRecv` | 4 | An IPC channel read was issued |
| `WasmCall` | 5 | A WASM host function was dispatched |
| `FsRead` | 6 | A filesystem read was performed |
| `FsWrite` | 7 | A filesystem write was performed |
| `Syscall` | 8 | A syscall boundary was observed |

### `IntentDecision`

Every call to `IntentGraph::observe(pid, signal)` returns one of:

| Variant | Meaning |
|---|---|
| `Allow` | No policy concern — continue |
| `Alert(score)` | Anomaly threshold crossed — log, but do not restrict |
| `Restrict(score)` | Behaviour matches a high-risk pattern — apply `AdaptiveRestriction` |

### `IntentPolicy` and `PolicyTensor`

`IntentPolicy` encodes the operator-configurable thresholds:

| Field | Default | Meaning |
|---|---|---|
| `alert_score` | `INTENT_ALERT_SCORE = 84` | Score at which an alert fires |
| `restrict_score` | `INTENT_RESTRICT_SCORE = 136` | Score at which restriction fires |
| `isolate_restrictions` | `3` | Restriction count that triggers full isolation |
| `terminate_restrictions` | `6` | Restriction count that triggers termination recommendation |
| `restrict_base_seconds` | `2` | Minimum restriction window |
| `restrict_max_seconds` | `12` | Maximum restriction window |
| `isolation_extension_seconds` | `20` | Extra seconds added per escalation step |
| `severity_step_score` | `16` | Score increment per escalation step |

`PolicyTensor<N>` is a fixed-size array of `N` policy weights used in the CTMC transition scoring.

### `IntentProcessState` — Per-Process CTMC

Every tracked process has an `IntentProcessState` slot:

- **Event counters per window**: `denied_events`, `invalid_events`, `ipc_events`, `wasm_events`, `syscall_events`, `fs_read_events`, `fs_write_events`, `object_novel_events`
- **Node transition matrix**: `node_counts[9]` and `transition_counts[...]` track which transitions have been observed
- **Object bloom filter**: `object_bloom[INTENT_OBJECT_BLOOM_WORDS]` — a hash-addressed bloom filter over `object_hint` values to detect novel (unseen) accesses
- **CTMC state vector**: `ctmc_state_vec[9]` — fixed-point (×1024 scale) probability mass over the 9 intent nodes
- **Restriction state**: `window_restrictions`, `restriction_until_tick`, `restricted_cap_types`, `restricted_rights`, `terminate_recommended`

The CTMC vector is updated on every observation using a discrete-time approximation of the continuous-time generator matrix. The score is computed as a dot product of the state vector with per-node risk weights.

### `AdaptiveRestriction`

When `IntentDecision::Restrict` is returned, an `AdaptiveRestriction` record is written for the offending process. This record specifies:

- Which `cap_types` are restricted (a bitmask over `CapabilityType`)
- Which `rights` bits are blocked within those types
- Until which PIT tick the restriction is active
- How many total restrictions have been applied to this process

Up to `ADAPTIVE_RESTRICTION_MAX_QUARANTINE = 32` concurrent restrictions are tracked.

Restrictions are periodically expired by the scheduler or manually lifted via `clear_restriction(pid)`. When a process accumulates `INTENT_TERMINATE_RESTRICTIONS = 6` restrictions without clearing, `terminate_recommended` is set and the kernel security manager is notified to terminate the process.

### Intent Tuning Constants

| Constant | Value | Meaning |
|---|---|---|
| `INTENT_WINDOW_SECONDS` | `8` | Observation window width |
| `INTENT_ALERT_SCORE` | `84` | Score for alert |
| `INTENT_RESTRICT_SCORE` | `136` | Score for restriction |
| `INTENT_ISOLATE_RESTRICTIONS` | `3` | Restrictions before isolation |
| `INTENT_TERMINATE_RESTRICTIONS` | `6` | Restrictions before termination recommendation |
| `INTENT_RESTRICT_BASE_SECONDS` | `2` | Base restriction duration |
| `INTENT_RESTRICT_MAX_SECONDS` | `12` | Maximum restriction duration |
| `INTENT_ISOLATION_EXTENSION_SECONDS` | `20` | Duration added per escalation step |
| `INTENT_SEVERITY_STEP_SCORE` | `16` | Score increment per escalation |
| `INTENT_ALERT_COOLDOWN_MS` | `1000` | Minimum gap between alert fires |
| `INTENT_RESTRICT_COOLDOWN_MS` | `500` | Minimum gap between restriction fires |

---

## `enclave.rs` — Hardware Enclave Lifecycle Manager

Provides a unified, architecture-agnostic enclave API over:

- **Intel SGX (x86-64)**: ECREATE → EADD → EEXTEND → EINIT → EENTER/EEXIT sequence
- **ARM TrustZone**: SMC (Secure Monitor Call)-based TEE contracts
- **Emulated / None**: detects unsupported hardware and degrades gracefully

### `EnclaveBackend`

| Variant | Value | Description |
|---|---|---|
| `None` | `0` | No hardware TEE available |
| `IntelSgx` | `1` | Intel Software Guard Extensions |
| `ArmTrustZone` | `2` | ARM TrustZone TEE |

### Session Model

| Constant | Value | Meaning |
|---|---|---|
| `MAX_ENCLAVE_SESSIONS` | `16` | Concurrent enclave sessions |
| `MAX_ATTESTATION_CERTS` | `8` | Stored attestation certificates |
| `MAX_PROVISIONED_KEYS` | `32` | Provisioned cryptographic keys |
| `MAX_REMOTE_VERIFIERS` | `8` | Registered remote verifier endpoints |
| `EPC_POOL_PAGES` | `256` | Pages in the Enclave Page Cache pool |
| `PAGE_SIZE` | `4096` | EPC page size in bytes |

### `EnclaveStatus`

| Field | Description |
|---|---|
| `enabled` | Whether the enclave manager is active |
| `backend` | Detected hardware backend |
| `active_session` | Currently executing session ID |
| `open_sessions` | Count of open (non-empty) sessions |
| `created_total` | Total sessions created lifetime |
| `failed_total` | Total session creation failures |
| `backend_ops_total` | Total low-level backend operations (EENTER, SMC, etc.) |
| `epc_total_pages` | Total EPC pool capacity |
| `epc_used_pages` | Currently allocated EPC pages |
| `attestation_reports` | Total attestation reports generated |
| `trustzone_contract_ready` | Whether the TrustZone contract is initialised |

### Session Lifecycle

| Function | Description |
|---|---|
| `init()` | Detect backend, init EPC pool, init TrustZone contract |
| `open_jit_session(...)` | Open a new enclave session, allocate EPC pages, map into memory isolation |
| `enter(session_id)` | Execute EENTER (SGX) or SMC (TrustZone); switches CR3 via `kpti` |
| `exit(session_id)` | Execute EEXIT; restores kernel CR3 |
| `close(session_id)` | Tear down session, EREMOVE all pages, release EPC pool |
| `attest_session(session_id, ...)` | Generate and sign an `EnclaveAttestationReport` |
| `status()` | Return an `EnclaveStatus` snapshot |

### Temporal Secret Redaction

When enclave temporal state is persisted, sensitive payload bytes can be zero-redacted before being written to the persistence log.

| Function | Description |
|---|---|
| `temporal_set_secret_redaction_enabled(bool)` | Enable or disable payload redaction |
| `temporal_secret_redaction_enabled() -> bool` | Query redaction state |
| `temporal_apply_enclave_state_payload(&[u8])` | Apply a temporal enclave state payload from persistence log replay |
| `temporal_active_session_reentry_self_check()` | Verify that re-entry into an active session is safe after temporal state restore |

### Remote Attestation Policy

| `RemoteAttestationPolicy` | Value | Behaviour |
|---|---|---|
| `Disabled` | `0` | No remote attestation |
| `Audit` | `1` | Generate reports but do not gate operations on them |
| `Enforce` | `2` | Gate sensitive operations on successful remote attestation |

### Temporal Schema Versioning

Enclave session state that is checkpointed to the temporal system has its own schema version independent of the kernel temporal schema:

| Version | Bytes | Change |
|---|---|---|
| V1 | 64 | Initial layout |
| V2 | 96 | Added physical memory addresses as u32 fields |
| V3 | 100 | Widened `backend_cookie` from u32 to u64 (SGX TCS is a 64-bit linear address) |

---

## `kpti.rs` — Kernel Page Table Isolation

Implements **Kernel Page Table Isolation** — the mitigation for Meltdown (CVE-2017-5754) and related speculative execution vulnerabilities. When KPTI is active, the kernel and userspace run with completely separate page table roots (`CR3` values). The user-mode CR3 contains only the minimal kernel mappings required to service interrupts.

### Globals

| Symbol | Type | Description |
|---|---|---|
| `KPTI_KERNEL_CR3` | `AtomicU32` | Physical address of the kernel page table root |
| `KPTI_USER_CR3` | `AtomicU32` | Physical address of the user shadow page table root |
| `KPTI_ENABLED` | `AtomicBool` | Runtime KPTI enablement flag |

### Trampoline Stub Architecture

Because the IDT (Interrupt Descriptor Table) must be mapped in the *user* CR3 for hardware-directed entry to work, `kpti.rs` writes 16-byte trampoline stubs (`STUB_STRIDE = 16`) for every IDT entry:

```
mov eax, [&KPTI_KERNEL_CR3]   ; load kernel CR3 value
mov cr3, eax                   ; switch to kernel page tables
jmp <original_handler>         ; jump to the real ISR
nop... (padding to 16 bytes)
```

One stub is generated for each of:
- ISR/exception handlers: `isr0`..`isr31` (32 entries)
- IRQ handlers: `irq0`..`irq15` (16 entries)
- Syscall/sysenter entry: `syscall_entry`, `sysenter_entry`

The trampoline region itself is mapped in both the user and kernel CR3 with execute rights.

### Functions

| Function | Description |
|---|---|
| `init()` | Detect CPU support, write trampolines, remap IDT in user CR3, set `KPTI_ENABLED` |
| `enabled()` | Query whether KPTI is active |
| `enter_user(cr3)` | Write user CR3 to `CR3` register before returning to userspace |
| `leave_user()` | Restore kernel CR3 from `KPTI_KERNEL_CR3` |
| `map_user_support(...)` | Map a kernel address range into the user shadow page table |

---

## `memory_isolation.rs` — Memory Domain Classification

Implements the kernel's memory tagging and access policy engine. Every page range in the kernel's address space can be tagged with an `IsolationDomain` that determines which `AccessPolicy` applies and which hardware isolation features (SGX, MPX, SMEP, SMAP) can enforce it.

### `IsolationDomain`

| Domain | Value | Region |
|---|---|---|
| `Unknown` | 0 | Unclassified / default |
| `KernelText` | 1 | Kernel `.text` — RX, no user mapping |
| `KernelRodata` | 2 | Kernel `.rodata` — RO, no user mapping |
| `KernelData` | 3 | Kernel `.data` — RW, no user mapping |
| `KernelBss` | 4 | Kernel `.bss` — RW, no user mapping |
| `KernelHeap` | 5 | Kernel heap region — RW, no user mapping |
| `JitArena` | 6 | JIT scratch area — RW during codegen, then sealed |
| `JitCode` | 7 | Sealed JIT code — RX after codegen |
| `WasmLinearMemory` | 8 | WASM linear memory — RW, user-mapped, no execute |
| `JitUserTrampoline` | 9 | JIT user-mode trampoline — RX, user-mapped |
| `JitUserState` | 10 | JIT process register save area — RW, user-mapped |
| `JitUserStack` | 11 | JIT userspace stack — RW, user-mapped |
| `DeviceMmio` | 12 | MMIO device registers — RW, no execute, no user |
| `EnclaveCode` | 13 | SGX/TrustZone enclave code pages |
| `EnclaveData` | 14 | SGX/TrustZone enclave data pages |

### `AccessPolicy`

| Constructor | R | W | X | User |
|---|---|---|---|---|
| `kernel_rx()` | ✓ | — | ✓ | — |
| `kernel_ro()` | ✓ | — | — | — |
| `kernel_rw()` | ✓ | ✓ | — | — |
| `user_rx()` | ✓ | — | ✓ | ✓ |
| `user_rw()` | ✓ | ✓ | — | ✓ |

### `HardwareIsolationCaps`

Populated at `init()` by CPUID interrogation:

| Field | Meaning |
|---|---|
| `sgx_supported` | CPUID bit 7.0 SGX present |
| `sgx1_supported` | SGX1 instruction set available |
| `sgx2_supported` | SGX2 (dynamic EPC management) available |
| `sgx_launch_control` | Flexible launch control supported |
| `trustzone_supported` | ARM TrustZone/SMC available |

### Key Functions

| Function | Description |
|---|---|
| `init()` | Probe HW caps, populate `IsolationStatus`, set up tag table |
| `status()` | Return `IsolationStatus` snapshot |
| `tag_range(start, len, domain, policy)` | Classify a page range with a domain and access policy |
| `tag_jit_code_kernel(start, len, sealed_rx)` | Tag kernel JIT code region; `sealed_rx=true` marks it execute-only |
| `tag_jit_code_user(start, len)` | Tag user JIT code region (user_rx) |
| `tag_jit_user_trampoline(start, len)` | Tag user trampoline region |
| `tag_jit_user_state(start, len)` | Tag user register save area |
| `tag_jit_user_stack(start, len)` | Tag user JIT stack region |
| `tag_wasm_linear_memory(start, len)` | Tag WASM linear memory region (user_rw, no-execute) |
| `validate_mapping_request(...)` | Check whether a requested mapping is permitted by current domain policy |

---

## `crash_log.rs` — Panic Ring Buffer

Records kernel panics and unexpected crash events in a statically allocated ring buffer that survives between reboots (provided the memory region is preserved and the `SLOT_MAGIC = 0x43524153` ("CRAS") sentinel is intact).

### Layout Constants

| Constant | Value | Meaning |
|---|---|---|
| `RING_CAP` | `8` | Maximum stored crash slots |
| `MSG_CAP` | `128` | Bytes per crash message / source location string |
| `SLOT_MAGIC` | `0x43524153` | "CRAS" — slot validity sentinel |

### `CrashSlot`

Each slot records:
- `magic: u32` — sentinel to detect valid slots
- `boot_session: u32` — which boot session this crash occurred in
- `crash_id: u32` — monotonic crash counter
- `timestamp: u64` — PIT tick at time of panic
- `msg: [u8; MSG_CAP]` — formatted panic message
- `location: [u8; MSG_CAP]` — source file + line (from `PanicInfo::location`)

### `CrashClass`

`classify_panic(info)` categorises panics into:

| Class | Description |
|---|---|
| `NullDeref` | Message contains "null" or "dereference" |
| `StackOverflow` | Message contains "stack overflow" |
| `OutOfMemory` | Message contains "out of memory" or "allocation failed" |
| `AssertionFailed` | Message contains "assertion" or "panic" |
| `ArithmeticOverflow` | Message contains "overflow" or "divide" |
| `KernelBug` | Message contains "unreachable", "unimplemented", "unwrap" |
| `HardwareFault` | Message contains "fault", "exception", or "trap" |
| `Unknown` | Catch-all for unrecognised messages |

### Public API

| Function | Description |
|---|---|
| `on_boot()` | Check ring for leftover magic signatures, increment `boot_session` |
| `record_panic(info)` | Format `PanicInfo`, classify, write into ring slot |
| `crash_count() -> u32` | Total lifetime crash count |
| `boot_session() -> u32` | Current boot session number |
| `for_each_crash(F)` | Iterate all valid ring slots passing `(index, timestamp, crash_id, msg, location)` |
| `flush_to_persistence()` | Write crash ring contents to the persistence log for durable recovery |

---

## `formal.rs` — In-Kernel Mechanized Proof Obligations

Provides deterministic, bounded-domain proof obligations that run **inside the kernel** at boot and in CI — no external theorem prover required.

### `FormalProofSummary`

| Field | Description |
|---|---|
| `obligations` | Count of distinct proof obligations checked |
| `checked_states` | Total individual state/case combinations verified |

### `run_mechanized_backend_check()`

On success returns `FormalProofSummary { obligations: 2, checked_states: ~4.4M }`.
On failure returns `Err(&'static str)` identifying which obligation and witness was violated.

**Obligation 1 — Capability Attenuation Subset Law**

For all `parent: u32` in `[0, 256)` and all `child: u32` in `[0, 256)`:

- `cap_subset(parent, child)` is true **if and only if** every bit set in `child` is also set in `parent`.
- Violation: a child capability would have rights the parent doesn't hold — the attenuation property is broken.

Total cases checked: 256 × 256 = 65,536.

**Obligation 2 — JIT Memory Guard Model Equivalence**

For all combinations of `addr`, `off`, `size`, and `mem_len` over bounded domains:

- The production guard impl (`jit_guard`) must agree with an independently written specification (`jit_guard_spec`) on every input.
- Both use overflow-safe checked arithmetic. `jit_guard` checks `eff <= mem_len - size`; `jit_guard_spec` checks `eff + size <= mem_len`.
- A mismatch would mean the JIT codegen bounds check diverges from its specification, opening a potential out-of-bounds code write.

Total cases checked: 5 sizes × 129 mem_len × 257 addr × 257 off ≈ 4.3M combinations.

---

## `cpu_security.rs` — x86-64 CPU Hardening

Enables CPU-enforced supervisor-mode protection features that complement the software capability model with hardware enforcement at the MMU/CPU level.

### Features

| Feature | CR4 Bit | Description |
|---|---|---|
| SMEP — Supervisor Mode Execution Prevention | bit 20 | Prevents the kernel from executing code mapped at user-accessible addresses. Blocks code-reuse attacks that craft kernel RIP values pointing at user memory. |
| SMAP — Supervisor Mode Access Prevention | bit 21 | Prevents the kernel from *reading or writing* user memory without an explicit `STAC`/`CLAC` guard. Closes data-exfil and confused-deputy attack vectors. |

### API

| Function | Description |
|---|---|
| `init()` | Read CR4, set SMEP and SMAP bits if CPU reports support, write CR4 |
| `has_smep() -> bool` | Query CPUID for SMEP support |
| `has_smap() -> bool` | Query CPUID for SMAP support |
| `smep_enabled() -> bool` | Query live CR4 SMEP bit |
| `smap_enabled() -> bool` | Query live CR4 SMAP bit |
| `with_user_access<F, R>(f: F) -> R` | Execute `f` with SMAP temporarily disabled (`STAC` before, `CLAC` after), then re-enable. Use this any time the kernel must dereference a user-supplied pointer. |

`with_user_access` is the **only safe way** to touch user pointers while SMAP is enabled. All copy-from-user paths in the syscall layer and WASI ABI are required to use this wrapper.

---

## Security Initialisation Sequence

At kernel boot, the following sequence occurs in `security::init()`:

1. `cpu_security::init()` — Enable SMEP + SMAP
2. `kpti::init()` — Write trampolines, reassemble IDT, activate dual CR3
3. `memory_isolation::init()` — Probe HW caps, initialise tag table
4. `enclave::init()` — Detect SGX/TrustZone, initialise EPC pool
5. `crash_log::on_boot()` — Scan ring for previous panics, increment `boot_session`
6. `SecurityManager` statics initialised — `AuditLog`, `AnomalyDetector`, `CapabilityValidator`, `RateLimiter`, `ResourceTracker` all zero-initialised in-place
7. `formal::run_mechanized_backend_check()` — Run proof obligations; panic on violation

If any obligatory step fails (KPTI init, formal check) the kernel panics before accepting any userspace code.

---

## Shell Commands

The security subsystem is exposed via the kernel shell (`kernel/src/shell/`):

| Command | Description |
|---|---|
| `audit-log` | Print recent `AuditLog` entries |
| `audit-count <event>` | Count events of a given type |
| `anomaly-stats` | Print `AnomalyStats` for the current window |
| `violations <pid>` | Show violation count for a process |
| `intent-snapshot <pid>` | Print `IntentProcessSnapshot` for a process |
| `intent-stats` | Print `IntentGraphStats` |
| `security-status` | Full `SecurityManager` status summary |
| `enclave-status` | Print `EnclaveStatus` |
| `kpti-status` | Print KPTI enabled state and CR3 addresses |
| `isolation-status` | Print `IsolationStatus` + hardware caps |
| `crash-log-show` | Print all crash ring slots |
| `crash-log-clear` | Wipe the crash ring |
| `formal-check` | Run `run_mechanized_backend_check()` live and print result |
