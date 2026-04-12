# Oreulius — Wasm ABI (Host Interface)

**Status:** Implemented / Frozen (Apr 10, 2026)

Oreulius is Wasm-native: applications run as WebAssembly modules. Unlike typical "Wasm on generic OS" approaches, Oreulius compiles Wasm modules directly to x86 kernel-mode code (Ring 0) or user-mode code (Ring 3) via an **In-Kernel JIT**.

This document defines the ABI that allows Wasm modules to interact with the kernel.

---

## 1. Execution Model

### 1.1 In-Kernel JIT
- **Compiler**: The kernel includes a streaming JIT compiler.
- **Input**: Standard WebAssembly (`.wasm`) binary.
- **Output**: Native x86 machine code.
- **Safety**: The JIT enforces memory safety boundaries (sandbox) during compilation by inserting bounds checks.

### 1.2 Performance
- **Zero-Cost Abstractions**: Internal kernel functions are called directly (via `CALL` instructions), not interpreted.
- **Throughput**: Near-native execution speed for compute-dense tasks.

---

## 2. Module Contract

### 2.1 Imports
Modules import kernel functionality from the `oreulius` namespace.

```wat
(import "oreulius" "channel_send" (func $send (param i32 i32 i32) (result i32)))
```

### 2.2 Exports
A module **must** export an entry point:
- `_start` or `oreulius_main`: The function called by the supervisor after instantiation.

### 2.3 Syscall Loader Profile (Frozen)
For `WasmLoad`/`WasmCall` syscall execution, the kernel now enforces strict binary-module validation:
- Requires standard WASM header/version (`\0asm`, `0x01`).
- Requires canonical section ordering.
- Parses and binds function signatures from `type` + `import` + `function` + `code` sections.
- Enforces immutable function signatures at call time (no dynamic arity mutation).
- Rejects malformed section bounds, invalid LEB encodings, and local overflows.
- Supports host import dispatch by namespace/name (`oreulius` imports map to kernel host functions).
- Supports one-time safe `start` execution at instantiation.
- Supports `table` + `element`, `global`, and `data` section initialization semantics in the current runtime profile.
- Supports structured control-flow execution (`block`, `loop`, `if`, `else`, `br`, `br_if`, `select`) with runtime label resolution.
- Enforces typed block signatures at runtime, including blocktype type-index forms with multi-value signatures.
- Enforces label typing at branch targets (`br`/`br_if`): loop labels consume block parameters, block/if labels consume declared results.
- Enforces typed frame exits for `else` and `end`, including implicit-`else` `if` paths.
- Enforces function exit stack shaping: only declared function results survive call return.
- Supports `i32`/`i64`/`f32`/`f64` value types in signatures and interpreter arithmetic coverage for core add/sub/mul/div paths.
- Supports reference-types profile semantics with type plumbing (`funcref`/`externref`) and MVP opcodes (`ref.null`, `ref.is_null`, `ref.func`).
- Supports exception-handling profile semantics with tags + typed payloads (`try`, `catch`, `catch_all`, `throw`, `rethrow`, `delegate`) and structured unwind.
- Includes proposal-level binary conformance corpus coverage for typed control-flow, reference-types MVP, and exception-handling paths, plus negative parser fuzzing.

This means `WasmLoad` now admits only modules compatible with the hardened interpreter profile and rejects malformed binaries early.

---

## 3. Capability Representation

Security is handled via integer handles (indices into the process's capability table).
- **Type**: `i32` (Wasm integer).
- **Validity**: Verified by the kernel on every syscall. Passing an invalid or unauthorized handle results in an error (or termination).

---

## 4. Syscall Interface (ABI)

The following host functions are available to Wasm modules:

### 4.1 Process & Threading
- `oreulius_thread_spawn(func_idx: i32, arg: i32) -> tid`: Spawn a cooperative WASM thread.
- `oreulius_thread_join(tid: i32) -> i32`: Join a cooperative WASM thread.
- `oreulius_thread_id() -> i32`: Return the current cooperative WASM thread ID.
- `oreulius_thread_yield()`: Yield the current CPU quantum.
- `oreulius_thread_exit(code: i32)`: Exit the current cooperative WASM thread.
- `proc_yield()`: Voluntarily yield the CPU.
- `proc_sleep(ticks: i32)`: Sleep for N PIT ticks (roughly milliseconds).
- `proc_spawn(bytes_ptr: i32, bytes_len: i32) -> pid`: Spawn a child WASM process from bytecode already in linear memory.

Notes:
- The import resolver accepts both the plain names above and `oreulius_*` aliases, for example
  `thread_spawn` and `oreulius_thread_spawn`.
- Cooperative WASM threads run inside one WasmInstance and share its linear memory; they make
  progress through the runtime's background thread runner plus explicit yield points.
- When a foreground `wasm <path>` command returns normally from `_start`, the shell gives that
  instance a bounded cooperative-thread drain window before teardown and reports if threads are
  still stalled or over budget.

### 4.2 IPC (Inter-Process Communication)
- `ipc_create() -> handle`: Create a new channel.
- `ipc_send(handle: i32, data_ptr: i32, len: i32) -> status`: blocking send.
- `ipc_recv(handle: i32, buf_ptr: i32) -> len`: blocking receive.
- `channel_send_cap(chan_cap: i32, msg_ptr: i32, msg_len: i32, cap_handle: i32) -> i32`:
  send a message and optionally attach one transferable capability.
  - pass `cap_handle = -1` (`u32::MAX`) for no attachment.
- `last_service_cap() -> i32`: returns the most recently imported service-pointer cap handle
  from `channel_recv`/`ipc_recv` processing (`-1` if none).

### 4.3 Filesystem
- `fs_open(path_ptr: i32, path_len: i32, flags: i32) -> fd`
- `fs_read(fd: i32, buf_ptr: i32, max_len: i32) -> len`
- `fs_write(fd: i32, data_ptr: i32, len: i32) -> len`
- `fs_close(fd: i32)`

### 4.4 Debugging / Console
- `debug_log(ptr: i32, len: i32)`: Write to kernel debug log.
- `console_write(ptr: i32, len: i32)`: Write to serial/vga (if capability held).

### 4.5 Service Pointer Capabilities
- `service_register(func: i32|funcref, delegate: i32) -> i32`:
  register a directly callable capability and return a cap handle.
  - `func` may be a legacy numeric function index (`i32`) or a direct `ref.func` value (`funcref`).
  - `delegate != 0` grants transfer right.
- `service_invoke(cap_handle: i32, args_ptr: i32, args_count: i32) -> i32`:
  legacy invoke path (`i32` arguments only, `i32` or empty result).
- `service_invoke_typed(cap_handle: i32, args_ptr: i32, args_count: i32, results_ptr: i32, results_capacity: i32) -> i32`:
  typed invoke path. Arguments and results are encoded as fixed 9-byte slots in linear memory:
  - byte 0: kind (`0=i32,1=i64,2=f32,3=f64,4=funcref,5=externref`)
  - bytes 1..8: payload (`little-endian`; null refs use all-ones payload).
  - return value is the number of result slots written.

Notes:
- Service-pointer capabilities are typed kernel capabilities (`ServicePointer`), not raw pointers.
- Invocation is authorized by capability rights (`SERVICE_INVOKE`) and per-pointer rate policy.
- Runtime enforces full registered function signatures (arity + value types) on every service-pointer call.
- Transfer authorization is enforced by `SERVICE_DELEGATE`.
- On instance teardown, service pointers attempt hot-swap rebinding to compatible live replacement instances; unmatched pointers are revoked.
- Formal technical deep dive: `docs/services/oreulius-service-pointer-capabilities.md`.

### 4.6 Polyglot Kernel Services (IDs 103–105)

Oreulius allows WASM modules written in **any** language to be registered as
named kernel services and to call each other securely via capability handoffs,
even across language boundaries. The exact-export link surface remains at
IDs `103–105`; durable lineage, status, pagination, revoke/rebind, and event
feed control are documented in the polyglot lineage ABI range below
(`132–142`).

#### `oreulius_lang` Custom Section

To declare its source language, a WASM module embeds a custom section named
`oreulius_lang`.  The binary layout (after the standard LEB128 name length +
name bytes) is:

```
Offset  Size  Field
──────  ────  ──────────────────────────────────────────────────
  0       1   Language tag (u8)
  1       1   Version: major
  2       1   Version: minor
  3       1   Version: patch
  4       1   Reserved (must be 0)
```

**Language tag values:**

| Tag  | Language           |
|------|--------------------|
| 0x00 | Unknown / unset    |
| 0x01 | Rust               |
| 0x02 | Zig                |
| 0x03 | C / C++            |
| 0x04 | Python (Pyodide)   |
| 0x05 | JavaScript (QuickJS) |
| 0x06 | AssemblyScript     |
| 0xFF | Other              |

#### Syscalls

- `polyglot_register(name_ptr: i32, name_len: i32) -> i32`  
  Register this module as a named polyglot kernel service.  
  `name` must be ≤ 32 bytes of UTF-8.  
  The kernel records the `oreulius_lang` language tag alongside the name.  
  **Singleton languages** (Python `0x04`, JavaScript `0x05`): if a service
  with the same name and language already exists, the instance/owner reference
  is refreshed instead of returning an error.  
  Returns `0` on success, or a negative error code.

- `polyglot_resolve(name_ptr: i32, name_len: i32) -> i32`  
  Look up a registered polyglot service by name.  
  Returns `instance_id` (≥ 0) on success, `-2` if not found.

- `polyglot_link(name_ptr: i32, name_len: i32, export_ptr: i32, export_len: i32) -> i32`  
  Obtain a cross-language `ServicePointer` capability handle for a specific
  export on a registered service.  Pass the returned handle to
  `service_invoke` / `service_invoke_typed`. The requested export must resolve
  against the target module's export table and a matching registered service
  pointer.
  Returns capability handle (≥ 0) on success, or a negative error code.

**Error codes:**

| Code | Meaning |
|------|---------|
|   0  | Success (`polyglot_register`) |
|  ≥ 0 | Instance ID (`polyglot_resolve`) or capability handle (`polyglot_link`) |
|  -1  | Bad arguments (null pointer, zero length, name > 32 bytes) |
|  -2  | Registry full (`polyglot_register`) or name not found (`polyglot_resolve` / `polyglot_link`) |
|  -3  | Name taken by a non-singleton module (`polyglot_register`) or the requested export is missing or not service-registered (`polyglot_link`) |
|  -4  | Capability table full (`polyglot_link`) |

**Capability type**: Links created by `polyglot_link` carry a `CrossLanguage`
(`CapabilityType = 15`) capability with `SERVICE_INVOKE` rights.  The
`label_hash` field stores the target module's language tag, enabling
language-aware policy enforcement.

**Registry limits**: Up to 16 polyglot service entries.  Slot 0 is reserved
for the Python singleton, slot 1 for the JavaScript singleton (by convention).

**SDK**: Use `oreulius_sdk::polyglot` for idiomatic Rust wrappers:
```rust
// Service side
oreulius_sdk::polyglot::register("py_math").unwrap();

// Client side
let cap = oreulius_sdk::polyglot::link("py_math", "add").unwrap();
```

#### Polyglot lineage query ABI

The kernel also exposes a durable lineage query surface:

- `polyglot_lineage_count() -> i32`
- `polyglot_lineage_query(buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_query_filtered(buf_ptr: i32, buf_len: i32, filter_kind: i32, filter_a: i32, filter_b: i32) -> i32`
- `polyglot_lineage_lookup(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_lookup_object(object_lo: i32, object_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_revoke(cap_handle: i32) -> i32`
- `polyglot_lineage_rebind(cap_handle: i32, target_instance: i32) -> i32`
- `polyglot_lineage_status(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_status_object(object_lo: i32, object_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_query_page(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32`
- `polyglot_lineage_event_query(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32`

These host functions are implemented at IDs `132` through `142`.

`polyglot_lineage_count` returns the number of lineage records currently retained by the kernel. `polyglot_lineage_query` writes a packed snapshot into caller memory:

This keeps the audit trail easy to read while the live handle stays separate.

```
Offset  Size  Field
──────  ────  ───────────────────────────────────────────────
  0       1   Wire version (`u8`, currently 1)
  1       1   Record count (`u8`)
  2       2   Max records (`u16`, currently 64)
  4       4   Next record id (`u32`, low 32 bits)
  8     96*n  Packed lineage records
```

Each 96-byte record is encoded as:

```
Offset  Size  Field
──────  ────  ───────────────────────────────────────────────
  0       1   Live flag (`u8`, 1 = live handle at query time)
  1       1   Lifecycle state (`u8`)
  2       2   Reserved
  4       8   Record id (`u64`)
 12       4   Source pid (`u32`)
 16       4   Source instance (`u32`)
 20       4   Target instance (`u32`)
 24       8   Object id (`u64`)
 32       4   Capability id (`u32`)
 36       1   Language tag (`u8`)
 37       1   Export-name length (`u8`)
 38      32   Export name bytes
 70       4   Rights bitmask (`u32`)
 74       8   Created ticks (`u64`)
 82       8   Updated ticks (`u64`)
 90       6   Reserved
```

The query is intentionally read-only: it exposes durable provenance for audit and replay, but does not grant authority. Terminal records remain queryable after teardown with lifecycle `TornDown`.

`polyglot_lineage_query_filtered` uses a simple selector model:

- `0` = all records
- `1` = match `source_pid` against `filter_a`
- `2` = match `target_instance` against `filter_a`
- `3` = match `lifecycle` against `filter_a`
- `4` = match exact export name; `filter_a` points to the bytes and `filter_b` is the byte length

`polyglot_lineage_lookup` and `polyglot_lineage_lookup_object` return the latest lineage record for a specific live handle or persistent object id, which makes rebind and revocation state inspectable without scanning the whole history.

`polyglot_lineage_revoke` is the explicit terminal transition: it removes the live capability from the caller's table and marks the durable record `Revoked`. `polyglot_lineage_rebind` is the explicit retargeting transition: it verifies a caller-selected replacement instance with the same owner, export name, and signature before moving the handle and marking the durable record `Rebound`.

`polyglot_lineage_status` and `polyglot_lineage_status_object` return a compact summary that carries:

- current lifecycle
- current target instance
- last update tick
- live-authority flag

`polyglot_lineage_query_page` returns a cursor-based page of lineage records with the same 96-byte record shape as the full snapshot query. The `cursor` is a record-id watermark: only records with `record_id > cursor` are returned. This makes audit walks incremental instead of full-table scans.

SDK usage is intentionally shaped as a plain Rust loop:

```rust,no_run
let mut pages = oreulius_sdk::polyglot::lineage_pages(16);
while let Some(page) = pages.next() {
    let page = page.expect("lineage page");
    for record in page.iter() {
        let _ = record.record_id;
    }
}

let mut events = oreulius_sdk::polyglot::lineage_events(16);
while let Some(batch) = events.next() {
    let batch = batch.expect("lineage events");
    for event in batch.iter() {
        let _ = event.event_id;
    }
}
```

`polyglot_lineage_event_query` returns an append-only feed of `Rebound` and `Revoked` transition events. The event stream uses the same header form as lineage snapshots, but each record is a compact transition record instead of a full provenance record. Each event includes both the new lifecycle and the previous lifecycle so callers can diff the transition directly.

### 4.7 Temporal Objects ABI
- `temporal_snapshot(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32`:
  captures a snapshot for `path` and writes latest version metadata.
- `temporal_latest(cap: i32, path_ptr: i32, path_len: i32, out_meta_ptr: i32) -> i32`:
  returns metadata for the latest version of `path`.
- `temporal_read(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, buf_ptr: i32, buf_len: i32) -> i32`:
  reads a specific version payload into `buf_ptr`; returns copied byte count.
- `temporal_rollback(cap: i32, path_ptr: i32, path_len: i32, version_lo: i32, version_hi: i32, out_ptr: i32) -> i32`:
  rolls `path` back to a specific version and emits rollback result.
- `temporal_stats(out_ptr: i32) -> i32`:
  returns global temporal-object counters.
- `temporal_history(cap: i32, path_ptr: i32, path_len: i32, start_from_newest: i32, max_entries: i32, out_ptr: i32, out_capacity: i32) -> i32`:
  exports a newest-first history window. Returns the number of records written.

All functions return `0` for control-plane success or `-1` on failure, except `temporal_read`, which returns `>=0` copied bytes or `-1`.

Capability policy:
- `temporal_snapshot`, `temporal_latest`, `temporal_read` require a valid filesystem capability with `READ`.
- `temporal_rollback` requires a valid filesystem capability with `WRITE`.
- Scoped filesystem capabilities enforce prefix checks on temporal paths as well.

Capture policy (current kernel profile):
- Temporal `write` versions are emitted for memory-backed file mutations through both path and FD APIs:
  `vfs::write_path`, `vfs::write_fd`, and `open(..., TRUNC)`.
- This keeps ABI-visible history (`temporal_history`) aligned with ordinary shell/process write paths.

`u64` version IDs are passed as `(version_lo, version_hi)` little-endian words.

`out_meta_ptr` layout (32 bytes, little-endian `u32` words):
1. `version_lo`
2. `version_hi`
3. `branch_id`
4. `data_len`
5. `leaf_count`
6. `content_hash`
7. `merkle_root`
8. `operation` (`1=snapshot,2=write,3=rollback`)

`out_ptr` for `temporal_rollback` layout (16 bytes):
1. `new_version_lo`
2. `new_version_hi`
3. `branch_id`
4. `restored_len`

`out_ptr` for `temporal_stats` layout (20 bytes):
1. `objects`
2. `versions`
3. `bytes_lo`
4. `bytes_hi`
5. `active_branches`

`out_ptr` for `temporal_history` record layout (64 bytes each, little-endian):
1. `version_lo`
2. `version_hi`
3. `parent_lo` (`0xFFFF_FFFF` if none)
4. `parent_hi`
5. `rollback_from_lo` (`0xFFFF_FFFF` if none)
6. `rollback_from_hi`
7. `branch_id`
8. `data_len`
9. `leaf_count`
10. `content_hash`
11. `merkle_root`
12. `operation`
13. `tick_lo`
14. `tick_hi`
15. `flags` bit0=`has_parent`, bit1=`has_rollback_from`
16. `record_format_version` (`1`)

---

### 4.7 TLS 1.3 (Host IDs 91–99)

Oreulius provides a bounded in-kernel TLS 1.3 client stack accessible from WASM modules. All
functions return `i32`; negative values indicate failure. Sessions are identified by an opaque
`i32` handle allocated by the kernel.

| Host ID | Function signature | Description |
|---------|--------------------|-------------|
| 91 | `tls_connect(host_ptr: i32, host_len: i32, server_ip: i32, port: i32) -> i32` | Allocate a new TLS session to `server_ip:port` for SNI host `host_ptr[0..host_len]`. Returns the session handle (≥ 0) or `-1` on failure. `server_ip` is a big-endian packed `u32` (e.g. `0xC0A80001` for `192.168.0.1`). |
| 92 | `tls_write(handle: i32, buf_ptr: i32, buf_len: i32) -> i32` | Send `buf_len` bytes of application data. Returns bytes queued (≥ 0) or `-1`. |
| 93 | `tls_read(handle: i32, buf_ptr: i32, buf_len: i32) -> i32` | Receive up to `buf_len` decrypted bytes into the module's linear memory. Returns bytes read (≥ 0). |
| 94 | `tls_close(handle: i32) -> i32` | Send a TLS `close_notify` alert and release the session. Returns `0`. |
| 95 | `tls_state(handle: i32) -> i32` | Return the current `HandshakeState` enum value. `Connected = 2`; other values indicate in-progress or error states. |
| 96 | `tls_error(handle: i32, buf_ptr: i32, buf_len: i32) -> i32` | Copy a human-readable error string into `buf_ptr[0..buf_len]`. Returns the number of bytes written. |
| 97 | `tls_handshake_done(handle: i32) -> i32` | Returns `1` if the TLS handshake has completed (`HandshakeState::Connected`), `0` otherwise. |
| 98 | `tls_tick(handle: i32) -> i32` | Drive the TLS state machine forward (process incoming records, advance handshake). Returns `0`. Should be called in a polling loop until `tls_handshake_done` returns `1`. |
| 99 | `tls_free(handle: i32) -> i32` | Unconditionally free a session handle without sending `close_notify`. Returns `0`. Use `tls_close` for graceful teardown. |

#### Typical usage pattern

```wat
;; Connect
(local.set $h (call $tls_connect (i32.const host_ptr) (i32.const 8) (i32.const 0xC0A80001) (i32.const 443)))
;; Drive handshake
(block $done
  (loop $poll
    (br_if $done (i32.eq (call $tls_handshake_done (local.get $h)) (i32.const 1)))
    (drop (call $tls_tick (local.get $h)))
    (br $poll)))
;; Send/receive application data
(drop (call $tls_write (local.get $h) (i32.const data_ptr) (i32.const data_len)))
(local.set $n (call $tls_read (local.get $h) (i32.const buf_ptr) (i32.const buf_len)))
;; Graceful close
(drop (call $tls_close (local.get $h)))
```

#### Notes

- The in-kernel TLS stack currently implements a bounded TLS 1.3 client handshake/profile.
  It does not perform full certificate-chain validation in the current kernel profile; host
  identity is supplied by the `host_ptr` SNI string for session binding and diagnostics.
- `tls_tick` must be called from the module's event loop; the kernel does not drive sessions
  autonomously between WASM host calls.
- Session handles are scoped to the WASM instance. They are freed automatically when the
  instance is destroyed (equivalent to calling `tls_free` on each live handle).
- `tls_connect` calls `tls_tick` once internally after session allocation to begin the
  handshake; subsequent ticks are the caller's responsibility.

---

### 4.8 Extended Runtime Services (Host IDs 106–142)

The production runtime also exposes additional host ranges beyond the core
process/TLS/polyglot surface documented above.

| Host IDs | Category | Frozen surface |
|----------|----------|-----------------|
| 106–108 | Kernel observer | `observer_subscribe`, `observer_unsubscribe`, `observer_query` |
| 109–115 | Decentralized kernel mesh | `mesh_local_id`, `mesh_peer_register`, `mesh_peer_session`, `mesh_token_mint`, `mesh_token_send`, `mesh_token_recv`, `mesh_migrate` |
| 116–120 | Temporal capabilities / checkpoints | `temporal_cap_grant`, `temporal_cap_revoke`, `temporal_cap_check`, `temporal_checkpoint_create`, `temporal_checkpoint_rollback` |
| 121–124 | Policy contracts | `policy_bind`, `policy_unbind`, `policy_eval`, `policy_query` |
| 125–128 | Capability entanglement | `cap_entangle`, `cap_entangle_group`, `cap_disentangle`, `cap_entangle_query` |
| 129–131 | Capability graph verification | `cap_graph_query`, `cap_graph_verify`, `cap_graph_depth` |
| 132–142 | Polyglot lineage query and transition control | `polyglot_lineage_count`, `polyglot_lineage_query`, `polyglot_lineage_query_filtered`, `polyglot_lineage_lookup`, `polyglot_lineage_lookup_object`, `polyglot_lineage_revoke`, `polyglot_lineage_rebind`, `polyglot_lineage_status`, `polyglot_lineage_status_object`, `polyglot_lineage_query_page`, `polyglot_lineage_event_query` |

These ranges are implemented in the frozen WASM host dispatcher in
[kernel/src/execution/wasm.rs](/Users/keefereeves/Desktop/OreuliusKernel/TheActualKernelProject/oreulius/kernel/src/execution/wasm.rs). This document mirrors the frozen table for host IDs, names, arity, aliases, and result shapes. Any future per-service ABI docs must be generated from the same source of truth.

### 4.9 ABI family modes

Different ABI families are intentionally shaped around different primary access patterns:

| Family | Primary mode | Notes |
|--------|--------------|-------|
| Temporal | status-first | `cap_check`, checkpointing, and rollback expose live state and replay state. |
| Policy | status-first | `query` / `status` describe the current binding; `eval` is the enforcement path. |
| Capability entanglement | query-first | `cap_entangle_query` describes the current peer set; revocation is the control path. |
| Capability graph | query-and-verify | `cap_graph_query`, `cap_graph_verify`, and `cap_graph_depth` focus on audit and prospective safety. |
| Observer | event-first | `observer_query` drains a stream of delivered kernel events. |
| Polyglot lineage | snapshot/status/event | `query`, `query_page`, `status`, `event_query`, revoke, and rebind expose audit, terminal state, and transition history. |

### 4.10 Polyglot invariants

The polyglot subsystem is specified by a small set of invariants:

1. `authority(c, t) ⇒ lineage(c, t)`: every live cross-language capability must have a corresponding lineage record.
2. `lineage(c, t) ⇏ authority(c, t)`: a lineage record alone never grants authority.
3. `rights_out ≤ rights_in`: cross-language link creation must not widen rights.
4. `teardown(c) ⇒ lifecycle(c) = TornDown`: teardown removes live authority and preserves a terminal record for audit.
5. `restore(G) = G`: snapshot/restore must preserve the lineage graph modulo explicitly revoked or torn-down edges.

For implementers, the kernel treats these as runtime checks rather than purely documentary claims.

---

## 5. Memory Model

- **Linear Memory**: Wasm defines a single linear memory space.
- **Pointers**: All pointers passed to syscalls are offsets into this linear memory.
- **Validation**: The kernel validates that `[ptr, ptr + len)` is strictly within the module's memory bounds before reading/writing.
### 5.3 `yield`

- `yield() -> void`

### 5.4 `abort`

- `abort(code: i32) -> noreturn`

---

## 6. Error codes

Use stable negative error codes:

- `-1`: `InvalidCap`
- `-2`: `PermissionDenied`
- `-3`: `WouldBlock`
- `-4`: `MessageTooLarge`
- `-5`: `TooManyCaps`
- `-6`: `BufferTooSmall`

---

## 7. Console, clock, store access

Oreulius avoids dedicated syscalls like `write(fd, ...)`.

Instead:

- console is a service reachable through a channel
- clock is a service reachable through a channel
- store is a service reachable through a channel

A module interacts by sending typed messages to those services.

This keeps the ABI small and pushes policy/protocol to user space.

---

## 8. Capability injection

At instantiation, the loader provides the module with a set of initial capabilities.

Current capability bootstrap mechanisms:

1. **Pre-filled table**: loader places caps into indices 0..N.
2. **Init message**: module starts with one channel cap; loader sends an init message containing other caps.

Preferred production path:

- **Init message** (explicit, replayable, and scalable).

For service-pointer capabilities, runtime injection is also available:
- shell: `svcptr-inject <instance_id> <cap_id>`
- kernel host path: `inject_service_pointer_capability(...)`

---

## 9. Determinism considerations

- No direct access to wall-clock.
- No direct access to entropy.
- Any external input arrives through message channels and can be recorded/replayed.

---

## 10. Future extensions

- shared memory capabilities
- stronger typed IPC schemas
- optional WASI layer as a compatibility personality
