# Oreulia — Wasm ABI v0 (Host Interface)

**Status:** Implemented / JIT-Native (Feb 8, 2026)

Oreulia is Wasm-native: applications run as WebAssembly modules. Unlike typical "Wasm on generic OS" approaches, Oreulia compiles Wasm modules directly to x86 kernel-mode code (Ring 0) or user-mode code (Ring 3) via an **In-Kernel JIT**.

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
Modules import kernel functionality from the `oreulia` namespace.

```wat
(import "oreulia" "channel_send" (func $send (param i32 i32 i32) (result i32)))
```

### 2.2 Exports
A module **must** export an entry point:
- `_start` or `oreulia_main`: The function called by the supervisor after instantiation.

### 2.3 Syscall Loader Profile (Current)
For `WasmLoad`/`WasmCall` syscall execution, the kernel now enforces strict binary-module validation:
- Requires standard WASM header/version (`\0asm`, `0x01`).
- Requires canonical section ordering.
- Parses and binds function signatures from `type` + `import` + `function` + `code` sections.
- Enforces immutable function signatures at call time (no dynamic arity mutation).
- Rejects malformed section bounds, invalid LEB encodings, and local overflows.
- Supports host import dispatch by namespace/name (`oreulia` imports map to kernel host functions).
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
- `proc_yield()`: Voluntarily yield the CPU.
- `proc_sleep(ms: i32)`: Sleep for N milliseconds.
- `proc_spawn(name_ptr: i32, len: i32) -> pid`: Capabilities-gated process creation.

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
- Formal technical deep dive: `docs/oreulia-service-pointer-capabilities.md`.

### 4.6 Temporal Objects ABI
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

## 5. Memory Model

- **Linear Memory**: Wasm defines a single linear memory space.
- **Pointers**: All pointers passed to syscalls are offsets into this linear memory.
- **Validation**: The kernel validates that `[ptr, ptr + len)` is strictly within the module's memory bounds before reading/writing.
### 5.3 `yield`

- `yield() -> void`

### 5.4 `abort`

- `abort(code: i32) -> noreturn`

---

## 6. Error codes (v0)

Use stable negative error codes:

- `-1`: `InvalidCap`
- `-2`: `PermissionDenied`
- `-3`: `WouldBlock`
- `-4`: `MessageTooLarge`
- `-5`: `TooManyCaps`
- `-6`: `BufferTooSmall`

---

## 7. Console, clock, store access

Oreulia avoids dedicated syscalls like `write(fd, ...)`.

Instead:

- console is a service reachable through a channel
- clock is a service reachable through a channel
- store is a service reachable through a channel

A module interacts by sending typed messages to those services.

This keeps the ABI small and pushes policy/protocol to user space.

---

## 8. Capability injection

At instantiation, the loader provides the module with a set of initial capabilities.

Mechanisms (choose one for v0):

1. **Pre-filled table**: loader places caps into indices 0..N.
2. **Init message**: module starts with one channel cap; loader sends an init message containing other caps.

v0 recommendation:

- **Init message** (more explicit and scalable).

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
