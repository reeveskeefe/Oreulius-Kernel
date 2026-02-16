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
- Includes binary conformance corpus coverage for typed control-flow modules, plus negative parser fuzzing.

Current profile explicitly does **not** yet implement exception-handling/reference-type proposal opcodes end-to-end.

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
- `service_register(func_idx: i32, delegate: i32) -> i32`:
  register an exported function as a directly callable capability and return a cap handle.
  - `delegate != 0` grants transfer right.
- `service_invoke(cap_handle: i32, args_ptr: i32, args_count: i32) -> i32`:
  invoke a service-pointer capability directly (no conventional syscall trampoline).

Notes:
- Service-pointer capabilities are typed kernel capabilities (`ServicePointer`), not raw pointers.
- Invocation is authorized by capability rights (`SERVICE_INVOKE`) and per-pointer rate policy.
- Transfer authorization is enforced by `SERVICE_DELEGATE`.

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
