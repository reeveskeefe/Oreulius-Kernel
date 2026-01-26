# Oreulia — Wasm ABI v0 (Host Interface)

**Status:** Draft (Jan 24, 2026)

Oreulia is Wasm-native: applications run as WebAssembly modules and interact with the system through a small, capability-oriented host interface.

This document defines ABI v0.

---

## 1. Goals

- Small, explicit syscall surface.
- No ambient authority: modules can only use injected capabilities.
- IPC-first: messaging is the primary interaction mechanism.
- Determinism-friendly: time/randomness/I/O are capability mediated.

Non-goals (v0):

- POSIX emulation
- full WASI compatibility (may be layered later)

---

## 2. Module contract

### 2.1 Imports

An Oreulia module imports functions from a single host namespace, e.g.:

- `oreulia.*`

### 2.2 Exports

A minimal convention:

- module exports `oreulia_main()`

Optionally accept an initial channel capability as the entrypoint argument later; v0 can rely on pre-injected capabilities placed in a table.

---

## 3. Capability representation inside Wasm

Wasm code cannot hold kernel pointers; it holds integer handles.

- `cap` is a `u32` (index into module’s imported capability table)

The runtime maps Wasm `cap` values to task `cap_id` values.

---

## 4. Memory model

### 4.1 Linear memory

- Module uses Wasm linear memory.
- Host calls read/write from that memory.

### 4.2 Buffers

All byte data passed to/from the host uses `(ptr, len)` pairs.

---

## 5. Host calls (v0)

### 5.1 `channel_send`

Send bytes and capabilities to a channel.

Signature (conceptual):

- `channel_send(chan_cap: u32, data_ptr: u32, data_len: u32, caps_ptr: u32, caps_len: u32) -> i32`

Where `caps_ptr` points to an array of `u32` capability handles.

Returns:

- `0` on success
- negative error code on failure

### 5.2 `channel_recv`

Receive bytes and capabilities from a channel.

Signature (conceptual):

- `channel_recv(chan_cap: u32, out_data_ptr: u32, out_data_cap: u32, out_caps_ptr: u32, out_caps_cap: u32) -> i32`

Semantics:

- writes up to `out_data_cap` bytes
- writes up to `out_caps_cap` capability handles
- returns a packed result or uses additional out-params (implementation choice)

v0 recommendation:

- use a small result struct written to memory (lengths + status)

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
