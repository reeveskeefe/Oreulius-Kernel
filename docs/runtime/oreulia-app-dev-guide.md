# Oreulius Application Developer Guide

This guide covers everything you need to build, run, and debug userland
applications on the Oreulius OS WASM runtime.

---

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Hello World (WAT)](#hello-world-wat)
4. [Hello World (Rust SDK)](#hello-world-rust-sdk)
5. [WASI API Reference](#wasi-api-reference)
6. [Oreulius Native ABI](#oreulius-native-abi)
7. [Process Lifecycle](#process-lifecycle)
8. [IPC Channels](#ipc-channels)
9. [Capability Model](#capability-model)
10. [Sockets and Networking](#sockets-and-networking)
11. [Polling and Async I/O](#polling-and-async-io)
12. [File System](#file-system)
13. [Sample Applications](#sample-applications)
14. [Debugging](#debugging)
15. [ABI Stability](#abi-stability)

---

## Overview

Oreulius executes applications as **WASM modules** inside a capability-secured
sandbox.  Every module runs in its own linear memory space, communicates with
the kernel via typed host functions, and cannot access hardware directly.

Two layers of host functions are available:

| Layer | Import module | IDs | Standard |
|-------|---------------|-----|----------|
| WASI Preview 1 | `wasi_snapshot_preview1` | 45–90 | Yes |
| Oreulius native | `oreulius` or `env` | 0–44, 91–131 | Oreulius-specific |

Any valid WASM binary targeting `wasm32-wasi` runs unmodified.  WASI-SDK,
`wasi-sdk`, Emscripten, and `cargo build --target wasm32-wasi` are all
supported.

---

## Getting Started

### Prerequisites

| Tool | Purpose |
|------|---------|
| `wat2wasm` (WABT) | Compile `.wat` text format to `.wasm` |
| `rustup target add wasm32-wasi` | Build Rust apps |
| `wasm-objdump` (optional) | Inspect WASM binaries |

### Running a WASM binary inside Oreulius

```text
Oreulius OS (x86_64)
> wasm hello.wasm
```

The `wasm` shell command:
1. Reads the `.wasm` binary from the Oreulius VFS.
2. Calls `wasm_runtime().instantiate(bytes, pid)`.
3. Calls the exported `_start` function.

---

## Hello World (WAT)

```wat
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit"
    (func $proc_exit (param i32)))

  (memory (export "memory") 1)
  (data (i32.const 8) "Hello from Oreulius!\n")  ;; 20 bytes

  (func (export "_start")
    ;; iovec: { buf_ptr=8, buf_len=20 } at address 0
    (i32.store (i32.const 0) (i32.const 8))
    (i32.store (i32.const 4) (i32.const 20))
    ;; fd_write(fd=1, iovs=0, iovs_len=1, nwritten=28)
    (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 28))
    drop
    (call $proc_exit (i32.const 0))
  )
)
```

Compile and run:

```bash
wat2wasm hello.wat -o hello.wasm
# Copy hello.wasm into the Oreulius VFS image, then:
# wasm hello.wasm
```

---

## Hello World (Rust SDK)

```rust
#![no_std]
#![no_main]

use oreulius_sdk::{io, process};

#[no_mangle]
pub extern "C" fn _start() {
    unsafe { io::println("Hello from Oreulius SDK!") };
    process::exit(0);
}
```

**Build:**

```bash
cd wasm/sdk
cargo build --target wasm32-wasi --release
# Output: target/wasm32-wasi/release/oreulius_sdk.wasm
```

**`Cargo.toml` for your app:**

```toml
[package]
name = "my-app"
edition = "2021"

[dependencies]
oreulius-sdk = { path = "/path/to/wasm/sdk" }

[profile.release]
opt-level = "z"
lto = true
panic = "abort"
```

---

## WASI API Reference

Full spec: https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md

| ID | Function | Notes |
|----|----------|-------|
| 45 | `args_get` | Command-line arguments |
| 46 | `args_sizes_get` | |
| 47 | `environ_get` | Environment variables |
| 48 | `environ_sizes_get` | |
| 49 | `clock_res_get` | Clock resolution |
| 50 | `clock_time_get` | Monotonic / realtime clock |
| 51–52 | `fd_advise`, `fd_allocate` | No-ops |
| 53 | `fd_close` | Close fd |
| 54 | `fd_datasync` | No-op |
| 55 | `fd_fdstat_get` | fd metadata |
| 61 | `fd_pread` | Positional read |
| 64 | `fd_pwrite` | Positional write |
| 65 | `fd_read` | Read from fd |
| 66 | `fd_readdir` | Directory listing |
| 68 | `fd_seek` | Seek |
| 70 | `fd_tell` | Tell position |
| 71 | `fd_write` | Write to fd |
| 72 | `path_create_directory` | `mkdir` |
| 73 | `path_filestat_get` | `stat` |
| 76 | `path_open` | Open file |
| 78 | `path_remove_directory` | `rmdir` |
| 81 | `path_unlink_file` | `unlink` |
| **82** | **`poll_oneoff`** | Wait for I/O or timeout |
| 83 | `proc_exit` | Terminate process |
| 85 | `sched_yield` | Cooperative yield |
| 86 | `random_get` | RDRAND-seeded PRNG |
| **87** | **`sock_accept`** | Accept inbound connection |
| 88 | `sock_recv` | Receive from socket |
| 89 | `sock_send` | Send via socket |
| 90 | `sock_shutdown` | Close socket direction |

### `poll_oneoff` — blocking I/O wait

Oreulius's `poll_oneoff` honours **clock subscriptions** (relative and absolute
nanosecond timeouts) and **fd_read readiness** for stdin (fd 0) and the
network receive ring.  It yields the current time slice during the wait rather
than busy-spinning.

**Subscription struct (48 bytes):**

```
Offset  Size  Field
     0     8  userdata    (u64, opaque, returned in event)
     8     1  tag         (0=clock, 1=fd_read, 2=fd_write)
     9     7  _padding
    16     4  clock_id    (0=realtime, 1=monotonic)  [tag=0]
    24     8  timeout_ns  (nanoseconds)               [tag=0]
    32     8  precision   (0 = don't care)            [tag=0]
    40     2  flags       (0=relative, 1=absolute)    [tag=0]
    16     4  fd          [tag=1 or 2]
```

**Event struct (32 bytes, written to `out_ptr`):**

```
Offset  Size  Field
     0     8  userdata   (copied from subscription)
     8     2  error      (0 = success)
    10     2  type       (matches subscription tag)
    12    20  fd_readwrite.nbytes / flags / _pad
```

---

## Oreulius Native ABI

Import module name: `"oreulius"` (also accepts `"env"`).

The authoritative per-host ABI reference is:
- [oreulius-wasm-abi.md](./oreulius-wasm-abi.md)

Current native host ranges in the production runtime:

| ID range | Category |
|----------|----------|
| `0–12` | debug log, filesystem, IPC/channel messaging, network, service-pointer invocation/registration |
| `13–22` | temporal object operations and branch/merge APIs |
| `23–27` | cooperative WASM threads |
| `28–44` | compositor and input services |
| `91–99` | TLS client services |
| `100–102` | process lifecycle (`proc_spawn`, `proc_yield`, `proc_sleep`) |
| `103–105` | polyglot kernel service registry/linking |
| `106–108` | kernel observer services |
| `109–115` | decentralized kernel mesh services |
| `116–120` | temporal capability and checkpoint services |
| `121–124` | policy/capability-contract services |
| `125–128` | capability entanglement services |
| `129–131` | capability graph query/verification services |

The loader accepts both `oreulius_*` import names and the shorter plain names,
for example `thread_spawn` as well as `oreulius_thread_spawn`.

### Process management

The current process/thread host surface is:
- `thread_spawn`, `thread_join`, `thread_id`, `thread_yield`, `thread_exit`
- `proc_spawn`, `proc_yield`, `proc_sleep`

`proc_spawn` copies `bytes_len` bytes from linear memory at `bytes_ptr`,
registers a child kernel process, enqueues a new WASM instance, and returns
the child PID. Spawn instantiation is deferred until the current host call
returns so the runtime does not re-enter itself while holding internal locks.

### IPC and service pointers

The current IPC/service host surface is:
- `channel_send`
- `channel_recv`
- `channel_send_cap`
- `last_service_cap`
- `service_register`
- `service_invoke`
- `service_invoke_typed`

Oreulius's current runtime does not expose the old `channel_open` import from
this guide revision; channel creation and capability distribution are mediated
through the kernel/runtime paths described in the ABI reference.

---

## Process Lifecycle

```
  kernel boot
       │
       ▼
  x86_64_init_wasm_task  ← INIT_WASM_BIN (embedded init supervisor)
       │ instantiate + call _start
       │ drain_pending_spawns()
       ▼
  shell (run_serial_shell)
       │  user types: wasm foo.wasm
       │  instantiate + call _start
       │  drain_pending_spawns()   ← child processes started here
       ▼
  idle loop (hlt)
```

When a WASM module calls `proc_spawn`:
1. The child PID is registered in the kernel process table, then the WASM instantiation request is **queued** (not executed immediately) to avoid re-entrant lock deadlock.
2. After the top-level `call_host_function` returns, `drain_pending_spawns()` instantiates each queued child.
3. The child's `_start` is invoked and it runs to completion (or yields).

Cooperative WASM threads are lighter-weight than `proc_spawn`: they stay inside
the same WasmInstance, share linear memory, and are scheduled by the runtime's
background thread runner. A module that spawns threads should still use
`thread_yield` or `proc_yield` at meaningful boundaries so sibling threads make
observable progress during foreground execution. When `wasm <path>` returns
normally from `_start`, the shell also drains a bounded number of leftover
cooperative thread quanta before tearing the instance down, and warns if the
remaining threads are stalled or still live after that budget.

---

## IPC Channels

Channels are first-class kernel objects mediated by capabilities and runtime
attachment/import paths.

```rust
// Pseudocode: use the capability/handle injected by the runtime or parent
// process, then route messages through the SDK wrapper that matches your app.
```

From WAT:

```wat
(import "oreulius" "channel_send"  (func $channel_send  (param i32 i32 i32) (result i32)))
(import "oreulius" "channel_recv"  (func $channel_recv  (param i32 i32 i32) (result i32)))
(import "oreulius" "channel_send_cap" (func $channel_send_cap (param i32 i32 i32 i32) (result i32)))
```

---

## Capability Model

Every kernel object (memory region, device, socket, IPC endpoint) is
referenced by a **capability** — an unforgeable token that carries both
identity and permission bits.

WASM modules receive capabilities from their parent process or the kernel
init table.  They cannot manufacture capability IDs — they must be
**granted**.

```
parent spawns child
  │  capability_create() → cap_id
  │  capability_send(cap_id, ...)   ← grant to child
  │
child receives
  │  capability_recv(cap_id, ...)   ← reads message
  │  ...uses capability...
  │  capability_drop(cap_id)         ← reference released
```

The capability manager enforces **temporal revocation**: a process cannot
use a capability after the object it refers to has been destroyed, even if
it retains the numeric ID.

---

## Sockets and Networking

Oreulius's network stack is built on the RTL8139 Ethernet driver.  The WASI
socket layer maps onto raw Ethernet frames at the driver level.

**Accepting a connection:**

```wat
;; sock_accept(listen_fd=5, flags=0, &new_fd)
(call $sock_accept (i32.const 5) (i32.const 0) (i32.const 100))
;; new_fd is written to linear memory at address 100
```

`sock_accept` returns `Errno::Again` (6) if no packet is available in the
receive ring.  Poll first with `poll_oneoff` (tag=`fd_read`) to avoid spinning.

---

## Polling and Async I/O

The recommended pattern for non-blocking I/O:

```wat
;; 1. Build a clock subscription for a 10 ms timeout at address 0
;; 2. Build an fd_read subscription for stdin at address 48
;; 3. Call poll_oneoff(in=0, out=96, nsubs=2, nevents=160)
;; 4. Check the event count at address 160
;; 5. Check each event's tag to determine what fired
```

See `wasm/poll_demo.wat` for a complete working example.

---

## File System

The Oreulius VFS is pre-opened at fd 3 (the first pre-opened directory).

```wat
;; Open "/hello.txt" for reading
(call $path_open
  (i32.const 3)   ;; dirfd = pre-opened root
  (i32.const 0)   ;; LOOKUP_SYMLINK_FOLLOW = off
  (i32.const 256) ;; path_ptr
  (i32.const 9)   ;; path_len ("hello.txt")
  (i32.const 0)   ;; oflags = 0 (open existing)
  (i64.const 15)  ;; rights_base: read+write+seek+tell
  (i64.const 15)  ;; rights_inheriting
  (i32.const 0)   ;; fdflags
  (i32.const 300) ;; &new_fd output
)
```

---

## Sample Applications

| File | Description |
|------|-------------|
| `wasm/hello.wat` | Print "Hello from Oreulius!" and exit |
| `wasm/echo.wat` | Echo stdin to stdout line by line |
| `wasm/spawn_children.wat` | Demonstrate `proc_spawn` with child processes |
| `wasm/poll_demo.wat` | Use `poll_oneoff` for a 100 ms clock timeout |
| `wasm/thread_demo.wat` | Demonstrate cooperative thread spawn/join/yield/exit |

Compile all samples:

```bash
cd wasm
for f in *.wat; do wat2wasm "$f" -o "${f%.wat}.wasm"; done
```

---

## Debugging

- The Oreulius serial console outputs `[WASM]` tagged lines for instantiation
  and errors.
- WASM traps (divide by zero, OOB memory, unreachable) are caught by the
  runtime and printed as `WasmError::Trap`.
- Use `wasm-objdump -d myapp.wasm` to disassemble before loading.
- The `wasm-validate` tool (WABT) checks structural correctness before upload.

---

## ABI Stability

The current runtime keeps the following stability rules:

- WASI Preview 1 function IDs `45–90` follow the current implemented Preview 1 profile.
- Oreulius native host IDs are append-only within the current runtime surface.
- The implemented native ranges now extend through `131`.
- New host IDs should be allocated above the current high-water mark rather than
  reusing retired numbers.

For exact signatures and wire layouts, treat [oreulius-wasm-abi.md](./oreulius-wasm-abi.md)
as the primary ABI contract.
