# Oreulia Kernel

<div align="center">

**A capability-native, WebAssembly-first kernel with temporal state and in-kernel verification**

[![Written in Rust](https://img.shields.io/badge/written%20in-Rust-orange.svg)](https://www.rust-lang.org/)
[![Written in assembly](https://img.shields.io/badge/written%20in-Assembly-brown.svg)](https://en.wikipedia.org/wiki/Assembly_language)
[![License: Oreulia](docs/oreulius-license-badge.svg)](LICENSE)
[![i686](https://img.shields.io/badge/i686-legacy%20runtime-success)](https://en.wikipedia.org/wiki/I686)
[![x86_64](https://img.shields.io/badge/x86__64-Multiboot2%20QEMU%20bringup-blue)](https://en.wikipedia.org/wiki/X86-64)
[![AArch64](https://img.shields.io/badge/AArch64-QEMU%20virt%20bringup-blue)](https://en.wikipedia.org/wiki/AArch64)
[![Boot Handoff](https://img.shields.io/badge/boot%20handoff-MB1%20%7C%20MB2%20%7C%20DTB-informational)](#platform-and-portability-status)
[![WASM Host ABI](https://img.shields.io/badge/WASM%20host%20ABI-IDs%200%E2%80%93131-blueviolet)](#wasm-host-abi-reference)
[![Multiarch QEMU Smoke](https://github.com/reeveskeefe/oreulia/actions/workflows/multiarch-qemu-smoke.yml/badge.svg)](https://github.com/reeveskeefe/oreulia/actions/workflows/multiarch-qemu-smoke.yml)
[![Multiarch QEMU Extended](https://github.com/reeveskeefe/oreulia/actions/workflows/multiarch-qemu-extended.yml/badge.svg)](https://github.com/reeveskeefe/oreulia/actions/workflows/multiarch-qemu-extended.yml)
[![CapNet Regression](https://github.com/reeveskeefe/oreulia/actions/workflows/capnet-regression.yml/badge.svg)](https://github.com/reeveskeefe/oreulia/actions/workflows/capnet-regression.yml)
[![WASM JIT Regression](https://github.com/reeveskeefe/oreulia/actions/workflows/wasm-jit-regression.yml/badge.svg)](https://github.com/reeveskeefe/oreulia/actions/workflows/wasm-jit-regression.yml)
[![Proof Check](https://github.com/reeveskeefe/oreulia/actions/workflows/proof-check.yml/badge.svg)](https://github.com/reeveskeefe/oreulia/actions/workflows/proof-check.yml)

[Why It Is Different](#why-it-is-different) • [Portability](#platform-and-portability-status) • [Architecture](#architecture) • [Host ABI](#wasm-host-abi-reference) • [SDK](#wasm-sdk-module-reference) • [Kernel Modules](#kernel-module-map) • [Capability Internals](#capability-system-internals) • [CI](#continuous-integration) • [Cross-Arch Internals](#cross-architecture-implementation) • [Verification](#verification-and-hardening) • [Build](#build-and-run) • [Commands](#command-taxonomy) • [Docs](#documentation-map)

</div>

<div align="center">
<img src="docs/assets/oreuliuswhitebackground.png" width="640" alt="Oreulia kernel logo">
</div>

## Overview

Oreulia is an experimental kernel that treats capabilities, temporal/versioned kernel state, and WebAssembly execution as first-order primitives.

Oreulia is source-available under the Oreulia Community License. The public
license allows research, evaluation, modification, public forks, benchmarking,
and non-commercial distribution. Commercial deployment and production use
require a separate written agreement. See `LICENSE` and `COMMERCIAL.md`.

It now has active bring-up/build paths for three architectures:

- `i686` (legacy/full runtime path)
- `x86_64` (Multiboot2 + GRUB + QEMU bring-up shell path)
- `AArch64` (QEMU `virt` raw `Image` + DTB bring-up shell path)

It is designed for technical audiences who care about:

- Authority minimization (no ambient access).
- Deterministic replay and versioned kernel object history.
- Tight privilege boundaries for JIT-enabled workloads.
- Built-in verification and fuzz workflows runnable from the shell.

<div align="center">
<img src="docs/assets/opencommandlineinterface.png" width="640" alt="Oreulia shell interface">
</div>

## Why It Is Different

| Area | What Oreulia Does | Why It Matters |
|---|---|---|
| Capability model | Access is explicitly delegated via capabilities, not global privilege assumptions. | Reduces blast radius and makes authority flow auditable. |
| Temporal objects | Kernel objects are versioned with rollback, branching, and merge semantics. | Enables recovery, provenance, and deterministic investigation. |
| WASM execution | Interpreter + JIT path with hardening and differential validation. | High execution flexibility with safety-focused guardrails. |
| CapNet control plane | Capability delegation extends over network peers with attestation and replay guards. | Portable authority transfer without ambient trust. |
| In-kernel verification | Shell commands run formal checks, targeted hardening tests, and fuzz corpus replay. | Reproducible evidence of invariants at runtime. |
| Polyglot WASM runtime | WASM modules can register and resolve cross-language type bindings at runtime (IDs 103–105). | Multiple WASM language toolchains coexist in the same process without a global type registry. |
| Kernel-mesh networking | Capability tokens are minted, routed, and migrated across an in-kernel peer mesh (IDs 109–115). | Authority delegation survives process migration and cross-node transfer without re-negotiation. |
| Observer / event bus | Host-visible capability event subscriptions with filtered delivery (IDs 106–108). | Audit and reactive policy without polling loops or extra syscalls. |
| Temporal capability checkpoints | Capabilities carry their own temporal checkpoint; rollback rewinds both state and access rights (IDs 116–120). | A revocation that happens after a checkpoint can be replayed rather than silently accepted. |
| Policy contracts | Named policy objects bind to capabilities and are evaluated inline on every access (IDs 121–124). | Runtime policy changes take effect without recompiling the kernel or restarting workloads. |
| Quantum-inspired capability entanglement | Pairs or groups of capabilities are entangled; revoking any member automatically revokes all co-entangled members (IDs 125–128). | Authority collapse is atomic across capability groups, eliminating partial-revocation races. |
| Runtime capability graph verification | Every delegation is recorded in a live DAG; cycles and rights-escalation are detected and rejected before the transfer is committed (IDs 129–131). | The delegation graph is auditable at runtime; violations are counted and logged, not silently accepted. |

## Feature Snapshot

- Capability-based security and explicit authority flow.
- Intent graph predictive revocation and runtime policy control.
- Service/function pointer capabilities for typed WASM invocation.
- CapNet tokenized cross-peer capability delegation.
- Temporal object persistence, branching, rollback, and merge.
- WebAssembly runtime with JIT toggle, threshold tuning, and fuzz tooling.
- IPC channels, service registry, VFS, scheduler, network stack, and enclave state integration.
- Formal verification and corpus-driven fuzzing commands available in shell.
- Polyglot WASM runtime with cross-language type resolution and cross-module linking (IDs 103–105).
- In-kernel peer mesh with capability token minting, routing, and live process migration (IDs 109–115).
- Observer/event bus for capability lifecycle events with subscription and filtered query (IDs 106–108).
- Temporal capability checkpoints — authority state snapshotted and rolled back atomically (IDs 116–120).
- Runtime policy contracts bound to individual capabilities and evaluated inline (IDs 121–124).
- Quantum-inspired capability entanglement with atomic group revocation (IDs 125–128).
- Runtime capability delegation graph (DAG) with cycle detection, no-escalation enforcement, and live violation counting (IDs 129–131).
- WASM host ABI spans IDs 0–131 across 132 callable host functions.
- 77+ kernel modules organized into subsystem directories within a single Rust `no_std` crate.
- 5 GitHub Actions CI workflows (smoke, extended, CapNet regression, WASM JIT regression, proof check).
- 14 shell-level CI scripts for i686, x86_64, and AArch64 covering smoke, extended, and soak profiles.

## Platform And Portability Status

Oreulia is now cross-compatible at the boot/runtime abstraction layer across `i686`, `x86_64`, and `AArch64`, but feature parity is intentionally uneven:

- `i686` remains the most complete/runtime-rich path.
- `x86_64` is a real QEMU bring-up path with working boot, traps, timer IRQs, MMU backend, and serial shell, but many legacy asm/runtime subsystems are still being ported.
- `AArch64` is a real QEMU `virt` bring-up path with DTB parsing, PL011, exception vectors, GICv2 timer IRQs, MMU backend, serial shell, and virtio-mmio bring-up tests; broader driver/runtime parity is still in progress.

### Compatibility Matrix

| Arch | Boot Path | Current Status | Console / Bring-up Surface |
|---|---|---|---|
| `i686` | Multiboot1 + GRUB (`build.sh`, `run.sh`) | Most complete runtime path | VGA + serial shell, core kernel services |
| `x86_64` | Multiboot2 + GRUB ISO (`build-x86_64-full.sh`) | Real QEMU bring-up (serial shell, traps, timer, MMU) | Serial bring-up shell and diagnostics |
| `AArch64` | QEMU `virt` raw `Image` + DTB (`build-aarch64-virt.sh`) | Real QEMU `virt` bring-up (PL011, vectors, GICv2, MMU, virtio-mmio tests) | PL011 serial shell and diagnostics |

## Architecture

### System Shape

```text
+--------------------------------------------------------------+
| Shell / Command Plane                                        |
|  help, formal-verify, temporal-*, wasm-jit-*, capnet-*       |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Capability, Security, Intent, Registry, IPC                  |
| authority checks, policy, channels, service discovery        |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| WASM Runtime + JIT + Service Pointers                        |
| interpreted + compiled paths, typed calls, replay hooks      |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Temporal + Persistence Layer                                 |
| object adapters, version DAG, rollback/merge, snapshots      |
+-------------------------------+------------------------------+
                                |
+-------------------------------v------------------------------+
| Process/Scheduler + VM + Syscall + Network/WiFi/E1000        |
| context switch, paging, user transitions, protocol stack     |
+--------------------------------------------------------------+
```

### Subsystem Map

| Subsystem | Primary Responsibility | Operational Surface |
|---|---|---|
| Capability manager | Fine-grained authority definition and transfer | `cap-list`, `cap-arch`, `cap-test-*` |
| Security + intent graph | Audit stream, anomaly tracking, predictive policy | `security-*` commands |
| Process + scheduler | Preemptive scheduling, process lifecycle, context handoff | `spawn`, `ps`, `kill`, `sched-stats`, `quantum-stats` |
| IPC + registry | Typed channels and service discovery | `ipc-*`, `svc-*`, `intro-demo` |
| WASM runtime + JIT | Sandboxed execution + optional compilation path | `wasm-*`, `svcptr-*` |
| Temporal service | Versioned object history, branch/merge/rollback | `temporal-*` |
| Persistence | Durable snapshot read/write for temporal state | Used by temporal self-checks and restore path |
| Network + CapNet | Ethernet/WiFi stack and capability network control plane | `net-*`, `wifi-*`, `capnet-*`, `http-*`, `dns-resolve` |
| Assembly paths | Low-level context, syscall, memory, and perf primitives | `asm-test`, `cpu-bench`, VM/syscall tests |

## WASM Host ABI Reference

The Oreulia WASM runtime exposes 132 host functions (IDs 0–131) through a single import module. Functions are resolved by name — both the short form (e.g. `log`) and the fully-qualified `oreulia_` prefix form (e.g. `oreulia_log`) are accepted. Every function call is dispatched through a single match arm in the `WasmInterpreter::call_host_fn` method in `kernel/src/wasm.rs` (19,536 lines).

### Group 0 — Core I/O and IPC (IDs 0–12)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 0 | `debug_log` / `oreulia_log` | 2 | 0 | Write a UTF-8 string slice (ptr, len) to the kernel serial log. |
| 1 | `fs_read` | 5 | 1 | Read bytes from a VFS path into a WASM memory buffer. |
| 2 | `fs_write` | 5 | 1 | Write bytes from a WASM memory buffer to a VFS path. |
| 3 | `channel_send` | 3 | 1 | Send a message on a named IPC channel by capability handle. |
| 4 | `channel_recv` | 3 | 1 | Receive a message from a named IPC channel by capability handle. |
| 5 | `net_http_get` | 4 | 1 | Perform an HTTP GET via the kernel network stack; write response to buffer. |
| 6 | `net_connect` | 3 | 1 | Open a TCP connection by (host_ptr, host_len, port). |
| 7 | `dns_resolve` | 2 | 1 | Resolve a hostname; write result IPv4/IPv6 as text into buffer. |
| 8 | `service_invoke` | 3 | 1 | Invoke a registered service by name and cap handle. |
| 9 | `service_register` | — | 1 | Register the current module as a named service. |
| 10 | `channel_send_cap` | 4 | 1 | Send a message on a channel, attaching a capability token. |
| 11 | `last_service_cap` | 0 | 1 | Return the capability handle from the most recent service call result. |
| 12 | `service_invoke_typed` | 5 | 1 | Typed service invocation; caller provides signature descriptor. |

### Group 1 — Temporal Object Operations (IDs 13–22)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 13 | `temporal_snapshot` | 4 | 1 | Snapshot the current value of a temporal object at a named key. |
| 14 | `temporal_latest` | 4 | 1 | Read the latest version entry for a temporal object. |
| 15 | `temporal_read` | 7 | 1 | Read a specific historical version of a temporal object into a buffer. |
| 16 | `temporal_rollback` | 6 | 1 | Roll back a temporal object to a given version number. |
| 17 | `temporal_stats` | 1 | 1 | Return stats (version count, size, schema version) for a temporal object. |
| 18 | `temporal_history` | 7 | 1 | Enumerate version history for a temporal object into a buffer. |
| 19 | `temporal_branch_create` | 8 | 1 | Create a named branch of a temporal object from a base version. |
| 20 | `temporal_branch_checkout` | 6 | 1 | Check out a branch of a temporal object (make it the active head). |
| 21 | `temporal_branch_list` | 5 | 1 | Enumerate all branches of a temporal object into a buffer. |
| 22 | `temporal_merge` | 9 | 1 | Merge two branches of a temporal object with a caller-specified strategy (0=FastForwardOnly, 1=Ours, 2=Theirs, 3=ThreeWay). |

### Group 2 — Thread Primitives (IDs 23–27)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 23 | `thread_spawn` | 2 | 1 | Spawn a WASM thread by (func_index, arg). Returns thread handle or -1. |
| 24 | `thread_join` | 1 | 1 | Block until a thread handle completes. Returns exit value. |
| 25 | `thread_id` | 0 | 1 | Return the current thread's numeric ID. |
| 26 | `thread_yield` | 0 | 0 | Yield the current WASM thread's time slice. |
| 27 | `thread_exit` | 1 | 0 | Terminate the current WASM thread with a given exit code. |

### Group 3 — Compositor / Windowing (IDs 28–37)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 28 | `compositor_create_window` | — | 1 | Create a new compositor window surface. Returns window handle. |
| 29 | `compositor_destroy_window` | — | 1 | Destroy a compositor window by handle. |
| 30 | `compositor_set_pixel` | — | 1 | Set a single pixel in a window at (x, y, color). |
| 31 | `compositor_fill_rect` | — | 1 | Fill a rectangular region of a window with a solid color. |
| 32 | `compositor_flush` | — | 1 | Flush a window's framebuffer to the display. |
| 33 | `compositor_move_window` | — | 1 | Move a compositor window to (x, y). |
| 34 | `compositor_set_z_order` | — | 1 | Set the z-order of a compositor window. |
| 35 | `compositor_get_width` | — | 1 | Return the width of a compositor window in pixels. |
| 36 | `compositor_get_height` | — | 1 | Return the height of a compositor window in pixels. |
| 37 | `compositor_draw_text` | — | 1 | Draw a UTF-8 text string at a position within a compositor window. |

### Group 4 — Input Events (IDs 38–44)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 38 | `input_poll` | — | 1 | Return 1 if any input event is pending, 0 otherwise. |
| 39 | `input_read` | — | 1 | Read the next raw input event into a buffer. |
| 40 | `input_event_type` | — | 1 | Return the type tag of the last read input event. |
| 41 | `input_flush` | — | 1 | Discard all pending input events. |
| 42 | `input_key_poll` | — | 1 | Return 1 if a keyboard event is pending. |
| 43 | `input_mouse_poll` | — | 1 | Return 1 if a mouse event is pending. |
| 44 | `input_gamepad_poll` | — | 1 | Return 1 if a gamepad event is pending. |

### Group 5 — WASI Compatibility Layer (IDs 45–90)

Oreulia implements a WASI preview-1 compatibility surface over the kernel's own VFS and process model. WASM modules compiled for `wasm32-wasi` can import from the `wasi_snapshot_preview1` module and be hosted without modification.

| ID | WASI Function | ID | WASI Function |
|---|---|---|---|
| 45 | `args_get` | 68 | `fd_seek` |
| 46 | `args_sizes_get` | 69 | `fd_stat_set_flags` |
| 47 | `environ_get` | 70 | `fd_tell` |
| 48 | `environ_sizes_get` | 71 | `fd_write` |
| 49 | `clock_res_get` | 72 | `path_create_directory` |
| 50 | `clock_time_get` | 73 | `path_filestat_get` |
| 51 | `fd_advise` | 74 | `path_filestat_set_times` |
| 52 | `fd_allocate` | 75 | `path_link` |
| 53 | `fd_close` | 76 | `path_open` |
| 54 | `fd_datasync` | 77 | `path_readlink` |
| 55 | `fd_fdstat_get` | 78 | `path_remove_directory` |
| 56 | `fd_fdstat_set_flags` | 79 | `path_rename` |
| 57 | `fd_fdstat_set_rights` | 80 | `path_symlink` |
| 58 | `fd_filestat_get` | 81 | `path_unlink_file` |
| 59 | `fd_filestat_set_size` | 82 | `poll_oneoff` |
| 60 | `fd_filestat_set_times` | 83 | `proc_exit` |
| 61 | `fd_pread` | 84 | `proc_raise` |
| 62 | `fd_prestat_get` | 85 | `sched_yield` |
| 63 | `fd_prestat_dir_name` | 86 | `random_get` |
| 64 | `fd_pwrite` | 87 | `sock_accept` |
| 65 | `fd_read` | 88 | `sock_recv` |
| 66 | `fd_readdir` | 89 | `sock_send` |
| 67 | `fd_renumber` | 90 | `sock_shutdown` |

### Group 6 — TLS (IDs 91–99)

| ID | Export Name | Description |
|---|---|---|
| 91 | `tls_connect` | Open a TLS session to (host_ptr, host_len, port). Returns session handle or -1. |
| 92 | `tls_write` | Write bytes to an open TLS session. |
| 93 | `tls_read` | Read bytes from an open TLS session into a buffer. |
| 94 | `tls_close` | Close a TLS session by handle. |
| 95 | `tls_state` | Return the current state tag of a TLS session. |
| 96 | `tls_error` | Return the last error code of a TLS session. |
| 97 | `tls_handshake_done` | Return 1 if the TLS handshake for a session is complete. |
| 98 | `tls_tick` | Drive a TLS session's internal state machine forward by one step. |
| 99 | `tls_free` | Free all resources associated with a TLS session handle. |

### Group 7 — Process Lifecycle (IDs 100–102)

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 100 | `proc_spawn` | 2 | 1 | Spawn a new process from a WASM function index. Returns PID or -1. |
| 101 | `proc_yield` | 0 | 0 | Yield the current process's time slice. |
| 102 | `proc_sleep` | 1 | 0 | Sleep the current process for N milliseconds. |

### Group 8 — Polyglot Runtime (IDs 103–105)

The polyglot subsystem allows multiple WASM language runtimes to coexist in the same kernel session. A module registers its type ABI under a namespace, then other modules resolve and link against it without a shared global registry.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 103 | `polyglot_register` | 2 | 1 | Register the calling module's type ABI under a (namespace_ptr, namespace_len) key. |
| 104 | `polyglot_resolve` | 2 | 1 | Resolve a type binding by namespace; returns a handle to the registered ABI. |
| 105 | `polyglot_link` | 4 | 1 | Link a resolved ABI handle into the caller's import table at a given slot. |

### Group 9 — Observer / Event Bus (IDs 106–108)

The observer subsystem exposes capability lifecycle events to WASM modules. A module subscribes to a capability's event stream; the kernel delivers events (grant, revoke, transfer, violation) without polling.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 106 | `observer_subscribe` | 1 | 1 | Subscribe to events for a capability ID. Returns a subscription handle. |
| 107 | `observer_unsubscribe` | 0 | 1 | Unsubscribe the most recent subscription. |
| 108 | `observer_query` | 2 | 1 | Read the next pending event for a subscription into a buffer. Returns bytes written or -1 if none. |

### Group 10 — Kernel Mesh (IDs 109–115)

The mesh subsystem implements an in-kernel peer table with capability token minting, peer-to-peer token routing, and live process migration. Each peer has a stable local ID; tokens are 256-bit opaque values whose rights are enforced by the issuing kernel instance.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 109 | `mesh_local_id` | 0 | 1 | Return the local peer ID of the current kernel instance. |
| 110 | `mesh_peer_register` | 3 | 1 | Register a remote peer by (addr_ptr, addr_len, peer_id). |
| 111 | `mesh_peer_session` | 2 | 1 | Open an authenticated session to a peer by peer_id and session_key. |
| 112 | `mesh_token_mint` | 6 | 1 | Mint a new capability token with specified rights for a target peer session. |
| 113 | `mesh_token_send` | 4 | 1 | Route a previously minted token to a registered peer. |
| 114 | `mesh_token_recv` | 2 | 1 | Receive an inbound token from a peer into a buffer. |
| 115 | `mesh_migrate` | 4 | 1 | Initiate a live process migration to a target peer, transferring capability set. |

### Group 11 — Temporal Capability Checkpoints (IDs 116–120)

Temporal capabilities bind authority to a point in time. A grant is recorded in the temporal log; rolling back the object version atomically rolls back both the payload state and the capability rights that were active at that version.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 116 | `temporal_cap_grant` | 3 | 1 | Grant a temporally-scoped capability to a target PID at the current version. |
| 117 | `temporal_cap_revoke` | 1 | 1 | Revoke a temporally-scoped capability by handle; records the revocation in the version log. |
| 118 | `temporal_cap_check` | 1 | 1 | Check whether a temporally-scoped capability is still valid at the current version. Returns 0=valid, 1=expired, 2=revoked. |
| 119 | `temporal_checkpoint_create` | 0 | 1 | Snapshot the entire current capability set for the calling process into the temporal log. |
| 120 | `temporal_checkpoint_rollback` | 1 | 1 | Roll back the calling process's capability set to the version recorded at checkpoint N. |

### Group 12 — Policy Contracts (IDs 121–124)

Policy contracts are named rule objects that can be bound to a capability. Every time that capability is exercised, the bound policy is evaluated inline. Policies can be updated at runtime; the change takes effect on the next exercise without restarting the holder.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 121 | `policy_bind` | 3 | 1 | Bind a named policy to a capability by (cap_id, policy_name_ptr, policy_name_len). Returns 0 on success. |
| 122 | `policy_unbind` | 1 | 1 | Remove the policy bound to a capability by cap_id. |
| 123 | `policy_eval` | 3 | 1 | Evaluate the policy currently bound to a capability against a context buffer. Returns 0=allow, 1=deny, 2=no policy. |
| 124 | `policy_query` | 3 | 1 | Read the policy name and metadata bound to a capability into a caller buffer. |

### Group 13 — Quantum-Inspired Capability Entanglement (IDs 125–128)

Capability entanglement is the kernel's implementation of atomic multi-party revocation. Two capabilities can be entangled pairwise; any number of capabilities can be entangled as a named group. When any member of an entangled set is revoked, the kernel atomically revokes all co-entangled members in the same operation. This eliminates the partial-revocation race that occurs when authority must be withdrawn from multiple holders simultaneously.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 125 | `cap_entangle` | 2 | 1 | Entangle two capabilities by (cap_id_a, cap_id_b). Returns 0 on success, -1 if either is invalid. |
| 126 | `cap_entangle_group` | 2 | 1 | Add a capability to a named entanglement group by (cap_id, group_name_hash). Creates the group if it does not exist. |
| 127 | `cap_disentangle` | 1 | 1 | Remove all entanglement links for a capability. Does not revoke the capability itself. |
| 128 | `cap_entangle_query` | 3 | 1 | Read the list of capabilities entangled with a given cap_id into a caller buffer. Returns count or -1. |

### Group 14 — Runtime Capability Graph Verification (IDs 129–131)

The runtime capability graph is a live delegation DAG maintained in `kernel/src/capability/cap_graph.rs`. Every `transfer_capability` call passes through `check_invariants` (no-escalation + no-cycle check) before the transfer is committed; the edge is recorded via `record_delegation` after a successful transfer. Every `revoke_capability` call prunes the corresponding edges. The graph is stored as a flat 256-slot edge table protected by a `spin::Mutex`. Cycle detection uses iterative DFS with a 32-deep visited stack; the algorithm is fail-closed (overflow = reject). The lifetime violation counter is monotonic and never resets.

| ID | Export Name | Args | Rets | Description |
|---|---|---|---|---|
| 129 | `cap_graph_query` | 3 | 1 | Read up to 16 delegation edges for a (cap_id, buf_ptr, buf_len). Each edge is 20 bytes: `[from_pid:u32][from_cap:u32][to_pid:u32][to_cap:u32][rights:u32]` in little-endian. Returns edge count or -1. |
| 130 | `cap_graph_verify` | 2 | 1 | Prospectively check whether delegating cap_id to delegatee_pid would violate invariants. Returns 0=safe, 1=rights escalation, 2=would create cycle, 3=cap not found. |
| 131 | `cap_graph_depth` | 1 | 1 | Return the delegation depth of cap_id from its original grantor. Returns 0 if the capability has no recorded delegation ancestor. |

## WASM SDK Module Reference

The `wasm/sdk` crate provides a Rust `no_std` SDK for WASM modules running on the Oreulia host. All 15 public modules correspond to groups of host functions described above. Modules are declared in `wasm/sdk/src/lib.rs` and each wraps the raw `extern "C"` FFI stubs in `wasm/sdk/src/raw/oreulia.rs` and `wasm/sdk/src/raw/wasi.rs` with safe, ergonomic abstractions.

| Module | Host IDs | Key Types / Functions | Purpose |
|---|---|---|---|
| `capgraph` | 129–131 | `DelegationEdge`, `EdgeList`, `VerifyResult`, `query()`, `verify()`, `depth()`, `assert_safe()` | Query the live delegation DAG; prospectively verify a planned delegation; check delegation depth; ergonomic pre-delegation guard. |
| `entangle` | 125–128 | `EntangleList`, `EntangleGuard`, `GroupEntangleGuard`, `entangle()`, `entangle_group()`, `disentangle()`, `entangle_query()` | Pairwise and group capability entanglement with RAII unlink-on-drop guards. |
| `fs` | 1–2 | `read()`, `write()` | VFS read/write over host IDs 1–2. |
| `io` | 0 | `log()` | Kernel serial log write. |
| `ipc` | 3–4, 10–12 | `send()`, `recv()`, `send_cap()`, `last_cap()` | IPC channel send/receive with optional capability attachment. |
| `mesh` | 109–115 | `local_id()`, `peer_register()`, `peer_session()`, `token_mint()`, `token_send()`, `token_recv()`, `migrate()` | Full kernel-mesh peer table and capability token lifecycle. |
| `net` | 5–7 | `http_get()`, `connect()`, `dns_resolve()` | Network I/O via the kernel network stack. |
| `observer` | 106–108 | `subscribe()`, `unsubscribe()`, `query()` | Capability event bus subscription and delivery. |
| `policy` | 121–124 | `PolicyResult`, `PolicyInfo`, `PolicyGuard`, `bind()`, `unbind()`, `eval()`, `query()`, `opol_stub()` | Runtime policy contract bind/eval/query with RAII unbind-on-drop guard. |
| `polyglot` | 103–105 | `register()`, `resolve()`, `link()` | Cross-language WASM type ABI registration and resolution. |
| `process` | 100–102 | `spawn()`, `yield_()`, `sleep()` | Process lifecycle primitives. |
| `temporal` | 13–22 | `snapshot()`, `latest()`, `read()`, `rollback()`, `stats()`, `history()`, `branch_create()`, `branch_checkout()`, `branch_list()`, `merge()` | Full temporal object lifecycle. |
| `thread` | 23–27 | `spawn()`, `join()`, `id()`, `yield_()`, `exit()` | WASM thread primitives. |
| `time` | 49–50 | `clock_res_get()`, `clock_time_get()` | WASI-compatible clock access. |
| `raw::oreulia` | 0–131 | All `extern "C"` FFI stubs | Direct FFI declarations for all Oreulia-native host functions. |
| `raw::wasi` | 45–90 | All WASI `extern "C"` FFI stubs | Direct FFI declarations for the WASI preview-1 compatibility surface. |

## Kernel Module Map

The kernel is a single Rust `no_std` `staticlib` crate (`oreulia-kernel v0.1.0`). Top-level subsystems are declared in `kernel/src/lib.rs`, with most implementation files grouped under subsystem directories. Architecture-conditioned modules use `#[cfg(not(target_arch = "aarch64"))]` (present on x86/i686) or `#[cfg(target_arch = "aarch64")]` (AArch64 only). Unconditional modules compile on all targets.

### Unconditional Modules (all architectures)

| Module | File | Responsibility |
|---|---|---|
| `arch` | `arch/` | Per-arch MMU, trap, interrupt, and boot backends |
| `cap_graph` | `capability/cap_graph.rs` | Live capability delegation DAG; cycle detection; no-escalation enforcement |
| `capability` | `capability/mod.rs` | Capability table, grant/transfer/revoke lifecycle, rights bitmask |
| `commands_shared` | `shell/commands_shared.rs` | Commands available on all architectures |
| `crypto` | `crypto.rs` | In-kernel cryptographic primitives |
| `exact_rational` | `exact_rational.rs` | Exact rational arithmetic for scheduler and policy math |
| `fs` | `fs.rs` | Key-value filesystem primitives |
| `intent_graph` | `intent_graph.rs` | Intent graph construction and predictive revocation |
| `intent_wasm` | `intent_wasm.rs` | WASM-visible intent graph interface |
| `interrupt_dag` | `interrupt_dag.rs` | Interrupt dependency graph for ordered delivery |
| `ipc` | `ipc/mod.rs` | IPC channel table and typed message dispatch |
| `persistence` | `persistence.rs` | Durable snapshot store for temporal objects |
| `pit` | `pit.rs` | PIT/timer abstraction (cross-arch) |
| `process` | `process.rs` | Process table and lifecycle management |
| `process_platform` | `process_platform.rs` | Architecture-agnostic process platform abstraction |
| `quantum_scheduler` | `quantum_scheduler.rs` | Preemptive quantum scheduler with entropy-based hints |
| `registry` | `registry.rs` | Service registry and discovery |
| `replay` | `replay.rs` | WASM execution replay record/load/verify |
| `scheduler_platform` | `scheduler_platform.rs` | Scheduler platform abstraction layer |
| `scheduler_runtime_platform` | `scheduler_runtime_platform.rs` | Runtime-side scheduler hooks |
| `security` | `security.rs` | Audit log, anomaly detection, and security event stream |
| `serial` | `serial.rs` | Serial console write (COM1 / PL011) |
| `temporal` | `temporal.rs` | Temporal object store, versioning, branch/merge |
| `temporal_asm` | `temporal_asm.rs` | Low-level temporal persistence assembly helpers |
| `telemetry` | `telemetry.rs` | In-kernel telemetry collection |
| `tensor_core` | `tensor_core.rs` | Tensor computation primitives for ML workloads |
| `vfs` | `vfs.rs` | Virtual filesystem with inode table and path resolution |
| `vfs_platform` | `vfs_platform.rs` | Platform abstraction for VFS block I/O |
| `virtio_blk` | `virtio_blk.rs` | Virtio block device driver (mmio + pci) |
| `wait_free_ring` | `wait_free_ring.rs` | Wait-free ring buffer for lock-free IPC fast path |

### x86 / i686-Only Modules

| Module | Responsibility |
|---|---|
| `acpi_asm` | ACPI table enumeration via assembly helpers |
| `advanced_commands` | Extended shell commands specific to the full x86 runtime |
| `asm_bindings` | Assembly binding stubs for legacy x86 kernel calls |
| `ata` | ATA/IDE disk driver |
| `audio` | Audio device driver |
| `bluetooth` | Bluetooth driver bring-up |
| `capnet` | CapNet cross-peer capability delegation control plane |
| `commands` | Full x86 shell command set |
| `compositor` | Windowed compositor and framebuffer rendering |
| `console_service` | Console service object and registration |
| `cpu_security` | CPU feature checks (SMEP, SMAP, KASLR) |
| `crash_log` | In-kernel crash log and fault capture |
| `disk` | Disk I/O abstraction layer |
| `dma_asm` | DMA controller ASM helpers |
| `e1000` | Intel e1000 NIC driver |
| `elf` | ELF binary loader for userspace launch |
| `enclave` | Enclave / secure session state management |
| `fleet` | Fleet management and OTA coordination |
| `formal` | In-kernel formal verification pipeline |
| `framebuffer` | Linear framebuffer driver |
| `gdt` | GDT and TSS setup |
| `gpu_support` | GPU/display acceleration bring-up |
| `hardened_allocator` | Hardened slab allocator with guard pages |
| `health` | Health check and liveness subsystem |
| `idt_asm` | IDT programming and trap handler stubs |
| `input` | Unified input event subsystem |
| `keyboard` | PS/2 keyboard driver |
| `kpti` | Kernel Page Table Isolation (KPTI) |
| `memopt_asm` | Memory optimization assembly primitives |
| `memory` | Physical memory manager |
| `memory_isolation` | Memory isolation and sandbox page table helpers |
| `mouse` | PS/2 mouse driver |
| `net` | Network stack (TCP/IP, UDP, ICMP) |
| `net_reactor` | Async network I/O reactor |
| `netstack` | Protocol stack integration layer |
| `nvme` | NVMe block device driver |
| `ota` | Over-the-air update pipeline |
| `paging` | Legacy i686 page table management |
| `pci` | PCI bus enumeration and device configuration |
| `process_asm` | Process context-switch ASM stubs |
| `rtl8139` | Realtek RTL8139 NIC driver |
| `scheduler` | Legacy i686 preemptive scheduler |
| `syscall` | Syscall entry (`INT 0x80`, `SYSENTER`) |
| `tasks` | Task control block management |
| `terminal` | In-kernel terminal/line-discipline |
| `tls` | In-kernel TLS session state |
| `usermode` | Ring-3 transition and user-mode management |
| `usb` | USB host controller driver |
| `vga` | VGA text-mode console |
| `wasi` | WASI host implementation |
| `wasm` | WASM interpreter, JIT dispatch, host ABI (IDs 0–131) |
| `wasm_jit` | WASM JIT compiler backend |
| `wasm_thread` | WASM threading and cooperative scheduling |
| `wifi` | WiFi driver and association state |

### AArch64-Only Modules

| Module | Responsibility |
|---|---|
| `commands` (aarch64 variant) | AArch64 bring-up shell command set |

## Capability System Internals

### CapabilityTable

The capability system lives in `kernel/src/capability/mod.rs` (2,150 lines). The primary structure is `CapabilityTable`, a fixed-size flat array of `CapabilityEntry` objects protected by a `spin::Mutex`. Each entry records:

- `cap_type`: The authority class (filesystem, IPC channel, network socket, service pointer, WASM module, temporal object, CapNet lease, etc.).
- `rights`: A bitmask (`bitflags`-generated) encoding the permitted operations (read, write, exec, delegate, revoke, transfer, etc.).
- `owner_pid`: The PID that holds this capability.
- `object_id`: The kernel object this capability references.
- `active`: Whether this entry is live.
- `temporal_version`: If temporally-scoped, the version at which this capability was granted.

### Rights Bitmask

Capability rights are composed from a `bitflags` set. The defined bits include:

- `READ` — read the referenced object's data.
- `WRITE` — mutate the referenced object.
- `EXEC` — invoke the referenced object (service call, WASM invocation).
- `DELEGATE` — transfer a copy to another process (subject to no-escalation).
- `REVOKE` — revoke a capability previously delegated to a child.
- `TRANSFER` — move (not copy) the capability to another process.
- `GRANT_TEMPORAL` — attach a temporal scope to a delegation.

The no-escalation rule enforced by `cap_graph::check_invariants` means a delegating process cannot grant a rights superset of its own entry. Any proposed delegation where `proposed_rights & !delegator_rights != 0` is rejected with `CapabilityError::SecurityViolation` before the transfer is committed.

### CapabilityError Variants

| Variant | `as_str()` | When Raised |
|---|---|---|
| `NotFound` | `"Capability not found"` | Lookup by cap_id or (pid, type) finds no active entry. |
| `PermissionDenied` | `"Permission denied"` | Caller's rights do not include the requested operation. |
| `InvalidType` | `"Invalid capability type"` | Cap type field does not match the expected operation. |
| `TableFull` | `"Capability table full"` | All slots in the fixed-size table are occupied. |
| `AlreadyExists` | `"Capability already exists"` | Attempt to insert a duplicate entry. |
| `Revoked` | `"Capability has been revoked"` | Operation attempted on a previously revoked entry. |
| `SecurityViolation` | `"Capability graph security violation"` | `cap_graph::check_invariants` detected rights escalation or a delegation cycle. |

### cap_graph Internals (`kernel/src/capability/cap_graph.rs`, 306 lines)

The capability delegation graph maintains a flat 256-slot edge table in static memory:

```text
CAP_GRAPH: spin::Mutex<CapGraph>
  .edges: [CapDelegationEdge; 256]
  .edge_count: usize
  .violations: u64
```

Each `CapDelegationEdge` records:
- `active: bool`
- `from_pid: u32`, `from_cap: u32` — the delegating (pid, cap_id) pair.
- `to_pid: u32`, `to_cap: u32` — the receiving (pid, cap_id) pair.
- `rights_bits: u32` — the rights bitmask at the time of transfer.

**`check_invariants(from_pid, from_cap, to_pid, delegator_rights, proposed_rights)`**
- Verifies `proposed_rights & !delegator_rights == 0` (no escalation).
- Calls `would_create_cycle(from_pid, from_cap, to_pid)` before recording.
- Returns `Err("rights escalation")` or `Err("cycle detected")` on violation; increments `violations`; logs via `serial_println!`.

**`would_create_cycle(from_pid, from_cap, to_pid)`**
- Iterative DFS using a 32-slot on-stack `[u32; 32]` visited set and a 32-slot `[(u32, u32); 32]` traversal stack.
- Fail-closed: stack overflow returns `true` (reject the delegation).
- Returns `true` if following existing edges from `(to_pid, to_cap)` can reach `(from_pid, from_cap)`.

**`record_delegation`** — called by `transfer_capability` after a successful invariant check.

**`prune_edges_for(pid, cap_id)`** — called by `revoke_capability`; marks all edges where `from` or `to` matches `(pid, cap_id)` as inactive.

**`prune_edges_for_pid(pid)`** — called on process teardown; prunes all edges touching any capability owned by `pid`.

**`delegation_depth(pid, cap_id)`** — recursive DFS, depth capped at 32; returns how many delegation hops separate this capability from its original grant.

**`violation_count()`** — returns the lifetime monotonic count of invariant breaches.

## Continuous Integration

### GitHub Actions Workflows

Five workflows run on every push and pull request:

| Workflow File | Trigger | What It Runs |
|---|---|---|
| `.github/workflows/multiarch-qemu-smoke.yml` | Push / PR | Smoke tests for i686, x86_64, and AArch64 under QEMU. Boot, serial shell, and immediate-exit checks. |
| `.github/workflows/multiarch-qemu-extended.yml` | Push / PR | Extended QEMU tests for all three architectures. Includes trap/MMU/IRQ/JIT/CapNet/temporal/VFS scenario scripts. |
| `.github/workflows/capnet-regression.yml` | Push / PR | CapNet parser, enforcer, and cross-peer delegation regression. Runs fuzz corpus and known-bad input set. |
| `.github/workflows/wasm-jit-regression.yml` | Push / PR | WASM interpreter vs JIT differential validation. Runs deterministic seed fuzz and corpus replay. |
| `.github/workflows/proof-check.yml` | Push / PR | Runs the 8-stage formal verification pipeline (`formal-verify`) via `kernel/formal-verify.sh`. |

### Shell CI Scripts (`kernel/ci/`)

14 shell scripts cover three architectures at three test depths:

| Script | Arch | Depth | Description |
|---|---|---|---|
| `smoke-i686.sh` / `.expect` | i686 | Smoke | Boot and minimal shell responsiveness check. |
| `smoke-x86_64.sh` / `.expect` | x86_64 | Smoke | MB2 boot, serial shell, and command availability. |
| `smoke-aarch64.sh` / `.expect` | AArch64 | Smoke | QEMU `virt` boot, PL011 shell, basic command echo. |
| `extended-x86_64.sh` / `.expect` | x86_64 | Extended | Traps, MMU, timer IRQ, JIT toggle, CapNet, temporal, VFS. |
| `extended-aarch64.sh` / `.expect` | AArch64 | Extended | Exception vectors, GICv2, generic timer, virtio-mmio. |
| `extended-all.sh` | All | Extended | Orchestrator that runs all three extended scripts in sequence. |
| `soak-x86_64.sh` | x86_64 | Soak | Long-duration stability run: JIT fuzz-soak, CapNet fuzz-soak, temporal churn. |
| `soak-aarch64.sh` | AArch64 | Soak | AArch64 long-duration stability, virtio-blk, and IRQ stability. |

### Formal Verification Pipeline Detail (`formal-verify`)

The `formal-verify` shell command runs an 8-stage in-kernel pipeline. Each stage is self-contained, fail-fast, and reports pass/fail to the serial console:

| Stage | Subject | Checks |
|---|---|---|
| 1 | JIT translation proof obligations | Opcode semantics equivalence between interpreter and JIT paths. |
| 2 | Capability proof obligations | Grant/transfer/revoke invariants; rights monotonicity; table compactness. |
| 3 | CapNet proof obligations | Token format; replay-guard nonce uniqueness; lease expiry enforcement. |
| 4 | Service pointer proof obligations | Typed invocation ABI; cross-PID pointer validity; type tag matching. |
| 5 | WASM control-flow semantics | Stack depth, branch target, and trap-on-unreachable self-check. |
| 6 | Temporal ABI/VFS/object/persistence/branch/audit/IPC checks | 7-domain temporal correctness sweep. |
| 7 | WASM binary conformance + negative parser fuzz | Well-formed module parsing + known-malformed input rejection. |
| 8 | Mechanized backend model checks | Algebraic invariants for the scheduler, capability graph, and temporal merge strategies. |

### Fuzz Admission Gate

Fuzz corpus runs serve as admission gates for capability-adjacent and JIT-adjacent subsystems. A regression is defined as any output divergence between the interpreter and JIT paths on the same seed, or any kernel panic/trap triggered by a corpus input. The corpus is maintained under `kernel/fuzz/` and is replayed on every CI run via `wasm-jit-fuzz-corpus` and `capnet-fuzz-corpus`.

## Cargo Crate Details

```text
Name:       oreulia-kernel
Version:    0.1.0
Edition:    2021
Crate type: staticlib
Target:     x86_64-unknown-none (default build)
            i686-oreulia (custom JSON target)
            aarch64-unknown-none (AArch64 bring-up)
```

### Dependencies

| Crate | Version | Feature Flags Used | Purpose |
|---|---|---|---|
| `spin` | 0.9 | (default) | `spin::Mutex` for all kernel-internal data structures |
| `bitflags` | 2.5 | (default) | Rights bitmasks for capabilities and permissions |
| `lazy_static` | 1.4 | `spin_no_std` | `no_std`-safe lazily-initialized statics |

### Cargo Feature Flags

| Feature | Effect |
|---|---|
| `formal-verify` | Enables the 8-stage formal verification pipeline and its proof obligation generators. |
| `jit-fuzz-24bin` | Enables 24-binary JIT fuzz mode; generates extended opcode coverage test vectors. |
| `experimental_entropy_sched` | Enables the entropy-based scheduler hint path in `quantum_scheduler`. |

## Honest Gaps (What Isn't Done Yet)

Oreulia makes no false completeness claims. The following items are explicitly acknowledged as incomplete or not yet started:

| Area | Status | Notes |
|---|---|---|
| AArch64 full runtime parity | In progress | AArch64 bring-up shell works; full x86 subsystem set (WASM, JIT, CapNet, temporal, IPC) not yet ported to AArch64. |
| x86_64 JIT opcode parity | In progress | x86_64 JIT path covers the most common opcodes; full WASM opcode coverage parity with i686 interpreter is not yet complete. |
| Non-QEMU hardware validation | Not started | All three architectures are validated under QEMU. Physical hardware bring-up has not been attempted. |
| POSIX / Linux ABI compatibility | Explicit non-goal | Oreulia is not a drop-in Linux replacement. No libc, no POSIX process model, no `/proc`. |
| Production workload benchmarking | Not started | Performance positioning is based on bounded control-path design; no workload-specific benchmarks have been published. |
| Universal binary merge semantics | Explicit non-goal | The temporal merge path supports defined strategies (FastForwardOnly, Ours, Theirs, ThreeWay) for structured payloads; arbitrary binary object merge is not a goal. |
| Multi-node CapNet (real network) | Not started | CapNet cross-peer delegation is implemented in-kernel; real multi-machine TCP transport has not been wired up. |

## Cross-Architecture Implementation

Oreulia's multi-arch work is not a separate fork or "second kernel." The same kernel crate is compiled for different targets, with architecture-specific boot/runtime/MMU backends selected behind stable interfaces in `kernel/src/arch/`.

### 1) Unified Boot Handoff (`BootInfo`)

The boot protocols are different, but the Rust entry side is normalized:

- `i686`: Multiboot1 handoff (legacy path)
- `x86_64`: Multiboot2 handoff via GRUB (MB2 boot stub + long-mode transition)
- `AArch64`: raw `Image` entry with DTB pointer in `x0` (QEMU `virt`)

`BootInfo` acts as the cross-arch handoff struct so early init code in `lib.rs` can log/use:

- boot protocol (`unknown` / `multiboot1` / `multiboot2` / DTB-backed platform handoff)
- raw handoff pointers/magic
- cmdline and bootloader strings (safe bounded C-string helpers)
- ACPI/DTB pointers when present

This keeps early Rust initialization mostly architecture-agnostic while each boot stub remains free to implement the platform-specific ABI.

### 2) Split Trap Table vs Interrupt Controller Initialization

Interrupt bring-up was split so architecture differences do not leak into common boot sequencing:

- `init_trap_table()`: IDT/vector table programming (`x86_64` IDT vs `AArch64` VBAR/vector table)
- `init_interrupt_controller()`: PIC/APIC/GIC setup and routing
- `init_timer()`: PIT / generic timer setup

That split is what allows `lib.rs` to call a consistent sequence while `x86` and `AArch64` do fundamentally different work underneath.

### 3) `arch::mmu` Abstraction (Per-Arch MMU Backends)

The major portability step was moving MMU-sensitive call sites behind `kernel/src/arch/mmu.rs`, with backends:

- `mmu_x86_legacy.rs` (legacy i686 paging integration)
- `mmu_x86_64.rs` (x86_64 long-mode page tables, CR3/TLB ops, page attributes/COW, map/unmap path)
- `mmu_aarch64.rs` (AArch64 4KB translation tables, TTBR/TCR/MAIR setup, map/unmap path)
- `mmu_unsupported.rs` (safe placeholder backend for unported targets)

The abstraction intentionally covers more than "turn paging on":

- page-table root get/set
- TLB invalidation ops
- page attribute updates (e.g. writable/device mappings)
- per-address-space allocation/map/unmap operations
- `AddressSpace` usage in higher-level code (ELF loader, JIT sandbox plumbing)

This is how the same `elf.rs` and JIT sandbox setup code can now compile against x86 and AArch64 without hardcoding `paging.rs` assumptions.

### 4) Runtime Bring-up Per Architecture (Same Kernel, Different Low-Level Paths)

`i686` path (legacy)

- Existing `gdt.rs`, `idt_asm.rs`, `paging.rs`, PIT, and legacy asm bindings remain the primary full-runtime path.

`x86_64` path (QEMU bring-up)

- Dedicated Multiboot2 boot stub and linker script
- Long-mode handoff into the same Rust kernel crate
- Real x86_64 GDT/TSS, IDT/traps, PIT IRQs, and CR3/TLB-backed MMU runtime path
- Bring-up serial shell for trap/MMU/JIT sandbox preflight diagnostics while legacy x86-only subsystems continue to be ported

`AArch64` path (QEMU `virt` bring-up)

- Raw `Image` boot stub + DTB handoff (`x0`)
- PL011 serial console
- Real `VBAR_EL1` vector table entries + synchronous exception logging
- GICv2 + generic timer IRQ handling
- AArch64 MMU backend with page-table map/unmap support for shell/runtime bring-up
- DTB-driven discovery of memory/UART/GIC/virtio-mmio instead of hardcoded addresses

### 5) Device Discovery And Driver Bring-up Strategy

Cross-compatibility is being implemented by separating:

- platform discovery (`BootInfo`, DTB parsing, future ACPI normalization)
- interrupt routing (PIC/APIC/GIC)
- MMU mapping semantics (normal memory vs device memory)
- driver/protocol logic (e.g. virtio-mmio queue bring-up)

Recent AArch64 work follows this pattern:

- DTB parser extracts UART/GIC/timer/virtio-mmio info
- MMU maps DTB-discovered MMIO windows as device memory
- GIC routes timer/UART/virtio interrupts
- shell-level diagnostics validate IRQ delivery and queue completion before full driver integration

### 6) Build/Launch Compatibility (Target-Specific Entrypoints)

The repo now contains target-specific build/run scripts rather than pretending one boot flow works everywhere:

- `kernel/build.sh` + `kernel/run.sh` for legacy `i686`
- `kernel/build-x86_64-full.sh` for `x86_64` MB2 full-link path
- `kernel/build-aarch64-virt.sh` + `kernel/run-aarch64-virt-image.sh` for AArch64 QEMU `virt`
- `kernel/run-aarch64-virt-image-virtio-blk-mmio.sh` for AArch64 virtio-mmio block transport testing

That split is deliberate: it keeps boot/link/firmware details per-target while preserving shared Rust kernel logic above the architecture layer.

## Temporal Universality

Oreulia's temporal subsystem is adapter-based. Each object class is represented by a stable key prefix and an apply adapter. This is why the model is universal across currently integrated kernel object domains.

### Object-Class Coverage Matrix

| Object Key / Prefix | Object Class | Apply Adapter | Restore Style |
|---|---|---|---|
| `/` (VFS path roots) | Filesystem objects | `temporal_apply_vfs_file_payload` | Payload restore into VFS object |
| `/socket/tcp/listener/<id>` | TCP listener state | `temporal_apply_tcp_listener_payload` | Control-plane state restore |
| `/socket/tcp/conn/<id>` | TCP connection state | `temporal_apply_tcp_conn_payload` | Control-plane state restore |
| `/ipc/channel/<id>` | IPC channel state | `temporal_apply_ipc_channel_payload` | Channel metadata/message state restore |
| `/process/<pid>` | Process metadata state | `temporal_apply_process_payload` | Process state projection restore |
| `/capability/<pid>/<type>/<obj>` | Capability events/state | `temporal_apply_capability_payload` | Capability graph/state replay |
| `/registry/service/<type>/<ns>` | Service registry state | `temporal_apply_registry_payload` | Registry entry reconciliation |
| `/console/object/<id>` | Console service state | `temporal_apply_console_payload` | Console control-plane restore |
| `/security/intent/policy` | Security intent policy state | `temporal_apply_security_payload` | Policy object restore |
| `/capnet/state` | CapNet state | `temporal_apply_capnet_payload` | Control-plane restore |
| `/wasm/service-pointers` | WASM service pointer registry | `temporal_apply_wasm_service_pointer_payload` | Registry/table restore |
| `/network/config` | Network configuration state | `temporal_apply_network_config_payload` | Config restore |
| `/wasm/syscall-modules` | WASM syscall module table | `temporal_apply_wasm_syscall_module_table_payload` | Module mapping restore |
| `/scheduler/state` | Scheduler state snapshot | `temporal_apply_scheduler_payload` | Scheduler metadata restore |
| `/replay/state` | Replay manager state | `temporal_apply_replay_manager_payload` | Replay control-plane restore |
| `/network/legacy/state` | Legacy network service state | `temporal_apply_network_legacy_payload` | Legacy service restore |
| `/wifi/state` | WiFi driver state | `temporal_apply_wifi_payload` | Driver control-plane restore |
| `/enclave/state` | Enclave/session policy state | `temporal_apply_enclave_payload` | Enclave control-plane restore |

### Why This Is "Universal" in Practice

- Coverage is key-driven, not special-cased per command.
- The adapter registry allows additional object classes via `register_object_adapter`.
- Snapshot decoding supports schema evolution (`v1`, `v2`, `v3`) with integrity validation on decode.
- Merge path includes deterministic three-way strategies with bounded behavior.

## Verification And Hardening

### Formal Verification Pipeline (`formal-verify`)

`formal-verify` runs an 8-stage in-kernel verification pipeline:

1. JIT translation proof obligations.
2. Capability proof obligations.
3. CapNet proof obligations.
4. Service pointer proof obligations.
5. WASM control-flow semantics self-check.
6. Temporal ABI/VFS/object/persistence/branch/audit/IPC checks.
7. WASM binary conformance + negative parser fuzz.
8. Mechanized backend model checks.

### Temporal Hardening Suite (`temporal-hardening-selftest`)

| Check | Purpose |
|---|---|
| v2 -> v3 decode compatibility | Validates backward-compatible temporal snapshot decode semantics. |
| Integrity-tag tamper rejection | Ensures corrupted persisted metadata is rejected. |
| Deterministic divergent merge | Ensures repeatable merge output for equivalent inputs. |
| WiFi required-reconnect failure path | Verifies explicit failure behavior for reconnect-required restore conditions. |
| Enclave active-session re-entry path | Verifies enclave/session hardening behavior across temporal transitions. |

### Differential And Fuzz Validation

- `wasm-jit-fuzz <iters> [seed]`.
- `wasm-jit-fuzz-corpus <iters>`.
- `wasm-jit-fuzz-soak <iters> <rounds>`.
- `capnet-fuzz <iters> [seed]`.
- `capnet-fuzz-corpus <iters>`.
- `capnet-fuzz-soak <iters> <rounds>`.

## Build And Run

### Prerequisites

```bash
# Kernel-pinned toolchain
rustup toolchain install nightly-2023-11-01
rustup component add rust-src --toolchain nightly-2023-11-01

# macOS example
brew install nasm qemu xorriso grub
```

### Build

```bash
git clone https://github.com/reeveskeefe/oreulieus-kernel.git
cd oreulieus-kernel/kernel
```

### i686 (Legacy Runtime Path)

```bash
./build.sh
./run.sh
```

Known-good QEMU serial launch (interactive from your terminal):

```bash
qemu-system-i386 -cdrom oreulia.iso -serial stdio
```

Notes:

- `i686` supports the legacy runtime path and can be used through the VGA window and/or serial depending on the shell path you boot into.
- If you want reproducible command capture, prefer the serial launch above.

### x86_64 (Multiboot2 + GRUB + QEMU)

Build and package the x86_64 Multiboot2 kernel (full-link + GRUB ISO):

```bash
./build-x86_64-mb2-iso.sh
```

Run the x86_64 bring-up shell in QEMU using the provided launcher (recommended):

```bash
QEMU_EXTRA_ARGS="-monitor none -nographic" ./run-x86_64-mb2-grub.sh
```

Notes:

- The x86_64 bring-up shell is **serial-input driven**. Typing in the QEMU VGA window will not control the shell.
- Use `-nographic` (as above) or another `QEMU_EXTRA_ARGS` variant that keeps COM1 attached to your terminal.
- If you prefer a windowed QEMU session, you still need serial attached to your terminal; for example:

```bash
qemu-system-x86_64 \
  -cdrom target/x86_64-mb2/oreulia-x86_64-mb2.iso \
  -serial mon:stdio \
  -monitor none \
  -m 512M
```

- `./build-x86_64-full.sh` validates the Multiboot2 header when `grub-file` is available.
- `./build-x86_64-mb2-iso.sh` automatically prefers `i686-elf-grub-mkrescue` when available because it is the most reliable BIOS-bootable GRUB ISO path for this flow.
- If you see `unknown command` for `wasm-jit-fuzz` in the x86_64 shell, use the x86_64 bring-up commands instead (`jitbench`, `jitfuzz`, `jitfuzzreg`, `jitcall`).

### AArch64 (QEMU `virt` Raw `Image`)

Build the AArch64 QEMU `virt` raw `Image`:

```bash
./build-aarch64-virt.sh
```

Run the basic AArch64 `virt` bring-up shell (recommended launcher):

```bash
./run-aarch64-virt-image.sh
```

Run the AArch64 `virt` variant with an explicit DTB-visible `virtio-mmio` block device binding (for block/VFS smoke work):

```bash
./run-aarch64-virt-image-virtio-blk-mmio.sh
```

Notes:

- The AArch64 bring-up shell is a **PL011 serial shell**. These launchers already run QEMU in terminal/serial mode.
- If you want a manual QEMU invocation, the raw `Image` path is the validated route (not `-kernel` ELF on this target path):

```bash
qemu-system-aarch64 \
  -M virt -cpu cortex-a57 -m 512M \
  -nographic -monitor none -serial stdio \
  -kernel target/aarch64-virt/Image
```

Optional launcher parameters:

- `BUS_SLOT` (default `0`) to choose `virtio-mmio-bus.N`
- `DISK_IMAGE` (default `target/aarch64-virt/virtio-blk-mmio-test.img`)
- `DISK_SIZE` (default `16M`)

### Known-Good QEMU Bring-up Matrix (Copy/Paste)

```bash
# i686 (legacy runtime)
cd kernel
./build.sh
qemu-system-i386 -cdrom oreulia.iso -serial stdio

# x86_64 (MB2 + GRUB ISO; serial shell)
cd kernel
./build-x86_64-mb2-iso.sh
QEMU_EXTRA_ARGS="-monitor none -nographic" ./run-x86_64-mb2-grub.sh

# AArch64 (QEMU virt raw Image; PL011 serial shell)
cd kernel
./build-aarch64-virt.sh
./run-aarch64-virt-image.sh
```

### Quick Rebuild Loop

```bash
./quick-rebuild.sh
```

## Command Taxonomy

Use `help` in-kernel for the exhaustive, source-of-truth command list. The taxonomy below highlights the most important command clusters.

### Core System

- `help`, `clear`, `echo`, `uptime`, `sleep`, `calculate`, `cpu-info`, `cpu-bench`, `pci-list`.

### Process And Scheduling

- `spawn`, `ps`, `kill`, `yield`, `whoami`, `sched-stats`, `quantum-stats`, `sched-net-soak`.

### Filesystem And VFS

- `vfs-mkdir`, `vfs-write`, `vfs-read`, `vfs-ls`, `vfs-open`, `vfs-readfd`, `vfs-writefd`, `vfs-close`.
- `vfs-mount-virtio`, `blk-info`, `blk-partitions`, `blk-read`, `blk-write`.
- Legacy KV commands: `fs-write`, `fs-read`, `fs-delete`, `fs-list`, `fs-stats`.

### Temporal Object Operations

- `temporal-write`, `temporal-snapshot`, `temporal-history`, `temporal-read`, `temporal-rollback`.
- `temporal-branch-create`, `temporal-branch-list`, `temporal-branch-checkout`, `temporal-merge`.
- `temporal-stats`, `temporal-retention`, `temporal-ipc-demo`, `temporal-abi-selftest`, `temporal-hardening-selftest`.

### WASM And Service Pointer Capabilities

- `wasm-demo`, `wasm-fs-demo`, `wasm-log-demo`, `wasm-list`.
- `svcptr-register`, `svcptr-invoke`, `svcptr-send`, `svcptr-recv`, `svcptr-inject`.
- `svcptr-demo`, `svcptr-demo-crosspid`, `svcptr-typed-demo`.
- `wasm-jit-on`, `wasm-jit-off`, `wasm-jit-bench`, `wasm-jit-selftest`, `wasm-jit-stats`, `wasm-jit-threshold`.
- `wasm-jit-fuzz`, `wasm-jit-fuzz-corpus`, `wasm-jit-fuzz-soak`.
- `wasm-replay-record`, `wasm-replay-stop`, `wasm-replay-save`, `wasm-replay-load`, `wasm-replay-status`, `wasm-replay-clear`, `wasm-replay-verify`.

### Networking And CapNet

- `net-info`, `eth-info`, `eth-status`, `netstack-info`, `dns-resolve`.
- `wifi-scan`, `wifi-connect`, `wifi-status`.
- `http-get`, `http-server-start`, `http-server-stop`.
- `capnet-local`, `capnet-peer-add`, `capnet-peer-show`, `capnet-peer-list`, `capnet-lease-list`.
- `capnet-hello`, `capnet-heartbeat`, `capnet-lend`, `capnet-accept`, `capnet-revoke`, `capnet-stats`, `capnet-demo`.
- `capnet-fuzz`, `capnet-fuzz-corpus`, `capnet-fuzz-soak`.

### Security And Capability Introspection

- `security-audit`, `security-stats`, `security-anomaly`.
- `security-intent`, `security-intent-clear`, `security-intent-policy`.
- `enclave-secret-policy`.
- `cap-list`, `cap-arch`, `cap-test-atten`, `cap-test-cons`, `cap-demo`.

### Low-Level Validation

- `formal-verify`.
- `paging-test`, `syscall-test`, `atomic-test`, `spinlock-test`, `asm-test`.
- `test-div0`, `test-pf`, `user-test`, `elf-run`.

## Reproducible Evaluation Flows

### 1) End-to-End Verification Sweep

```text
formal-verify
temporal-hardening-selftest
wasm-jit-selftest
```

### 2) JIT Differential Stress

```text
wasm-jit-on
wasm-jit-fuzz 1000 0
wasm-jit-fuzz-corpus 500
wasm-jit-fuzz-soak 500 5
```

### 3) CapNet Parser/Enforcer Stress

```text
capnet-fuzz 1000 0
capnet-fuzz-corpus 1000
capnet-fuzz-soak 500 10
```

### 4) Temporal Lifecycle Demo

```text
temporal-write /tmp/demo alpha
temporal-snapshot /tmp/demo
temporal-write /tmp/demo beta
temporal-history /tmp/demo
```

## Threat Model And Non-Goals

### Threat Model Focus

- Unauthorized authority escalation in kernel services.
- Replay and stale-state acceptance in delegated control paths.
- Unsafe JIT transitions and uncontrolled executable memory behavior.
- State corruption or silent divergence in temporal restore/merge paths.

### Explicit Non-Goals

- Drop-in POSIX/Linux compatibility.
- Production product claims without workload-specific benchmarking.
- Universal semantic merge for arbitrary binary object payloads.

## Performance Positioning

Oreulia is engineered around bounded and inspectable control paths:

- Fixed-level scheduler behavior with preemptive operation.
- Explicit syscall entry paths (`INT 0x80`, `SYSENTER`).
- Descriptor-ring networking on supported NICs.
- Differential JIT/interpreter tooling to catch semantic drift.
- Bounded protocol and parser workflows in CapNet and WASM paths.

Suggested measurement commands for reproducible local baselines:

- `cpu-bench`
- `wasm-jit-bench`
- `sched-net-soak <seconds> [probe_ms]`
- `capnet-fuzz-soak <iters> <rounds>`
- `wasm-jit-fuzz-soak <iters> <rounds>`

## Documentation Map

- [Vision](docs/oreulia-vision.md)
- [MVP Specification](docs/oreulia-mvp.md)
- [Capabilities](docs/oreulia-capabilities.md)
- [IPC](docs/oreulia-ipc.md)
- [Persistence](docs/oreulia-persistence.md)
- [Filesystem](docs/oreulia-filesystem.md)
- [WASM ABI](docs/oreulia-wasm-abi.md)
- [Temporal Adapters + Durable Persistence](docs/oreulia-temporal-adapters-durable-persistence.md)
- [JIT Security Resolution](docs/oreulia-jit-security-resolution.md)
- [CapNet Scientific Resolution](docs/capnet.md)
- [Intent Graph Predictive Revocation](docs/oreulia-intent-graph-predictive-revocation.md)
- [Function/Service Pointer Capabilities](docs/oreulia-service-pointer-capabilities.md)
- [WASM JIT Pairwise Transition Coverage](docs/oreulia-wasm-jit-pairwise-transition-coverage.md)
- [WASM/WASI ABI Reference](docs/oreulia-wasm-abi.md)
- [Assembly Quick Reference](docs/assembly-quick-reference.md)
- [Code Page Header](docs/codepageheader.md)
- [Commercial Use Cases](docs/CommercialUseCases.md)
- [Contributing Guide](docs/CONTRIBUTING.md)
- [Contributor License Terms](CONTRIBUTOR-LICENSE.md)

## Project Layout

```text
oreulia/
├── kernel/              # Kernel source, asm, linker, build/run scripts
│   ├── src/             # Grouped Rust subsystems (`capability/`, `drivers/`, `execution/`, `fs/`, `memory/`, `platform/`, `scheduler/`, `security/`, `services/`, `shell/`, `temporal/`, …)
│   ├── ci/              # 14 shell CI scripts (smoke/extended/soak × i686/x86_64/AArch64)
│   ├── fuzz/            # WASM and CapNet fuzz corpus
│   └── iso/             # ISO build artifacts
├── docs/                # Formal and technical documentation
├── services/            # Service prototypes / planned expansions
│   └── telemetry_daemon/
├── wasm/                # WASM modules and examples
│   └── sdk/             # Rust no_std SDK crate (15 modules, IDs 0–131)
│       └── src/
│           ├── lib.rs   # Module declarations
│           ├── capgraph.rs, entangle.rs, policy.rs, mesh.rs, …
│           └── raw/     # oreulia.rs + wasi.rs FFI stubs
├── verification/        # Formal verification specs, proofs, and artifacts
│   ├── spec/
│   ├── proof/
│   ├── theories/
│   └── mapping/
├── ThingsYetToDo/       # Design notes and roadmap documents
├── CONTRIBUTOR-LICENSE.md
├── COMMERCIAL.md
├── README.md            # This file
└── LICENSE
```

## Contributing

Contributions are welcome for architecture, verification, runtime hardening, and subsystem correctness.

1. Fork the repository.
2. Create a branch.
3. Implement and test.
4. Open a pull request with rationale and evidence.

Inbound contributor rights are defined in
[CONTRIBUTOR-LICENSE.md](CONTRIBUTOR-LICENSE.md).

## License

Public use is licensed under [LICENSE](LICENSE). Commercial deployment is
described in [COMMERCIAL.md](COMMERCIAL.md). Inbound contribution rights are in
[CONTRIBUTOR-LICENSE.md](CONTRIBUTOR-LICENSE.md).

## Contact

`reeveskeefe@gmail.com`

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) and [NASM](https://www.nasm.us/)
- Bootable with [GRUB](https://www.gnu.org/software/grub/)
- Tested with [QEMU](https://www.qemu.org/)
- Inspired by capability-oriented system design traditions

<div align="center">

**Made by Keefe Reeves and contributors in the Oreulia community**

</div>
