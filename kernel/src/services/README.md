# `kernel/src/services` — In-Kernel Service Layer

> **Important distinction**: This directory is NOT the same as `/services` at the repository root.
>
> - `/services` (repository root) — **host-side / out-of-band daemons** that run on the host machine alongside QEMU, communicate with the kernel over UNIX sockets, and use the full Rust `std` library (e.g. `telemetry_daemon`).
> - `kernel/src/services` (this directory) — **in-kernel Ring-0 service infrastructure** compiled directly into the kernel binary as `#[no_std]` Rust, executing inside the kernel's memory space with the same trust level as the scheduler and capability manager.

---

## Purpose

`kernel/src/services` implements the **kernel-resident layer of Oreulius's service architecture**. It defines what a "service" means inside the OS, how services register themselves, how consumers discover them, how the kernel tracks their health, how firmware is updated atomically across A/B slots, how the kernel attests its own runtime state to remote peers, and how WASM programs are mapped onto the full WASI Preview 1 ABI using Oreulius's capability model.

The philosophy throughout is **no ambient authority**: services are not global names in a flat namespace. They are capability-mediated resources discovered through explicit *introduction* protocols. A process cannot access the filesystem service by importing a module — it must hold a valid `ServiceIntroductionCapability` and request an introduction from a registered introducer.

---

## Why In-Kernel (Not Userspace)

These services must live inside the kernel because:

1. **They own trusted kernel state.** The service registry holds the authoritative table of what services are alive and which processes may introduce connections to them. That table cannot live in a process that can crash or be killed.
2. **OTA and attestation require cryptographic access to the platform.** The `fleet` and `ota` modules read crash logs, slot hashes, and boot measurement data that are only trustworthy when computed by code that cannot be tampered with from userspace.
3. **WASI ABI mapping is a kernel responsibility.** WASM modules running inside the kernel sandbox need their filesystem, clock, and I/O calls resolved by the kernel before the WASM instruction pointer moves. There is no intermediary.
4. **Health telemetry must be zero-latency.** `health.rs` takes a snapshot directly from scheduler counters, IPC tables, filesystem stats, and the persistence log in one lock-guarded pass. Routing this through IPC would introduce race windows.

---

## Source Layout

| File | Architecture | Role |
|---|---|---|
| `mod.rs` | All | Conditional module exports |
| `registry.rs` | All | Service registration, introduction protocol, capability-gated discovery |
| `health.rs` | x86-64 | `HealthSnapshot` aggregator, crash log, health history |
| `fleet.rs` | x86-64 | Attestation bundles, remote diagnostics, fleet trust key management |
| `ota.rs` | x86-64 | A/B slot OTA update manager with SHA-256 manifest verification |
| `telemetry.rs` | All | Lock-free `TelemetryQueue` — bridges Ring-0 observations to the out-of-band math daemon |
| `wasi.rs` | x86-64 | Full WASI Preview 1 ABI implementation over Oreulius capabilities |

Note: `fleet.rs`, `health.rs`, `ota.rs`, and `wasi.rs` are conditionally compiled only on `not(target_arch = "aarch64")`. `registry.rs` and `telemetry.rs` compile on all targets.

---

## `registry.rs` — Capability-Gated Service Discovery

### Design Principles

The registry implements a **no-ambient-authority introduction protocol**:

- No process can look up a service by name and obtain access. There is no `open("/dev/network")`.
- Services must be registered with an explicit `ServiceOffer` proving the registering process holds a `ServiceIntroductionCapability` with adequate rights.
- Consumers request introductions through a registered `Introducer`. The introducer's capability controls which service types it can introduce, which namespaces it can mediate, and how many total introductions it is allowed to make.
- Every introduction is recorded and auditable. Introduction rights can be attenuated and further delegated with strictly fewer permissions.

### Registered Service Types

| `ServiceType` | Tag | Description |
|---|---|---|
| `Filesystem` | `1` | VFS / flat-FS access |
| `Persistence` | `2` | Append-only log and snapshot store |
| `Network` | `3` | TCP/UDP stack |
| `Timer` | `4` | Monotonic clock |
| `Console` | `5` | Output streams (capability-gated) |
| `Temporal` | `6` | Versioned state system |
| `Compositor` | `7` | Display / framebuffer compositor |
| `BrowserBackend` | `8` | TLS, fetch, origin model, cookies |
| `Custom(u32)` | `1000+` | User-defined extensible types |

### Capacity Limits

| Constant | Value | Meaning |
|---|---|---|
| `MAX_SERVICES` | `64` | Total simultaneously registered services |
| `MAX_INTRODUCERS` | `32` | Total registered introducer records |
| `MAX_INTRODUCTIONS_DEFAULT` | `100` | Default per-introducer introduction quota |

### Key API

| Function | Description |
|---|---|
| `register_service(offer)` | Register a service offer from a holding provider |
| `request_introduction(request)` | Request mediated access to a registered service |
| `ServiceIntroductionCapability::root(...)` | Create a root introduction capability |
| `ServiceIntroductionCapability::restricted(...)` | Create an attenuated child cape |
| `ServiceIntroductionCapability::attenuate(...)` | Further restrict an existing capability |

---

## `health.rs` — System Health Telemetry

Provides a live **`HealthSnapshot`** — a point-in-time cross-subsystem health report captured atomically inside the kernel.

### `HealthSnapshot` Fields

| Category | Fields |
|---|---|
| Identity | `tick`, `boot_session` |
| Scheduler | `total_processes`, `running_processes`, `ready_processes`, `sleeping_processes`, `total_context_switches`, `preemptions`, `voluntary_yields` |
| Crashes | `crash_count` |
| Flat Filesystem | `fs_file_count`, `fs_total_bytes`, `fs_total_ops`, `fs_perm_denials` |
| IPC | `ipc_channel_count`, `ipc_channel_max` |
| Persistence | `persist_records`, `persist_bytes` |
| Network | `net_rx_packets`, `net_tx_packets`, `net_rx_bytes`, `net_tx_bytes` |

### Shell Commands

| Command | Description |
|---|---|
| `health` | Print a live `HealthSnapshot` to VGA/serial |
| `health-history` | List persisted `HealthSnapshot` records from the persistence log |
| `crash-log-show` | Display the crash ring buffer |
| `crash-log-clear` | Clear the crash ring buffer |

Snapshots are persisted via `persistence::emit_snapshot()` so health history is recoverable across reboots through the temporal replay engine.

---

## `fleet.rs` — Attestation & Remote Diagnostics

Implements **hardware-rooted attestation** and a remote diagnostics surface for fleet management of Oreulius nodes.

### Attestation

An attestation bundle is a SHA-256 measurement hash over 56 bytes of runtime state:

| Offset | Field | Size |
|---|---|---|
| `[0..8]` | `boot_tick` | u64 LE |
| `[8..12]` | `crash_count` | u32 LE |
| `[12..16]` | `boot_session` | u32 LE |
| `[16..48]` | `active_slot_hash` | [u8; 32] |
| `[48..56]` | `sched_switches` | u64 LE |

The 32-byte SHA-256 measurement hash + boot metadata is stored as an `AttestationRecord` in the persistence log (40-byte binary payload) and can be sent to a CapNet peer via `fleet-attest <peer-id>`.

Attestation records can be verified offline using a stored Ed25519 public key (`/fleet/attest.pub`). Signature verification is performed by `verify_detached_ed25519` from the kernel's `crypto` module.

### Shell Commands

| Command | Description |
|---|---|
| `fleet-attest <peer-id>` | Build measurement, sign, send to CapNet peer |
| `fleet-attest-export` | Persist attestation record and message to VFS |
| `fleet-attest-verify` | Verify stored attestation against trust key |
| `fleet-trust-key <hex>` | Import an Ed25519 attestation public key |
| `fleet-set-signature <hex>` | Set a detached signature for verification |
| `fleet-diag` | One-screen diagnostic: CapNet peers + crash ring + health + OTA slot |

---

## `ota.rs` — A/B Slot Over-the-Air Update Manager

Implements **atomic A/B image slot management** for firmware updates.

### Slot Layout (VFS paths)

| Path | Contents |
|---|---|
| `/ota/slot_a` | Image binary for slot A |
| `/ota/slot_b` | Image binary for slot B |
| `/ota/active` | `"a"` or `"b"` — currently active slot |
| `/ota/manifest` | Expected SHA-256 hex (64 ASCII bytes) of the pending image |
| `/ota/manifest.sig` | Ed25519 detached signature over the manifest |
| `/ota/manifest.pub` | Ed25519 public key for manifest verification |
| `/ota/version` | Staged image version string (up to 32 ASCII bytes) |
| `/ota/rollback_needed` | Rollback sentinel written on boot if crash detected |

### Update Lifecycle

```
ota-apply <vfs-path>   →  Copy image into inactive slot,
                           compute SHA-256, write /ota/manifest,
                           mark OtaPhase::Apply in persistence log.

ota-commit             →  Verify pending slot against manifest hash,
                           switch /ota/active pointer,
                           write OtaPhase::Commit in persistence log.

ota-rollback           →  Revert /ota/active to the other slot,
                           write OtaPhase::Rollback in persistence log.
```

### Shell Commands

| Command | Description |
|---|---|
| `ota-status` | Show A/B slot state, active pointer, and manifest hash |
| `ota-apply <vfs-path>` | Stage an image into the inactive slot |
| `ota-commit` | Verify and activate the pending slot |
| `ota-rollback` | Revert to the previously active slot |
| `ota-trust-key <hex>` | Import OTA manifest verification public key |
| `ota-set-signature <hex>` | Set a detached signature for the manifest |

If a crash is detected at boot, `init_slots()` writes the rollback sentinel and `verify_boot_image()` can trigger an automatic `ota-rollback` before any user interaction.

---

## `telemetry.rs` — Lock-Free Ring-0 → Out-of-Band Bridge

This is the **kernel-side half** of the telemetry pipeline. It is the bridge between Ring-0 observations and the `telemetry_daemon` running in `/services/telemetry_daemon` on the host.

The kernel cannot perform floating-point CTMC matrix computations or run `nalgebra` inside Ring-0. Instead:

1. The kernel appends `ScalarTensor<i32, 128>` state observations to the global `TelemetryQueue` using atomic Compare-And-Swap (`AtomicUsize`) — fully wait-free, zero locks in the fast path.
2. The queue (`QUEUE_SIZE = 128` entries, constant-size ring) drains into the UART/serial output which QEMU bridges to the host UNIX socket.
3. The out-of-band `telemetry_daemon` (in `/services/telemetry_daemon`) consumes those entries, runs the CTMC mathematics, and sends capability revocations back via the same socket.

This module deliberately contains no floating-point, no `std`, and no dynamic allocation. It is an eBPF-style bounded ring with atomic head/tail cursors.

---

## `wasi.rs` — WASI Preview 1 ABI over Oreulius Capabilities

Enables WASM binaries compiled for **WASI Preview 1** (musl-libc, WASI-SDK, Emscripten) to run inside the Oreulius WASM sandbox **unmodified**, by mapping all 55+ WASI syscall functions onto the kernel's capability model.

### Design

- Every WASI function has the signature `fn(&mut WasiCtx, ...) -> Errno`.
- `WasiCtx` holds per-instance state: an fd table, a list of preopened directory capabilities, and a clock epoch offset.
- All file I/O routes through `crate::capability` and `crate::fs` (no direct memory access).
- All clock functions route through the kernel timer service.
- Network I/O routes through `crate::net::rtl8139` for raw socket access.
- **No heap allocations in the hot path** — the fd table and preopened dir table are fixed-size arrays.

### WASM Host Function IDs (45–99)

| ID Range | Functions |
|---|---|
| `45–48` | `args_get`, `args_sizes_get`, `environ_get`, `environ_sizes_get` |
| `49–50` | `clock_res_get`, `clock_time_get` |
| `51–71` | All `fd_*` operations: `fd_close`, `fd_read`, `fd_write`, `fd_seek`, `fd_stat`, `fd_pread`, `fd_pwrite`, `fd_readdir`, `fd_prestat_get`, `fd_prestat_dir_name` |
| `72–80` | All `path_*` operations: `path_open`, `path_create_directory`, `path_filestat_get`, `path_rename`, `path_unlink_file`, `path_remove_directory` |
| `81–85` | `poll_oneoff`, `proc_exit`, `proc_raise`, `sched_yield`, `random_get` |
| `86–89` | `sock_accept`, `sock_recv`, `sock_send`, `sock_shutdown` |
| `90–99` | Oreulius extensions and reserved |

No-op stubs are provided for WASI functions that map to features outside the current kernel scope (`fd_advise`, `fd_allocate`, `fd_datasync`, `path_link`, `path_readlink`) to ensure ABI compatibility without breaking the import table.
