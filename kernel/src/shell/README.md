# `kernel/src/shell` — In-Kernel Interactive Shell

## Purpose

The `shell` module is the **interactive operator interface built directly into the Oreulia kernel**. It is not a userspace shell process. It runs inside Ring-0 during the active execution loop and provides a command-line interface over the VGA text buffer (and optionally the serial port) that exposes the entire kernel subsystem surface to direct inspection and manipulation.

The shell exists because Oreulia is a research and systems kernel. During development and verification, every subsystem — the scheduler, IPC, temporal versioning, capability graphs, CapNet, WASM execution, filesystem, network stack, and security layer — needs to be exercisable interactively without booting a full userspace. The shell is that interface. When the kernel boots, you get a prompt. Every command dispatched through that prompt is a direct native kernel call.

The shell is *not* a POSIX shell. There is no `fork`/`exec` process spawning for commands. There are no environment variables, no piping, no shell scripting. Commands are matched by string prefix inside a monolithic `execute(input: &str)` dispatcher and call internal kernel functions directly.

---

## Why It Lives Inside the Kernel

1. **No userspace ABI yet**: The ability to run userspace processes and route their I/O is still being built. The shell fills the gap, making the kernel immediately interactive.
2. **Direct subsystem access**: Commands like `temporal-rollback`, `cap-list`, `svc-stats`, `security-audit` call the exact same functions that kernel internals call. There is no translation layer, no IPC dispatch — results are immediate and authoritative.
3. **Debugging without a debugger**: Under QEMU, attaching `gdb` for interactive subsystem checks is cumbersome. The shell lets you run `cap-arch`, `sched-stats`, `ipc-recv`, `asm-test` and see live kernel state without a second tool.
4. **Capability-gated I/O**: Even the print path goes through a capability-verified console service (`console_service.rs`), demonstrating the capability model works correctly before any application trust is established.

---

## Platform Split: x86-64 vs AArch64

Module compilation is architecture-conditional:

| File | Compiled When | Role |
|---|---|---|
| `commands.rs` | `not(aarch64)` | Full x86-64 command set (~13,000 lines) |
| `advanced_commands.rs` | `not(aarch64)` | Quantum scheduler / allocator diagnostic commands |
| `commands_aarch64.rs` | `aarch64` | Reduced command set for the `aarch64-virt` QEMU target |
| `commands_shared.rs` | All architectures | Shared VFS and filesystem commands used by both targets |
| `terminal.rs` | `not(aarch64)` | Virtual terminal multiplexer (6 terminals, VGA-backed) |
| `console_service.rs` | `not(aarch64)` | Capability-gated console object management |
| `mod.rs` | All | Conditional re-exports per target |

On `aarch64`, `commands_shared` is the shared baseline and `commands_aarch64` provides the platform-specific surface, with `use commands_aarch64 as commands` aliasing ensuring the rest of the kernel sees a uniform API.

---

## Source File Descriptions

### `commands.rs`
The main command dispatcher for x86-64. The entry point is:

```rust
pub fn execute(input: &str)
```

The function splits input on whitespace, matches the first token against a large `match` arm, and calls the appropriate `cmd_*` function. Unrecognised input prints `unknown command: <input>`. All output goes through `vga::print_str` or the `VgaWriter` implementation of `core::fmt::Write`.

### `advanced_commands.rs`
An addendum file hosting diagnostic commands for the quantum scheduler, memory allocator, and related kernel hardening features. Exported as `pub fn` and called from `commands.rs`'s dispatch table.

### `commands_shared.rs`
Cross-architecture VFS and filesystem command handlers. Used by both the x86-64 shell and the AArch64 shell. Implements `parse_u64_auto` (hex and decimal), `write_line`, and the full VFS command surface (`vfs-mkdir`, `vfs-ls`, `vfs-open`, `vfs-read`, `vfs-write`, `vfs-close`).

### `commands_aarch64.rs`
A reduced command surface targeting the AArch64 QEMU virtual machine, where several x86-64 specific subsystems (PCI, VirtIO block, legacy net stack) are absent.

### `terminal.rs`
A software virtual terminal multiplexer. Controls `TERM_COUNT = 6` independent terminal views backed by VGA memory. Manages switching between terminal contexts using raw `pushfq`/`cli`/`popfq` sequences for interrupt safety, without depending on the `x86_64` crate.

### `console_service.rs`
Implements **capability-gated console objects**. Unlike POSIX where `stdout` is an ambient resource available to any process, Oreulia requires an explicit `Console` capability token to write output. This module stores up to `MAX_CONSOLES = 16` active console objects. Each `Console` is owned by a `ProcessId` and has per-object `write_count` / `read_count` statistics. Access is checked against the capability manager before any I/O operation proceeds.

---

## Command Categories

The full command surface is grouped by subsystem:

### Filesystem & VFS

| Command | Description |
|---|---|
| `fs-write <path> <data>` | Write to the flat filesystem |
| `fs-read <path>` | Read bytes from flat FS |
| `fs-delete <path>` | Delete a flat FS file |
| `fs-list` | List all flat FS files |
| `fs-stats` | Flat FS usage statistics |
| `fs-scrub` | Integrity scrub over flat FS |
| `vfs-mkdir <path>` | Create a VFS directory |
| `vfs-write <path> <data>` | Write a VFS file |
| `vfs-read <path>` | Read a VFS file |
| `vfs-ls <path>` | List VFS directory |
| `vfs-open <path>` | Open a VFS file descriptor |
| `vfs-readfd <fd>` | Read from an open FD |
| `vfs-writefd <fd> <data>` | Write to an open FD |
| `vfs-close <fd>` | Close an open FD |
| `vfs-mount-virtio <dev>` | Mount a VirtIO block device |
| `cat <path>` | Print a VFS file to screen |
| `rm <path>` | Remove a VFS file |
| `cp <src> <dst>` | Copy a VFS file |
| `stat <path>` | Show VFS file metadata |

### Temporal State

| Command | Description |
|---|---|
| `temporal-write <path> <data>` | Record a Write version for a temporal object |
| `temporal-snapshot <path>` | Record a full Snapshot version |
| `temporal-history <path>` | List all versions for an object |
| `temporal-read <path> <version>` | Read payload of a specific version |
| `temporal-rollback <path> <version>` | Roll back object to a previous version |
| `temporal-branch-create <path> <name>` | Fork a version branch |
| `temporal-branch-list <path>` | List all branches for an object |
| `temporal-branch-checkout <path> <name>` | Switch to a branch |
| `temporal-merge <path> <src> <dst>` | Merge two branches |
| `temporal-stats` | Global temporal store statistics |
| `temporal-retention <max-v> <max-bytes>` | Set GC retention policy |
| `temporal-ipc-demo` | End-to-end IPC + temporal round-trip demo |

### IPC Channels

| Command | Description |
|---|---|
| `ipc-create` | Create a new IPC channel pair |
| `ipc-send <channel> <data>` | Send a message over a channel |
| `ipc-recv <channel>` | Receive a message from a channel |

### Processes & ELF / WASM Execution

| Command | Description |
|---|---|
| `elf-run <vfs-path>` | Load and execute a static ELF binary |
| `wasm-run <vfs-path>` | Load and execute a WASM module |
| `fork-test` | Spawn child processes via fork |
| `user-test` | Launch a minimal userspace test process |

### Scheduler

| Command | Description |
|---|---|
| `sched-stats` | Print scheduler run-queue and context-switch statistics |
| `sleep <ms>` | Put the shell process to sleep |
| `uptime` | Print kernel uptime in ticks |
| `sched-net-soak <n>` | Run a combined scheduler + network stress test |

### Capabilities

| Command | Description |
|---|---|
| `cap-list` | List all active capability tokens |
| `cap-test-attenuation` | Demonstrate capability attenuation |
| `cap-test-console` | Exercise console capability creation/use |
| `cap-arch` | Print the capability architecture summary |

### Security & Intent Graph

| Command | Description |
|---|---|
| `security-stats` | Print intent graph statistics |
| `security-anomaly` | Trigger and detect an anomalous intent event |
| `security-intent <pid> <node>` | Record a manual intent observation |
| `security-intent-policy <args>` | Configure intent policy thresholds |
| `security-intent-clear <pid>` | Reset intent observations for a PID |
| `security-audit <args>` | Run a security audit pass |
| `security-test` | Full security subsystem smoke test |

### Services & Registry

| Command | Description |
|---|---|
| `svc-list` | List all registered kernel services |
| `svc-register <type>` | Register a new service |
| `svc-stats` | Service registry statistics |
| `svc-request <type>` | Request a service connection |

### Fleet & OTA

| Command | Description |
|---|---|
| `fleet-attest <peer>` | Build and send an attestation bundle to a CapNet peer |
| `fleet-attest-export` | Export attestation record to VFS |
| `fleet-attest-verify` | Verify a stored attestation against the public key |
| `fleet-trust-key <hex>` | Import a fleet attestation public key |
| `fleet-diag` | Remote diagnostics: CapNet + crash ring + health + OTA snapshot |
| `ota-status` | Show current A/B slot state and manifest hash |
| `ota-apply <path>` | Stage a new firmware image into the inactive slot |
| `ota-commit` | Verify and activate the pending OTA slot |
| `ota-rollback` | Revert to the previously active OTA slot |

### Health

| Command | Description |
|---|---|
| `health` | Print a live `HealthSnapshot` across all kernel subsystems |
| `health-history` | Show persisted health snapshot records |

### Network

| Command | Description |
|---|---|
| `wifi-status` | Print Wi-Fi interface state |
| `http-get <url>` | Issue an HTTP GET request |
| `http-server-start <port>` | Start the built-in HTTP server |
| `http-server-stop` | Stop the HTTP server |
| `dns-resolve <hostname>` | Resolve a hostname |
| `eth-status` | Ethernet interface status |
| `eth-info` | Ethernet driver details |
| `netstack-info` | Full network stack statistics |

### Hardware & Low-Level

| Command | Description |
|---|---|
| `pci-list` | Enumerate PCI devices |
| `blk-info` | VirtIO block device info |
| `blk-partitions` | Print partition table |
| `blk-read <lba> <count>` | Read raw sectors |
| `blk-write <lba> <data>` | Write raw sectors |
| `cpu-info` | CPUID features and capabilities |
| `cpu-benchmark` | CPU throughput benchmark |
| `asm-test` | Assembly routine integration test |
| `atomic-test` | Atomic operations correctness test |
| `spinlock-test` | Spinlock contention test |
| `paging-test` | Paging subsystem integrity test |
| `syscall-test` | Syscall entry/exit round-trip test |

### Advanced Diagnostic (`advanced_commands.rs`)

| Command | Description |
|---|---|
| `quantum-stats` | Quantum scheduler entropy and scheduling statistics |
| `sched-entropy-bench` | Scheduler entropy source benchmark |
| `alloc-stats` | Heap allocator utilization and fragmentation |
| `leak-check` | Check for detected heap allocation leaks |
| `futex-test` | Futex wait/wake correctness test |
| `update-frag` | Simulate allocator update fragmentation |

---

## Terminal Multiplexer (`terminal.rs`)

The virtual terminal system maintains `TERM_COUNT = 6` independent terminal buffers in VGA memory. Key properties:

- Terminal switches are interrupt-safe: `cli`/`sti` are emitted via inline assembly using `pushfq`/`popfq` patterns, without importing the `x86_64` crate.
- Each terminal has a cursor position, an 80x25 character buffer, and a foreground/background `Color` pair.
- The shell prompt is written into the active terminal; switching terminals does not disturb the current input line in progress.

---

## Console Capability Model (`console_service.rs`)

Console I/O in Oreulia is **not ambient**. A process must hold a `Console` capability with `Rights::Write` to write to any output stream. This module:

1. Allocates `Console` objects (up to `MAX_CONSOLES = 16`) with `object_id` and `owner` fields.
2. Issues `OreuliaCapability` tokens of type `CapabilityType::Console` via the central capability manager.
3. Before every write, the capability manager verifies token validity and rights membership.
4. All console creation and state changes are recorded through the temporal system (`record_console_event`).

This design ensures that even the most basic I/O in Oreulia is observable, auditable, and revocable — stdout can be taken away from a process the same way any other capability can.
