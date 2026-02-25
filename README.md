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

[Why It Is Different](#why-it-is-different) • [Portability](#platform-and-portability-status) • [Architecture](#architecture) • [Cross-Arch Internals](#cross-architecture-implementation) • [Verification](#verification-and-hardening) • [Build](#build-and-run) • [Commands](#command-taxonomy) • [Docs](#documentation-map)

</div>

<div align="center">
<img src="oreuliuswhitebackground.png" width="640" alt="Oreulia kernel logo">
</div>

## Overview

Oreulia is an experimental kernel that treats capabilities, temporal/versioned kernel state, and WebAssembly execution as first-order primitives.

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
<img src="opencommandlineinterface.png" width="640" alt="Oreulia shell interface">
</div>

## Why It Is Different

| Area | What Oreulia Does | Why It Matters |
|---|---|---|
| Capability model | Access is explicitly delegated via capabilities, not global privilege assumptions. | Reduces blast radius and makes authority flow auditable. |
| Temporal objects | Kernel objects are versioned with rollback, branching, and merge semantics. | Enables recovery, provenance, and deterministic investigation. |
| WASM execution | Interpreter + JIT path with hardening and differential validation. | High execution flexibility with safety-focused guardrails. |
| CapNet control plane | Capability delegation extends over network peers with attestation and replay guards. | Portable authority transfer without ambient trust. |
| In-kernel verification | Shell commands run formal checks, targeted hardening tests, and fuzz corpus replay. | Reproducible evidence of invariants at runtime. |

## Feature Snapshot

- Capability-based security and explicit authority flow.
- Intent graph predictive revocation and runtime policy control.
- Service/function pointer capabilities for typed WASM invocation.
- CapNet tokenized cross-peer capability delegation.
- Temporal object persistence, branching, rollback, and merge.
- WebAssembly runtime with JIT toggle, threshold tuning, and fuzz tooling.
- IPC channels, service registry, VFS, scheduler, network stack, and enclave state integration.
- Formal verification and corpus-driven fuzzing commands available in shell.

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
- [Commercial Use Cases](docs/CommercialUseCases.md)
- [Contributing Guide](docs/CONTRIBUTING.md)

## Project Layout

```text
oreulia/
├── kernel/              # Kernel source, asm, linker, build/run scripts
├── docs/                # Formal and technical documentation
├── services/            # Service prototypes / planned expansions
├── wasm/                # WASM modules and examples
├── README.md            # This file
└── LICENSE
```

## Contributing

Contributions are welcome for architecture, verification, runtime hardening, and subsystem correctness.

1. Fork the repository.
2. Create a branch.
3. Implement and test.
4. Open a pull request with rationale and evidence.

## License

Licensed under the terms in [LICENSE](LICENSE).

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
