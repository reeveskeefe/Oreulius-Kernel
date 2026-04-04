# Oreulius Kernel

Oreulius is a capability-native, WASM-first kernel for isolated workloads with temporal state and verification-oriented control surfaces.

## Start Here

If you are landing on this repository for the first time, use this path:

1. build and boot the recommended target: `i686`
2. run one capability command
3. run one temporal command
4. then decide whether you want architecture, verification, or ABI depth

Recommended first-run path:

```bash
cd kernel
./build.sh
./run.sh
```

Then, in the shell:

```text
cap-test-atten
temporal-write /tmp/demo alpha
temporal-snapshot /tmp/demo
temporal-history /tmp/demo
```

That path gives the fastest "aha" moment in this repo:

- authority is capability-mediated rather than ambient
- state is versioned and inspectable rather than silently overwritten

<div align="center">

[![Written in Rust](https://img.shields.io/badge/written%20in-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: Oreulius](docs/assets/oreulius-license-badge.svg)](LICENSE)
[![Multiarch QEMU Smoke](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-smoke.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-smoke.yml)
[![Proof Check](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/proof-check.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/proof-check.yml)

[Start Here](#start-here) • [One-Minute Demo](#one-minute-demo) • [Architecture](#architecture-at-a-glance) • [Verification](#verification-status) • [Build](#build-and-run) • [Docs](#documentation-map)

</div>

<div align="center">
<img src="docs/assets/oreuliuswhitebackground.png" width="640" alt="Oreulius kernel logo">
</div>

## Important

this is going through some final bug fixes and finalizations before being snapshot into the alpha release. I would not consider this project complete, but it is near completion trajectory

## Overview

Oreulius boots on `i686`, `x86_64`, and `AArch64`, exposes a shell surface for kernel services, runs WASM workloads, enforces capability-mediated access, and tracks temporal object history inside the kernel.

It is aimed at systems research, security-sensitive service design, and deterministic debugging. It is not a POSIX/Linux replacement, not a desktop OS, and not a general-purpose native compatibility layer.

Oreulius is source-available under the Oreulius Community License. The public license allows research, evaluation, modification, public forks, benchmarking, and non-commercial distribution. Commercial deployment and production use require a separate written agreement. See [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).

### What This Is and What It Is Not

| This is | This is not |
|---|---|
| A WASM-first kernel for isolated workloads | A POSIX or Linux replacement |
| Capability-native: no ambient authority | A general-purpose OS for arbitrary native code |
| Built for auditable authority flow and replayable state | A hypervisor or virtualization host |
| Designed for deterministic investigation and systems research | A hard-real-time kernel |
| A platform for temporal objects, verification surfaces, and capability experiments | A drop-in container runtime |

## Who This Is For

- systems researchers exploring capability-native kernels, replay, or temporal state
- kernel and security engineers who want a real codebase for authority flow, JIT hardening, and verification posture
- people evaluating WASM-first execution models outside the usual POSIX/container path
- contributors who want runnable CI, explicit verification material, and real subsystem depth

This repository is not optimized for readers whose main goal is to find a Linux-compatible desktop or server OS.

## Why It Matters

Most systems treat authority, replay, and verification as separate layers. Oreulius treats them as part of the runtime model itself.

That changes where the system draws its hard boundaries:

- authority changes are explicit and inspectable
- temporal history is part of the object model
- JIT execution is paired with hardening and validation, not treated as an opaque fast path
- verification is exposed as a discipline with artifacts, assumptions, evidence, and runnable checks

## One-Minute Demo

If you want a minimal "show me" path before reading the rest of the repo, boot the recommended `i686` target and run:

```text
cap-test-atten
temporal-write /tmp/demo alpha
temporal-snapshot /tmp/demo
temporal-history /tmp/demo
formal-verify
```

What this demonstrates:

- `cap-test-atten` shows the capability model enforcing rights attenuation instead of ambient privilege
- the `temporal-*` sequence shows state turning into history, not just mutation
- `formal-verify` shows that verification is a live kernel surface, not only an external whitepaper claim

<div align="center">
<img src="docs/assets/opencommandlineinterface.png" width="640" alt="Oreulius serial shell after boot">
</div>

<div align="center">
<sub>Oreulius serial shell after boot. This is the surface exercised by the smoke, network, and verification flows.</sub>
</div>

## Recommended First Run

For onboarding, the recommended path is `i686`.

Why `i686` first:

- it remains the most complete runtime-rich path
- it has the most direct shell-oriented bring-up story
- it is the least surprising place to see capability, temporal, and verification commands behave end to end

Also available:

- `x86_64` for the modern Multiboot2 + GRUB bring-up shell path
- `AArch64` for the QEMU `virt` raw `Image` + DTB serial shell path

## Architecture At A Glance

| Arch | Role | First-Run Recommendation | Current Surface |
|---|---|---|---|
| `i686` | default onboarding path | Recommended first run | Most complete runtime path |
| `x86_64` | modern bring-up path | Recommended after first success | Multiboot2 + GRUB + serial shell |
| `AArch64` | alternate bring-up / portability path | Advanced / alternate target | QEMU `virt` + DTB + PL011 shell |

## Repository Map

- [`kernel/`](kernel/README.md) — kernel source, asm, build scripts, launchers, CI runners
- [`docs/`](docs/README.md) — architecture, runtime, capability, storage, and contributor documentation
- [`verification/`](verification/README.md) — proofs, assumptions, mapping, runtime evidence, and verification governance
- [`wasm/`](wasm/README.md) — guest-side SDK and example WASM workloads
- [`services/`](services/README.md) — out-of-band or userspace-adjacent service prototypes

## Verification Status

Oreulius treats verification as a scoped engineering claim, not a blanket marketing statement.

Current posture:

- mechanized proof material lives under [`verification/`](verification/README.md)
- staged targets and whole-system claim boundaries live in [`VERIFICATION_TARGET_MATRIX.md`](VERIFICATION_TARGET_MATRIX.md)
- CI continuously checks smoke, network, JIT, CapNet, and proof-governance surfaces
- the project does **not** currently claim full whole-system verification across all architectures, low-level assembly boundaries, and hardware/toolchain assumptions

If you want the deeper verification story, start with:

- [`verification/README.md`](verification/README.md)
- [`VERIFICATION_TARGET_MATRIX.md`](VERIFICATION_TARGET_MATRIX.md)
- [`verification/proof/THEOREM_INDEX.md`](verification/proof/THEOREM_INDEX.md)

## Why It Is Different

| Area | What Oreulius Does | Why It Matters |
|---|---|---|
| Capability model | Access is explicitly delegated via capabilities, not global privilege assumptions. | Reduces blast radius and makes authority flow auditable. |
| Temporal objects | Kernel objects are versioned with rollback, branching, and merge semantics. | Enables recovery, provenance, and deterministic investigation. |
| WASM execution | Interpreter + JIT path with hardening and differential validation. | High execution flexibility with safety-focused guardrails. |
| CapNet control plane | Capability delegation extends over network peers with attestation and replay guards. | Portable authority transfer without ambient trust. |
| In-kernel verification | Shell commands run formal checks, targeted hardening tests, and fuzz corpus replay. | Reproducible evidence of invariants at runtime. |

### Deeper Technical Positioning

Oreulius is designed for workloads and experiments where authority boundaries, replayability, and runtime evidence matter as much as raw feature breadth.

The kernel is intentionally opinionated:

- capability-mediated access is preferred over ambient access
- temporal state is treated as a first-class system concern
- WASM is the primary guest execution model
- verification and hardening are treated as operational surfaces

### Advanced Features

These are part of the project’s technical depth, but they are not the best place to start if you are still building a first mental model:

| Area | What Oreulius Does | Why It Matters |
|---|---|---|
| Polyglot WASM runtime | WASM modules can register and resolve cross-language type bindings at runtime (IDs 103–105). | Multiple WASM language toolchains coexist in the same process without a global type registry. |
| Kernel-mesh networking | Capability tokens are minted, routed, and migrated across an in-kernel peer mesh (IDs 109–115). | Authority delegation survives process migration and cross-node transfer without re-negotiation. |
| Observer / event bus | Host-visible capability event subscriptions with filtered delivery (IDs 106–108). | Audit and reactive policy without polling loops or extra syscalls. |
| Temporal capability checkpoints | Capabilities carry their own temporal checkpoint; rollback rewinds both state and access rights (IDs 116–120). | A revocation that happens after a checkpoint can be replayed rather than silently accepted. |
| Policy contracts | Named policy objects bind to capabilities and are evaluated inline on every access (IDs 121–124). | Runtime policy changes take effect without recompiling the kernel or restarting workloads. |
| Quantum-inspired capability entanglement | Pairs or groups of capabilities are entangled; revoking any member automatically revokes all co-entangled members (IDs 125–128). | Authority collapse is atomic across capability groups, eliminating partial-revocation races. |
| Runtime capability graph verification | Every delegation is recorded in a live DAG; cycles and rights-escalation are detected and rejected before the transfer is committed (IDs 129–131). | The delegation graph is auditable at runtime; violations are counted and logged, not silently accepted. |

## Core Capabilities

- capability-based security and explicit authority flow
- temporal object persistence, branching, rollback, and merge
- WebAssembly runtime with interpreter and JIT paths
- verification, fuzzing, and runtime hardening workflows
- cross-architecture bring-up across `i686`, `x86_64`, and `AArch64`
- network and service surfaces for real end-to-end shell demos

## Platform And Portability Status

Oreulius is cross-compatible at the boot/runtime abstraction layer across `i686`, `x86_64`, and `AArch64`, but feature parity is intentionally uneven:

- `i686` remains the most complete runtime-rich path
- `x86_64` is a real QEMU bring-up path with working boot, traps, timer IRQs, MMU backend, and serial shell
- `AArch64` is a real QEMU `virt` bring-up path with DTB parsing, PL011, exception vectors, GICv2 timer IRQs, MMU backend, serial shell, and virtio-mmio tests

### Compatibility Matrix

| Arch | Boot Path | Current Status | Console / Bring-up Surface |
|---|---|---|---|
| `i686` | Multiboot1 + GRUB (`build.sh`, `run.sh`) | Most complete runtime path | VGA + serial shell, core kernel services |
| `x86_64` | Multiboot2 + GRUB ISO (`build-x86_64-full.sh`) | Real QEMU bring-up | Serial bring-up shell and diagnostics |
| `AArch64` | QEMU `virt` raw `Image` + DTB (`build-aarch64-virt.sh`) | Real QEMU `virt` bring-up | PL011 serial shell and diagnostics |

## Status And CI Matrix

<div align="center">

[![Written in Rust](https://img.shields.io/badge/written%20in-Rust-orange.svg)](https://www.rust-lang.org/)
[![Written in assembly](https://img.shields.io/badge/written%20in-Assembly-brown.svg)](https://en.wikipedia.org/wiki/Assembly_language)
[![License: Oreulius](docs/assets/oreulius-license-badge.svg)](LICENSE)
[![i686](https://img.shields.io/badge/i686-legacy%20runtime-success)](https://en.wikipedia.org/wiki/I686)
[![x86_64](https://img.shields.io/badge/x86__64-Multiboot2%20QEMU%20bringup-blue)](https://en.wikipedia.org/wiki/X86-64)
[![AArch64](https://img.shields.io/badge/AArch64-QEMU%20virt%20bringup-blue)](https://en.wikipedia.org/wiki/AArch64)
[![Boot Handoff](https://img.shields.io/badge/boot%20handoff-MB1%20%7C%20MB2%20%7C%20DTB-informational)](#platform-and-portability-status)
[![WASM Host ABI](https://img.shields.io/badge/WASM%20host%20ABI-IDs%200%E2%80%93131-blueviolet)](#wasm-host-abi-reference)
[![Multiarch QEMU Smoke](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-smoke.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-smoke.yml)
[![Multiarch QEMU Extended](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-extended.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/multiarch-qemu-extended.yml)
[![i686 Network Regression](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/i686-network-regression.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/i686-network-regression.yml)
[![x86_64 Network Regression](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/x86_64-network-regression.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/x86_64-network-regression.yml)
[![Aarch64 Network Regression](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/aarch64-network-regression.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/aarch64-network-regression.yml)
[![CapNet Regression](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/capnet-regression.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/capnet-regression.yml)
[![WASM JIT Regression](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/wasm-jit-regression.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/wasm-jit-regression.yml)
[![Proof Check](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/proof-check.yml/badge.svg)](https://github.com/reeveskeefe/Oreulius-Kernel/actions/workflows/proof-check.yml)

</div>

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
| Persistence | Durable snapshot read/write for temporal state | used by temporal self-checks and restore path |
| Network + CapNet | Ethernet/WiFi stack and capability network control plane | `net-*`, `wifi-*`, `capnet-*`, `http-*`, `dns-resolve` |
| Assembly paths | Low-level context, syscall, memory, and perf primitives | `asm-test`, `cpu-bench`, VM/syscall tests |

### Memory Mapping ABI

`MemoryMap` syscall `32` supports both anonymous and file-backed mappings on `x86_64`.

- Anonymous mapping:
  `arg1=addr`, `arg2=size`, `arg3=prot`, `arg4=MAP_ANONYMOUS|flags`, `arg5=0`
- File-backed mapping:
  `arg1=addr`, `arg2=size`, `arg3=prot`, `arg4=flags`, `arg5=(offset_pages << 16) | fd`

Current behavior:

- file-backed mappings are lazy-filled on page fault from VFS-backed files
- in-memory VFS files and mounted VFS files are supported
- `MAP_SHARED|PROT_WRITE` writes are flushed back on unmap and process teardown
- raw block / virtio raw handles are not accepted as file-backed mmap sources
- shared file mappings on `x86_64` use coherent shared physical pages once faulted in; writable mappings still flush back on unmap and process teardown

## WASM Host ABI Reference

Oreulius exposes a 132-function WASM host ABI spanning IDs `0–131`.

Use these references:

- [`docs/abi-reference.md`](docs/abi-reference.md)
- [`docs/runtime/oreulius-wasm-abi.md`](docs/runtime/oreulius-wasm-abi.md)

High-level grouping:

| Group | ID Range | Purpose |
|---|---|---|
| Core I/O, IPC, network, services | `0–12` | logging, files, channels, DNS, HTTP, service calls |
| Temporal objects | `13–22` | snapshot, history, rollback, branch, merge |
| Threads and compositor/input | `23–44` | cooperative threading, windowing, input |
| WASI and TLS | `45–99` | compatibility surface plus kernel TLS session control |
| Process lifecycle and advanced capability/runtime features | `100–131` | process ops, polyglot runtime, observer bus, mesh, checkpoints, policy, entanglement, cap graph |

The in-kernel dispatch surface lives in [`kernel/src/execution/wasm.rs`](kernel/src/execution/wasm.rs).

## WASM SDK Module Reference

The `wasm/sdk` crate mirrors the host ABI with a Rust `no_std` guest-side SDK.

Start here:

- [`wasm/README.md`](wasm/README.md)
- [`docs/abi-reference.md`](docs/abi-reference.md)

The SDK is organized around the same domains as the host ABI:

- core I/O and filesystem
- IPC and services
- temporal objects
- process and thread lifecycle
- network access
- policy, observer, mesh, entanglement, and delegation-graph queries

## Kernel Module Map

Oreulius is a single Rust `no_std` kernel crate with most implementation grouped by subsystem under `kernel/src/`.

If you are browsing the code for the first time, start with:

| Area | Where to Start | Why |
|---|---|---|
| Capability and authority | [`kernel/src/capability/`](kernel/src/capability) | capabilities, delegation, revocation, graph checks |
| Execution and WASM | [`kernel/src/execution/`](kernel/src/execution) | interpreter, JIT, host ABI |
| Process and scheduling | [`kernel/src/scheduler/`](kernel/src/scheduler) | process lifecycle, context, scheduling |
| Temporal and persistence | [`kernel/src/temporal/`](kernel/src/temporal) | snapshots, branching, rollback, merge |
| Networking | [`kernel/src/net/`](kernel/src/net) | stack, reactor, CapNet, transport |
| Verification surfaces | [`verification/`](verification/README.md) | proofs, assumptions, evidence, target matrix |

For the fuller subsystem inventory, use:

- [`kernel/README.md`](kernel/README.md)
- [`docs/architecture-overview.md`](docs/architecture-overview.md)

## Capability System Internals

The core capability implementation lives under [`kernel/src/capability/`](kernel/src/capability).

The most important internal surfaces are:

- `CapabilityTable` for install, lookup, transfer, and revoke
- the rights bitmask / rights-type model
- `cap_graph` for delegation DAG checks, cycle rejection, and no-escalation enforcement

For deeper detail, use:

- [`kernel/README.md`](kernel/README.md)
- [`docs/capability/oreulius-capabilities.md`](docs/capability/oreulius-capabilities.md)
- [`docs/capability/oreulius-cap-graph-verification.md`](docs/capability/oreulius-cap-graph-verification.md)

## Continuous Integration

### GitHub Actions Workflows

Eight workflows are available as CI gates. They all support `workflow_dispatch`; push and pull request execution is path-filtered by workflow file:

| Workflow File | Trigger | What It Runs |
|---|---|---|
| `.github/workflows/multiarch-qemu-smoke.yml` | Push / PR / Dispatch | Smoke tests for i686, x86_64, and AArch64 under QEMU |
| `.github/workflows/multiarch-qemu-extended.yml` | Push / PR / Dispatch | Extended QEMU tests for all three architectures |
| `.github/workflows/i686-network-regression.yml` | Push / PR / Dispatch | Dedicated i686 QEMU usernet regression |
| `.github/workflows/x86_64-network-regression.yml` | Push / PR / Dispatch | Dedicated x86_64 QEMU usernet regression |
| `.github/workflows/aarch64-network-regression.yml` | Push / PR / Dispatch | Dedicated AArch64 QEMU `virt` usernet regression |
| `.github/workflows/capnet-regression.yml` | Push / PR / Dispatch | CapNet parser, enforcer, and cross-peer delegation regression |
| `.github/workflows/wasm-jit-regression.yml` | Push / PR / Dispatch | WASM interpreter vs JIT differential validation |
| `.github/workflows/proof-check.yml` | Push / PR / Dispatch | Proof-governance and verification-structure checks |

### Shell CI Scripts (`kernel/ci/`)

| Script / Harness | Arch | Depth | Description |
|---|---|---|---|
| `smoke-i686.sh` / `.expect` | i686 | Smoke | Boot and minimal shell responsiveness check |
| `smoke-x86_64.sh` / `.expect` | x86_64 | Smoke | MB2 boot, serial shell, and command availability |
| `smoke-aarch64.sh` / `.expect` | AArch64 | Smoke | QEMU `virt` boot, PL011 shell, basic command echo |
| `network-i686.sh` / `network-i686.py` | i686 | Network | usernet regression with DNS, plain HTTP, and HTTPS fail-closed checks |
| `network-x86_64.sh` / `.expect` | x86_64 | Network | usernet regression for `netstack-info`, DNS, plain HTTP, and HTTPS fail-closed behavior |
| `network-aarch64.sh` / `.expect` | AArch64 | Network | `virt` usernet regression for READY state, DNS, plain HTTP, and HTTPS fail-closed behavior |
| `extended-x86_64.sh` / `.expect` | x86_64 | Extended | traps, MMU, timer IRQ, JIT toggle, CapNet, temporal, VFS |
| `extended-aarch64.sh` / `.expect` | AArch64 | Extended | exception vectors, GICv2, generic timer, virtio-mmio |
| `extended-all.sh` | All | Extended | orchestrator that runs all three extended scripts in sequence |
| `soak-i686.sh` / `.expect` | i686 | Soak | long-duration legacy-x86 stability run using the serial shell harness |

## Honest Gaps

Oreulius does not make false completeness claims. Important current boundaries include:

- feature parity across `i686`, `x86_64`, and `AArch64` is still intentionally uneven
- whole-system verification is not yet claimed across boot, assembly, MMU, toolchain, and hardware assumptions
- some advanced runtime and driver surfaces are still more complete on `i686` than on the newer bring-up paths
- the README is now an onboarding-and-navigation document; exhaustive internals live in docs and subsystem READMEs

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
git clone https://github.com/reeveskeefe/Oreulius-Kernel.git
cd Oreulius-Kernel/kernel
```

### i686 (Recommended First Run)

```bash
./build.sh
./run.sh
```

Known-good QEMU serial launch:

```bash
qemu-system-i386 -cdrom oreulius.iso -serial stdio
```

Notes:

- `i686` is the recommended onboarding path
- if you want reproducible command capture, prefer the serial launch above

### x86_64 (Multiboot2 + GRUB + QEMU)

Build and package the x86_64 Multiboot2 kernel:

```bash
./build-x86_64-mb2-iso.sh
```

Run the x86_64 bring-up shell in QEMU:

```bash
QEMU_EXTRA_ARGS="-monitor none -nographic" ./run-x86_64-mb2-grub.sh
```

Notes:

- the x86_64 shell is serial-input driven
- use `-nographic` or another `QEMU_EXTRA_ARGS` variant that keeps COM1 attached to your terminal

### AArch64 (QEMU `virt` Raw `Image`)

Build the AArch64 QEMU `virt` raw `Image`:

```bash
./build-aarch64-virt.sh
```

Run the basic AArch64 `virt` bring-up shell:

```bash
./run-aarch64-virt-image.sh
```

Run the AArch64 `virt` variant with an explicit `virtio-mmio` block device binding:

```bash
./run-aarch64-virt-image-virtio-blk-mmio.sh
```

### Known-Good QEMU Bring-up Matrix

```bash
# i686
cd kernel
./build.sh
qemu-system-i386 -cdrom oreulius.iso -serial stdio

# x86_64
cd kernel
./build-x86_64-mb2-iso.sh
QEMU_EXTRA_ARGS="-monitor none -nographic" ./run-x86_64-mb2-grub.sh

# AArch64
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

- `help`, `clear`, `echo`, `uptime`, `sleep`, `calculate`, `cpu-info`, `cpu-bench`, `pci-list`

### Process And Scheduling

- `spawn`, `ps`, `kill`, `yield`, `whoami`, `sched-stats`, `quantum-stats`, `sched-net-soak`

### Filesystem And VFS

- `vfs-mkdir`, `vfs-write`, `vfs-read`, `vfs-ls`, `vfs-open`, `vfs-readfd`, `vfs-writefd`, `vfs-close`
- `vfs-mount-virtio`, `blk-info`, `blk-partitions`, `blk-read`, `blk-write`
- legacy KV commands: `fs-write`, `fs-read`, `fs-delete`, `fs-list`, `fs-stats`

### Temporal Object Operations

- `temporal-write`, `temporal-snapshot`, `temporal-history`, `temporal-read`, `temporal-rollback`
- `temporal-branch-create`, `temporal-branch-list`, `temporal-branch-checkout`, `temporal-merge`
- `temporal-stats`, `temporal-retention`, `temporal-ipc-demo`, `temporal-abi-selftest`, `temporal-hardening-selftest`

### WASM And Service Pointer Capabilities

- `wasm-demo`, `wasm-fs-demo`, `wasm-log-demo`, `wasm-list`
- `svcptr-register`, `svcptr-invoke`, `svcptr-send`, `svcptr-recv`, `svcptr-inject`
- `svcptr-demo`, `svcptr-demo-crosspid`, `svcptr-typed-demo`
- `wasm-jit-on`, `wasm-jit-off`, `wasm-jit-bench`, `wasm-jit-selftest`, `wasm-jit-stats`, `wasm-jit-threshold`
- `wasm-jit-fuzz`, `wasm-jit-fuzz-corpus`, `wasm-jit-fuzz-soak`
- `wasm-replay-record`, `wasm-replay-stop`, `wasm-replay-save`, `wasm-replay-load`, `wasm-replay-status`, `wasm-replay-clear`, `wasm-replay-verify`

### Networking And CapNet

- `net-info`, `eth-info`, `eth-status`, `netstack-info`, `dns-resolve`
- `wifi-scan`, `wifi-connect`, `wifi-status`
- `http-get`, `http-server-start`, `http-server-stop`
- `capnet-local`, `capnet-peer-add`, `capnet-peer-show`, `capnet-peer-list`, `capnet-lease-list`
- `capnet-hello`, `capnet-heartbeat`, `capnet-lend`, `capnet-accept`, `capnet-revoke`, `capnet-stats`, `capnet-demo`
- `capnet-fuzz`, `capnet-fuzz-corpus`, `capnet-fuzz-soak`

### Security And Capability Introspection

- `security-audit`, `security-stats`, `security-anomaly`
- `security-intent`, `security-intent-clear`, `security-intent-policy`
- `enclave-secret-policy`
- `cap-list`, `cap-arch`, `cap-test-atten`, `cap-test-cons`, `cap-demo`

### Low-Level Validation

- `formal-verify`
- `paging-test`, `syscall-test`, `atomic-test`, `spinlock-test`, `asm-test`
- `test-div0`, `test-pf`, `user-test`, `elf-run`

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

- unauthorized authority escalation in kernel services
- replay and stale-state acceptance in delegated control paths
- unsafe JIT transitions and uncontrolled executable memory behavior
- state corruption or silent divergence in temporal restore or merge paths

### Explicit Non-Goals

- replacing Linux or POSIX
- supporting arbitrary native userspace workloads
- claiming full-system verification before the low-level, toolchain, and composition boundaries are discharged

## Performance Positioning

Oreulius is optimized for explicit control, bounded behavior, and inspectability first. Performance work exists in the scheduler, JIT, transport, and memory layers, but the project’s public identity is not “fastest possible general-purpose kernel.” It is a systems kernel that treats authority, replay, and verification as core runtime concerns.

## Documentation Map

Start here:

- [Docs Home](docs/README.md)
- [Getting Started](docs/getting-started.md)
- [First Demo](docs/first-demo.md)
- [Architecture Overview](docs/architecture-overview.md)
- [Verification Overview](docs/verification-overview.md)
- [ABI Reference](docs/abi-reference.md)

Then go deeper:

- Project: [Vision](docs/project/oreulius-vision.md), [MVP Specification](docs/project/oreulius-mvp.md), [Commercial Use Cases](docs/project/CommercialUseCases.md)
- Capability: [Capabilities](docs/capability/oreulius-capabilities.md), [CapNet Scientific Resolution](docs/capability/capnet.md), [Intent Graph Predictive Revocation](docs/capability/oreulius-intent-graph-predictive-revocation.md)
- IPC and storage: [IPC](docs/ipc/oreulius-ipc.md), [Persistence](docs/storage/oreulius-persistence.md), [Filesystem](docs/storage/oreulius-filesystem.md), [Temporal Adapters + Durable Persistence](docs/storage/oreulius-temporal-adapters-durable-persistence.md)
- Runtime and services: [WASM ABI](docs/runtime/oreulius-wasm-abi.md), [JIT Security Resolution](docs/runtime/oreulius-jit-security-resolution.md), [Function/Service Pointer Capabilities](docs/services/oreulius-service-pointer-capabilities.md), [WASM JIT Pairwise Transition Coverage](docs/runtime/oreulius-wasm-jit-pairwise-transition-coverage.md)
- Verification: [Verification Workspace](verification/README.md), [Verification Target Matrix](VERIFICATION_TARGET_MATRIX.md)
- Contributor process: [Contributing Guide](docs/CONTRIBUTING.md), [Contributor License Terms](CONTRIBUTOR-LICENSE.md)

## Project Layout

```text
Oreulius-Kernel/
├── kernel/              # Kernel source, asm, linker, build/run scripts
├── ci/                  # Root-level helper scripts and local CI entrypoints
├── docs/                # Architecture, runtime, capability, storage, contributor docs
├── services/            # Service prototypes / planned expansions
├── wasm/                # WASM modules, examples, and SDK
├── verification/        # Formal verification specs, proofs, and artifacts
├── VERIFICATION_TARGET_MATRIX.md
├── CONTRIBUTOR-LICENSE.md
├── COMMERCIAL.md
├── SECURITY.md
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome for architecture, verification, runtime hardening, and subsystem correctness.

1. Fork the repository.
2. Create a branch.
3. Implement and test.
4. Open a pull request with rationale and evidence.

Inbound contributor rights are defined in [CONTRIBUTOR-LICENSE.md](CONTRIBUTOR-LICENSE.md). See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for workflow details.

## License

Public use is licensed under [LICENSE](LICENSE). Commercial deployment is described in [COMMERCIAL.md](COMMERCIAL.md). Inbound contribution rights are in [CONTRIBUTOR-LICENSE.md](CONTRIBUTOR-LICENSE.md).

## Contact

`reeveskeefe@gmail.com`

## Acknowledgments

Oreulius builds on decades of systems, capability-security, formal-methods, and runtime-isolation work. The repository documentation cites many of the specific technical influences directly where they are most relevant.
