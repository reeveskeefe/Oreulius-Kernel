# The Oreulius Kernel

<div align="center">

**A capability-oriented, WebAssembly-native kernel built from the ground up**

[![Written in Rust](https://img.shields.io/badge/written%20in-Rust-orange.svg)](https://www.rust-lang.org/)
[![Written in assembly](https://img.shields.io/badge/written%20in-Assembly-brown.svg)](https://en.wikipedia.org/wiki/Assembly_language)
[![License: Oreulius](docs/oreulius-license-badge.svg)](LICENCE)
[![Platform](https://img.shields.io/badge/platform-i686-lightgrey.svg)](https://en.wikipedia.org/wiki/I686)
<br>
[![Canada Badge](docs/Made-In-Canada-Badge.svg)](https://en.wikipedia.org/wiki/Canada)

[Features](#key-features) • [Architecture](#architecture) • [Building](#building) • [Running](#running) • [Commands](#commands) • [Documentation](#documentation)

</div>

---
<div align="center">
<img src="oreuliuswhitebackground.png" border-radius="10%" width="600" alt="the logo for the kernel oreulius">

</div>

## Overview

Oreulieus is an experimental operating system that rethinks traditional OS design principles. Built in Rust with a focus on security and modern execution models, it provides a foundation for exploring capability-based security, WebAssembly execution, strict privilege transitions, and deterministic system behavior.

<div align="center">
<img src="opencommandlineinterface.png" width="600" alt="the oreulius command line interface once the kernel is booted">

</div>

## Formal Security Papers

Oreulia's formal security records are documented in three companion papers:

- **[Oreulia JIT Security Resolution](docs/oreulia-jit-security-resolution.md)**
- **[CapNet Scientific Resolution](docs/capnet.md)**
- **[Intent Graph Predictive Revocation](docs/oreulia-intent-graph-predictive-revocation.md)**

Together they cover theorem-backed hardening for in-kernel JIT execution, decentralized capability transfer over the network control plane, and behavior-aware predictive capability control in kernel space.

### Key Features

- **Capability-Based Security** - No ambient authority; all access is explicitly granted through capabilities
- **Intent Graph Predictive Revocation** - Per-process behavioral graph scoring with predictive restriction, quarantine/restore, isolation escalation, and termination recommendation
- **CapNet Capability Network** - Portable capability tokens with session-key MAC verification, replay windows, delegation-chain constraints, and persistent revocation
- **WebAssembly Native** - First-class support for WASM execution with sandboxed module isolation
- **JIT Hardening Pipeline** - W^X sealing, decoder whitelist validation, SFI/CFI constraints, and translation certificates
- **Message-Passing IPC** - Dataflow channels for inter-process communication
- **Persistence-First Design** - Built-in snapshotting and deterministic replay
- **High-Performance Assembly** - Optimized low-level operations for context switching, memory management, and crypto
- **Formal + Fuzz Verification** - In-kernel `formal-verify`, coverage-guided fuzzing, corpus replay, and soak checks
- **QEMU-Ready** - Designed for easy testing and development in virtualized environments

---

## Architecture

Oreulieus is built on several core subsystems:

- **Security Manager** - Audit logging and security policy enforcement
- **Intent Graph Engine** - Behavioral telemetry, risk scoring, and escalation policy for predictive capability control
- **Capability Manager** - Authority model with fine-grained permissions
- **Process Scheduler** - Preemptive multitasking with 100Hz timer
- **IPC System** - Typed message channels with capability-based access control
- **Filesystem Service** - Virtual filesystem with quota management
- **WASM Runtime** - Sandboxed execution environment for WebAssembly modules
- **Network Stack** - Ethernet (E1000/RTL8139) and WiFi support with ARP/ICMP/UDP/TCP + DNS paths
- **CapNet Control Plane** - Authenticated capability-token exchange (`HELLO/ATTEST/TOKEN_OFFER/TOKEN_ACCEPT/TOKEN_REVOKE/HEARTBEAT`) with attestation-bound peer policy

### CapNet Capability Networking

CapNet extends Oreulia's local capability semantics to cross-device delegation without introducing ambient trust. Tokens are fixed-size, signed capability objects accepted only when all invariants hold:

\[
\text{Accept}(\tau, p) = \text{MAC}_{k_p}(\tau) \land \text{FreshSeq}(p) \land \text{FreshNonce}(p) \land \text{SubsetRights}(\tau) \land \text{NotRevoked}(\tau)
\]

Implementation properties:

- **Token Integrity** - `CapabilityTokenV1` uses deterministic encoding and SipHash MAC under per-peer session keys (boot-key fallback for local diagnostics).
- **Attestation-Bound Session Keys** - `enclave.rs` installs CapNet peer sessions after attestation policy checks; peer trust policy (`disabled`/`audit`/`enforce`) gates acceptance strictness.
- **Delegation Safety** - token acceptance enforces parent hash linkage, bounded depth, and rights attenuation before creating a local remote-capability lease.
- **Replay Resistance** - both control-frame sequence numbers and token nonces use high-watermark + bitmap windows for deterministic stale/duplicate rejection.
- **Revocation Durability** - token revocations are stored as epoch-ordered tombstones and replayed at initialization to prevent post-reboot replay.
- **Deterministic Validation** - shell commands expose `capnet-fuzz`, corpus replay, and soak loops for reproducible parser/enforcer regression checks.

### Assembly-Optimized Components

Oreulieus includes hand-written x86 assembly modules for critical operations:

- **CPU Features** - CPUID detection and runtime capability gating
- **Atomic Operations** - Lock-free synchronization primitives with spinlocks
- **Performance Tools** - RDTSC timing, instruction benchmarking, cache control
- **Context Switching** - Register/EFLAGS save-restore and thread trampoline transitions
- **Memory Operations** - Optimized copy/zero paths for hot memory routines
- **Cryptography** - Assembly-assisted primitives and secure wipe/compare paths
- **Privilege Entry Paths** - INT 0x80 and SYSENTER with KPTI-aware CR3 transitions
- **SGX Primitives** - `ECREATE/EADD/EEXTEND/EINIT/EENTER` wiring on supported targets

---

## Building

### Prerequisites

Make sure you have the following tools installed:

```bash
# Rust toolchain (kernel-pinned nightly)
rustup toolchain install nightly-2023-11-01
rustup component add rust-src

# Build tools (macOS example)
brew install nasm qemu xorriso

# GRUB tooling
brew install grub
```

### Build Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/reeveskeefe/oreulieus-kernel.git
   cd oreulieus-kernel/kernel
   ```

2. **Build the kernel**
   ```bash
   ./build.sh
   ```

   This will:
   - Compile the Rust kernel (`cargo build --release`)
   - Assemble boot stub and assembly modules (NASM)
   - Link everything into a multiboot-compliant kernel
   - Generate `oreulia.iso` bootable image

3. **Verify the build**
   ```bash
   # Check for the ISO file
   ls -lh oreulia.iso
   ```

---

## Running

### Launch with QEMU

```bash
# Recommended launcher (uses project defaults)
./run.sh

# Manual launch with serial output
qemu-system-i386 -cdrom oreulia.iso -serial stdio

# Headless mode
QEMU_EXTRA_ARGS="-display none -nographic -no-reboot -no-shutdown" ./run.sh
```

### Quick Rebuild Script

For rapid development cycles:

```bash
chmod +x quick-rebuild.sh
./quick-rebuild.sh
```

---

## Commands

Once Oreulia boots, you'll see the shell prompt (`>`). Try these commands:

### System & General
- `help` - Display available commands
- `clear` - Clear the screen
- `echo <text>` - Echo text back to screen
- `uptime` - Show system uptime
- `sleep <ms>` - Sleep for N milliseconds
- `calculate <a> <op> <b>` - Scientific calculator
- `cpu-info` - Show CPU features and capabilities
- `cpu-bench` - Benchmark CPU instructions
- `pci-list` - List PCI devices (hardware detection)

### Process Management
- `spawn <name>` - Spawn a new process
- `ps` - List all processes
- `kill <pid>` - Terminate a process
- `yield` - Yield current process
- `whoami` - Show current process info
- `sched-stats` - Show scheduler statistics
- `elf-run <path>` - Load and run ELF executable from VFS
- `user-test` - Enter user mode (INT 0x80 test)

### Filesystem (VFS & Block)
- `vfs-ls <path>` - List directory
- `vfs-mkdir <path>` - Create directory
- `vfs-write <path> <data>` - Write file
- `vfs-read <path>` - Read file
- `vfs-open <path>` - Open file to get fd
- `vfs-readfd <fd> [n]` - Read via file descriptor
- `vfs-writefd <fd> <data>` - Write via file descriptor
- `vfs-close <fd>` - Close file descriptor
- `vfs-mount-virtio` - Mount VirtIO block device
- `blk-info` - Show VirtIO block device info
- `blk-partitions` - List disk partitions
- `fs-write/read/delete/list` - Key-value filesystem commands (legacy)

### IPC & Services
- `ipc-create` - Create a new channel
- `ipc-send <chan> <msg>` - Send a message to channel
- `ipc-recv <chan>` - Receive a message from channel
- `svc-register <type>` - Register a service
- `svc-request <type>` - Request a service
- `svc-list` - List all services
- `cap-demo <key>` - Demo capability passing
- `intro-demo` - Demo introduction protocol

### Networking
- `net-info` / `eth-info` - Show network/ethernet status
- `wifi-scan` - Scan for WiFi networks
- `wifi-connect <ssid>` - Connect to WiFi
- `http-get <url>` - Perform HTTP GET request
- `http-server-start [port]` - Start built-in HTTP server
- `dns-resolve <domain>` - Resolve domain name
- `netstack-info` - Show TCP/IP stack status

### CapNet (Capability Network)
- `capnet-local` - Show local CapNet device identity
- `capnet-peer-add <peer_id> <disabled|audit|enforce> [measurement]` - Register/update peer trust state
- `capnet-peer-show <peer_id>` / `capnet-peer-list` - Inspect peer session and trust metadata
- `capnet-lease-list` - Show active remote capability leases
- `capnet-hello <ip> <port> <peer_id>` - Send HELLO control frame
- `capnet-heartbeat <ip> <port> <peer_id> [ack] [ack_only]` - Send heartbeat/ack control frame
- `capnet-lend <ip> <port> <peer_id> <cap_type> <object_id> <rights> <ttl_ticks> [context_pid] [max_uses] [max_bytes] [measurement] [session_id]` - Send delegated capability token
- `capnet-accept <ip> <port> <peer_id> <token_id> [ack]` - Acknowledge accepted delegated token
- `capnet-revoke <ip> <port> <peer_id> <token_id>` - Revoke a delegated token
- `capnet-stats` - Report peer/lease/journal counters
- `capnet-demo` - End-to-end lend/use/revoke verification loop
- `capnet-fuzz <iters> [seed]` - CapNet parser/enforcer fuzzing
- `capnet-fuzz-corpus <iters>` - Replay deterministic CapNet seed corpus
- `capnet-fuzz-soak <iters> <rounds>` - Multi-round CapNet corpus soak test

### WebAssembly
- `wasm-demo` - Run simple WASM math demo
- `wasm-fs-demo` - Demo WASM filesystem access
- `wasm-log-demo` - Demo WASM logging
- `wasm-list` - List loaded WASM instances
- `wasm-jit-on` / `wasm-jit-off` - Enable/Disable JIT compilation
- `wasm-jit-bench` - Benchmark JIT vs Interpreter
- `wasm-jit-stats` - Show JIT statistics
- `wasm-jit-fuzz <iters> [seed]` - Coverage-guided differential JIT fuzzing
- `wasm-jit-fuzz-corpus <iters>` - Replay external seed corpus
- `wasm-jit-fuzz-soak <iters> <rounds>` - Multi-round corpus replay for non-determinism checks
- `formal-verify` - Run formal verification obligations for JIT translation, capability logic, CapNet model checks, and intent policy checks

### Security & Capabilities
- `security-audit [count]` - Show security audit log
- `security-stats` - Show security subsystem statistics
- `security-anomaly` - Show anomaly detector score/window state
- `security-intent [pid]` - Show intent-graph process snapshot (scores, counters, restrictions, escalation state)
- `security-intent-clear <pid>` - Clear intent restriction/recommendation and force-restore quarantined capabilities
- `security-intent-policy [show|set|reset]` - View or tune runtime intent thresholds/cooldowns/durations without rebuilds
- `cap-list` - List capabilities
- `cap-arch` - Show capability architecture
- `cap-test-atten/cons` - Test capability mechanisms

### Advanced / Debug / Performance
- `alloc-stats` - Show allocator statistics
- `leak-check` - Check for memory leaks
- `quantum-stats` - Process quantum scheduler stats
- `sched-net-soak <seconds> [probe_ms]` - Scheduler/network soak verification
- `paging-test` - Test virtual memory paging
- `atomic-test` - Test atomic operations
- `spinlock-test` - Measure spinlock overhead
- `syscall-test` - Verify system call interface
- `test-div0` / `test-pf` - Trigger exceptions (div0, page fault)

---

## Commercial Use Cases

Oreulieus is built for secure, programmable edge systems where dynamic logic must run safely at high speed. The commercial vision covers embedded/edge appliances, multi-tenant IoT gateways, security/network appliances, and AI thin-client edge nodes.

Read the full overview here: **[Commercial Use Cases](docs/CommercialUseCases.md)**.

---

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Vision](docs/oreulia-vision.md)** - Project goals and philosophy
- **[MVP Specification](docs/oreulia-mvp.md)** - QEMU-first minimum viable product
- **[Capabilities](docs/oreulia-capabilities.md)** - Capability-based security model
- **[IPC System](docs/oreulia-ipc.md)** - Inter-process communication and dataflow
- **[Persistence](docs/oreulia-persistence.md)** - Logging, snapshots, and recovery
- **[Filesystem](docs/oreulia-filesystem.md)** - Virtual filesystem implementation
- **[WASM ABI](docs/oreulia-wasm-abi.md)** - WebAssembly host interface
- **[Assembly Quick Reference](docs/assembly-quick-reference.md)** - Low-level assembly interfaces and notes
- **[JIT Security Resolution](docs/oreulia-jit-security-resolution.md)** - Formal security model and implementation proof obligations
- **[CapNet Scientific Resolution](docs/capnet.md)** - Formal model and implementation analysis for decentralized capability networking
- **[Intent Graph Predictive Revocation](docs/oreulia-intent-graph-predictive-revocation.md)** - Formal specification of behavioral scoring, escalation thresholds, quarantine automaton, and correctness lemmas
- **[Commercial Use Cases](docs/CommercialUseCases.md)** - Market targets and product vision
- **[Contributing](docs/CONTRIBUTING.md)** - Contribution guidelines and process

---

## Project Structure

```
oreulia/
├── kernel/              # Kernel workspace
│   ├── .cargo/          # Cargo config
│   ├── Cargo.toml       # Kernel crate manifest
│   ├── Cargo.lock       # Dependency lockfile
│   ├── README.md        # Kernel-specific docs
│   ├── build.sh         # Build script
│   ├── build-iso.sh     # ISO build script
│   ├── run.sh           # QEMU run script
│   ├── quick-rebuild.sh # Fast rebuild helper
│   ├── kernel.ld        # Linker script
│   ├── i686-oreulia.json# Target spec
│   ├── src/             # Rust kernel modules
│   │   └── asm/         # x86 assembly modules
│   ├── iso/             # ISO staging
│   ├── iso_check/       # ISO validation
│   ├── target/          # Cargo build output
│   ├── oreulia.iso      # Build artifact
│   └── run*.log         # Runtime logs (qemu/run/output)
├── docs/                # Documentation
├── services/            # User-space services (planned)
└── wasm/                # WASM modules (planned)
```

---


### Performance Characteristics

- Scheduler dispatch path is O(1) over fixed MLFQ levels.
- Syscall entry supports both INT 0x80 and SYSENTER/SYSEXIT fast paths.
- Memory hot paths use optimized assembly primitives.
- Networking uses descriptor-ring DMA on supported NICs.
- JIT and interpreter dual paths support differential validation and replay.
- CapNet control-path parsing and token verification are fixed-width and bounded by protocol constants.
- Absolute throughput/latency depends on host CPU, QEMU mode, and runtime workload.

---

## Contributing

Oreulia is an experimental research project. Contributions, ideas, and feedback are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This project is licensed under the OREULIUS LISCENCE - see the [liscence](LICENSE) for details.

## Contact

**Email**
```bash
reeveskeefe@gmail.com
```

---

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) and [NASM](https://www.nasm.us/)
- Bootable with [GRUB](https://www.gnu.org/software/grub/)
- Tested on [QEMU](https://www.qemu.org/)
- Inspired by capability-based systems like [seL4](https://sel4.systems/) and [Fuchsia](https://fuchsia.dev/)

---

<div align="center">

**Made by Keefe Reeves and any potential contributors of the Oreulius Community**

</div>
