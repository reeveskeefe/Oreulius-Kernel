# Oreulia OS

<div align="center">

**A capability-based, WebAssembly-native operating system built from the ground up**

[![Written in Rust](https://img.shields.io/badge/written%20in-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-i686-lightgrey.svg)](https://en.wikipedia.org/wiki/I686)

[Features](#features) • [Architecture](#architecture) • [Building](#building) • [Running](#running) • [Commands](#commands) • [Documentation](#documentation)

</div>

---

## Overview

Oreulia is an experimental operating system that rethinks traditional OS design principles. Built in Rust with a focus on security and modern execution models, it provides a foundation for exploring capability-based security, WebAssembly execution, and deterministic system behavior.

### Key Features

- 🔐 **Capability-Based Security** - No ambient authority; all access is explicitly granted through capabilities
- 🌐 **WebAssembly Native** - First-class support for WASM execution with sandboxed module isolation
- 📡 **Message-Passing IPC** - Dataflow channels for inter-process communication
- 💾 **Persistence-First Design** - Built-in snapshotting and deterministic replay
- ⚡ **High-Performance Assembly** - Optimized low-level operations for context switching, memory management, and crypto
- 🔧 **QEMU-Ready** - Designed for easy testing and development in virtualized environments

---

## Architecture

Oreulia is built on several core subsystems:

- **Security Manager** - Audit logging and security policy enforcement
- **Capability Manager** - Authority model with fine-grained permissions
- **Process Scheduler** - Preemptive multitasking with 100Hz timer
- **IPC System** - Typed message channels with capability-based access control
- **Filesystem Service** - Virtual filesystem with quota management
- **WASM Runtime** - Sandboxed execution environment for WebAssembly modules
- **Network Stack** - Ethernet (e1000) and WiFi device support with DNS/ARP/UDP

### Assembly-Optimized Components

Oreulia includes hand-written x86 assembly modules for critical operations:

- **CPU Features** - CPUID detection, SIMD support (SSE/SSE2/SSE3/SSE4/AVX), RDRAND
- **Atomic Operations** - Lock-free synchronization primitives with spinlocks
- **Performance Tools** - RDTSC timing, instruction benchmarking, cache control
- **Context Switching** - ~10× faster than pure Rust implementation
- **Memory Operations** - ~5× faster with optimized routines
- **Cryptography** - ~8× faster checksums and hashing

---

## Building

### Prerequisites

Make sure you have the following tools installed:

```bash
# Rust toolchain (nightly)
rustup default nightly
rustup component add rust-src

# Cross-compilation tools
brew install nasm x86_64-elf-gcc x86_64-elf-binutils i686-elf-grub

# QEMU for testing
brew install qemu
```

### Build Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/reeveskeefe/oreulia.git
   cd oreulia/kernel
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
# Standard launch
qemu-system-i386 -cdrom oreulia.iso

# With serial output (useful for debugging)
qemu-system-i386 -cdrom oreulia.iso -serial stdio

# Headless mode
qemu-system-i386 -cdrom oreulia.iso -serial stdio -nographic
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

### System Information
- `help` - Display all available commands
- `cpu-info` - Show CPU vendor, SIMD support, and features
- `mem-info` - Display memory usage statistics

### Performance Testing
- `cpu-bench` - Benchmark instruction throughput (NOP, ADD, MUL, DIV, LOAD, STORE, LOCK)
- `atomic-test` - Test atomic operations (add, sub, swap, CAS, bitwise ops)
- `spinlock-test` - Test spinlock correctness and performance

### Process Management
- `ps` - List all processes with their states
- `spawn <name>` - Create a new process
- `kill <pid>` - Terminate a process
- `nice <pid> <priority>` - Set process priority

### Filesystem
- `ls [path]` - List directory contents
- `cat <file>` - Display file contents
- `write <file> <data>` - Write data to a file
- `rm <file>` - Remove a file
- `mkdir <dir>` - Create a directory

### IPC & Capabilities
- `ipc-test` - Test inter-process communication
- `cap-list <pid>` - List capabilities for a process
- `cap-grant <pid> <object> <rights>` - Grant a capability

### Network
- `net-status` - Show network interface status
- `ping <ip>` - Send ICMP ping (if network available)
- `dns-resolve <domain>` - Resolve DNS name

### WebAssembly
- `wasm-load <file>` - Load a WASM module
- `wasm-run <module>` - Execute a WASM module
- `wasm-list` - List loaded WASM modules

### Security
- `audit-log` - Display security audit log
- `sec-status` - Show security manager status

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
- **[Assembly Enhancements](docs/assembly-enhancements.md)** - Low-level optimization details
- **[Assembly Quick Reference](docs/assembly-quick-reference.md)** - Developer API guide

---

## Project Structure

```
oreulia/
├── kernel/              # Kernel source code
│   ├── src/            # Rust kernel modules
│   ├── asm/            # x86 assembly modules
│   ├── boot.asm        # Multiboot boot stub
│   ├── build.sh        # Build script
│   └── kernel.ld       # Linker script
├── docs/               # Documentation
├── services/           # User-space services (planned)
└── wasm/              # WASM modules (planned)
```

---

## Development

### Code Organization

- **Security**: `src/security.rs`, `src/capability.rs`
- **Process Management**: `src/process.rs`, `src/scheduler.rs`
- **IPC**: `src/ipc.rs`
- **Filesystem**: `src/fs.rs`
- **Networking**: `src/net.rs`, `src/netstack.rs`, `src/e1000.rs`
- **WASM**: `src/wasm.rs`
- **Assembly**: `asm/cpu_features.asm`, `asm/atomic.asm`, `asm/perf.asm`

### Performance Characteristics

Based on internal benchmarks:

| Operation | Pure Rust | Assembly | Speedup |
|-----------|-----------|----------|---------|
| Context Switch | ~1000 cycles | ~100 cycles | 10× |
| Memory Copy | ~500 cycles | ~100 cycles | 5× |
| Network Checksum | ~800 cycles | ~100 cycles | 8× |
| Spinlock Acquire | ~50 cycles | ~10 cycles | 5× |

---

## Contributing

Oreulia is an experimental research project. Contributions, ideas, and feedback are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) and [NASM](https://www.nasm.us/)
- Bootable with [GRUB](https://www.gnu.org/software/grub/)
- Tested on [QEMU](https://www.qemu.org/)
- Inspired by capability-based systems like [seL4](https://sel4.systems/) and [Fuchsia](https://fuchsia.dev/)

---

<div align="center">

**Made with ⚡ by Keefe Reeves**

</div>
