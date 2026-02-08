# Oreulia Kernel

The core kernel component of Oreulia OS, written in Rust with performance-critical sections in x86 Assembly.

**Architecture**: `i686` (32-bit Protected Mode)
**Boot Protocol**: Multiboot 1 (GRUB compatible)

## Features

This kernel implements a feature-rich hybrid architecture:
- **Networking**: Full in-kernel TCP/IP stack (ARP, UDP, TCP, DNS, DHCP) with drivers for E1000 and RTL8139.
- **Filesystem**: Unix-like VFS with hierarchical directory support, Virtual Block Devices, and RAMFS.
- **Execution**: In-kernel **WebAssembly JIT Compiler** that translates Wasm to native x86 code.
- **Concurrency**: Priority-based preemptive scheduling (Quantum Scheduler) with processes and threads.
- **Security**: Capability-based resource access (no ambient authority).
- **Optimization**: Hand-tuned Assembly for atomic operations, context switching, and cryptography (`asm/` modules).

## Building

The build process is automated via shell scripts to handle the mix of Rust, Assembly, and Linking.

**Prerequisites**:
- `rustup` (Nightly toolchain)
- `nasm` (Netwide Assembler)
- `qemu-system-i386` (Virtualization)
- `xorriso` / `grub-mkrescue` (For ISO generation)

**Build Command**:
```bash
# Builds Rust kernel, assembles ASM stubs, links them, and generates oreulia.iso
./build.sh
```

**Quick Rebuild** (Skip ISO generation):
```bash
# Faster for dev loops
./quick-rebuild.sh
```

## Running

Launch the kernel in QEMU:

```bash
# Defaults: stdio serial console + network tap
./run.sh

# Or manually:
qemu-system-i386 -cdrom oreulia.iso -serial stdio -net nic,model=e1000
```

## Directory Structure

- `src/`: Rust kernel source code.
  - `main.rs`: Entry point (`_start`).
  - `vfs.rs`, `fs.rs`: Filesystem logic.
  - `net.rs`, `netstack.rs`: Networking stack.
  - `wasm.rs`, `wasm_jit.rs`: WebAssembly runtime & JIT.
  - `process.rs`, `scheduler.rs`: Task management.
- `asm/`: Assembly modules (.asm).
  - `context_switch.asm`: Task switching logic.
  - `interrupt.asm`: IDT/ISR handlers.
  - `atomic.asm`: Synchronization primitives.
- `boot.asm`: Multiboot header and initial bootstrap code.
- `kernel.ld`: Linker script defining memory layout.

## Debugging

The kernel outputs extensive logs to the serial port (`COM1`).

**View Logs**:
Launch QEMU with `-serial stdio` to see kernel debug output in your terminal.

**Panic Handling**:
On panic, the kernel prints the stack trace and halts everything.
