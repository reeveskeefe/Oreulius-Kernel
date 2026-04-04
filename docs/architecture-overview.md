# Architecture Overview

Oreulius is best understood through four core ideas:

- capability-mediated authority
- WASM-first execution
- temporal state and replayable history
- verification-oriented control surfaces

## System Shape

At a high level, the kernel is organized as:

- shell and command plane
- capability, security, registry, and IPC
- WASM runtime and JIT
- temporal and persistence layer
- scheduler, VM, syscall, and networking substrate

This keeps the most important control surfaces explicit:

- capability grant / transfer / revoke
- host ABI entry points
- temporal snapshot / rollback / merge
- scheduling and privilege transitions

## Recommended Code Entry Points

- [`kernel/src/capability/`](../kernel/src/capability)
- [`kernel/src/execution/`](../kernel/src/execution)
- [`kernel/src/temporal/`](../kernel/src/temporal)
- [`kernel/src/scheduler/`](../kernel/src/scheduler)
- [`kernel/src/net/`](../kernel/src/net)

## Architecture-Specific Paths

- `i686`
  - most complete runtime path
- `x86_64`
  - Multiboot2 + GRUB + serial bring-up path
- `AArch64`
  - QEMU `virt` raw `Image` + DTB + PL011 bring-up path

## Read Next

- [../kernel/README.md](../kernel/README.md)
- [architecture/Polymorphic_Mathematical_Architecture.md](architecture/Polymorphic_Mathematical_Architecture.md)
- [architecture/unified-theory-capability-trust-causal-semantics-thermodynamic-liveness.md](architecture/unified-theory-capability-trust-causal-semantics-thermodynamic-liveness.md)
