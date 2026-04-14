# Architecture Overview

Most operating systems make authority flow hard to audit and post-incident state hard to replay. Oreulius is an experimental kernel trying to make those two concerns first-class runtime behavior rather than after-the-fact tooling.

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

## Scope And Current Status

- The default user-facing surface today is the serial shell.
- Oreulius is not currently a desktop OS and does not ship a default GUI/window-manager experience.
- Some subsystems are implementation-complete, some are target-gated, and some are still migration work.
- For practical bring-up status by target, use the top-level README section "Target Bring-Up At A Glance" before diving deeper.

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
