# Threat Model

## Adversary Capabilities

An adversary is assumed to be capable of the following within the threat
boundary of this model:

1. **Unprivileged user-space code execution** — the adversary controls one or
   more user processes running at ring-3 and may craft arbitrary WASM modules
   or ELF binaries for execution under the Oreulius WASM/ELF loader.
2. **IPC injection** — the adversary may send arbitrary payloads over any IPC
   channel to which it holds a valid capability token, including forged or
   replayed messages.
3. **WASM escape attempts** — the adversary may attempt to break out of the
   WASM sandbox via crafted opcodes, integer overflows in linear-memory
   address arithmetic, or malformed JIT-compiled code sequences.
4. **Capability forgery** — the adversary attempts to manufacture capability
   tokens without going through the kernel's `cap_grant` path (e.g. by
   writing directly to capability tables or manipulating raw integer PIDs).
5. **Timing channels** (partial) — adversaries may attempt to infer secret
   scheduler state via timing of context switches or slice exhaustion, to
   the extent measurable from user space.

The adversary is **not** assumed to have:
- Physical access to the machine
- Kernel-level code execution (ring-0 compromise is considered post-breach)
- The ability to modify the kernel binary at rest or in flight

## Trust Boundaries

| Boundary | Description |
|---|---|
| **Ring-0 / Ring-3** | Hardware privilege separation; all kernel-mode code runs at ring-0, all user processes at ring-3. System calls cross this boundary via the `syscall` / `sysenter` gate. |
| **Capability Token Boundary** | Capability tokens are opaque handles allocated by the kernel. No user-space process may create, duplicate, or revoke a capability except by invoking the kernel's capability API. |
| **CapNet Peer Boundary** | Each CapNet peer holds only the capability tokens explicitly granted to it. Cross-peer IPC requires a valid forwarding capability; ambient access does not exist. |
| **WASM Linear-Memory Boundary** | WASM instances address only their own linear memory. The JIT and interpreter enforce bounds on every load/store. Host-function calls cross this boundary only through the ABI shim. |
| **Scheduler Domain** | The scheduler's ready queues and process table are accessible only to kernel code. No user-space path may directly modify process state. |

## Out-of-Scope

The following threat classes are explicitly **out of scope** for this version
of the threat model and the associated formal proofs:

- **Hardware side-channels** (Spectre, Meltdown, MDS, L1TF, Row Hammer) —
  mitigations are a separate engineering concern.
- **Physical access** — an attacker with physical hardware access can bypass
  all software security boundaries and is not modelled here.
- **Compiler / toolchain compromise** — the Rust compiler, LLVM backend, and
  Coq proof checker are part of the trusted computing base (see ASM-TOOL-001).
- **Firmware / BIOS / UEFI** — pre-boot code is outside the kernel's control.
- **Denial of service via resource exhaustion** — liveness/fairness properties
  are tracked separately; the current proofs address only safety invariants.
- **Multi-tenant scheduling fairness** — the EWMA scheduler (THM-TMP-001) is
  proved for single-queue liveness; multi-tenant interference is future work.
