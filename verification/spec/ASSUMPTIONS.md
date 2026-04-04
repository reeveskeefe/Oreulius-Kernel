ok# Assumption Register

> Full TCB accounting and program-scoped assumption usage: see
> [`proof/VERIFICATION_TARGET_MATRIX.md` § Program K](../proof/VERIFICATION_TARGET_MATRIX.md).

Use named, versioned assumptions only:
- ASM-MODEL-*
- ASM-HW-*
- ASM-TOOL-*

## ASM-MODEL-001 — Model Coverage Boundary

The formal model covers only the transition subsets explicitly represented in
the Coq theories (`verification/theories/`). Kernel behaviors that operate
outside these modeled transition systems (e.g. device-driver I/O, DMA
operations, real-time interrupt latency) are **not claimed** to satisfy any
proved invariant. Any new subsystem added to the kernel must be accompanied by
a corresponding theory file before coverage can be extended.

## ASM-HW-001 — Atomic Instruction Semantics

The hardware is assumed to execute load/store instructions atomically at the
granularity modeled in the Coq theories (word-sized aligned accesses). Cache
coherence is assumed to hold across cores for the architectures targeted by
Oreulius (x86_64, AArch64). Microarchitectural side-channel effects (e.g.
speculative execution, cache-timing), physical probing, and Row Hammer
variants are **explicitly out of scope** for these proofs and are addressed
separately in the hardware security threat model.

QEMU is the authoritative execution model for all runtime evidence. Claims do
not extend to bare-metal hardware unless a separate hardware validation program
is completed.

## ASM-TOOL-001 — Proof Checker Trustworthiness

Proofs are mechanised in Coq / The Rocq Prover (pinned to version 9.1.1) using
only the standard library (`Stdlib.Init`, `Stdlib.Lists`, `Stdlib.ZArith`,
`Stdlib.micromega.Lia`). The compiled `.vo` artifacts produced by `coqc` are
the authoritative proof record. The Coq/Rocq kernel itself is part of the
trusted computing base (TCB); no axioms beyond `Classical` are admitted. All
theory files must compile without warnings under `coqc -w all` before a
theorem may be marked Proven.

## ASM-TOOL-002 — Compiler and Toolchain Trustworthiness

All proved properties hold at the **Rust source level**. The Rust compiler
(`rustc`, version pinned in `kernel/rust-toolchain`), LLVM backend, assembler,
and linker are trusted without proof. The compiled binary may differ from the
source-level model; no claim is made about binary-level correctness unless an
explicit binary-level refinement proof is added. This is an open obligation
(see Program K in the target matrix).

## ASM-MODEL-002 — Assembly and Boot Boundary

The architecture-specific assembly stubs (syscall entry, interrupt entry,
context-switch, MMU operations) and the boot path (Multiboot2 handoff,
AArch64 DTB handoff) are **in the trusted base** until Program J proof
obligations are discharged. The ring-transition proof (THM-PRIV-001) holds
at the abstract `CpuState` model level and does not extend to the assembly
implementation of those transitions. Any release claim must name this
boundary explicitly.
