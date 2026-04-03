# Assumption Register

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

## ASM-TOOL-001 — Proof Checker Trustworthiness

Proofs are mechanised in Coq (minimum version 8.17) using only the standard
library (`Coq.Init`, `Coq.Lists`, `Coq.Bool`). The compiled `.vo` artifacts
produced by `coqc` are the authoritative proof record. The Coq kernel itself
is part of the trusted computing base (TCB); no axioms beyond `Coq.Logic.
Classical` are admitted. All theory files must compile without warnings under
`coqc -w all` before a theorem may be marked **Proven**.
