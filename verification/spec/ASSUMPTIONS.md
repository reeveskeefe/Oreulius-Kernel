# Verification Assumptions

These assumptions describe the trust boundary used by the verification
workspace. They are explicit so they can be reviewed and revised separately
from the kernel runtime.

- ASM-001: Proof tooling runs on a trusted Linux host with Coq available in CI.
- ASM-002: The proof workspace is treated as evidence, not as a runtime import.
- ASM-003: QEMU and similar emulators are regression harnesses, not semantic
  authorities.
- ASM-004: Runtime self-checks fail closed and do not mutate proof artifacts.
- ASM-005: Generated manifests and proof outputs are published or checked
  separately from kernel binaries.
- ASM-A64-001: The AArch64 proof surface is limited to the QEMU `virt`
  raw-image + DTB bring-up path.
- ASM-A64-002: AArch64 proof claims cover boot handoff, DTB parsing, exception
  vectors, MMU setup, timer/interrupt entry, syscall boundary stubs, and the
  scheduler handoff/context-switch path only.
- ASM-A64-003: The AArch64 scheduler proof surface is limited to the timer
  tick / reschedule-pending boundary and its local slice bookkeeping. It
  does not claim fairness, interrupt-controller fidelity, or full scheduler
  semantics.
- ASM-A64-004: The AArch64 syscall proof surface is limited to the dispatcher
  and return-frame helpers named in `CODE_MODEL_TRACE.md`.
- ASM-A64-005: The AArch64 context-switch proof surface is limited to the
  scheduler handoff and AArch64 switch/load entrypoints named in
  `CODE_MODEL_TRACE.md`.
