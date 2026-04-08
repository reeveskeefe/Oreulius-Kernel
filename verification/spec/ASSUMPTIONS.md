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
