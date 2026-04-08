# Verification Overview

Oreulius treats verification as a scoped engineering program, not a blanket claim.

## Boundary Map

- Runtime code: kernel self-checks, shell commands, and runtime validation hooks
  remain inside [`kernel/`](../kernel/README.md).
- Generated evidence/artifacts: proof manifests and exported proof outputs live
  under [`../verification/artifacts/`](../verification/artifacts/manifest.json).
- Formal/spec docs: assumptions, invariants, and theorem inventory live under
  [`../verification/spec/`](../verification/spec/ASSUMPTIONS.md) and
  [`../verification/proof/`](../verification/proof/THEOREM_INDEX.md).
- CI/verification harness: structural checks live in
  [`../verification/scripts/`](../verification/scripts/proof_check.sh) and are
  enforced by [`../.github/workflows/proof-check.yml`](../.github/workflows/proof-check.yml).

## What Exists Today

- a dedicated verification workspace under [`../verification/`](../verification/README.md)
- theorem inventory and proof-governance material
- assumptions, threat model, and mapping documents
- CI gates that validate proof structure and repository consistency
- runtime evidence surfaces and regression harnesses that stay in the kernel tree

## What Is Explicitly Bounded

Oreulius does **not** currently claim full whole-system verification across:

- all architectures
- all low-level assembly paths
- all MMU / boot / trap boundaries
- the full toolchain and hardware stack
- all subsystem composition obligations

Those boundaries are tracked rather than hand-waved.

## Primary Documents

- [../verification/README.md](../verification/README.md)
- [../VERIFICATION_TARGET_MATRIX.md](../VERIFICATION_TARGET_MATRIX.md)
- [../verification/proof/THEOREM_INDEX.md](../verification/proof/THEOREM_INDEX.md)
- [../verification/spec/INVARIANTS.md](../verification/spec/INVARIANTS.md)
- [../verification/spec/ASSUMPTIONS.md](../verification/spec/ASSUMPTIONS.md)

## How To Read The Claim

The right question is not “is the kernel verified?” in the abstract.

The right question is:

- which properties are mechanized
- which runtime surfaces are checked
- which assumptions are trusted
- which composition obligations remain open

The proof workspace answers the artifact question. The kernel runtime answers
the operational self-check question. Keeping those separate reduces the chance
that a proof scaffold becomes an accidental runtime dependency.

That is the framing Oreulius uses.
