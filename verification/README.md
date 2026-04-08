# Oreulius Verification Workspace

This directory is the boundary between runtime code and verification material.

The kernel runtime keeps its self-check entry points inside `kernel/src/`.
The proof workspace, assumptions, theorem inventory, and generated evidence
live here so they do not become runtime dependencies.

## Layout

- `spec/` - assumptions and invariants that define the verification scope
- `proof/` - theorem inventory and proof-governance records
- `theories/` - Coq theory files that mechanize the proof artifacts
- `artifacts/` - generated evidence such as manifests and exported proof data
- `scripts/` - CI-only verification checks and consistency gates

## Boundary Policy

- Runtime self-checks such as `formal-verify` remain in the kernel shell and
  kernel subsystems.
- Proof artifacts do not get imported by the kernel binary.
- Generated evidence is treated as CI and governance output, not runtime state.
- Formal/spec documents here describe the verification target, not the runtime
  implementation details.

## Primary Files

- `spec/ASSUMPTIONS.md`
- `spec/INVARIANTS.md`
- `proof/THEOREM_INDEX.md`
- `artifacts/manifest.json`
- `scripts/proof_check.sh`

## Reading Order

1. Read `spec/ASSUMPTIONS.md` to understand the trusted base.
2. Read `spec/INVARIANTS.md` to understand the properties being preserved.
3. Read `proof/THEOREM_INDEX.md` to see which artifacts are tracked.
4. Inspect `theories/` for the mechanized model surface.
5. Use the runtime shell command `formal-verify` to exercise the kernel-side
   self-checks when you need an operational evidence surface.
