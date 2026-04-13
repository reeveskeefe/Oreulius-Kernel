# Oreulius Verification Workspace

This directory is the boundary between runtime code and verification material.

The kernel runtime keeps its self-check entry points inside `kernel/src/`.
The proof workspace, assumptions, theorem inventory, and generated evidence
live here so they do not become runtime dependencies.

## Layout

- `spec/` - assumptions and invariants that define the verification scope
- `proof/` - theorem inventory and proof-governance records
- `theories/` - Coq theory files, `_CoqProject`, and the dependency-aware Makefile
- `artifacts/` - generated evidence such as manifests and exported proof data
- `scripts/` - CI-only verification checks and consistency gates

## Boundary Policy

- Runtime self-checks such as `formal-verify` remain in the kernel shell and
  kernel subsystems.
- Proof artifacts do not get imported by the kernel binary.
- Generated evidence is treated as CI and governance output, not runtime state.
- Formal/spec documents here describe the verification target, not the runtime
  implementation details.

## Runtime Invariants In Scope

The verification workspace should stay aligned with the kernel-side invariants
that are exercised by `formal-verify` and the dedicated self-checks. Current
runtime invariants that must remain documented here include:

- full-WASM policy contracts are fail-closed, self-contained, and export `policy_check(ctx_ptr, ctx_len) -> i32`
- `mesh_migrate(..., wasm_len = 0)` migrates the caller's stored bytecode rather than an empty payload
- `oreulius_net_connect(...)` resolves IPv4 literals or DNS names and returns a real TCP handle from the reactor stack
- `polyglot_link(...)` records provenance/audit state when a cross-language service link is created
- ticketed message-carried capability transfer is zero-sum and one-time
- Temporal-bound IPC channels enforce session and phase typing
- IPC channel snapshots round-trip committed queue, wait queues, closure, protocol, and counter state
- `formal-verify` now includes the IPC self-check report in the runtime gate

When new runtime invariants are added in `kernel/src/execution/wasm.rs`, they
should be reflected in `spec/INVARIANTS.md`, the relevant proof targets, and
the runtime evidence records under `artifacts/`.

## Primary Files

- `spec/ASSUMPTIONS.md`
- `spec/INVARIANTS.md`
- `proof/THEOREM_INDEX.md`
- `theories/_CoqProject`
- `theories/Makefile`
- `artifacts/manifest.json`
- `scripts/proof_check.sh`

## Reading Order

1. Read `spec/ASSUMPTIONS.md` to understand the trusted base.
2. Read `spec/INVARIANTS.md` to understand the properties being preserved.
3. Read `proof/THEOREM_INDEX.md` to see which artifacts are tracked.
4. Inspect `theories/` for the mechanized model surface and the Coq build entry points.
5. Use the runtime shell command `formal-verify` to exercise the kernel-side
   self-checks when you need an operational evidence surface.
