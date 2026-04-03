# Oreulius Docs Index

The `docs/` tree is organized by topic so the technical papers are grouped by subsystem instead of living in one flat directory.

## Root

- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` stay at the top level because they are repo-wide process documents.
- `codepageheader.md` stays at the top level because source headers and contributor instructions point to it directly.
- `assets/` contains badges, screenshots, and branding used by the docs and README.

## Subdirectories

- `project/`
  - high-level positioning, MVP scope, and commercial framing
  - `oreulius-vision.md`
  - `oreulius-mvp.md`
  - `CommercialUseCases.md`

- `architecture/`
  - foundational theory, mathematical framing, and low-level reference material
  - `Polymorphic_Mathematical_Architecture.md`
  - `unified-theory-capability-trust-causal-semantics-thermodynamic-liveness.md`
  - `assembly-quick-reference.md`

- `capability/`
  - authority model, CapNet, policy contracts, predictive revocation, and runtime graph verification
  - `oreulius-capabilities.md`
  - `capnet.md`
  - `oreulius-intent-graph-predictive-revocation.md`
  - `oreulius-policy-contracts.md`
  - `oreulius-capability-entanglement.md`
  - `oreulius-cap-graph-verification.md`
  - `oreulius-kernel-mesh.md`

- `ipc/`
  - IPC design and implementation roadmap
  - `oreulius-ipc.md`
  - `oreulius-ipc-implementation-roadmap.md`

- `runtime/`
  - WASM execution, JIT hardening, ABI, and app-facing runtime guidance
  - `oreulius-app-dev-guide.md`
  - `oreulius-wasm-abi.md`
  - `oreulius-jit-security-resolution.md`
  - `oreulius-wasm-jit-pairwise-transition-coverage.md`

- `services/`
  - service-pointer capabilities, observer/event delivery, and polyglot service model
  - `oreulius-service-pointer-capabilities.md`
  - `oreulius-kernel-observers.md`
  - `oreulius-polyglot-services.md`

- `storage/`
  - filesystem, persistence, temporal objects, and temporal capability state
  - `oreulius-filesystem.md`
  - `oreulius-persistence.md`
  - `oreulius-temporal-adapters-durable-persistence.md`
  - `oreulius-temporal-capabilities.md`
