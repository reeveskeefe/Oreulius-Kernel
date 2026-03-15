# Oreulia Docs Index

The `docs/` tree is organized by topic so the technical papers are grouped by subsystem instead of living in one flat directory.

## Root

- `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` stay at the top level because they are repo-wide process documents.
- `codepageheader.md` stays at the top level because source headers and contributor instructions point to it directly.
- `assets/` contains badges, screenshots, and branding used by the docs and README.

## Subdirectories

- `project/`
  - high-level positioning, MVP scope, and commercial framing
  - `oreulia-vision.md`
  - `oreulia-mvp.md`
  - `CommercialUseCases.md`

- `architecture/`
  - foundational theory, mathematical framing, and low-level reference material
  - `Polymorphic_Mathematical_Architecture.md`
  - `unified-theory-capability-trust-causal-semantics-thermodynamic-liveness.md`
  - `assembly-quick-reference.md`

- `capability/`
  - authority model, CapNet, policy contracts, predictive revocation, and runtime graph verification
  - `oreulia-capabilities.md`
  - `capnet.md`
  - `oreulia-intent-graph-predictive-revocation.md`
  - `oreulia-policy-contracts.md`
  - `oreulia-capability-entanglement.md`
  - `oreulia-cap-graph-verification.md`
  - `oreulia-kernel-mesh.md`

- `ipc/`
  - IPC design and implementation roadmap
  - `oreulia-ipc.md`
  - `oreulia-ipc-implementation-roadmap.md`

- `runtime/`
  - WASM execution, JIT hardening, ABI, and app-facing runtime guidance
  - `oreulia-app-dev-guide.md`
  - `oreulia-wasm-abi.md`
  - `oreulia-jit-security-resolution.md`
  - `oreulia-wasm-jit-pairwise-transition-coverage.md`

- `services/`
  - service-pointer capabilities, observer/event delivery, and polyglot service model
  - `oreulia-service-pointer-capabilities.md`
  - `oreulia-kernel-observers.md`
  - `oreulia-polyglot-services.md`

- `storage/`
  - filesystem, persistence, temporal objects, and temporal capability state
  - `oreulia-filesystem.md`
  - `oreulia-persistence.md`
  - `oreulia-temporal-adapters-durable-persistence.md`
  - `oreulia-temporal-capabilities.md`
