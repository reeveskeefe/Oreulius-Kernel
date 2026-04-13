# Runtime Evidence

## formal-verify
- **Description**: Dependency-aware Coq proof compilation of all `.v` theory files under `verification/theories/` using the tracked `_CoqProject` and Makefile, plus the runtime boundary checks recorded in `verification/proof/THEOREM_INDEX.md`, including the IPC self-check report surfaced by `kernel/src/shell/commands.rs::cmd_formal_verify`.
- **How to run**: `make -C verification/theories -j1`, `bash verification/scripts/proof_check.sh`, or `bash kernel/formal-verify.sh`
- **Expected output**: `make` exits 0 for all tracked theory files under `verification/theories/`; compiled `.vo` artifacts written to `verification/theories/`.
- **CI job**: `proof-check` workflow, `coq-proofs` step.
- **Last known passing commit**: a2acf53

## ipc-selftest
- **Description**: In-kernel runtime self-test that exercises ticketed zero-sum capability transfer, Temporal session typing, and replayable channel snapshots with wait-queue restoration alongside the legacy IPC basics.
- **How to trigger**: Shell command `ipc-selftest`; also included in `formal-verify`.
- **Expected output**: All 15 sub-tests print `PASS`; no assertion failures or panics.
- **CI coverage**: `kernel/src/ipc/selftest.rs::runtime_ipc_selftest_cases_pass`; the `formal-verify` shell surface includes the same report.
- **Last known passing commit**: pending on the current branch

## temporal-hardening-selftest
- **Description**: In-kernel runtime self-test that exercises the temporal object write/read/recover path, verifying the monotonic-clock and persistence-roundtrip properties at boot.
- **How to trigger**: Shell command `temporal-hardening-selftest` (wired in `kernel/src/shell/commands.rs`).
- **Expected output**: All sub-tests print `PASS`; no assertion failures or panics.
- **CI coverage**: `extended-x86_64.sh` and `extended-aarch64.sh` run the selftest via `expect` scripts in `kernel/ci/`.
- **Last known passing commit**: a2acf53

## policy-contract-selftest
- **Description**: In-kernel runtime self-test for full-WASM policy contracts, confirming the sandboxed `policy_check(ctx_ptr, ctx_len) -> i32` path fails closed on invalid modules and permits a minimal conforming blob.
- **How to trigger**: Covered by the kernel unit tests in `kernel/src/execution/wasm.rs` under `policy_tests`.
- **Expected output**: Policy contract evaluation returns `Permit` for the minimal conforming blob and denies malformed or unsupported modules.
- **CI coverage**: Kernel `cargo check` / unit test coverage; should be promoted to explicit shell evidence if a dedicated command is added.
- **Last known passing commit**: a2acf53

## mesh-migrate-selftest
- **Description**: In-kernel runtime self-test that verifies `mesh_migrate(..., wasm_len = 0)` snapshots the caller's stored module bytecode instead of queueing an empty payload.
- **How to trigger**: Covered by the kernel unit tests in `kernel/src/execution/wasm.rs` under `policy_tests`.
- **Expected output**: The payload snapshot equals the instance's module bytecode when the explicit payload length is zero.
- **CI coverage**: Kernel `cargo check` / unit test coverage; should be promoted to explicit shell evidence if a dedicated command is added.
- **Last known passing commit**: a2acf53

## net-connect-selftest
- **Description**: In-kernel runtime self-test that verifies dotted-quad IPv4 parsing for `oreulius_net_connect` and documents the real TCP-connection path used by the host ABI.
- **How to trigger**: Covered by the kernel unit tests in `kernel/src/execution/wasm.rs` under `policy_tests`.
- **Expected output**: Valid IPv4 literals parse to the expected octets; non-literals fall through to hostname resolution in the host path.
- **CI coverage**: Kernel `cargo check` / unit test coverage.
- **Last known passing commit**: a2acf53

## polyglot-link-audit
- **Description**: In-kernel audit event emitted when `polyglot_link` establishes a cross-language service link.
- **How to trigger**: `polyglot_link(...)` during a runtime session with an audit observer active.
- **Expected output**: `SecurityEvent::CapDelegationChain` entry with provenance context.
- **CI coverage**: Exercised by the polyglot ABI runtime conformance self-checks and security audit log path.
- **Last known passing commit**: a2acf53

## capnet-fuzz-corpus
- **Description**: LibFuzzer / cargo-fuzz corpus for the CapNet IPC path. Exercises arbitrary message payloads including malformed capability tokens, oversized messages, and revoke-then-send races.
- **How to run**: `cd kernel && cargo fuzz run capnet_fuzz -- corpus/capnet/`
- **Corpus location**: `kernel/fuzz/corpus/capnet/` (seed inputs committed; expanded corpus generated during CI).
- **Expected outcome**: No panics, no memory safety violations, no capability bypass findings after 60 s minimum run.
- **CI job**: `fuzz` workflow (optional / scheduled); triggered on demand by maintainers.
- **Last known passing commit**: a2acf53

## wasm-jit-fuzz-corpus
- **Description**: LibFuzzer corpus for the WASM JIT compiler and bounds-checking path. Exercises arbitrary WASM binary inputs to verify the W^X and CFI invariants hold under malformed modules.
- **How to run**: `cd kernel && cargo fuzz run wasm_jit_fuzz -- corpus/wasm_jit/`
- **Corpus location**: `kernel/fuzz/corpus/wasm_jit/` (seed valid + invalid WASM modules; expanded during CI).
- **Expected outcome**: No OOB writes to non-WASM pages, no execution from writable pages, no panics.
- **CI job**: `fuzz` workflow (optional / scheduled); triggered on demand by maintainers.
- **Last known passing commit**: a2acf53
