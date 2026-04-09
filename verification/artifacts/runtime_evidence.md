# Runtime Evidence

## formal-verify
- **Description**: Dependency-aware Coq proof compilation of all `.v` theory files under `verification/theories/` using the tracked `_CoqProject` and Makefile.
- **How to run**: `make -C verification/theories -j1`, `bash verification/scripts/proof_check.sh`, or `bash kernel/formal-verify.sh`
- **Expected output**: `make` exits 0 for all tracked theory files under `verification/theories/`; compiled `.vo` artifacts written to `verification/theories/`.
- **CI job**: `proof-check` workflow, `coq-proofs` step.
- **Last known passing commit**: a2acf53

## temporal-hardening-selftest
- **Description**: In-kernel runtime self-test that exercises the temporal object write/read/recover path, verifying the monotonic-clock and persistence-roundtrip properties at boot.
- **How to trigger**: Shell command `temporal-hardening-selftest` (wired in `kernel/src/shell/commands.rs`).
- **Expected output**: All sub-tests print `PASS`; no assertion failures or panics.
- **CI coverage**: `extended-x86_64.sh` and `extended-aarch64.sh` run the selftest via `expect` scripts in `kernel/ci/`.
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
