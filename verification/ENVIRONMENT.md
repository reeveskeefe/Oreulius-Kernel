# Verification Environment Bootstrap

## Reproducible Setup

```bash
# from repo root — directory structure (already present in repo)
mkdir -p verification/{spec,proof,theories,mapping,artifacts,scripts,ci}
```

## Toolchain Install

### macOS (Homebrew)
```bash
brew install coq          # installs Rocq Prover 9.1.1 + OCaml 5.4.0
coqc --version            # expected: "The Rocq Prover, version 9.1.1"
```

### Ubuntu / Debian (CI)
```bash
sudo apt-get update -qq
# Option A — Ubuntu 24.04 apt (Coq 8.19.x, compatible with all .v files here):
sudo apt-get install -y coq
# Option B — exact 9.1.1 via PPA:
sudo add-apt-repository ppa:rocq-prover/rocq -y
sudo apt-get update -qq && sudo apt-get install -y rocq
coqc --version
```

### Version Check
```
coqc --version
# Accepted outputs:
#   The Rocq Prover, version 9.1.1        (macOS Homebrew / PPA)
#   The Coq Proof Assistant, version 8.19.x  (Ubuntu 24.04 apt)
```

## Compiling Theories
```bash
# Compile all .v files with the dependency-aware Coq Makefile:
make -C verification/theories -j1
# Success: no output; .vo / .vok / .vos artifacts written alongside each .v file.
```

## Verification Entry Points
- `bash verification/scripts/proof_check.sh`   — structural gate (runs in CI)
- `bash kernel/formal-verify.sh`               — QEMU-based runtime verification gate
- `make -C verification/theories -j1`          — dependency-aware Coq theory build
