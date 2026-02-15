# Kernel Regression Corpus

This directory contains external regression corpora for Oreulia kernel fuzzing.

## Files

- `wasm_jit_seed_corpus.txt`:
  Stable seed corpus used for replay/regression checks.
- `run_wasm_jit_corpus.expect`:
  External runner that boots QEMU, executes each corpus seed through
  `wasm-jit-fuzz`, then runs `wasm-jit-fuzz-corpus` for aggregate stats.
- `ci_regression_check.sh`:
  CI gate for WASM JIT corpus replay + soak checks.
- `capnet_seed_corpus.txt`:
  Stable seed corpus used for CapNet parser/enforcer replay checks.
- `run_capnet_corpus.expect`:
  External runner that executes `capnet-fuzz` per seed, then aggregate
  `capnet-fuzz-corpus`, `capnet-fuzz-soak`, and `formal-verify`.
- `ci_capnet_check.sh`:
  CI gate for CapNet corpus replay + soak + formal verification checks.

## Usage

From `kernel/`:

```bash
./fuzz/run_wasm_jit_corpus.expect 1000
./fuzz/run_wasm_jit_corpus.expect 1000 3
./fuzz/ci_regression_check.sh 1000 2

./fuzz/run_capnet_corpus.expect 1000
./fuzz/run_capnet_corpus.expect 1000 2
./fuzz/ci_capnet_check.sh 1000 2
```

Inside the Oreulia shell, you can also run:

```text
wasm-jit-fuzz 1000 3418704842
wasm-jit-fuzz-corpus 1000
capnet-fuzz 1000 3418704842
capnet-fuzz-corpus 1000
```
