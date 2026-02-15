# WASM JIT Fuzz Corpus

This directory contains the external regression corpus for Oreulia's in-kernel WASM JIT fuzzing.

## Files

- `wasm_jit_seed_corpus.txt`:
  Stable seed corpus used for replay/regression checks.
- `run_wasm_jit_corpus.expect`:
  External runner that boots QEMU, executes each corpus seed through
  `wasm-jit-fuzz`, then runs `wasm-jit-fuzz-corpus` for aggregate stats.

## Usage

From `kernel/`:

```bash
./fuzz/run_wasm_jit_corpus.expect 1000
./fuzz/run_wasm_jit_corpus.expect 1000 3
./fuzz/ci_regression_check.sh 1000 2
```

Inside the Oreulia shell, you can also run:

```text
wasm-jit-fuzz 1000 3418704842
wasm-jit-fuzz-corpus 1000
```
