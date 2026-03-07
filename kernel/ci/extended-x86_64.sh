#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs

if [[ "${X64_JIT_FUZZ_24BIN:-0}" == "1" ]]; then
  export KERNEL_CARGO_FEATURES="${KERNEL_CARGO_FEATURES:-jit-fuzz-24bin}"
  export X64_EXPECT_BINS_TOTAL="${X64_EXPECT_BINS_TOTAL:-24}"
  export X64_EXPECT_EDGE_TOTAL="${X64_EXPECT_EDGE_TOTAL:-576}"
  export X64_EXPECT_EDGE_ADM_TOTAL="${X64_EXPECT_EDGE_ADM_TOTAL:-576}"
  # Coverage gate defaults for 24-bin mode.
  # Tune upward as backend parity improves.
  export X64_EXPECT_MIN_BINS="${X64_EXPECT_MIN_BINS:-24}"
  export X64_EXPECT_MIN_EDGES_FULL="${X64_EXPECT_MIN_EDGES_FULL:-240}"
  export X64_EXPECT_MIN_EDGES_ADM="${X64_EXPECT_MIN_EDGES_ADM:-240}"
  # jitfuzzreg full is a small cross-seed smoke run by default; keep a light gate
  # and enforce high edge floors on the dedicated wasm-jit-fuzz command above.
  export X64_EXPECT_MIN_JITFUZZREG_EDGES_FULL="${X64_EXPECT_MIN_JITFUZZREG_EDGES_FULL:-1}"
  export X64_EXPECT_MIN_JITFUZZREG_EDGES_ADM="${X64_EXPECT_MIN_JITFUZZREG_EDGES_ADM:-1}"
fi

./build-x86_64-mb2-iso.sh
expect -f ci/extended-x86_64.expect | tee "ci/logs/extended-x86_64.log"
