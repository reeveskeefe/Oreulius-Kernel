#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs

if [[ "${X64_JIT_FUZZ_24BIN:-0}" == "1" ]]; then
  export KERNEL_CARGO_FEATURES="${KERNEL_CARGO_FEATURES:-jit-fuzz-24bin}"
  export X64_EXPECT_BINS_TOTAL="${X64_EXPECT_BINS_TOTAL:-24}"
  export X64_EXPECT_EDGE_TOTAL="${X64_EXPECT_EDGE_TOTAL:-576}"
  export X64_EXPECT_EDGE_ADM_TOTAL="${X64_EXPECT_EDGE_ADM_TOTAL:-576}"
fi

./build-x86_64-mb2-iso.sh
expect -f ci/extended-x86_64.expect | tee "ci/logs/extended-x86_64.log"
