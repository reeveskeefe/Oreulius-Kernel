#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== i686 boot soak =="
I686_SOAK_SECONDS="${I686_SOAK_SECONDS:-20}" ./ci/soak-i686.sh

echo "== x86_64 extended shell regression =="
X64_EXT_LOOPS="${X64_EXT_LOOPS:-5}" ./ci/extended-x86_64.sh

echo "== AArch64 extended shell regression =="
A64_EXT_LOOPS="${A64_EXT_LOOPS:-4}" ./ci/extended-aarch64.sh

