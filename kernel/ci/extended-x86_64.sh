#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs

./build-x86_64-mb2-iso.sh
expect -f ci/extended-x86_64.expect | tee "ci/logs/extended-x86_64.log"

