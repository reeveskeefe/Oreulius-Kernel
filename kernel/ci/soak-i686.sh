#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs

./build.sh
expect -f ci/soak-i686.expect | tee "ci/logs/soak-i686.log"

