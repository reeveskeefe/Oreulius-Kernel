#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

./build-aarch64-virt.sh
expect -f ci/smoke-aarch64.expect

