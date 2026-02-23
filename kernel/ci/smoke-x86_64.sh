#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

./build-x86_64-mb2-iso.sh
expect -f ci/smoke-x86_64.expect

