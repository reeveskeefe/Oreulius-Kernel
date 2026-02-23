#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

./build.sh
expect -f ci/smoke-i686.expect

