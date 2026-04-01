#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

tmp_dir="$(pwd)/target/aarch64-virt"
mkdir -p "${tmp_dir}"
temp_disk="${tmp_dir}/smoke-aarch64-$$.img"
truncate -s 16M "${temp_disk}"
trap 'rm -f "${temp_disk}"' EXIT

export DISK_IMAGE="${DISK_IMAGE:-${temp_disk}}"

./build-aarch64-virt.sh
expect -f ci/smoke-aarch64.expect
