#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs

./build-aarch64-virt.sh
export DISK_IMAGE="${DISK_IMAGE:-target/aarch64-virt/virtio-blk-mmio-extended-$$.img}"
expect -f ci/extended-aarch64.expect | tee "ci/logs/extended-aarch64.log"

