#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="target/aarch64-virt/Image"

if [[ ! -f "${IMAGE}" ]]; then
  echo "Image not found: ${IMAGE}"
  echo "Build it first with ./build-aarch64-virt.sh"
  exit 1
fi

exec qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a57 \
  -m 512M \
  -nographic \
  -monitor none \
  -serial stdio \
  -kernel "${IMAGE}"

