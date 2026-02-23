#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="target/aarch64-virt/Image"
if [[ ! -f "${IMAGE}" ]]; then
  echo "Image not found: ${IMAGE}"
  echo "Build it first with ./build-aarch64-virt.sh"
  exit 1
fi

BUS_SLOT="${BUS_SLOT:-0}"
DISK_IMAGE="${DISK_IMAGE:-target/aarch64-virt/virtio-blk-mmio-test.img}"
DISK_SIZE="${DISK_SIZE:-16M}"

mkdir -p "$(dirname "${DISK_IMAGE}")"
if [[ ! -f "${DISK_IMAGE}" ]]; then
  truncate -s "${DISK_SIZE}" "${DISK_IMAGE}"
fi

exec qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a57 \
  -m 512M \
  -nographic \
  -monitor none \
  -serial stdio \
  -kernel "${IMAGE}" \
  -drive if=none,id=vd0,file="${DISK_IMAGE}",format=raw \
  -device "virtio-blk-device,drive=vd0,bus=virtio-mmio-bus.${BUS_SLOT}"
