#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="target/aarch64-virt/Image"
if [[ ! -f "${IMAGE}" ]]; then
  echo "Image not found: ${IMAGE}"
  echo "Build it first with ./build-aarch64-virt.sh"
  exit 1
fi

DISK_IMAGE="${DISK_IMAGE:-target/aarch64-virt/virtio-net-blk-mmio-test.img}"
DISK_SIZE="${DISK_SIZE:-16M}"
NET_MAC="${NET_MAC:-52:54:00:12:34:56}"

mkdir -p "$(dirname "${DISK_IMAGE}")"
if [[ ! -f "${DISK_IMAGE}" ]]; then
  truncate -s "${DISK_SIZE}" "${DISK_IMAGE}"
fi

extra_args=()
if [[ -n "${QEMU_EXTRA_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  extra_args=(${QEMU_EXTRA_ARGS})
fi

exec qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a57 \
  -m 512M \
  -nographic \
  -monitor none \
  -serial stdio \
  -kernel "${IMAGE}" \
  -global virtio-mmio.force-legacy=false \
  -drive if=none,id=vd0,file="${DISK_IMAGE}",format=raw \
  -netdev user,id=net0 \
  -device "virtio-blk-device,drive=vd0,bus=virtio-mmio-bus.0" \
  -device "virtio-net-device,netdev=net0,mac=${NET_MAC},bus=virtio-mmio-bus.1" \
  "${extra_args[@]}"
