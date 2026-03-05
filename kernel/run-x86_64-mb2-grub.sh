#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

ISO="target/x86_64-mb2/oreulia-x86_64-mb2.iso"
ELF="target/x86_64-mb2/oreulia-kernel-x86_64"
if [[ ! -f "${ISO}" ]]; then
  echo "ISO not found: ${ISO}"
  echo "Build it first with ./build-x86_64-mb2-iso.sh"
  exit 1
fi
if [[ -f "${ELF}" && "${ELF}" -nt "${ISO}" ]]; then
  echo "x86_64 ELF is newer than ISO:"
  echo "  ELF: ${ELF}"
  echo "  ISO: ${ISO}"
  echo "Rebuild ISO first:"
  echo "  ./build-x86_64-mb2-iso.sh"
  exit 1
fi

QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:-}"

if [[ -n "${QEMU_EXTRA_ARGS}" ]]; then
  # shellcheck disable=SC2086
  exec qemu-system-x86_64 -cdrom "${ISO}" -serial stdio ${QEMU_EXTRA_ARGS}
else
  exec qemu-system-x86_64 -cdrom "${ISO}" -serial stdio
fi
