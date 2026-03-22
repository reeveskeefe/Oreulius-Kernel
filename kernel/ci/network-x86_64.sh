#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

log_dir="${CI_LOG_DIR:-}"
if [[ -z "${log_dir}" ]]; then
  if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
    log_dir="${GITHUB_WORKSPACE}/kernel/ci/logs"
  else
    log_dir="$(pwd)/ci/logs"
  fi
fi
mkdir -p "${log_dir}"

export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--display none -monitor none -nographic -no-reboot -no-shutdown -m 512M -netdev user,id=n0 -device e1000,netdev=n0}"

./build-x86_64-mb2-iso.sh
expect -f ci/network-x86_64.expect | tee "${log_dir}/network-x86_64.log"
