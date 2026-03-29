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
tmp_dir="$(pwd)/target/aarch64-virt"
mkdir -p "${tmp_dir}"
temp_disk="${tmp_dir}/network-aarch64-$$.img"
truncate -s 16M "${temp_disk}"
trap 'rm -f "${temp_disk}"' EXIT

export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--no-reboot -no-shutdown}"
export DISK_IMAGE="${DISK_IMAGE:-${temp_disk}}"

./build-aarch64-virt.sh
expect -f ci/network-aarch64.expect | tee "${log_dir}/network-aarch64.log"
