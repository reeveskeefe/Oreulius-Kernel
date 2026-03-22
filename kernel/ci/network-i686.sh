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

./build.sh
expect -f ci/network-i686.expect | tee "${log_dir}/network-i686.log"
