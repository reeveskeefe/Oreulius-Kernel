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

repeats="${CI_NETWORK_REPEATS:-1}"
: > "${log_dir}/network-i686.log"

for ((run = 1; run <= repeats; run++)); do
  echo "=== i686 network run ${run}/${repeats} ===" | tee -a "${log_dir}/network-i686.log"
  OREULIA_BOOT_ARGS="oreulia.shell_ci=1" ./build.sh
  python3 ci/network-i686.py 2>&1 | tee -a "${log_dir}/network-i686.log"
done
