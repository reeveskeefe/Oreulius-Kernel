#!/bin/bash
# CI driver for the two-node CapNet regression lane.
# Builds the x86_64 ISO once, then runs the expect orchestrator which
# spawns two QEMU instances connected via a QEMU socket network.
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

# Port used for the QEMU socket tunnel between Node A (listen) and Node B (connect).
export CAPNET_SOCKET_PORT="${CAPNET_SOCKET_PORT:-5560}"

./build-x86_64-mb2-iso.sh
expect -f ci/capnet-multinode-x86_64.expect \
  | tee "${log_dir}/capnet-multinode-x86_64.log"
