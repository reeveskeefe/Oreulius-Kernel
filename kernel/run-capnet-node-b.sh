#!/bin/bash
# Launch Node B for the multi-node CapNet regression lane.
# Node B connects to Node A's QEMU socket.
# Uses the same ISO as run-x86_64-mb2-grub.sh.
set -euo pipefail
cd "$(dirname "$0")"

CAPNET_SOCKET_PORT="${CAPNET_SOCKET_PORT:-5560}"

export QEMU_EXTRA_ARGS="\
-display none -monitor none -nographic -no-reboot -no-shutdown -m 512M \
-netdev socket,connect=127.0.0.1:${CAPNET_SOCKET_PORT},id=n0 \
-device e1000,netdev=n0,mac=52:54:00:bb:bb:bb"

exec ./run-x86_64-mb2-grub.sh
