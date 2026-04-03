#!/bin/bash
# Launch Node A for the multi-node CapNet regression lane.
# Node A listens on a QEMU socket so Node B can connect.
# Uses the same ISO as run-x86_64-mb2-grub.sh.
set -euo pipefail
cd "$(dirname "$0")"

CAPNET_SOCKET_PORT="${CAPNET_SOCKET_PORT:-5560}"

export QEMU_EXTRA_ARGS="\
-display none -monitor none -nographic -no-reboot -no-shutdown -m 512M \
-netdev socket,listen=:${CAPNET_SOCKET_PORT},id=n0 \
-device e1000,netdev=n0,mac=52:54:00:aa:aa:aa"

exec ./run-x86_64-mb2-grub.sh
