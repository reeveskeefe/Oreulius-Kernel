#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p ci/logs
log_file="ci/logs/extended-aarch64.log"
expect_cmd_timeout="${A64_EXPECT_CMD_TIMEOUT:-300}"
harness_timeout="${A64_EXPECT_HARNESS_TIMEOUT:-420}"

export DISK_IMAGE="${DISK_IMAGE:-target/aarch64-virt/virtio-blk-mmio-extended-$$.img}"
export A64_EXPECT_CMD_TIMEOUT="$expect_cmd_timeout"

{
    echo "=== AArch64 extended shell regression ==="
    echo "log_file=$log_file"
    echo "disk_image=$DISK_IMAGE"
    echo "A64_EXT_LOOPS=${A64_EXT_LOOPS:-4}"
    echo "A64_INCLUDE_VMTEST=${A64_INCLUDE_VMTEST:-1}"
    echo "A64_INCLUDE_STRICT_UART_IRQ=${A64_INCLUDE_STRICT_UART_IRQ:-0}"
    echo "A64_EXPECT_CMD_TIMEOUT=$A64_EXPECT_CMD_TIMEOUT"
    echo "A64_EXPECT_HARNESS_TIMEOUT=$harness_timeout"
    echo "=== Building Oreulius kernel (AArch64 QEMU virt bring-up) ==="
} | tee "$log_file"

./build-aarch64-virt.sh 2>&1 | tee -a "$log_file"

echo "=== Running AArch64 extended expect harness ===" | tee -a "$log_file"
set +e
timeout --foreground "$harness_timeout" expect -f ci/extended-aarch64.expect 2>&1 | tee -a "$log_file"
status=${PIPESTATUS[0]}
set -e

case "$status" in
    0)
        echo "AArch64 extended harness completed successfully" | tee -a "$log_file"
        ;;
    124)
        echo "AArch64 extended harness timed out after ${harness_timeout}s" | tee -a "$log_file" >&2
        ;;
    *)
        echo "AArch64 extended harness failed with exit status ${status}" | tee -a "$log_file" >&2
        ;;
esac

exit "$status"
