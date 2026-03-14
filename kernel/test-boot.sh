#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

ISO_PATH="oreulia.iso"
KERNEL_ELF="target/oreulia-kernel"

if [[ ! -f "${KERNEL_ELF}" ]]; then
    echo "Kernel ELF not found at ${KERNEL_ELF}"
    echo "Run ./build.sh first."
    exit 1
fi

if [[ ! -f "${ISO_PATH}" ]]; then
    echo "ISO not found at ${ISO_PATH}"
    echo "Run ./build.sh first."
    exit 1
fi

echo "=== Oreulia Boot Test ==="
echo "Kernel size: $(ls -lh "${KERNEL_ELF}" | awk '{print $5}')"
echo "ISO size: $(ls -lh "${ISO_PATH}" | awk '{print $5}')"
echo ""

# Kill any existing QEMU instances
pkill -9 qemu-system-i386 2>/dev/null
sleep 1

echo "Starting QEMU with GUI (close window to exit)..."
echo "If you see GRUB, the kernel should boot and show VGA output."
echo ""

qemu-system-i386 -cdrom "${ISO_PATH}"

echo ""
echo "QEMU closed."
