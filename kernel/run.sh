#!/bin/bash
# Run Oreulia kernel in QEMU

set -euo pipefail

# Check for QEMU i386
if ! command -v qemu-system-i386 >/dev/null 2>&1; then
    echo "qemu-system-i386 not found. Install QEMU first."
    echo "  macOS: brew install qemu"
    echo "  Linux: sudo apt-get install qemu-system-x86"
    exit 1
fi

ISO_PATH="oreulia.iso"

# Check if ISO exists
if [ ! -f "$ISO_PATH" ]; then
    echo "ISO not found at $ISO_PATH"
    echo "Run ./build.sh first to create the ISO"
    exit 1
fi

echo "Starting Oreulia OS in QEMU..."
echo "Press Ctrl+C to exit"
echo ""

# Run QEMU with the ISO
qemu-system-i386 \
    -cdrom "$ISO_PATH" \
    -serial stdio
