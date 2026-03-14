#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

ISO_PATH="oreulia.iso"
if [[ ! -f "${ISO_PATH}" ]]; then
    echo "ISO not found at ${ISO_PATH}"
    echo "Run ./build.sh first."
    exit 1
fi

echo "Testing Oreulia Filesystem Implementation"
echo "=========================================="
echo ""
echo "Starting QEMU with ${ISO_PATH}..."
echo ""
echo "Commands to test:"
echo "  help         - Show available commands"
echo "  fs-write key data - Write a file"
echo "  fs-read key  - Read a file"
echo "  fs-list      - List all files"
echo "  fs-stats     - Show filesystem statistics"
echo "  fs-delete key - Delete a file"
echo ""
echo "Example session:"
echo "  > fs-write test.txt hello"
echo "  > fs-read test.txt"
echo "  > fs-list"
echo "  > fs-stats"
echo ""

# Run QEMU with display
qemu-system-i386 -cdrom "${ISO_PATH}"
