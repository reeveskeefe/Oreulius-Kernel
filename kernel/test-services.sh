#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

ISO_PATH="oreulius.iso"
if [[ ! -f "${ISO_PATH}" ]]; then
    echo "ISO not found at ${ISO_PATH}"
    echo "Run ./build.sh first."
    exit 1
fi

echo "Testing Oreulius Service Functionality"
echo "===================================="

# Create input file
cat > /tmp/qemu_input.txt << 'EOF'
help
svc-list
svc-register filesystem
svc-register console
svc-register timer
svc-list
svc-stats
svc-request filesystem
svc-request console
svc-request timer
EOF

# Run QEMU with input from file
qemu-system-i386 -cdrom "${ISO_PATH}" -serial stdio < /tmp/qemu_input.txt
