#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

if ./build.sh > /tmp/build-output.log 2>&1; then
    echo "✓ Build successful!"
    echo "✓ ISO: oreulius.iso"
    echo ""
    echo "To run: qemu-system-i386 -cdrom oreulius.iso"
else
    echo "✗ Build failed. Check /tmp/build-output.log"
    tail -20 /tmp/build-output.log
fi
