#!/bin/bash
# Test boot script - simple version for macOS
cd "$(dirname "$0")"

echo "=== Oreulia Boot Test ==="
echo "Kernel size: $(ls -lh target/oreulia-kernel | awk '{print $5}')"
echo "ISO size: $(ls -lh oreulia.iso | awk '{print $5}')"
echo ""

# Kill any existing QEMU instances
pkill -9 qemu-system-i386 2>/dev/null
sleep 1

echo "Starting QEMU with GUI (close window to exit)..."
echo "If you see GRUB, the kernel should boot and show VGA output."
echo ""

qemu-system-i386 -cdrom oreulia.iso

echo ""
echo "QEMU closed."
