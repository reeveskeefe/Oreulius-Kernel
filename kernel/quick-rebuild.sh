#!/bin/bash
cd /Users/keefereeves/Desktop/oreulia/kernel
./build.sh > /tmp/build-output.log 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Build successful!"
    echo "✓ ISO: oreulia.iso"
    echo ""
    echo "To run: qemu-system-i386 -cdrom oreulia.iso"
else
    echo "✗ Build failed. Check /tmp/build-output.log"
    tail -20 /tmp/build-output.log
fi
