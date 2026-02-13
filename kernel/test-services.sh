#!/bin/bash
# Test script for service functionality

echo "Testing Oreulia Service Functionality"
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
qemu-system-i386 -cdrom oreulia.iso -serial stdio < /tmp/qemu_input.txt