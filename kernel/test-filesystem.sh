#!/bin/bash
# Test script for Oreulia filesystem

echo "Testing Oreulia Filesystem Implementation"
echo "=========================================="
echo ""
echo "Starting QEMU with oreulia.iso..."
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
qemu-system-i386 -cdrom oreulia.iso
