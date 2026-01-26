#!/bin/bash
# Run Oreulia kernel in QEMU

set -euo pipefail

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 not found. Install QEMU first."
    exit 1
fi

if ! command -v bootimage >/dev/null 2>&1; then
    echo "bootimage not found. Installing..."
    cargo install bootimage
fi

if ! command -v rust-objcopy >/dev/null 2>&1; then
    echo "llvm-tools-preview not found. Installing..."
    rustup component add llvm-tools-preview
fi

echo "Building kernel..."
cargo +nightly bootimage

IMAGE_PATH="target/x86_64-unknown-none/debug/bootimage-oreulia-kernel.bin"
if [ ! -f "$IMAGE_PATH" ]; then
    echo "Boot image not found at $IMAGE_PATH"
    exit 1
fi

echo "Starting QEMU..."
qemu-system-x86_64 \
    -drive format=raw,file="$IMAGE_PATH" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -serial stdio