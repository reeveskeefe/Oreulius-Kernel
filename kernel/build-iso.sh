#!/bin/bash
set -e

KERNEL_BIN="target/x86_64-unknown-none/debug/oreulia-kernel"
ISO_DIR="iso"
GRUB_CFG="$ISO_DIR/boot/grub/grub.cfg"
ISO_FILE="oreulia.iso"

# Build kernel
echo "Building kernel..."
cargo +nightly-2023-11-01 build

# Create ISO directory structure
mkdir -p "$ISO_DIR/boot/grub"

# Copy kernel
cp "$KERNEL_BIN" "$ISO_DIR/boot/"

# Create GRUB config
cat > "$GRUB_CFG" << 'EOF'
set timeout=0
set default=0

menuentry "Oreulia OS" {
    multiboot2 /boot/oreulia-kernel
    boot
}
EOF

# Create ISO with GRUB
echo "Creating bootable ISO..."
i686-elf-grub-mkrescue -o "$ISO_FILE" "$ISO_DIR" 2>/dev/null || {
    echo "Error creating ISO"
    exit 1
}

echo "ISO created: $ISO_FILE"
echo "Starting QEMU..."
qemu-system-x86_64 -cdrom "$ISO_FILE" -serial stdio -m 512M
