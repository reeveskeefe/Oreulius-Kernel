#!/bin/bash
set -e

echo "=== Building Oreulia OS ==="

echo "[1/3] Assembling bootloader..."
nasm -f elf32 simpleboot.asm -o simpleboot.o

echo "[2/3] Linking kernel..."
x86_64-elf-ld -m elf_i386 -T kernel.ld -o target/oreulia-kernel simpleboot.o

echo "[3/3] Creating ISO..."
mkdir -p iso/boot/grub
cp target/oreulia-kernel iso/boot/
i686-elf-grub-mkrescue -o oreulia.iso iso/ 2>&1 | grep -i "success" || true

if i686-elf-grub-file --is-x86-multiboot target/oreulia-kernel; then
    echo "✓ Multiboot kernel created"
    echo "✓ ISO: oreulia.iso"
    echo ""
    echo "Boot: qemu-system-i386 -cdrom oreulia.iso"
fi
