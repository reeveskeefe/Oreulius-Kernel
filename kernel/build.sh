#!/bin/bash
set -euo pipefail

echo "=== Building Oreulia OS ==="

TOOLCHAIN="+nightly-2023-11-01"
RUST_TARGET="./i686-oreulia.json"
RUST_LIB="target/i686-oreulia/release/liboreulia_kernel.a"

mkdir -p target

echo "[1/4] Building Rust kernel (staticlib, i686)..."
cargo ${TOOLCHAIN} build --release --lib --target "${RUST_TARGET}" \
  -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem

if [[ ! -f "${RUST_LIB}" ]]; then
  echo "ERROR: expected staticlib at ${RUST_LIB}"
  exit 1
fi

echo "[2/4] Assembling boot stub (boot.asm)..."
nasm -f elf32 boot.asm -o boot.o

echo "[3/4] Linking kernel (boot.o + liboreulia_kernel.a)..."
x86_64-elf-ld \
  -m elf_i386 \
  -T kernel.ld \
  -nostdlib \
  -o target/oreulia-kernel \
  boot.o \
  --whole-archive "${RUST_LIB}" --no-whole-archive

echo "[4/4] Creating ISO..."
mkdir -p iso/boot/grub
cp target/oreulia-kernel iso/boot/
i686-elf-grub-mkrescue -o oreulia.iso iso/ 2>&1 | grep -i "success" || true

echo ""
echo "=== Verification ==="
if i686-elf-grub-file --is-x86-multiboot target/oreulia-kernel; then
    echo "✓ Multiboot kernel created"
    echo "✓ ISO: oreulia.iso"
    echo ""
    echo "Boot: qemu-system-i386 -cdrom oreulia.iso"
else
    echo "✗ Kernel NOT multiboot compliant"
    exit 1
fi
