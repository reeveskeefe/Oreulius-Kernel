#!/bin/bash
set -euo pipefail

echo "=== Building Oreulia OS ==="

TOOLCHAIN="+nightly-2023-11-01"
RUST_TARGET="./i686-oreulia.json"
RUST_LIB="target/i686-oreulia/release/liboreulia_kernel.a"

mkdir -p target

echo "[1/6] Assembling optimized assembly modules..."
# Core Assembly Modules (migrated to src/asm/)
nasm -f elf32 src/asm/context_switch.asm -o target/context_switch.o
nasm -f elf32 src/asm/memory.asm -o target/memory.o
nasm -f elf32 src/asm/interrupt.asm -o target/interrupt.o
nasm -f elf32 src/asm/network.asm -o target/network.o
nasm -f elf32 src/asm/crypto.asm -o target/crypto.o
nasm -f elf32 src/asm/cpu_features.asm -o target/cpu_features.o
nasm -f elf32 src/asm/atomic.asm -o target/atomic.o
nasm -f elf32 src/asm/perf.asm -o target/perf.o

# Additional Kernel Assembly
nasm -f elf32 src/asm/cow.asm -o target/cow.o
nasm -f elf32 src/asm/process.asm -o target/process.o
nasm -f elf32 src/asm/idt.asm -o target/idt.o
nasm -f elf32 src/asm/dma.asm -o target/dma.o
nasm -f elf32 src/asm/acpi.asm -o target/acpi.o
nasm -f elf32 src/asm/memopt.asm -o target/memopt.o
nasm -f elf32 src/asm/gdt.asm -o target/gdt.o
nasm -f elf32 src/asm/sysenter.asm -o target/sysenter.o
nasm -f elf32 src/asm/syscall_entry.asm -o target/syscall_entry.o

echo "  ✓ context_switch.o, memory.o, interrupt.o, network.o, crypto.o"
echo "  ✓ cpu_features.o, atomic.o, perf.o, cow.o, process.o, idt.o"
echo "  ✓ dma.o, acpi.o, memopt.o, gdt.o, sysenter.o, syscall_entry.o"

echo "[2/6] Building Rust kernel (staticlib, i686)..."
cargo ${TOOLCHAIN} build --release --lib --target "${RUST_TARGET}" \
  -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem

if [[ ! -f "${RUST_LIB}" ]]; then
  echo "ERROR: expected staticlib at ${RUST_LIB}"
  exit 1
fi

echo "[3/6] Assembling boot stub (boot.asm)..."
# Now located in src/asm/boot.asm
nasm -f elf32 src/asm/boot.asm -o target/boot.o

echo "[4/6] Linking kernel (boot.o + asm/*.o + liboreulia_kernel.a)..."
x86_64-elf-ld \
  -m elf_i386 \
  -T kernel.ld \
  -nostdlib \
  -o target/oreulia-kernel \
  target/boot.o \
  target/context_switch.o \
  target/memory.o \
  target/interrupt.o \
  target/network.o \
  target/crypto.o \
  target/cpu_features.o \
  target/atomic.o \
  target/perf.o \
  target/cow.o \
  target/process.o \
  target/idt.o \
  target/dma.o \
  target/acpi.o \
  target/memopt.o \
  target/gdt.o \
  target/sysenter.o \
  target/syscall_entry.o \
  --whole-archive "${RUST_LIB}" --no-whole-archive

echo "[5/6] Creating ISO..."
mkdir -p iso/boot/grub
cp target/oreulia-kernel iso/boot/
i686-elf-grub-mkrescue -o oreulia.iso iso/ 2>&1 | grep -i "success" || true

echo ""
echo "=== Verification ==="
if i686-elf-grub-file --is-x86-multiboot target/oreulia-kernel; then
    echo "Boot: qemu-system-i386 -cdrom oreulia.iso"
else
    echo "✗ Kernel NOT multiboot compliant"
    exit 1
fi
