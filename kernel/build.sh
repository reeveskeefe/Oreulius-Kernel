#!/bin/bash
set -euo pipefail

echo "=== Building Oreulia OS ==="

TOOLCHAIN="+nightly-2023-11-01"
RUST_TARGET="./i686-oreulia.json"
RUST_LIB="target/i686-oreulia/release/liboreulia_kernel.a"

resolve_tool() {
  local resolved=""
  for candidate in "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      resolved="$candidate"
      break
    fi
  done
  if [[ -z "$resolved" ]]; then
    return 1
  fi
  printf "%s" "$resolved"
}

LD_BIN="${LD_BIN:-}"
if [[ -z "${LD_BIN}" ]]; then
  LD_BIN="$(resolve_tool x86_64-elf-ld ld.lld ld || true)"
fi
if [[ -z "${LD_BIN}" ]]; then
  echo "ERROR: linker not found (tried: x86_64-elf-ld, ld.lld, ld)"
  exit 1
fi

GRUB_MKRESCUE_BIN="${GRUB_MKRESCUE_BIN:-}"
if [[ -z "${GRUB_MKRESCUE_BIN}" ]]; then
  GRUB_MKRESCUE_BIN="$(resolve_tool i686-elf-grub-mkrescue grub-mkrescue || true)"
fi
if [[ -z "${GRUB_MKRESCUE_BIN}" ]]; then
  echo "ERROR: grub-mkrescue tool not found (tried: i686-elf-grub-mkrescue, grub-mkrescue)"
  exit 1
fi

GRUB_FILE_BIN="${GRUB_FILE_BIN:-}"
if [[ -z "${GRUB_FILE_BIN}" ]]; then
  GRUB_FILE_BIN="$(resolve_tool i686-elf-grub-file grub-file || true)"
fi
if [[ -z "${GRUB_FILE_BIN}" ]]; then
  echo "ERROR: grub-file tool not found (tried: i686-elf-grub-file, grub-file)"
  exit 1
fi

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
nasm -f elf32 src/asm/sgx.asm -o target/sgx.o

echo "  ✓ context_switch.o, memory.o, interrupt.o, network.o, crypto.o"
echo "  ✓ cpu_features.o, atomic.o, perf.o, cow.o, process.o, idt.o"
echo "  ✓ dma.o, acpi.o, memopt.o, gdt.o, sysenter.o, syscall_entry.o, sgx.o"

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
"${LD_BIN}" \
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
  target/sgx.o \
  --whole-archive "${RUST_LIB}" --no-whole-archive

echo "[5/6] Creating ISO..."
mkdir -p iso/boot/grub
cp target/oreulia-kernel iso/boot/
"${GRUB_MKRESCUE_BIN}" -o oreulia.iso iso/ 2>&1 | grep -i "success" || true

echo ""
echo "=== Verification ==="
if "${GRUB_FILE_BIN}" --is-x86-multiboot target/oreulia-kernel; then
    echo "Boot: qemu-system-i386 -cdrom oreulia.iso"
else
    echo "✗ Kernel NOT multiboot compliant"
    exit 1
fi
