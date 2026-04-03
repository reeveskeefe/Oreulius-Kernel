#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building Oreulius kernel (AArch64 QEMU virt bring-up) ==="

TOOLCHAIN="${TOOLCHAIN:-+nightly-2024-01-01}"
RUST_TARGET="${RUST_TARGET:-aarch64-unknown-none}"
RUST_LIB="target/${RUST_TARGET}/release/liboreulius_kernel.a"
OUT_DIR="target/aarch64-virt"
BOOT_OBJ="${OUT_DIR}/boot_aarch64_virt.o"
VECTORS_OBJ="${OUT_DIR}/aarch64_vectors.o"
SCHED_OBJ="${OUT_DIR}/aarch64_scheduler.o"
OUT_ELF="${OUT_DIR}/oreulius-kernel-aarch64-virt"
OUT_IMAGE="${OUT_DIR}/Image"

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

AS_BIN="${AS_BIN:-}"
if [[ -z "${AS_BIN}" ]]; then
  AS_BIN="$(resolve_tool aarch64-elf-as llvm-as || true)"
fi
if [[ -z "${AS_BIN}" ]]; then
  echo "ERROR: assembler not found (tried: aarch64-elf-as, llvm-as)"
  exit 1
fi

LD_BIN="${LD_BIN:-}"
if [[ -z "${LD_BIN}" ]]; then
  LD_BIN="$(resolve_tool aarch64-elf-ld ld.lld ld || true)"
fi
if [[ -z "${LD_BIN}" ]]; then
  echo "ERROR: linker not found (tried: aarch64-elf-ld, ld.lld, ld)"
  exit 1
fi

OBJCOPY_BIN="${OBJCOPY_BIN:-}"
if [[ -z "${OBJCOPY_BIN}" ]]; then
  OBJCOPY_BIN="$(resolve_tool aarch64-elf-objcopy llvm-objcopy gobjcopy || true)"
fi
if [[ -z "${OBJCOPY_BIN}" ]]; then
  echo "ERROR: objcopy not found (tried: aarch64-elf-objcopy, llvm-objcopy, gobjcopy)"
  exit 1
fi

mkdir -p "${OUT_DIR}"

echo "[1/4] Assembling AArch64 virt support objects..."
"${AS_BIN}" "src/asm/boot_aarch64_virt.S" -o "${BOOT_OBJ}"
"${AS_BIN}" "src/asm/aarch64_vectors.S" -o "${VECTORS_OBJ}"
"${AS_BIN}" "src/asm/aarch64_scheduler.S" -o "${SCHED_OBJ}"

echo "[2/4] Building Rust kernel staticlib for AArch64..."
CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS:--C relocation-model=static}" \
  cargo ${TOOLCHAIN} build --release --lib --target "${RUST_TARGET}" \
    -Z build-std=core,compiler_builtins,alloc \
    -Z build-std-features=compiler-builtins-mem

if [[ ! -f "${RUST_LIB}" ]]; then
  echo "ERROR: expected staticlib at ${RUST_LIB}"
  exit 1
fi

echo "[3/4] Linking AArch64 kernel ELF..."
"${LD_BIN}" \
  -T linker-aarch64-virt.ld \
  -nostdlib \
  -o "${OUT_ELF}" \
  "${BOOT_OBJ}" \
  "${VECTORS_OBJ}" \
  "${SCHED_OBJ}" \
  "${RUST_LIB}"

echo "Built: ${OUT_ELF}"

echo "[4/4] Generating raw AArch64 Image..."
"${OBJCOPY_BIN}" -O binary "${OUT_ELF}" "${OUT_IMAGE}"
echo "Built: ${OUT_IMAGE}"
