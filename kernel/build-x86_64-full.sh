#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building Oreulia kernel (x86_64 Multiboot2 path) ==="

TOOLCHAIN="${TOOLCHAIN:-+nightly-2023-11-01}"
RUST_TARGET="x86_64-unknown-none"
RUST_LIB="target/${RUST_TARGET}/release/liboreulia_kernel.a"
OUT_DIR="target/x86_64-mb2"
BOOT_OBJ="${OUT_DIR}/boot_x86_64_mb2.o"
SHIM_OBJ="${OUT_DIR}/x86_64_shims.o"
OUT_ELF="${OUT_DIR}/oreulia-kernel-x86_64"

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

mkdir -p "${OUT_DIR}"

echo "[1/3] Assembling x86_64 boot support objects..."
nasm -f elf64 src/asm/boot_x86_64_mb2.asm -o "${BOOT_OBJ}"
nasm -f elf64 src/asm/x86_64_shims.asm -o "${SHIM_OBJ}"

echo "[2/3] Building Rust kernel staticlib for x86_64..."
CARGO_FEATURES="${KERNEL_CARGO_FEATURES:-${CARGO_FEATURES:-}}"
if [[ -n "${CARGO_FEATURES}" ]]; then
  echo "[2/3] Enabling Cargo features: ${CARGO_FEATURES}"
fi
CARGO_BUILD_CMD=(
  cargo ${TOOLCHAIN} build --release --lib --target "${RUST_TARGET}"
  -Z build-std=core,compiler_builtins,alloc
  -Z build-std-features=compiler-builtins-mem
)
if [[ -n "${CARGO_FEATURES}" ]]; then
  CARGO_BUILD_CMD+=(--features "${CARGO_FEATURES}")
fi
if ! CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS="-C relocation-model=static -C code-model=kernel" \
  "${CARGO_BUILD_CMD[@]}"; then
  cat <<'EOF'
Rust x86_64 build failed.

This script is the full-link path for the new x86_64 MB2 boot flow and is
expected to fail until the kernel Rust modules and asm bindings are clean for:
  - target_arch = "x86_64"
  - x86_64-compatible inline/global assembly and extern symbols
EOF
  exit 1
fi

if [[ ! -f "${RUST_LIB}" ]]; then
  echo "ERROR: expected staticlib at ${RUST_LIB}"
  exit 1
fi

echo "[3/3] Linking x86_64 kernel ELF..."
"${LD_BIN}" \
  -m elf_x86_64 \
  -T linker-x86_64-mb2.ld \
  -nostdlib \
  -z max-page-size=0x1000 \
  -o "${OUT_ELF}" \
  "${BOOT_OBJ}" \
  "${SHIM_OBJ}" \
  --whole-archive "${RUST_LIB}" --no-whole-archive

echo "Built: ${OUT_ELF}"
echo "Note: ISO is not rebuilt by this script."
echo "Run ./build-x86_64-mb2-iso.sh before ./run-x86_64-mb2-grub.sh."

GRUB_FILE_BIN="${GRUB_FILE_BIN:-}"
if [[ -z "${GRUB_FILE_BIN}" ]]; then
  GRUB_FILE_BIN="$(resolve_tool i686-elf-grub-file grub-file || true)"
fi
if [[ -n "${GRUB_FILE_BIN}" ]]; then
  if "${GRUB_FILE_BIN}" --is-x86-multiboot2 "${OUT_ELF}"; then
    echo "Multiboot2 header: OK"
  else
    echo "WARNING: ${OUT_ELF} failed grub-file multiboot2 check"
  fi
fi
