#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

./build-x86_64-full.sh

OUT_DIR="target/x86_64-mb2"
ISO_ROOT="${OUT_DIR}/iso"
ISO_FILE="${OUT_DIR}/oreulius-x86_64-mb2.iso"
KERNEL_ELF="${OUT_DIR}/oreulius-kernel-x86_64"

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

GRUB_MKRESCUE_BIN="${GRUB_MKRESCUE_BIN:-}"
if [[ -z "${GRUB_MKRESCUE_BIN}" ]]; then
  GRUB_MKRESCUE_BIN="$(resolve_tool i686-elf-grub-mkrescue grub-mkrescue || true)"
fi
if [[ -z "${GRUB_MKRESCUE_BIN}" ]]; then
  echo "ERROR: grub-mkrescue tool not found (tried: i686-elf-grub-mkrescue, grub-mkrescue)"
  exit 1
fi

mkdir -p "${ISO_ROOT}/boot/grub"
cp "${KERNEL_ELF}" "${ISO_ROOT}/boot/oreulius-kernel-x86_64"

cat > "${ISO_ROOT}/boot/grub/grub.cfg" <<'EOF'
set timeout=0
set default=0
terminal_output console

menuentry "Oreulius x86_64 MB2" {
    multiboot2 /boot/oreulius-kernel-x86_64
    boot
}
EOF

"${GRUB_MKRESCUE_BIN}" -o "${ISO_FILE}" "${ISO_ROOT}" >/dev/null 2>&1 || {
  echo "ERROR: failed to create x86_64 MB2 GRUB ISO (${ISO_FILE})"
  exit 1
}

echo "Built: ${ISO_FILE}"

