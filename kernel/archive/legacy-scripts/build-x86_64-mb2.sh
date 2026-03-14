#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Assembling x86_64 Multiboot2 boot path (stub only) ==="
mkdir -p target/x86_64-mb2

nasm -f elf64 src/asm/boot_x86_64_mb2.asm -o target/x86_64-mb2/boot_x86_64_mb2.o
echo "Built: target/x86_64-mb2/boot_x86_64_mb2.o"

cat <<'EOF'
This validates the separate x86_64 boot stub syntax/path only.

Next integration step (not completed here):
- make the Rust kernel compile for x86_64
- link liboreulia_kernel.a with:
    linker-x86_64-mb2.ld
    src/asm/boot_x86_64_mb2.asm
EOF
