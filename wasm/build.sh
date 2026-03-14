#!/usr/bin/env bash
# wasm/build.sh — Compile all .wat source files to .wasm binaries
#
# Requirements:
#   wat2wasm  (part of the WABT toolchain: https://github.com/WebAssembly/wabt)
#
# Usage:
#   ./wasm/build.sh              # compile everything
#   ./wasm/build.sh hello.wat    # compile a specific file
#
# Output: <name>.wasm next to each <name>.wat source file.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify wat2wasm is available.
if ! command -v wat2wasm &>/dev/null; then
    echo "Error: 'wat2wasm' not found."
    echo ""
    echo "Install WABT on macOS:   brew install wabt"
    echo "Install WABT on Debian:  apt install wabt"
    echo "Or download from:        https://github.com/WebAssembly/wabt/releases"
    exit 1
fi

WAT2WASM_VERSION=$(wat2wasm --version 2>&1 || true)
echo "wat2wasm: ${WAT2WASM_VERSION}"
echo ""

# Collect targets: either from command-line args or discover all .wat files.
if [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    mapfile -t TARGETS < <(find "${SCRIPT_DIR}" -maxdepth 1 -name "*.wat" | sort)
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "No .wat files found in ${SCRIPT_DIR}"
    exit 0
fi

PASS=0
FAIL=0

for wat in "${TARGETS[@]}"; do
    # Resolve absolute path relative to script dir when a bare name is given.
    if [[ "${wat}" != /* ]]; then
        wat="${SCRIPT_DIR}/${wat}"
    fi

    if [[ ! -f "${wat}" ]]; then
        echo "SKIP  ${wat}  (not found)"
        continue
    fi

    wasm="${wat%.wat}.wasm"
    basename_wat="$(basename "${wat}")"

    if wat2wasm "${wat}" -o "${wasm}" 2>&1; then
        size=$(wc -c < "${wasm}" | tr -d ' ')
        echo "OK    ${basename_wat}  ->  $(basename "${wasm}")  (${size} bytes)"
        PASS=$((PASS + 1))
    else
        echo "FAIL  ${basename_wat}"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "Results: ${PASS} compiled, ${FAIL} failed"

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
