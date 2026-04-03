#!/bin/bash
# Run Oreulius kernel in QEMU

set -euo pipefail

# Check for QEMU i386
if ! command -v qemu-system-i386 >/dev/null 2>&1; then
    echo "qemu-system-i386 not found. Install QEMU first."
    echo "  macOS: brew install qemu"
    echo "  Linux: sudo apt-get install qemu-system-x86"
    exit 1
fi

ISO_PATH="oreulius.iso"

# Check if ISO exists
if [ ! -f "$ISO_PATH" ]; then
    echo "ISO not found at $ISO_PATH"
    echo "Run ./build.sh first to create the ISO"
    exit 1
fi

echo "Starting Oreulius OS in QEMU..."
echo "Press Ctrl+C to exit"
echo ""

QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:-}"
USE_DEFAULT_SERIAL=1
USE_MONITOR_NONE=0
if [[ "$QEMU_EXTRA_ARGS" =~ (^|[[:space:]])-serial($|[[:space:]]) ]]; then
    USE_DEFAULT_SERIAL=0
fi
if [[ "$QEMU_EXTRA_ARGS" =~ (^|[[:space:]])-nographic($|[[:space:]]) ]]; then
    USE_MONITOR_NONE=1
fi

if [ -n "$QEMU_EXTRA_ARGS" ]; then
    if [ "$USE_DEFAULT_SERIAL" -eq 1 ]; then
        # shellcheck disable=SC2086
        qemu-system-i386 \
            -cdrom "$ISO_PATH" \
            -serial stdio \
            $(if [ "$USE_MONITOR_NONE" -eq 1 ]; then printf '%s' "-monitor none"; fi) \
            -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
            -serial chardev:telemetry_socket \
            $QEMU_EXTRA_ARGS
    else
        # shellcheck disable=SC2086
        qemu-system-i386 \
            -cdrom "$ISO_PATH" \
            -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
            -serial chardev:telemetry_socket \
            $QEMU_EXTRA_ARGS
    fi
else
    qemu-system-i386 \
        -cdrom "$ISO_PATH" \
        -serial stdio \
        -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
        -serial chardev:telemetry_socket
fi
