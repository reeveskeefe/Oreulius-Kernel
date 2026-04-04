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
OREULIUS_CONSOLE="${OREULIUS_CONSOLE:-vga}"
SERIAL_LOG_PATH="${OREULIUS_SERIAL_LOG:-/tmp/oreulius-serial.log}"
USE_DEFAULT_SERIAL=1
USE_MONITOR_NONE=0
USE_GRAPHICAL_DISPLAY=1
if [[ "$QEMU_EXTRA_ARGS" =~ (^|[[:space:]])-serial($|[[:space:]]) ]]; then
    USE_DEFAULT_SERIAL=0
fi
if [[ "$QEMU_EXTRA_ARGS" =~ (^|[[:space:]])-nographic($|[[:space:]]) ]]; then
    USE_MONITOR_NONE=1
    USE_GRAPHICAL_DISPLAY=0
fi
if [[ "$QEMU_EXTRA_ARGS" =~ (^|[[:space:]])-display[[:space:]]+none($|[[:space:]]) ]]; then
    USE_GRAPHICAL_DISPLAY=0
fi

if [[ "${OREULIUS_CONSOLE}" != "serial" && "${OREULIUS_CONSOLE}" != "vga" ]]; then
    echo "Unsupported OREULIUS_CONSOLE='${OREULIUS_CONSOLE}'. Use 'vga' or 'serial'."
    exit 1
fi

if [ -n "$QEMU_EXTRA_ARGS" ]; then
    if [ "$USE_DEFAULT_SERIAL" -eq 1 ]; then
        if [ "$USE_GRAPHICAL_DISPLAY" -eq 1 ] && [ "${OREULIUS_CONSOLE}" = "vga" ]; then
            rm -f "${SERIAL_LOG_PATH}"
            echo "Interactive VGA mode enabled."
            echo "Type in the QEMU window; serial log is mirrored to ${SERIAL_LOG_PATH}"
            # shellcheck disable=SC2086
            qemu-system-i386 \
                -cdrom "$ISO_PATH" \
                -serial file:"${SERIAL_LOG_PATH}" \
                -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
                -serial chardev:telemetry_socket \
                $QEMU_EXTRA_ARGS
            exit $?
        fi
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
    if [ "${OREULIUS_CONSOLE}" = "vga" ]; then
        rm -f "${SERIAL_LOG_PATH}"
        echo "Interactive VGA mode enabled."
        echo "Type in the QEMU window; serial log is mirrored to ${SERIAL_LOG_PATH}"
        qemu-system-i386 \
            -cdrom "$ISO_PATH" \
            -serial file:"${SERIAL_LOG_PATH}" \
            -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
            -serial chardev:telemetry_socket
    else
        qemu-system-i386 \
            -cdrom "$ISO_PATH" \
            -serial stdio \
            -chardev socket,path=/tmp/oreulius_ebpf_telemetry,server=on,wait=off,id=telemetry_socket \
            -serial chardev:telemetry_socket
    fi
fi
