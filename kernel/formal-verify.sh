#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./formal-verify.sh [options]

Runs in-kernel formal verification under QEMU and validates PASS markers.

Options:
  --build           Build kernel/ISO before running
  --formal-only     Run only `formal-verify` (skip temporal hardening self-test)
  --log <path>      Write full run log to <path>
  --qemu-extra <s>  Override QEMU_EXTRA_ARGS for this run
  --timeout <sec>   Expect timeout in seconds (default: 900)
  -h, --help        Show this help

Environment:
  QEMU_EXTRA_ARGS   Extra args passed through to run.sh
                    Default (if unset): -display none -no-reboot -no-shutdown
EOF
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd"
        exit 1
    fi
}

build_first=0
run_hardening=1
log_file=""
qemu_extra="${QEMU_EXTRA_ARGS:-}"
expect_timeout=900

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            build_first=1
            shift
            ;;
        --formal-only)
            run_hardening=0
            shift
            ;;
        --log)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --log requires a path argument"
                usage
                exit 1
            fi
            log_file="$2"
            shift 2
            ;;
        --qemu-extra)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --qemu-extra requires an argument"
                usage
                exit 1
            fi
            qemu_extra="$2"
            shift 2
            ;;
        --timeout)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --timeout requires a value in seconds"
                usage
                exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [[ "$2" -lt 1 ]]; then
                echo "ERROR: --timeout must be a positive integer"
                exit 1
            fi
            expect_timeout="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

require_cmd expect
require_cmd qemu-system-i386

if [[ ! -x ./run.sh ]]; then
    echo "ERROR: expected executable run.sh in kernel root"
    exit 1
fi

if [[ "$build_first" -eq 1 ]]; then
    echo "Building kernel before verification..."
    ./build.sh
fi

if [[ ! -f oreulius.iso ]]; then
    echo "ERROR: oreulius.iso not found; run ./build.sh or pass --build"
    exit 1
fi

if [[ -z "$qemu_extra" ]]; then
    qemu_extra="-display none -no-reboot -no-shutdown"
fi

if [[ -z "$log_file" ]]; then
    log_file="$(mktemp -t oreulius-formal-verify.XXXXXX.log)"
fi

echo "Running formal verification..."
echo "  hardening self-test: $([[ "$run_hardening" -eq 1 ]] && echo enabled || echo disabled)"
echo "  QEMU_EXTRA_ARGS: $qemu_extra"
echo "  expect timeout: ${expect_timeout}s"
echo "  log: $log_file"

export QEMU_EXTRA_ARGS="$qemu_extra"
export OREULIA_RUN_HARDENING="$run_hardening"
export OREULIA_EXPECT_TIMEOUT="$expect_timeout"

expect <<'EOF' | tee "$log_file"
set timeout 900
set prompt_re {\r?\n> }

if {[info exists env(OREULIA_EXPECT_TIMEOUT)]} {
    if {[string is integer -strict $env(OREULIA_EXPECT_TIMEOUT)]} {
        set timeout $env(OREULIA_EXPECT_TIMEOUT)
    }
}
set run_hardening 1
if {[info exists env(OREULIA_RUN_HARDENING)]} {
    if {$env(OREULIA_RUN_HARDENING) eq "0"} {
        set run_hardening 0
    }
}

# QEMU_EXTRA_ARGS is inherited from the parent environment.
spawn ./run.sh

expect {
    -re $prompt_re {}
    timeout {
        puts "ERROR: timeout waiting for shell prompt"
        exit 2
    }
    eof {
        puts "ERROR: QEMU terminated before shell prompt"
        exit 2
    }
}

sleep 2
send "formal-verify\r"
expect {
    -re $prompt_re {}
    timeout {
        puts "ERROR: timeout waiting for formal-verify completion"
        exit 3
    }
    eof {
        puts "ERROR: QEMU terminated before formal-verify completion"
        exit 3
    }
}

if {$run_hardening == 1} {
    send "temporal-hardening-selftest\r"
    expect {
        -re $prompt_re {}
        timeout {
            puts "ERROR: timeout waiting for temporal-hardening-selftest completion"
            exit 4
        }
        eof {
            puts "ERROR: QEMU terminated before temporal-hardening-selftest completion"
            exit 4
        }
    }
}

sleep 1
send "\003"
expect eof
EOF

if ! grep -q '^Formal verification checks: PASSED' "$log_file"; then
    echo "ERROR: formal-verify did not report PASS"
    exit 1
fi

if [[ "$run_hardening" -eq 1 ]]; then
    if grep -q '^Temporal .* self-check: FAIL' "$log_file"; then
        echo "ERROR: temporal hardening self-test reported FAIL"
        exit 1
    fi

    required_markers=(
        "Temporal v2->v3 decode compatibility self-check: PASS"
        "Temporal integrity-tag tamper rejection self-check: PASS"
        "Temporal deterministic divergent merge self-check: PASS"
        "Temporal WiFi required-reconnect failure-path self-check: PASS"
        "Temporal enclave active-session re-entry-path self-check: PASS"
    )
    for marker in "${required_markers[@]}"; do
        if ! grep -Fq "$marker" "$log_file"; then
            echo "ERROR: missing hardening PASS marker: $marker"
            exit 1
        fi
    done
fi

echo "Formal verification run PASSED."
echo "Log saved at: $log_file"
