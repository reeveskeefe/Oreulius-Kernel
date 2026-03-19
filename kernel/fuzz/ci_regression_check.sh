#!/usr/bin/env bash
set -euo pipefail

iters="${1:-1000}"
soak_rounds="${2:-3}"

if [[ "${iters}" -lt 1 || "${iters}" -gt 10000 ]]; then
    echo "iters must be in 1..10000"
    exit 1
fi
if [[ "${soak_rounds}" -lt 1 || "${soak_rounds}" -gt 50 ]]; then
    echo "soak_rounds must be in 1..50"
    exit 1
fi

# Write logs to a stable directory so GitHub Actions artifact uploads work.
log_dir="${CI_LOG_DIR:-}"
if [[ -z "${log_dir}" ]]; then
    if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
        log_dir="${GITHUB_WORKSPACE}/kernel/ci/logs"
    else
        log_dir="$(pwd)/ci/logs"
    fi
fi
mkdir -p "${log_dir}"
log_file="${log_dir}/wasm_jit_corpus.log"

export LOG_DIR="${log_dir}"
export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--display none -nographic -no-reboot -no-shutdown}"

echo "Running external corpus replay (iters=${iters}, soak_rounds=${soak_rounds})..."
set +e
./fuzz/run_wasm_jit_corpus.expect "${iters}" "${soak_rounds}" > "${log_file}" 2>&1
runner_status=$?
set -e
cat "${log_file}"

if (( runner_status != 0 )); then
    echo "ERROR: WASM expect runner failed with exit status ${runner_status}"
    exit "${runner_status}"
fi

seeds_line="$(grep -E '^Seeds passed:' "${log_file}" | tail -1 || true)"
mismatch_line="$(grep -E '^Total mismatches:' "${log_file}" | tail -1 || true)"
compile_line="$(grep -E '^Total compile errors:' "${log_file}" | tail -1 || true)"

if [[ -z "${seeds_line}" || -z "${mismatch_line}" || -z "${compile_line}" ]]; then
    echo "ERROR: Could not parse corpus summary from output"
    exit 1
fi

seeds_passed="$(echo "${seeds_line}" | awk '{print $3}')"
seeds_total="$(echo "${seeds_line}" | awk '{print $5}')"
total_mismatches="$(echo "${mismatch_line}" | awk '{print $3}')"
total_compile_errors="$(echo "${compile_line}" | awk '{print $4}')"

seeds_passed="${seeds_passed//$'\r'/}"
seeds_total="${seeds_total//$'\r'/}"
total_mismatches="${total_mismatches//$'\r'/}"
total_compile_errors="${total_compile_errors//$'\r'/}"

if (( seeds_passed != seeds_total )); then
    echo "ERROR: corpus replay failed (${seeds_passed}/${seeds_total} seeds passed)"
    exit 1
fi
if (( total_mismatches != 0 )); then
    echo "ERROR: corpus replay reported mismatches (${total_mismatches})"
    exit 1
fi
if (( total_compile_errors != 0 )); then
    echo "ERROR: corpus replay reported compile errors (${total_compile_errors})"
    exit 1
fi

rounds_line="$(awk '
    /^===== WASM JIT Corpus Soak =====/ {in_soak=1; next}
    in_soak && /^Rounds passed:/ {line=$0}
    END {print line}
' "${log_file}")"
soak_mismatch_line="$(awk '
    /^===== WASM JIT Corpus Soak =====/ {in_soak=1; next}
    in_soak && /^Total mismatches:/ {line=$0}
    END {print line}
' "${log_file}")"
soak_compile_line="$(awk '
    /^===== WASM JIT Corpus Soak =====/ {in_soak=1; next}
    in_soak && /^Total compile errors:/ {line=$0}
    END {print line}
' "${log_file}")"

if [[ -z "${rounds_line}" || -z "${soak_mismatch_line}" || -z "${soak_compile_line}" ]]; then
    echo "ERROR: Could not parse soak summary from output"
    exit 1
fi

rounds_passed="$(echo "${rounds_line}" | awk '{print $3}')"
rounds_total="$(echo "${rounds_line}" | awk '{print $5}')"
soak_mismatches="$(echo "${soak_mismatch_line}" | awk '{print $3}')"
soak_compile_errors="$(echo "${soak_compile_line}" | awk '{print $4}')"

rounds_passed="${rounds_passed//$'\r'/}"
rounds_total="${rounds_total//$'\r'/}"
soak_mismatches="${soak_mismatches//$'\r'/}"
soak_compile_errors="${soak_compile_errors//$'\r'/}"

if (( rounds_passed != rounds_total )); then
    echo "ERROR: soak replay failed (${rounds_passed}/${rounds_total} rounds passed)"
    exit 1
fi
if (( soak_mismatches != 0 )); then
    echo "ERROR: soak replay reported mismatches (${soak_mismatches})"
    exit 1
fi
if (( soak_compile_errors != 0 )); then
    echo "ERROR: soak replay reported compile errors (${soak_compile_errors})"
    exit 1
fi

echo "Corpus replay + soak checks passed."
