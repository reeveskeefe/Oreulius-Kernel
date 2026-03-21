#!/usr/bin/env bash
set -euo pipefail

iters="${1:-1000}"
soak_rounds="${2:-2}"

if [[ "${iters}" -lt 1 || "${iters}" -gt 10000 ]]; then
    echo "iters must be in 1..10000"
    exit 1
fi
if [[ "${soak_rounds}" -lt 1 || "${soak_rounds}" -gt 50 ]]; then
    echo "soak_rounds must be in 1..50"
    exit 1
fi

# Write logs to a stable directory so GitHub Actions artifact uploads work.
# Fall back to a temp file when running outside CI.
log_dir="${CI_LOG_DIR:-}"
if [[ -z "${log_dir}" ]]; then
    if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
        log_dir="${GITHUB_WORKSPACE}/kernel/ci/logs"
    else
        log_dir="$(pwd)/ci/logs"
    fi
fi
mkdir -p "${log_dir}"
log_file="${log_dir}/capnet_corpus.log"

export LOG_DIR="${log_dir}"
export QEMU_EXTRA_ARGS="${QEMU_EXTRA_ARGS:--display none -nographic -no-reboot -no-shutdown}"

echo "Running CapNet corpus replay (iters=${iters}, soak_rounds=${soak_rounds})..."
set +e
./fuzz/run_capnet_corpus.expect "${iters}" "${soak_rounds}" > "${log_file}" 2>&1
runner_status=$?
set -e
cat "${log_file}"

if (( runner_status != 0 )); then
    echo "ERROR: CapNet expect runner failed with exit status ${runner_status}"
    exit "${runner_status}"
fi

seeds_line="$(grep -E '^Seeds passed:' "${log_file}" | tail -1 || true)"
failures_line="$(grep -E '^Total failures:' "${log_file}" | head -1 || true)"
formal_line="$(grep -E '^Formal verification checks: PASSED' "${log_file}" | tail -1 || true)"

if [[ -z "${seeds_line}" || -z "${failures_line}" ]]; then
    echo "ERROR: Could not parse CapNet corpus summary from output"
    exit 1
fi

seeds_passed="$(echo "${seeds_line}" | awk '{print $3}')"
seeds_total="$(echo "${seeds_line}" | awk '{print $5}')"
total_failures="$(echo "${failures_line}" | awk '{print $3}')"

seeds_passed="${seeds_passed//$'\r'/}"
seeds_total="${seeds_total//$'\r'/}"
total_failures="${total_failures//$'\r'/}"

if (( seeds_passed != seeds_total )); then
    echo "ERROR: CapNet corpus replay failed (${seeds_passed}/${seeds_total} seeds passed)"

    # ── diagnostic re-run: extract failing seed and replay with extra logging ──
    failing_seed="$(grep -E '^First failing seed:' "${log_file}" | awk '{print $NF}' | tr -d '\r' || true)"
    if [[ -n "${failing_seed}" && -x ./fuzz/run_capnet_single_seed.expect ]]; then
        diag_log="${log_dir}/capnet_diag_seed_${failing_seed}.log"
        echo "Re-running failing seed ${failing_seed} for diagnostics..."
        set +e
        ./fuzz/run_capnet_single_seed.expect "${iters}" "${failing_seed}" > "${diag_log}" 2>&1
        diag_status=$?
        set -e
        echo "---- diagnostic log (seed ${failing_seed}) ----"
        cat "${diag_log}"
        echo "---- end diagnostic log ----"
    fi

    exit 1
fi
if (( total_failures != 0 )); then
    echo "ERROR: CapNet corpus replay reported failures (${total_failures})"
    exit 1
fi

rounds_line="$(awk '
    /^===== CapNet Corpus Soak =====/ {in_soak=1; next}
    in_soak && /^Rounds passed:/ {line=$0}
    END {print line}
' "${log_file}")"
soak_failures_line="$(awk '
    /^===== CapNet Corpus Soak =====/ {in_soak=1; next}
    in_soak && /^Total failures:/ {line=$0}
    END {print line}
' "${log_file}")"

if [[ -z "${rounds_line}" || -z "${soak_failures_line}" ]]; then
    echo "ERROR: Could not parse CapNet soak summary from output"
    exit 1
fi

rounds_passed="$(echo "${rounds_line}" | awk '{print $3}')"
rounds_total="$(echo "${rounds_line}" | awk '{print $5}')"
soak_failures="$(echo "${soak_failures_line}" | awk '{print $3}')"

rounds_passed="${rounds_passed//$'\r'/}"
rounds_total="${rounds_total//$'\r'/}"
soak_failures="${soak_failures//$'\r'/}"

if (( rounds_passed != rounds_total )); then
    echo "ERROR: CapNet soak replay failed (${rounds_passed}/${rounds_total} rounds passed)"
    exit 1
fi
if (( soak_failures != 0 )); then
    echo "ERROR: CapNet soak replay reported failures (${soak_failures})"
    exit 1
fi

if [[ -z "${formal_line}" ]]; then
    echo "ERROR: Formal verification did not report success"
    exit 1
fi

echo "CapNet corpus replay + soak + formal checks passed."
