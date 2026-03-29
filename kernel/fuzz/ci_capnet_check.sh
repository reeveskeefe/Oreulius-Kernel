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

fixed_seed=3870443198
fixed_seed_log="${log_dir}/capnet_fixed_seed_${fixed_seed}.log"
formal_log="${log_dir}/capnet_formal.log"
max_attempts=3

regression_seeds=()
while IFS= read -r seed; do
    regression_seeds+=("${seed}")
done < <(
    awk '
        /CAPNET_FUZZ_REGRESSION_SEEDS:/ {capture=1; next}
        capture {
            if ($0 ~ /\];/) {
                capture = 0
            }
            gsub(/[_ ,]/, "", $0)
            if ($0 ~ /^[0-9]+$/) {
                print $0
            }
        }
    ' ./src/net/capnet.rs
)

if (( ${#regression_seeds[@]} == 0 )); then
    echo "ERROR: Could not parse CAPNET_FUZZ_REGRESSION_SEEDS from src/net/capnet.rs"
    exit 1
fi

echo "Running CapNet fixed-seed precheck (seed=${fixed_seed}, iters=${iters})..."
fixed_seed_status=1
attempt=1
while (( attempt <= max_attempts )); do
    echo "Fixed-seed attempt ${attempt}/${max_attempts}"
    set +e
    ./fuzz/run_capnet_single_seed.expect "${iters}" "${fixed_seed}" > "${fixed_seed_log}" 2>&1
    fixed_seed_status=$?
    set -e
    cat "${fixed_seed_log}"
    if (( fixed_seed_status == 0 )); then
        break
    fi
    attempt=$((attempt + 1))
done

if (( fixed_seed_status != 0 )); then
    echo "ERROR: CapNet fixed-seed precheck failed for seed ${fixed_seed}"
    exit "${fixed_seed_status}"
fi

round=1
while (( round <= soak_rounds )); do
    if (( round == 1 )); then
        echo "Running CapNet corpus replay (iters=${iters})..."
        round_log="${log_file}"
    else
        echo "Running CapNet soak replay round ${round}/${soak_rounds} (fresh boot)..."
        round_log="${log_dir}/capnet_corpus_round_${round}.log"
    fi

    : > "${round_log}"
    total_seeds="${#regression_seeds[@]}"
    idx=1
    for seed in "${regression_seeds[@]}"; do
        seed_log="${log_dir}/capnet_seed_${seed}_round_${round}.log"
        echo "Replaying seed ${idx}/${total_seeds}: ${seed}"
        {
            echo "===== CapNet seed ${idx}/${total_seeds}: ${seed} (round ${round}/${soak_rounds}) ====="
            echo
        } >> "${round_log}"

        runner_status=1
        attempt=1
        while (( attempt <= max_attempts )); do
            echo "Seed ${seed} attempt ${attempt}/${max_attempts}"
            {
                echo "----- attempt ${attempt}/${max_attempts} -----"
            } >> "${round_log}"

            set +e
            ./fuzz/run_capnet_single_seed.expect "${iters}" "${seed}" > "${seed_log}" 2>&1
            runner_status=$?
            set -e

            cat "${seed_log}"
            cat "${seed_log}" >> "${round_log}"
            echo >> "${round_log}"

            if (( runner_status == 0 )); then
                break
            fi
            attempt=$((attempt + 1))
        done

        if (( runner_status != 0 )); then
            echo "ERROR: CapNet seed replay failed for seed ${seed} in round ${round}"
            exit "${runner_status}"
        fi

        idx=$((idx + 1))
    done

    round=$((round + 1))
done

echo "Running CapNet formal verification..."
formal_status=1
attempt=1
while (( attempt <= max_attempts )); do
    echo "Formal verification attempt ${attempt}/${max_attempts}"
    set +e
    ./fuzz/run_capnet_corpus.expect 0 0 > "${formal_log}" 2>&1
    formal_status=$?
    set -e
    cat "${formal_log}"
    if (( formal_status == 0 )); then
        break
    fi
    attempt=$((attempt + 1))
done

if (( formal_status != 0 )); then
    echo "ERROR: CapNet formal verification failed"
    exit "${formal_status}"
fi

echo "CapNet corpus replay + soak + formal checks passed."
