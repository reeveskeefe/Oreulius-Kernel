#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./formal-verification-runbook.sh bootstrap [--force]
  ./formal-verification-runbook.sh check [--strict]
  ./formal-verification-runbook.sh status [--strict]
  ./formal-verification-runbook.sh all [--force] [--strict]

Purpose:
  Implements the execution runbook in ThingsYetToDo/FormalVerification.md.

Commands:
  bootstrap   Create the mandatory verification/ structure and baseline files.
  check       Enforce runbook compliance checks (fails on missing MUST items).
  status      Print checklist status without failing fast.
  all         Run bootstrap, then check.

Options:
  --force     Overwrite existing generated template files during bootstrap.
  --strict    Enforce additional release-gating checks.
  -h, --help  Show this help.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REQUIRED_DIRS=(
    "verification/spec"
    "verification/proof"
    "verification/theories"
    "verification/mapping"
    "verification/artifacts"
    "verification/scripts"
    "verification/ci"
)

REQUIRED_FILES=(
    "verification/README.md"
    "verification/DECISION.md"
    "verification/ENVIRONMENT.md"
    "verification/BOOTSTRAP_NOTES.md"
    "verification/spec/INVARIANTS.md"
    "verification/spec/ASSUMPTIONS.md"
    "verification/spec/THREAT_MODEL.md"
    "verification/proof/THEOREM_INDEX.md"
    "verification/mapping/CODE_MODEL_TRACE.md"
    "verification/artifacts/manifest.schema.json"
    "verification/scripts/proof_check.sh"
    ".github/workflows/proof-check.yml"
)

MANDATORY_INVARIANTS=(
    "INV-CAP-001"
    "INV-MEM-001"
    "INV-WX-001"
    "INV-CFI-001"
    "INV-TMP-001"
    "INV-PER-001"
    "INV-NET-001"
    "INV-PRIV-001"
)

MANDATORY_THEOREMS=(
    "THM-CAP-001"
    "THM-MEM-001"
    "THM-WX-001"
    "THM-CFI-001"
    "THM-TMP-001"
    "THM-PER-001"
    "THM-NET-001"
    "THM-PRIV-001"
)

STRICT_CI_JOB_NAMES=(
    "proof-check"
    "proof-trace-check"
    "runtime-verify-check"
    "fuzz-regression-check"
)

FORCE=0
STRICT=0
CMD=""

log() {
    echo "[formal-runbook] $*"
}

warn() {
    echo "[formal-runbook][WARN] $*" >&2
}

die() {
    echo "[formal-runbook][ERROR] $*" >&2
    exit 1
}

need_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
}

parse_args() {
    [[ $# -ge 1 ]] || {
        usage
        exit 1
    }

    CMD="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                FORCE=1
                ;;
            --strict)
                STRICT=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
        shift
    done
}

write_template_file() {
    local path="$1"
    local mode="${2:-0644}"
    if [[ -f "$path" && "$FORCE" -ne 1 ]]; then
        return 0
    fi
    mkdir -p "$(dirname "$path")"
    cat >"$path"
    chmod "$mode" "$path"
}

bootstrap() {
    log "Creating verification directory tree..."
    mkdir -p "${REQUIRED_DIRS[@]}"

    log "Writing baseline runbook templates..."

    write_template_file "verification/README.md" <<'EOF'
# Oreulia Verification Workspace

This directory operationalizes `ThingsYetToDo/FormalVerification.md`.

- `spec/`: formal specs, invariants, assumptions, threat model
- `proof/`: theorem index + proof artifacts
- `mapping/`: code-to-model correspondence obligations
- `artifacts/`: generated manifests and weekly status
- `scripts/`: verification automation
- `ci/`: CI helper material
EOF

    write_template_file "verification/DECISION.md" <<'EOF'
# Verification Toolchain Decision

Status: Draft

## Proof Assistant
- Choice: Coq (default track)
- Version: TODO

## Runtime / Package Tooling
- OCaml / opam version: TODO
- Pin/lock strategy: TODO

## Rationale
- Why this toolchain: TODO
- Deviations from default (if any): TODO
EOF

    write_template_file "verification/ENVIRONMENT.md" <<'EOF'
# Verification Environment Bootstrap

## Reproducible Setup

```bash
# from repo root
mkdir -p verification/{spec,proof,theories,mapping,artifacts,scripts,ci}
```

## Toolchain Install
- TODO: exact install commands
- TODO: exact version checks

## Verification Entry Points
- `bash verification/scripts/proof_check.sh`
EOF

    write_template_file "verification/BOOTSTRAP_NOTES.md" <<'EOF'
# Bootstrap Notes

Fresh-state required reading completed:
- README.md verification + temporal sections
- docs/oreulia-jit-security-resolution.md
- docs/capnet.md
- docs/oreulia-temporal-adapters-durable-persistence.md
- docs/oreulia-service-pointer-capabilities.md
- kernel/src/commands.rs
- kernel/src/temporal.rs
- kernel/src/capnet.rs
- kernel/src/wasm_jit.rs
- kernel/src/syscall.rs

Subsystem summary:
- TODO
EOF

    write_template_file "verification/spec/INVARIANTS.md" <<'EOF'
# Canonical Invariants

- INV-CAP-001: capability authority cannot increase without authorized derivation.
- INV-MEM-001: no out-of-bounds memory access in modeled transitions.
- INV-WX-001: no reachable RWX page state.
- INV-CFI-001: indirect control transfers target only allowed entry sets.
- INV-TMP-001: temporal rollback and merge preserve object consistency invariants.
- INV-PER-001: persisted temporal decode rejects integrity-inconsistent payloads.
- INV-NET-001: CapNet acceptance requires integrity + freshness + rights attenuation.
- INV-PRIV-001: user/kernel privilege transitions preserve control-return integrity.
EOF

    write_template_file "verification/spec/ASSUMPTIONS.md" <<'EOF'
# Assumption Register

Use named, versioned assumptions only:
- ASM-MODEL-*
- ASM-HW-*
- ASM-TOOL-*

Initial assumptions:
- ASM-MODEL-001: TODO
- ASM-HW-001: TODO
- ASM-TOOL-001: TODO
EOF

    write_template_file "verification/spec/THREAT_MODEL.md" <<'EOF'
# Threat Model

## Adversary Capabilities
- TODO

## Trust Boundaries
- TODO

## Out-of-Scope
- TODO
EOF

    write_template_file "verification/proof/THEOREM_INDEX.md" <<'EOF'
# Theorem Index

Mandatory baseline backlog:
- THM-CAP-001 (INV-CAP-001) Status: Planned
- THM-MEM-001 (INV-MEM-001) Status: Planned
- THM-WX-001 (INV-WX-001) Status: Planned
- THM-CFI-001 (INV-CFI-001) Status: Planned
- THM-TMP-001 (INV-TMP-001) Status: Planned
- THM-PER-001 (INV-PER-001) Status: Planned
- THM-NET-001 (INV-NET-001) Status: Planned
- THM-PRIV-001 (INV-PRIV-001) Status: Planned

Required theorem record template:

Theorem ID: THM-<SUBSYSTEM>-<NNN>
Invariant ID(s): INV-...
Statement: <formal statement in assistant syntax + plain English paraphrase>
Assumptions: <ASSUMPTION IDs only>
Dependencies: <Theorem IDs only>
Implementation Surface: <file paths>
Proof Artifact: <path>
CI Evidence: <job URL/hash>
Status: <Planned|InProgress|Proven|Invalidated|Blocked>
Owner: <maintainer>
Last Verified Commit: <sha>
EOF

    write_template_file "verification/mapping/CODE_MODEL_TRACE.md" <<'EOF'
# Code <-> Model Traceability

Correspondence obligations:

- CO-SYNTAX-001: TODO
- CO-SEM-001: TODO
- CO-BOUNDARY-001: TODO

Per-subsystem mapping:
- Capability: kernel/src/capability.rs -> spec/capability.*
- Temporal: kernel/src/temporal.rs -> spec/temporal.*
- CapNet: kernel/src/capnet.rs -> spec/capnet.*
- JIT: kernel/src/wasm_jit.rs -> spec/jit.*
- Privilege transitions: kernel/src/asm/*.asm, kernel/src/syscall.rs -> spec/priv.*
EOF

    write_template_file "verification/artifacts/manifest.schema.json" <<'EOF'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Oreulia Verification Manifest",
  "type": "object",
  "required": [
    "commit_sha",
    "generated_at",
    "theorems",
    "assumptions_version",
    "ci_runs",
    "runtime_evidence"
  ],
  "properties": {
    "commit_sha": { "type": "string" },
    "generated_at": { "type": "string" },
    "theorems": { "type": "array" },
    "assumptions_version": { "type": "string" },
    "ci_runs": { "type": "array" },
    "runtime_evidence": { "type": "array" }
  }
}
EOF

    write_template_file "verification/scripts/proof_check.sh" 0755 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

need_file() {
    local f="$1"
    [[ -f "$f" ]] || {
        echo "proof_check: missing file: $f" >&2
        exit 1
    }
}

required_files=(
  "verification/DECISION.md"
  "verification/ENVIRONMENT.md"
  "verification/spec/INVARIANTS.md"
  "verification/spec/ASSUMPTIONS.md"
  "verification/proof/THEOREM_INDEX.md"
  "verification/mapping/CODE_MODEL_TRACE.md"
  "verification/artifacts/manifest.schema.json"
)

for f in "${required_files[@]}"; do
    need_file "$f"
done

for id in INV-CAP-001 INV-MEM-001 INV-WX-001 INV-CFI-001 INV-TMP-001 INV-PER-001 INV-NET-001 INV-PRIV-001; do
    rg -q "$id" verification/spec/INVARIANTS.md || {
        echo "proof_check: missing invariant: $id" >&2
        exit 1
    }
done

for id in THM-CAP-001 THM-MEM-001 THM-WX-001 THM-CFI-001 THM-TMP-001 THM-PER-001 THM-NET-001 THM-PRIV-001; do
    rg -q "$id" verification/proof/THEOREM_INDEX.md || {
        echo "proof_check: missing theorem: $id" >&2
        exit 1
    }
done

rg -q "ASM-" verification/spec/ASSUMPTIONS.md || {
    echo "proof_check: missing ASM-* assumptions" >&2
    exit 1
}

rg -q "CO-" verification/mapping/CODE_MODEL_TRACE.md || {
    echo "proof_check: missing CO-* correspondence IDs" >&2
    exit 1
}

if rg -n '^Status:' verification/proof/THEOREM_INDEX.md >/dev/null; then
    bad_status_lines="$(rg -n '^Status:' verification/proof/THEOREM_INDEX.md | rg -v 'Status: <Planned\|InProgress\|Proven\|Invalidated\|Blocked>|Status: (Planned|InProgress|Proven|Invalidated|Blocked)$' || true)"
    if [[ -n "$bad_status_lines" ]]; then
        echo "proof_check: invalid theorem status labels detected:" >&2
        echo "$bad_status_lines" >&2
        exit 1
    fi
fi

for key in commit_sha generated_at theorems assumptions_version ci_runs runtime_evidence; do
    rg -q "\"$key\"" verification/artifacts/manifest.schema.json || {
        echo "proof_check: manifest schema missing key: $key" >&2
        exit 1
    }
done

echo "proof_check: baseline structure present"
EOF

    write_template_file ".github/workflows/proof-check.yml" <<'EOF'
name: proof-check

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  proof-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Baseline verification structure
        run: bash verification/scripts/proof_check.sh
EOF

    write_template_file "verification/artifacts/runtime_evidence.md" <<'EOF'
# Runtime Evidence

- formal-verify: TODO
- temporal-hardening-selftest: TODO
- capnet-fuzz-corpus: TODO
- wasm-jit-fuzz-corpus: TODO
EOF

    write_template_file "verification/artifacts/manifest.json" <<'EOF'
{
  "commit_sha": "TODO",
  "generated_at": "TODO",
  "theorems": [],
  "assumptions_version": "TODO",
  "ci_runs": [],
  "runtime_evidence": []
}
EOF

    log "Bootstrap complete."
}

check_common() {
    local fail_count=0
    local missing=()

    for d in "${REQUIRED_DIRS[@]}"; do
        if [[ ! -d "$d" ]]; then
            missing+=("$d (dir)")
            fail_count=$((fail_count + 1))
        fi
    done

    for f in "${REQUIRED_FILES[@]}"; do
        if [[ ! -f "$f" ]]; then
            missing+=("$f")
            fail_count=$((fail_count + 1))
        fi
    done

    if [[ "$fail_count" -gt 0 ]]; then
        printf '%s\n' "${missing[@]}" >&2
        die "missing required runbook paths (count=$fail_count)"
    fi

    [[ -x verification/scripts/proof_check.sh ]] || die "verification/scripts/proof_check.sh is not executable"
    bash verification/scripts/proof_check.sh

    for inv in "${MANDATORY_INVARIANTS[@]}"; do
        rg -q "$inv" verification/spec/INVARIANTS.md || die "missing mandatory invariant in index: $inv"
    done

    for thm in "${MANDATORY_THEOREMS[@]}"; do
        rg -q "$thm" verification/proof/THEOREM_INDEX.md || die "missing mandatory theorem in index: $thm"
    done

    if rg -n '^Status:' verification/proof/THEOREM_INDEX.md >/dev/null; then
        if rg -n '^Status:' verification/proof/THEOREM_INDEX.md | rg -v 'Status: <Planned\|InProgress\|Proven\|Invalidated\|Blocked>|Status: (Planned|InProgress|Proven|Invalidated|Blocked)$' >/dev/null; then
            die "detected invalid theorem status label(s); allowed: Planned, InProgress, Proven, Invalidated, Blocked"
        fi
    fi

    rg -q "ASM-" verification/spec/ASSUMPTIONS.md || die "ASSUMPTIONS.md must include ASM-* IDs"
    rg -q "CO-" verification/mapping/CODE_MODEL_TRACE.md || die "CODE_MODEL_TRACE.md must include CO-* IDs"
}

check_strict() {
    local workflow_dir=".github/workflows"
    [[ -d "$workflow_dir" ]] || die "missing workflow directory: $workflow_dir"

    for job in "${STRICT_CI_JOB_NAMES[@]}"; do
        if ! rg -q "$job" "$workflow_dir"/*.yml "$workflow_dir"/*.yaml 2>/dev/null; then
            die "strict mode: missing required CI job name in workflows: $job"
        fi
    done

    rg -q "formal-verify" verification/artifacts/runtime_evidence.md || die "strict mode: runtime evidence file missing formal-verify record"
    rg -q "temporal-hardening-selftest" verification/artifacts/runtime_evidence.md || die "strict mode: runtime evidence file missing temporal-hardening-selftest record"
}

check_runbook() {
    check_common
    if [[ "$STRICT" -eq 1 ]]; then
        check_strict
    fi
    log "Runbook checks PASSED."
}

status_runbook() {
    local rc=0
    echo "Formal Verification Runbook Status"
    echo "================================="

    for d in "${REQUIRED_DIRS[@]}"; do
        if [[ -d "$d" ]]; then
            echo "[OK]    $d"
        else
            echo "[MISS]  $d"
            rc=1
        fi
    done

    for f in "${REQUIRED_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            echo "[OK]    $f"
        else
            echo "[MISS]  $f"
            rc=1
        fi
    done

    if [[ "$STRICT" -eq 1 ]]; then
        echo ""
        echo "Strict CI Jobs"
        echo "--------------"
        for job in "${STRICT_CI_JOB_NAMES[@]}"; do
            if rg -q "$job" .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null; then
                echo "[OK]    $job"
            else
                echo "[MISS]  $job"
                rc=1
            fi
        done
    fi

    echo ""
    if [[ "$rc" -eq 0 ]]; then
        echo "Status: READY"
    else
        echo "Status: INCOMPLETE"
    fi
    return "$rc"
}

main() {
    need_cmd rg
    parse_args "$@"

    case "$CMD" in
        bootstrap)
            bootstrap
            ;;
        check)
            check_runbook
            ;;
        status)
            status_runbook
            ;;
        all)
            bootstrap
            check_runbook
            ;;
        *)
            usage
            die "unknown command: $CMD"
            ;;
    esac
}

main "$@"
