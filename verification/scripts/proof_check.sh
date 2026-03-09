#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Use ripgrep when available; fall back to grep for portability.
if command -v rg &>/dev/null; then
    _rg() { rg "$@"; }
else
    _rg() {
        # Translate the ripgrep flags used in this script:
        #   -q  -> -q (same in grep)
        #   -n  -> -n (same in grep)
        # No PCRE patterns are used, so basic grep is sufficient.
        grep "$@"
    }
fi

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
    _rg -q "$id" verification/spec/INVARIANTS.md || {
        echo "proof_check: missing invariant: $id" >&2
        exit 1
    }
done

for id in THM-CAP-001 THM-MEM-001 THM-WX-001 THM-CFI-001 THM-TMP-001 THM-PER-001 THM-NET-001 THM-PRIV-001; do
    _rg -q "$id" verification/proof/THEOREM_INDEX.md || {
        echo "proof_check: missing theorem: $id" >&2
        exit 1
    }
done

_rg -q "ASM-" verification/spec/ASSUMPTIONS.md || {
    echo "proof_check: missing ASM-* assumptions" >&2
    exit 1
}

_rg -q "CO-" verification/mapping/CODE_MODEL_TRACE.md || {
    echo "proof_check: missing CO-* correspondence IDs" >&2
    exit 1
}

if _rg -n '^Status:' verification/proof/THEOREM_INDEX.md >/dev/null; then
    bad_status_lines="$(_rg -n '^Status:' verification/proof/THEOREM_INDEX.md | _rg -v 'Status: (Planned|InProgress|Proven|Invalidated|Blocked)$' || true)"
    if [[ -n "$bad_status_lines" ]]; then
        echo "proof_check: invalid theorem status labels detected:" >&2
        echo "$bad_status_lines" >&2
        exit 1
    fi
fi

for key in commit_sha generated_at theorems assumptions_version ci_runs runtime_evidence; do
    _rg -q "\"$key\"" verification/artifacts/manifest.schema.json || {
        echo "proof_check: manifest schema missing key: $key" >&2
        exit 1
    }
done

echo "proof_check: baseline structure present"
