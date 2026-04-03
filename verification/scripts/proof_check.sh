#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if command -v rg >/dev/null 2>&1; then
    _rg() { rg "$@"; }
else
    _rg() { grep "$@"; }
fi

die() {
    echo "proof_check: $*" >&2
    exit 1
}

need_file() {
    local f="$1"
    [[ -f "$f" ]] || die "missing file: $f"
}

need_dir() {
    local d="$1"
    [[ -d "$d" ]] || die "missing directory: $d"
}

need_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
}

required_dirs=(
    "verification/spec"
    "verification/proof"
    "verification/theories"
    "verification/mapping"
    "verification/artifacts"
    "verification/scripts"
    "verification/ci"
)

required_files=(
    "verification/README.md"
    "verification/DECISION.md"
    "verification/ENVIRONMENT.md"
    "verification/BOOTSTRAP_NOTES.md"
    "verification/parity-matrix.json"
    "verification/spec/INVARIANTS.md"
    "verification/spec/ASSUMPTIONS.md"
    "verification/spec/THREAT_MODEL.md"
    "verification/proof/THEOREM_INDEX.md"
    "verification/mapping/CODE_MODEL_TRACE.md"
    "verification/artifacts/manifest.schema.json"
    "verification/artifacts/manifest.json"
    "verification/artifacts/runtime_evidence.md"
    "verification/scripts/formal-verification-runbook.sh"
    "verification/scripts/proof_check.sh"
    "verification/ci/proof-check.yml"
    ".github/workflows/proof-check.yml"
)

mandatory_invariants=(
    "INV-CAP-001"
    "INV-MEM-001"
    "INV-WX-001"
    "INV-CFI-001"
    "INV-TMP-001"
    "INV-PER-001"
    "INV-NET-001"
    "INV-PRIV-001"
)

mandatory_theorems=(
    "THM-CAP-001"
    "THM-MEM-001"
    "THM-WX-001"
    "THM-CFI-001"
    "THM-TMP-001"
    "THM-PER-001"
    "THM-NET-001"
    "THM-PRIV-001"
)

mandatory_theory_sources=(
    "verification/theories/ipc_flow.v"
    "verification/theories/temporal_logic.v"
    "verification/theories/wx_cfi.v"
    "verification/theories/lock_dag.v"
    "verification/theories/scheduler_entropy.v"
    "verification/theories/memory_isolation.v"
    "verification/theories/persistence.v"
    "verification/theories/capnet_integrity.v"
    "verification/theories/privilege_safety.v"
)

for d in "${required_dirs[@]}"; do
    need_dir "$d"
done

for f in "${required_files[@]}"; do
    need_file "$f"
done

for f in "${mandatory_theory_sources[@]}"; do
    need_file "$f"
done

for id in "${mandatory_invariants[@]}"; do
    _rg -q "$id" verification/spec/INVARIANTS.md || die "missing invariant: $id"
done

for id in "${mandatory_theorems[@]}"; do
    _rg -q "$id" verification/proof/THEOREM_INDEX.md || die "missing theorem: $id"
done

_rg -q "ASM-" verification/spec/ASSUMPTIONS.md || die "missing ASM-* assumptions"
_rg -q "CO-" verification/mapping/CODE_MODEL_TRACE.md || die "missing CO-* correspondence IDs"

if _rg -n '^Status:' verification/proof/THEOREM_INDEX.md >/dev/null; then
    bad_status_lines="$(_rg -n '^Status:' verification/proof/THEOREM_INDEX.md | _rg -v 'Status: (Planned|InProgress|Proven|Invalidated|Blocked)$' || true)"
    [[ -z "$bad_status_lines" ]] || {
        echo "proof_check: invalid theorem status labels detected:" >&2
        echo "$bad_status_lines" >&2
        exit 1
    }
fi

need_cmd python3

python3 <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(".")
manifest = json.loads((root / "verification/artifacts/manifest.json").read_text())
schema = json.loads((root / "verification/artifacts/manifest.schema.json").read_text())
parity = json.loads((root / "verification/parity-matrix.json").read_text())
theorem_index = (root / "verification/proof/THEOREM_INDEX.md").read_text()
runtime_evidence = (root / "verification/artifacts/runtime_evidence.md").read_text()
decision = (root / "verification/DECISION.md").read_text()

required_manifest = ["commit_sha", "generated_at", "theorems", "assumptions_version", "ci_runs", "runtime_evidence"]
for key in required_manifest:
    if key not in schema.get("required", []):
        raise SystemExit(f"proof_check: manifest schema missing required key declaration: {key}")
    if key not in manifest:
        raise SystemExit(f"proof_check: manifest missing key: {key}")

if not isinstance(manifest["theorems"], list) or not manifest["theorems"]:
    raise SystemExit("proof_check: manifest.theorems must be a non-empty array")
if not isinstance(manifest["ci_runs"], list) or not manifest["ci_runs"]:
    raise SystemExit("proof_check: manifest.ci_runs must be a non-empty array")
if not isinstance(manifest["runtime_evidence"], list) or not manifest["runtime_evidence"]:
    raise SystemExit("proof_check: manifest.runtime_evidence must be a non-empty array")

placeholder_values = {"", "UNSET", "pending", "<pending>"}

def check_placeholder(value, path):
    if isinstance(value, str) and value.strip() in placeholder_values:
        raise SystemExit(f"proof_check: unresolved placeholder value at {path}: {value!r}")
    if isinstance(value, list) and not value:
        raise SystemExit(f"proof_check: unresolved empty list at {path}")
    if isinstance(value, dict):
        if not value:
            raise SystemExit(f"proof_check: unresolved empty object at {path}")
        for k, v in value.items():
            check_placeholder(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            check_placeholder(v, f"{path}[{i}]")

check_placeholder(manifest, "manifest")

allowed_status = {"Planned", "InProgress", "Proven", "Invalidated", "Blocked"}
manifest_theorem_ids = set()
for idx, theorem in enumerate(manifest["theorems"]):
    path = f"manifest.theorems[{idx}]"
    for key in ("id", "status", "artifact", "invariant"):
        if key not in theorem:
            raise SystemExit(f"proof_check: missing {path}.{key}")
    if theorem["status"] not in allowed_status:
        raise SystemExit(f"proof_check: invalid {path}.status={theorem['status']!r}")
    artifact = root / theorem["artifact"]
    if not artifact.is_file():
        raise SystemExit(f"proof_check: theorem artifact missing on disk: {artifact}")
    if theorem["id"] in manifest_theorem_ids:
        raise SystemExit(f"proof_check: duplicate theorem id in manifest: {theorem['id']}")
    manifest_theorem_ids.add(theorem["id"])
    if theorem["id"] not in theorem_index:
        raise SystemExit(f"proof_check: theorem id absent from THEOREM_INDEX: {theorem['id']}")
    if theorem["invariant"] not in theorem_index:
        raise SystemExit(f"proof_check: theorem invariant absent from THEOREM_INDEX: {theorem['invariant']}")

expected_theorems = {
    "THM-CAP-001",
    "THM-MEM-001",
    "THM-WX-001",
    "THM-CFI-001",
    "THM-TMP-001",
    "THM-PER-001",
    "THM-NET-001",
    "THM-PRIV-001",
}
missing = expected_theorems - manifest_theorem_ids
if missing:
    raise SystemExit(f"proof_check: manifest missing mandatory theorem records: {sorted(missing)}")

for idx, entry in enumerate(manifest["runtime_evidence"]):
    path = f"manifest.runtime_evidence[{idx}]"
    for key in ("id", "status", "commit"):
        if key not in entry:
            raise SystemExit(f"proof_check: missing {path}.{key}")
    if entry["id"] not in runtime_evidence:
        raise SystemExit(f"proof_check: runtime_evidence.md missing record for {entry['id']}")

for idx, run in enumerate(manifest["ci_runs"]):
    path = f"manifest.ci_runs[{idx}]"
    for key in ("job", "result", "commit"):
        if key not in run:
            raise SystemExit(f"proof_check: missing {path}.{key}")
    artifacts = run.get("artifacts")
    if artifacts is not None:
        if not isinstance(artifacts, list) or not artifacts:
            raise SystemExit(f"proof_check: {path}.artifacts must be a non-empty array when present")

required_ci_jobs = {"proof-check", "coq-proofs", "manifest-check"}
for job in required_ci_jobs:
    if job not in (root / ".github/workflows/proof-check.yml").read_text():
        raise SystemExit(f"proof_check: missing CI job in repo workflow: {job}")
    if job not in (root / "verification/ci/proof-check.yml").read_text():
        raise SystemExit(f"proof_check: missing CI job in verification workflow helper: {job}")

status_values = {"true", "false", "partial"}
targets = parity.get("targets", [])
if set(targets) != {"i686", "x86_64", "aarch64"}:
    raise SystemExit(f"proof_check: unexpected parity targets: {targets}")
subsystems = parity.get("subsystems")
if not isinstance(subsystems, list) or not subsystems:
    raise SystemExit("proof_check: parity matrix must contain non-empty subsystems array")
seen_names = set()
for idx, subsystem in enumerate(subsystems):
    name = subsystem.get("name")
    if not name:
        raise SystemExit(f"proof_check: parity subsystem[{idx}] missing name")
    if name in seen_names:
        raise SystemExit(f"proof_check: duplicate parity subsystem name: {name}")
    seen_names.add(name)
    for target in targets:
        if target not in subsystem:
            raise SystemExit(f"proof_check: parity subsystem {name} missing target {target}")
        value = subsystem[target]
        if isinstance(value, bool):
            continue
        if value != "partial":
            raise SystemExit(f"proof_check: invalid parity value for {name}.{target}: {value!r}")
    notes = subsystem.get("notes")
    if not isinstance(notes, str) or not notes.strip():
        raise SystemExit(f"proof_check: parity subsystem {name} missing notes")

if "Coq / The Rocq Prover" not in decision or "9.1.1" not in decision:
    raise SystemExit("proof_check: DECISION.md missing expected toolchain declaration")

sha = manifest["commit_sha"]
if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
    raise SystemExit(f"proof_check: commit_sha has unexpected format: {sha!r}")

print("proof_check: manifest, parity matrix, workflow, and theorem metadata are consistent")
PY

echo "proof_check: baseline structure and metadata present"
