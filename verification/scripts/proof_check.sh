#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

required_paths=(
  "verification/README.md"
  "verification/spec/ASSUMPTIONS.md"
  "verification/spec/INVARIANTS.md"
  "verification/proof/THEOREM_INDEX.md"
  "verification/artifacts/manifest.json"
  "verification/theories/temporal_logic.v"
  "verification/theories/ipc_flow.v"
  "verification/theories/wx_cfi.v"
  "verification/theories/lock_dag.v"
  "verification/theories/scheduler_entropy.v"
)

for path in "${required_paths[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing verification workspace file: $path" >&2
    exit 1
  fi
done

python3 - <<'PY'
import json
from pathlib import Path
import sys

manifest_path = Path("verification/artifacts/manifest.json")
manifest = json.loads(manifest_path.read_text())

required_keys = [
    "commit_sha",
    "generated_at",
    "assumptions_version",
    "theorems",
    "ci_runs",
    "runtime_evidence",
]
missing = [key for key in required_keys if key not in manifest]
if missing:
    print(f"manifest.json missing keys: {missing}", file=sys.stderr)
    sys.exit(1)

if not manifest["theorems"]:
    print("manifest.json has an empty theorems list", file=sys.stderr)
    sys.exit(1)

if not manifest["ci_runs"]:
    print("manifest.json has an empty ci_runs list", file=sys.stderr)
    sys.exit(1)

if not manifest["runtime_evidence"]:
    print("manifest.json has an empty runtime_evidence list", file=sys.stderr)
    sys.exit(1)

placeholders = [
    key for key, value in manifest.items()
    if value in ("", "UNSET") or value == []
]
if placeholders:
    print(
        f"manifest.json has unresolved placeholder fields: {placeholders}",
        file=sys.stderr,
    )
    sys.exit(1)

theorem_index = Path("verification/proof/THEOREM_INDEX.md").read_text()
if "Status: Planned" in theorem_index:
    print("THEOREM_INDEX.md still contains Planned entries", file=sys.stderr)
    sys.exit(1)

assumptions = Path("verification/spec/ASSUMPTIONS.md").read_text().splitlines()
for line in assumptions:
    if line.startswith("- ASM-") and any(
        token in line for token in ("<", "TBD", "UNSET", "pending")
    ):
        print(
            f"ASSUMPTIONS.md contains an unresolved placeholder: {line}",
            file=sys.stderr,
        )
        sys.exit(1)

print("verification workspace structure OK")
PY
