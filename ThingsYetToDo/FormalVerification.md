# Oreulia Formal Verification Program

Status: Normative execution runbook  
Owner: Kernel architecture + verification maintainers  
Primary goal: Move from strong runtime self-checks to machine-checked, theorem-backed subsystem correctness claims.

---

## 0. Current Assessment (What Needed Improvement)

The previous version had the right direction, but it was not execution-ready because:

- It listed goals, but not strict phase exit criteria.
- It did not define required artifacts per step.
- It did not define pass/fail release gates.
- It did not define traceability from code -> spec -> theorem -> CI evidence.
- It did not separate full proof claims from modeled-subset claims.

This version fixes that by making the plan enforceable.

---

## 1. Scope, Claims, and Non-Claims

### 1.1 Scope

This program covers formalization and machine-checked reasoning for:

- Capability semantics and authority transitions.
- Temporal object transitions and persistence decode/restore invariants.
- CapNet token acceptance and replay-safety invariants.
- WASM/JIT translation safety properties for the modeled translation subset.
- Privilege transition invariants for syscall/user-return pathways.

### 1.2 Allowed Claims

A claim may be made only when accompanied by:

- A formal statement with theorem ID.
- A machine-checked proof artifact.
- A reproducible CI record for the exact commit.

### 1.3 Forbidden Claims

Do not claim:

- "Fully proven kernel" if any required subsystem remains outside model scope.
- "No bugs" or "unbreakable" under undefined attacker or hardware models.
- Properties not tied to a theorem and proof artifact.

---

## 2. Normative Language

- MUST: mandatory for merge/release.
- SHOULD: strongly recommended; deviations require written rationale.
- MAY: optional.

If a MUST is unmet, release is blocked.

---

## 3. Verification Architecture

The verification stack is split into four layers:

1. Formal model layer: mathematical state machines and invariants.
2. Mechanized proof layer: machine-checked proofs over the model.
3. Correspondence layer: mapping implementation constructs to modeled semantics.
4. Runtime evidence layer: in-kernel verification commands and fuzz regressions.

All four layers are required for production-grade claims.

---

## 4. Required Invariants (Canonical Set)

The formal corpus MUST include at least these invariants:

- INV-CAP-001: capability authority cannot increase without authorized derivation.
- INV-MEM-001: no out-of-bounds memory access in modeled transitions.
- INV-WX-001: no reachable RWX page state.
- INV-CFI-001: indirect control transfers target only allowed entry sets.
- INV-TMP-001: temporal rollback and merge preserve object consistency invariants.
- INV-PER-001: persisted temporal decode rejects integrity-inconsistent payloads.
- INV-NET-001: CapNet acceptance requires integrity + freshness + rights attenuation.
- INV-PRIV-001: user/kernel privilege transitions preserve control-return integrity.

Each invariant MUST have:

- A formal definition.
- A theorem over transition closure.
- A proof status and artifact reference.

---

## 5. Formal Core Equations (Minimum Required)

These equations define the minimum formal backbone.

### 5.1 Invariant Preservation

For system transition relation `T` and invariant `I`:

`Init(s0) AND Reachable(T, s0, s) => I(s)`

### 5.2 Step Induction

`I(s) AND T(s, s') => I(s')`

### 5.3 Authority Attenuation

For derived capability `c'` from `c`:

`Derive(c, c') => Rights(c') subseteq Rights(c)`

### 5.4 CapNet Acceptance Soundness

`Accept(tok) => MAC_Valid(tok) AND Fresh(tok) AND Attenuated(tok) AND NotRevoked(tok)`

### 5.5 Temporal Integrity Consistency

`Decode(snapshot) = Some(state) => IntegrityTag(snapshot) = RecomputeTag(snapshot_payload)`

### 5.6 W^X Safety

`ReachableState(s) => NOT Exists(page) . Writable(page, s) AND Executable(page, s)`

---

## 6. Program Phases With Strict Exit Gates

### Phase A: Toolchain and Model Foundation

Deliverables:

- Selected proof assistant and rationale document.
- Repository structure for specs/proofs.
- Coding standard for theorem naming and proof style.

Exit gate (MUST):

- Decision document merged.
- Proof environment reproducibly builds in CI.

### Phase B: Formal Semantics

Deliverables:

- Abstract machine semantics for process, memory, capability, temporal, network, and JIT modeled subset.
- Small-step or transition relation definitions with test vectors.

Exit gate (MUST):

- Semantics compile/check in proof assistant.
- Peer-reviewed semantics document merged.

### Phase C: Invariant Specification

Deliverables:

- Canonical invariant catalog (IDs, definitions, assumptions, scope).
- Attack model and trust boundary document.

Exit gate (MUST):

- Every invariant linked to a specific subsystem owner.
- No invariant has unresolved TODOs.

### Phase D: Mechanized Proofs

Deliverables:

- Proof scripts for canonical invariants.
- Automated proof runner for CI.

Exit gate (MUST):

- All designated theorems in this phase marked Proven.
- CI job `proof-check` passes on clean checkout.

### Phase E: Code-Model Correspondence

Deliverables:

- Mapping document from implementation constructs to formal entities.
- Checked contracts/lemmas for critical Rust/asm boundaries.

Exit gate (MUST):

- Correspondence proof obligations pass for covered modules.
- Any uncovered area is explicitly listed in limitation set.

### Phase F: Verified JIT Path

Deliverables:

- Formal translation relation for modeled WASM subset.
- Proof of memory/control-flow safety for generated code under assumptions.

Exit gate (MUST):

- Translation theorem suite passes.
- Differential fuzz + formal obligations both pass in CI.

### Phase G: Release Gating

Deliverables:

- Release policy wired to proof CI results.
- Artifact manifest (theorem hashes, proof logs, commit IDs).

Exit gate (MUST):

- Release pipeline fails closed on proof regression.
- Manifest generated and attached to every release candidate.

### Phase H: External Audit and Publication

Deliverables:

- Independent expert review report.
- Published proof corpus and reproducibility instructions.

Exit gate (MUST):

- Audit issues triaged and dispositioned.
- Public docs link claims to theorem IDs and artifacts.

---

## 7. Artifact Requirements (Mandatory)

Every verification-relevant PR MUST include:

- `spec diff`: what formal statement changed.
- `proof impact`: which theorem IDs were touched.
- `correspondence impact`: implementation-to-model mapping impact.
- `evidence`: CI links/logs showing proof status.
- `limitations`: any newly uncovered or deferred areas.

PRs missing these are non-compliant.

---

## 8. Traceability Matrix (Required Format)

Maintain this table and keep it current:

| Subsystem | Spec File | Theorem IDs | Implementation Surface | CI Job | Runtime Evidence |
|---|---|---|---|---|---|
| Capability | `spec/capability.*` | `THM-CAP-*` | `kernel/src/capability.rs` | `proof-check` | `formal-verify` |
| Temporal | `spec/temporal.*` | `THM-TMP-*` | `kernel/src/temporal.rs` | `proof-check` | `formal-verify`, `temporal-hardening-selftest` |
| CapNet | `spec/capnet.*` | `THM-NET-*` | `kernel/src/capnet.rs` | `proof-check` | `formal-verify`, `capnet-fuzz-corpus` |
| JIT | `spec/jit.*` | `THM-JIT-*` | `kernel/src/wasm_jit.rs` | `proof-check` | `formal-verify`, `wasm-jit-fuzz-corpus` |
| Privilege transitions | `spec/priv.*` | `THM-PRIV-*` | `kernel/src/asm/*.asm`, syscall path | `proof-check` | `formal-verify`, syscall tests |

If a row is missing theorem IDs or CI wiring, subsystem is not verification-complete.

---

## 9. Runtime Verification Integration Rules

Runtime checks are evidence, not substitutes for formal proof.

- `formal-verify` MUST stay green on release branches.
- `temporal-hardening-selftest` MUST stay green on release branches.
- Corpus replay/fuzz regressions MUST run deterministically in CI for fixed seeds.
- Any mismatch between formal assumptions and runtime behavior MUST open a blocking issue.

---

## 10. Definition of Done (Strict)

A subsystem is "formally verified" only if all are true:

- Formal semantics exist and are versioned.
- Theorem set is complete for declared invariants.
- Proof artifacts are machine-checked in CI.
- Code-model correspondence obligations are satisfied.
- Limitations are explicit and reviewed.
- Runtime evidence commands pass for the same release commit.

If any condition is false, label is "partially verified".

---

## 11. Immediate Next Actions (Execution Queue)

1. Create `verification/` tree with `spec/`, `proof/`, `correspondence/`, `artifacts/`.
2. Lock theorem naming scheme (`THM-CAP-*`, `THM-TMP-*`, `THM-JIT-*`, `THM-NET-*`, `THM-PRIV-*`).
3. Draft first machine semantics for capability + temporal transitions.
4. Encode canonical invariants `INV-*` and corresponding `THM-*` stubs.
5. Wire proof runner into CI as mandatory check.
6. Add release manifest generation for proof artifacts.

---

## 12. Final Constraint

No release should claim stronger assurance than the proven model scope.

In short:

- Proven in model => allowed claim.
- Not proven in model => explicit limitation.

---

## 13. Fresh-State Bootstrap Runbook (Cold Start)

This section is mandatory for any engineer starting from zero context.

### 13.1 Required Inputs

Before writing proofs, the engineer MUST have:

- The current repository checkout.
- The current kernel command surface (`formal-verify`, temporal hardening checks, fuzz corpus commands).
- The current subsystem docs in `docs/`.

### 13.2 Required Reading Order (Do Not Skip)

Read these in order:

1. `README.md` (verification and temporal sections).
2. `docs/oreulia-jit-security-resolution.md`.
3. `docs/capnet.md`.
4. `docs/oreulia-temporal-adapters-durable-persistence.md`.
5. `docs/oreulia-service-pointer-capabilities.md`.
6. `kernel/src/commands.rs` (verification command implementations).
7. `kernel/src/temporal.rs`, `kernel/src/capnet.rs`, `kernel/src/wasm_jit.rs`, `kernel/src/syscall.rs`.

Exit gate (MUST):

- A one-page subsystem summary is written and checked in at `verification/BOOTSTRAP_NOTES.md`.

### 13.3 Environment Bootstrap (Default: Coq Track)

Default proof track is Coq unless a decision record says otherwise.

Required commands (reference workflow):

```bash
git clone <repo>
cd oreulia
mkdir -p verification/{spec,proof,theories,mapping,artifacts,scripts,ci}
```

Toolchain MUST be pinned in `verification/DECISION.md` with:

- proof assistant and version,
- OCaml/runtime version if applicable,
- package lock strategy,
- rationale for any deviation from default.

Exit gate (MUST):

- `verification/DECISION.md` exists and is approved.
- `verification/ENVIRONMENT.md` contains reproducible setup commands.

### 13.4 Mandatory Initial File Set

These files MUST exist before Phase B begins:

- `verification/README.md`
- `verification/DECISION.md`
- `verification/ENVIRONMENT.md`
- `verification/spec/INVARIANTS.md`
- `verification/spec/ASSUMPTIONS.md`
- `verification/spec/THREAT_MODEL.md`
- `verification/proof/THEOREM_INDEX.md`
- `verification/mapping/CODE_MODEL_TRACE.md`
- `verification/artifacts/manifest.schema.json`
- `verification/scripts/proof_check.sh`

Exit gate (MUST):

- `proof_check.sh` returns non-zero on missing theorem artifacts.
- CI invokes `verification/scripts/proof_check.sh`.

---

## 14. Mandatory Theorem Workflow (Per Theorem)

Each theorem MUST follow this lifecycle:

1. Draft statement.
2. Register theorem ID in index.
3. Declare assumptions.
4. Prove in assistant.
5. Link implementation correspondence.
6. Attach CI evidence hash.
7. Mark status.

Allowed statuses:

- `Planned`
- `InProgress`
- `Proven`
- `Invalidated`
- `Blocked`

No other status labels are allowed.

### 14.1 Theorem Record Template (Required)

Use this exact template in `verification/proof/THEOREM_INDEX.md`:

```text
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
```

If any field is missing, theorem is non-compliant.

---

## 15. Model and Correspondence Rules

### 15.1 Assumption Discipline

All assumptions MUST be explicit, named, and versioned:

- `ASM-MODEL-*` for model abstractions.
- `ASM-HW-*` for hardware assumptions.
- `ASM-TOOL-*` for proof tool trust assumptions.

No hidden assumptions are allowed in proof comments.

### 15.2 Correspondence Obligation Types

Each subsystem MUST have these correspondence obligations:

- `CO-SYNTAX-*`: implementation structure maps to model entities.
- `CO-SEM-*`: transition behavior matches modeled transition relation.
- `CO-BOUNDARY-*`: boundary/FFI/asm interactions preserve modeled guarantees.

Each `THM-*` MUST reference at least one `CO-*` when implementation claims are made.

---

## 16. CI and Release Enforcement (Strict)

### 16.1 Required CI Jobs

Release branches MUST include and gate on:

- `proof-check`: theorem artifacts and machine checks.
- `proof-trace-check`: theorem index <-> mapping consistency.
- `runtime-verify-check`: `formal-verify` and temporal hardening command evidence.
- `fuzz-regression-check`: deterministic corpus replay for configured seeds.

### 16.2 Fail-Closed Policy

Release candidate is blocked if any is true:

- Any required theorem status is not `Proven`.
- Any theorem references a missing assumption ID.
- Any correspondence record points to deleted/moved code without update.
- Runtime evidence for required commands is missing.
- Proof artifact manifest hash does not match checked-in index.

### 16.3 Required Manifest Fields

`verification/artifacts/manifest.json` MUST contain:

- commit SHA,
- theorem IDs and statuses,
- proof artifact hashes,
- CI run IDs,
- required runtime verification results.

---

## 17. Claim Language Policy (What You May Say Publicly)

Allowed phrasing examples:

- "Modeled subset proofs completed for capability attenuation and temporal integrity."
- "Machine-checked proofs exist for listed theorem IDs at commit `<sha>`."

Disallowed phrasing examples:

- "Kernel is fully mathematically proven" when any required subsystem is partial.
- "100% secure" without explicit model scope and assumptions.

All public claims MUST cite:

- theorem IDs,
- model scope,
- assumption set version.

---

## 18. Execution Checklist (Single-Page Operator View)

A fresh engineer can execute this program only when all are true:

- [ ] Read order in Section 13.2 completed and notes committed.
- [ ] Toolchain decision and environment docs committed.
- [ ] Mandatory file set in Section 13.4 exists.
- [ ] Invariants and assumptions indexed with IDs.
- [ ] Theorem index created using required template.
- [ ] Correspondence matrix created and linked.
- [ ] CI jobs from Section 16.1 running and enforced.
- [ ] Runtime verification evidence attached for required commands.
- [ ] Release manifest generated and hash-verified.

If any box is unchecked, verification program is not ready for release claims.

---

## 19. Practical Completeness Statement

Can someone "fully verify Oreulia" from this document alone?

- This document now provides enough operational guidance to execute the verification program from a fresh state.
- Full verification still requires implementing the formal models and proofs themselves.
- Therefore, this file is a complete runbook, not a substitute for theorem development effort.

This distinction is mandatory and must be preserved in all planning and release communication.

---

## 20. Minimum Theorem Backlog (Must Exist Before Strong Claims)

The following theorem IDs are mandatory baseline obligations:

| Theorem ID | Invariant | Minimum Statement Requirement |
|---|---|---|
| `THM-CAP-001` | `INV-CAP-001` | Derivation/transfer/revoke transitions cannot create unauthorized rights. |
| `THM-MEM-001` | `INV-MEM-001` | Modeled memory transitions preserve in-bounds access. |
| `THM-WX-001` | `INV-WX-001` | No reachable state admits simultaneously writable and executable page mapping. |
| `THM-CFI-001` | `INV-CFI-001` | Indirect branch targets are constrained to valid entry set. |
| `THM-TMP-001` | `INV-TMP-001` | Rollback/merge transitions preserve temporal consistency relation. |
| `THM-PER-001` | `INV-PER-001` | Persisted temporal decode rejects integrity-inconsistent snapshots. |
| `THM-NET-001` | `INV-NET-001` | CapNet acceptance implies integrity, freshness, attenuation, non-revocation. |
| `THM-PRIV-001` | `INV-PRIV-001` | User/kernel transition path preserves return integrity constraints. |

Strong public verification claims are forbidden until all rows above are `Proven`.

---

## 21. Copy-Paste Bootstrap Templates

### 21.1 `verification/scripts/proof_check.sh` (Baseline)

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

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
  test -f "$f"
done

grep -q "THM-" verification/proof/THEOREM_INDEX.md
grep -q "INV-" verification/spec/INVARIANTS.md
grep -q "ASM-" verification/spec/ASSUMPTIONS.md
grep -q "CO-" verification/mapping/CODE_MODEL_TRACE.md

echo "proof_check: baseline structure present"
```

### 21.2 CI Skeleton (`.github/workflows/proof-check.yml`)

```yaml
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
```

### 21.3 Manifest Schema Minimum Keys

`verification/artifacts/manifest.schema.json` MUST define:

- `commit_sha`
- `generated_at`
- `theorems` (array of theorem objects)
- `assumptions_version`
- `ci_runs`
- `runtime_evidence`

---

## 22. Required Weekly Verification Cadence

Every week, maintainers MUST execute:

1. Theorem status review (`Planned/InProgress/Proven/Invalidated/Blocked`).
2. Assumption drift review (new hidden assumptions forbidden).
3. Correspondence drift review (changed kernel files mapped).
4. Runtime evidence replay (`formal-verify`, temporal hardening, corpus jobs).
5. Claim language review for docs/PR descriptions.

Exit artifact (MUST):

- `verification/artifacts/WEEKLY_STATUS_<YYYYMMDD>.md`

---

## 23. Blocker Protocol (When Proof Work Stalls)

If a theorem is blocked for > 7 days:

1. Mark theorem status `Blocked`.
2. Record blocker type:
   - model gap,
   - tool limitation,
   - correspondence ambiguity,
   - implementation instability.
3. Open linked issue with unblock plan and owner.
4. Downgrade any release claim touching that theorem scope.

No silent blockers are allowed.

---

## 24. Final Readiness Test (Fresh Engineer Test)

A new engineer passes the readiness test only if they can:

1. Bootstrap the verification directory and CI using this document alone.
2. Add one new theorem using the required template.
3. Link that theorem to at least one code surface and one correspondence obligation.
4. Produce manifest output and attach runtime evidence.

If they cannot do all four steps, this document must be revised before the next release.
