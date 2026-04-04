# Oreulius Verification Workspace

This directory is the verification control plane for Oreulius. It ties together:

- mechanized proofs under [theories/](./theories)
- human-readable invariants under [spec/](./spec)
- code-to-model correspondence under [mapping/](./mapping)
- generated or collected evidence under [artifacts/](./artifacts)
- structural and CI gates under [scripts/](./scripts) and [ci/](./ci)

It is not a marketing folder and it is not a generic "future formal methods" placeholder. It is the place where Oreulius states:

- what is being proved
- for which code surfaces those claims are intended to apply
- under which assumptions those claims are valid
- how a reviewer or maintainer can re-run the checks
- what evidence must exist before a theorem may be treated as live release evidence

---

## 1. The 5 Ws

### Who

This workspace is for:

- kernel maintainers changing trusted subsystems
- reviewers deciding whether a change invalidates a proof claim
- release engineers collecting proof and runtime evidence
- auditors mapping implementation claims to actual proof artifacts

### What

Oreulius currently verifies a bounded but meaningful set of safety properties:

- capability provenance and non-forgeability
- memory isolation over the modeled allocator / sandbox regions
- `W^X` and JIT control-flow integrity
- temporal monotonicity and persistence roundtrip properties
- CapNet capability-gated forwarding integrity
- privilege-transition safety across the syscall gate

### Where

The verified surfaces live across:

- [kernel/src/capability/mod.rs](../kernel/src/capability/mod.rs)
- [kernel/src/capability/cap_graph.rs](../kernel/src/capability/cap_graph.rs)
- [kernel/src/temporal/mod.rs](../kernel/src/temporal/mod.rs)
- [kernel/src/temporal/persistence.rs](../kernel/src/temporal/persistence.rs)
- [kernel/src/execution/wasm_jit.rs](../kernel/src/execution/wasm_jit.rs)
- [kernel/src/net/capnet.rs](../kernel/src/net/capnet.rs)
- [kernel/src/platform/syscall.rs](../kernel/src/platform/syscall.rs)
- [kernel/src/arch/x86_runtime.rs](../kernel/src/arch/x86_runtime.rs)
- [kernel/src/security/memory_isolation.rs](../kernel/src/security/memory_isolation.rs)

The mechanized theory files are under [verification/theories/](./theories).

### When

Run verification:

- before merging any change to a verified subsystem
- before cutting a release
- after changing invariant-relevant constants, state machines, or wire formats
- after changing CI/parsing logic that affects evidence collection

### Why

Oreulius is built around explicit authority, temporal semantics, and bounded execution. Those properties are only useful if the repo can answer:

- what the kernel claims
- what it does not claim
- which results are mechanized
- which results are only runtime evidence
- which results are still assumptions or open obligations

This directory exists to make those boundaries explicit.

---

## 2. Workspace Topology

```text
verification/
├── README.md                    # this document
├── DECISION.md                  # proof assistant / toolchain choice
├── ENVIRONMENT.md               # reproducible environment bootstrap
├── BOOTSTRAP_NOTES.md           # current workspace bootstrap notes
├── parity-matrix.json           # subsystem parity / verification coverage summary
├── spec/
│   ├── INVARIANTS.md            # canonical invariant IDs
│   ├── ASSUMPTIONS.md           # trusted assumptions and model boundaries
│   └── THREAT_MODEL.md          # attack surface / boundary framing
├── proof/
│   └── THEOREM_INDEX.md         # theorem records, status, proof artifacts
├── theories/
│   ├── *.v                      # Coq / Rocq theories
│   └── *.vo                     # compiled proof artifacts
├── mapping/
│   └── CODE_MODEL_TRACE.md      # correspondence obligations
├── artifacts/
│   ├── manifest.json            # generated manifest
│   ├── manifest.schema.json     # schema for the manifest
│   └── runtime_evidence.md      # runtime self-check / fuzz evidence register
├── scripts/
│   ├── proof_check.sh           # structural gate
│   └── formal-verification-runbook.sh
└── ci/
    └── proof-check.yml          # CI helper material
```

---

## 3. Verification Model

Oreulius verification is layered:

1. `Spec` layer: name the invariant precisely.
2. `Theory` layer: mechanize the property in Coq / Rocq.
3. `Mapping` layer: show which code surface the theory is intended to represent.
4. `Runtime evidence` layer: demonstrate the live kernel still behaves like the modeled design where practical.
5. `CI gate` layer: ensure the previous four layers remain structurally present and syntactically live.

The workspace is only credible if all five layers line up.

Let:

- `K` be the set of kernel states
- `T` be the set of modeled transitions
- `Inv : K -> Prop` be an invariant
- `step : K -> T -> K` be the modeled transition function

The base proof shape is the standard inductive preservation form:

\[
\forall k \in K.\; Inv(k) \land Enabled(t, k) \implies Inv(step(k,t))
\]

For reachability claims, Oreulius uses the closure form:

\[
Reachable(k_0, k) \implies Inv(k)
\]

For a set of invariants \( \{Inv_i\}_{i=1}^{n} \), the verification target is:

\[
Inv^\* (k) = \bigwedge_{i=1}^{n} Inv_i(k)
\]

The release-facing question is not "did one theorem compile?" It is:

\[
\forall k \in Reach(K_0).\; Inv^\*(k)
\]

subject to the explicit assumption register in [spec/ASSUMPTIONS.md](./spec/ASSUMPTIONS.md).

---

## 4. Trusted Computing Boundary

The verification story is only as honest as its trusted base.

### Trusted components

- the Coq / Rocq proof kernel
- the Rust compiler and assembler toolchain
- the QEMU/runtime harness for dynamic evidence
- the hardware model assumptions in [spec/ASSUMPTIONS.md](./spec/ASSUMPTIONS.md)

### Explicit assumptions

Current named assumptions are:

- `ASM-MODEL-001`: only modeled transition subsets are covered
- `ASM-MODEL-002`: architecture/assembly stubs (boot, trap, MMU, context-switch) are in the TCB until Program J obligations are discharged
- `ASM-HW-001`: hardware atomicity / coherence semantics at the modeled granularity; QEMU is the execution model for all runtime evidence
- `ASM-TOOL-001`: proof checker trustworthiness and artifact validity
- `ASM-TOOL-002`: Rust compiler, assembler, and linker are trusted base; proofs hold at source level only

Formally, proved statements in this workspace should be read as:

\[
ASM\_MODEL\_001 \land ASM\_HW\_001 \land ASM\_TOOL\_001 \implies Theorem
\]

If a subsystem or transition is not represented in the theory, no proof claim should be projected onto it by implication.

---

## 5. Canonical Invariants

The canonical invariant register lives in [spec/INVARIANTS.md](./spec/INVARIANTS.md). The current core set is:

- `INV-CAP-001`: capability authority cannot increase without authorized derivation
- `INV-MEM-001`: no out-of-bounds memory access in modeled transitions
- `INV-WX-001`: no reachable RWX page state
- `INV-CFI-001`: indirect control transfers target only allowed entry sets
- `INV-TMP-001`: temporal rollback and merge preserve object consistency invariants
- `INV-PER-001`: persisted temporal decode rejects integrity-inconsistent payloads
- `INV-NET-001`: CapNet acceptance requires integrity + freshness + rights attenuation
- `INV-PRIV-001`: user/kernel privilege transitions preserve control-return integrity

These can be summarized as a safety conjunction:

\[
Inv^\* =
Inv_{cap}
\land Inv_{mem}
\land Inv_{wx}
\land Inv_{cfi}
\land Inv_{tmp}
\land Inv_{per}
\land Inv_{net}
\land Inv_{priv}
\]

The theorem index under [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md) binds each invariant to a theorem record and a proof artifact.

The full verification target matrix — claim tiers T0–T5, Programs A–L, staged milestones, and the defensible whole-system definition — lives in [proof/VERIFICATION_TARGET_MATRIX.md](./proof/VERIFICATION_TARGET_MATRIX.md).

---

## 6. Theorem Inventory

The current theorem inventory is maintained in [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md). The live set includes:

| Theorem | Invariant | Theory | Main implementation surface |
|---|---|---|---|
| `THM-CAP-001` | `INV-CAP-001` | [`ipc_flow.v`](./theories/ipc_flow.v) | capability provenance / derivation |
| `THM-MEM-001` | `INV-MEM-001` | [`memory_isolation.v`](./theories/memory_isolation.v) | allocator + sandbox isolation |
| `THM-WX-001` | `INV-WX-001` | [`wx_cfi.v`](./theories/wx_cfi.v) | JIT write/execute separation |
| `THM-CFI-001` | `INV-CFI-001` | [`wx_cfi.v`](./theories/wx_cfi.v) | valid indirect JIT targets |
| `THM-TMP-001` | `INV-TMP-001` | [`temporal_logic.v`](./theories/temporal_logic.v) | temporal monotonicity / merge bounds |
| `THM-PER-001` | `INV-PER-001` | [`persistence.v`](./theories/persistence.v) | write/read crash-recovery roundtrip |
| `THM-NET-001` | `INV-NET-001` | [`capnet_integrity.v`](./theories/capnet_integrity.v) | CapNet forwarding validity |
| `THM-PRIV-001` | `INV-PRIV-001` | [`privilege_safety.v`](./theories/privilege_safety.v) | ring transition safety |

Two additional compiled theory surfaces are also present:

- [`lock_dag.v`](./theories/lock_dag.v)
- [`scheduler_entropy.v`](./theories/scheduler_entropy.v)

These matter because they extend the proof surface into scheduler and lock-order reasoning, even when a README-level summary focuses on the mandatory baseline theorem IDs.

---

## 7. Core Equational View

Oreulius’s verification story can be read as a family of preservation and exclusion statements.

### 7.1 Capability provenance

Let \( Auth(p, c) \) mean process \( p \) lawfully holds capability \( c \). Then:

\[
Auth(p, c) \implies OriginatesInKernel(c) \lor DerivedFromKernelGranted(c)
\]

Corollary:

\[
\neg KernelGrant(c) \land \neg KernelDerive(c) \implies \neg ReachableCapability(c)
\]

### 7.2 Memory isolation

Let \( Region(p) \) be the set of memory intervals granted to process \( p \). Then:

\[
Alloc(p, a, n) \implies [a, a+n) \subseteq Region(p)
\]

and for distinct live processes \( p \neq q \):

\[
[a_p, a_p+n_p) \cap [a_q, a_q+n_q) = \varnothing
\]

### 7.3 W^X

For every reachable page-table state and page \( x \):

\[
Writable(x) \implies \neg Executable(x)
\]

Equivalently:

\[
\forall x.\; \neg (W(x) \land X(x))
\]

### 7.4 JIT control-flow integrity

Let \( Target(j) \) be an indirect branch target in JIT code and \( EntrySet \) the function-table entry set. Then:

\[
Target(j) \in EntrySet
\]

and:

\[
Target(j) \notin MidInstructionAddressSpace
\]

### 7.5 Temporal monotonicity

For a snapshot chain \( s_0, s_1, \dots, s_n \) with logical timestamps \( \tau(s_i) \):

\[
\tau(s_i) \le \tau(s_{i+1})
\]

and for merge:

\[
\tau(merge(a,b)) \ge \max(\tau(a), \tau(b))
\]

### 7.6 Persistence roundtrip

If `encode` and `decode` are the persistence codec maps:

\[
decode(encode(x)) = x
\]

for all states \( x \) admitted by the persistence model.

### 7.7 CapNet integrity

For peers \( P_1, P_2 \) and forwarding capability \( fc \):

\[
Send(P_1, P_2, m) \implies Valid(fc) \land Fresh(fc) \land Attenuated(fc)
\]

and after revocation:

\[
Revoked(fc) \implies \neg Valid(fc)
\]

### 7.8 Privilege safety

Let \( ring(k) \in \{0,3\} \) be the current privilege ring of CPU state \( k \). Then:

\[
ring(step(k,t)) = 0 \implies ViaSyscallGate(t)
\]

This is the critical exclusion form:

\[
\neg ViaSyscallGate(t) \implies ring(step(k,t)) \neq 0
\]

---

## 8. Lemmas and Corollaries Maintainers Should Care About

This section is operational, not merely formal.

### Lemma 8.1: Structural presence is a proof precondition

If a theorem ID, invariant ID, or manifest key disappears, the release no longer has traceable proof coverage.

Operationalization:

- `proof_check.sh` must pass
- theorem IDs must still appear in [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md)
- invariant IDs must still appear in [spec/INVARIANTS.md](./spec/INVARIANTS.md)

### Lemma 8.2: A compiled `.vo` file is necessary but not sufficient

Compiled proof artifacts prove that the theorem script type-checks. They do not, by themselves, prove that the implementation still matches the model.

Therefore:

\[
CompiledTheory \not\Rightarrow Correspondence
\]

You still need [mapping/CODE_MODEL_TRACE.md](./mapping/CODE_MODEL_TRACE.md) and runtime evidence.

### Lemma 8.3: Runtime evidence is evidence of conformance, not a substitute for proof

Self-tests and fuzzing can falsify an implementation claim, but they cannot establish the universal closure that a mechanized theorem is asserting.

So the valid relationship is:

\[
Proof \land Mapping \land RuntimeEvidence
\]

not:

\[
RuntimeEvidence \Rightarrow Proof
\]

### Corollary 8.4: Every verified subsystem change has three obligations

If you change a verified subsystem, you must inspect:

1. the theorem record
2. the code-to-model mapping
3. the runtime evidence path

If any of the three drift, the verification claim is stale even if CI still compiles.

---

## 9. How To Run Verification

### 9.1 Quick structural gate

From repo root:

```bash
bash verification/scripts/proof_check.sh
```

What it checks:

- required files are present
- mandatory invariant IDs exist
- mandatory theorem IDs exist
- assumption and correspondence tags exist
- manifest schema contains required keys
- theorem status labels are valid

Expected result:

```text
proof_check: baseline structure present
```

### 9.2 Full runbook status

```bash
bash verification/scripts/formal-verification-runbook.sh status
bash verification/scripts/formal-verification-runbook.sh check
bash verification/scripts/formal-verification-runbook.sh check --strict
```

Use `status` when auditing.

Use `check --strict` before release or when reviewing proof-sensitive changes.

### 9.3 Compile all mechanized theories

From repo root:

```bash
cd verification/theories
coqc ipc_flow.v
coqc temporal_logic.v
coqc wx_cfi.v
coqc lock_dag.v
coqc scheduler_entropy.v
coqc memory_isolation.v
coqc persistence.v
coqc capnet_integrity.v
coqc privilege_safety.v
```

Or, more compactly:

```bash
for f in verification/theories/*.v; do
  coqc "$f"
done
```

Expected result:

- exit code `0`
- fresh `.vo`, `.vos`, and `.vok` artifacts alongside each `.v`

### 9.4 Runtime verification gate

```bash
bash kernel/formal-verify.sh
```

This is the runtime side of the story. It complements, but does not replace, Coq compilation.

### 9.5 Runtime self-check surfaces

Examples of live evidence surfaces:

```bash
# shell-driven temporal hardening path
temporal-hardening-selftest

# kernel-side formalized capability checks
# wired through kernel boot or shell self-check paths depending on subsystem
```

### 9.6 CI evidence surfaces

Relevant workflow surfaces include:

- [verification/ci/proof-check.yml](./ci/proof-check.yml)
- `.github/workflows/proof-check.yml`
- `.github/workflows/capnet-regression.yml`
- the kernel runtime/fuzz lanes referenced from [artifacts/runtime_evidence.md](./artifacts/runtime_evidence.md)

---

## 10. Toolchain and Environment

Canonical environment details live in:

- [ENVIRONMENT.md](./ENVIRONMENT.md)
- [DECISION.md](./DECISION.md)

Current accepted toolchain:

- Coq / Rocq Prover `9.1.1`
- Ubuntu-compatible fallback: Coq `8.19.x`
- OCaml `5.4.0` on the Homebrew Rocq path

macOS bootstrap:

```bash
brew install coq
coqc --version
```

Ubuntu bootstrap:

```bash
sudo apt-get update -qq
sudo apt-get install -y coq
coqc --version
```

If exact `9.1.1` is required:

```bash
sudo add-apt-repository ppa:rocq-prover/rocq -y
sudo apt-get update -qq
sudo apt-get install -y rocq
coqc --version
```

---

## 11. How To Read Evidence

### Mechanized evidence

Authoritative mechanized evidence is:

- the `.v` source file
- the compiled `.vo` artifact
- the matching theorem record in [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md)

### Runtime evidence

Authoritative runtime evidence is tracked in [artifacts/runtime_evidence.md](./artifacts/runtime_evidence.md).

Examples:

- `temporal-hardening-selftest`
- `capnet-fuzz-corpus`
- `wasm-jit-fuzz-corpus`

### Manifest evidence

The manifest files under [artifacts/](./artifacts) exist to make the evidence machine-readable:

- [artifacts/manifest.json](./artifacts/manifest.json)
- [artifacts/manifest.schema.json](./artifacts/manifest.schema.json)

These should be updated when theorem status, commits, or runtime evidence pointers materially change.

---

## 12. Code-to-Model Correspondence

The most dangerous failure mode is not a false theorem. It is a true theorem about the wrong model.

That is why [mapping/CODE_MODEL_TRACE.md](./mapping/CODE_MODEL_TRACE.md) matters.

The three main correspondence obligations are:

- `CO-SYNTAX-001`: model-visible runtime structures should be annotated and cross-referenceable
- `CO-SEM-001`: theorem-visible types must correspond to runtime types actually used in the code path
- `CO-BOUNDARY-001`: trust boundary crossings must have either a proof lemma, an axiom, or an explicit out-of-scope declaration

In practical review terms:

- if you refactor a verified structure, update the mapping
- if you introduce a new trust boundary, add a correspondence note or an assumption
- if you widen a subsystem beyond the current theory, the theorem coverage becomes partial until the theory is extended

---

## 13. What Is and Is Not Claimed

### Claimed

Oreulius claims that the theorem set in [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md) is mechanized for the corresponding theory files and that the assumptions and boundaries are documented. All current theorems are **T2 (Model Proven)** — proven over abstract models; code-to-model refinement is an open obligation. See [proof/VERIFICATION_TARGET_MATRIX.md](./proof/VERIFICATION_TARGET_MATRIX.md) for the full tier definitions and what each stage of verification requires.

### Not claimed

Oreulius does not claim:

- full-system functional correctness
- total correspondence between all Rust code and all proof models
- proof coverage for every device-driver path
- proof coverage for DMA, speculative execution, cache timing, or physical fault injection
- automatic extension of theorem coverage to new subsystems without new theory work

Formally:

\[
ProofCoverage \subset KernelBehavior
\]

not:

\[
ProofCoverage = KernelBehavior
\]

---

## 14. Reviewer Checklist

When reviewing a proof-sensitive change, ask:

1. Which theorem IDs are affected?
2. Which invariant IDs are affected?
3. Which implementation files named in the theorem record changed?
4. Does [mapping/CODE_MODEL_TRACE.md](./mapping/CODE_MODEL_TRACE.md) still describe the runtime/model relationship honestly?
5. Do the relevant `.v` files still compile?
6. Does the runtime evidence path still exist and still exercise the same class of property?
7. Does the manifest or theorem index need a `Last Verified Commit` update?

If the answer to any of those is unclear, the change should not be described as verification-neutral.

---

## 15. Common Commands

From repo root:

```bash
# Structural gate
bash verification/scripts/proof_check.sh

# Run the runbook
bash verification/scripts/formal-verification-runbook.sh status
bash verification/scripts/formal-verification-runbook.sh check --strict

# Compile all theories
for f in verification/theories/*.v; do coqc "$f"; done

# Runtime verification gate
bash kernel/formal-verify.sh

# Inspect theorem status
sed -n '1,220p' verification/proof/THEOREM_INDEX.md

# Inspect assumptions
sed -n '1,220p' verification/spec/ASSUMPTIONS.md

# Inspect mapping obligations
sed -n '1,220p' verification/mapping/CODE_MODEL_TRACE.md
```

---

## 16. Deep Links

- [DECISION.md](./DECISION.md)
- [ENVIRONMENT.md](./ENVIRONMENT.md)
- [BOOTSTRAP_NOTES.md](./BOOTSTRAP_NOTES.md)
- [spec/INVARIANTS.md](./spec/INVARIANTS.md)
- [spec/ASSUMPTIONS.md](./spec/ASSUMPTIONS.md)
- [spec/THREAT_MODEL.md](./spec/THREAT_MODEL.md)
- [proof/THEOREM_INDEX.md](./proof/THEOREM_INDEX.md)
- [mapping/CODE_MODEL_TRACE.md](./mapping/CODE_MODEL_TRACE.md)
- [artifacts/runtime_evidence.md](./artifacts/runtime_evidence.md)
- [scripts/formal-verification-runbook.sh](./scripts/formal-verification-runbook.sh)
- [scripts/proof_check.sh](./scripts/proof_check.sh)

---

## 17. Current Bottom Line

Oreulius already has a real verification workspace:

- named invariants
- named theorem records
- mechanized proofs with compiled artifacts
- runtime evidence records
- structural CI enforcement

The correct technical claim is not "fully verified kernel." The correct claim is:

\[
VerifiedSubset(Kernel) \neq \varnothing
\]

and the subset is explicit, reproducible, assumption-scoped, and reviewable from this directory.
