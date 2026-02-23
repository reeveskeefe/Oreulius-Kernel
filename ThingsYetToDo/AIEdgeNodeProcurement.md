# Oreulia AI Edge Node Procurement Playbook v2

Status: Draft (Normative)  
Owner: Product + Kernel + Security Leads  
Primary objective: Win AI edge-node procurement using measurable security, reliability, and economic outcomes.

---

## 1. Scope and Decision Rule

This playbook governs adoption of Oreulia for the wedge use case:

- secure execution substrate for untrusted AI-side modules (WASM/plugin logic) on edge nodes.

This is not a host-OS replacement play in phase 1.

### 1.1 Global Decision Function

A phase decision is `PASS` only if:

`PASS = (All_Mandatory_Gates = true) AND (Critical_Findings = 0) AND (Evidence_Package = complete)`

If false, decision is `NO-GO`.

---

## 2. Target Buyer Profile

Primary buyers:

- frontier AI labs with untrusted tool/plugin execution paths,
- AI hardware teams shipping thin-client/edge control nodes,
- enterprise AI platform teams needing auditable runtime isolation.

Buyer priorities this playbook optimizes:

- containment and authority minimization,
- deterministic replay and incident forensics,
- fleet-safe update and rollback,
- bounded operational overhead and support certainty.

---

## 3. Procurement Paths

Use one of two paths at kickoff.

## 3.1 Fast Path (Design Partner / Lab)

- expected duration: 8-16 weeks,
- streamlined security review,
- narrow deployment scope.

## 3.2 Enterprise Path (Procurement + Governance)

- expected duration: 16-36 weeks,
- full security/compliance/legal review,
- formal support/SLA negotiation and vendor risk review.

Path selection MUST be documented in `PROCUREMENT_PATH.md`.

---

## 4. Wedge Integration Contract (Mandatory)

Before technical qualification, produce a one-page integration contract defining:

- host environment boundary (Oreulia component placement),
- API surface (input/output contracts),
- observability hooks (logs, metrics, trace IDs),
- failure containment behavior,
- rollback trigger and rollback owner.

If any field is undefined, phase 0 fails.

---

## 5. Procurement Phases and Strict Gates

## Phase 0: Fit Screening

Objective:

- confirm buyer-workload fit and pilot viability.

Required inputs:

- workload profile,
- security constraints,
- latency/reliability SLOs,
- deployment topology,
- procurement path selection (fast/enterprise).

Mandatory gate checks:

- scoped wedge accepted by buyer owner,
- written success criteria signed by technical and product stakeholders,
- controlled pilot environment available.

Hard disqualifiers:

- requirement for full host-OS replacement in initial pilot,
- missing measurable success criteria,
- no rollback-safe environment.

## Phase 1: Technical Qualification Packet

Objective:

- provide buyer with decision-grade technical package for lab entry.

Required deliverables:

- architecture brief (trust boundaries + attack surface),
- threat model + assumptions + non-goals,
- verification evidence pack (formal/runtime/fuzz summaries),
- integration contract from Section 4,
- benchmark plan with baseline methodology.

Gate:

- buyer security owner + platform owner sign lab test plan.

## Phase 2: Controlled Lab Evaluation

Objective:

- reproduce claims under buyer-observed conditions.

Required test suites:

1. isolation and authority tests,
2. deterministic replay tests,
3. fault/rollback drills,
4. overhead and stability benchmarks,
5. update failure and recovery drills.

Gate:

- all mandatory tests pass,
- KPI thresholds in Section 6 pass,
- zero unresolved critical findings.

## Phase 3: Narrow Production Pilot

Objective:

- validate production behavior under bounded real workload.

Scope constraints:

- single workload lane,
- staged traffic or bounded node set,
- explicit rollback ownership and trigger policy.

Gate:

- KPIs hold for pilot window,
- incident/rollback tabletop and live drills pass,
- buyer operational readiness checklist signed.

## Phase 4: Security and Compliance Review

Objective:

- satisfy buyer governance and control requirements.

Required artifacts listed in Section 7 MUST be complete.

Gate:

- zero blocker findings after review disposition.

## Phase 5: Commercial and Support Finalization

Objective:

- convert successful pilot into contractual deployment.

Contract MUST define:

- support SLA,
- patch and release cadence,
- escalation and incident response timelines,
- supported versions and deprecation windows,
- evidence-retention obligations.

Gate:

- executed agreement with explicit service boundaries.

## Phase 6: Controlled Rollout

Objective:

- expand deployment without losing evidence discipline.

Gate per rollout wave:

- wave KPI pass,
- no unresolved critical regressions,
- evidence package refreshed.

---

## 6. KPI Contract (Default Thresholds + Measurement Protocol)

Thresholds below are defaults. If buyer overrides, override values must be signed before phase 2.

| KPI | Metric Definition | Default Threshold | Minimum Sample Requirement | Measurement Method |
|---|---|---|---|---|
| Isolation integrity | unauthorized cross-module access attempts blocked | 100% blocked | >= 10,000 adversarial attempts | capability audit logs + adversarial harness |
| Replay determinism | identical traces reproduce identical outputs | >= 99.99% | >= 100,000 replay runs | deterministic replay suite |
| Recovery time (RTO) | time to restore known-good state | <= 60s | >= 100 rollback drills | rollback drill timing |
| Update rollback success | failed update recovers safely | 100% | >= 500 failure-injection updates | OTA simulation + recovery logs |
| Stability | crash-free operation under soak | >= 168h no critical crash | >= 3 independent runs | soak runs + incident logs |
| Overhead (p95 latency) | p95 latency delta vs baseline | <= 10% | >= 1M requests | side-by-side benchmark |
| Overhead (CPU) | CPU overhead vs baseline | <= 15% | >= 1M requests | perf telemetry |

### 6.1 Confidence and Repeatability Requirements

- Each KPI run MUST include three independent repetitions.
- Reported value MUST include run median and worst-case.
- Any run-to-run variance > 10% requires rerun and root-cause note.

---

## 7. Security and Compliance Artifact Matrix (Mandatory)

All rows are required for phase 4 pass.

| Artifact | Minimum Contents |
|---|---|
| Threat model | attacker classes, trust boundaries, assumptions, non-goals |
| Security architecture | control map, data-flow boundaries, privilege transitions |
| SBOM | component inventory with version pinning and generation method |
| Vulnerability policy | intake, severity taxonomy, fix SLAs, disclosure path |
| Release gate policy | mandatory verification/fuzz/soak checks before release |
| Signing and key policy | signing chain, key custody, rotation, revocation |
| Evidence retention policy | test artifacts, audit retention window, integrity controls |
| Incident response runbook | detection, triage, containment, rollback, postmortem process |
| Compliance mapping | control mapping to buyer-required framework (SOC2/ISO/NIST/etc.) |

If any artifact is missing or stale, phase 4 fails.

---

## 8. Economic Decision Package (Mandatory for Procurement)

Technical pass is insufficient without economic viability.

Required economic fields:

- baseline cost model (current stack),
- Oreulia integration and migration cost,
- run-cost delta (compute/ops/support),
- risk-reduction value hypothesis,
- payback period estimate.

Default decision thresholds:

- payback period <= 12 months,
- no unbounded support liability,
- migration risk classified as manageable by buyer.

If economic package is incomplete, phase 5 cannot pass.

---

## 9. Reproducibility Contract (Evidence Quality Bar)

Every evidence package MUST include:

- commit SHA and build identifiers,
- pinned environment and tool versions,
- benchmark/replay scripts,
- dataset or trace hashes,
- seed values and run configs,
- raw outputs and summary outputs,
- rerun instructions.

No evidence without rerun path is admissible.

---

## 10. Failure and Pause Conditions

Procurement pauses immediately on:

- reproducible isolation break,
- deterministic replay failure above threshold,
- rollback failure in mandatory drill,
- unverifiable release claim,
- unresolved critical security finding.

Resume requires:

- root cause analysis,
- fix and regression evidence,
- full gate rerun for affected phase.

---

## 11. RACI (Internal + Buyer Counterparts)

| Workstream | Responsible (Vendor) | Accountable (Vendor) | Buyer Counterpart Owner |
|---|---|---|---|
| Kernel hardening | Kernel lead | CTO/Founder | Platform engineering owner |
| Verification evidence | Verification lead | CTO/Founder | Security architecture owner |
| Benchmarking | Performance lead | Product lead | Perf/SRE owner |
| Security review response | Security lead | CTO/Founder | Security review owner |
| Commercial package | Product lead | Founder | Procurement/legal owner |

If buyer counterpart owner is undefined, phase gate cannot close.

---

## 12. 90-Day Readiness Plan

1. Weeks 1-2: lock wedge scope, integration contract template, KPI defaults.
2. Weeks 3-4: build reproducible evidence pipeline and scripts.
3. Weeks 5-7: close highest-risk reliability/security blockers.
4. Weeks 8-9: run red-team, rollback, and soak campaigns.
5. Weeks 10-11: produce qualification packet and buyer lab scripts.
6. Weeks 12-13: initiate first external controlled lab evaluation.

---

## 13. Claim Language Policy

Allowed claim examples:

- "Qualified for pilot in defined scope with measured KPI results at commit `<sha>`."
- "Verification and fuzz evidence available for listed runs and seeds."

Forbidden claim examples:

- "Production-ready for all AI workloads."
- "Provably secure in all contexts."
- "Drop-in replacement for all Linux edge stacks."

Every external claim MUST cite:

- scope boundary,
- KPI run IDs,
- commit SHA,
- assumption set version.

---

## 14. Procurement-Ready Definition of Done

Oreulia is procurement-ready for AI edge-node wedge deployment only if:

- phases 0-3 passed with signed gates,
- phase 4 blocker count is zero,
- phase 5 contract/SLA terms are executed,
- reproducibility contract is satisfied,
- economic package meets decision thresholds,
- claim language is bounded to proven/measured scope.

Otherwise status is:

- `NOT PROCUREMENT-READY`.

---

## 15. Operator Checklist

- [ ] Procurement path selected and documented.
- [ ] Integration contract complete.
- [ ] KPI thresholds signed before phase 2.
- [ ] Security/compliance artifact matrix complete.
- [ ] Economic decision package complete.
- [ ] Reproducibility contract satisfied.
- [ ] All mandatory gates signed with evidence links.
- [ ] Claim language reviewed for scope correctness.

---

## 16. Post-Procurement Execution Plan

Once status is `PROCUREMENT-READY`, execute this sequence:

1. Run 2-3 paid pilots in parallel (avoid single-customer concentration risk).
2. Convert at least 1 pilot to an annual production contract.
3. Publish one evidence-backed case study (with buyer approval).
4. Use case-study evidence to tighten terms and increase pricing on subsequent contracts.
5. Maintain quarterly evidence refresh (verification/fuzz/benchmark pack) for renewals.

### 16.1 Conversion Targets (Default)

- Pilot -> annual conversion target: >= 40%
- Time from pilot start to production contract: <= 120 days
- Referenceable deployment target: >= 1 within first 2 production wins

---

## 17. Commercial Packaging and Pricing (Realistic Starting Bands)

These are starting bands for early commercial deployment and should be adjusted based on scope, support load, and buyer criticality.

### 17.1 Paid Pilot (6-10 weeks)

- Target price band: **$50k-$150k**
- Recommended default anchor: **$75k**
- Minimum acceptable floor (without strategic concessions): **$30k**

Pilot should include:

- bounded workload scope,
- success criteria tied to Section 6 KPIs,
- explicit conversion decision date,
- defined handoff artifacts and evidence package.

### 17.2 Production Starter (Annual)

- Target price band: **$250k-$600k/year**
- Suitable for first production deployment with bounded footprint.

### 17.3 Enterprise Production (Annual)

- Target price band: **$600k-$1.5M+/year**
- For larger deployment scope, stricter SLA, and higher support obligations.

### 17.4 Premium Support Add-On

- Add-on range: **15-25%** of annual contract value
- Includes accelerated response, escalation priority, and higher-touch operational support.

### 17.5 Discount Guardrails

Discount below pilot floor (`$30k`) is allowed only when at least one strategic concession is contractually secured:

- public case study rights,
- logo/reference rights,
- deep integration access that materially improves product readiness,
- multi-phase expansion commitment.

If none apply, deal should be treated as `NO-GO`.

---

## 18. Revenue and Traction Milestones

Default early milestones:

- Milestone A: first paid pilot closed.
- Milestone B: three paid pilots closed.
- Milestone C: first annual production contract signed.
- Milestone D: second production contract signed + first case study published.

These milestones are used to decide when to increase pricing and narrow discount allowances.

---

## 19. Outreach Plan (Execution Layer)

This section defines who to contact, in what order, through which channels, and with what message format.

## 19.1 Target Roles (Priority Order)

Contact in this order:

1. AI platform/inference runtime engineering managers.
2. Staff/principal engineers in runtime/systems.
3. Security architecture leads (sandboxing/isolation).
4. Fleet/edge reliability leads (rollout and rollback owners).
5. Procurement/vendor-risk leads after technical champion alignment.

Do not start with executive outreach before technical owners engage.

## 19.2 Channel Order (Best to Worst)

1. Warm intro from mutual founder/investor/engineer.
2. Direct technical email to manager + senior individual contributor.
3. LinkedIn follow-up 2-3 business days later.
4. Conference/meetup follow-up with the same evidence packet.
5. Broad cold outreach only after targeted list is complete.

## 19.3 Contact Cadence

Per target contact:

- Day 0: initial technical email.
- Day 3-4: concise follow-up with one new artifact (benchmark, replay evidence, or pilot one-pager).
- Day 8-10: final follow-up with explicit close ("should we park this for now?").

Stop after three touches unless there is engagement.

## 19.4 Funnel Targets (Planning Assumptions)

Use these baseline planning numbers:

- cold reply rate: 2-8%,
- warm-intro reply rate: 25-50%,
- first call to pilot conversion: 10-20%.

Working target:

- 15-30 qualified technical contacts per campaign wave.

## 19.5 Mandatory Outreach Packet

Every outbound message MUST include:

- wedge statement (one sentence),
- three measurable metrics (from Section 6),
- one reproducible artifact link,
- one-page pilot brief,
- explicit call-to-action for a 20-minute technical qualification call.

No outreach without measurable evidence attached.

## 19.6 First Message Template (Short Form)

Subject:

`Scoped pilot: secure untrusted AI module execution on edge nodes`

Body:

`Hi <Name>,`

`We are proposing a narrowly scoped pilot for untrusted AI-side module execution on edge nodes, focused on isolation, replay determinism, and rollback reliability.`

`Current measured defaults:`  
`- Isolation integrity: 100% block in adversarial corpus`  
`- Replay determinism: >= 99.99%`  
`- Rollback RTO target: <= 60s`

`If useful, we can share a reproducible technical packet and run a 20-minute qualification call to define a 6-10 week paid pilot with explicit KPI gates.`

`Best,`  
`<Name>`

## 19.7 xAI-Specific Application

For xAI, prioritize contacts in:

- inference/runtime platform engineering,
- security engineering for execution isolation,
- infrastructure reliability for deployment/rollback.

Primary ask remains:

- 20-minute technical qualification call for a scoped pilot, not a broad OS replacement discussion.

---

## 20. Outreach Readiness Checklist

- [ ] Contact list of 15-30 qualified technical owners prepared.
- [ ] At least one warm-intro path identified.
- [ ] Outreach packet includes wedge + metrics + reproducible artifact + pilot brief.
- [ ] Message template customized per recipient team context.
- [ ] Follow-up cadence calendar prepared.
- [ ] Conversion tracking sheet prepared (reply/call/pilot status).
