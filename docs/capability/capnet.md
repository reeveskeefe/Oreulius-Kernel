# CapNet: Scientific Resolution and Formal Systems Analysis

## Abstract

CapNet is Oreulius's kernel-level capability-token network protocol for decentralized authority transfer across devices. It generalizes local capability semantics into authenticated, replay-safe, attenuation-preserving, revocable network tokens, while preserving in-kernel enforcement and auditability. This document is the post-implementation scientific record for CapNet. It replaces planning artifacts with a formalized model of the protocol, the security invariants it enforces, the implementation mechanics in the kernel, and the verification pipeline used to gate regressions.

The completed system combines: fixed-format token serialization, keyed MAC integrity, attestation-derived per-peer session keys, control-channel replay windows, rights-monotone delegation chains, persistent revocation tombstones with epoch ordering, local capability-table bridging, and deterministic corpus replay under CI. The result is a bounded, fail-closed, auditable control plane that behaves as an "OAuth-like authority fabric for devices," but with kernel-enforced object/type/rights semantics and without ambient authority.

---

## 1. Introduction

### 1.1 Problem

Classical distributed authority models centralize trust in identity providers, ACL stores, or coarse service-role assumptions. Kernel capability systems solve ambient authority locally, but do not natively define portable, cryptographically constrained delegation objects for inter-device transfer.

CapNet addresses this by introducing a kernel-native portable capability token with explicit authority semantics:

- issuer and subject identity,
- object and type binding,
- rights mask,
- temporal validity window,
- delegation lineage,
- optional bounded-use and quota constraints,
- measurement/session binding for attested channels.

### 1.2 Design Goals

The implementation was constrained by the following objectives:

1. Preserve Oreulius's local capability attenuation law under network delegation.
2. Prevent forged or replayed token acceptance in the control channel.
3. Ensure revocation survives reboot and dominates all acceptance/use paths.
4. Keep parser and verifier fail-closed under malformed inputs.
5. Support deterministic in-kernel verification and reproducible CI gating.
6. Maintain bounded memory and predictable runtime behavior.

### 1.3 Scope

This document covers CapNet as implemented in:

- `kernel/src/capnet.rs`
- `kernel/src/capability.rs`
- `kernel/src/netstack.rs`
- `kernel/src/net_reactor.rs`
- `kernel/src/enclave.rs`
- `kernel/src/commands.rs`
- `kernel/fuzz/*`
- `.github/workflows/capnet-regression.yml`

---

## 2. System Model

Let global kernel state be:

\[
\Sigma = (K, P, L, D, R, N, A)
\tag{2.1}
\]

where:

- \(K\): key material (boot key and peer session keys),
- \(P\): peer-session table state,
- \(L\): remote capability lease table,
- \(D\): delegation record table,
- \(R\): revocation tombstone set and epoch counter,
- \(N\): network control-channel state (seq/ack/retransmit),
- \(A\): audit/anomaly observability state.

Let a token be:

\[
\tau = (\text{issuer}, \text{subject}, \text{cap\_type}, \text{object}, \text{rights},
\text{flags}, \text{issued}, \text{not\_before}, \text{expires},
\text{nonce}, \text{depth}, \text{parent}, \text{measurement},
\text{session}, \text{context}, \text{budgets}, \text{mac})
\tag{2.2}
\]

where budgets represent \((\text{max\_uses}, \text{max\_bytes}, \text{resource\_quota})\).

### 2.1 Transition Families

CapNet state evolution is modeled with transitions:

\[
T = T_{\text{peer}} \cup T_{\text{session}} \cup T_{\text{offer}} \cup T_{\text{accept}} \cup
T_{\text{revoke}} \cup T_{\text{lease-use}} \cup T_{\text{rebuild}}
\tag{2.3}
\]

where:

- \(T_{\text{peer}}\): peer registration/policy updates,
- \(T_{\text{session}}\): key epoch installation/rotation,
- \(T_{\text{offer}}\): incoming token-offer verification and lease install,
- \(T_{\text{accept}}\): accept acknowledgment semantics,
- \(T_{\text{revoke}}\): transitive revocation application and journaling,
- \(T_{\text{lease-use}}\): runtime capability-use checks,
- \(T_{\text{rebuild}}\): persistent journal replay at init.

---

## 3. Threat Model

### 3.1 In Scope

- Forged control frames and forged tokens.
- Sequence and nonce replay attacks.
- Delegation escalation attacks (rights/type/object/temporal/constraint violations).
- Use-after-revocation attempts.
- Malformed frame/token parser abuse.
- Reboot-window revocation bypass attempts.

### 3.2 Out of Scope

- Physical compromise of trusted endpoints.
- Full byzantine multi-party consensus.
- Side-channel completeness beyond constant-time comparison and bounded-state behavior.
- Post-quantum cryptographic claims.

---

## 4. Data Structures and Serialization

### 4.1 Token Layout

`CapabilityTokenV1` is a fixed-width binary object of 116 bytes:

\[
|\tau| = 116
\tag{4.1}
\]

with body length:

\[
|\tau_{\text{body}}| = 108
\tag{4.2}
\]

The final 8 bytes are MAC, while the body includes all semantic fields. Fixed-width layout eliminates variable-length parser ambiguity and bounds copy/verification costs.

### 4.2 Canonical Token Identifier

Token ID is deterministic over the body only:

\[
\text{token\_id}(\tau) = \operatorname{FNV1a64}(\tau_{\text{body}})
\tag{4.3}
\]

Excluding MAC from ID guarantees stable identity across re-signing under key rotation.

### 4.3 Control Frame Layout

CapNet control frames use a bounded header + bounded payload:

\[
|f| \leq |\text{header}| + |\text{payload}_{\max}|
\tag{4.4}
\]

with payload upper bound tied to token size.

Message types:

- `HELLO`
- `ATTEST`
- `TOKEN_OFFER`
- `TOKEN_ACCEPT`
- `TOKEN_REVOKE`
- `HEARTBEAT`

---

## 5. Cryptographic Construction

### 5.1 MAC Integrity

For key \(k\) and message \(m\):

\[
\operatorname{MAC}(k,m) = \operatorname{SipHash}_{k}(m)
\tag{5.1}
\]

Token validity requires:

\[
\operatorname{Verify}(k,m,\sigma) \iff \operatorname{MAC}(k,m)=\sigma
\tag{5.2}
\]

where \(m=\tau_{\text{body}}\), \(\sigma=\tau_{\text{mac}}\).

### 5.2 Key Domains

CapNet uses two key domains:

- boot-local key for local diagnostics paths,
- per-peer session keys for network control and token exchange.

Per-peer session keys are installed from attestation exchange outputs and tracked with key epochs. Frame validation enforces epoch equality between peer session state and incoming frame.

### 5.3 Forgery Bound

Under PRF assumptions for SipHash:

\[
\Pr[\text{single-shot forge}] \le 2^{-64}
\tag{5.3}
\]

and with \(q\) adaptive attempts:

\[
\Pr[\text{forge in } q \text{ tries}] \le \frac{q}{2^{64}}
\tag{5.4}
\]

This bound is practical for kernel control-plane authentication under bounded-rate inputs and anomaly/rate logging.

---

## 6. Replay, Sequence, and Freshness Semantics

### 6.1 Nonce Window for Tokens

Each peer tracks:

- \(h_n\): highest accepted nonce,
- \(B_n\): 64-bit bitmap for recently accepted nonces.

Acceptance rule:

1. If \(n > h_n\): shift bitmap by \(n-h_n\), set LSB, set \(h_n=n\).
2. Else if \(h_n-n \ge 64\): reject.
3. Else if bit \((h_n-n)\) is set: reject.
4. Else set bit and accept.

This defines:

\[
\operatorname{FreshNonce}(n,P)=\text{true} \iff n \notin W(P) \land n \in \text{window}(P)
\tag{6.1}
\]

### 6.2 Sequence Window for Control Frames

Control frames apply the same high-watermark/bitmap mechanism to `seq`, giving deterministic replay rejection for duplicated or stale frames.

\[
\operatorname{FreshSeq}(s,P)=\text{true} \iff s \notin S(P) \land s \in \text{seq-window}(P)
\tag{6.2}
\]

---

## 7. Delegation Algebra

### 7.1 Rights Lattice

Let rights be bitmasks in lattice \((\mathcal{R}, \subseteq)\) where:

\[
R_a \subseteq R_b \iff (R_a \wedge \neg R_b)=0
\tag{7.1}
\]

Delegation attenuation requirement:

\[
R_c \subseteq R_p
\tag{7.2}
\]

### 7.2 Chain Consistency Conditions

For child token \(\tau_c\) and parent token \(\tau_p\):

\[
\text{parent\_id}(\tau_c)=\text{id}(\tau_p)
\tag{7.3}
\]
\[
\text{depth}(\tau_c)=\text{depth}(\tau_p)+1
\tag{7.4}
\]
\[
\text{type}(\tau_c)=\text{type}(\tau_p)
\tag{7.5}
\]
\[
\text{object}(\tau_c)=\text{object}(\tau_p)
\tag{7.6}
\]
\[
R(\tau_c)\subseteq R(\tau_p)
\tag{7.7}
\]
\[
[\text{not\_before}_c,\text{expires}_c] \subseteq [\text{not\_before}_p,\text{expires}_p]
\tag{7.8}
\]

Bounded-use and bounded-byte constraints are also monotone:

\[
\text{max\_uses}_c \le \text{max\_uses}_p
\tag{7.9}
\]
\[
\text{max\_bytes}_c \le \text{max\_bytes}_p
\tag{7.10}
\]

when corresponding constraint flags are enabled in parent.

### 7.3 Non-Escalation Theorem

Given Equations (7.3) to (7.10), any accepted descendant token cannot increase authority relative to its ancestor set.

\[
\forall \tau_i \in \text{Chain}(\tau_0): R(\tau_i)\subseteq R(\tau_0)
\tag{7.11}
\]

---

## 8. Revocation Semantics and Persistence

### 8.1 Tombstone Model

Define revocation tombstone set:

\[
\mathcal{T} = \{(\text{token\_id}, \text{issuer}, \text{epoch}, t_r)\}
\tag{8.1}
\]

Token acceptance requires:

\[
(\text{id}(\tau),\text{issuer}(\tau),*,*) \notin \mathcal{T}
\tag{8.2}
\]

### 8.2 Epoch Monotonicity

Revocation epochs satisfy:

\[
e_{n+1} = e_n + 1,\quad e_0 \ge 1
\tag{8.3}
\]

ensuring total order for local revocation events.

### 8.3 Transitive Revocation Closure

Let graph \(G=(V,E)\), vertices as accepted delegation records, edge \(u \to v\) if \(v.\text{parent}=u.\text{id}\). Revoking parent \(u\) revokes:

\[
\text{Closure}(u)=\{v \in V \mid u \leadsto v\}
\tag{8.4}
\]

All vertices in closure are tombstoned and mapped leases are revoked.

### 8.4 Reboot-Safe Rebuild

Revocation events are appended to persistence log and replayed at init:

\[
\mathcal{T}_{boot} = \operatorname{ReplayLog}(\text{capnet-revoke-records})
\tag{8.5}
\]

Therefore revocation denial survives reboot boundaries.

---

## 9. Acceptance Predicate

Incoming `TOKEN_OFFER` acceptance is equivalent to:

\[
\operatorname{Accept}(\tau,\Sigma,t) =
\operatorname{SemValid}(\tau) \land
\operatorname{TemporalValid}(\tau,t) \land
\operatorname{SubjectBind}(\tau,\Sigma) \land
\operatorname{PeerKnown}(\tau,\Sigma) \land
\operatorname{SessionEpochValid}(\tau,\Sigma) \land
\operatorname{MacValid}(\tau,\Sigma) \land
\operatorname{FreshNonce}(\tau,\Sigma) \land
\neg \operatorname{Revoked}(\tau,\Sigma) \land
\operatorname{DelegationValid}(\tau,\Sigma)
\tag{9.1}
\]

Only if Equation (9.1) holds is lease installation allowed.

### 9.1 Capability Bridge Mapping

Lease install is a mapping:

\[
\Phi:\tau \mapsto \lambda
\tag{9.2}
\]

where lease \(\lambda\) includes:

- token identity and issuer,
- cap type/object/rights,
- owner binding (`context==0` wildcard or PID-bound),
- temporal limits,
- use-budget status.

PID-bound leases materialize as concrete capability-table entries; wildcard leases remain in lease table fallback path.

---

## 10. Network Control-Plane Semantics

### 10.1 Frame Authentication

Control frame MAC is computed over canonical header-without-mac plus payload:

\[
\sigma_f = \operatorname{SipHash}_{k_{\text{peer}}}(f_{\text{canonical}})
\tag{10.1}
\]

Validation failure is fail-closed and logged as integrity violation.

### 10.2 ACK and Retransmit

CapNet uses bounded retransmit queue with:

- finite slots,
- fixed retry interval,
- fixed retry cap,
- ACK-driven dequeue.

This guarantees bounded memory and bounded retransmit work:

\[
\text{retransmit work} = O(Q_{\max})
\tag{10.2}
\]

with queue size \(Q_{\max}\) fixed at compile-time.

### 10.3 Determinism

Given fixed seed corpus and deterministic command path, replay outcomes are deterministic up to explicit randomized seed choice in fuzz mode.

---

## 11. Formal Verification Obligations

`formal-verify` includes CapNet obligations through `formal_capnet_self_check`, with mandatory pass/fail gating.

### 11.1 Obligations

1. **Attenuation monotonicity**:
   escalated child rights must be rejected.
2. **Temporal validity**:
   malformed intervals (`issued_at > not_before`) must fail.
3. **Replay safety**:
   duplicate control sequence must be rejected.
4. **Revocation precedence**:
   parent revocation must deny descendant acceptance.

### 11.2 Obligation Form

\[
\forall i \in \{1,2,3,4\}: \operatorname{Obligation}_i = \text{PASS}
\tag{11.1}
\]

Formal verification gate passes iff Equation (11.1) is true.

---

## 12. Fuzzing and Regression Science

### 12.1 CapNet Fuzz

`capnet-fuzz <iters> [seed]` performs deterministic parser/enforcer stress across:

- random token decode attempts,
- random control-frame decode attempts,
- random process-path inputs,
- replay-duplicate checks,
- semantic constraint checks,
- overflow payload-length decode checks.

### 12.2 Stable Corpus

CapNet uses fixed external seeds:

\[
\mathcal{S}_{capnet} = \{s_0,\dots,s_9\}
\tag{12.1}
\]

for reproducible replay and soak comparison.

### 12.3 Aggregate Criteria

For corpus run:

\[
\text{seeds\_passed} = |\mathcal{S}_{capnet}|
\quad \land \quad
\text{total\_failures} = 0
\tag{12.2}
\]

For soak run:

\[
\text{rounds\_passed} = \text{rounds}
\quad \land \quad
\text{total\_failures} = 0
\tag{12.3}
\]

CI fails if either Equation (12.2) or (12.3) is false.

---

## 13. CI Gating

CapNet regression is enforced by:

- `kernel/fuzz/run_capnet_corpus.expect`
- `kernel/fuzz/ci_capnet_check.sh`
- `.github/workflows/capnet-regression.yml`

Pipeline stages:

1. build kernel ISO,
2. run per-seed fuzz replay,
3. run corpus aggregate command,
4. run corpus soak command,
5. run `formal-verify`,
6. parse summaries and enforce zero-failure criteria.

This gives a deterministic and machine-enforced release gate for CapNet invariants.

---

## 14. Complexity and Resource Bounds

All core structures are compile-time bounded:

- peer table size \(P_{\max}\),
- delegation record size \(D_{\max}\),
- tombstone size \(R_{\max}\),
- retransmit queue size \(Q_{\max}\).

### 14.1 Time Complexity

- peer lookup: \(O(P_{\max})\),
- delegation parent search: \(O(D_{\max})\),
- transitive revoke closure: \(O(D_{\max}^2)\) worst-case bounded,
- tombstone lookup: \(O(R_{\max})\),
- retransmit scan tick: \(O(Q_{\max})\).

Since all maxima are small constants, runtime is bounded and predictable.

### 14.2 Memory Complexity

CapNet control-plane memory:

\[
M = O(P_{\max} + D_{\max} + R_{\max} + Q_{\max})
\tag{14.1}
\]

with fixed constant bounds in implementation.

---

## 15. Threat-Control Matrix

| Threat Class | Mathematical Condition | Control Path |
|---|---|---|
| Token forge | Eq. (5.2) false | Reject token/frame |
| Nonce replay | Eq. (6.1) false | Reject token |
| Sequence replay | Eq. (6.2) false | Reject frame |
| Delegation escalation | Eq. (7.2) violated | Reject child token |
| Type/object confusion | Eq. (7.5)/(7.6) violated | Reject child token |
| Temporal bypass | Eq. (7.8) violated | Reject child token |
| Revoked reuse | Eq. (8.2) violated | Reject token/use |
| Reboot replay gap | Eq. (8.5) absent | Rebuild tombstones at init |
| Lease bypass | Eq. (9.1) false | Deny install/use |

---

## 16. Implementation Deep Dive

### 16.1 Token and Frame Codec

The codec uses explicit, checked read/write primitives over fixed-length arrays. Every decode path checks:

- length equality,
- magic/version/algorithm identifiers,
- payload bounds,
- checked offset arithmetic.

Any decode overflow returns explicit error and never falls through to partial acceptance.

### 16.2 Offer Processing Path

`TOKEN_OFFER` ingress path:

1. decode frame,
2. verify frame MAC + sequence freshness,
3. decode token,
4. verify token MAC + nonce freshness,
5. enforce revocation/tombstone denial,
6. enforce delegation-chain constraints,
7. install/update remote lease,
8. record accepted delegation record,
9. audit security event.

Each step is fail-closed. No lease is installed before full predicate satisfaction.

### 16.3 Revoke Processing Path

`TOKEN_REVOKE` ingress path:

1. verify control frame authenticity/freshness,
2. allocate monotonic revocation epoch,
3. compute descendant closure in delegation records,
4. write tombstones for all revoked IDs,
5. append journal records to persistence,
6. revoke mapped local leases/capabilities,
7. audit revocation event.

### 16.4 Capability Enforcement Hook

`check_capability()` first evaluates local/mapped capability entries and remote lease constraints:

- owner binding,
- type/object equality,
- rights inclusion,
- temporal validity,
- budget availability,
- revocation status.

Only then can operation dispatch proceed.

---

## 17. Scientific Claims and Proof Sketches

### Claim 1: Authority Non-Escalation

Under accepted delegation-chain constraints, rights are monotone decreasing over any accepted chain.

**Sketch.** Follows directly from Equation (7.2) at each edge and transitivity of subset relation.

### Claim 2: Replay Immunity Within Window Model

For any accepted token/frame nonce/seq \(x\), a second submission with same \(x\) from same peer/key epoch is rejected.

**Sketch.** Acceptance sets corresponding bitmap bit; duplicate check rejects set bits.

### Claim 3: Revocation Dominance

If token \(u\) is revoked, all descendants in closure are denied on future acceptance and use paths.

**Sketch.** Closure application marks tombstones and lease revocations; acceptance checks tombstones before install.

### Claim 4: Reboot-Safe Revocation

Revoked IDs remain denied after reboot.

**Sketch.** Persistence replay reconstructs tombstones during init before control-path acceptance.

---

## 18. Operational Reproducibility

### 18.1 In-Kernel Commands

- `capnet-fuzz <iters> [seed]`
- `capnet-fuzz-corpus <iters>`
- `capnet-fuzz-soak <iters> <rounds>`
- `formal-verify`
- `capnet-stats`
- `capnet-demo`

### 18.2 External Runner

From `kernel/`:

```bash
./fuzz/ci_capnet_check.sh 1000 2
```

This command is the local equivalent of CI gate behavior.

---

## 19. Limitations and Future Scientific Work

1. **MAC width and cryptographic model**:
   SipHash-64 is strong for keyed integrity under current threat model, but high-scale adversarial federation may motivate stronger detached signatures and algorithm agility.
2. **Federation semantics**:
   current design is optimized for peer-session trust. Global multi-domain trust exchange can extend verifier and root-set interoperability layers.
3. **Side-channel model**:
   current guarantees are functional and control-plane oriented, not complete microarchitectural noninterference.
4. **Proof depth**:
   obligations are machine-checked and deterministic but bounded; full theorem-prover mechanization over all implementation semantics remains future work.

---

## 20. Conclusion

CapNet is now a completed kernel feature, not a roadmap item. The protocol and enforcement stack convert distributed capability transfer from an ad hoc control path into a formalized security substrate with explicit mathematical invariants, bounded-state implementation, deterministic fuzz/corpus replay, and CI-enforced proof obligations.

In practical terms, Oreulius can now delegate, consume, and revoke cross-device authority under a single kernel authority model, with measurable replay resistance, non-escalation guarantees, persistent revocation semantics, and release-time regression gates.

