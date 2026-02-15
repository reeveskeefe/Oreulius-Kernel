# The JIT-in-Kernel Security Paradox

At the heart of Oreulia's architecture lies a bold but controversial design decision: executing a Just-In-Time (JIT) compiler inside the kernel itself, running at the highest privilege level (Ring 0). While this approach delivers extraordinary performance benefits--eliminating context-switching overhead and enabling near-native execution speeds for WebAssembly code--it introduces a fundamental security tension that challenges conventional operating system design principles. The paradox is this: the WebAssembly sandbox is mathematically sound and provides robust isolation guarantees, but the very compiler that enforces these guarantees runs with unrestricted kernel privileges. If the JIT compiler contains a bug--whether in its bytecode parser, instruction selector, register allocator, or code generator--an attacker can potentially exploit that bug to achieve arbitrary kernel code execution, bypassing all the carefully constructed security boundaries that the system was designed to enforce.

Traditional operating systems avoid this problem by moving JIT compilation to user space (Ring 3), where compiler bugs result in application crashes rather than kernel compromises. When V8 compiles JavaScript or when Wasmtime generates native code, these operations occur in sandboxed processes with limited privileges; if the compiler produces incorrect machine code or crashes while optimizing a hot loop, only the application dies--the kernel remains intact and other processes continue unaffected. Oreulia's decision to embed the JIT compiler directly in kernel space means accepting a dramatically expanded Trusted Computing Base (TCB): every line of code in the JIT compiler, every optimization pass, every instruction selection heuristic, and every bounds check insertion must be flawless. A single integer overflow in address calculation, a missing bounds check in an optimization path, or a type confusion in the register allocator becomes a kernel-level vulnerability that could grant an attacker complete control of the system.

This creates a philosophical and practical dilemma for achieving "provably secure" systems. While Oreulia's capability-based security model is theoretically elegant--no ambient authority, unforgeable capabilities, complete audit trails--the presence of an unverified JIT compiler in kernel space undermines these guarantees at the implementation level. The engineering defenses are impressive: memory tagging, W^X enforcement, control flow integrity, MAC-signed IPC capabilities (SipHash), and defense-in-depth strategies can mitigate many attack vectors. However, mathematically proving the system's security requires formally verifying the JIT compiler itself--a problem that remains at the frontier of computer science research and has consumed entire PhD programs for simpler compilers like CompCert. The tension between performance (JIT in kernel) and provable security (formalized correctness guarantees) represents the central challenge in transforming Oreulia from an innovative research prototype into a production-grade secure operating system. Without formal verification of the JIT compiler or strong in-kernel hardening and translation validation, the system remains vulnerable to a class of attacks that bypass all other security mechanisms, making "impenetrability" a practical impossibility rather than an achievable engineering goal.

## Formal Resolution Statement

This document is the completed, scientific resolution record for the Oreulia in-kernel JIT security paradox. The objective was not to remove JIT, but to keep kernel-resident JIT compilation while forcing execution and authority behavior into mathematically constrained, fail-closed regimes.

The security target was:

`forall state s: Safe(s) => Safe(T_jit(s))`

where `T_jit` is the transition relation induced by JIT compile-load-execute cycles and `Safe` includes:

- memory safety and non-writable executable constraints,
- control-flow admissibility,
- capability authenticity and rights monotonicity,
- privilege and address-space isolation,
- deterministic detection of translation drift,
- deterministic regression and runtime anomaly observability.



### How we did it
- W^X enforcement for JIT
- Kernel `.text` and `.rodata` read-only mapping
- Dedicated JIT arena
- Isolated execution address space
- Ring 3 usermode execution path
- Guard pages for JIT regions
- JIT page-fault trapping
- Fuel-based execution limits
- Integrity checks for code and executable buffers
- Shadow validation against interpreter behavior
- JIT cache hardening
- Concurrency hardening
- Cryptographic capability tokens for IPC
- Cryptographic capability tokens for core capability tables
- JIT fuzz harness and regression seeds
- Complete instruction whitelist and decoder validation
- Expanded SFI on all memory access paths
- Per-instance JIT user pages and wipe policy
- Full CFI with shadow stack and valid target sets
- SMEP/SMAP/KPTI enforcement paths
- Memory tagging and hardware isolation capability layer
- Hardware enclave backend framework
- Hardware enclave primitive wiring
- Production enclave provisioning
- Remote attestation and key provisioning hardening
- External remote attestation interoperability hardening
- Scheduler and context-switch hardening
- Keyboard IRQ recovery under preemption
- Translation validation with per-block certificate model
- Coverage-guided fuzzing and external regression corpus
- Panic-safe bytecode/function range handling
- Allocator-stable corpus fuzz execution
- Formal verification framework for JIT and capabilities
- Mechanized backend model checks
- CI automation for corpus replay
- Residual non-determinism soak checks
- Runtime anomaly detection
- Scheduler/network soak verification command

## Global Mathematical Model

Let:

- `Pages` be all virtual pages.
- `ExecPages subseteq Pages` be executable pages.
- `Cap` be capabilities.
- `R` be the rights lattice with partial order `<=` defined as bit-subset.
- `B` be emitted machine instruction stream.
- `W` be WASM instruction stream.
- `Sigma` be machine state.
- `A_t` be anomaly window state at time `t`.

Core invariants:

1. `forall p in ExecPages: not (Writable(p) and Executable(p))`
2. `forall b in IndirectBranches(B): target(b) in ValidTargets(B)`
3. `forall m in MemOps(B): Guarded(m)`
4. `forall c in Cap: VerifyToken(c) = true`
5. `forall c_parent, c_child: c_child derived from c_parent => rights(c_child) <= rights(c_parent)`
6. `forall runs: ReplayDeterminism(runs) => mismatches = 0 and compile_errors = 0`

The rest of this document explains how each implemented control establishes one or more of these invariants.

## Ordered Resolution Details

### 1) W^X enforcement for JIT

Threat addressed: self-modifying executable code and post-publication code injection.

Control mechanism: JIT code pages move through a one-way permission automaton:

`RW --seal--> RX --reclaim--> NONE`

Forbidden state:

`RWX = false` for all JIT pages and all times.

Solved condition:

`forall t, p: Executable(p,t) => not Writable(p,t)`

This converts many write-what-where primitives into non-executable corruption rather than direct control transfer.

### 2) Kernel `.text` and `.rodata` read-only mapping

Threat addressed: kernel text patching and constant-pool overwrite.

Control mechanism: strict region policy:

`WriteAllowed(v) = 1 iff v in (.data union .bss)`

Solved condition:

`forall v in (.text union .rodata): WriteAllowed(v) = 0`

Any attempted write in those regions transitions to trap/fault handling rather than silent state corruption.

### 3) Dedicated JIT arena

Threat addressed: broad executable footprint and aliasing into unrelated kernel memory.

Control mechanism: executable allocations constrained to an arena interval `[A0, A1)`.

Allocation predicate:

`ArenaAlloc(x, n) => A0 <= x and x + n <= A1`

Solved condition:

`ExecPages subseteq ArenaPages`

This narrows scanning, validation, and reclamation scope and reduces accidental executable exposure.

### 4) Isolated execution address space

Threat addressed: JIT code observing or writing broad kernel mappings.

Control mechanism: execute under sandbox page directory `PD_s` with explicit allowed map set `M_s`.

Visibility invariant:

`Visible(va) = 1 => va in M_s`

Solved condition:

`CR3 = PD_s during JIT execution`

This creates an address-space cut between compiler context and execution context.

### 5) Ring 3 usermode execution path

Threat addressed: executing untrusted translated logic at Ring 0.

Control mechanism: privilege demotion with user selectors and controlled return trampoline.

Privilege invariant:

`CPL_exec = 3` for user JIT path.

Solved condition:

`forall user-jit instruction i: Privileged(i) => fault`

Hardware privilege checks provide a second line of defense even if software checks are imperfect.

### 6) Guard pages for JIT regions

Threat addressed: stack/code/data linear overflow.

Control mechanism: guard page boundaries where adjacent pages are non-present.

Boundary invariant:

`Access(addr) with addr in GuardPages => fault`

Solved example:

If `stack_top = S`, mapped stack is `[S-N, S)`, then write to `S` or read below `S-N-1` faults immediately.

### 7) JIT page-fault trapping

Threat addressed: kernel panic escalation from JIT memory faults.

Control mechanism: classify JIT-context faults and convert to VM/WASM trap codes.

Trap mapping function:

`TrapCode = PFMap(error_code, fault_addr, context)`

Solved condition:

`FaultInJitContext => return trap, not kernel panic`

This preserves system availability under adversarial memory behaviors.

### 8) Fuel-based execution limits

Threat addressed: non-terminating loops and resource denial.

Control mechanism: instruction fuel `F_i` and memory fuel `F_m` decremented on each guarded event.

Dynamics:

`F_i(k+1) = F_i(k) - 1`
`F_m(k+1) = F_m(k) - delta_m(k)`

Trap condition:

`F_i <= 0 or F_m <= 0 => trap`

This gives strict upper bounds on execution effort.

### 9) Integrity checks

Threat addressed: executable buffer tampering between compile and execute.

Control mechanism: hash and seal checks for source code and executable image.

Invariant:

`Hash(exec_runtime) = Hash(exec_signed)`
`Hash(code_runtime) = Hash(code_signed)`

Any mismatch fails integrity validation before execution.

### 10) Shadow validation

Threat addressed: silent semantic drift between interpreter and JIT path.

Control mechanism: early executions compare outputs, traps, and memory effects.

Differential predicate:

`EqBehavior = (ret_i = ret_j) and (trap_i = trap_j) and (mem_i = mem_j)`

If `EqBehavior = false`, JIT path is rejected/fallbacked and discrepancy is recorded.

### 11) JIT cache hardening

Threat addressed: stale or colliding cache entries mapping wrong code to execution artifacts.

Control mechanism: 64-bit hash plus metadata checks (`code_len`, locals) and integrity checks.

Collision estimate for random adversary:

`P_collision approx N^2 / 2^65`

for `N` cached entries.

Combined with exact metadata checks, the practical collision exploitability is substantially reduced.

### 12) Concurrency hardening

Threat addressed: race conditions across user transition and return signaling.

Control mechanism: critical sections and serialized transition state.

Race safety target:

`forall transitions tau1, tau2: overlap(tau1, tau2) => serialized(tau1, tau2)`

This avoids inconsistent state publication across interrupt boundaries.

### 13) Cryptographic capability tokens (IPC)

Threat addressed: forged/replayed transferred capabilities.

Control mechanism:

`token = SipHash_k(cap_id || rights || sender || receiver || nonce)`

Verification equation:

`Accept = (token' = token) and Fresh(nonce) and rights_subset`

Without key `k`, successful forgery probability per attempt is bounded by `2^-64`.

### 14) Cryptographic capability tokens (core tables)

Threat addressed: in-memory capability table tampering.

Control mechanism: each stored capability entry is authenticated and re-verified on use.

Entry invariant:

`Verify(entry_payload, entry_token) = true`

Tampered entries transition to denial/audit path instead of authority grant.

### 15) JIT fuzz harness and regression seeds

Threat addressed: unknown translation and runtime corner cases.

Control mechanism: differential fuzzing against interpreter with seeded replay.

Outcome vector per run:

`(ok, traps, mismatches, compile_errors)`

Security acceptance criterion:

`mismatches = 0 and compile_errors = 0` on required seeds.

### 16) Complete instruction whitelist and decoder validation

Threat addressed: unsafe x86 emission including privileged/undefined forms.

Control mechanism: emitted bytes must belong to a strict accepted language `L_safe`.

Language-membership predicate:

`B in L_safe`

If `B notin L_safe`, compile fails before publication.

This closes the "emit something unsafe" gap.

### 17) Expanded SFI on all memory paths

Threat addressed: unguarded load/store edge cases.

Control mechanism: every memory op must satisfy guard predicate:

`Guard(addr, off, size, L) = checked_add(addr,off)=e and e <= L-size`

Coverage invariant:

`forall m in MemOps(B): Guarded(m) = true`

No memory path bypasses guard insertion/validation.

### 18) Per-instance JIT user pages and wipe policy

Threat addressed: residual data/code leakage across JIT runs.

Control mechanism: allocate per-instance pages; wipe and reseal on teardown.

Confidentiality invariant:

`PostTeardown(page) => entropy(page_prev, page_now) minimized and stale data inaccessible`

Operationally this removes cross-instance residue as an attack primitive.

### 19) Full CFI (shadow stack and valid target sets)

Threat addressed: intra-region ROP/JOP and return spoofing.

Control mechanism:

- indirect targets constrained to `T_valid`,
- returns validated against shadow stack sequence.

CFI invariant:

`forall indirect edge e: target(e) in T_valid`

Return invariant:

`RetAddr_arch(k) = RetAddr_shadow(k)`

Violation leads to trap, not speculative continuation.

### 20) SMEP/SMAP/KPTI

Threat addressed: supervisor misuse of user pages and user/kernel map abuse.

Control mechanism:

- SMEP forbids supervisor execution of user pages,
- SMAP constrains supervisor data access to user pages unless explicitly enabled,
- KPTI isolates user-visible maps from kernel-critical maps.

Simplified policy:

`CPL=0 and UserPageExec => forbidden`
`CPL=0 and UserPageDataAccess => gated`

Combined with CR3 splits, this significantly reduces privilege crossing abuse.

### 21) Memory tagging and hardware isolation capability layer

Threat addressed: mapping user contexts to pages outside intended trust domain.

Control mechanism: software tags and policy checks on mapping decisions, plus hardware capability detection.

Tag invariant:

`MapUser(page, domain_u) => Tag(page) compatible_with domain_u`

Fail-closed behavior blocks mappings that violate policy.

### 22) Hardware enclave backend framework

Threat addressed: unverifiable enclave session state transitions.

Control mechanism: explicit state machine:

`Closed -> Open -> Entered -> Exited -> Closed`

No transition outside defined edges is accepted.

This prevents lifecycle confusion and session-state abuse.

### 23) Hardware enclave primitive wiring

Threat addressed: backend abstraction without real primitive semantics.

Control mechanism: SGX and TrustZone backends invoke hardware-specific paths where supported.

Correctness objective:

`BackendSelected = SGX => SGXPrimitivePath`
`BackendSelected = TrustZone => SMCPath`

This binds policy claims to concrete backend execution semantics.

### 24) Production enclave provisioning

Threat addressed: weak provisioning, unmanaged EPC/service contracts.

Control mechanism: EPC management, token checks, attestation material flow, and secure-world contract negotiation.

Provisioning predicate:

`ProvisionOK = epc_ok and token_ok and contract_ok`

If `ProvisionOK = false`, enclave session admission is denied.

### 25) Remote attestation and key provisioning hardening

Threat addressed: entering enclave paths without valid key/attestation state.

Control mechanism: fail-closed sequencing:

`OpenAllowed iff ProvisionKeyOK`
`EnterAllowed iff Attested and RuntimeKeyValid`
`Close => KeyRevoked`

This ensures key lifecycle cannot drift from attestation lifecycle.

### 26) External remote attestation interoperability hardening

Threat addressed: accepting unverifiable external attestations.

Control mechanism: vendor root anchors, signer chain checks, deterministic quote verification, verifier-token exchange.

Admission equation:

`Accept = RootValid and ChainValid and QuoteValid and TokenValid and NotExpired`

Policy mode controls strictness but preserves auditable decision structure.

### 27) Scheduler and context-switch hardening

Threat addressed: interrupt-state corruption and unsafe first-run transitions.

Control mechanism: preserve raw EFLAGS semantics and controlled IF behavior at bootstrap/resume.

State invariant:

`Resume(pid) => IF_after = IF_saved(pid)`

This keeps scheduling correctness aligned with security timing assumptions.

### 28) Keyboard IRQ recovery under preemption

Threat addressed: IRQ starvation after cooperative/preemptive switches.

Control mechanism: restore interrupt state on resumption paths.

Liveness condition:

`Eventually(IRQ_keyboard_serviced)` under normal scheduler fairness assumptions.

This closes a practical availability regression that can mask other security diagnostics.

### 29) Translation validation (per-block certificate)

Threat addressed: valid-looking global output with invalid local translation segments.

Control mechanism: each block carries digest and trace obligations, re-checked at integrity time.

Certificate condition:

`forall block b: Digest_runtime(b) = Digest_cert(b)`

and coverage condition:

`TraceCoverage(W,B) = 1`

This localizes correctness guarantees to block granularity.

### 30) Coverage-guided fuzzing and external regression corpus

Threat addressed: shallow random test distributions.

Control mechanism: guide generation using novelty over opcode bins and edge transitions.

Coverage functions:

`BinCov = hit_bins / total_bins`
`EdgeCov = hit_edges / total_edges`

Novelty function:

`Novel(p) = 1 if introduces_new_bin_or_edge(p)`

Corpus replay stabilizes discovered bug classes into permanent regression checks.

### 31) Panic-safe bytecode and function-range handling

Threat addressed: slice/index panics from malformed offsets and lengths.

Control mechanism: checked arithmetic and range clamps before dereference.

Safety predicate:

`RangeOK = (off <= len) and (off + n <= len)` with overflow-safe arithmetic.

If false, return semantic error (`InvalidModule`) instead of panic.

### 32) Allocator-stable corpus fuzz execution

Threat addressed: allocator exhaustion causing false-negative security signal.

Control mechanism: reuse fuzz instances, compiler state, and scratch buffers.

Memory stability objective:

`PeakAlloc_soak <= bound` and no progressive fragmentation failure in normal corpus rounds.

This keeps long campaigns meaningful and reproducible.

### 33) Formal verification framework for JIT and capabilities

Threat addressed: unstructured proof obligations and fragmented assurance.

Control mechanism: explicit proof certificates and unified capability proof predicates.

JIT proof tuple:

`Proof = (trace_continuity, opcode_consistency, mem_obligations, proof_hash)`

Capability proof predicate:

`CapProof = TokenValid and TypeMatch and ObjectMatch and RightsSatisfy`

`formal-verify` executes deterministic obligations over these predicates.

### 34) Mechanized backend model checks

Threat addressed: drift between intended law and implementation law.

Control mechanism: bounded machine-check passes for:

- rights attenuation subset law,
- memory-guard equivalence law.

Attenuation law:

`child <= parent`

Guard equivalence law:

`Guard_lowlevel(addr,off,size,L) = Guard_spec(addr,off,size,L)`

These are executable mathematical obligations, not only narrative claims.

### 35) CI automation for corpus replay

Threat addressed: manual testing gaps and regressions entering mainline.

Control mechanism: per-commit/PR replay with fail conditions.

CI gate:

`PassCI iff mismatches = 0 and compile_errors = 0 and required_seeds_pass = true`

This converts security validation into admission policy.

### 36) Residual non-determinism soak checks

Threat addressed: intermittent failures not visible in single replay pass.

Control mechanism: repeated corpus rounds with first-failure capture.

Soak criterion:

`forall round r in [1..R], forall seed s in S: pass(r,s) = true`

Where `pass(r,s)` means zero mismatch and zero compile error for that `(r,s)`.

### 37) Runtime anomaly detection

Threat addressed: unknown exploit classes and policy drift during live runtime.

Control mechanism: sliding score over event classes.

Current score function:

`Score_t = 2D_t + 2Q_t + R_t + 4I_t + 16H_t`

where:

- `D_t`: permission denied events,
- `Q_t`: quota exceeded events,
- `R_t`: rate limit exceeded events,
- `I_t`: invalid capability events,
- `H_t`: integrity failures.

Solved numeric example:

If `D_t=11, Q_t=4, R_t=5, I_t=3, H_t=1`, then:

`Score_t = 2*11 + 2*4 + 5 + 4*3 + 16*1 = 63`

If threshold is `64`, this run remains below alert threshold by 1 point.

### 38) Scheduler/network soak verification command

Threat addressed: hidden runtime instability in mixed scheduler/network operation.

Control mechanism: long-run probe loop with scheduler deltas and reactor health measurements.

Stability condition:

`NetErrorCount = 0 and CriticalAnomalyDelta = 0`

with monotonic scheduler progress:

`DeltaSwitches > 0`

This gives an operational proof of liveness-compatible security behavior under sustained load.

## Composite Resolution Argument

The security paradox is solved compositionally rather than by single-point claims.

Let event `E_i` be failure of control `i` above. A successful adversarial end state requires conjunction of multiple control failures:

`E_total = E_1 and E_2 and ... and E_n`

Under conservative independence approximation:

`P(E_total) <= product_i P(E_i)`

Even when strict independence is not assumed, defense-in-depth still enforces layered rejection paths, making exploit chains longer, less reliable, and more detectable.

## Deterministic Evidence Policy

Security acceptance is tied to deterministic metrics:

- `mismatches = 0`
- `compile_errors = 0`
- replay/soak required seed set passes,
- formal obligations pass,
- anomaly system operational and visible.

This transforms security from narrative confidence into measurable release gates.

## Residual Scientific Limits

The current resolution is complete for the original issue scope, but two scientific limits remain true in any practical system:

1. Bounded mechanized checks are not equivalent to unbounded theorem-prover completeness.
2. Hardware/microarchitectural leakage classes require separate and ongoing formalization.

These are not unresolved implementation tasks in this paradox closure; they are long-horizon research boundaries for any high-assurance kernel.

## Conclusion

Oreulia retained in-kernel JIT and resolved the paradox by enforcing strict invariants across memory permissions, control flow, privilege separation, authority integrity, attestation admission, deterministic fuzz regression, machine-checked proof obligations, and runtime anomaly scoring.

In short form:

`Fast JIT` and `Strong Security` are jointly achieved by constraining transitions, proving guard equivalence on critical predicates, and continuously rejecting regression through deterministic CI and soak evidence.



## Extended Scientific Analysis

### 10. Adversary Model and Capability Profile

A security argument is only as strong as its adversary model. We define the Oreulia JIT adversary as a tuple:

`Adv = (InputControl, RuntimeInfluence, AuthorityForgery, TimingInfluence, SupplyChainInfluence)`

with each component measured on an ordinal scale from `0` (none) to `3` (maximal).

The implemented paradox resolution targets the following classes:

1. `Adv_module`:
   `InputControl=3`, `RuntimeInfluence=2`, `AuthorityForgery<=1`, `TimingInfluence=2`, `SupplyChainInfluence=0`.
2. `Adv_local`:
   `InputControl=3`, `RuntimeInfluence=3`, `AuthorityForgery=3`, `TimingInfluence=3`, `SupplyChainInfluence=1`.
3. `Adv_remote_attest`:
   `InputControl=2`, `RuntimeInfluence=1`, `AuthorityForgery=2`, `TimingInfluence=1`, `SupplyChainInfluence=2`.

For all three classes, success requires bypassing at least two control families among memory, control flow, authority integrity, and deterministic regression gates.

This is formalized as:

`Success(Adv_x) => exists F subseteq Families: |F| >= 2 and forall f in F: Bypass(f)=true`

where `Families = {Mem, CFI, Cap, Iso, Attest, Det, Anom}`.

### 11. Threat-to-Control Traceability Algebra

Let `Theta = {theta_1, ..., theta_m}` be threat classes and `C = {c_1, ..., c_n}` be implemented controls.

Define a binary mitigation matrix:

`M in {0,1}^{m x n}` where `M[i,j] = 1` iff control `c_j` mitigates threat `theta_i`.

For each threat, define mitigation multiplicity:

`mu(theta_i) = sum_j M[i,j]`

The paradox is considered structurally resolved only if all critical threats satisfy:

`mu(theta_i) >= 2`.

Operationally, this means no critical threat has a single-point fail-open dependency.

Example mapping:

- `theta_overflow_write` -> `{SFI, GuardPages, FaultTrap, TranslationValidation}`
- `theta_indirect_hijack` -> `{WhitelistDecoder, CFI_TargetSets, ShadowStack}`
- `theta_cap_forgery` -> `{IPC_MAC, Table_MAC, RightsSubsetLaw, AnomalyScoring}`

### 12. Safety Objective Decomposition and Closure

Define top objective:

`O_total = O_mem and O_cf and O_iso and O_cap and O_sem and O_det and O_run`

with:

- `O_mem`: memory execution and bounds constraints hold,
- `O_cf`: control-flow validity holds,
- `O_iso`: privilege/address-space isolation holds,
- `O_cap`: capability authenticity and attenuation hold,
- `O_sem`: semantic consistency checks hold,
- `O_det`: deterministic replay regression gates hold,
- `O_run`: runtime anomaly observability and threshold logic hold.

Closure property:

`(forall k: O_k) => O_total`

and non-degeneracy condition:

`exists k: O_k` is insufficient.

The implemented architecture was explicitly designed to avoid this degenerate case.

### 13. Proof Sketches of Core Lemmas

#### Lemma A: No Executable Writable JIT Page

Given transition automaton:

`RW -> RX -> NONE`

and no edges to `RWX`, then:

`forall page p, time t: not (W(p,t) and X(p,t))`.

Sketch:

- Base case: allocation yields `RW`, not executable.
- Induction over allowed transitions preserves `not (W and X)`.
- Terminal `NONE` trivially preserves invariant.

#### Lemma B: Guard Equivalence for Memory Access

Low-level guard:

`G_l(addr,off,size,L) = [checked_add(addr,off)=e and e <= L-size]`

Spec guard:

`G_s(addr,off,size,L) = [checked_add(addr,off)=e and checked_add(e,size)=end and end <= L]`

Under unsigned arithmetic and finite `L`,

`G_l <=> G_s`.

This is directly tested by mechanized backend checks in bounded domains.

#### Lemma C: Capability Attenuation Monotonicity

If child is derived from parent, then:

`rights(child) subseteq rights(parent)`.

Therefore for any required right `r`:

`r in rights(child) => r in rights(parent)`.

No attenuation step can introduce a right not already present.

#### Lemma D: Deterministic Replay Admission Soundness

Given CI policy:

`PassCI iff mismatches=0 and compile_errors=0 and required_seed_set_passed`.

Then any change that violates observed corpus equivalence fails admission.

This is a sound rejection criterion for the exercised seed set.

### 14. Attack-Chain Neutralization Studies

#### Study 1: Offset-Wrap Arbitrary Write Attempt

Adversary strategy:

1. choose `addr,off` with wraparound,
2. force write operation past linear memory window,
3. hijack state through out-of-bounds write.

Neutralization stack:

- checked-add overflow rejection,
- SFI guard denial,
- guard-page hard fault,
- fault-to-trap conversion,
- differential mismatch detection if any silent divergence occurs.

Expected attacker utility collapses from code execution to trapped execution.

#### Study 2: Indirect Branch Redirection Attempt

Adversary strategy:

1. control a dynamic jump input,
2. jump into non-whitelisted gadget bytes,
3. chain returns to escape intended flow.

Neutralization stack:

- emitted bytes constrained to safe decoder language,
- valid-target set enforcement,
- shadow-stack return equality checks.

Control-flow equation:

`ExecutableEdge(e) => target(e) in T_valid and ReturnEq(e)=true`.

#### Study 3: Capability Transfer Forgery Attempt

Adversary strategy:

1. forge token for elevated rights,
2. replay on IPC channel,
3. escalate operation authority.

Neutralization stack:

- token verification under per-boot key,
- sender/receiver/nonce context binding,
- rights-subset attenuation law,
- anomaly rise under repeated invalid attempts.

Upper bound:

`P_success <= N / 2^64` for `N` independent forgery attempts.

#### Study 4: Attestation Substitution Attempt

Adversary strategy:

1. inject alternative quote chain,
2. bypass remote verifier state,
3. enter enclave with untrusted measurement.

Neutralization stack:

- vendor-root and signer chain enforcement,
- deterministic quote verification,
- verdict token binding to session+nonce,
- freshness and expiry checks at entry.

Admission condition remains conjunction-only:

`Accept = RootValid and ChainValid and QuoteValid and TokenValid and Fresh`.

### 15. Quantitative Assurance Framework

Define assurance vector:

`Q = (D, R_c, S_cov, A, K)` where:

- `D`: replay determinism score,
- `R_c`: corpus reliability,
- `S_cov`: structural fuzz coverage score,
- `A`: normalized anomaly pressure,
- `K`: key/attestation lifecycle consistency score.

Representative definitions:

`D = passed_rounds / total_rounds`

`R_c = 1 - (mismatches + compile_errors)/total_runs`

`S_cov = alpha*BinCov + beta*EdgeCov`, with `alpha+beta=1`

`A = Score_t / AlertThreshold`

`K = valid_lifecycle_transitions / total_lifecycle_transitions`

Release gate:

`ReleaseAllowed iff D=1 and R_c=1 and A<1 and K=1 and FormalPass=1`.

### 16. Scheduler-Security Coupling Formalization

Security checks are only meaningful if scheduler/interrupt semantics are stable.

Let `IF_s(pid)` be saved interrupt flag and `IF_r(pid)` be restored flag.

Invariant:

`forall pid: IF_r(pid) = IF_s(pid)`.

Let `Service(irq,t)` denote IRQ service at time `t`.

Liveness envelope:

`forall irq in RequiredSet: exists t<=T: Service(irq,t)`.

The scheduler/network soak command is a runtime witness for these properties under sustained mixed load.

### 17. Translation Certificate Semantics

For each compiled function `f`, certificate:

`Cert_f = (Trace_f, BlockDigests_f, GuardObligations_f, ProofHash_f)`.

Validation map:

`Validate(f) = [Recompute(Cert_f) = Cert_f]`.

This yields post-generation tamper evidence and enforces that translation obligations are not merely compile-time assertions but runtime-checked facts.

### 18. Runtime Anomaly Scoring Deep Dive

Current score function:

`Score_t = 2D_t + 2Q_t + R_t + 4I_t + 16H_t`.

This weighting privileges integrity failures (`H_t`) as highest severity class.

Sensitivity interpretation:

`partial Score / partial H = 16`

`partial Score / partial I = 4`

`partial Score / partial D = 2`

This means one integrity failure carries the same weight as eight denied events.

Solved examples:

- Example A: `D=10,Q=2,R=6,I=1,H=0` gives `Score=34`.
- Example B: `D=10,Q=2,R=6,I=1,H=2` gives `Score=66`.

A two-event increase in `H` can push state from normal to alert without any change in low-severity counters.

### 19. Non-Determinism Soak Semantics

Single-pass corpus replay does not establish temporal stability. Multi-round soak introduces time-indexed confidence.

Define pass indicator:

`P(r,s)=1` if round `r`, seed `s` has zero mismatch and zero compile error, else `0`.

Soak success:

`SoakPass = product_{r=1..R} product_{s in S} P(r,s)`.

Thus `SoakPass=1` iff all `(r,s)` pairs pass.

This strict product form intentionally treats a single failure as full gate failure.

### 20. Reliability Under Composition

If each control family `f_i` has bypass probability `p_i`, then under conservative independence approximation:

`P_total <= product_i p_i`.

Even when dependence exists, composition still increases required exploit complexity if no two dependent controls share identical failure mode.

Define dependency graph `G_dep` over controls. Desired property:

`max_clique_size(SharedFailureModeSubgraph) << |Controls|`.

Oreulia's implementation aims to minimize shared failure-mode cliques by mixing:

- hardware controls,
- software checks,
- cryptographic checks,
- runtime detection,
- CI regression gating.

### 21. Evidence Preservation and Reproducibility

A security claim is only reusable if evidence is reproducible.

Required evidence tuple per release candidate:

`E_release = (FormalSummary, CorpusSummary, SoakSummary, AnomalySummary, LifecycleSummary)`.

Consistency requirement:

`Hash(E_release) = recorded_release_hash`.

This enables post hoc auditability and differential review between releases.

### 22. Distinguishing Implementation Completion from Research Completion

The paradox closure is implementation-complete for the original issue scope. This does not imply global theorem-complete security.

Define:

`C_impl = completed engineering controls`

`C_research = open long-horizon proof/side-channel domains`

Current status:

`C_impl = 1`

`C_research > 0`.

This distinction protects scientific honesty while preserving strong practical security claims.

### 23. Scientific Conclusion 

Oreulia's paradox resolution can be summarized as a constrained-transition security architecture with measurable admission criteria.

Core statement:

`(ConstrainedPermissions and ConstrainedControlFlow and ConstrainedAuthority and ConstrainedExecutionContext and DeterministicRegression and RuntimeAnomalyVisibility) => OperationallyStrongJITSecurity`.

In practical terms, the design preserves the performance objective of in-kernel JIT while replacing unchecked trust with layered, mathematically stated, and continuously verified acceptance conditions.

This is the defining result: the system no longer depends on a single claim of compiler correctness for safety, but on a compositional structure where violating security requires coordinated failure across independent enforcement planes.
