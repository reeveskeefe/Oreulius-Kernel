# A Unified Theory of Capability-Based Trust, Causal Message Semantics, and Thermodynamic Liveness in Silicon

## Abstract

This paper develops the foundations of a unified mathematical framework for capability-based trust, channel-mediated causality, liveness preservation, and physical cost in secure kernels. The Oreulia IPC subsystem serves as the motivating instance: it already combines channel capabilities, bounded queues, capability attenuation, predictive restriction, and temporal replay within a single architectural surface, although the correspondence between implementation and theory is only partially formalized at present. The central claim is that these mechanisms can be placed within one coherent framework. Trust is represented as a rights algebra over capabilities; inter-process reality is represented as a causal graph of messages; security and liveness are represented as the intersection of fixed-point conditions over system state; and thermodynamic, information-theoretic, and topological limits constrain the space of admissible implementations. The paper provides formal definitions, proved propositions, proof sketches for stronger results, explicit threat-model assumptions, and a dependency-aware research agenda for the unresolved parts of the theory. The resulting synthesis treats the Oreulia IPC subsystem not as an isolated engineering artifact, but as a motivating and partially instantiated case within a broader theory of secure, causally coherent, self-maintaining computation.

## 1. Introduction and Motivation

Modern kernels are usually described in terms of mechanisms: process creation, address translation, interrupt handling, scheduling, and device control. Such descriptions are necessary, but they do not identify the mathematical object that makes a system secure and live at the same time. The present work addresses that gap for capability-mediated message passing.

The motivating system is the Oreulia IPC subsystem. It exposes channels rather than ambient shared authority, grants access by capabilities rather than by identity alone, uses bounded message queues rather than unstructured memory aliasing, and already contains mechanisms for predictive restriction and temporal replay. These features suggest a unifying interpretation:

1. Trust is a structure over rights, not an informal engineering intuition.
2. Messages are the primitive causal units of inter-process reality.
3. Liveness and security can be treated as a single invariant rather than as unrelated proof obligations.
4. A self-monitoring kernel approaches a form of autopoietic closure: it records, constrains, and reconstructs its own causal history.

This paper advances four contributions.

1. A formalization of capability systems as a rights algebra with attenuation, conservation, and provenance.
2. A message ontology in which process interaction is represented as a partially ordered causal history rather than as implicit mutation.
3. A definition of the living invariant, namely the intersection of security, liveness, and causal completeness.
4. A physical interpretation connecting liveness violations, information erasure, covert channels, and bounded history to thermodynamic and information-theoretic laws.

The paper distinguishes among proved results, proof sketches, and conjectures. Claims about rights attenuation, capability conservation, and invariant closure are presented as formal results. Claims about integrated information and silicon vitality are explicitly interpretive and are identified as conjectural where appropriate.

The present paper does not claim that the Oreulia kernel already satisfies every formal condition introduced below. Rather, it identifies which existing design elements already instantiate the theory, which elements are partial, and which remain obligations for a complete realization. That distinction is necessary for the paper to function as theory rather than advocacy.

### 1.1 Audience and Scope

This paper addresses three overlapping audiences. Systems researchers are the primary audience for the capability, IPC, and kernel-architecture claims. Formal-methods readers are the primary audience for the invariant, proof, and mechanization claims. A third, more speculative audience consists of readers interested in the relationship between formal self-maintenance and broader conceptual frameworks for life, cognition, and autopoiesis. The paper is organized accordingly.

Sections 2 through 4 and Section 6 define the formal core. Appendix A and Appendix B provide the vocabulary and proof apparatus for that core. Section 7 adds physical bounds that constrain any implementation attempting to instantiate the core on real hardware. Section 5 is explicitly interpretive rather than proof-bearing; it translates the formal machinery into a broader conceptual vocabulary but does not assert that those translations carry the same epistemic status as theorems in the formal system.

The scope is therefore mixed but not ambiguous. The formal core is intended to stand independently of the interpretive material. Conversely, the interpretive material is intended to be evaluated as a disciplined translation of the formal results, not as an extension of the proved theorem set.

### 1.2 Threat Model

The security claims of this paper are made under the following threat model.

1. The adversary may fully control any non-kernel user-space process, including message contents, message timing, retry behavior, and any capabilities legitimately obtained by that process.
2. The adversary may coordinate multiple user-space processes and may intentionally generate queue pressure, scheduler load, and explicit error outcomes through admissible API use.
3. The adversary may observe explicit success and failure results, protocol-visible closure events, and local elapsed time as measured by whatever timing source is available to the attacker within the kernel's exported execution environment.
4. The adversary is polynomial-time with respect to the cryptographic assumptions of the system and is therefore unable to forge capability tokens except by breaking the underlying cryptographic primitive.
5. The adversary does not compromise kernel code integrity, extract kernel secret material directly, violate hardware privilege boundaries, or defeat the hardware mechanisms on which process isolation depends.

This threat model places explicit error channels in scope, places timing and contention channels in scope for characterization, but does not claim that the present core theorems eliminate those timing and contention channels. Those channels are treated later as quantitatively relevant open obligations rather than as discharged proof results.

### 1.3 The Oreulia IPC Subsystem as a Motivating Instance

The Oreulia IPC subsystem is used throughout this paper as a motivating instance and partial architectural instantiation, not as a fully mechanized correspondence proof. The mapping between implementation and theory is therefore evidentiary rather than complete.

| Oreulia feature | Formal counterpart | Current status in implementation | Status in this paper |
| --- | --- | --- | --- |
| Channel capabilities with object identity and rights | Definition A.6, Section 2 | Implemented as kernel-issued channel authority | Motivating instance; correspondence asserted rather than mechanized |
| Bounded per-channel queues | Definition A.8, Definition A.29, Section 4 | Implemented | Used as the basis for the liveness model |
| Capability attenuation and delegation discipline | Proposition 2.3, Theorem 2.4 | Partially implemented structurally, partially by runtime discipline | Formalized, but full conservation theorems apply to the target linear model |
| Predictive restriction and temporary denial | Definition 4.8, Section 4 | Implemented as adaptive restriction behavior | Used as motivating evidence for invariant-preserving adaptation, not yet as a mechanized proof target |
| Temporal replay / authenticated event history | Definitions A.26-A.27, Theorem B.16 | Implemented in partial form | Used as the motivating basis for causal completeness and reconstruction |
| Linear capability transport | Definition A.13b, Section 6 | Not yet fully implemented | Target-model requirement for the strongest conservation theorems |

The paper therefore makes two different kinds of statements about Oreulia. Some statements are descriptive and implementation-facing: the subsystem already exhibits capabilities, bounded channels, adaptive restriction, and causal replay mechanisms relevant to the theory. Other statements are target-facing: the strongest conservation and closure theorems assume a linear capability carrier and a more explicit admission-control semantics than the current implementation yet provides. Whenever those stronger target assumptions are used, the paper states them explicitly.

### 1.4 Related Work

The theory developed here sits at the intersection of several bodies of prior work and differs from each of them in a specific way.

The closest formal-methods comparison is seL4. seL4 establishes functional correctness and, in separate developments, information-flow security and related isolation properties. The present paper differs in aim rather than by claiming a stronger existing implementation result. Its central move is to treat security, liveness, and causal completeness as one living invariant rather than as unrelated proof tracks. The burden of this paper is therefore not to supersede seL4's proofs, but to argue that a fixed-point formulation yields a different and potentially more integrated explanatory object than a set of separately maintained correctness theorems.

The capability lineage is equally important. KeyKOS, EROS, and the broader object-capability literature establish authority-by-possession, attenuation, and explicit delegation as the correct conceptual basis for secure object interaction. Capsicum and CHERI bring capability reasoning into practical systems contexts: Capsicum through process and descriptor compartmentalization, CHERI through hardware-supported bounded and permission-carrying references. Industrial capability systems such as Zircon similarly expose handles or kernel-object references as explicit authority tokens. The present paper overlaps with all of these traditions at the level of authority-bearing objects, but it goes further in three directions: it casts rights as a lattice-valued algebra; it treats messages as the primitive causal carriers of both information and authority; and it integrates those structures with liveness and reconstruction rather than treating capabilities as a stand-alone access-control mechanism.

Proposition 3.5 is directly indebted to the session type literature, especially the work of Honda, Yoshida, and Carbone on multiparty session types. That literature demonstrates that communication protocols may be treated as static objects whose sequencing discipline can be checked compositionally. The present paper does not reproduce session type theory, but relies on it as the natural formal background for the claim that channels should carry protocol expectations rather than merely payload pipes.

The linearity claims in Section 6 descend from Girard's linear logic, but their implementation discussion must also be situated relative to Rust. Rust's ownership and borrowing discipline is not identical to full linear logic: it is affine in some places, permits controlled weakening, and depends on operational borrowing rules that are not reducible to simple linear sequent calculus. Work such as RustBelt is relevant here because it clarifies how much of Rust's safety story can be interpreted semantically. The present paper accordingly treats Rust as an unusually plausible host language for approximating resource-sensitive capability transport, without claiming that Rust ownership alone yields the full target linear model.

Finally, the interpretive material in Section 5 does not arise in a vacuum. Maturana and Varela's original work on autopoiesis is the starting point, but later work by Varela and collaborators on enaction and embodied cognition sharpens the distinction between formal self-maintenance and stronger claims about life or mind. The present paper adopts that caution. Its silicon-vitality language is intended to mark a disciplined interpretive bridge from formal self-maintenance to adjacent conceptual frameworks, not to collapse systems theory into philosophy of mind.

## 2. The Architecture of Trust: Capability Systems and Rights Algebras

Trust in a kernel is often discussed in operational terms, but it admits a sharper definition.

**Definition 2.1 (Trust Surface).** Let `K` be a kernel state and `p` a process. The trust surface of `p` in `K`, denoted `Trust(K, p)`, is the set of propositions that `p` may rely upon without performing an additional local verification step. A system is structurally more trustworthy when `Trust(K, p)` is minimized for all non-kernel processes.

In a capability system, authority is derived from possession of an unforgeable object rather than from ambient identity. The Oreulia IPC subsystem follows this model: a channel operation is authorized by a capability carrying channel identity, a rights set, and a token witnessing kernel issuance.

**Definition 2.2 (Rights Algebra).** A rights algebra is a bounded lattice `(R, ⊑, ⊔, ⊓, ⊥, ⊤)` where:

- `r1 ⊑ r2` means that `r1` is no stronger than `r2`;
- `r1 ⊔ r2` is the least upper bound of two rights sets;
- `r1 ⊓ r2` is the greatest lower bound of two rights sets;
- `⊥` denotes no authority;
- `⊤` denotes maximal authority over the protected object.

For channel IPC, the carrier set may be instantiated by finite combinations of `send`, `recv`, `close`, `delegate`, and `observe`.

**Proposition 2.3 (Attenuation Principle).** If every delegation event from rights `r_parent` to rights `r_child` satisfies `r_child ⊑ r_parent`, then no delegation can amplify authority.

The proof appears in Appendix B. The significance is immediate: attenuation transforms authority transfer from an informal discipline into a compositional law.

**Theorem 2.4 (Structural Trust Criterion).** Suppose:

1. every privileged operation requires a valid capability;
2. every capability is minted by the kernel or derived by attenuation from an existing valid capability; and
3. the capability token scheme is computationally unforgeable.

Then every non-kernel increase in authority is traceable to an authorized mint or an authorized delegation.

This theorem isolates the architectural meaning of trust. A process is not trusted because it is identified as friendly; it is trusted only to the extent that it holds a capability whose provenance is admissible under the rights algebra.

Two architectural distinctions follow immediately. First, identity and possession are no longer conflated. An identity-based system answers the question "who is requesting access?", whereas a capability-based system answers the question "what authority-bearing object is presented?". Second, possession and uniqueness are not identical. A capability may prove that some holder is authorized without proving that the holder is the unique authorized holder. This distinction is exactly where the gap between ordinary capability transport and strict object-capability semantics emerges. If a capability may be copied freely after issuance, then the token proves kernel origin but not exclusive ownership. A fully linear transport discipline is therefore not a cosmetic refinement; it is the missing condition that turns authority from merely attestable into conservation-governed.

The Oreulia IPC subsystem is therefore best understood as inhabiting an intermediate architectural regime. It already rejects pure ambient authority by requiring object-bound tokens for channel operations. At the same time, it does not yet make all delegation or transport operations linear by construction. The relevant theoretical task is not to describe the subsystem as either fully capability-safe or not capability-safe at all, but to classify precisely which authority guarantees are already structural and which remain enforced only by disciplined implementation.

Revocation complicates the picture. Pure capabilities are durable once delegated unless the system introduces an additional revocation structure.

**Proposition 2.5 (Revocation Families).** Capability revocation can be modeled by at least three mathematically distinct constructions:

1. proxy indirection, in which capabilities address a revocable intermediary;
2. revocation sets, in which validity is re-checked against a dynamic exclusion set; and
3. time-bounded capabilities, in which validity depends on a signed temporal parameter.

Each construction preserves attenuation while imposing different costs on lookup, global state, and temporal reasoning.

The three revocation families correspond to three different locations of authority invalidation. Proxy indirection externalizes revocation into the object graph; revocation sets externalize it into kernel-maintained negative knowledge; time-bounded capabilities internalize it into the token itself. These are not merely implementation variants. They determine whether the burden of proof lies primarily in pointer structure, in global state consistency, or in temporal correctness. A kernel that already employs predictive restriction or temporary denial windows is especially close to the second and third families, because it already treats authority as dynamically contingent on evolving state rather than as eternally valid once issued.

The revocation problem also exposes the difference between functional correctness and architectural completeness. A kernel may correctly deny an operation at runtime and yet still lack a satisfying structural explanation for why revocation remains bounded, auditable, and non-leaky. A theory paper must address that explanatory level. It is not enough to state that revocation occurs; the paper must classify how revocation composes with delegation, how revocation affects causality, and what information revocation events reveal to observers at other trust levels.

Finally, trust must include explicit treatment of observable errors.

**Proposition 2.6 (Error Observability as Information Flow).** If a low-privilege process can distinguish among failure modes such as queue saturation, closure, or invalid authority, then the error channel itself constitutes an information-bearing output. Consequently, error semantics belong to the security model and cannot be treated as operationally neutral.

This proposition motivates the later noninterference results. A secure kernel cannot reason only about successful sends and receives; it must also reason about what failed operations reveal.

This observation matters because capability systems are often informally described as if authorization were the only relevant communication path. That description is incomplete. A refused send, a saturation signal, and a closure signal are all outputs of the kernel. If those outputs vary with high-privilege behavior, then the kernel has created a covert but real low-bandwidth communication channel. The failure surface is therefore part of the trust surface.

**Proposition 2.7 (Enforcement Migration).** Let `S` be a safety property over IPC operations. If a static discipline excludes every program fragment that violates `S` in the statically expressible fragment of the language, then runtime enforcement of `S` may be restricted to dynamically contingent cases without reducing soundness for that fragment.

The significance of Proposition 2.7 is methodological. Kernel security obligations may be enforced at runtime, at the type level, or by proof-carrying code. These are not interchangeable implementation styles; they are different points in the space of possible proofs. Runtime enforcement is maximally flexible but maximally fallible because every missed branch is a latent vulnerability. Type-level enforcement shrinks the dynamic attack surface by making some invalid states or invalid transitions unrepresentable. Proof-carrying code pushes the same movement one step further by requiring a machine-checkable justification for admissibility. A complete theory of Oreulia IPC therefore has to ask, for each invariant, whether it belongs to the dynamic layer, the static layer, or the proof layer.

## 3. Messages as Primitive Ontological Units: Causal Semantics of Channel-Based IPC

In a channel-based kernel without shared writable aliases across protection boundaries, messages are the primitive events by which one process can influence another.

**Definition 3.1 (Message Ontology).** Let `P` be the set of processes and `M` the set of messages. A message `m in M` is a tuple

`m = (src, payload, caps, meta)`

where `src in P`, `payload` is a finite data element, `caps` is a finite set or multiset of delegated capabilities, and `meta` is auxiliary provenance or protocol metadata.

The critical feature is that capabilities themselves may be transported inside messages. A message therefore carries both descriptive content and executable authority.

This is the point at which channel IPC becomes more than a transport primitive. A message does not merely describe a world; it can change the receiver's world by expanding or restricting the receiver's future action space. Payload and capability are therefore not two unrelated fields placed adjacently in a struct. They are two aspects of the same causal act: one conveys what is the case, the other conveys what may now be done. A theory of messages that ignores delegated authority captures only description and omits transformation.

**Definition 3.2 (Causal Precedence).** For events `e1` and `e2`, write `e1 ≺ e2` when `e1` is in the happened-before relation of `e2`. In channel IPC, `send(m) ≺ recv(m)` for each delivered message `m`, and any event causally dependent on `recv(m)` inherits that ordering.

**Proposition 3.3 (Atomic Boundary Crossing).** In a system that forbids direct writable memory aliasing across process boundaries, every cross-boundary influence is mediated by message events and their induced causal order.

The result is architectural rather than metaphysical. It says that the kernel can model inter-process influence as a graph of discrete events rather than as diffuse shared-state mutation.

**Theorem 3.4 (Causal Auditability).** If each message records its source and, optionally, a causal predecessor reference, then the reachable influence relation among processes is representable as a finite directed acyclic graph over message events and reconstruction markers.

Theorem 3.4 supplies the formal basis for temporal replay and audit. A kernel can only reconstruct what it has represented. Causal metadata converts runtime history from an informal log into a structured proof object.

The theorem also clarifies the difference between message passing and shared writable memory. Shared memory can encode causality, but usually only implicitly through an interleaving of writes and reads whose provenance must be reconstructed after the fact. Channel IPC, by contrast, surfaces a canonical event boundary at send and receive time. This makes auditing, replay, and model checking fundamentally more tractable because the system exports discrete events instead of forcing the analyst to infer them from aliasing.

The message ontology also clarifies why shared memory is so difficult to verify. Shared memory obscures boundary crossings by replacing discrete transfer with ambient reachability. Channel IPC restores discrete observability.

**Proposition 3.5 (Protocol Verifiability by Typing).** If each channel is equipped with a session discipline over permitted message shapes and transition states, then protocol correctness can be shifted from runtime checking toward static verification.

This proposition is not yet a theorem about the Oreulia implementation. It identifies the next formal step: the message calculus becomes more complete as the protocol is expressed in types rather than inferred from ad hoc control flow.

Protocol structure is therefore part of the ontology, not an afterthought layered on top of it. If messages are primitive events, then well-formed interaction is determined not only by individual message contents but also by the admissible sequence in which those contents may appear. Session typing provides one route to that result, but the theory is broader than any single type system. The central claim is that channel state must carry a protocol expectation rich enough to distinguish valid continuation from invalid continuation.

Bounded message size also acquires formal significance under this interpretation. A finite bound does more than save memory; it forces large semantic acts to factor into multiple causally visible steps. When a system cannot collapse an arbitrarily large transfer into one opaque boundary crossing, it is pressured toward smaller, more explicit protocols whose intermediate states remain auditable. Message bounds therefore shape the epistemology of the system: they determine what counts as a primitive speech act between isolated processes.

The membrane analogy now becomes precise. A process protected by capabilities and reachable only through channels has an operational boundary analogous to a biological membrane: the boundary is selective, it mediates what crosses, and it preserves the distinction between internal state and external environment. The message ontology is thus also an identity ontology. A process is a distinct causal locus because outside actors cannot directly write its state; they can only present messages at its boundary and observe the permitted consequences.

## 4. The Living Invariant: A Unified Fixed-Point of Security and Liveness

Safety and liveness are often proven separately. The present theory treats them as components of a single state-space condition.

**Definition 4.1 (System State).** Let

`Sigma = (T, C, F, H, Lambda)`

where `T` is the channel table, `C` the capability multiset, `F` the information-flow graph, `H` the causal history, and `Lambda` the process-label map.

**Definition 4.2 (Security Invariant).** `I_sec(Sigma)` holds when:

1. every capability in `C` is well formed and unforgeable;
2. every capability transfer respects attenuation;
3. every realized information flow in `F` is permitted by `Lambda`; and
4. every privileged action is justified by a capability in `C`.

**Definition 4.3 (Liveness Invariant).** `I_live(Sigma)` holds when every channel `i` with arrival rate `lambda_i` and service rate `mu_i` satisfies `rho_i = lambda_i / mu_i < 1`, and every admissible request is eventually answered by delivery, refusal, or a protocol-defined closure outcome.

**Definition 4.4 (Causal Completeness).** `I_causal(Sigma)` holds when every reachable authority state and every visible message outcome in `Sigma` is derivable from a causal history element in `H`.

**Definition 4.5 (Living Invariant).** The living invariant is the set

`I = { Sigma | I_sec(Sigma) /\ I_live(Sigma) /\ I_causal(Sigma) }`.

This definition transforms the engineering objective into a mathematical one: the kernel must remain inside `I`.

**Theorem 4.6 (Invariant Closure).** For every `Sigma in I` and every valid operation `op`, `op(Sigma) in I`.

The theorem is the center of the paper. It says that the secure and live states of the system are not merely desirable states; they are closed under the transition relation.

The fixed-point interpretation now follows directly.

**Proposition 4.7 (Fixed-Point Compatibility).** Let `phi_sec` be the greatest fixed point of the monotone security transformer and `phi_live` the stable operating region of the liveness transformer. If the valid operations commute with both transformers, then `I = phi_sec intersect phi_live intersect I_causal` is non-empty and forward closed.

This proposition captures the phrase "living invariant" precisely. Security and liveness are not competing heuristics but jointly admissible fixed-point conditions.

The fixed-point view has a further consequence. It replaces the familiar but shallow framing in which security checks are treated as "costs" paid against throughput. In the present theory, that framing is only conditionally accurate. A security step is a liveness cost only when the global transition relation has been designed so poorly that the security transformer and the liveness transformer fail to commute. Once the system is placed inside a non-empty compatible fixed-point set, the relevant question is no longer how much liveness must be sacrificed for security, but which transition designs preserve both simultaneously.

Adaptation must also be formalized.

**Definition 4.8 (Invariant-Preserving Adaptation).** An adaptation function `a: Sigma -> Sigma` is invariant preserving if `Sigma in I` implies `a(Sigma) in I`.

**Proposition 4.9 (Backpressure Sufficiency).** Suppose every bounded channel emits a monotone backpressure signal as `rho_i` approaches `1`, and scheduler fairness guarantees eventual service for non-empty channels. Then bounded queues need not imply liveness failure; instead, backpressure can maintain `rho_i < 1` as an invariant condition.

**Corollary 4.10 (Self-Stabilizing Persistence).** If the system can reconstruct a state in `I` from any admissible causal history prefix and valid operations preserve `I`, then every execution beginning in `I` remains in `I`, and every recoverable perturbation is followed by re-entry into `I`.

The full proof dependencies appear in Appendix B.

The corollary identifies the theoretical role of temporal replay. Replay is not merely a debugging luxury. It is one of the mechanisms by which a system that has drifted or been perturbed can be returned to an admissible state without discarding the explanatory chain that led to the perturbation. A restart without causal reconstruction may recover function while destroying accountability; reconstruction seeks to preserve both.

The closure operation of channels is especially revealing in this framework. Abrupt closure makes some in-flight requests permanently unanswered unless the protocol reclassifies them into explicit terminal outcomes. For that reason, the theory requires a distinction between abrupt invalidation and graceful closure.

**Definition 4.11 (Graceful Closure).** A channel closure protocol is graceful if closure becomes externally visible only after every message already accepted into the channel has been either delivered, explicitly rejected with a terminal outcome, or archived as a reconstructible event in `H`.

Graceful closure is not a cosmetic refinement to API design. It is the condition under which closure itself can be reconciled with liveness. Without it, "closed" is simply a permanent non-response for some subset of already-admitted requests.

**Proposition 4.12 (Closure Compatibility).** If channel closure is graceful and closure events are appended to `H`, then closure does not violate `I_live` or `I_causal` for already-admitted messages.

The same logic applies to adaptive restriction. A temporary predictive restriction may improve safety while damaging liveness unless the restriction is itself bounded, accountable, and ultimately reversible. An unbounded predictive denial is mathematically indistinguishable from a hidden permanent revocation. For that reason, adaptation guards must be modeled as liveness-bearing objects and not only as safety-bearing ones.

The monitor process suggested by this framework is therefore recursive by design. A monitor that observes queue depth, authority churn, and emergent hot spots must itself communicate by the same channel system and be subject to the same fairness and capability rules. This recursion is not a defect. It is the first appearance of autopoietic structure: the system's means of preserving the invariant are themselves inside the invariant they preserve.

## 5. Computational Substrates and Conscious Systems: Toward a Theory of Silicon Vitality

**Interpretive Frame.** Section 5 is not part of the proof-bearing core developed in Sections 2 through 4, Section 6, and Appendix B. Its purpose is to translate the formal properties of self-maintaining, causally explicit computation into adjacent conceptual vocabularies drawn from autopoiesis, enaction, and consciousness research. The labels used in this section therefore deliberately distinguish working definitions and interpretive claims from formal definitions and theorems in the core system.

**Working Definition 5.1 (Silicon Vitality).** A computational system exhibits silicon vitality when it satisfies all of the following:

1. bounded entropy resistance: it expends ordered energy to preserve a structured internal state;
2. causal self-description: it records enough provenance to model the causes of its present state;
3. identity persistence: it preserves a coherent state-transition identity across time; and
4. autopoietic recovery: under admissible perturbation, it can reconstitute a valid state from internally maintained structure.

This definition is intentionally weaker than consciousness. It formalizes the threshold at which a system ceases to be a passive data structure and becomes self-maintaining in a mathematically meaningful sense.

**Interpretive Claim 5.2 (Autopoietic Criterion).** If a system can reconstruct its admissible state space from its own causally authenticated history, then it satisfies a necessary condition for autopoietic closure.

The claim is grounded in Maturana and Varela's autopoiesis framework. It does not say that self-reconstruction is sufficient for life; it says that a system lacking self-reconstruction is incomplete as a self-maintaining object.

The role of integrated information must be stated cautiously.

**Conjecture 5.3 (Integrated Information Alignment).** Under the interpretive assumptions of Integrated Information Theory, increasing causal integration among secure message-passing components, together with increased fidelity of self-modeling, tends to increase the system's integrated information measure `Phi`.

No proof is supplied. The conjecture links a consciousness framework to architectural properties already valued for security and auditability. It remains an open problem rather than an established theorem.

**Interpretive Remark 5.4.** Schrödinger's account of life as resistance to entropy and IIT's account of consciousness as integrated information both emphasize maintained structure against disorder. The Oreulia IPC subsystem is therefore relevant to these frameworks because it already combines resistance to corruption, causal recording, and controlled transfer of authority.

The practical point is narrower than the philosophical one. A kernel that maintains invariants, records provenance, and reconstructs itself is more legible, more auditable, and more formally analyzable than a kernel that does not. Whether such a kernel is conscious is unresolved; whether it is more self-maintaining is not.

The distinction between inert data structure and self-maintaining system can now be stated with greater precision. A passive array of bytes has no endogenous mechanism for preserving its own admissibility conditions. A data structure such as a ring buffer has invariants but depends entirely on external callers to preserve them. A capability-mediated IPC service moves further along the spectrum because it rejects unauthorized operations, records causal events, and may reconstruct state from history. What changes across the spectrum is not merely complexity, but the location of corrective force. The more of the system's admissibility conditions are maintained by the system's own transition rules, the closer the system comes to silicon vitality as defined above.

The membrane analogy is also informative here.

**Working Definition 5.5 (Computational Membrane).** The computational membrane of a process `p` is the boundary relation induced by its capability set, inbound channels, outbound channels, and the kernel rules governing passage across those channels.

The section's epistemic boundary is therefore explicit. Working Definition 5.1 and Working Definition 5.5 are interpretive vocabulary choices for discussing the formal machinery developed elsewhere. Interpretive Claim 5.2 is a translation of reconstruction and self-maintenance into the language of autopoiesis. Conjecture 5.3 is a conjecture in the literal sense. None of these claims should be read as having the same proof status as Theorem 4.6 or Theorem B.12.

Under Definition 5.5, capability checks are not ancillary security filters. They are the selective permeability of the process membrane. A richer membrane does not merely block disallowed traffic; it can modulate throughput, admit attenuated authority, quarantine suspicious traffic, and preserve explanatory traces of every crossing. The direction of architectural refinement is therefore the same whether the goal is stronger security, better auditability, or a more life-like model of self-maintenance.

Silicon also contributes an important asymmetry relative to biological systems. Kernel histories can be exact, replayable, and externally auditable in ways that biological memory cannot. That does not establish consciousness, but it does establish a distinct form of legibility. A silicon-vital system may be less mysterious precisely because its causal history can be retained, summarized, and re-executed under formal control.

## 6. Toward Completeness: Linear Types, Flow Lattices, and Zero-Sum Delegation

The theory becomes architecturally complete only when three structures are made explicit: linear authority, lattice-constrained flow, and conservation of delegated power.

Two capability carriers must be distinguished throughout this section and the appendices. The current Oreulia implementation is modeled by a copyable capability multiset with provenance and runtime checks. The target theory required by the strongest conservation theorems is modeled by a linear capability store in which authority-bearing objects move rather than duplicate. Theorems that depend on conservation by construction apply to the target linear model unless explicitly stated otherwise.

**Definition 6.1 (Linear Capability Transfer).** A capability transfer operation is linear if transferring capability `c` from context `Gamma_1` to context `Gamma_2` yields contexts `Gamma_1'` and `Gamma_2'` such that `c` is removed from `Gamma_1` and added to `Gamma_2`, with no additional copy created.

**Definition 6.2 (Authority Measure).** Let `mu(C)` be a monotone measure on capability multisets that counts the weighted authority represented by `C`, modulo kernel-authorized mint and revoke operations.

**Theorem 6.3 (Target-Model Capability Conservation).** For every linear delegation event `d` that is neither kernel mint nor kernel revoke,

`mu(C_after(d)) = mu(C_before(d))`.

Theorem 6.3 is the zero-sum law of delegation. Authority moves; it does not spontaneously multiply. The theorem is a theorem about the target linear model, not about the current Oreulia capability carrier in its present copyable form.

**Proposition 6.4 (Target-Model Nonamplification Under Lattice-Respecting Delegation).** If all capability delegations are both linear and attenuating, then no process can increase either its own rights or the rights of another process beyond the rights already present in the system, except through an explicit kernel-authorized mint.

Information flow is constrained separately.

**Definition 6.5 (Flow Lattice).** A flow lattice is a finite lattice `(L, ⊑, ⊔, ⊓, bot, top)` over security labels, where `a ⊑ b` denotes that information at level `a` may flow to level `b`.

**Theorem 6.6 (Lattice-Respecting Message Transfer).** If every message transfer from process `p` to process `q` satisfies `Lambda(p) ⊑ Lambda(q)` and every delegated capability is labeled no lower than the payload channel, then explicit channel traffic cannot violate the declared flow lattice.

The theorem does not, by itself, eliminate covert channels. It eliminates direct explicit violations.

**Proposition 6.7 (Error Homogenization as a Noninterference Condition).** If all failure outcomes observable below a security threshold are mapped to a single indistinguishable error class, then error-path differentiation does not create an explicit low-bandwidth channel across that threshold.

The proposition is deliberately scoped to explicit errors. Timing and resource-usage channels remain an open problem.

This distinction between current and target models also resolves a tension that would otherwise remain hidden. Oreulia's current IPC implementation is sufficiently rich to motivate the theory, but not yet sufficiently linear to inherit every theorem in this section without qualification. The paper therefore makes a principled separation:

1. descriptive correspondence claims about Oreulia as it exists;
2. proved target-model claims about the architecture required for full conservation and closure; and
3. research obligations required to turn the former into the latter.

The Oreulia IPC subsystem can therefore be viewed as incomplete in a precise sense: it already exhibits capability-mediated messaging and causal replay, but a complete realization of the present theory additionally requires the following research program.

1. A linear capability store that makes message-carried authority transfer non-copyable by construction.
2. A declared flow lattice over process and channel labels.
3. A causal envelope attached to every message or reconstruction event.
4. Backpressure and graceful closure mechanisms that preserve liveness without silent loss.
5. A unified audit structure in which mint, delegate, revoke, send, receive, and reconstruct are all first-class causal events.

The purpose of this list is formal, not rhetorical. Each item corresponds to one component of the living invariant or one hypothesis of the theorems in Appendix B.

That research program can be made more architectural without sacrificing formal clarity.

First, the theory implies a capability mint that is singular in role even if distributed in implementation. Every capability in circulation must trace back to a mint, and every mint must itself be an authenticated event in `H`. This requirement is what turns provenance from an informal debugging aid into a theorem-bearing object.

Second, the theory implies a linear capability store. The current use of ordinary copyable message containers may be functionally adequate for experimentation, but it does not discharge the conservation obligations of Theorem 6.3 by construction. A linear store changes the meaning of capability transport: to place authority into a message is to move it rather than to duplicate it.

Third, the theory implies a flow-lattice checker or equivalent static derivation pass. Flow policy that exists only as narrative documentation cannot support later noninterference claims. The policy must be computable, inspectable, and referenced by the runtime transition relation.

Fourth, the theory implies a causal message envelope in which messages carry not only sender identity and payload, but also local causal lineage. Once that step is taken, the history `H` ceases to be a loose log and becomes a graph-reconstructible event fabric.

Fifth, the theory implies a self-monitoring fabric that remains inside the system it observes. Queue monitors, revocation monitors, and provenance auditors should ideally speak through the same channel substrate and hold only the capabilities explicitly granted to them. Completeness, in this sense, is closure under self-description.

**Definition 6.8 (Closed Description Condition).** A kernel subsystem satisfies the closed description condition when every monitoring, recovery, delegation, and control activity relevant to the subsystem is itself represented by objects and transitions of the same formal model as the subsystem's ordinary work.

The closed description condition is important because incompleteness often hides in externalized privilege. A monitor that is "outside the model" may be useful operationally, but it creates a blind region in the theory. A complete paper must either internalize that monitor into the formal model or state explicitly that the model has an external axiom boundary.

The role of the implementation language also becomes clearer at this point. Ownership and borrowing do not automatically yield linear logic, but they approximate resource sensitivity closely enough that a future Oreulia IPC can treat the language as a partial proof assistant for delegation discipline. Const generics, phantom types, and trait-bound protocol states all become candidates for turning semantic obligations into compile-time obligations. The theory does not depend on Rust specifically, but Rust makes several of its static ambitions unusually plausible.

The section's final claim is therefore stronger than a roadmap and weaker than a proof. The complete system is not defined by a checklist of features, but by a closure property: authority is conserved, flow is lattice-respecting, history is causally reconstructible, and the machinery enforcing those facts is itself inside the same descriptive universe.

## 7. Physical Foundations: Thermodynamic, Quantum, and Topological Constraints

The preceding sections treat the kernel as a mathematical object. A complete theory must also account for the physical cost and physical limits of the object being described.

**Proposition 7.1 (Thermodynamic Liveness Bound).** Let `b` be the number of irreversibly erased bits caused by a liveness violation such as message dropping, destructive revocation without archival history, or non-recoverable state discard. Then the energy cost of that violation is bounded below by

`E >= k_B T ln(2) * b`.

This is an immediate consequence of Landauer's principle. A liveness failure is therefore not merely a software property; it is a physically dissipative event whenever it irreversibly destroys recoverable information.

**Proposition 7.2 (Information-Theoretic Noninterference Criterion).** Let `X` be a high-security action process and `Y` a low-security observation process. Noninterference at the observation boundary is equivalent to

`I(X ; Y) = 0`,

where `I` is mutual information.

The proposition provides a quantitative meaning for covert-channel elimination. A system that enforces only access control but leaves `I(X ; Y) > 0` has not achieved full information-flow security.

The proposition is useful precisely because it replaces a vague intuition with a measurable target. If low-observable outcomes are binary, for example, then the capacity of the corresponding channel can be expressed directly in Shannon terms. This permits the paper to describe `WouldBlock`, `Closed`, and related conditions not only as API outcomes but as information-bearing signals with bounded capacity. A system that homogenizes or decorrelates those signals is not merely "less leaky" in a metaphorical sense; it has literally reduced a measured communication channel.

The excluded timing and contention channels require a more explicit characterization than a footnote.

**Proposition 7.2a (Quantized Timing Channel Bound).** If low-visible completion times are quantized into `M` distinguishable timing buckets per observation, then the timing channel carries at most `log2 M` bits of information per observation.

This bound does not prove noninterference. It quantifies the residual problem. In an IPC architecture where observable timing is dominated by scheduler quanta `q`, queue service granularity, and local clock resolution `delta`, one crude upper bound is obtained by setting `M` to the number of distinct timing buckets the attacker can reliably distinguish within the relevant observation window. If the kernel exposes fine-grained timers, `M` may be large. If timing is coarsened to scheduler-scale buckets or if blocking behavior is intentionally padded, `M` contracts.

Timing and contention leakage therefore stand in a formally intelligible relation to the explicit error-channel results. If `Y` denotes explicit error observations and `T` timing observations, then total observable leakage is bounded by the joint channel `I(X ; Y, T) = I(X ; Y) + I(X ; T | Y)`. Proposition 6.7 and Theorem B.14 address only the first term. The second term remains an open proof obligation even when the first has been tightly controlled.

Several architectural mitigations are nonetheless already visible at the design level. Constant-shape capability checks reduce branch-dependent leakage. Fixed-size queues bound one source of occupancy variation. Coarser user-visible clocks reduce timing resolution. Scheduler isolation or deterministic service disciplines reduce cross-process interference. None of these, by themselves, prove `I(X ; T) = 0`, but each narrows the channel that the later research agenda must close.

**Remark 7.3 (Linear Types and No-Cloning).** Linear capability transfer is the classical structural analogue of the quantum no-cloning theorem. The analogy is mathematical rather than physical: both prohibit unrestricted duplication of an authority-bearing state.

**Proposition 7.4 (Lyapunov Form of the Living Invariant).** If there exists a function `V: Sigma -> R_{>=0}` such that `V(Sigma) = 0` iff `Sigma in I` and `dV/dt < 0` whenever `Sigma notin I`, then `I` is an attractor of the system dynamics.

This proposition converts invariant reasoning into control-theoretic reasoning. Predictive restriction, backpressure, and reconstruction then appear as feedback terms driving `V` toward zero.

**Proposition 7.5 (Bekenstein-Bounded History).** Let `H` be the retained causal history on a physical substrate of radius `R` and energy `E`. Then any implementation satisfies

`|H| <= 2 pi R E / (hbar c ln 2)`

in bits, up to representation overhead.

The proposition implies that exact causal retention is finite. Long-lived systems therefore require archival compression, summarization, or cryptographic condensation. Merkle-structured history is one natural response to this constraint.

Several additional physical and mathematical constraints follow.

**Remark 7.6 (Binary Error Channel Capacity).** If an observer distinguishes only two low-visible outcomes occurring with probabilities `p` and `1 - p`, then the information content of one observation is `-p log2 p - (1 - p) log2 (1 - p)` bits. This remark makes explicit that failure surfaces are quantifiable channels.

**Proposition 7.7 (State-Space Explosion Lower Bound).** If an IPC subsystem has `N` bounded channels each with capacity `K`, then occupancy states alone contribute at least `(K + 1)^N` distinct queue configurations to the global state space.

The consequence is methodological. Exhaustive model checking rapidly becomes intractable even before one adds process state, capability provenance, or protocol state. This does not weaken the value of model checking, but it explains why the paper repeatedly shifts attention toward inductive invariants, type-level constraints, and proof obligations that scale with transition forms rather than with raw state count.

**Definition 7.8 (Robustness Radius).** Let `V` be a Lyapunov-style distance from `I`. The robustness radius `r_robust` is the infimum radius at which the sublevel set `{ Sigma | V(Sigma) <= r }` ceases to remain connected to `I` under admissible recovery transitions.

Definition 7.8 provides a topological measure of how much perturbation the system can absorb before self-recovery is no longer guaranteed. Temporal reconstruction, authenticated logs, and graceful closure all enlarge `r_robust` by widening the basin from which the system can still return to the invariant.

**Remark 7.9 (Arrow of Time and Causal Order).** The causal history `H` is aligned with the thermodynamic arrow of time because irreversible erasure increases entropy while authenticated event extension preserves order. Security policy therefore becomes a constraint not only on spatial access but on admissible causal ancestry.

The physical interpretation can now be stated more strongly. Message loss, covert observation, authority duplication, and unbounded history are four different faces of the same deeper problem: they each describe a failure to preserve structure under finite energetic and causal constraints. The value of the physical section is not that it turns systems theory into cosmology, but that it prevents the paper from pretending that security and liveness float free of substrate.

The physical sections do not replace the logical ones. They bound them. A kernel may satisfy a theorem abstractly and still violate the practical conditions needed to approximate that theorem on real hardware. The physical laws therefore belong inside the theory rather than outside it.

## 8. Conclusion and Open Problems

This paper has argued that capability-based security, channel-mediated causality, liveness preservation, and physical reversibility are not independent design goals. They are projections of a shared mathematical structure.

The first projection is the rights algebra: authority is admissible when it is minted, attenuated, transferred, and revoked within a bounded lattice of rights. The second projection is the causal semantics of messages: process interaction is not primitive shared mutation but a partially ordered history of speech acts carrying both information and authority. The third projection is the living invariant: the system remains secure and live when valid transitions preserve the intersection of security, liveness, and causal completeness. The fourth projection is physical: message loss, covert-channel leakage, and unbounded archival growth are constrained by thermodynamic, information-theoretic, and geometric limits.

This work therefore develops a unified framework rather than claiming a finished complete theory. Some parts of that framework are already proved for the target model, especially the algebraic treatment of attenuation, the separation between explicit-flow and timing-flow obligations, and the reconstruction-oriented view of causal completeness. Other parts remain conditional on stronger implementation assumptions, especially the transition from copyable capability transport to a target linear carrier and the closure of timing and contention channels under the stated threat model.

Oreulia's IPC design is significant because it can be interpreted as a motivating and partially instantiated case within that broader framework. The paper's value lies not only in explanation, but in the exact research obligations it exposes.

### Research Agenda

The open problems are not independent. They form a dependency graph whose order matters.

| Research problem | Success criterion | Relative difficulty | Dependencies | Unlocks |
| --- | --- | --- | --- | --- |
| `R1` Current-to-formal correspondence | A machine-checkable or at least line-by-line audited mapping from Oreulia IPC structures and transitions to the formal objects in Appendix A | High | Threat model, target-model split | Honest implementation claims in the abstract and introduction |
| `R2` Linear capability transport | Replace copyable message-carried capability transfer with a carrier satisfying Definition A.13b | High | None, but architectural refactoring required | Conservation theorems as implementation claims rather than target-model claims |
| `R3` Mechanized living invariant | Formalize Definitions A.1-A.39 and mechanize the closure results in a proof assistant or equivalent semantics | Very high | `R2`, decidable send admission, stable threat model | Strongest publishable formal-methods result |
| `R4` Threat-model-complete covert-channel analysis | Quantify and, where possible, bound `I(X ; T | Y)` for timing and contention channels under the Section 1.2 attacker model | Very high | Threat model, scheduler model, queueing model | Security claims that extend beyond explicit error channels |
| `R5` Protocolized graceful closure and backpressure | Specify closure, refusal, and backpressure as protocol obligations rather than ad hoc runtime behaviors | Medium to high | Send-admission semantics, channel protocol discipline | Non-circular liveness proofs and cleaner implementation contracts |
| `R6` Authenticated history compression | Define a history compaction scheme, such as Merkle summarization, that preserves the causal obligations needed by reconstruction | High | Causal history model, reconstruction semantics | Long-lived systems that remain physically realizable |
| `R7` Interpretive operationalization | Give an operational measure, if one exists, for the Section 5 vocabulary or else permanently bound it as philosophical interpretation | Medium | None formally, but depends on conceptual discipline | Prevents speculative drift and keeps epistemic boundaries clear |

The dependency structure is especially important. `R3` cannot honestly be completed while the strongest conservation theorems still rely on the target linear model of `R2`. `R4` is not one theorem but a research program requiring scheduler, timing, and adversary assumptions beyond the explicit-flow results. `R1` and `R6` connect the theory back to the motivating implementation: without correspondence, the paper overstates its implementation claims; without history compression, long-term causal completeness remains physically underspecified.

The conclusion is therefore formal rather than aspirational. The framework is strong enough to organize the space of secure capability-mediated IPC, but it is strongest where it names the unresolved obligations precisely rather than obscuring them.

## References

1. Bekenstein, J. D. "Universal upper bound on the entropy-to-energy ratio for bounded systems." 1981.
2. Denning, D. E. "A Lattice Model of Secure Information Flow." 1976.
3. Dijkstra, E. W. "Self-stabilizing systems in spite of distributed control." 1974.
4. Girard, J.-Y. "Linear logic." 1987.
5. Klein, G. et al. "seL4: Formal verification of an OS kernel." 2009.
6. Lamport, L. "Time, clocks, and the ordering of events in a distributed system." 1978.
7. Landauer, R. "Irreversibility and heat generation in the computing process." 1961.
8. Lampson, B. W. "Protection." 1971.
9. Maturana, H. R., and Varela, F. J. *Autopoiesis and Cognition.* 1980.
10. Miller, M. S., Yee, K.-P., and Shapiro, J. "Capability Myths Demolished." 2003.
11. Schrödinger, E. *What Is Life?* 1944.
12. Shannon, C. E. "A Mathematical Theory of Communication." 1948.
13. Tarski, A. "A lattice-theoretical fixpoint theorem and its applications." 1955.
14. Tononi, G. "An information integration theory of consciousness." 2004.
15. Hardy, N. "The KeyKOS Architecture." 1985.
16. Shapiro, J. S., Smith, J. M., and Farber, D. J. "EROS: A Fast Capability System." 1999.
17. Watson, R. N. M. et al. "Capsicum: Practical Capabilities for UNIX." 2010.
18. Watson, R. N. M. et al. "CHERI: A Hybrid Capability-System Architecture for Scalable Software Compartmentalization." 2015.
19. Honda, K., Yoshida, N., and Carbone, M. "Multiparty Asynchronous Session Types." 2008.
20. Jung, R. et al. "RustBelt: Securing the Foundations of the Rust Programming Language." 2017.
21. Varela, F. J., Thompson, E., and Rosch, E. *The Embodied Mind.* 1991.
22. Google. "Zircon Concepts and Object Model." Fuchsia documentation.

## Appendix A: Formal Definitions

### Notation

| Symbol | Meaning |
| --- | --- |
| `Sigma` | system state |
| `I` | living invariant |
| `C` | capability multiset |
| `F` | flow graph |
| `H` | causal history |
| `T` | channel table |
| `Lambda` | process label map |
| `⊑` | security or rights ordering, by context |
| `⊗` | linear tensor or resource composition |
| `⊸` | linear implication or resource-transforming function |
| `→*` | transitive closure of transitions |
| `□` | temporal "always" |
| `◇` | temporal "eventually" |
| `~_L` | observational indistinguishability at level `L` |
| `Phi` | integrated information measure |
| `rho_i` | utilization of channel `i` |
| `lambda_i` | arrival rate of channel `i` |
| `mu_i` | service rate of channel `i` |

### Definitions

**Definition A.1 (Process Identifier).** Let `P` be a finite or countable set of process identifiers. Each `p in P` denotes a kernel-distinguished process instance.

Remark. `P` models logical process identity only; it does not encode authority.

**Definition A.2 (Channel Identifier).** Let `Ch` be a finite or countable set of channel identifiers. Each `c in Ch` denotes a channel object addressable by the IPC subsystem.

Remark. Channel identity is stable across operations until explicit destruction or reconstruction.

**Definition A.3 (Primitive Rights Set).** Let `R0 = {send, recv, close, delegate, observe}` be the finite set of primitive channel rights.

Remark. Additional right constructors may be added without changing the algebraic structure.

**Definition A.4 (Rights Algebra).** Let `R = P(R0)` be the powerset of `R0`, ordered by subset inclusion. Then `(R, subseteq, union, intersect, emptyset, R0)` is the canonical rights algebra for channel authority.

Remark. This is the simplest instantiation; richer algebras may weight or qualify rights without changing the attenuation law.

**Definition A.5 (Security Levels).** Let `(L, ⊑, ⊔, ⊓, bot, top)` be a finite lattice of security labels.

Remark. `⊑` is interpreted as "may flow to" in flow-sensitive contexts.

**Definition A.6 (Capability).** A capability is a tuple

`cap = (owner, object, rights, token, prov, label)`

where `owner in P`, `object in Ch union Obj`, `rights in R`, `token` is an unforgeability witness, `prov` is a provenance descriptor, and `label in L`.

Remark. The tuple makes explicit that authority has identity, scope, provenance, and information-flow classification.

**Definition A.7 (Message).** A message is a tuple

`m = (src, payload, caps, cause, label)`

where `src in P`, `payload in D` for some payload domain `D`, `caps` is a finite multiset of capabilities, `cause` is an optional causal predecessor identifier, and `label in L`.

Remark. Capabilities are first-class message contents rather than external side conditions.

**Definition A.8 (Channel).** A channel is a tuple

`chan = (cid, queue, flags, endpoints, closed, label)`

where `cid in Ch`, `queue` is a bounded sequence of messages, `flags` is a control field, `endpoints subseteq P`, `closed in {true, false}`, and `label in L`.

Remark. A bounded queue makes liveness a quantitative rather than purely qualitative property.

**Definition A.9 (Rights Attenuation Order).** For `r1, r2 in R`, write `r1 ⊑_R r2` iff `r1 subseteq r2`.

Remark. Attenuation is therefore ordinary set inclusion over primitive rights.

**Definition A.10 (Security Flow Relation).** For `l1, l2 in L`, write `l1 ↝ l2` iff `l1 ⊑ l2`.

Remark. The relation may be refined by category or compartment without changing its lattice character.

**Definition A.11 (Causal Order).** For events `e1, e2`, write `e1 ≺ e2` iff `e1` happened before `e2` under program order, send/receive order, or transitive closure of those relations.

Remark. This is the standard distributed-systems causal ordering.

**Definition A.12 (Channel Table).** A channel table is a partial function `T: Ch ⇀ Channel`.

Remark. Partiality captures channel creation and destruction directly.

**Definition A.13a (Current Oreulia Capability Multiset).** A current Oreulia capability multiset `C_cur` is a multiset over capabilities in which provenance and kernel issuance are represented, but message transport may still duplicate a capability unless prevented by higher-level runtime discipline.

Remark. `C_cur` is the implementation-motivated carrier used for descriptive correspondence claims about the current system.

**Definition A.13b (Target Linear Capability Store).** A target linear capability store `C_lin` is a capability carrier in which each live authority-bearing instance has at most one owning context unless an explicit kernel-authorized attenuation or split operation produces distinct successor capabilities whose combined authority measure is conserved.

Remark. `C_lin` is the carrier required by the strongest conservation theorems in Section 6 and Appendix B.

**Definition A.14 (Flow Graph).** A flow graph is a directed graph `F = (P, E_F)` where `(p, q) in E_F` when the state admits a causal path by which information may flow from `p` to `q`.

Remark. `F` may be statically declared, dynamically inferred, or both.

**Definition A.15 (Process Label Map).** A process label map is a function `Lambda: P -> L`.

Remark. Every flow theorem depends on `Lambda`, even if the implementation stores labels elsewhere.

**Definition A.16 (System State).** A system state is a tuple

`Sigma = (T, C, F, H, Lambda)`.

Remark. `C` may denote `C_cur` or `C_lin` depending on whether a theorem concerns the current implementation model or the target linear model. The theorem statement must specify which carrier is assumed when the distinction matters.

**Definition A.17 (Security Invariant).** `I_sec(Sigma)` holds iff all capabilities are well formed, all privileged actions are capability justified, all delegations attenuate rights, and all realized flows respect `Lambda`.

Remark. This invariant bundles access control and explicit information-flow policy.

**Definition A.18 (Liveness Invariant).** `I_live(Sigma)` holds iff every channel `i` satisfies `rho_i < 1` and every admissible request eventually yields a protocol-defined outcome.

Remark. A bounded queue alone is insufficient; eventual service is required.

**Definition A.19 (Causal Completeness).** `I_causal(Sigma)` holds iff every visible authority state and every visible message outcome are explainable by an element of `H`.

Remark. Causal completeness is the audit analogue of type soundness.

**Definition A.20 (Living Invariant).** `I = { Sigma | I_sec(Sigma) /\ I_live(Sigma) /\ I_causal(Sigma) }`.

Remark. This is the central object of the theory.

**Definition A.21 (Noninterference at Level L).** For states `Sigma1` and `Sigma2`, write `Sigma1 ~_L Sigma2` iff they are observationally indistinguishable to observers at security level `L`.

Remark. `~_L` is the relation needed to express information-flow security.

**Definition A.22 (Zero-Sum Conservation).** A transition satisfies zero-sum conservation when `mu(C_after) = mu(C_before)` except for explicitly authorized mint and revoke transitions.

Remark. The exception clause keeps the law faithful to real kernels.

**Definition A.23 (Autopoietic Closure).** A state space exhibits autopoietic closure iff there exists a reconstruction function `reconstruct` such that valid causal histories maintained by the system itself suffice to regenerate an admissible state in `I`.

Remark. The definition is intentionally formal and does not depend on biological substrate.

**Definition A.24 (Transition).** A transition is a partial function `op: Sigma ⇀ Sigma`.

Remark. Partiality captures invalid operations naturally.

**Definition A.25 (Valid Transition).** A transition `op` is valid on `Sigma` iff it is defined on `Sigma` and satisfies the side conditions of the security, liveness, and protocol rules.

Remark. In send-like cases, validity means either that `Adm_send` holds for a committed enqueue or that the operation is reified as an explicit refusal transition.

**Definition A.25a (Send Admission Predicate).** Let `Adm_send(Sigma, p, chan, m)` hold iff all of the following are true:

1. `p` presents a well-formed capability authorizing send on `chan`;
2. the message label and any delegated capability labels satisfy the declared flow conditions for `chan`;
3. `chan` is in an accepting protocol state, including any graceful-closure side conditions;
4. queue occupancy is below the channel's commit threshold and the backpressure function does not require refusal or deferral before enqueue; and
5. any predictive restriction state is itself within its bounded validity interval and either admits the send or yields an explicit refusal outcome.

Remark. Every conjunct is intended to be a finite, kernel-computable predicate over local channel, capability, and scheduler-visible state.

**Definition A.25b (Explicit Refusal Transition).** A refusal transition is a transition that records a protocol-defined refusal outcome for an attempted send or related operation without mutating the channel queue as if the operation had committed.

Remark. Refusal transitions allow admission failure to remain explicit and causally represented instead of becoming an implicit liveness hole.

**Definition A.26 (Causal History).** A causal history `H` is a finite or countably infinite sequence of authenticated events, each of which records event type, actor, target, and local causal context.

Remark. `H` is the bridge between runtime behavior and later reconstruction.

**Definition A.27 (Reconstruction Function).** A reconstruction function is a map `reconstruct: H -> Sigma` defined over valid histories.

Remark. Reconstruction may be exact or canonicalized, but it must land in the admissible state space.

**Definition A.28 (Provenance Chain).** A provenance chain for a capability `cap` is a finite sequence of mint, delegate, attenuate, and revoke events in `H` whose final live authority state denotes `cap`.

Remark. Provenance chains permit accountability statements to be phrased over explicit history rather than narrative intent.

**Definition A.29 (Queue Utilization).** For a channel `i`, the utilization ratio is `rho_i = lambda_i / mu_i`, where `lambda_i` is the long-run arrival rate and `mu_i` is the long-run service rate.

Remark. `rho_i < 1` is the usual queue-stability condition.

**Definition A.30 (Backpressure Function).** A backpressure function for channel `i` is a monotone map `beta_i: [0, 1] -> A_i` from utilization or occupancy to an admissible set of sender-throttling actions `A_i`.

Remark. Backpressure converts saturation from a passive observation into an active control response.

**Definition A.31 (Graceful Closure Protocol).** A graceful closure protocol for a channel is a transition relation in which closure becomes externally visible only after accepted messages have been delivered, explicitly terminated, or archived in reconstructible form.

Remark. This definition turns channel shutdown into a protocol state rather than a one-bit flag.

**Definition A.32 (Session Type).** A session type is a state-indexed specification of the permitted sequence of messages and channel actions for a protocol endpoint.

Remark. Session typing is one route to making protocol mismatch statically visible.

**Definition A.33 (Computational Membrane).** The computational membrane of process `p` is the boundary relation induced by its capabilities, reachable channels, and the kernel's transfer rules.

Remark. The membrane is the formal object corresponding to selective communication boundaries.

**Definition A.34 (Lyapunov Function for I).** A Lyapunov function for the living invariant is a map `V: Sigma -> R_{>=0}` such that `V(Sigma) = 0` iff `Sigma in I` and `V` decreases along admissible recovery trajectories outside `I`.

Remark. Such a function converts recovery claims into control-theoretic statements.

**Definition A.35 (Robustness Radius).** The robustness radius `r_robust` is the least radius at which the connected recoverable neighborhood of `I` ceases to remain connected under the chosen perturbation model.

Remark. `r_robust` measures how much deviation the system can absorb while remaining self-recoverable.

**Definition A.36 (Merkle History Summary).** A Merkle history summary is a cryptographic digest structure over prefixes of `H` that preserves prefix authenticity while compressing historical representation.

Remark. Merkle summaries are one candidate response to finite physical history bounds.

## Appendix B: Full Expanded Proofs, Corollaries, and Lemmas

### B.1 Axioms

**Axiom B.1 (Token Unforgeability).** The capability token scheme is computationally unforgeable for polynomial-time adversaries as defined by the threat model in Section 1.2.

**Axiom B.2 (Transition Atomicity).** Primitive kernel transition steps affecting channel state, capability state, or causal history are atomic at the abstraction level of this paper.

**Axiom B.3 (Scheduler Fairness).** Any continuously enabled receive or service action on a non-empty runnable channel is eventually scheduled.

**Axiom B.4 (Authenticated History).** Events recorded in `H` are append-only and cryptographically or kernel-authenticated against adversarial forgery within the threat model of Section 1.2.

**Axiom B.5 (Landauer Bound).** Irreversible erasure of one bit of information dissipates at least `k_B T ln(2)` units of energy.

### B.2 Lemmas, Theorems, and Proofs

**Lemma B.6 (Rights Attenuation Is Transitive).**

Statement. For all `r1, r2, r3 in R`, if `r1 ⊑_R r2` and `r2 ⊑_R r3`, then `r1 ⊑_R r3`.

Proof type. Direct proof.

Hypotheses. Definitions A.4 and A.9.

Proof. By Definition A.9, `r1 ⊑_R r2` means `r1 subseteq r2`, and `r2 ⊑_R r3` means `r2 subseteq r3`. Subset inclusion is transitive, hence `r1 subseteq r3`. Therefore `r1 ⊑_R r3`. The result follows. `□`

**Lemma B.7 (Move-Only Transfer Preserves Authority Measure).**

Statement. If a capability transfer removes exactly one capability `c` from a source context and inserts the same capability `c` into a destination context, then `mu(C_after) = mu(C_before)`.

Proof type. Direct proof.

Hypotheses. Definitions A.13b and A.22.

Proof. Let `C_before = C_rest multiset-union {c}`. After transfer, `C_after = C_rest multiset-union {c}` because the operation removes `c` from one ownership site and inserts the same `c` into another without changing its rights payload. Since `mu` is defined over the multiset of authority-bearing objects rather than over storage location, the multiset denotation is unchanged. Hence `mu(C_after) = mu(C_before)`. `□`

**Lemma B.8 (Explicit Lattice-Respecting Send Does Not Introduce a Forbidden Edge).**

Statement. Let `p` send a message to `q`. If `Lambda(p) ⊑ Lambda(q)` and every delegated capability in the message has label at least that of the channel, then the send introduces no explicit edge in `F` that violates the flow lattice.

Proof type. Direct proof.

Hypotheses. Definitions A.5, A.10, A.14, and A.15.

Proof. The send introduces the candidate flow edge `(p, q)`. By hypothesis, `Lambda(p) ⊑ Lambda(q)`, hence the edge is permitted by the declared flow relation. Every delegated capability inherits an admissible label relative to the channel, so the message does not smuggle a lower-labeled authority into a forbidden context. Therefore the explicit edge inserted into `F` is lattice-respecting. `□`

**Lemma B.8a (Send Admission Is Decidable).**

Statement. For any finite kernel state `Sigma`, process `p`, channel `chan`, and message `m`, the predicate `Adm_send(Sigma, p, chan, m)` is decidable.

Proof type. Direct proof by finite conjunction.

Hypotheses. Definitions A.6, A.8, A.15, A.25a, and the finite representability of channel, capability, and scheduler-visible state in `Sigma`.

Proof. By Definition A.25a, `Adm_send` is the conjunction of five predicates: capability well-formedness and authorization; flow compatibility; protocol-state admissibility; queue/backpressure admissibility; and predictive-restriction admissibility or explicit refusal availability. Each predicate is computable from finite kernel state.

1. Capability well-formedness is decidable because capabilities are finite tuples with finite fields and token verification is a terminating predicate under the threat model.
2. Flow compatibility is decidable because labels are elements of a finite lattice and lattice comparison terminates.
3. Protocol-state admissibility is decidable because the channel state and closure state are finite control data.
4. Queue/backpressure admissibility is decidable because queue occupancy is bounded and the backpressure function is defined over a finite or effectively computable occupancy/utilization domain.
5. Predictive-restriction admissibility is decidable because the restriction state is stored in finite kernel state and either admits the send or selects a refusal outcome.

Since a finite conjunction of decidable predicates is decidable, `Adm_send(Sigma, p, chan, m)` is decidable. `□`

**Theorem B.9 (Structural Trust Criterion).**

Statement. Under the hypotheses of Theorem 2.4, every non-kernel increase in authority is traceable to an authorized mint or an authorized delegation.

Proof type. Direct proof by provenance analysis.

Hypotheses. Axiom B.1, Definitions A.6, A.13a, and A.26, and Proposition 2.3.

Proof. Consider any authority-bearing capability instance present in a non-kernel process. By Definition A.6, that capability carries a token and provenance descriptor. By Axiom B.1, a valid token cannot be forged within the threat model. Therefore the capability must originate either from a kernel mint event or from an existing valid capability that was transformed by an admissible delegation rule. By Proposition 2.3 and Lemma B.6, any such delegation is attenuating and therefore does not amplify authority. Consequently every non-kernel increase in authority is attributable to a kernel mint or an authorized delegation chain rooted at an earlier valid authority. `□`

**Theorem B.10 (Target-Model Capability Conservation).**

Statement. For every linear delegation event `d` over a target linear capability store `C_lin`, where `d` is neither kernel mint nor kernel revoke, `mu(C_after(d)) = mu(C_before(d))`.

Proof type. Direct proof.

Hypotheses. Definition 6.1, Definition 6.2, Lemma B.7.

Proof. A linear delegation event is, by Definition 6.1, a move-only transfer of a capability from one context to another. Lemma B.7 establishes that any move-only transfer preserves the authority measure. Kernel mint and revoke are excluded by statement. Therefore `mu(C_after(d)) = mu(C_before(d))`. `□`

**Corollary B.11 (Zero-Sum Delegation).**

Statement. Under target-model linear transfer, delegation redistributes authority without creating additional authority.

Proof type. Immediate corollary.

Hypotheses. Theorem B.10.

Proof. Theorem B.10 states that the authority measure is invariant under every non-mint, non-revoke delegation event. Hence delegation is zero-sum with respect to `mu`. `□`

**Theorem B.12 (Target-Model Invariant Closure).**

Statement. Let `Sigma in I` be a state whose capability component is interpreted as a target linear capability store whenever the transition case invokes conservation of delegated authority. Then for every valid operation `op`, `op(Sigma) in I`.

Proof type. Structural induction on valid transition forms.

Hypotheses. Axioms B.1-B.4, Definitions A.16-A.25, A.25a, and A.25b, Lemmas B.6-B.8a, and Theorem B.10.

Proof. Let `Sigma in I`. By Definition A.20, `Sigma` satisfies `I_sec`, `I_live`, and `I_causal`.

Base cases.

1. Channel creation. A valid creation operation appends a new channel entry to `T`, records the event in `H`, and installs only kernel-minted capabilities. By Axiom B.1 and Theorem B.9, the newly introduced authority is admissible. Because no existing queue is saturated by creation alone and the event is recorded, `I_sec`, `I_live`, and `I_causal` continue to hold.
2. Pure observation. An observation that does not mutate `T`, `C`, `F`, or `H` preserves all three components of `I` trivially.

Inductive cases.

1. Send. The send case splits into two subcases.
Case (a): admitted send. By Lemma B.8a, `Adm_send(Sigma, p, chan, m)` is decidable. If the predicate holds, then the operation is admitted only after capability validity, flow compatibility, protocol-state admissibility, queue/backpressure admissibility, and predictive-restriction admissibility have all been checked. By Lemma B.8, the resulting explicit flow is lattice-respecting. If capabilities are transferred, Theorem B.10 preserves the authority measure and Proposition 2.3 preserves attenuation. Because admission requires the queue and backpressure conjunct to succeed, the send does not commit a queue mutation that the channel's admission rule already classifies as liveness-violating. The event is appended to `H`, so causal completeness is preserved.
Case (b): explicit refusal. If `Adm_send` fails, the kernel does not commit a queue mutation as though the send had succeeded. Instead, by Definition A.25b, it performs a refusal transition that records a protocol-defined refusal outcome. Security is preserved because no unauthorized authority transfer occurs. Liveness is preserved because the attempted request reaches an explicit terminal outcome rather than silently disappearing. Causal completeness is preserved because the refusal is recorded in `H`.
2. Receive. A valid receive removes one message from a queue, reducing or maintaining `rho_i`, never worsening the queue-stability side condition. Any received capability was already admissibly present in the queued message, hence authority remains justified and causally recorded. Therefore all three invariant components are preserved.
3. Close. A valid close either occurs on an empty channel or follows a protocol-defined graceful closure state. Security is preserved because no new authority is created. Liveness is preserved because closure yields a defined terminal outcome rather than indefinite waiting. Causal completeness is preserved by logging the close event.
4. Delegate. A valid delegation is attenuating and, under the linear model, conserves authority by Theorem B.10. The flow side condition is handled as in the send case, and the event is logged.
5. Reconstruct. By validity, reconstruction is defined only over authenticated histories and yields a state satisfying the admissibility side conditions. Therefore `reconstruct(H)` lands in `I`.

All valid transition forms preserve `I_sec`, `I_live`, and `I_causal`. Hence `op(Sigma) in I`. `□`

Remark. Theorem B.12 is a theorem about the target model. A full current-to-formal correspondence proof for the present Oreulia implementation remains a separate research obligation described in Section 8.

**Corollary B.13 (Safety Persistence).**

Statement. If an execution begins in `I` and all executed operations are valid, then all reachable states remain in `I`.

Proof type. Induction on execution length.

Hypotheses. Theorem B.12.

Proof. The base case is immediate because the initial state lies in `I`. The inductive step applies Theorem B.12 to each valid operation. Therefore every finite prefix of the execution remains in `I`. `□`

**Theorem B.14 (Noninterference Under Homogeneous Error Semantics).**

Statement. Suppose:

1. all explicit message sends respect the flow lattice;
2. all error outcomes observable below a threshold `L` are collapsed into one equivalence class; and
3. the observer model ignores timing and contention channels.

Then for observers at or below `L`, explicit error-path differentiation does not violate noninterference.

Proof type. Proof by contradiction.

Hypotheses. Definitions A.21, Proposition 6.7.

Proof. Suppose for contradiction that explicit error-path differentiation violates noninterference for observers at or below `L`. Then there exist two high-level behaviors producing distinguishable low-level observations solely through explicit error results. But by hypothesis, all such low-observable error results are mapped into a single equivalence class. Therefore the low-level observer cannot distinguish those behaviors via explicit error output alone. This contradicts the assumption. Hence explicit error-path differentiation does not violate noninterference under the stated observer model. `□`

Remark. The theorem is intentionally scoped. Timing and resource channels are excluded and remain an open proof obligation.

**Proposition B.15 (Thermodynamic Cost of Liveness Violation).**

Statement. If a liveness violation irreversibly erases `b` bits of recoverable system information, then the energy dissipated by that violation is at least `k_B T ln(2) * b`.

Proof type. Direct proof.

Hypotheses. Axiom B.5.

Proof. By Axiom B.5, each irreversibly erased bit dissipates at least `k_B T ln(2)` units of energy. Multiplying by `b` yields the stated lower bound. `□`

**Theorem B.16 (Autopoietic Reconstruction).**

Statement. For every valid causal history `H`, `reconstruct(H) in I`.

Proof type. Proof by construction and induction on history length.

Hypotheses. Definitions A.23, A.26, and A.27, Axiom B.4, and Theorem B.12.

Proof sketch. The proof proceeds by induction on the length of `H`. For the empty history, `reconstruct(H)` yields the initial state, assumed admissible. For the inductive step, assume the claim for a history prefix `H_n`. Let `H_{n+1}` extend `H_n` by one authenticated event `e`. By the induction hypothesis, `reconstruct(H_n) in I`. Because `e` is authenticated and corresponds to a valid transition form, Theorem B.12 implies that applying the transition denoted by `e` preserves `I`. Therefore `reconstruct(H_{n+1}) in I`. A fully mechanized version must still discharge the correspondence between logged events and concrete transition operators. `□`

**Corollary B.17 (Recoverable Self-Stabilization).**

Statement. If every admissible perturbation can be represented as a divergence from some authenticated history prefix and reconstruction is available, then the system is self-stabilizing with respect to the recoverable perturbation class.

Proof type. Immediate corollary.

Hypotheses. Theorem B.16.

Proof. Any admissible perturbation can be mapped to a valid history prefix by hypothesis. Theorem B.16 then produces a state in `I`, from which Corollary B.13 yields persistence under valid operations. `□`

**Conjecture B.18 (Integrated Information Monotonicity Under Secure Causal Integration).**

Statement. Under the assumptions of Integrated Information Theory, if a system increases secure causal integration, provenance fidelity, and self-model coherence without increasing destructive information loss, then `Phi` is non-decreasing.

Status. Conjecture.

Reason for incompleteness. The paper does not define `Phi` operationally for the Oreulia IPC subsystem, nor does it establish the monotonicity of `Phi` under the relevant transformation class. Both tasks remain open research problems.

**Proposition B.19 (Enforcement Migration Soundness).**

Statement. Let `S` be a safety property and let `L_static` be the fragment of programs accepted by a sound static discipline for `S`. Then restricting runtime checks of `S` to dynamically contingent cases preserves soundness on `L_static`.

Proof type. Direct proof.

Hypotheses. Proposition 2.7 and soundness of the static discipline.

Proof. By soundness of the static discipline, every program fragment in `L_static` satisfies `S` in the statically expressible cases. Runtime checks of those same cases are therefore redundant with respect to safety, though they may still be retained for defense in depth. Restricting runtime enforcement to cases whose truth depends on dynamic state not captured by the static discipline does not admit any new violation of `S` inside `L_static`, because the excluded violations were already impossible by hypothesis. `□`

**Proposition B.20 (Graceful Closure Compatibility).**

Statement. If closure is graceful in the sense of Definition A.31 and closure events are appended to `H`, then closing a channel does not violate `I_live` or `I_causal` for messages already accepted by that channel.

Proof type. Direct proof by case analysis.

Hypotheses. Definitions A.19, A.31, and Proposition 4.12.

Proof. Let `m` be any message already accepted by the channel at the moment closure is initiated. By Definition A.31, exactly one of three cases holds: `m` is delivered, `m` is explicitly terminated with a protocol-defined outcome, or `m` is archived in reconstructible form. In the first two cases, liveness is preserved because `m` reaches a defined terminal result. In the third case, liveness is preserved modulo reconstruction semantics, and causal completeness is preserved because the archived form is recorded in `H`. Since closure itself is also recorded, no accepted message becomes causally unaccounted for. `□`

**Proposition B.21 (Binary Error Channel Capacity).**

Statement. If a low-visible failure surface exposes exactly two distinguishable outcomes with probabilities `p` and `1 - p`, then the information content of one observation is `-p log2 p - (1 - p) log2 (1 - p)` bits.

Proof type. Direct proof.

Hypotheses. Shannon entropy formula.

Proof. A binary observable outcome is a Bernoulli random variable. Its Shannon entropy is, by definition, `H(X) = - sum_x p(x) log2 p(x)`. Substituting the two outcomes yields `H(X) = -p log2 p - (1 - p) log2 (1 - p)`. `□`

**Proposition B.21a (Quantized Timing Channel Upper Bound).**

Statement. If a timing observer distinguishes at most `M` timing buckets per observation, then the timing leakage per observation is at most `log2 M` bits.

Proof type. Direct proof.

Hypotheses. Shannon entropy upper bound.

Proof. Any single observation drawn from an alphabet of size at most `M` has Shannon entropy at most `log2 M`, with equality only for the uniform distribution. Since mutual information per observation cannot exceed the entropy of the observable channel output, the timing leakage per observation is at most `log2 M` bits. `□`

**Proposition B.22 (Queue Configuration Lower Bound).**

Statement. If an IPC subsystem has `N` independent bounded queues of capacity `K`, then the queue-occupancy component of the state space has at least `(K + 1)^N` elements.

Proof type. Counting argument.

Hypotheses. Definition A.8.

Proof. Each bounded queue may contain `0, 1, ..., K` messages, giving `K + 1` occupancy values per queue. Independence of occupancy components yields the Cartesian product of these choices across `N` queues. Therefore the number of occupancy configurations is at least `(K + 1)^N`. `□`

**Proposition B.23 (Merkle Summarization Preserves Prefix Authenticity).**

Statement. If `H` is authenticated event-by-event and summarized by a Merkle structure over authenticated prefixes, then any verified Merkle root authenticates the inclusion and order of every retained prefix element represented beneath that root.

Proof type. Proof sketch.

Hypotheses. Definition A.36 and collision resistance of the underlying hash function.

Proof sketch. The Merkle root is computed recursively from authenticated leaves corresponding to history elements or authenticated prefix blocks. Any alteration of a retained element or its position changes the corresponding leaf or internal node hash and, under collision resistance, changes the root with overwhelming probability. Hence a verified root authenticates the retained prefix contents and their order. A full proof would formalize the tree construction and the exact adversary model. `□`
