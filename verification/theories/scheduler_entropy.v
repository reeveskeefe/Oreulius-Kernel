(** * Scheduler Entropy Proofs  (PMA §3 / PMA §4)
 *
 * Formalises the EWMA-based entropy quantum scheduler from
 * [kernel/src/quantum_scheduler.rs].
 *
 * Key constants mirrored from Rust source:
 *   QUANTUM_LOW  = 5   (QUANTUM_LOW in quantum_scheduler.rs)
 *   QUANTUM_HIGH = 20  (QUANTUM_HIGH in quantum_scheduler.rs)
 *
 * The EWMA recurrence is:
 *   e_{n+1} = (e_n * 7 + y_n) / 8          (integer division)
 *
 * Proof strategy:
 *   - [ewma_step_monotone_decay]: if y ≤ e then e' ≤ e  (EWMA is contractive)
 *   - [ewma_step_convergence]:    if e ≤ MAX and y ≤ MAX then e' ≤ MAX
 *   - [quantum_clamp_in_bounds]:  clamped quantum always lies in [LOW, HIGH]
 *   - [entropy_quantum_is_bounded]: composite entropy quantum is bounded
 *
 * All proofs use [lia] — no manual arithmetic.
 *
 * Traceability: PMA-SCH-001 .. PMA-SCH-004
 *)

Require Import Stdlib.Init.Nat.
Require Import Stdlib.Arith.PeanoNat.
Require Import Stdlib.micromega.Lia.

(* ------------------------------------------------------------------ *)
(** ** §1  Constants                                                    *)
(* ------------------------------------------------------------------ *)

Definition QUANTUM_LOW  : nat := 5.
Definition QUANTUM_HIGH : nat := 20.

(** Upper bound on any single-window yield/fault sample.
    The scheduler resets yield_count per window, so it is bounded by
    MAX_PROCESSES * ticks_per_window ≈ 64 * 100 = 6400.
    We use a conservative 65535 here so the bound is architecture-independent. *)
Definition MAX_SAMPLE : nat := 65535.

(* ------------------------------------------------------------------ *)
(** ** §2  EWMA step                                                    *)
(* ------------------------------------------------------------------ *)

(** One step of the bit-shift EWMA:
      e' = (7 * e + y) / 8
    This is exactly the formula in plan_switch() of quantum_scheduler.rs. *)
Definition ewma_step (e y : nat) : nat := (7 * e + y) / 8.

(** PMA-SCH-001: If both inputs are ≤ MAX_SAMPLE, the output fits in nat
    and is ≤ the arithmetic mean biased 7:1 toward the old value. *)
Lemma ewma_step_bounded :
  forall (e y : nat),
    e  <= MAX_SAMPLE ->
    y  <= MAX_SAMPLE ->
    ewma_step e y <= MAX_SAMPLE.
Proof.
  intros e y He Hy.
  unfold ewma_step, MAX_SAMPLE in *.
  apply Nat.Div0.div_le_upper_bound; lia.
Qed.

(** PMA-SCH-002: EWMA is contractive: if y ≤ e then e' ≤ e.
    (Weights 7 on old, 1 on new → new value cannot exceed old when new ≤ old.) *)
Lemma ewma_step_monotone_decay :
  forall (e y : nat),
    y <= e ->
    ewma_step e y <= e.
Proof.
  intros e y Hle.
  unfold ewma_step.
  (* (7*e + y) / 8 ≤ e  iff  7*e + y ≤ 8*e  iff  y ≤ e *)
  apply Nat.Div0.div_le_upper_bound; lia.
Qed.

(** PMA-SCH-003: If e ≤ QUANTUM_HIGH and y ≤ QUANTUM_HIGH,
    then e' ≤ QUANTUM_HIGH.
    The quantum-domain EWMA is closed under [0, QUANTUM_HIGH]. *)
Lemma ewma_step_convergence :
  forall (e y : nat),
    e <= QUANTUM_HIGH ->
    y <= QUANTUM_HIGH ->
    ewma_step e y <= QUANTUM_HIGH.
Proof.
  intros e y He Hy.
  unfold ewma_step, QUANTUM_HIGH in *.
  apply Nat.Div0.div_le_upper_bound; lia.
Qed.

(* ------------------------------------------------------------------ *)

(** The adjusted quantum q is clamped to [QUANTUM_LOW, QUANTUM_HIGH]
    by [Nat.max QUANTUM_LOW (Nat.min QUANTUM_HIGH q)].
    This matches the [.clamp(QUANTUM_LOW, QUANTUM_HIGH)] call in Rust. *)

(** PMA-SCH-004: The clamped quantum lies in [QUANTUM_LOW, QUANTUM_HIGH]
    for any nat input q. *)
Lemma quantum_clamp_in_bounds :
  forall (q : nat),
    QUANTUM_LOW  <= Nat.max QUANTUM_LOW (Nat.min QUANTUM_HIGH q) /\
    Nat.max QUANTUM_LOW (Nat.min QUANTUM_HIGH q) <= QUANTUM_HIGH.
Proof.
  intros q.
  unfold QUANTUM_LOW, QUANTUM_HIGH.
  split; lia.
Qed.

(* ------------------------------------------------------------------ *)
(** ** §4  Composite entropy quantum                                    *)
(* ------------------------------------------------------------------ *)

(** Model of compute_entropy_quantum from quantum_scheduler.rs
    (feature = experimental_entropy_sched):
      reward  = (ewma_yield * log2_yield) >> 4
      penalty = (ewma_fault * log2_fault) >> 4
      adjusted = base + reward - penalty   (saturating)
      result   = clamp(adjusted, QUANTUM_LOW, QUANTUM_HIGH)

    We abstract log2 and the shift as an opaque non-decreasing function
    [entropy_weight] bounded by 1 per unit of input, which is the weakest
    assumption needed for the bounds proof. *)

Parameter entropy_weight : nat -> nat.
Axiom entropy_weight_bounded :
  forall (x : nat), entropy_weight x <= x.

Definition entropy_quantum (ewma_yield ewma_fault base : nat) : nat :=
  let reward  := (ewma_yield * entropy_weight ewma_yield) / 16 in
  let penalty := (ewma_fault * entropy_weight ewma_fault) / 16 in
  let adjusted := base + reward in  (* Nat subtraction is saturating by default *)
  let adjusted' := if Nat.leb penalty adjusted then adjusted - penalty else 0 in
  Nat.max QUANTUM_LOW (Nat.min QUANTUM_HIGH adjusted').

(** PMA-SCH-005: The composite entropy quantum is always in
    [QUANTUM_LOW, QUANTUM_HIGH], regardless of EWMA inputs. *)
Lemma entropy_quantum_is_bounded :
  forall (ey ef base : nat),
    QUANTUM_LOW  <= entropy_quantum ey ef base /\
    entropy_quantum ey ef base <= QUANTUM_HIGH.
Proof.
  intros ey ef base.
  unfold entropy_quantum, QUANTUM_LOW, QUANTUM_HIGH.
  split; lia.
Qed.

(* ------------------------------------------------------------------ *)
(** ** §5  EWMA non-negativity (trivially true in nat, stated for doc)  *)
(* ------------------------------------------------------------------ *)

Lemma ewma_step_nonneg :
  forall (e y : nat), 0 <= ewma_step e y.
Proof.
  intros; lia.
Qed.
