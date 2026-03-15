(* Temporal Functor Composition Proofs for Oreulia Mathematical Architecture *)
(* This formalizes the temporal.rs capability mapping using Functors *)

Require Import Stdlib.Init.Logic.
Require Import Stdlib.Arith.Arith.
Require Import Stdlib.Structures.Equalities.

(* Abstract representation of a Kernel Capability *)
Parameter Capability : Type.
Parameter Valid : Capability -> Prop.
Parameter Rights : Capability -> nat.

(* Temporal Window represents a mapping over time/state *)
Record TemporalWindow (A : Type) := mkWindow {
  value : A;
  timestamp : nat;
}.

(* Functor definition for TemporalWindow *)
Definition fmap {A B : Type} (f : A -> B) (w : TemporalWindow A) : TemporalWindow B :=
  mkWindow B (f (value A w)) (timestamp A w).

(* Functor Laws to prove composition over temporal bounds *)
Lemma temporal_functor_id : forall (A : Type) (w : TemporalWindow A),
  fmap (fun x => x) w = w.
Proof.
  intros A w.
  destruct w.
  unfold fmap.
  reflexivity.
Qed.

Lemma temporal_functor_comp : forall (A B C : Type) (f : A -> B) (g : B -> C) (w : TemporalWindow A),
  fmap g (fmap f w) = fmap (fun x => g (f x)) w.
Proof.
  intros A B C f g w.
  destruct w.
  unfold fmap.
  reflexivity.
Qed.

(* Temporal revocation logic: a capability functor that loses validity is safely revoked *)
Parameter Revoked : Capability -> Prop.
Axiom revoke_axiom : forall (c : Capability), Valid c -> Revoked c -> False.

(* Invariants from INV-TMP-001 and THM-TMP-001: 
   Rollback/merge transitions preserve temporal consistency relation. *)
Definition Merge {A: Type} (w1 w2: TemporalWindow A) (f: A -> A -> A) :=
  mkWindow A (f (value A w1) (value A w2)) (timestamp A w2).

Lemma temporal_merge_preserves_bounds : forall (A: Type) (w1 w2: TemporalWindow A) (f: A -> A -> A),
  timestamp A (Merge w1 w2 f) = timestamp A w2.
Proof.
  intros A w1 w2 f.
  unfold Merge.
  reflexivity.
Qed.

(* Invariant INV-CAP-001: Capability attenuation. *)
Parameter Attenuate : Capability -> Capability.
Axiom attenuate_rights_axiom : forall c, Rights (Attenuate c) <= Rights c.

Lemma capability_attenuation_safe : forall (c : Capability),
  Rights (Attenuate c) <= Rights c.
Proof.
  intros c.
  apply attenuate_rights_axiom.
Qed.

(* ======================================================================== *)
(** * Extended Proofs (PMA §4 — THM-TMP-002 .. THM-TMP-005)
 *
 * These lemmas extend the original four with:
 *   1. Revocation propagates through attenuation chains.
 *   2. Temporal window functor preserves validity ordering.
 *   3. Double attenuation is monotone (rights only decrease).
 *   4. Temporal merge timestamp is monotone in the second argument.
 *
 * Traceability: PMA-TMP-002 .. PMA-TMP-005
 *)
(* ======================================================================== *)

(** ** Revocation propagation axiom
    An attenuated capability shares the revocation state of its parent.
    This axiom is stated separately so it can be swapped for a proof
    once the full capability model is formalised. *)
Axiom attenuate_revocation_propagates :
  forall (c : Capability), Revoked c -> Revoked (Attenuate c).

(** THM-TMP-002: A valid attenuated capability cannot exist once its
    parent is revoked.
    Proof: Attenuate(c) is Revoked (by [attenuate_revocation_propagates]),
    and revoke_axiom prevents Valid ∧ Revoked. *)
Lemma temporal_attenuated_revocation_safe :
  forall (c : Capability),
    Revoked c ->
    ~ Valid (Attenuate c).
Proof.
  intros c Hrev Hvalid_att.
  apply attenuate_revocation_propagates in Hrev.
  exact (revoke_axiom (Attenuate c) Hvalid_att Hrev).
Qed.

(** THM-TMP-003: Double attenuation cannot exceed the original rights.
    Attenuation is idempotent in the sense that applying it twice only
    further reduces (or maintains) the rights count. *)
Lemma double_attenuation_monotone :
  forall (c : Capability),
    Rights (Attenuate (Attenuate c)) <= Rights c.
Proof.
  intros c.
  apply Nat.le_trans with (m := Rights (Attenuate c)).
  - apply attenuate_rights_axiom.
  - apply attenuate_rights_axiom.
Qed.

(** THM-TMP-004: fmap over TemporalWindow preserves the timestamp. *)
Lemma fmap_preserves_timestamp :
  forall (A B : Type) (f : A -> B) (w : TemporalWindow A),
    timestamp B (fmap f w) = timestamp A w.
Proof.
  intros A B f w.
  unfold fmap. reflexivity.
Qed.

(** THM-TMP-005: Temporal Merge timestamp is non-decreasing when w2's
    timestamp is at least w1's timestamp.
    This captures the "later snapshot wins" semantics of rollback merges. *)
Lemma temporal_merge_timestamp_monotone :
  forall (A : Type) (w1 w2 : TemporalWindow A) (f : A -> A -> A),
    timestamp A w1 <= timestamp A w2 ->
    timestamp A w1 <= timestamp A (Merge w1 w2 f).
Proof.
  intros A w1 w2 f H.
  rewrite temporal_merge_preserves_bounds.
  exact H.
Qed.
