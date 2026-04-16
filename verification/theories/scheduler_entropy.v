(* Oreulius Verification Workspace
   SPDX-License-Identifier: BUSL-1.1 *)

From Coq Require Import Arith.PeanoNat.

Definition consume_fuel (budget demand : nat) : nat :=
  if Nat.leb budget demand then budget else demand.

Theorem consume_fuel_bounded_by_budget :
  forall budget demand, consume_fuel budget demand <= budget.
Proof.
  intros budget demand.
  unfold consume_fuel.
  destruct (Nat.leb budget demand) eqn:Hbool.
  - apply Nat.leb_le in Hbool.
    apply le_n.
  - apply Nat.leb_gt in Hbool.
    apply Nat.lt_le_incl.
    exact Hbool.
Qed.

Theorem consume_fuel_bounded_by_demand :
  forall budget demand, consume_fuel budget demand <= demand.
Proof.
  intros budget demand.
  unfold consume_fuel.
  destruct (Nat.leb budget demand) eqn:Hbool.
  - apply Nat.leb_le in Hbool.
    exact Hbool.
  - apply le_n.
Qed.
