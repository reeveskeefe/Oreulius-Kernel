(* Oreulius Verification Workspace
   SPDX-License-Identifier: LicenseRef-Oreulius-Community *)

From Stdlib Require Import Arith.PeanoNat.

Definition attenuate (rights mask : nat) : nat :=
  if Nat.leb rights mask then rights else mask.

Theorem attenuate_never_increases_rights :
  forall rights mask, attenuate rights mask <= rights.
Proof.
  intros rights mask.
  unfold attenuate.
  destruct (Nat.leb rights mask) eqn:Hbool.
  - apply Nat.leb_le in Hbool.
    apply le_n.
  - apply Nat.leb_gt in Hbool.
    apply Nat.lt_le_incl.
    exact Hbool.
Qed.

Theorem attenuate_never_exceeds_mask :
  forall rights mask, attenuate rights mask <= mask.
Proof.
  intros rights mask.
  unfold attenuate.
  destruct (Nat.leb rights mask) eqn:Hbool.
  - apply Nat.leb_le in Hbool.
    exact Hbool.
  - apply le_n.
Qed.
