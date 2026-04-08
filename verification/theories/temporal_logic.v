(* Oreulius Verification Workspace
   SPDX-License-Identifier: LicenseRef-Oreulius-Community *)

From Coq Require Import Arith.PeanoNat.

Definition temporal_step (tick : nat) : nat := S tick.

Theorem temporal_step_progress : forall tick, tick <= temporal_step tick.
Proof.
  intro tick.
  unfold temporal_step.
  exact (Nat.le_succ_diag_r tick).
Qed.
