(* Oreulius Verification Workspace
   SPDX-License-Identifier: LicenseRef-Oreulius-Community *)

Inductive node :=
  | Boot
  | Dispatch
  | Runtime.

Definition edge (src dst : node) : Prop :=
  match src, dst with
  | Boot, Dispatch => True
  | Dispatch, Runtime => True
  | Boot, Runtime => True
  | _, _ => False
  end.

Theorem no_self_edge : forall n, ~ edge n n.
Proof.
  intro n.
  destruct n; simpl; intro H; exact H.
Qed.
