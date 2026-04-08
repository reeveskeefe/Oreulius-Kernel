(* Oreulius Verification Workspace
   SPDX-License-Identifier: LicenseRef-Oreulius-Community *)

Inductive page_perm :=
  | Data
  | Code
  | ReadOnly.

Definition writable (perm : page_perm) : bool :=
  match perm with
  | Data => true
  | Code => false
  | ReadOnly => false
  end.

Definition executable (perm : page_perm) : bool :=
  match perm with
  | Data => false
  | Code => true
  | ReadOnly => false
  end.

Theorem wx_disjoint :
  forall perm, writable perm = true -> executable perm = true -> False.
Proof.
  intro perm.
  destruct perm; simpl; intro; intro; discriminate.
Qed.
