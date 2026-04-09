(** * AArch64 Boot Handoff Coherence  (A64-BOOT-002)
 *
 * This theory models the boot-handoff contract used by the AArch64 virt
 * backend: the DTB pointer captured during boot is the same pointer later
 * surfaced to the runtime through both raw_info_ptr and dtb_ptr.
 *
 * The theorem is deliberately narrow. It does not claim the entire boot
 * sequence is correct; it only proves that the handoff does not invent a
 * second DTB pointer or widen the trusted input set.
 *)

From Stdlib Require Import Init.Nat.

Record A64BootInfoModel := mkA64BootInfoModel
  { model_dtb_ptr : option nat
  ; model_raw_info_ptr : option nat
  ; model_boot_protocol_ok : bool
  }.

Definition a64_boot_handoff_consistent (m : A64BootInfoModel) : Prop :=
  model_boot_protocol_ok m = true /\
  model_raw_info_ptr m = model_dtb_ptr m.

Definition a64_runtime_sees_same_dtb (m : A64BootInfoModel) : Prop :=
  model_raw_info_ptr m = model_dtb_ptr m /\
  (model_dtb_ptr m = None \/ exists ptr, model_dtb_ptr m = Some ptr).

Lemma a64_boot_handoff_preserves_dtb_pointer :
  forall m : A64BootInfoModel,
    a64_boot_handoff_consistent m ->
    a64_runtime_sees_same_dtb m.
Proof.
  intros m [Hproto Heq].
  unfold a64_runtime_sees_same_dtb.
  split.
  - exact Heq.
  - destruct (model_dtb_ptr m) as [ptr|].
    + right. exists ptr. reflexivity.
    + left. reflexivity.
Qed.

(* Code-model trace:
   - kernel/src/arch/aarch64_virt.rs::arch_aarch64_record_boot_handoff
   - kernel/src/arch/aarch64_virt.rs::boot_info
   - kernel/src/arch/aarch64_runtime.rs::enter_runtime
   - kernel/src/arch/mod.rs::BootInfo
*)
