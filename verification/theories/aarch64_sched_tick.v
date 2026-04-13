(** * AArch64 Scheduler Tick / Reschedule-Pending Boundary  (A64-SCHED-001)
 *
 * This theory mechanizes a narrow scheduler-adjacent boundary on the AArch64
 * bring-up path. It models the timer tick bookkeeping, the reschedule-pending
 * flag, and the timeslice update path used by the AArch64 runtime hooks.
 *
 * The theorem is intentionally narrow:
 *   - boundary ticks set `resched_pending` and increment reschedule requests
 *   - `scheduler_note_context_switch` clears `resched_pending`
 *   - timeslice updates reject zero and preserve positivity on success
 *
 * It does not claim fairness, interrupt-controller fidelity, or full scheduler
 * correctness.
 *
 * Status: Proven for the model-level boundary properties stated here.
 *)

From Stdlib Require Import Arith.PeanoNat.
From Stdlib Require Import micromega.Lia.

Record A64SchedState := mkA64SchedState
  { a64_tick_total : nat
  ; a64_timeslice : nat
  ; a64_tick_pos : nat
  ; a64_resched_pending : bool
  ; a64_resched_requests : nat
  ; a64_context_switches : nat
  }.

Definition a64_effective_timeslice (s : A64SchedState) : nat :=
  Nat.max 1 (a64_timeslice s).

Definition a64_timer_tick (s : A64SchedState) : A64SchedState :=
  let total' := S (a64_tick_total s) in
  let timeslice := a64_effective_timeslice s in
  let pos := total' mod timeslice in
  let pending' :=
    if Nat.eqb pos 0 then true else a64_resched_pending s in
  let requests' :=
    if Nat.eqb pos 0 then S (a64_resched_requests s)
    else a64_resched_requests s in
  mkA64SchedState
    total'
    (a64_timeslice s)
    pos
    pending'
    requests'
    (a64_context_switches s).

Definition a64_note_context_switch (s : A64SchedState) : A64SchedState :=
  mkA64SchedState
    (a64_tick_total s)
    (a64_timeslice s)
    (a64_tick_pos s)
    false
    (a64_resched_requests s)
    (S (a64_context_switches s)).

Definition a64_set_timeslice (ticks : nat) (s : A64SchedState) : option A64SchedState :=
  if Nat.eqb ticks 0 then None
  else
    Some (
      mkA64SchedState
        (a64_tick_total s)
        ticks
        (a64_tick_pos s)
        (a64_resched_pending s)
        (a64_resched_requests s)
        (a64_context_switches s)).

Lemma a64_timer_tick_boundary_sets_resched_pending :
  forall s : A64SchedState,
    a64_tick_pos (a64_timer_tick s) = 0 ->
    a64_resched_pending (a64_timer_tick s) = true /\
    a64_resched_requests (a64_timer_tick s) = S (a64_resched_requests s).
Proof.
  intros s Hboundary.
  unfold a64_timer_tick in *.
  simpl in Hboundary.
  destruct (Nat.eqb (S (a64_tick_total s) mod a64_effective_timeslice s) 0) eqn:Hcase.
  - apply Nat.eqb_eq in Hcase.
    subst.
    split; reflexivity.
  - apply Nat.eqb_neq in Hcase.
    exfalso.
    apply Hcase.
    exact Hboundary.
Qed.

Lemma a64_note_context_switch_clears_pending :
  forall s : A64SchedState,
    a64_resched_pending (a64_note_context_switch s) = false /\
    a64_context_switches (a64_note_context_switch s) =
      S (a64_context_switches s).
Proof.
  intros s.
  unfold a64_note_context_switch.
  simpl.
  split; reflexivity.
Qed.

Lemma a64_set_timeslice_rejects_zero :
  forall s : A64SchedState,
    a64_set_timeslice 0 s = None.
Proof.
  intros s.
  unfold a64_set_timeslice.
  simpl.
  reflexivity.
Qed.

Lemma a64_set_timeslice_success_preserves_positive :
  forall ticks s s',
    a64_set_timeslice ticks s = Some s' ->
    0 < a64_timeslice s' /\ a64_timeslice s' = ticks.
Proof.
  intros ticks s s' Hset.
  unfold a64_set_timeslice in Hset.
  destruct (Nat.eqb ticks 0) eqn:Hzero.
  - apply Nat.eqb_eq in Hzero.
    subst.
    discriminate.
  - inversion Hset; subst.
    apply Nat.eqb_neq in Hzero.
    destruct ticks as [| ticks'].
    + exfalso.
      apply Hzero.
      reflexivity.
    + split.
      * apply Nat.lt_0_succ.
      * reflexivity.
Qed.

Theorem a64_scheduler_tick_boundary_refinement :
  forall s : A64SchedState,
    (a64_tick_pos (a64_timer_tick s) = 0 ->
      a64_resched_pending (a64_timer_tick s) = true /\
      a64_resched_requests (a64_timer_tick s) = S (a64_resched_requests s)) /\
    (a64_resched_pending (a64_note_context_switch s) = false /\
      a64_context_switches (a64_note_context_switch s) = S (a64_context_switches s)) /\
    (a64_set_timeslice 0 s = None) /\
    (forall ticks s',
      a64_set_timeslice ticks s = Some s' ->
      0 < a64_timeslice s' /\ a64_timeslice s' = ticks).
Proof.
  intros s.
  split.
  - intros Hboundary.
    exact (a64_timer_tick_boundary_sets_resched_pending s Hboundary).
  - split.
    + exact (a64_note_context_switch_clears_pending s).
    + split.
      * exact (a64_set_timeslice_rejects_zero s).
      * intros ticks s' Hset.
        exact (a64_set_timeslice_success_preserves_positive ticks s s' Hset).
Qed.

(* Code-model trace:
   - kernel/src/arch/aarch64_virt.rs::scheduler_timer_tick_hook
   - kernel/src/arch/aarch64_virt.rs::scheduler_note_context_switch
   - kernel/src/arch/aarch64_virt.rs::scheduler_tick_backend_clear_pending
   - kernel/src/arch/aarch64_virt.rs::scheduler_tick_backend_set_timeslice
   - kernel/src/scheduler/slice_scheduler.rs::on_timer_tick
   - kernel/src/scheduler/slice_scheduler.rs::maybe_reschedule
*)
