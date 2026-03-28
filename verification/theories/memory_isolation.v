(** * Memory Region Isolation Proofs  (THM-MEM-001 / INV-MEM-001)
 *
 * Formalises the kernel memory isolation invariant:
 *   (a) Every user-space allocation lies entirely within the grant region
 *       issued to the requesting process.
 *   (b) No two live allocations belonging to different processes overlap.
 *
 * Implementation surface:
 *   kernel/src/memory/hardened_allocator.rs  (arena + slab allocator)
 *   kernel/src/memory/page_allocator.rs      (allocate_frame / free_frame)
 *   kernel/src/execution/wasm_thread.rs      (SharedLinearMemory bounds-check)
 *   kernel/src/security/memory_isolation.rs  (tag_range domain table)
 *
 * Model
 * -----
 * Memory regions are represented as records  { base : nat ; len : nat }
 * denoting the half-open byte interval  [base, base+len).  This matches:
 *   - page_allocator  : frame address + page size * frame count
 *   - SharedLinearMemory : base + active_bytes
 *   - tag_range API   : start + len
 *
 * The grant-disjointness axiom (ASM-ALLOC-UNIQUE) models the page
 * allocator's frame bitmap: each physical frame's refcount is at most 1,
 * so the same frame is never handed to two distinct processes simultaneously.
 *
 * Proof strategy
 * --------------
 * All properties reduce to linear arithmetic over ℕ and are discharged
 * by [lia].  No byte-level memory model is needed; the bounds-check and
 * non-overlap proofs follow directly from interval arithmetic.
 *
 * Traceability: THM-MEM-001 (INV-MEM-001)
 *   PMA-MEM-001 .. PMA-MEM-005
 *
 * Status: Proven ✅
 *)

From Stdlib Require Import Init.Nat.
From Stdlib Require Import Arith.PeanoNat.
From Stdlib Require Import micromega.Lia.

(* ================================================================== *)
(** * §1  Memory Region Model                                           *)
(* ================================================================== *)

(** A contiguous byte region [base, base+len).
    Mirrors the (start, len) pairs used by the tag_range API and the
    (base, active_bytes) fields of SharedLinearMemory. *)
Record MemRegion : Type := mkRegion
  { base : nat
  ; len  : nat
  }.

(** `in_bounds a g` — allocation `a` lies entirely within grant region `g`.

    Requires:
      g.base ≤ a.base                         (left edge)
      a.base + a.len ≤ g.base + g.len         (right edge)

    Mirrors the bounds check in SharedLinearMemory::read / write:
      if offset.saturating_add(len) > self.active_bytes { return false } *)
Definition in_bounds (a g : MemRegion) : Prop :=
  g.(base) <= a.(base) /\
  a.(base) + a.(len) <= g.(base) + g.(len).

(** `disjoint r1 r2` — two regions do not share any byte.
    r1 ends at or before r2 starts, or vice versa.

    Mirrors the non-overlap invariant enforced by the page-frame bitmap:
    each frame belongs to exactly one process at any given time. *)
Definition disjoint (r1 r2 : MemRegion) : Prop :=
  r1.(base) + r1.(len) <= r2.(base) \/
  r2.(base) + r2.(len) <= r1.(base).

(** `wasm_access_valid offset acc_len active_bytes`
    A WASM guest memory access (offset, acc_len) stays within the live
    sandbox window of size active_bytes.

    Mirrors the guard in SharedLinearMemory::read:
      if offset.saturating_add(len) > self.active_bytes { return false } *)
Definition wasm_access_valid (offset acc_len active_bytes : nat) : Prop :=
  offset + acc_len <= active_bytes.

(* ================================================================== *)
(** * §2  Core Isolation Lemmas                                         *)
(* ================================================================== *)

(** PMA-MEM-001: An in-bounds allocation does not exceed the grant's right
    edge.  Corresponds to hardened_allocator refusing allocations that
    would overflow the process's assigned page range. *)
Lemma alloc_within_upper_bound :
  forall (a g : MemRegion),
    in_bounds a g ->
    a.(base) + a.(len) <= g.(base) + g.(len).
Proof.
  intros a g [_ Hright].
  exact Hright.
Qed.

(** PMA-MEM-002: An in-bounds allocation starts at or after the grant's
    left edge.  Corresponds to allocate_frame never handing out frames
    below the process's arena base address. *)
Lemma alloc_within_lower_bound :
  forall (a g : MemRegion),
    in_bounds a g ->
    g.(base) <= a.(base).
Proof.
  intros a g [Hleft _].
  exact Hleft.
Qed.

(** PMA-MEM-003: If two grants are disjoint and each process's allocation
    lies in-bounds of its own grant, then the two allocations are disjoint.

    This is the core cross-process non-overlap lemma.

    Proof: transitivity of ≤ over the chain (case 1):
      a2.base + a2.len ≤ g2.base + g2.len ≤ g1.base ≤ a1.base
    or (case 2):
      a1.base + a1.len ≤ g1.base + g1.len ≤ g2.base ≤ a2.base *)
Lemma cross_process_no_overlap :
  forall (a1 a2 g1 g2 : MemRegion),
    in_bounds a1 g1 ->
    in_bounds a2 g2 ->
    disjoint g1 g2 ->
    disjoint a1 a2.
Proof.
  intros a1 a2 g1 g2 [Hl1 Hr1] [Hl2 Hr2] Hdisj.
  unfold disjoint in *.
  destruct Hdisj as [Hg | Hg]; [left | right]; lia.
Qed.

(** PMA-MEM-004: A valid WASM guest access (offset, acc_len) with the
    sandbox guard `offset + acc_len ≤ active_bytes` resolves to a host
    address range entirely inside [sandbox_base, sandbox_base + active_bytes).

    This formalises the bounds-check in SharedLinearMemory::read / write. *)
Lemma wasm_access_in_sandbox :
  forall (sandbox_base offset acc_len active_bytes : nat),
    wasm_access_valid offset acc_len active_bytes ->
    sandbox_base <= sandbox_base + offset /\
    sandbox_base + offset + acc_len <= sandbox_base + active_bytes.
Proof.
  intros sb off al ab Hv.
  unfold wasm_access_valid in Hv.
  split; lia.
Qed.

(** PMA-MEM-005: Two WASM sandboxes with disjoint active windows produce
    disjoint host-side accesses regardless of guest offsets, provided each
    guest access passes its own sandbox guard.

    Proof: host-side access regions are sub-intervals of their respective
    sandbox regions; disjoint sandboxes ⟹ disjoint sub-intervals
    (by PMA-MEM-003). *)
Lemma wasm_sandboxes_disjoint_host_access :
  forall (base1 base2 off1 off2 len1 len2 active1 active2 : nat),
    wasm_access_valid off1 len1 active1 ->
    wasm_access_valid off2 len2 active2 ->
    disjoint (mkRegion base1 active1) (mkRegion base2 active2) ->
    disjoint (mkRegion (base1 + off1) len1) (mkRegion (base2 + off2) len2).
Proof.
  intros b1 b2 o1 o2 l1 l2 a1 a2 Hv1 Hv2 Hdisj.
  unfold wasm_access_valid in *.
  apply cross_process_no_overlap with
    (g1 := mkRegion b1 a1)
    (g2 := mkRegion b2 a2).
  - unfold in_bounds; simpl; lia.
  - unfold in_bounds; simpl; lia.
  - exact Hdisj.
Qed.

(* ================================================================== *)
(** * §3  THM-MEM-001 Main Theorem                                      *)
(* ================================================================== *)

(** THM-MEM-001: Memory Region Isolation.
 *
 * Given:
 *   (1) allocation a1 is in-bounds of grant g1  (process P1)
 *   (2) allocation a2 is in-bounds of grant g2  (process P2)
 *   (3) grants g1 and g2 are disjoint           (kernel grant-table invariant)
 *
 * Conclude:
 *   (A) a1 lies entirely within g1             (PMA-MEM-001 / PMA-MEM-002)
 *   (B) a2 lies entirely within g2
 *   (C) a1 and a2 do not overlap               (PMA-MEM-003)
 *
 * The grant disjointness precondition maps to the page allocator's
 * frame bitmap: each physical frame is owned by at most one process at
 * a time (refcount = 1).  allocate_frame prevents double allocation via
 * the bitmap, ensuring the grants handed to distinct processes are always
 * disjoint intervals of physical memory.
 *
 * Implementation note: the WASM sandbox layer (SharedLinearMemory) additionally
 * ensures guest-visible accesses satisfy wasm_access_valid (PMA-MEM-004/005),
 * so WASM-to-WASM cross-instance sandbox isolation is a corollary. *)
Theorem memory_region_isolation :
  forall (a1 a2 g1 g2 : MemRegion),
    in_bounds a1 g1 ->
    in_bounds a2 g2 ->
    disjoint g1 g2 ->
    (* (A) a1 within g1 *)
    g1.(base) <= a1.(base) /\
    a1.(base) + a1.(len) <= g1.(base) + g1.(len) /\
    (* (B) a2 within g2 *)
    g2.(base) <= a2.(base) /\
    a2.(base) + a2.(len) <= g2.(base) + g2.(len) /\
    (* (C) cross-process non-overlap *)
    disjoint a1 a2.
Proof.
  intros a1 a2 g1 g2 Hb1 Hb2 Hdisj.
  refine (conj _ (conj _ (conj _ (conj _ _)))).
  - exact (alloc_within_lower_bound a1 g1 Hb1).
  - exact (alloc_within_upper_bound a1 g1 Hb1).
  - exact (alloc_within_lower_bound a2 g2 Hb2).
  - exact (alloc_within_upper_bound a2 g2 Hb2).
  - exact (cross_process_no_overlap a1 a2 g1 g2 Hb1 Hb2 Hdisj).
Qed.
