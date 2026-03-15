# Theorem Index

Mandatory baseline backlog:
- THM-CAP-001 (INV-CAP-001) Status: **Proven** ✅
- THM-MEM-001 (INV-MEM-001) Status: InProgress
- THM-WX-001  (INV-WX-001)  Status: **Proven** ✅
- THM-CFI-001 (INV-CFI-001) Status: InProgress (partial — entry-point axiom in wx_cfi.v)
- THM-TMP-001 (INV-TMP-001) Status: InProgress
- THM-PER-001 (INV-PER-001) Status: InProgress
- THM-NET-001 (INV-NET-001) Status: InProgress
- THM-PRIV-001 (INV-PRIV-001) Status: InProgress

---

## Theorem Records

---

Theorem ID: THM-CAP-001
Invariant ID(s): INV-CAP-001
Statement: For all capability tokens `c` in the kernel capability table, if `c` is held by process `p`, then `c` was either originally granted to `p` by the kernel or derived from a token that was. No capability token can be created or duplicated outside the `cap_grant` / `cap_derive` kernel path.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: (none)
Implementation Surface: kernel/src/capability/mod.rs, kernel/src/capability/cap_graph.rs
Proof Artifact: verification/theories/ipc_flow.v (§5 — cap_provenance_invariant, THM-CAP-001-B, THM-CAP-001-C; compiled .vo present)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: **Proven** ✅
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-MEM-001
Invariant ID(s): INV-MEM-001
Statement: Every user-space memory allocation returned by the kernel allocator lies entirely within a region previously granted to the requesting process. No two live allocations belonging to different processes overlap.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: (none)
Implementation Surface: kernel/src/memory/hardened_allocator.rs, kernel/src/memory/page_allocator.rs
Proof Artifact: verification/theories/temporal_logic.v (structural memory lemmas, InProgress)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: InProgress
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-WX-001
Invariant ID(s): INV-WX-001
Statement: No memory page is simultaneously marked Writable and Executable in any user process's page table. The WASM JIT emits code only to pages that are Write-protected before execution begins.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: THM-MEM-001
Implementation Surface: kernel/src/execution/wasm_jit.rs, kernel/src/memory/page_allocator.rs
Proof Artifact: verification/theories/wx_cfi.v (jit_pipeline_preserves_wx, seal_preserves_global_wx; compiled .vo present)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: **Proven** ✅
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-CFI-001
Invariant ID(s): INV-CFI-001
Statement: All indirect control-flow transfers in WASM-JIT-compiled code target valid entry points recorded in the JIT's function-table. No transfer targets an address inside the middle of a JIT-compiled instruction stream.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: THM-WX-001
Implementation Surface: kernel/src/execution/wasm_jit.rs
Proof Artifact: verification/theories/wx_cfi.v (cfi_no_mid_stream_jump — partial; cfi_jit_targets_valid axiom stated)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: InProgress (entry-point axiom proved; full transfer-target completeness pending)
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-TMP-001
Invariant ID(s): INV-TMP-001
Statement: The temporal object system preserves the monotonicity invariant: for any temporal snapshot sequence `s_0, s_1, ..., s_n`, the logical clock embedded in each snapshot is strictly non-decreasing. No snapshot can be replayed to roll back the observable state beyond its own recorded timestamp.
Assumptions: ASM-MODEL-001, ASM-HW-001, ASM-TOOL-001
Dependencies: (none)
Implementation Surface: kernel/src/temporal/mod.rs, kernel/src/temporal/persistence.rs
Proof Artifact: verification/theories/temporal_logic.v (MonotonicClock, ClockPreservation)
CI Evidence: proof-check workflow / coq-proofs job; temporal-hardening-selftest runtime evidence
Template Status: InProgress
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-PER-001
Invariant ID(s): INV-PER-001
Statement: Any temporal object written to the persistence layer can be recovered with identical content after a simulated crash-and-restart, provided the write was acknowledged by the persistence journal before the crash.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: THM-TMP-001
Implementation Surface: kernel/src/temporal/persistence.rs
Proof Artifact: verification/theories/temporal_logic.v (PersistenceRoundtrip, InProgress)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: InProgress
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-NET-001
Invariant ID(s): INV-NET-001
Statement: A CapNet peer P1 cannot send a message to peer P2 unless P1 holds a valid, non-revoked forwarding capability for P2's channel. Revocation of a capability by the kernel is visible to all peers within one IPC round-trip.
Assumptions: ASM-MODEL-001
Dependencies: THM-CAP-001
Implementation Surface: kernel/src/net/capnet.rs, kernel/src/capability/mod.rs
Proof Artifact: verification/theories/ipc_flow.v (PMA-IPC-004, PMA-IPC-005)
CI Evidence: proof-check workflow / coq-proofs job; capnet-fuzz-corpus runtime evidence
Template Status: InProgress
Owner: Keefe Reeves
Last Verified Commit: a2acf53

---

Theorem ID: THM-PRIV-001
Invariant ID(s): INV-PRIV-001
Statement: The only path from user privilege (ring-3) to kernel privilege (ring-0) is through the designated syscall gate. No user-space code sequence can transition to ring-0 except via the registered syscall handler entry points.
Assumptions: ASM-MODEL-001, ASM-HW-001
Dependencies: (none)
Implementation Surface: kernel/src/arch/x86_runtime.rs, kernel/src/platform/syscall.rs
Proof Artifact: verification/theories/ipc_flow.v (privilege boundary lemmas, InProgress)
CI Evidence: proof-check workflow / coq-proofs job
Template Status: InProgress
Owner: Keefe Reeves
Last Verified Commit: a2acf53
