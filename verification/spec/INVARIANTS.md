# Canonical Invariants

> Full program-by-program target map with claim tiers: see
> [`proof/VERIFICATION_TARGET_MATRIX.md`](../proof/VERIFICATION_TARGET_MATRIX.md).

## Proven Invariants (T2 — Model Level)

- **INV-CAP-001**: capability authority cannot increase without authorized derivation.
- **INV-MEM-001**: no out-of-bounds memory access in modeled transitions.
- **INV-WX-001**: no reachable RWX page state.
- **INV-CFI-001**: indirect control transfers target only allowed entry sets.
- **INV-TMP-001**: temporal rollback and merge preserve object consistency invariants.
- **INV-PER-001**: persisted temporal decode rejects integrity-inconsistent payloads.
- **INV-NET-001**: CapNet acceptance requires integrity + freshness + rights attenuation.
- **INV-PRIV-001**: user/kernel privilege transitions preserve control-return integrity.
- **INV-LOCK-001**: the modeled lock acquisition order contains no cycles (deadlock freedom within the model).
- **INV-SCH-001**: the scheduler process-state transition relation admits no illegal state transitions within the modeled state machine.

## Open Invariants (T1 — Spec Only, Not Yet Mechanized)

- **INV-CAP-002**: derived capabilities carry only a proper subset of their parent's rights (no rights escalation).
- **INV-CAP-003**: the capability delegation graph is acyclic at all reachable states.
- **INV-CAP-004**: revoking a capability also revokes all transitively derived descendant capabilities.
- **INV-CAP-005**: no capability token that has been revoked can become active again (no resurrection).
- **INV-TMP-002**: branching a temporal object produces a copy with no shared mutable state with the parent branch.
- **INV-TMP-003**: rolling back a temporal object to snapshot S cannot expose any state written strictly after S was taken.
- **INV-NET-002**: within one protocol round, a revoked capability is invalid at all reachable CapNet peers.
- **INV-IPC-001**: messages on a channel are delivered in FIFO order relative to their send sequence.
- **INV-SCH-002**: scheduler preemption does not corrupt the internal invariant of any co-resident subsystem.
