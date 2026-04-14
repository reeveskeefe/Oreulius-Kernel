<!-- Rapid Boundary Test Addition Guide: Using the Assertion Helper -->

# Rapid Boundary Test Addition: Helper-Driven TDD

This guide demonstrates how to add new negative-trace tests for additional kernel boundaries using the centralized assertion helper, reducing per-test boilerplate from ~50 lines to ~10 lines of focused test code.

---

## Quick Start: The Pattern

Every negative-trace test follows this structure:

```rust
#[test]
fn your_boundary_negative_trace_closure_chain() {
    // 1. Verify the invariant check predicts failure
    let expected = your_invariant_check(invalid_input);
    assert!(!expected.valid);
    assert_eq!(expected.id, "INV-YOUR-BOUNDARY-NNN");
    assert_eq!(expected.severity, InvariantSeverity::Safety); // or Consistency, Progress, Diagnostic

    // 2. Capture event count before violation trigger
    let before = ring_buffer::write_count();

    // 3. Execute operation that violates the invariant
    let result = your_operation_that_fails(invalid_input);
    assert!(result.is_err()); // Confirm it failed

    // 4. Capture event count after
    let after = ring_buffer::write_count();

    // 5. Assert with helper: expected events + outcome match
    assert_closure_chain_closure(
        before,
        after,
        &[EventType::InvariantViolation, EventType::FailurePolicyAction],
        FailureSubsystem::YourSubsystem,
        FailureAction::YourExpectedAction,
    );
}
```

That's it. ~15 lines of focused test logic per boundary.

---

## Template: Capability Transfer Boundary (Example)

This shows how to add a **Capability Transfer Boundary** test as an example of the rapid pattern.

### Step 1: Define the Invariant Check

In `kernel/src/invariants/capability.rs` (new file):

```rust
pub fn check_capability_transfer(from_pid: ProcessId, to_pid: ProcessId, cap: &Capability) -> InvariantCheckResult {
    // Invariant: Cannot transfer to self, must have rights to delegate
    let valid = from_pid != to_pid && cap.rights.contains(Rights::DELEGATE);
    InvariantCheckResult {
        valid,
        id: "INV-CAP-TRANSFER-001",
        severity: InvariantSeverity::Safety,
        detail: if !valid { Some("capability transfer violates delegation rights or target is self") } else { None },
    }
}
```

### Step 2: Wire the Boundary

In `kernel/src/capability/transfer.rs` (existing):

```rust
pub fn transfer_capability(from_pid: ProcessId, to_pid: ProcessId, cap: &Capability) -> Result<(), Error> {
    crate::observability::emit_capability_boundary(EventType::Boundary, 0x6100, &[]);

    // Check invariant
    let check = crate::invariants::capability::check_capability_transfer(from_pid, to_pid, cap);
    if let Some(_outcome) = crate::invariants::enforce(&check, "transfer_capability") {
        crate::observability::emit_capability_boundary(EventType::Boundary, 0x61FF, &[]);
        return Err(Error::CapabilityViolation);
    }

    // Proceed with transfer...
    crate::observability::emit_capability_boundary(EventType::Boundary, 0x6101, &[]);
    Ok(())
}
```

### Step 3: Add the Negative-Trace Test

In the same file's `#[cfg(test)]` module:

```rust
#[test]
fn capability_negative_trace_closure_chain() {
    let from_pid = ProcessId(1);
    let to_pid = ProcessId(1);  // Self transfer (violation)
    let cap = Capability {
        rights: Rights::READ | Rights::WRITE,  // No DELEGATE right
        target: Some(Object::Memory(0x1000)),
    };

    let expected = crate::invariants::capability::check_capability_transfer(from_pid, to_pid, &cap);
    assert!(!expected.valid);
    assert_eq!(expected.id, "INV-CAP-TRANSFER-001");
    assert_eq!(expected.severity, InvariantSeverity::Safety);

    let before = ring_buffer::write_count();
    let result = transfer_capability(from_pid, to_pid, &cap);
    assert!(result.is_err());
    let after = ring_buffer::write_count();

    crate::observability::assert_closure_chain_closure(
        before,
        after,
        &[EventType::InvariantViolation, EventType::FailurePolicyAction],
        FailureSubsystem::Capability,
        FailureAction::FailStop,
    );
}
```

**Line count for test logic**: ~15 lines (focused on violation setup and assertion).
**Without helper**: ~50+ lines (manual event iteration + outcome checking).
**Time to add**: ~5 minutes per boundary (setup invariant + wire boundary + write test).

---

## Why This Scales

### Before the Helper (Manual Event Iteration):

```rust
// ~50 lines of boilerplate per test
let mut saw_invariant = false;
let mut saw_failure_policy = false;
for seq in before..after {
    if let Some(ev) = ring_buffer::snapshot_seq(seq) {
        if ev.event_type == EventType::InvariantViolation {
            saw_invariant = true;
        }
        if ev.event_type == EventType::FailurePolicyAction {
            saw_failure_policy = true;
        }
    }
}
assert!(saw_invariant, "expected invariant violation event");
assert!(saw_failure_policy, "expected failure policy event");

let outcome = last_failure_outcome().expect("failure outcome snapshot");
assert_eq!(outcome.subsystem, FailureSubsystem::Capability);
assert_eq!(outcome.action, FailureAction::FailStop);
```

### With the Helper (Single Line):

```rust
assert_closure_chain_closure(
    before,
    after,
    &[EventType::InvariantViolation, EventType::FailurePolicyAction],
    FailureSubsystem::Capability,
    FailureAction::FailStop,
);
```

---

## Next Boundaries (Planned in Phase 1C)

Based on the verification roadmap, the following boundaries are candidates for rapid test addition:

1. **Capability Transfer Boundary** (Syscall subsystem)
   - Invariant: INV-CAP-TRANSFER-001 (Safety)
   - Violations: Self-transfer, missing DELEGATE right, revoked capability
   - Failure Policy: FailStop (Capability subsystem)
   - Estimated effort: ~15 minutes

2. **IPC Channel Protocol Boundary** (IPC subsystem)
   - Invariant: INV-IPC-PROTO-001 (Consistency)
   - Violations: Phase transition violation, invalid session ID
   - Failure Policy: Isolate (IPC subsystem)
   - Estimated effort: ~15 minutes

3. **Persistence Recovery Boundary** (Storage subsystem)
   - Invariant: INV-PERSIST-RECOVER-001 (Consistency)
   - Violations: Invalid recovery state, corrupted checkpoint
   - Failure Policy: Degrade (Storage subsystem)
   - Estimated effort: ~20 minutes

4. **Network Dispatch Boundary** (Net subsystem)
   - Invariant: INV-NET-DISPATCH-001 (Safety)
   - Violations: Invalid socket descriptor, unauthorized access
   - Failure Policy: Isolate (Net subsystem)
   - Estimated effort: ~20 minutes

5. **Execution (WASM) Boundary** (Execution subsystem)
   - Invariant: INV-EXEC-BOUNDS-001 (Safety)
   - Violations: Out-of-bounds memory access attempt, invalid function call
   - Failure Policy: FailStop (Execution subsystem)
   - Estimated effort: ~25 minutes

---

## Adding a Boundary: Full Walkthrough

### Assume: Clock Tick Boundary (hypothetical future boundary)

**Requirement**: Verify that timer tick intervals remain non-zero and within bounds (prevents tight-loop DoS).

#### 1. Add Invariant Check (5 min)

File: `kernel/src/invariants/scheduler.rs`

```rust
pub fn check_timer_tick_interval(interval_us: u64) -> InvariantCheckResult {
    let valid = interval_us > 0 && interval_us <= 1_000_000; // Max 1 second
    InvariantCheckResult {
        valid,
        id: "INV-SCHED-TICK-002",
        severity: InvariantSeverity::Progress,
        detail: if !valid { Some("timer interval out of bounds") } else { None },
    }
}
```

#### 2. Wire the Boundary (10 min)

File: `kernel/src/arch/aarch64_timer.rs`

```rust
pub fn set_timer_interval(interval_us: u64) -> Result<(), Error> {
    emit_trap_boundary(EventType::Boundary, 0x4200, &[]);

    let check = crate::invariants::scheduler::check_timer_tick_interval(interval_us);
    if let Some(_outcome) = crate::invariants::enforce(&check, "set_timer_interval") {
        emit_trap_boundary(EventType::Boundary, 0x42FF, &[]);
        return Err(Error::InvalidTimerInterval);
    }

    // Set the timer...
    emit_trap_boundary(EventType::Boundary, 0x4201, &[]);
    Ok(())
}
```

#### 3. Add Test (5 min with helper)

File: `kernel/src/arch/aarch64_timer.rs::tests`

```rust
#[test]
fn timer_tick_negative_trace_closure_chain() {
    let expected = crate::invariants::scheduler::check_timer_tick_interval(0);
    assert!(!expected.valid);
    assert_eq!(expected.id, "INV-SCHED-TICK-002");
    assert_eq!(expected.severity, InvariantSeverity::Progress);

    let before = ring_buffer::write_count();
    let result = set_timer_interval(0);  // Zero interval (violation)
    assert!(result.is_err());
    let after = ring_buffer::write_count();

    assert_closure_chain_closure(
        before,
        after,
        &[EventType::InvariantViolation, EventType::FailurePolicyAction],
        FailureSubsystem::TrapVector,
        FailureAction::Isolate,
    );
}
```

**Total time: ~20 minutes per boundary** (vs. ~1 hour without the helper).

---

## Composition Patterns

Once you have multiple boundaries wired, the helper scales to composition testing:

```rust
#[test]
fn cap_transfer_then_ipc_negative_trace() {
    // Trigger invalid capability transfer
    let before_cap = ring_buffer::write_count();
    let cap_result = transfer_capability(from, to_self, &invalid_cap);
    assert!(cap_result.is_err());
    let after_cap = ring_buffer::write_count();

    assert_closure_chain_closure(
        before_cap, after_cap,
        &[EventType::InvariantViolation, EventType::FailurePolicyAction],
        FailureSubsystem::Capability,
        FailureAction::FailStop,
    );

    // Subsequent IPC attempt should also fail (due to isolated process)
    let before_ipc = ring_buffer::write_count();
    let ipc_result = send_message(from_isolated_pid, &msg);
    assert!(ipc_result.is_err());
    let after_ipc = ring_buffer::write_count();

    assert_closure_chain_closure(
        before_ipc, after_ipc,
        &[EventType::FailurePolicyAction],  // Should see failure dispatch, not invariant check
        FailureSubsystem::Ipc,
        FailureAction::Isolate,
    );
}
```

---

## Integration Checklist

When adding a new boundary:

- [ ] Invariant check function defined (step 1)
- [ ] Boundary emit codes registered in verify/proof/PHASE_PLAN.md (code 0xNNNN format)
- [ ] Boundary wiring in subsystem file (entry/ok/fail emits)
- [ ] Invariant enforce() call integrated with failure dispatch
- [ ] Negative-trace test added to subsystem test module
- [ ] Test compiles with zero errors
- [ ] Test helper used (no manual event iteration)
- [ ] Commit message references PHASE_PLAN.md and test location
- [ ] THEOREM_INDEX.md updated with new INV-* entry

---

## Helper Signature Reference

```rust
pub fn assert_closure_chain_closure(
    event_count_before: usize,             // ring_buffer::write_count() before violation
    event_count_after: usize,              // ring_buffer::write_count() after violation
    expected_event_types: &[EventType],    // Events to check (e.g., &[InvariantViolation, FailurePolicyAction])
    expected_subsystem: FailureSubsystem,  // Expected subsystem (Scheduler, Syscall, MMU, etc.)
    expected_action: FailureAction,        // Expected action (Isolate, FailStop, Degrade)
)
```

**Panics** if:
- `after ≤ before` (no events emitted)
- Any expected event type not found in [before..after)
- failure outcome subsystem or action don't match

**Returns**: Nothing on success; all assertions pass silently.

---

## Performance Notes

- Ring buffer snapshot is O(1) per event
- Helper completes in O(N) where N = event_count_after - event_count_before (typically ~3–5 events)
- No heap allocation; all operations use atomic loads
- Tests are fast enough for CI / pre-commit gates

---

## Next Steps

1. Pick a boundary candidate from the "Next Boundaries" section above.
2. Follow the "Adding a Boundary: Full Walkthrough" pattern.
3. Run `cargo test --lib negative_trace_closure_chain` (once workspace dependency issue is resolved).
4. Update PHASE_PLAN.md and THEOREM_INDEX.md with the new test reference.
5. Commit with reference: `Adds [SUBSYSTEM]_negative_trace_closure_chain boundary test using assertion helper`.

---

## Related Documentation

- Implementation: [kernel/src/observability/test_helpers.rs](../../kernel/src/observability/test_helpers.rs)
- Phase tracking: [verification/proof/PHASE_PLAN.md](PHASE_PLAN.md)
- Theorem inventory: [verification/proof/THEOREM_INDEX.md](THEOREM_INDEX.md)
- Existing tests: [kernel/src/scheduler/process.rs](../../kernel/src/scheduler/process.rs#L1369), [kernel/src/platform/syscall.rs](../../kernel/src/platform/syscall.rs#L2120), [kernel/src/arch/aarch64_vectors.rs](../../kernel/src/arch/aarch64_vectors.rs#L420), [kernel/src/arch/mmu_aarch64.rs](../../kernel/src/arch/mmu_aarch64.rs#L1053), [kernel/src/arch/aarch64_dtb.rs](../../kernel/src/arch/aarch64_dtb.rs#L958)
