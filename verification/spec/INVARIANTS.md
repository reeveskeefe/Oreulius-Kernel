# Verification Invariants

These invariants define the safety properties the verification workspace tracks.

- INV-001: Capability attenuation must never increase authority.
- INV-002: Replay windows must reject duplicate or expired transcripts.
- INV-003: Writable and executable memory states must remain disjoint where
  W^X is claimed.
- INV-004: Lock ordering must not admit self-deadlock edges in the modeled DAG.
- INV-005: Scheduler fuel consumption must remain bounded by the declared
  execution budget.
- INV-006: Generated proof evidence must remain outside the runtime dependency
  graph.
