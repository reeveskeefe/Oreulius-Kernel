# Canonical Invariants

- INV-CAP-001: capability authority cannot increase without authorized derivation.
- INV-MEM-001: no out-of-bounds memory access in modeled transitions.
- INV-WX-001: no reachable RWX page state.
- INV-CFI-001: indirect control transfers target only allowed entry sets.
- INV-TMP-001: temporal rollback and merge preserve object consistency invariants.
- INV-PER-001: persisted temporal decode rejects integrity-inconsistent payloads.
- INV-NET-001: CapNet acceptance requires integrity + freshness + rights attenuation.
- INV-PRIV-001: user/kernel privilege transitions preserve control-return integrity.
