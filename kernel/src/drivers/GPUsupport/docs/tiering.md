# GPU Tiering

- Tier 0: Probe only
- Tier 1: Scanout
- Tier 2: Transfer2D
- Tier 3: Compute
- Tier 4: Optimized

Backends may only claim a tier when the corresponding feature set is actually
implemented and safe.

