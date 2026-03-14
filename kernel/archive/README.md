## Kernel Archive

This directory holds files that are intentionally kept out of the active
kernel build and run surface.

Archived here:
- `boot-experiments/`: old standalone boot or minimal test sources that are
  not assembled or linked by the current build scripts.
- `legacy-scripts/`: superseded helper scripts that are no longer part of the
  documented build or run flows.

Generated artifacts and ad hoc logs are not tracked here. They are kept in
ignored local archive folders when preserved, or regenerated from the active
build scripts when needed.
