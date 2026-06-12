# Legacy Compositor Retirement

The driver-level compositor in `kernel/src/drivers/compositor.rs` has been
removed. Oreulius now has one application-facing compositor architecture:
the capability-checked service in `kernel/src/compositor`.

The existing WASM imports remain ABI-compatible. A `WasmInstance` opens one
compositor session bound to its `ProcessId` and receives opaque local window
handles. The kernel maps those handles to service-owned window and surface
identifiers plus their capabilities; those capabilities are never exposed to
the module.

Pixel writes, rectangle fills, text drawing, movement, z-order changes, size
queries, destruction, and presentation all pass through
`CompositorRequest`. `compositor_flush` now commits surface damage and lets the
service present through its backend. It no longer locks or writes the GPU
framebuffer directly.

Destroying a WASM runtime instance closes its compositor session. Session
closure destroys its windows and surfaces and revokes their capabilities.
Failed runtime initialization performs the same cleanup.

Reusable behavior lives in:

- `kernel/src/compositor/surface.rs` for ARGB8888 surfaces, clipping, fills,
  row blits, and bitmap text.
- `kernel/src/compositor/present.rs` for source-over alpha blending and
  damage-driven presentation.
- `kernel/src/compositor/service.rs` for authenticated resource operations,
  lifecycle, policy, capabilities, and audit records.
