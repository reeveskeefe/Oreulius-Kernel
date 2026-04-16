// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


//! Oreulius Compositor Subsystem
//!
//! A first-class kernel display service providing:
//!
//! - **Capability-scoped window ownership** — no process can mutate another
//!   process's window by guessing a numeric ID.
//! - **IPC / service boundary** — clients open sessions through the kernel
//!   service registry; raw global draw functions are not the primary API.
//! - **Focus-managed input routing** — only the focused/captured client
//!   receives relevant keyboard and pointer events.
//! - **Damage-driven presentation** — dirty rectangles are tracked per window
//!   and only damaged regions are re-composited on each present tick.
//! - **Dedicated surface allocator** — surface pixel buffers come from the
//!   general kernel page allocator, not the JIT arena.
//!
//! ## Module layout
//!
//! ```text
//! compositor/
//! ├── mod.rs          ← this file: init, global accessor, re-exports
//! ├── service.rs      ← CompositorService: global singleton + service entry
//! ├── protocol.rs     ← IPC message types (CompositorRequest / Response)
//! ├── session.rs      ← one CompositorSession per GUI client process
//! ├── window.rs       ← WindowTable, WindowMeta, z-order management
//! ├── surface.rs      ← SurfaceAllocator, Surface (not JIT arena)
//! ├── damage.rs       ← DamageAccumulator, dirty-rect merge
//! ├── present.rs      ← present loop, frame scheduling, full composite
//! ├── input.rs        ← FocusStack, hit-test, event routing
//! ├── backend.rs      ← DisplayBackend trait
//! ├── fb_backend.rs   ← Framebuffer/GPU-backed DisplayBackend impl
//! ├── capability.rs   ← display/window/surface capability helpers
//! ├── policy.rs       ← quotas, visibility rules, security checks
//! └── audit.rs        ← audit and telemetry hooks
//! ```
//!
//! ## Runtime flow
//!
//! ```text
//! App / WASM client
//!   → CompositorRequest::OpenSession      (via service registry IPC)
//!   → CompositorResponse::SessionGranted  (session_id + event_channel cap)
//!   → CompositorRequest::CreateWindow     (session capability required)
//!   → CompositorResponse::WindowCreated   (window_id + surface_cap)
//!   → CompositorRequest::CommitSurface    (surface capability required)
//!
//! CompositorService (kernel side)
//!   → validates capabilities
//!   → records damage regions
//!   → schedules present pass via kernel timer tick
//!   → routes input events to focused window's channel
//! ```

#![allow(dead_code)]

pub mod audit;
pub mod backend;
pub mod capability;
pub mod damage;
pub mod fb_backend;
#[cfg(not(target_arch = "aarch64"))]
pub mod input;
pub mod policy;
pub mod present;
pub mod protocol;
#[cfg(not(target_arch = "aarch64"))]
pub mod service;
pub mod session;
pub mod surface;
pub mod window;

#[cfg(not(target_arch = "aarch64"))]
pub use service::CompositorService;
#[cfg(not(target_arch = "aarch64"))]
pub use service::COMPOSITOR_SERVICE;

// ---------------------------------------------------------------------------
// Legacy backward-compatibility shim
// ---------------------------------------------------------------------------
//
// The WASM runtime (execution/wasm.rs) calls `crate::compositor::compositor()`
// to obtain a guard with the old low-level drawing API (create_window, set_pixel,
// draw_text, …).  We delegate to the legacy drivers::compositor instance so
// that existing WASM host functions continue working unmodified.
//
// New code should use `COMPOSITOR_SERVICE` / `CompositorRequest` IPC instead.

/// Return a lock-guard for the legacy compositor, preserving the old API.
///
/// Delegates to `crate::drivers::x86::compositor::compositor()`.
#[cfg(not(target_arch = "aarch64"))]
pub fn compositor() -> spin::MutexGuard<'static, crate::drivers::x86::compositor::Compositor> {
    crate::drivers::x86::compositor::compositor()
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/// Initialise the compositor service from the resolved framebuffer resolution.
///
/// Call this once after `gpu_support::init()` has configured the display.
/// On platforms with no framebuffer the compositor still starts but the
/// backend is a no-op stub.
#[cfg(not(target_arch = "aarch64"))]
pub fn init(width: u32, height: u32) {
    service::init(width, height);
}
#[cfg(target_arch = "aarch64")]
pub fn init(_width: u32, _height: u32) {}

/// Perform a compositor present tick.  Call from the kernel timer hook or the
/// scheduler idle loop.  This is a no-op if nothing is dirty.
#[cfg(not(target_arch = "aarch64"))]
pub fn tick() {
    service::tick();
}
#[cfg(target_arch = "aarch64")]
pub fn tick() {}
