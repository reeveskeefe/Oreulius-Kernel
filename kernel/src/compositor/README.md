# Oreulius Compositor (kernel/src/compositor)

This document explains what the compositor is for in Oreulius.

Oreulius is designed to run small, isolated WASI workloads on edge/cloud hosts,
providing deterministic temporal snapshots, capability-based authority transfer,
and in-kernel verification to enable secure, auditable migration and replay.

The compositor exists to support that mission by making display, input, and
pixel authority explicit, bounded, and auditable.

## 1) Purpose in the system

The compositor is not a generic desktop add-on. It is a capability-scoped
interaction surface for isolated workloads that need visual output while
preserving Oreulius security and replay properties.

For this purpose, the compositor provides:
- deterministic present behavior with damage-driven updates
- capability-scoped authority over sessions, windows, and surfaces
- explicit input routing and capture semantics
- bounded, auditable state transitions

## 2) Runtime status (concise)

- The compositor is an active kernel subsystem on non-AArch64 builds.
- The default user interaction surface for Oreulius is still the serial shell.
- The compositor is part of the desktop track, not yet the default system personality.
- Legacy draw host functions are still present and used by existing WASM paths.

What this means:
- The compositor is real and wired.
- The desktop experience is staged, not claimed as complete.

## 3) Why this subsystem exists

Oreulius is capability-native and WASM-first. A compositor aligns with that model by making
pixel authority explicit instead of ambient.

The compositor exists to provide:
- capability-scoped ownership of windows and surfaces
- deterministic present behavior with damage-driven updates
- explicit input routing rules (focus/capture) instead of implicit global trust
- an auditable transition path from legacy host draw calls to capability-scoped IPC

## 4) Non-goals (for now)

The compositor is not currently:
- a full desktop shell
- a complete window-manager product
- a cross-hardware accelerated graphics stack
- a replacement for all legacy rendering paths in one step

## 5) Runtime position in the kernel

High-level flow:

1. Boot/runtime initializes GPU substrate (if available).
2. Runtime initializes compositor with active scanout dimensions.
3. Timer tick calls compositor tick.
4. Tick pumps input and presents dirty regions.
5. Legacy WASM host functions continue to draw through the compatibility path.

Primary integration points:
- Runtime init call site: `kernel/src/arch/x86_64_runtime.rs`
- Tick hook: `kernel/src/lib.rs`
- Legacy host function calls: `kernel/src/execution/wasm.rs`
- Legacy compositor backend: `kernel/src/drivers/compositor.rs`

## 6) Module layout

`kernel/src/compositor/` currently includes:

- `mod.rs`: exports, init/tick wrappers, legacy compatibility shim
- `service.rs`: global compositor service singleton and request dispatcher
- `protocol.rs`: request/response and error protocol types
- `session.rs`: per-client session table and quotas
- `window.rs`: window metadata, z-order, ownership tracking
- `surface.rs`: pixel surface allocation and write operations
- `damage.rs`: dirty-rect tracking and clipping
- `present.rs`: blending/composition pass and scanout writes
- `input.rs`: focus/capture routing for input events
- `capability.rs`: compositor capability mint/validate/revoke
- `policy.rs`: guardrails for dimensions and quotas
- `audit.rs`: event recording and recent history
- `backend.rs`: display backend abstraction
- `fb_backend.rs`: framebuffer/gpu-support-backed backend

## 7) API model

Two API layers currently coexist:

### 6.1 Legacy compatibility API (active)

Legacy WASM host functions (28-37) call into the compatibility shim and legacy draw path.
This preserves existing applications while migration continues.

### 6.2 Capability-scoped service API (target)

Service IPC uses typed requests and responses with explicit capability checks per operation.
The target steady-state is to route clients through this path.

## 8) Security model

The compositor applies capability checks for all mutating operations.

Core rules:
- A session must hold a valid session capability for session-level actions.
- Window operations require a valid window capability bound to that window.
- Pixel writes and commits require a valid surface capability bound to that surface.
- Session teardown revokes session-associated capabilities.

Security intent:
- no ambient draw authority
- no cross-session window mutation by guessed IDs
- explicit revocation model on teardown

## 9) Rendering model

Composition behavior is damage-driven:

1. Mutations mark dirty window regions.
2. Dirty regions are clipped and accumulated.
3. Tick triggers present when dirty state exists.
4. Windows are composed in z-order into backend output.
5. Damage state clears after successful present.

Operational goals:
- work proportional to changed regions
- deterministic present pass ordering
- predictable bounds via static limits

## 10) Input and focus model

Input routing uses focus and pointer-capture semantics:
- keyboard events route to focused target
- pointer events route by hit-test unless captured
- capture persists for drag-style interactions until release

This prevents implicit global input trust and keeps delivery explicit.

## 11) Platform and build gating

- Full service/input path is non-AArch64 today.
- AArch64 builds keep data/model portability where possible but use stubs for active service behavior.
- Legacy and service paths currently coexist by design during migration.

## 12) Static limits and operational guardrails

The compositor uses compile-time bounded tables and explicit quotas.
This is intentional to reduce memory surprise and failure ambiguity.

Guardrails include:
- bounded sessions/windows/surfaces
- bounded damage rect accumulation
- explicit size validation for windows/surfaces
- policy checks before allocation-heavy operations

## 13) Mission alignment

The compositor supports the core Oreulius mission in four direct ways:

1. Isolated WASI workloads:
- separates visual resources by capability instead of ambient global access.

2. Deterministic temporal behavior:
- damage-driven present and bounded internal state make rendering behavior
	traceable and replay-friendly.

3. Capability-based authority transfer:
- operations are guarded by explicit capabilities for session/window/surface scope.

4. In-kernel verification posture:
- the subsystem exposes bounded, testable surfaces that can be validated in
	runtime and CI verification workflows.

## 14) Desktop track milestones

The compositor is part of the Desktop Track with explicit phases:

- D0 (current): compositor wired and testable, shell remains default surface
- D1: single-session demonstrable GUI loop on x86_64 QEMU
- D2: stable multi-window capability-scoped app contract
- D3: desktop session shell and day-to-day interaction loop

Exit criteria are code and tests, not docs-only claims.

## 15) Test strategy (minimum)

Before raising compositor claims, verify at least:

1. Build and boot x86_64 path.
2. Compositor init logs with detected dimensions.
3. Tick path runs without panic under timer load.
4. Legacy host function draw path still works.
5. Capability validation rejects invalid tokens.
6. Session teardown revokes associated capabilities.
7. Damage/present path handles partial and full-screen updates.

## 16) Contributor rules for this subsystem

When changing compositor behavior:
- update this README and keep claims exact
- state whether change affects legacy path, service path, or both
- include architecture implications (x86_64/i686/AArch64)
- do not mark milestone progression without test evidence

## 17) Summary

The compositor is a capability-aligned kernel subsystem that provides a visual
control surface without breaking Oreulius's core promises around isolation,
determinism, authority tracking, and auditability.

It should be discussed as:
- purpose-built for secure, auditable workload interaction,
- aligned with WASI edge/cloud execution goals,
- and measured by deterministic, verifiable behavior.
