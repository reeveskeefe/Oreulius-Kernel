# Oreulia Compositor End-to-End Plan

## Current State

Oreulia already has a real compositor implementation in `kernel/src/drivers/compositor.rs`,
but it is not yet a full end-to-end display service.

What exists today:

- window/layer allocation
- per-window pixel buffers
- ARGB software composition
- framebuffer flush path
- WASM host calls for creating windows and drawing pixels/text
- unified keyboard/mouse event queue
- x86 framebuffer initialization

What is still missing:

- capability-scoped window ownership
- IPC/service boundary for GUI clients
- focused-window input routing
- correct overlapping-window present path
- damage tracking and frame pacing
- resize lifecycle and surface management
- multiarch display bring-up beyond x86 initialization
- security and quota controls for long-lived surfaces

## Why The Current Design Is Not Enough

The current compositor is too low-level and too global for Oreulia's actual
architecture.

Architectural problems:

- It lives in `drivers/`, but it is really a kernel service, not a hardware driver.
- Window access is raw `window_id` based. There is no capability or per-client isolation.
- Input is global. There is no focus manager or event routing to the owning window.
- `flush_window()` writes a single window directly to the framebuffer and ignores
  occlusion by higher z-order windows.
- `composite()` performs a full-screen software walk and is not wired into a
  regular present loop.
- Window buffers are allocated from the JIT page arena, which is the wrong
  long-lived allocation domain for UI surfaces.

## Target Design

The compositor should become a first-class kernel subsystem with device backends
below it and service/capability interfaces above it.

Recommended target location:

```text
kernel/src/compositor/
```

This should eventually replace `kernel/src/drivers/compositor.rs`.

Hardware-facing code should remain where it already belongs:

- `kernel/src/drivers/framebuffer.rs`
- `kernel/src/drivers/GPUsupport/mod.rs`
- `kernel/src/drivers/input.rs`
- `kernel/src/drivers/mouse.rs`
- `kernel/src/drivers/keyboard.rs`

## Proposed Module Layout

```text
kernel/src/compositor/
├── mod.rs
├── service.rs        # global compositor service entry point
├── protocol.rs       # IPC message types for clients
├── session.rs        # one GUI client/session per process
├── window.rs         # window table, z-order, lifecycle
├── surface.rs        # pixel surfaces and dedicated surface allocator
├── damage.rs         # dirty rectangles / damage accumulation
├── present.rs        # composition + frame scheduling
├── input.rs          # focus, capture, hit-test routing, event delivery
├── backend.rs        # abstract display backend trait
├── fb_backend.rs     # framebuffer/GPU-backed implementation
├── capability.rs     # display/window/surface capability helpers
├── policy.rs         # quotas, visibility rules, security checks
└── audit.rs          # audit and telemetry hooks
```

## Core Rules

### 1. The compositor is a service

Clients should not call raw global drawing functions directly.

The compositor should register as a kernel service and expose:

- session creation
- window creation
- surface updates
- input subscription
- present requests

That matches Oreulia's service registry and IPC model much better than adding
more direct host hooks.

### 2. Windows must be capability-scoped

Each client process should receive capabilities for:

- compositor session
- window create/destroy
- surface write
- input subscribe
- present/commit

No process should be able to mutate another process's window by guessing a
numeric window ID.

### 3. Input must be routed, not globally consumed

The compositor should own focus and hit testing.

Input flow should be:

```text
keyboard/mouse IRQ -> input ring -> compositor input router -> focused window channel
```

This means the future browser app, terminal app, or desktop shell will each
receive only the events they are allowed to receive.

### 4. Presentation must be damage-driven

The compositor should not redraw the whole screen for every update, and it
should not flush a single window directly without considering overlap.

Instead:

- track per-window dirty rectangles
- merge them into a present damage list
- composite only damaged regions
- copy those regions to the active display backend

### 5. Surface memory must not come from the JIT arena

UI surfaces are persistent graphical resources.

They should use a dedicated surface allocator in the memory subsystem, not
`jit_allocate_pages()`.

## End-to-End Runtime Model

```text
App/WASM client
  -> requests compositor session
  -> receives session capability + event channel
  -> creates window
  -> receives window capability + surface capability
  -> writes into owned surface
  -> commits present request

Compositor service
  -> validates capability
  -> records damage
  -> schedules present pass
  -> routes input to focused window
  -> emits lifecycle and resize events

Display backend
  -> pushes composed frame or damage regions to framebuffer/GPU
```

## Implementation Phases

### Phase 1: Service Boundary

- create `kernel/src/compositor/` as a new subsystem
- move the current window/layer logic behind a `CompositorService`
- define IPC protocol for session, window, and present operations
- add a `ServiceType::Display` or `ServiceType::Compositor`
- stop exposing raw global window mutation as the primary interface

Exit criteria:

- a process can open a compositor session through a service call
- window creation is capability-checked

### Phase 2: Surface Model

- add dedicated surface allocator
- separate window metadata from surface storage
- support surface resize/recreate
- attach quotas per process/session

Exit criteria:

- no compositor allocations depend on the JIT arena
- surfaces can be resized without corrupting global state

### Phase 3: Input + Focus

- add focus stack
- add pointer hit testing and capture
- deliver input through per-session or per-window IPC channels
- stop relying on clients consuming the raw global input queue

Exit criteria:

- only the focused or captured client receives relevant input

### Phase 4: Correct Presentation

- replace direct `flush_window()` semantics with damage-aware composition
- add dirty rectangle accumulation
- add a compositor tick/present worker integrated with the scheduler
- support partial redraws

Exit criteria:

- overlapping windows redraw correctly
- frame updates are incremental, not brute-force full-screen on every change

### Phase 5: Desktop Shell Integration

- provide desktop/root window session
- add window list/focus-change events
- add move/resize protocol messages
- add cursor rendering and basic decorations if desired

Exit criteria:

- a shell app can manage multiple windows without privileged direct access

### Phase 6: Multiarch Bring-Up

- ensure compositor backend initialization works on x86_64, i686, and AArch64
- unify display backend selection around framebuffer or GPU support
- validate fallback behavior when only a text console is available

Exit criteria:

- compositor service initializes cleanly on every supported arch

## What Should Stay Out Of The Kernel

The kernel compositor should not become a full GUI toolkit.

Keep these outside:

- HTML layout
- CSS layout
- font shaping engines
- image codecs beyond minimal boot assets
- browser renderer logic
- JavaScript runtime

Those belong in clients or sandboxed services on top of the compositor.

## Recommended First Move

Do not try to "finish" the current `drivers/compositor.rs` in place.

The right first move is:

1. introduce `kernel/src/compositor/`
2. make it a service-oriented subsystem
3. move the current drawing logic under that service
4. add capability and IPC boundaries before adding more features

That gives Oreulia a real display architecture instead of a larger drawing stub.
