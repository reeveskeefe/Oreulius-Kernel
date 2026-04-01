# Oreulia Service Pointer Capabilities

**Status:** Implemented in the current WASM runtime, capability manager, IPC transfer path, and shell demos.

Primary implementation surfaces:

- [`kernel/src/execution/wasm.rs`](../../kernel/src/execution/wasm.rs)
- [`kernel/src/capability/mod.rs`](../../kernel/src/capability/mod.rs)
- [`kernel/src/shell/commands.rs`](../../kernel/src/shell/commands.rs)

---

## 1. What a service pointer is

A service pointer is a capability-scoped reference to a live WASM function owned by a running instance. Instead of calling a service by ambient name lookup, a caller must hold authority to a `ServicePointer` object and invoke that object explicitly.

Current rights relevant to service pointers are:

- `SERVICE_INVOKE`
- `SERVICE_DELEGATE`
- `SERVICE_INTROSPECT`

The object type used by the capability system is `CapabilityType::ServicePointer`.

---

## 2. Current implementation shape

The runtime keeps a dedicated service-pointer registry with capacity:

- `MAX_SERVICE_POINTERS = 64`

Each active entry records:

- `object_id`
- `owner_pid`
- `target_instance`
- `function_index`
- a parsed WASM signature snapshot
- per-window rate policy fields

Registration is performed by [`register_service_pointer`](../../kernel/src/execution/wasm.rs), and invocation is performed by:

- [`invoke_service_pointer`](../../kernel/src/execution/wasm.rs) for the legacy `u32` path
- [`invoke_service_pointer_typed`](../../kernel/src/execution/wasm.rs) for the typed path

---

## 3. Registration path

### 3.1 Host ABI

The WASM host registration surface is:

- host id `9`: `service_register`

The host implementation accepts either:

- an `i32` function selector
- a `funcref`

### 3.2 Registration rules

Current registration requires all of the following:

- the target instance must exist
- the registering `owner_pid` must match the instance owner
- the target must resolve to a defined WASM function
- host imports cannot be registered as service pointers
- parameter and result arity must fit the runtime limits

On success, the runtime:

1. creates a fresh kernel object id
2. inserts a registry entry
3. grants the owner a `ServicePointer` capability
4. returns both `object_id` and `cap_id`

Default rights on registration are:

- always: `SERVICE_INVOKE | SERVICE_INTROSPECT`
- plus `SERVICE_DELEGATE` when the caller requested a delegatable pointer

Default rate policy today is:

- `max_calls_per_window = 128`
- `window_ticks = PIT frequency`
- `window_start_tick = current tick`

---

## 4. Invocation semantics

### 4.1 Typed invocation is the authoritative path

The typed host ABI surface is:

- host id `12`: `service_invoke_typed`

The legacy integer-only helper delegates into the typed implementation.

### 4.2 Enforcement performed today

Before a call is executed, the runtime checks:

- the caller holds `SERVICE_INVOKE` for the object
- the registry entry is still active
- the current rate window allows another call
- the live runtime function signature still matches the stored signature snapshot
- provided argument values match the stored parameter types

Execution itself is performed under `with_instance_exclusive`, which prevents re-entrant mutation of the target instance while the call is in progress.

Observable failure classes include:

- invoke denied by capability check
- target instance busy
- target instance unavailable
- signature mismatch
- invocation failure inside the target

The legacy path remains intentionally narrower:

- it only marshals `u32` arguments as `i32`
- it expects zero or one `i32`-compatible result

---

## 5. IPC transfer and import

Service pointers can be moved over IPC, but only through the existing capability export/import path.

### 5.1 Export

To export a service pointer into an IPC message:

- the sender must hold the service-pointer capability
- the capability must include `SERVICE_DELEGATE`
- export goes through [`export_capability_to_ipc`](../../kernel/src/capability/mod.rs)

### 5.2 Import

Import is explicit:

- shell demos call [`import_capability_from_ipc`](../../kernel/src/capability/mod.rs) after receiving the message
- the WASM runtime automatically imports received service-pointer caps in the `channel_recv` host path and injects a WASM-side `ServicePointer` handle for them

The runtime also tracks the most recently auto-imported service handle for the current instance through the `last_service_handle` host surface.

This is important: service-pointer transfer is real and working, but it is not ambient. A receiver must still import or accept the transferred capability through the defined path.

---

## 6. Lifecycle and durability behavior

### 6.1 Instance teardown

When a WASM instance is destroyed:

- its service pointers are revoked from the registry
- active capabilities for the corresponding object are revoked

### 6.2 Rebind support

The runtime also includes a compatibility rebind path:

- when an instance disappears, the registry can search for a compatible replacement target
- compatibility is based on signature equality
- compatible pointers may be rebound instead of only being destroyed

This is a real implementation detail, not a theory-only idea.

### 6.3 Temporal persistence

The service-pointer registry has a temporal snapshot/restore path in the WASM runtime.

That snapshot preserves:

- active entries
- object ids
- owner pids
- target instances
- function indices
- rate-window state
- signature tags

So service pointers already participate in the broader temporal durability story, even though higher-level replay semantics remain incomplete elsewhere.

---

## 7. Shell and runtime verification surfaces

Current shell commands include:

- `svcptr-register`
- `svcptr-invoke`
- `svcptr-send`
- `svcptr-recv`
- `svcptr-inject`
- `svcptr-demo`
- `svcptr-demo-crosspid`
- `svcptr-typed-demo`

These are useful because they prove different slices of the implementation:

- direct registration and invocation
- IPC export/import
- cross-PID transfer
- typed mixed-value invocation

They are the fastest way to verify the service-pointer system end to end inside the kernel today.

---

## 8. What is true today, and what is not

### Implemented

- direct WASM-function registration as a service pointer
- typed and legacy invocation paths
- capability-gated invocation
- delegate-right enforcement for IPC export
- shell demos for local and cross-PID transfer
- automatic WASM-side import of received service-pointer caps
- registry snapshot/restore support
- instance-destroy revocation and compatible-target rebinding

### Not true

- service pointers are not a general ambient service namespace
- exported pointers are not zero-sum by construction
- the legacy ABI is not fully type-general
- registration does not allow host-import targets

The important public claim is narrower and accurate: Oreulia already has a real callable-capability model for WASM services, and that model is enforced by capability rights and runtime signature checks.
