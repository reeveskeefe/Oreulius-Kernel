# Oreulia First-Class Polyglot Kernel Services

> **Status:** Fully implemented. WASM host ABI IDs 103–105. Core: `kernel/src/execution/wasm.rs` (`POLYGLOT_REGISTRY`). SDK: `wasm/sdk/src/polyglot.rs`. Language tag sourced from `oreulia_lang` WASM custom section. Integrated with the Service Pointer and capability subsystems.

---

## 1. Overview

In virtually all microkernel designs, inter-process communication is uniform: a process calls a service via a channel and the kernel does not care what language either side is written in. Oreulia goes a step further — the kernel **knows** what language each WASM module is written in, validates language compatibility rules at link time, and makes cross-language capability injection a first-class kernel operation with its own host ABI.

Polyglot Kernel Services means:

1. **Modules self-declare their language** via the `oreulia_lang` custom WASM section, embedded at compile time.
2. **The kernel maintains a named service registry** (`POLYGLOT_REGISTRY`, 16 entries) mapping module names to their `instance_id`, `LanguageTag`, and associated capability.
3. **Linking** (`polyglot_link`) resolves a module-name + export-name pair into a live `ServicePointer` capability injected into the caller's capability table — the capability *is* the cross-language call gate.
4. **Singleton enforcement** — Python and JavaScript modules are inherently stateful interpreters; the registry enforces at most one active instance per name+language combination, refreshing its instance pointer on re-register rather than adding a duplicate entry.

The design principle is that language interoperability should be as verifiable and capability-scoped as any other kernel resource. A Rust module linking to a Python module gets a capability; the capability carries the `SERVICE_INVOKE` rights requirement; and the capability graph records the cross-language delegation edge.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Calling WASM Module (any language)                                  │
│  polyglot::register("my-service")                                   │
│  let cap = polyglot::link("target-module", "export-fn").unwrap()    │
│  // cap is now a ServicePointer in the caller's capability table     │
└────────────────────────────┬─────────────────────────────────────────┘
                             │  WASM host ABI (IDs 103–105)
┌────────────────────────────▼─────────────────────────────────────────┐
│  Polyglot Host Functions  (kernel/src/execution/wasm.rs)            │
│  host_polyglot_register / polyglot_resolve / polyglot_link          │
└──────────┬──────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────────┐
│  POLYGLOT_REGISTRY (16 × PolyglotEntry)                             │
│  name → { instance_id, language, cap_object, owner_pid, singleton } │
└──────┬───────────────────────────────────────────────────┬──────────┘
       │  polyglot_link path                               │
       │                                                   │
┌──────▼────────────────────────┐   ┌─────────────────────▼──────────┐
│  SERVICE_POINTERS registry    │   │  CapabilityManager              │
│  Find by target instance_id  │   │  Inject WasmCapability::        │
│  (ServicePointerEntry)        │   │  ServicePointer into caller     │
└───────────────────────────────┘   └────────────────────────────────┘
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/execution/wasm.rs` | `PolyglotEntry`, `LanguageTag`, `POLYGLOT_REGISTRY`, host functions IDs 103–105 |
| `kernel/src/execution/service_pointer.rs` | `SERVICE_POINTERS` registry, `ServicePointerEntry` |
| `kernel/src/capability/manager.rs` | `capabilities.inject()` called from `polyglot_link` |
| `wasm/sdk/src/polyglot.rs` | SDK: `register`, `resolve`, `link`, `PolyglotService`, `ServiceHandle` |

---

## 3. Formal Model

### 3.1 Language tag and singleton semantics

**Definition P.1 (Language Tag).** A `LanguageTag` is one of `{Unknown, Rust, C, Zig, Python, JS}`. It is embedded in the WASM binary in the `oreulia_lang` custom section at compile time. The kernel reads it from `self.module.language_tag` when a module is loaded.

**Definition P.2 (Singleton Language).** Python and JavaScript are *singleton* languages: the registry enforces at most one active service registration per `(name, LanguageTag)` pair where `LanguageTag ∈ {Python, JS}`.

**Definition P.3 (Registration Idempotency for Singletons).** For singleton languages, re-registering the same `(name, LanguageTag)` pair refreshes the `instance_id` and `owner_pid` of the existing entry rather than creating a new one.

**Proposition P.4 (No Singleton Duplication).** At any point in time, at most one `PolyglotEntry` in `POLYGLOT_REGISTRY` has a given `(name, Python)` or `(name, JS)` pair.

*Proof.* `host_polyglot_register` for a singleton language iterates the registry before inserting. If an entry with matching name and language is found, it updates `instance_id` and `owner_pid` in-place and returns `0` without consuming a new slot. $\square$

### 3.2 Name resolution invariants

**Definition P.5 (Name Uniqueness).** A name is a UTF-8 byte string of 1–32 bytes. The registry enforces that no two entries with different `LanguageTag` values may share the same name if the second registration is from a different module instance.

**Invariant P.6 (Name Conflict Rule).** If `POLYGLOT_REGISTRY` contains entry $e$ with name $n$ and `e.language ≠ lang` or `e.instance_id ≠ self.instance_id`, then `polyglot_register(n)` returns `−3` (name taken by different module).

### 3.3 Link capability semantics

**Definition P.7 (Polyglot Link Capability).** A polyglot link capability is an `OreuliaCapability` of type `WasmCapability::ServicePointer` with:
- `object_id`: derived from the target module's `instance_id` and current tick
- `cap_type`: `CapabilityType::PolyglotLink`
- `target_lang`: `LanguageTag` of the target module

**Definition P.8 (SERVICE_INVOKE rights requirement).** For target modules with `LanguageTag ∈ {Python, JS}`, the link capability is required to carry `SERVICE_INVOKE` rights. This is enforced at link time by `host_polyglot_link`.

**Proposition P.9 (Cross-Language Capability Lineage).** The delegation edge from the calling module's capability table to the injected `ServicePointer` capability is recorded in `CapGraph::record_delegation`. This means cross-language links are auditable in the capability provenance chain.

*Proof.* `host_polyglot_link` calls `self.capabilities.inject(pid, new_cap)` which goes through `CapabilityManager::grant_capability`. The `CapabilityManager` calls `cap_graph::record_delegation` for every grant that has a non-zero `parent_pid`. $\square$

---

## 4. Data Structures

### 4.1 `LanguageTag`

```rust
#[derive(Copy, Clone, PartialEq)]
pub enum LanguageTag {
    Unknown,
    Rust,
    C,
    Zig,
    Python,   // singleton
    JS,       // singleton
}
```

Read from the `oreulia_lang` WASM custom section on module load.

### 4.2 `PolyglotEntry`

```rust
struct PolyglotEntry {
    active:      bool,
    name:        [u8; 32],
    name_len:    u8,
    instance_id: usize,       // WasmInstance ID of registered module
    language:    LanguageTag,
    cap_object:  u64,         // capability object ID for the registry entry
    owner_pid:   ProcessId,
    singleton:   bool,        // true for Python and JS
}

// POLYGLOT_REGISTRY: Mutex<PolyglotRegistry>
// capacity: 16 entries
```

---

## 5. WASM Host ABI (IDs 103–105)

### ID 103 — `polyglot_register(name_ptr: i32, name_len: i32) → i32`

Registers the calling module as a named polyglot service:

1. Reads up to 32 bytes from WASM memory at `name_ptr`. Returns `−1` if `name_len == 0` or `name_len > 32`.
2. Reads `self.module.language_tag` to determine the caller's language.
3. Iterates `POLYGLOT_REGISTRY`:
   - If an entry with the same name and language exists AND `singleton == true` (Python/JS): updates `instance_id` and `owner_pid` in place, returns `0`.
   - If an entry with the same name exists for a **different** module instance: returns `−3`.
4. Finds a free registry slot. Returns `−2` if registry full (16 entries).
5. Inserts `PolyglotEntry { active: true, name, instance_id, language, singleton: language ∈ {Python, JS}, ... }`.
6. Returns `0`.

### ID 104 — `polyglot_resolve(name_ptr: i32, name_len: i32) → i32`

Resolves a service name to its `instance_id`:

1. Reads name bytes from WASM memory.
2. Iterates `POLYGLOT_REGISTRY` for an active entry with matching name.
3. Returns `instance_id as i32` on match, `−2` if not found.

This is useful for checking whether a service is available before attempting to link, or for obtaining the raw instance ID for custom dispatch.

### ID 105 — `polyglot_link(name_ptr: i32, name_len: i32, export_ptr: i32, export_len: i32) → i32`

Links the calling module to a specific exported function of a named polyglot service:

1. Reads `module_name` and `export_name` from WASM memory. Returns `−1` if either is empty or too long.
2. Resolves `module_name` in `POLYGLOT_REGISTRY`. Returns `−2` if not found.
3. Finds the corresponding `ServicePointerEntry` in `SERVICE_POINTERS` matching the resolved `instance_id`. Returns `−3` if the export is not found.
4. Creates `OreuliaCapability::new_polyglot_link(pid, object_id, target_lang)`.
5. Cross-language check: if `target_lang ∈ {Python, JS}`, asserts `SERVICE_INVOKE` rights on the new capability.
6. Injects `WasmCapability::ServicePointer` into the caller's capability table via `self.capabilities.inject()`. Returns `−4` if the capability table is full.
7. Logs: `[polyglot] link NAME (SRC_LANG) -> EXPORT (TGT_LANG) cap=N`.
8. Calls `observer_notify(POLYGLOT_LINK, &[src_id_le..., tgt_id_le...])`.
9. Returns `cap_handle as i32`.

---

## 6. SDK Usage

```rust
use oreulia_sdk::polyglot::{self, PolyglotService, ServiceHandle};

// ── Registering a service (module init code) ────────────────────────────────
let _svc = PolyglotService::register("my-analytics")
    .expect("registration failed (registry full or name conflict)");
// PolyglotService holds the name; re-registers on clone/re-creation for singletons.

// ── Resolving a service (existence check) ──────────────────────────────────
match polyglot::resolve("my-analytics") {
    Some(instance_id) => { /* service is active, instance_id known */ }
    None              => { /* service not yet registered */ }
}

// ── Linking to a service (get a capability) ─────────────────────────────────
let handle = ServiceHandle::link("my-analytics", "process_data")
    .expect("link failed: module not found or export not found");
// handle.cap is a ServicePointer capability in this module's cap table.
// Use handle.cap to invoke the service via the IPC/service ABI.

// ── Low-level API ───────────────────────────────────────────────────────────
let cap: u32 = polyglot::link("ml-runtime", "infer").expect("link failed");

// ── SDK types ───────────────────────────────────────────────────────────────
pub fn register(name: &str) -> bool
pub fn resolve(name: &str) -> Option<i32>
pub fn link(module_name: &str, export_name: &str) -> Option<u32>

pub struct PolyglotService { name: &'static str }
impl PolyglotService {
    pub fn register(name: &'static str) -> Option<Self>
}

pub struct ServiceHandle {
    pub cap:         u32,
    pub module_name: &'static str,
    pub export_name: &'static str,
}
impl ServiceHandle {
    pub fn link(module_name: &'static str, export_name: &'static str) -> Option<Self>
}
```

---

## 7. Language Identification: `oreulia_lang` Custom Section

The `LanguageTag` for a module is embedded at build time in a WASM custom section named `oreulia_lang`. The build toolchain sets this based on the source language. The kernel reads this section during module loading in `WasmModule::parse_custom_sections`.

| Language | Section value |
|---|---|
| Rust | `b"rust"` |
| C | `b"c"` |
| Zig | `b"zig"` |
| Python | `b"python"` |
| JavaScript | `b"js"` |
| (absent/unknown) | `LanguageTag::Unknown` |

Modules compiled without the Oreulia toolchain will have `LanguageTag::Unknown`. They can still register and be linked, but will not trigger singleton enforcement or cross-language `SERVICE_INVOKE` requirements.

---

## 8. Singleton Lifecycle Example

```
1. Python module "ml-runtime" boots, calls polyglot_register("ml-runtime").
   → New PolyglotEntry { language: Python, singleton: true, instance_id: 7 }

2. ml-runtime crashes; the kernel marks it as terminated.
   → PolyglotEntry remains in registry (active=true) but instance_id 7 is dead.

3. Supervisor restarts "ml-runtime" as instance_id 12.
   → Calls polyglot_register("ml-runtime") again.
   → Registry finds existing entry (name="ml-runtime", Python, singleton=true).
   → Refreshes instance_id to 12, owner_pid updated. No new slot consumed.
   → Returns 0.

4. Any module that previously resolved "ml-runtime" and calls polyglot_link again
   gets a fresh ServicePointer capability pointing to instance_id 12.
```

This pattern allows stateful Python/JS runtimes to restart transparently without consuming additional registry slots.

---

## 9. Multi-Language Service Composition

Polyglot linking supports multi-hop compositions:

```
Rust module A
  → polyglot_link("ml-runtime", "infer")
  → receives ServicePointer cap for Python module B

Python module B
  → polyglot_link("data-store", "query")
  → receives ServicePointer cap for Zig module C

CapGraph records:
  edge A→B (PolyglotLink, SERVICE_INVOKE rights)
  edge B→C (PolyglotLink, SERVICE_INVOKE rights)
```

The cap graph enforces that no capability in this chain can be re-exported with elevated rights, and cycle detection prevents A→B→C→A loops.

---

## 10. Known Limitations

| Limitation | Detail |
|---|---|
| **16-entry registry** | `POLYGLOT_REGISTRY` holds at most 16 concurrent service registrations. |
| **32-byte name limit** | Service names are capped at 32 bytes. Longer names are rejected with `−1`. |
| **No automatic re-link on restart** | Callers that cached a `cap_handle` from a previous `polyglot_link` hold a stale capability after a singleton restarts. They must call `polyglot_link` again to get a fresh handle. |
| **Export discovery** | `polyglot_resolve` returns an `instance_id` but not the list of exported functions. Callers must know the export name out-of-band. |
| **`SERVICE_INVOKE` rights not enforced post-link** | The rights check occurs at link time only. If a caller downgrades its capability's rights bitmask after linking, the `SERVICE_INVOKE` requirement is not re-checked on invocation. |
