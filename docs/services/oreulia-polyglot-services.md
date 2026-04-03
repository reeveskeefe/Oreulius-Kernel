# Oreulius Polyglot Services

**Status:** Implemented, but narrower than some earlier docs claimed.

Primary implementation surfaces:

- [`kernel/src/execution/wasm.rs`](../../kernel/src/execution/wasm.rs)
- [`wasm/sdk/src/polyglot.rs`](../../wasm/sdk/src/polyglot.rs)

Host ABI:

- `103` `polyglot_register`
- `104` `polyglot_resolve`
- `105` `polyglot_link`

---

## 1. What polyglot services currently are

The current polyglot subsystem gives Oreulius a **named registry of WASM modules by language-tagged service name**, plus a way to obtain a service-pointer handle to a registered module.

It does **not** yet implement the stricter export-resolved ABI linker that some older documents described.

Today the subsystem does three concrete things:

1. register a module name with its runtime instance id and language tag
2. resolve a name back to an instance id
3. link that registered module to a service-pointer handle in the caller's WASM capability table

---

## 2. Registry model

The runtime maintains:

- `MAX_POLYGLOT_ENTRIES = 16`

Each active entry stores:

- `name` up to 32 bytes
- `instance_id`
- `language`
- `owner_pid`
- `singleton` flag
- `cap_object` placeholder field

The language tag comes from the module's `oreulius_lang` custom section and defaults to `Unknown` if absent.

### Singleton behavior

The current implementation treats these languages as singletons:

- `Python`
- `JS`

If a module with the same name and same singleton language re-registers, the registry refreshes:

- `instance_id`
- `owner_pid`

instead of allocating a new slot.

If a name is already taken by a different non-singleton module, registration fails.

---

## 3. Current host behavior

### 3.1 `polyglot_register`

`polyglot_register(name_ptr, name_len) -> i32`

Current rules:

- name must be non-empty
- name length must be `<= 32`
- singleton same-name same-language entries refresh in place
- otherwise duplicate names fail
- failure also occurs when the registry is full

Return behavior:

- `0` on success
- `-1` invalid name
- `-2` registry full
- `-3` conflicting existing name

### 3.2 `polyglot_resolve`

`polyglot_resolve(name_ptr, name_len) -> i32`

This returns the registered `instance_id` for the name.

Return behavior:

- `>= 0` instance id on success
- `-1` invalid name
- `-2` not found

### 3.3 `polyglot_link`

`polyglot_link(name_ptr, name_len, export_ptr, export_len) -> i32`

This is the most important place where older docs drifted.

What the current implementation actually does:

1. resolves the target module by name
2. looks for the **first active service-pointer entry** whose `target_instance` matches that resolved instance
3. injects a WASM-side `ServicePointer` handle into the caller's capability table
4. logs source and target language information to serial

What it does **not** currently do:

- it does not resolve the requested export name against a per-export registry
- it does not inject a persistent `CrossLanguage` capability into the kernel capability manager
- it does not currently use `export_name` as a strict dispatch key beyond argument validation and logging

So the current semantics are **instance-level polyglot linking backed by service-pointer registration**, not fully export-specific cross-language linkage.

Return behavior:

- `>= 0` Wasm capability handle on success
- `-1` invalid arguments
- `-2` module not found
- `-3` no active service pointer found for the target instance
- `-4` caller's Wasm capability table full

---

## 4. Relationship to service pointers

Polyglot services sit on top of the service-pointer system.

That means:

- a module must first register a callable target through `service_register`
- polyglot registration only publishes the module name and language metadata
- polyglot linking ultimately returns a `ServicePointer` handle

This dependency is important. Polyglot services are not an independent RPC subsystem; they are a naming and linking layer over callable WASM capabilities.

---

## 5. SDK surface

The SDK wrapper in [`wasm/sdk/src/polyglot.rs`](../../wasm/sdk/src/polyglot.rs) currently exposes:

- `register(name: &str) -> bool`
- `resolve(name: &str) -> Option<i32>`
- `link(module_name: &str, export_name: &str) -> Option<u32>`

Convenience wrappers also exist:

- `PolyglotService`
- `ServiceHandle`

The SDK currently matches the kernel's real behavior better than the old prose docs did, but the wording should still be read in light of the implementation caveat above: `link` is currently instance-level service-pointer resolution, not exact export resolution.

---

## 6. Current limitations

These limitations are real and should be documented explicitly.

### 6.1 Export name is not yet authoritative

`polyglot_link` accepts an export name, but the current host path does not use it to disambiguate multiple service-pointer exports from the same instance. It simply finds the first active service pointer for that instance.

### 6.2 Registry teardown remains manual

There is no dedicated polyglot unregister path today.

Current consequence:

- destroying a WASM instance revokes its service pointers
- but the polyglot name registry entry is not explicitly cleared at destroy time

That means `polyglot_resolve` can still return a stale instance id until the service is refreshed or replaced.

In that stale case:

- `polyglot_resolve` may still succeed
- `polyglot_link` will later fail with `-3` because no active service pointer exists for that dead instance

### 6.3 Cross-language capability auditing is only partial

The code currently constructs a `CrossLanguage` capability-shaped audit object through `new_polyglot_link`, but it is not yet installed as a durable kernel capability record. The real authority that reaches the caller today is the Wasm-side `ServicePointer` handle.

So older claims about full capability-manager-backed cross-language lineage were overstated.

---

## 7. What is implemented today

Accurate claims:

- language-tagged named registration is implemented
- singleton refresh for Python and JS is implemented
- name resolution to instance id is implemented
- Wasm-side linking to a service-pointer handle is implemented
- shell/runtime logging records the source and target language tags

Claims that should not be made yet:

- exact export-level link resolution
- full kernel capability-manager installation of polyglot link objects
- complete stale-entry cleanup on instance teardown

The correct public description is that Oreulius already has a real polyglot registry and link surface, but it is still a lightweight layer over service-pointer capabilities rather than a fully generalized cross-language ABI linker.
