# Oreulius Polyglot Services

**Status:** Implemented and frozen for the current ABI version.

Primary implementation surfaces:

- [`kernel/src/execution/wasm.rs`](../../kernel/src/execution/wasm.rs)
- [`wasm/sdk/src/polyglot.rs`](../../wasm/sdk/src/polyglot.rs)

Host ABI:

- `103` `polyglot_register`
- `104` `polyglot_resolve`
- `105` `polyglot_link`
- `132` `polyglot_lineage_count`
- `133` `polyglot_lineage_query`
- `134` `polyglot_lineage_query_filtered`
- `135` `polyglot_lineage_lookup`
- `136` `polyglot_lineage_lookup_object`
- `137` `polyglot_lineage_revoke`
- `138` `polyglot_lineage_rebind`
- `139` `polyglot_lineage_status`
- `140` `polyglot_lineage_status_object`
- `141` `polyglot_lineage_query_page`
- `142` `polyglot_lineage_event_query`

---

## 1. What polyglot services currently are

The current polyglot subsystem gives Oreulius a **named registry of WASM modules by language-tagged service name**, plus an exact-export path to obtain a service-pointer handle to a registered callable export. The kernel now also keeps a durable lineage record so historical provenance can outlive live authority.

Today the subsystem does three concrete things:

1. register a module name with its runtime instance id and language tag
2. resolve a name back to an instance id
3. link an exact exported function from that registered module to a service-pointer handle in the caller's WASM capability table

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
- `cap_object` stable object identifier used for lineage and audit correlation
- `latest_record_id` pointing at the lineage ledger

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

What the current implementation does:

1. resolves the target module by name
2. resolves the requested export name against the target module's export table
3. matches that exact export to a registered service-pointer entry by `(target_instance, function_index)`
4. injects a WASM-side `ServicePointer` handle into the caller's capability table
5. records a durable lineage entry for the link
6. logs source and target language information to serial

What it still does **not** do:

- it does not provide a general cross-language value marshaling layer beyond the typed service-slot ABI
- it does not turn polyglot linking into an ambient name-based RPC namespace
- it does not let lineage records act as authority without a live `ServicePointer`

Return behavior:

- `>= 0` Wasm capability handle on success
- `-1` invalid arguments
- `-2` module not found
- `-3` export missing or not registered as a service pointer
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

- `register(name: &str) -> Result<(), PolyglotError>`
- `resolve(name: &str) -> Result<i32, PolyglotError>`
- `link(module_name: &str, export_name: &str) -> Result<u32, PolyglotError>`

Convenience wrappers also exist:

- `PolyglotService`
- `ServiceHandle`

---

## 6. Current limitations

These limitations are real and should be documented explicitly.

### 6.1 Registry teardown remains manual

There is still no dedicated polyglot unregister path today.

Current consequence:

- destroying a WASM instance revokes its service pointers
- the polyglot name registry entry is purged at the same time
- the durable lineage record is retained with a terminal lifecycle state

So:

- `polyglot_resolve` fails closed after teardown
- `polyglot_link` fails closed after teardown
- historical audit can still show the link existed and when it ended

### 6.2 Cross-language capability auditing is still partial

The code now constructs both:

- a live `ServicePointer` authority object
- a durable polyglot lineage record in the kernel

The real authority that reaches the caller is still the Wasm-side `ServicePointer` handle. The lineage record is the audit/replay source of truth and does not itself grant authority.

### 6.3 Lineage query is read-only by design

The new lineage host calls expose durable provenance for audit and replay. They do not create new authority, and they do not replace the `ServicePointer` handle returned by `polyglot_link`.

- `polyglot_lineage_lookup` is the explicit live-handle audit path.
- `polyglot_lineage_lookup_object` preserves the same record shape for terminal rebind/revocation inspection after the live handle is gone.
- `polyglot_lineage_revoke` explicitly removes live authority and leaves the durable lineage entry behind for later audit.
- `polyglot_lineage_rebind` explicitly retargets a live handle to a verified compatible instance owned by the same process.
- `polyglot_lineage_status` and `polyglot_lineage_status_object` expose the current lifecycle summary without requiring a full lineage scan.
- `polyglot_lineage_query_page` walks lineage records incrementally using a record-id cursor.
- `polyglot_lineage_event_query` returns the append-only `Rebound` / `Revoked` transition feed.

Example:

```rust
let mut pages = oreulius_sdk::polyglot::lineage_pages(16);
while let Some(page) = pages.next() {
    let page = page.expect("lineage page");
    for record in page.iter() {
        let _ = record.record_id;
    }
}

let mut events = oreulius_sdk::polyglot::lineage_events(16);
while let Some(batch) = events.next() {
    let batch = batch.expect("lineage events");
    for event in batch.iter() {
        let _ = event.event_id;
    }
}
```

---

## 7. What is implemented today

Accurate claims:

- language-tagged named registration is implemented
- singleton refresh for Python and JS is implemented
- name resolution to instance id is implemented
- exact-export Wasm-side linking to a service-pointer handle is implemented
- shell/runtime logging records the source and target language tags

Claims that should not be made yet:

- full kernel capability-manager installation of polyglot link objects
- a fully general cross-language ABI linker or marshaler
- using lineage records as ambient authority

The correct public description is that Oreulius already has a real polyglot registry and exact-export link surface, implemented as a capability-mediated layer over service-pointer capabilities rather than a fully generalized cross-language ABI linker.
