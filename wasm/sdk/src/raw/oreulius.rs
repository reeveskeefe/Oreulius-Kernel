//! Raw Oreulius host-function bindings.
//!
//! These are the frozen kernel-facing host imports in the `oreulius`
//! namespace. The field names here mirror the canonical host table in
//! `kernel/src/execution/wasm.rs`.
//!
//! This module intentionally exposes only the raw imports; higher-level typed
//! wrappers live in the sibling SDK modules.

#[link(wasm_import_module = "oreulius")]
extern "C" {
    // -----------------------------------------------------------------------
    // Core ABI (IDs 0–12)
    // -----------------------------------------------------------------------

    /// Write a debug line to the kernel log.
    pub fn debug_log(msg_ptr: u32, msg_len: u32);

    /// Read bytes from a filesystem capability-backed object.
    pub fn fs_read(cap: u32, key_ptr: u32, key_len: u32, buf_ptr: u32, buf_len: u32) -> i32;

    /// Write bytes to a filesystem capability-backed object.
    pub fn fs_write(cap: u32, key_ptr: u32, key_len: u32, data_ptr: u32, data_len: u32) -> i32;

    /// Send bytes over a channel capability.
    pub fn channel_send(cap: u32, msg_ptr: u32, msg_len: u32) -> i32;

    /// Receive bytes from a channel capability into `buf_ptr`.
    pub fn channel_recv(cap: u32, buf_ptr: u32, buf_len: u32) -> i32;

    /// Perform an HTTP GET request into a caller-provided buffer.
    pub fn net_http_get(url_ptr: u32, url_len: u32, buf_ptr: u32, buf_len: u32) -> i32;

    /// Open a TCP connection to `host:port`.
    pub fn net_connect(host_ptr: u32, host_len: u32, port: u32) -> i32;

    /// Resolve a domain name to an IPv4 address.
    pub fn dns_resolve(domain_ptr: u32, domain_len: u32) -> i32;

    /// Invoke a service-pointer capability with raw `u32` arguments.
    pub fn service_invoke(cap_handle: u32, args_ptr: u32, args_count: u32) -> i32;

    /// Register a callable function as a service-pointer capability.
    pub fn service_register(func_idx: i32, delegate: i32) -> i32;

    /// Send a channel message and optionally attach one transferable capability.
    pub fn channel_send_cap(chan_cap: u32, msg_ptr: u32, msg_len: u32, cap: u32) -> i32;

    /// Return the most recently imported service-pointer capability, or `-1`.
    pub fn last_service_cap() -> i32;

    /// Invoke a service-pointer capability with typed arguments/results.
    pub fn service_invoke_typed(
        cap_handle: u32,
        args_ptr: u32,
        args_count: u32,
        results_ptr: u32,
        results_capacity: u32,
    ) -> i32;

    // -----------------------------------------------------------------------
    // Cooperative WASM threads (IDs 23–27)
    // -----------------------------------------------------------------------

    /// Spawn a cooperative WASM thread at `func_idx` with one i32 argument.
    ///
    /// Returns a positive thread ID on success, or `-1` on failure.
    #[link_name = "oreulius_thread_spawn"]
    pub fn thread_spawn(func_idx: i32, arg: i32) -> i32;

    /// Join a cooperative WASM thread.
    ///
    /// Returns the thread exit code if it has finished, `0` if the thread no
    /// longer exists, or `-1` if the caller should try again later.
    #[link_name = "oreulius_thread_join"]
    pub fn thread_join(tid: i32) -> i32;

    /// Return the current WASM thread ID.
    ///
    /// The main instance returns `0`.
    #[link_name = "oreulius_thread_id"]
    pub fn thread_id() -> i32;

    /// Yield the current CPU quantum.
    #[link_name = "oreulius_thread_yield"]
    pub fn thread_yield();

    /// Exit the current WASM thread with `code`.
    #[link_name = "oreulius_thread_exit"]
    pub fn thread_exit(code: i32);

    // -----------------------------------------------------------------------
    // Process management (IDs 100–102)
    // -----------------------------------------------------------------------

    /// Spawn a child WASM process from bytecode in linear memory.
    ///
    /// `bytes_ptr` — offset of the WASM binary in this module's linear memory.
    /// `bytes_len` — byte length of the WASM binary.
    ///
    /// Returns the child PID (> 0) on success, 0 on failure.
    /// The child is enqueued via the deferred spawn queue and will start
    /// running after the current host function returns.
    pub fn proc_spawn(bytes_ptr: u32, bytes_len: u32) -> u32;

    /// Cooperatively yield the current time slice.
    /// The scheduler will context-switch to the next ready process.
    pub fn proc_yield();

    /// Sleep for approximately `ticks` PIT ticks (~1 ms per tick).
    /// Uses cooperative yielding; does not busy-spin.
    pub fn proc_sleep(ticks: u32);

    // -----------------------------------------------------------------------
    // Polyglot kernel services (IDs 103–105)
    // -----------------------------------------------------------------------

    /// Register this module as a named polyglot kernel service.
    ///
    /// `name_ptr` / `name_len` — UTF-8 service name (≤ 32 bytes) in linear
    /// memory.  Returns `0` on success, negative errno on failure.
    pub fn polyglot_register(name_ptr: i32, name_len: i32) -> i32;

    /// Resolve a registered polyglot service by name.
    ///
    /// Returns the target's `instance_id` (≥ 0) on success, or a negative
    /// error code if the name is not found.
    pub fn polyglot_resolve(name_ptr: i32, name_len: i32) -> i32;

    /// Obtain a cross-language capability handle for an exact named export on
    /// a registered polyglot service.
    ///
    /// `name_ptr` / `name_len`     — name of the target module.
    /// `export_ptr` / `export_len` — name of the specific export / method.
    ///
    /// Returns a capability handle (≥ 0) on success, or a negative error
    /// code on failure. The requested export name must resolve against the
    /// target module's export table and a matching registered service pointer.
    /// Pass the handle to `service_invoke`.
    pub fn polyglot_link(name_ptr: i32, name_len: i32,
                         export_ptr: i32, export_len: i32) -> i32;

    /// Return the number of active polyglot lineage records.
    pub fn polyglot_lineage_count() -> i32;

    /// Write polyglot lineage records into linear memory.
    ///
    /// `buf_ptr` points to the output buffer and `buf_len` is its byte length.
    /// Returns the number of active records written, or a negative error code.
    pub fn polyglot_lineage_query(buf_ptr: i32, buf_len: i32) -> i32;

    /// Write filtered polyglot lineage records into linear memory.
    ///
    /// `filter_kind` selects the predicate:
    /// `0=all`, `1=source_pid`, `2=target_instance`, `3=lifecycle`, `4=export_name`.
    /// When `filter_kind=4`, `filter_a` points to the export-name bytes and `filter_b`
    /// stores the byte length.
    pub fn polyglot_lineage_query_filtered(
        buf_ptr: i32,
        buf_len: i32,
        filter_kind: i32,
        filter_a: i32,
        filter_b: i32,
    ) -> i32;

    /// Write the latest lineage record for a live service-pointer handle.
    pub fn polyglot_lineage_lookup(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Write the latest lineage record for a persistent lineage object id.
    pub fn polyglot_lineage_lookup_object(
        object_lo: i32,
        object_hi: i32,
        buf_ptr: i32,
        buf_len: i32,
    ) -> i32;

    /// Explicitly revoke a live service-pointer capability and record the
    /// terminal lifecycle transition.
    pub fn polyglot_lineage_revoke(cap_handle: i32) -> i32;

    /// Rebind a live service-pointer capability to a verified compatible
    /// replacement instance owned by the same process.
    pub fn polyglot_lineage_rebind(cap_handle: i32, target_instance: i32) -> i32;

    /// Write a compact lifecycle summary for a live service-pointer handle.
    pub fn polyglot_lineage_status(cap_handle: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Write a compact lifecycle summary for a persistent object id.
    pub fn polyglot_lineage_status_object(object_lo: i32, object_hi: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Write a cursor-based page of lineage records.
    pub fn polyglot_lineage_query_page(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Write a cursor-based page of rebinding/revocation events.
    pub fn polyglot_lineage_event_query(cursor: i32, limit: i32, buf_ptr: i32, buf_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Kernel Observer services (IDs 106–108)
    // -----------------------------------------------------------------------

    /// Register this module as a kernel observer for the given `event_mask`.
    ///
    /// `event_mask` is a bitwise OR of the `observer_events::*` constants.
    /// Returns the IPC channel ID (> 0) used for event delivery, or -1 if
    /// the observer table is full, -2 if channel allocation failed, or -3
    /// if `event_mask` is zero.
    pub fn observer_subscribe(event_mask: i32) -> i32;

    /// Deregister this module as a kernel observer.
    ///
    /// Returns 0 on success, -1 if this module is not currently subscribed.
    pub fn observer_unsubscribe() -> i32;

    /// Drain pending kernel events from this module's observer channel into
    /// the buffer at `buf_ptr` with byte capacity `buf_len`.
    ///
    /// Each event occupies exactly 32 bytes (see `ObserverEvent` in the SDK).
    /// Returns the number of events written, or -1 if not subscribed.
    pub fn observer_query(buf_ptr: i32, buf_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Decentralized Kernel Mesh (IDs 109–115)
    // -----------------------------------------------------------------------

    /// Returns the low 32 bits of the local device's 64-bit CapNet device ID.
    pub fn mesh_local_id() -> i32;

    /// Register a remote peer by its 64-bit device ID (split as `peer_lo` /
    /// `peer_hi`) with the given trust level (`0` = Audit, `1` = Enforce).
    ///
    /// Returns `0` on success, `-1` on failure.
    pub fn mesh_peer_register(peer_lo: i32, peer_hi: i32, trust: i32) -> i32;

    /// Query the session key epoch for a registered peer.
    ///
    /// Returns the epoch (≥ 1 means active session), `0` if no session, or
    /// `-1` if the peer is not registered.
    pub fn mesh_peer_session(peer_lo: i32, peer_hi: i32) -> i32;

    /// Mint a signed `CapabilityTokenV1` (116 bytes) into the buffer at
    /// `buf_ptr`.
    ///
    /// - `obj_lo` / `obj_hi` — 64-bit object ID (split halves)
    /// - `cap_type`          — capability type byte
    /// - `rights`            — rights bitmask
    /// - `expires_ticks`     — lifetime in PIT ticks added to the current tick
    ///
    /// Returns `0` on success, negative on failure.
    pub fn mesh_token_mint(obj_lo: i32, obj_hi: i32, cap_type: i32,
                           rights: i32, expires_ticks: i32, buf_ptr: i32) -> i32;

    /// Wrap the token at `buf_ptr` (`buf_len` must be 116) in a CapNet
    /// `TokenOffer` frame and emit it toward the named peer.
    ///
    /// Returns the frame byte-length (> 0) on success, or negative on failure.
    pub fn mesh_token_send(peer_lo: i32, peer_hi: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Export an active remote capability lease visible to this process as a
    /// 116-byte `CapabilityTokenV1` snapshot into `buf_ptr`.
    ///
    /// Returns `0` on success, `-1` if no visible lease exists.
    pub fn mesh_token_recv(buf_ptr: i32, buf_len: i32) -> i32;

    /// Queue the WASM bytecode at `wasm_ptr` / `wasm_len` for migration to
    /// the named peer device.  Pass `wasm_len = 0` to migrate this module's
    /// own bytecode.
    ///
    /// Returns `0` on success, `-1` if the queue is full, `-2` if the
    /// bytecode exceeds the 64 KiB limit.
    pub fn mesh_migrate(peer_lo: i32, peer_hi: i32, wasm_ptr: i32, wasm_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Temporal Capabilities with Revocable History (IDs 116–120)
    // -----------------------------------------------------------------------

    /// Grant the calling process a time-bound capability.
    ///
    /// - `cap_type`      — numeric capability type.
    /// - `rights`        — rights bitmask.
    /// - `expires_ticks` — lifetime in 100 Hz PIT ticks.
    ///
    /// Returns the `cap_id` (> 0) on success, negative on failure.
    pub fn temporal_cap_grant(cap_type: i32, rights: i32, expires_ticks: i32) -> i32;

    /// Manually revoke a capability held by this process.
    ///
    /// Returns `0` on success, `-1` if not found.
    pub fn temporal_cap_revoke(cap_id: i32) -> i32;

    /// Query the remaining lifetime (PIT ticks) of a time-bound capability.
    ///
    /// Returns the ticks remaining (≥ 0), or `-1` if the cap_id is unknown
    /// or not time-bound.
    pub fn temporal_cap_check(cap_id: i32) -> i32;

    /// Snapshot the calling process's capability set.
    ///
    /// Returns a `checkpoint_id` (≥ 1) on success, `-1` if the store is full.
    pub fn temporal_checkpoint_create() -> i32;

    /// Roll back the capability set to the named checkpoint.
    ///
    /// Returns `0` on success, `-1` if the checkpoint is not found or not
    /// owned by this process, `-2` on re-grant failure.
    pub fn temporal_checkpoint_rollback(checkpoint_id: i32) -> i32;

    // -----------------------------------------------------------------------
    // Intensional Kernel: Policy-as-Capability-Contracts (IDs 121–124)
    // -----------------------------------------------------------------------

    /// Bind a policy contract (WASM bytecode or 8-byte OPOL stub at
    /// `wasm_ptr`/`wasm_len`, max 4 KiB) to `cap_id`.
    ///
    /// OPOL stub format: `[b'O', b'P', b'O', b'L', default_permit: u8,
    /// min_ctx_len: u8, ctx_byte0_eq: u8, ctx_byte0_val: u8]`
    ///
    /// Returns `0`=ok, `-1`=cap not found, `-2`=bytecode too large,
    /// `-3`=policy store full.
    pub fn policy_bind(cap_id: i32, wasm_ptr: i32, wasm_len: i32) -> i32;

    /// Remove the policy contract bound to `cap_id`.
    ///
    /// Returns `0`=ok, `-1`=not found.
    pub fn policy_unbind(cap_id: i32) -> i32;

    /// Evaluate the policy contract bound to `cap_id` against the context
    /// bytes at `ctx_ptr`/`ctx_len`.
    ///
    /// Returns `0`=permit, `1`=deny. Missing bindings and unsupported
    /// contracts are denied by default; use `policy_query` to distinguish
    /// an unbound capability from an explicit deny.
    pub fn policy_eval(cap_id: i32, ctx_ptr: i32, ctx_len: i32) -> i32;

    /// Write 16-byte policy metadata for `cap_id` to `buf_ptr`.
    ///
    /// Layout (little-endian):
    /// `[hash:u64][wasm_len:u16][bound:u8][_pad:u8][cap_id:u32]`
    ///
    /// Returns `0`=found, `-1`=not found, `-2`=`buf_len` < 16.
    pub fn policy_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Quantum-Inspired Capability Entanglement (IDs 125–128)
    // -----------------------------------------------------------------------

    /// Entangle two capabilities: revoking either one automatically revokes
    /// the other.
    ///
    /// Returns `0`=ok, `-1`=cap_a not found, `-2`=cap_b not found,
    /// `-3`=entanglement table full.
    pub fn cap_entangle(cap_a: i32, cap_b: i32) -> i32;

    /// Entangle a group of capabilities: revoking any one revokes all.
    /// `group_ptr` points to a `[u32]` of `group_len` cap IDs in linear
    /// memory (little-endian u32 each).
    ///
    /// Returns a `group_id` (> 0) on success, or negative on failure.
    pub fn cap_entangle_group(group_ptr: i32, group_len: i32) -> i32;

    /// Remove all entanglement links for `cap_id` (both pairwise and group).
    ///
    /// Returns `0`=ok, `-1`=not found.
    pub fn cap_disentangle(cap_id: i32) -> i32;

    /// Write entangled cap IDs for `cap_id` into `buf_ptr` as packed
    /// little-endian u32 values.  `buf_len` is the number of **u32 slots**
    /// available (not bytes).
    ///
    /// Returns the number of entangled cap IDs written (> 0), or `-1` if
    /// `cap_id` has no entanglements.
    pub fn cap_entangle_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Runtime Capability Graph Verification (IDs 129–131)
    // -----------------------------------------------------------------------

    /// Write delegation edges for `cap_id` owned by this process into
    /// `buf_ptr`.  Each edge is 20 bytes (LE):
    /// `[from_pid:u32][from_cap:u32][to_pid:u32][to_cap:u32][rights:u32]`
    ///
    /// `buf_len` is the number of edge slots available (not bytes).
    ///
    /// Returns the number of edges written (> 0), or `-1` if none.
    pub fn cap_graph_query(cap_id: i32, buf_ptr: i32, buf_len: i32) -> i32;

    /// Prospectively check whether delegating `cap_id` to `delegatee_pid`
    /// would violate a graph invariant.
    ///
    /// Returns `0`=safe, `1`=rights escalation, `2`=cycle, `3`=cap not found.
    pub fn cap_graph_verify(cap_id: i32, delegatee_pid: i32) -> i32;

    /// Return the longest delegation chain length reachable from `cap_id`
    /// (capped at 32).  Returns `0` if the cap has never been delegated.
    pub fn cap_graph_depth(cap_id: i32) -> i32;
}
