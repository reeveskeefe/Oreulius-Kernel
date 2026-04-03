//! Raw Oreulius-native host-function bindings.
//!
//! These functions are **Oreulius-specific extensions** beyond WASI Preview 1.
//! They expose the capability system, IPC channels, and process lifecycle
//! management that make Oreulius unique.
//!
//! Import module: `"oreulius"` (the runtime also accepts `"env"`).
//!
//! | ID  | Name                  | Description |
//! |-----|-----------------------|-------------|
//! |   0 | `capability_create`   | Allocate a new capability object |
//! |   1 | `capability_send`     | Send a message via a capability |
//! |   2 | `capability_recv`     | Receive a message from a capability |
//! |   3 | `capability_drop`     | Release a capability reference |
//! |   4 | `channel_open`        | Open a named IPC channel |
//! |   5 | `channel_send`        | Send bytes over a channel |
//! |   6 | `channel_recv`        | Receive bytes from a channel |
//! |   7 | `channel_close`       | Close a channel |
//! |  10 | `mem_map`             | Map a shared memory region |
//! |  11 | `mem_unmap`           | Unmap a shared memory region |
//! |  23 | `oreulius_thread_spawn`| Spawn a cooperative WASM thread |
//! |  24 | `oreulius_thread_join` | Join a cooperative WASM thread |
//! |  25 | `oreulius_thread_id`   | Return the current WASM thread ID |
//! |  26 | `oreulius_thread_yield`| Yield the current CPU quantum |
//! |  27 | `oreulius_thread_exit` | Exit the current WASM thread |
//! | 100 | `proc_spawn`          | Spawn a child WASM process |
//! | 101 | `proc_yield`          | Cooperatively yield the CPU |
//! | 102 | `proc_sleep`          | Sleep for N PIT ticks (~ms) |
//!
//! See `docs/runtime/oreulius-wasm-abi.md` for the complete stable ABI reference.

#[link(wasm_import_module = "oreulius")]
extern "C" {
    // -----------------------------------------------------------------------
    // Capability management (IDs 0–3)
    // -----------------------------------------------------------------------

    /// Allocate a new capability object.
    /// Returns the object ID on success, or u32::MAX on failure.
    pub fn capability_create() -> u32;

    /// Send a message to a capability.
    /// `data_ptr` / `data_len` — payload in linear memory.
    /// Returns 0 on success, non-zero errno on failure.
    pub fn capability_send(cap_id: u32, data_ptr: u32, data_len: u32) -> u32;

    /// Receive a pending message from a capability.
    /// Writes up to `buf_len` bytes into `buf_ptr`.
    /// Returns actual bytes written, or 0 if no message.
    pub fn capability_recv(cap_id: u32, buf_ptr: u32, buf_len: u32) -> u32;

    /// Decrement the reference count of a capability.
    /// When the count reaches zero the kernel reclaims it.
    pub fn capability_drop(cap_id: u32);

    // -----------------------------------------------------------------------
    // IPC channels (IDs 4–7)
    // -----------------------------------------------------------------------

    /// Open a named IPC channel.
    /// `name_ptr` / `name_len` — UTF-8 channel name in linear memory.
    /// Returns channel handle (u32), or u32::MAX on error.
    pub fn channel_open(name_ptr: u32, name_len: u32) -> u32;

    /// Send bytes over a channel.
    /// Returns 0 on success.
    pub fn channel_send(handle: u32, data_ptr: u32, data_len: u32) -> u32;

    /// Receive bytes from a channel into `buf_ptr`.
    /// Returns actual bytes written, 0 if empty.
    pub fn channel_recv(handle: u32, buf_ptr: u32, buf_len: u32) -> u32;

    /// Close a channel handle.
    pub fn channel_close(handle: u32);

    // -----------------------------------------------------------------------
    // Shared memory (IDs 10–11)
    // -----------------------------------------------------------------------

    /// Map a shared memory region identified by `region_id`.
    /// Returns the linear-memory offset of the mapped region, or u32::MAX.
    pub fn mem_map(region_id: u32, size: u32) -> u32;

    /// Unmap a previously mapped shared memory region.
    pub fn mem_unmap(region_id: u32);

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

    /// Obtain a cross-language capability handle for a named export on a
    /// registered polyglot service.
    ///
    /// `name_ptr` / `name_len`     — name of the target module.
    /// `export_ptr` / `export_len` — name of the specific export / method.
    ///
    /// Returns a capability handle (≥ 0) on success, or a negative error
    /// code on failure.  Pass the handle to `service_invoke`.
    pub fn polyglot_link(name_ptr: i32, name_len: i32,
                         export_ptr: i32, export_len: i32) -> i32;

    // -----------------------------------------------------------------------
    // Kernel Observer services (IDs 106–108)
    // -----------------------------------------------------------------------

    /// Register this module as a kernel observer for the given `event_mask`.
    ///
    /// `event_mask` is a bitwise OR of the `observer_events::*` constants.
    /// Returns the IPC channel ID (≥ 0) used for event delivery, or -1 if
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
    /// Returns the frame byte-length on success, or negative on failure.
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
    /// Returns the `cap_id` (≥ 0) on success, negative on failure.
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
    /// Returns `0`=permit, `1`=deny, `-1`=no policy bound to this cap.
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
    /// Returns the number of entangled cap IDs written (≥ 0), or `-1` if
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
    /// Returns the number of edges written (≥ 0), or `-1` if none.
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
