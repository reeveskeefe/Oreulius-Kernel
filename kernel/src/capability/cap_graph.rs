//! # Runtime Capability Graph Verification
//!
//! Maintains a live delegation graph of capability authority edges.
//! Every time a capability is **delegated** (transferred from one process to
//! another) an edge `delegator→delegatee` is recorded here.  The graph is
//! checked on every delegation for three invariants:
//!
//! 1. **No rights escalation** — the delegated rights must be a subset of the
//!    delegator's rights on that object.
//! 2. **No delegation cycles** — an authority chain must be a DAG; detecting a
//!    cycle (e.g. A→B→C→A) indicates a privilege escalation attack.
//! 3. **No orphan edges** — when a capability is revoked, all outgoing edges
//!    from that `(pid, cap_id)` node are pruned automatically.
//!
//! ## Integration points
//!
//! - `capability.rs: CapabilityManager::transfer_capability` — calls
//!   [`record_delegation`] and [`check_invariants`].
//! - `capability.rs: CapabilityManager::revoke_capability` — calls
//!   [`prune_edges_for`] to remove stale edges.
//! - `wasm.rs` host functions 129–131 expose the graph to WASM modules.

use spin::Mutex;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of live delegation edges tracked simultaneously.
pub const MAX_GRAPH_EDGES: usize = 256;

/// Maximum depth for the cycle-detection DFS.  Chains longer than this are
/// conservatively flagged as cycles (fail-closed for safety).
pub const MAX_CHAIN_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single directed delegation edge in the capability graph.
///
/// Semantics: "process `from_pid` delegated `from_cap` to process `to_pid`,
/// which received it as `to_cap`, with rights `rights_bits`."
#[derive(Clone, Copy)]
pub struct CapDelegationEdge {
    pub active:      bool,
    pub from_pid:    u32,
    pub from_cap:    u32,
    pub to_pid:      u32,
    pub to_cap:      u32,
    /// Rights bitmask on the delegated capability (for escalation checks).
    pub rights_bits: u32,
}

impl CapDelegationEdge {
    const fn empty() -> Self {
        CapDelegationEdge {
            active: false,
            from_pid: 0, from_cap: 0,
            to_pid: 0, to_cap: 0,
            rights_bits: 0,
        }
    }
}

/// The live delegation graph.
pub struct CapGraph {
    edges: [CapDelegationEdge; MAX_GRAPH_EDGES],
    /// Monotonic violation counter — incremented on each detected invariant
    /// breach.  Never resets; readable via the host query API.
    pub violations: u64,
}

impl CapGraph {
    const fn new() -> Self {
        CapGraph {
            edges: [CapDelegationEdge::empty(); MAX_GRAPH_EDGES],
            violations: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static CAP_GRAPH: Mutex<CapGraph> = Mutex::new(CapGraph::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Record that `from_pid` delegated `from_cap` (with `rights_bits`) to
/// `to_pid` who received it as `to_cap`.
///
/// Returns `Ok(())` on success or `Err` on graph full.  Callers should treat
/// `Err` as a reason to deny the delegation.
pub fn record_delegation(
    from_pid:    u32,
    from_cap:    u32,
    to_pid:      u32,
    to_cap:      u32,
    rights_bits: u32,
) -> Result<(), &'static str> {
    let mut g = CAP_GRAPH.lock();
    let mut slot = None;
    let mut i = 0usize;
    while i < MAX_GRAPH_EDGES {
        if !g.edges[i].active { slot = Some(i); break; }
        i += 1;
    }
    match slot {
        None => Err("cap_graph: edge table full"),
        Some(idx) => {
            g.edges[idx] = CapDelegationEdge {
                active: true,
                from_pid, from_cap,
                to_pid,   to_cap,
                rights_bits,
            };
            Ok(())
        }
    }
}

/// Check invariants for a proposed delegation.
///
/// `delegator_rights` is the rights bitmask the delegator actually holds on
/// the capability being transferred.  `proposed_rights` is what will be
/// granted to the delegatee.
///
/// Returns `Ok(())` if the delegation is safe, `Err(&str)` describing the
/// violated invariant.
pub fn check_invariants(
    from_pid:          u32,
    from_cap:          u32,
    to_pid:            u32,
    delegator_rights:  u32,
    proposed_rights:   u32,
) -> Result<(), &'static str> {
    // Invariant 1 — no rights escalation.
    if proposed_rights & !delegator_rights != 0 {
        let mut g = CAP_GRAPH.lock();
        g.violations = g.violations.wrapping_add(1);
        crate::serial_println!(
            "[cap_graph] VIOLATION: rights escalation pid={} cap={} proposed={:#010x} held={:#010x}",
            from_pid, from_cap, proposed_rights, delegator_rights
        );
        return Err("cap_graph: rights escalation");
    }

    // Invariant 2 — no delegation cycles.
    if would_create_cycle(from_pid, from_cap, to_pid) {
        let mut g = CAP_GRAPH.lock();
        g.violations = g.violations.wrapping_add(1);
        crate::serial_println!(
            "[cap_graph] VIOLATION: delegation cycle detected from_pid={} to_pid={}",
            from_pid, to_pid
        );
        return Err("cap_graph: delegation cycle");
    }

    Ok(())
}

/// Remove all delegation edges that originate from or arrive at
/// `(pid, cap_id)`.  Call this after revoking a capability.
pub fn prune_edges_for(pid: u32, cap_id: u32) {
    let mut g = CAP_GRAPH.lock();
    let mut i = 0usize;
    while i < MAX_GRAPH_EDGES {
        let e = &g.edges[i];
        if e.active
            && ((e.from_pid == pid && e.from_cap == cap_id)
                || (e.to_pid == pid && e.to_cap == cap_id))
        {
            g.edges[i].active = false;
        }
        i += 1;
    }
}

/// Remove all edges involving any capability owned by `pid`.  Call this when
/// a process is destroyed.
pub fn prune_edges_for_pid(pid: u32) {
    let mut g = CAP_GRAPH.lock();
    let mut i = 0usize;
    while i < MAX_GRAPH_EDGES {
        let e = &g.edges[i];
        if e.active && (e.from_pid == pid || e.to_pid == pid) {
            g.edges[i].active = false;
        }
        i += 1;
    }
}

/// Count active delegation edges emanting from `(pid, cap_id)` (depth 1).
/// Returns the chain depth (longest DAG path reachable from this node, capped
/// at `MAX_CHAIN_DEPTH`) for use by the WASM query API.
pub fn delegation_depth(pid: u32, cap_id: u32) -> u32 {
    let g = CAP_GRAPH.lock();
    dfs_depth(&g, pid, cap_id, 0)
}

/// Return the number of lifetime invariant violations ever detected.
pub fn violation_count() -> u64 {
    CAP_GRAPH.lock().violations
}

// ============================================================================
// ProvenanceChain — Def A.28 capability lineage
// ============================================================================

/// Maximum delegation depth tracked in a single provenance chain.
pub const PROVENANCE_MAX_DEPTH: usize = 32;

/// One link in a capability provenance chain.
#[derive(Clone, Copy, Debug)]
pub struct ProvenanceLink {
    /// Capability ID at this depth.
    pub cap_id: u32,
    /// Owner process at this depth.
    pub holder_pid: u32,
    /// Rights bitmask at the point this link was recorded.
    pub rights_bits: u32,
}

impl ProvenanceLink {
    const fn zero() -> Self {
        ProvenanceLink { cap_id: 0, holder_pid: 0, rights_bits: 0 }
    }
}

/// A linear chain of delegation links from a root capability down to a leaf.
///
/// `links[0]` is the *leaf* (most recently delegated) capability;
/// `links[depth - 1]` is the *root* (directly created by the kernel).
///
/// Built by [`build_chain`], which walks the `parent_cap_id` fields embedded
/// in `OreuliaCapability` structs back toward the root.
#[derive(Clone, Copy, Debug)]
pub struct ProvenanceChain {
    pub links: [ProvenanceLink; PROVENANCE_MAX_DEPTH],
    /// Number of valid entries in `links`.
    pub depth: usize,
    /// Set to `true` if the chain was truncated at `PROVENANCE_MAX_DEPTH`.
    pub truncated: bool,
}

impl ProvenanceChain {
    const fn empty() -> Self {
        ProvenanceChain {
            links: [ProvenanceLink::zero(); PROVENANCE_MAX_DEPTH],
            depth: 0,
            truncated: false,
        }
    }

    /// Serialize the chain into a fixed-size byte array suitable for embedding
    /// into `AuditEntry::context` or a temporal log record.
    ///
    /// Format (little-endian):
    /// ```text
    /// [0]        depth as u8
    /// [1]        truncated as u8 (0 or 1)
    /// [2..N]     for each link: cap_id (4B LE) | holder_pid (4B LE) | rights (4B LE)
    /// ```
    /// Returns the number of bytes written.
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        if out.len() < 2 {
            return 0;
        }
        out[0] = self.depth as u8;
        out[1] = self.truncated as u8;
        let mut pos = 2usize;
        let mut i = 0usize;
        while i < self.depth && i < PROVENANCE_MAX_DEPTH {
            if pos + 12 > out.len() {
                break;
            }
            let link = &self.links[i];
            out[pos..pos + 4].copy_from_slice(&link.cap_id.to_le_bytes());
            out[pos + 4..pos + 8].copy_from_slice(&link.holder_pid.to_le_bytes());
            out[pos + 8..pos + 12].copy_from_slice(&link.rights_bits.to_le_bytes());
            pos += 12;
            i += 1;
        }
        pos
    }
}

/// Build the provenance chain for `(pid, cap_id)` by walking `parent_cap_id`
/// links through the live capability tables.
///
/// Each hop resolves the parent cap in the *same process's* capability table
/// (since attenuations are intra-process) or falls back to the `CapGraph` edge
/// table for cross-process delegations.
///
/// Returns a [`ProvenanceChain`] with `depth == 0` if the cap is not found or
/// has no provenance.
pub fn build_chain(pid: u32, cap_id: u32) -> ProvenanceChain {
    let mut chain = ProvenanceChain::empty();
    let mut current_pid = pid;
    let mut current_cap = cap_id;

    loop {
        if chain.depth >= PROVENANCE_MAX_DEPTH {
            chain.truncated = true;
            break;
        }

        // Resolve current cap through the capability manager.
        let mgr = crate::capability::capability_manager();
        let (rights_bits, parent_cap_id_opt) = {
            let tables = mgr.tables.lock();
            if let Some(table) = tables[current_pid as usize].as_ref() {
                match table.lookup(current_cap) {
                    Ok(cap) => (cap.rights.bits(), cap.parent_cap_id),
                    Err(_) => break,
                }
            } else {
                break;
            }
        };

        chain.links[chain.depth] = ProvenanceLink {
            cap_id: current_cap,
            holder_pid: current_pid,
            rights_bits,
        };
        chain.depth += 1;

        match parent_cap_id_opt {
            None => break, // root capability
            Some(parent_cap) => {
                // Try intra-process first (attenuated cap in same process).
                // Then check the CapGraph for an incoming cross-process edge.
                let g = CAP_GRAPH.lock();
                let mut found_cross = false;
                let mut i = 0usize;
                while i < MAX_GRAPH_EDGES {
                    let e = &g.edges[i];
                    if e.active && e.to_pid == current_pid && e.to_cap == current_cap {
                        // The delegator holds `from_cap` in `from_pid`.
                        current_pid = e.from_pid;
                        current_cap = e.from_cap;
                        found_cross = true;
                        break;
                    }
                    i += 1;
                }
                drop(g);

                if !found_cross {
                    // Intra-process attenuation: parent is in the same process.
                    current_cap = parent_cap;
                    // current_pid stays the same.
                }
            }
        }
    }

    chain
}


/// Write up to `max_edges` raw edges for `(pid, cap_id)` into `out`.
/// Returns the number of edges written.
pub fn query_edges_for(
    pid:    u32,
    cap_id: u32,
    out:    &mut [CapDelegationEdge],
) -> usize {
    let g   = CAP_GRAPH.lock();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < MAX_GRAPH_EDGES && n < out.len() {
        let e = &g.edges[i];
        if e.active && e.from_pid == pid && e.from_cap == cap_id {
            out[n] = *e;
            n += 1;
        }
        i += 1;
    }
    n
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Iterative DFS (using a stack array) to detect whether adding an edge
/// `from_pid → to_pid` would create a cycle.
fn would_create_cycle(from_pid: u32, _from_cap: u32, to_pid: u32) -> bool {
    // If to_pid can already reach from_pid through the existing graph,
    // then adding from_pid→to_pid would create a cycle.
    let g = CAP_GRAPH.lock();

    // Iterative DFS from to_pid; if we reach from_pid → cycle.
    let mut stack = [0u32; MAX_CHAIN_DEPTH];
    let mut depth = 1usize;
    stack[0] = to_pid;

    let mut visited = [0u32; MAX_CHAIN_DEPTH];
    let mut n_visited = 0usize;

    while depth > 0 {
        depth -= 1;
        let current = stack[depth];

        if current == from_pid {
            return true; // cycle!
        }

        // Mark visited to avoid revisiting.
        let mut already = false;
        let mut vi = 0usize;
        while vi < n_visited {
            if visited[vi] == current { already = true; break; }
            vi += 1;
        }
        if already { continue; }
        if n_visited < MAX_CHAIN_DEPTH { visited[n_visited] = current; n_visited += 1; }

        // Push all successors of `current` onto the stack.
        let mut i = 0usize;
        while i < MAX_GRAPH_EDGES {
            let e = &g.edges[i];
            if e.active && e.from_pid == current {
                if depth < MAX_CHAIN_DEPTH {
                    stack[depth] = e.to_pid;
                    depth += 1;
                } else {
                    // Stack overflow — conservatively treat as cycle.
                    return true;
                }
            }
            i += 1;
        }
    }
    false
}

/// Recursive DFS to compute longest delegation chain length reachable from
/// `(pid, cap_id)`.  Caps the result at `MAX_CHAIN_DEPTH`.
fn dfs_depth(g: &CapGraph, pid: u32, cap_id: u32, depth: u32) -> u32 {
    if depth as usize >= MAX_CHAIN_DEPTH {
        return depth;
    }
    let mut max_child = depth;
    let mut i = 0usize;
    while i < MAX_GRAPH_EDGES {
        let e = &g.edges[i];
        if e.active && e.from_pid == pid && e.from_cap == cap_id {
            let child_depth = dfs_depth(g, e.to_pid, e.to_cap, depth + 1);
            if child_depth > max_child { max_child = child_depth; }
        }
        i += 1;
    }
    max_child
}
