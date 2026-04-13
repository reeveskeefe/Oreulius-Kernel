# Oreulius Runtime Capability Graph Verification


---

## 1. Overview

Every capability delegation in Oreulius is a verifiable event. The Capability Graph (CapGraph) subsystem builds a live, in-kernel directed graph of every delegation edge — every time one process transfers a capability to another, an edge is recorded. This graph is continuously verified against three invariants:

1. **No rights escalation** — a delegatee can never receive more rights than the delegator holds.
2. **No delegation cycles** — a capability chain from process A to B to C must not loop back to A.
3. **Orphan pruning** — when a capability is revoked, all outgoing delegation edges from it are automatically removed.

The graph also supports **provenance chain reconstruction**: given any active capability, the kernel can trace its lineage back through every process that held and delegated it, producing a serialized audit chain.

This subsystem is not a monitoring tool bolted on after the fact. It is embedded directly in the hot path of `transfer_capability` — invariant violations raise a `CapabilityError::SecurityViolation` inline, and the `violations` counter monotonically increases and never resets for the lifetime of the kernel.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  WASM Module                                                     │
│  capgraph::verify(cap_id, delegatee_pid)                        │
│  capgraph::query(cap_id) / capgraph::depth(cap_id)              │
└─────────────────────────┬────────────────────────────────────────┘
                          │  WASM host ABI (IDs 129–131)
┌─────────────────────────▼────────────────────────────────────────┐
│  Cap Graph Host Functions  (kernel/src/execution/wasm.rs)       │
│  host_cap_graph_query / cap_graph_verify / cap_graph_depth      │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│  kernel/src/capability/cap_graph.rs                             │
│                                                                 │
│  CapGraph                                                       │
│  ├── edges: [CapDelegationEdge; 256]                            │
│  ├── violations: u64  (monotonic)                               │
│  ├── check_invariants()  ← called from transfer_capability()    │
│  ├── record_delegation()                                        │
│  ├── prune_edges_for(pid, cap_id)  ← called from revoke()      │
│  ├── prune_edges_for_pid(pid)  ← called from process teardown  │
│  ├── delegation_depth(pid, cap_id)                              │
│  └── violation_count()                                          │
│                                                                 │
│  ProvenanceChain                                                │
│  ├── links: [ProvenanceLink; 32]                                │
│  ├── depth: usize                                               │
│  ├── truncated: bool                                            │
│  ├── build_chain(pid, cap_id)                                   │
│  └── serialize() → raw bytes                                    │
└─────────────────────────────────────────────────────────────────┘
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/capability/cap_graph.rs` | `CapGraph`, `CapDelegationEdge`, `ProvenanceChain`, all graph algorithms, `CAP_GRAPH` global |
| `kernel/src/execution/wasm.rs` | Host functions (IDs 129–131), integration with `transfer_capability` |
| `kernel/src/capability/mod.rs` | Calls `cap_graph::record_delegation()` and `cap_graph::prune_edges_for()` (2897 lines) |
| `wasm/sdk/src/capgraph.rs` | SDK: `query`, `verify`, `depth`, `assert_safe`, `VerifyResult` enum |

---

## 3. Formal Model

### 3.1 Delegation graph

**Definition G.1 (Delegation Graph).** A delegation graph $\mathcal{G} = (V, E)$ where:
- $V$ is the set of all (process, capability) pairs currently active in the kernel.
- $E$ is the set of directed delegation edges: $(p_1, c_1) \xrightarrow{r} (p_2, c_2)$ where $r$ is the rights bitmask of the delegated copy.

**Definition G.2 (Rights Bitmask Dominance).** Bitmask $r_2$ dominates $r_1$ iff $r_2 \supseteq r_1$, written $r_2 \geq r_1$, i.e., $r_2 \text{ \&\& } !\,r_1 = 0$.

**Definition G.3 (Rights Monotone Delegation).** A delegation edge $(p_1, c_1) \xrightarrow{r} (p_2, c_2)$ is rights-sound if $r \subseteq r_{\text{delegator}}$, where $r_{\text{delegator}}$ is the rights bitmask of $c_1$ in process $p_1$'s capability table.

**Invariant G.4 (No Escalation).** For every edge $(p_1, c_1) \xrightarrow{r} (p_2, c_2)$ in $E$:

$$r \mathbin{\&} (\sim r_{\text{delegator}}) = 0$$

Operationally: `proposed_rights & !delegator_rights == 0`. Violation increments `CapGraph::violations` and returns `Err("cap_graph: rights escalation")`.

**Invariant G.5 (Acyclicity).** $\mathcal{G}$ is a directed acyclic graph (DAG). No path from any node returns to itself. Checked via DFS before recording each delegation; violation increments `violations` and returns `Err("cap_graph: delegation cycle")`.

**Invariant G.6 (Edge Liveness).** Every edge $(p_1, c_1) \xrightarrow{r} (p_2, c_2)$ has both $c_1$ and $c_2$ in the live capability tables of $p_1$ and $p_2$ respectively. Revocation of either endpoint triggers `prune_edges_for(pid, cap_id)`, which marks all incident edges inactive.

### 3.2 Provenance chain

**Definition G.7 (Provenance Chain).** A provenance chain for $(p, c)$ is a sequence of `ProvenanceLink` records:

$$[(c_0, p_0, r_0), (c_1, p_1, r_1), \ldots, (c_k, p_k, r_k)]$$

where $(c_0, p_0, r_0)$ is the origin of the capability and $(c_k, p_k, r_k)$ is the current holder. Each link is derived by following `parent_cap_id` references through the kernel's capability tables.

**Definition G.8 (Chain Depth).** The delegation depth of $(p, c)$ is the length of the longest directed path from any root node to $(p, c)$ in $\mathcal{G}$. Bounded by `MAX_CHAIN_DEPTH = 32`.

**Proposition G.9 (Depth Termination).** The `delegation_depth` DFS terminates within `MAX_CHAIN_DEPTH = 32` steps.

*Proof.* The DFS is bounded by `MAX_CHAIN_DEPTH`. Combined with Invariant G.5 (acyclicity), re-visitation is impossible, and the DFS terminates in at most $\min(|E|, 32)$ steps. $\square$

**Theorem G.10 (Monotonic Violation Count).** `CAP_GRAPH.violations` is monotonically non-decreasing and is never reset after a violation is recorded.

*Proof.* The only modification site of `violations` is the increment `self.violations += 1` inside `check_invariants`. There is no reset or decrement path. $\square$

### 3.3 Serialization invariants

**Definition G.11 (Edge Wire Format).** Each delegation edge is serialized as a 20-byte record:

```
[from_pid: 4B LE][from_cap: 4B LE][to_pid: 4B LE][to_cap: 4B LE][rights: 4B LE]
```

**Definition G.12 (Provenance Wire Format).** A provenance chain serializes as:

```
[depth: 1B][truncated: 1B][per-link records ...]
per-link: [cap_id: 4B LE][holder_pid: 4B LE][rights: 4B LE]  (10 bytes per link)
```

Total size for a full chain: $2 + 10 \times \text{depth}$ bytes. Maximum: $2 + 10 \times 32 = 322$ bytes.

---

## 4. Data Structures

### 4.1 `CapDelegationEdge`

```rust
pub struct CapDelegationEdge {
    pub active:     bool,
    pub from_pid:   u32,    // delegating process
    pub from_cap:   u32,    // capability ID in delegating process
    pub to_pid:     u32,    // receiving process
    pub to_cap:     u32,    // capability ID in receiving process
    pub rights_bits: u32,   // bitmask of rights transferred
}
```

### 4.2 `CapGraph`

```rust
pub struct CapGraph {
    edges:           [CapDelegationEdge; 256],  // MAX_GRAPH_EDGES = 256
    pub violations:  u64,                        // monotonic, never resets
}

pub const MAX_GRAPH_EDGES:  usize = 256;
pub const MAX_CHAIN_DEPTH:  usize = 32;
pub const PROVENANCE_MAX_DEPTH: usize = 32;

static CAP_GRAPH: Mutex<CapGraph>  // kernel-global, single instance
```

### 4.3 `ProvenanceChain`

```rust
pub struct ProvenanceLink {
    pub cap_id:     u32,
    pub holder_pid: u32,
    pub rights_bits: u32,
}

pub struct ProvenanceChain {
    pub links:     [ProvenanceLink; 32],
    pub depth:     usize,
    pub truncated: bool,
}
```

---

## 5. Core Algorithms

### 5.1 `check_invariants`

Called immediately before `record_delegation`. Performs both invariant checks atomically under the `CAP_GRAPH` lock.

```
check_invariants(from_pid, from_cap, to_pid, delegator_rights, proposed_rights):
    if proposed_rights & !delegator_rights != 0:
        self.violations += 1
        return Err("cap_graph: rights escalation")
    if self.would_create_cycle(from_pid, from_cap, to_pid):
        self.violations += 1
        return Err("cap_graph: delegation cycle")
    Ok(())
```

### 5.2 `would_create_cycle` (DFS)

```
would_create_cycle(from_pid, from_cap, to_pid):
    // DFS from to_pid; if we reach from_pid through any edge, cycle detected
    let mut visited = [(u32, u32); MAX_CHAIN_DEPTH]
    let mut stack = [(to_pid, 0)]  // (pid, cap) pairs to explore
    while stack non-empty:
        (cur_pid, _) = stack.pop()
        if cur_pid == from_pid: return true  // loop detected
        for each active edge e where e.from_pid == cur_pid:
            if depth < MAX_CHAIN_DEPTH:
                stack.push((e.to_pid, e.to_cap))
    return false
```

The depth cap at `MAX_CHAIN_DEPTH = 32` ensures termination independent of graph structure.

### 5.3 `record_delegation`

```
record_delegation(from_pid, from_cap, to_pid, to_cap, rights_bits) -> Result<(),&str>:
    let mut g = CAP_GRAPH.lock()
    // find free slot in g.edges
    for i in 0..MAX_GRAPH_EDGES:
        if !g.edges[i].active:
            g.edges[i] = CapDelegationEdge { active: true, from_pid, from_cap, to_pid, to_cap, rights_bits }
            return Ok(())
    Err("cap_graph: edge table full")
```

### 5.4 `prune_edges_for` and `prune_edges_for_pid`

```
prune_edges_for(pid, cap_id):
    for each active edge e where (e.from_pid == pid && e.from_cap == cap_id)
                               || (e.to_pid   == pid && e.to_cap   == cap_id):
        e.active = false

prune_edges_for_pid(pid):
    for each active edge e where e.from_pid == pid || e.to_pid == pid:
        e.active = false
```

Both are called under lock. `prune_edges_for` is called from `revoke_capability`; `prune_edges_for_pid` from process teardown.

### 5.5 `build_chain` (provenance reconstruction)

Walks the live capability tables and `CAP_GRAPH` edge table to reconstruct the
full delegation ancestry. Each hop resolves `parent_cap_id` from the capability
table, then looks for an incoming cross-process delegation edge to determine
which process was the parent.

```
build_chain(pid, cap_id) -> ProvenanceChain:
    chain = ProvenanceChain { depth: 0, truncated: false }
    current_pid = pid
    current_cap = cap_id
    loop:
        if chain.depth >= PROVENANCE_MAX_DEPTH:
            chain.truncated = true; break
        // Resolve via capability_manager().tables (acquires lock)
        (rights_bits, parent_cap_id_opt) = lookup(current_pid, current_cap)
        if lookup fails: break
        chain.links[chain.depth] = ProvenanceLink {
            cap_id: current_cap, holder_pid: current_pid, rights_bits
        }
        chain.depth += 1
        match parent_cap_id_opt:
            None => break  // root capability (no parent)
            Some(parent_cap) =>
                // Search CAP_GRAPH for cross-process edge to (current_pid, current_cap)
                found_cross = false
                for each active edge e where e.to_pid == current_pid
                                         && e.to_cap == current_cap:
                    current_pid = e.from_pid
                    current_cap = e.from_cap
                    found_cross = true; break
                if not found_cross:
                    // Intra-process attenuation: stay in same PID
                    current_cap = parent_cap
                    // current_pid unchanged
    return chain
```

Key notes:
- `parent_cap_id` is `Option<u32>`, not a zero-sentinel; `None` means root.
- Cross-process provenance is recovered from `CAP_GRAPH` edges, not just the `parent_cap_id` field.
- The lock on `capability_manager().tables` and `CAP_GRAPH` are *not* held simultaneously; each hop releases and reacquires.

---

## 6. WASM Host ABI (IDs 129–131)

### ID 129 — `cap_graph_query(cap_id: i32, buf_ptr: i32, buf_len: i32) → i32`

Writes the delegation edges for `cap_id` into WASM memory. Each edge occupies 20 bytes in the wire format defined by Definition G.11. At most 16 edges are written per call regardless of `buf_len`.

Returns the number of edges written, or `−1` if `cap_id` is not found.

### ID 130 — `cap_graph_verify(cap_id: i32, delegatee_pid: i32) → i32`

Runs `check_invariants` for a proposed delegation from the current holder of `cap_id` to `delegatee_pid`.

Return codes:
- `0` — safe: no escalation, no cycle
- `1` — rights escalation detected
- `2` — would create a delegation cycle
- `3` — `cap_id` not found in the capability table

This call is **read-only**: it does not record an edge or modify any kernel state.

### ID 131 — `cap_graph_depth(cap_id: i32) → i32`

Returns the longest delegation chain length for `cap_id`, computed by `delegation_depth(pid, cap_id)`. Returns `0` if the capability is a root with no incoming delegation edges, or `−1` if not found.

---

## 7. Formal Verification Integration

`formal_capability_self_check()` executes the following proof obligations at kernel boot and on demand:

1. **Obligation C1 — No active edge references a non-existent process.** All `from_pid` and `to_pid` values in active edges must correspond to running processes.
2. **Obligation C2 — No active edge references a non-existent capability.** `from_cap` and `to_cap` must be present in the respective process's capability table.
3. **Obligation C3 — All edges are rights-monotone.** For every edge $(p_1, c_1, p_2, c_2, r)$: $r \subseteq r_{c_1}$.
4. **Obligation C4 — The delegation graph is acyclic.** DFS from every node confirms no back-edges.
5. **Obligation C5 — `violation_count()` equals the total number of times an invariant was broken.** The counter's monotonicity is verified by inspection of all write sites.

---

## 8. SDK Usage

```rust
use oreulius_sdk::capgraph;

// ── Verify a proposed delegation ───────────────────────────────────────────
match capgraph::verify(my_cap_id, target_pid) {
    capgraph::VerifyResult::Safe             => { /* proceed */ }
    capgraph::VerifyResult::RightsEscalation => { panic!("escalation attempt") }
    capgraph::VerifyResult::Cycle            => { panic!("delegation cycle") }
    capgraph::VerifyResult::NotFound         => { panic!("cap not found") }
}

// ── Query all delegation edges for a capability ─────────────────────────────
let mut edge_buf = [0u8; 320];  // room for 16 × 20-byte edges
let edge_count = capgraph::query(my_cap_id, &mut edge_buf);
for i in 0..edge_count {
    let off = i * 20;
    let from_pid  = u32::from_le_bytes(edge_buf[off..off+4].try_into().unwrap());
    let from_cap  = u32::from_le_bytes(edge_buf[off+4..off+8].try_into().unwrap());
    let to_pid    = u32::from_le_bytes(edge_buf[off+8..off+12].try_into().unwrap());
    let to_cap    = u32::from_le_bytes(edge_buf[off+12..off+16].try_into().unwrap());
    let rights    = u32::from_le_bytes(edge_buf[off+16..off+20].try_into().unwrap());
    // ...
}

// ── Query delegation chain depth ────────────────────────────────────────────
let depth = capgraph::depth(my_cap_id);
// depth == 0: root capability (not delegated to this process from another)
// depth > 0:  number of delegation hops from origin

// ── SDK types ───────────────────────────────────────────────────────────────
pub enum VerifyResult { Safe, RightsEscalation, Cycle, NotFound }
pub fn verify(cap_id: u32, delegatee_pid: u32) -> VerifyResult
pub fn query(cap_id: u32, buf: &mut [u8]) -> usize
pub fn depth(cap_id: u32) -> u32
pub fn assert_safe(cap_id: u32, delegatee_pid: u32) -> Result<(), VerifyResult>
```

---

## 9. Integration Points

### 9.1 `transfer_capability` hot path

```
CapabilityManager::transfer_capability(from_pid, from_cap, to_pid):
    // 1. Remove cap from source table (raises TaskNotFound if PID absent)
    let cap = from_table.remove(from_cap)?
    // 2. Check invariants BEFORE completing the transfer (same rights as delegator)
    cap_graph::check_invariants(
        from_pid, from_cap, to_pid,
        delegator_rights = cap.rights.bits(),
        proposed_rights  = cap.rights.bits(),
    ).map_err(|_| CapabilityError::SecurityViolation)?
    // 3. Stamp provenance
    delegated_cap.parent_cap_id = Some(from_cap)
    // 4. Install in destination table
    let to_cap = to_table.install(delegated_cap)?
    // 5. Record edge
    cap_graph::record_delegation(from_pid, from_cap, to_pid, to_cap, cap.rights.bits())
    // 6. Audit
    security().log_event(CapabilityTransferred, from_pid, from_cap)
```

The capability is moved (not copied). The error returned by `check_invariants`
propagates as `CapabilityError::SecurityViolation`.

### 9.2 `revoke_capability`

```
CapabilityManager::revoke_capability(pid, cap_id):
    // ... revoke in task cap table ...
    cap_graph::prune_edges_for(pid, cap_id)  // auto-orphan cleanup
```

### 9.3 Process teardown

```
on process_exit(pid):
    cap_graph::prune_edges_for_pid(pid)  // remove all edges from/to this process
```

This prevents the graph from accumulating stale edges from terminated processes, which would otherwise trigger false positives in cycle detection.

---

## 10. Known Limitations

| Limitation | Detail |
|---|---|
| **256-edge capacity** | `MAX_GRAPH_EDGES = 256`. A kernel with many delegating processes can exhaust the edge table; `record_delegation` returns `Err("cap_graph: edge table full")` and the delegation is refused. |
| **No runtime trimming of violations counter** | `violations` is monotonically increasing and never resets. Diagnostic consumers must handle large values; the counter can wrap at $2^{64}$. |
| **16 edges per `cap_graph_query` call** | The host function caps output at 16 edges per WASM call. Process with more than 16 outgoing delegations requires multiple queries (not currently supported by the host function API). |
| **Chain truncation** | `build_chain` sets `truncated = true` if provenance exceeds `PROVENANCE_MAX_DEPTH = 32`. Deep chains lose origin information. |
| **Verify is read-only** | `cap_graph_verify` (ID 130) does not pre-commit an edge; a verified delegation can still fail at `record_delegation` if the edge table fills between the verify and the transfer. |
