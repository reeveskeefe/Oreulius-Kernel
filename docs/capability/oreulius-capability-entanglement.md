# Oreulius Collapse-Linked Capability Entanglement



## 1. Overview

In the entanglement-collapse model, linked particles share correlated state: the act of observation (collapse) on one instantly propagates to all entangled partners, regardless of separation. Capability Entanglement in Oreulius applies this collapse-propagation model to kernel security: two or more capabilities can be *linked* such that **revoking any one of them automatically collapses authority across all the others**.

This is not metaphor. The entanglement is implemented as a set of links in a kernel table (`ENTANGLE_TABLE`). When the capability manager revokes a capability, it checks whether that capability has any entanglement links and immediately cascades revocation to all linked peers — without any further action from the owning process.

### Why this matters

Classical revocation requires the revoking party to explicitly enumerate all related capabilities and revoke them one by one. This is error-prone: if a module grants a capability to five different services and then needs to revoke all five (e.g., because a user logs out), it must track all five handles explicitly. If any one is missed, authority leaks.

Capability Entanglement makes revocation compositional:

1. **Lifecycle coupling** — link a session capability to a set of resource-access capabilities. When the session ends and its root capability is revoked, all resource capabilities vanish automatically.
2. **Atomic multi-capability revocation** — revoke a group of capabilities as an atomic unit: no partial states where some are gone and others remain.
3. **RAII integration** — the `EntangleGuard` type ensures entanglement links are cleaned up when they go out of scope, without revoking the capabilities themselves.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  WASM Module                                                         │
│  entangle::entangle(cap_a, cap_b)                                   │
│  entangle::entangle_group(&[cap_a, cap_b, cap_c])                  │
│  entangle::disentangle(cap_id)                                      │
│  entangle::entangle_query(cap_id, &mut list)                        │
└─────────────────────────────┬────────────────────────────────────────┘
                              │  WASM host ABI (IDs 125–128)
┌─────────────────────────────▼────────────────────────────────────────┐
│  Entanglement Host Functions  (kernel/src/execution/wasm.rs)        │
│  host_cap_entangle / cap_entangle_group /                           │
│  cap_disentangle / cap_entangle_query                               │
└──────────┬──────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────────┐
│  ENTANGLE_TABLE: Mutex<EntangleTable>                               │
│  128 × EntangleLink { active, pid, cap_a, cap_b, group_id }        │
│  next_group_id: u32 (starts at 1)                                  │
└──────────┬──────────────────────────────────────────────────────────┘
           │  entangle_cascade_revoke(pid, cap_id)
    ┌──────▼─────────────────────────────────────────────────────────┐
    │  Called from CapabilityManager::revoke_capability              │
    │  1. Collect peers under lock                                   │
    │  2. Deactivate links (prevents re-entry)                       │
    │  3. Revoke peers outside lock                                  │
    └────────────────────────────────────────────────────────────────┘
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/execution/wasm.rs` | `EntangleLink`, `EntangleTable`, `ENTANGLE_TABLE`, `entangle_cascade_revoke`, host functions IDs 125–128 |
| `kernel/src/capability/mod.rs` | Calls `entangle_cascade_revoke` from `revoke_capability` |
| `wasm/sdk/src/entangle.rs` | SDK: `entangle`, `entangle_group`, `disentangle`, `entangle_query`, `EntangleList`, `EntangleGuard`, `GroupEntangleGuard` |

---

## 3. Formal Model

### 3.1 Entanglement graph

**Definition E.1 (Entanglement Link).** An entanglement link is a tuple $(p, c_a, c_b, g)$ where $p$ is the owning process, $c_a$ and $c_b$ are capability IDs, and $g$ is the group ID (`0` for pairwise links, `> 0` for named groups).

**Definition E.2 (Entanglement Graph).** The entanglement graph $\mathcal{E} = (V, L)$ where $V$ is the set of active capabilities and $L$ is the set of active entanglement links.

**Definition E.3 (Reachability).** Two capabilities $c_i$ and $c_j$ are *entanglement-reachable* if there exists a path through $\mathcal{E}$: $c_i = c_0 \sim c_1 \sim \cdots \sim c_k = c_j$ where each $c_{m} \sim c_{m+1}$ is an active link.

**Definition E.4 (Cascade Revocation).** Revoking capability $c$ triggers cascade revocation of all capabilities directly linked to $c$ via active links. Note: cascade is depth-1 in a single pass; it is not recursive. However, since `entangle_cascade_revoke` is called from `revoke_capability`, and each revocation calls `entangle_cascade_revoke`, cascades propagate transitively through the chain.

**Proposition E.5 (Transitive Cascade).** If capabilities $A$, $B$, $C$ are linked as $A \sim B \sim C$, revoking $A$ revokes $B$ (direct link), and revoking $B$ revokes $C$ (second-generation cascade), provided that cascade loops are broken by link deactivation.

*Proof.* `revoke_capability(A)` calls `entangle_cascade_revoke(A)` which collects $\{B\}$ and deactivates the $A \sim B$ link, then calls `revoke_capability(B)`. `revoke_capability(B)` calls `entangle_cascade_revoke(B)` which collects $\{C\}$, deactivates $B \sim C$, and calls `revoke_capability(C)`. $\square$

**Proposition E.6 (No Cascade Re-entry).** If $A \sim B$ and $B \sim A$ (a symmetric pairwise link), revoking $A$ does not infinitely loop.

*Proof.* `entangle_cascade_revoke(A)`:
1. Acquires `ENTANGLE_TABLE` lock.
2. Finds link $\{A \sim B\}$; marks it inactive (`active = false`).
3. Collects peer $\{B\}$.
4. Releases lock.
5. Calls `revoke_capability(B)` → `entangle_cascade_revoke(B)`.
6. `entangle_cascade_revoke(B)` scans the table; the $A \sim B$ link is now inactive, so $A$ is not collected. No further cascade. $\square$

### 3.2 Group topology

**Definition E.7 (Star Topology).** A group with capabilities $[c_0, c_1, \ldots, c_{n-1}]$ is stored as $n-1$ pairwise links: $(p, c_0, c_i, g)$ for $i \in [1, n-1]$. $c_0$ is the *anchor*.

**Definition E.8 (Star Revocation Property).** In a star topology, revoking the anchor $c_0$ cascades to all $c_1, \ldots, c_{n-1}$ in a single pass. Revoking any non-anchor $c_i$ ($i > 0$) cascades only to $c_0$, which then cascades to all remaining non-anchors.

*Proof.* The star has links $(c_0, c_1), (c_0, c_2), \ldots, (c_0, c_{n-1})$. Revoking $c_0$: `entangle_cascade_revoke(c_0)` collects all $\{c_1, \ldots, c_{n-1}\}$ and deactivates all links in one lock pass, then revokes each peer. Revoking $c_i$ ($i > 0$): `entangle_cascade_revoke(c_i)` collects $\{c_0\}$ and deactivates link $(c_0, c_i)$, then revokes $c_0$. Revoking $c_0$ cascades to all remaining $c_j$ ($j \neq i$) via remaining active links. $\square$

**Corollary E.9 (Group Partial Revocation).** Revoking a non-anchor in a group revokes the anchor and all other members. This is a consequence of the star topology: there is no way to revoke one non-anchor member without triggering the full cascade. Applications that need partial revocation should use disentanglement before revocation.

### 3.3 Disentanglement vs. revocation

**Definition E.10 (Disentanglement).** `cap_disentangle(cap_id)` removes all entanglement links incident to `cap_id` without revoking the capability itself. After disentanglement, `cap_id` may be revoked independently with no cascade.

**Proposition E.11 (Disentanglement Safety).** Disentanglement is always safe to call before revocation: it reduces the blast radius of a revocation to exactly one capability. $\square$

---

## 4. Data Structures

### 4.1 `EntangleLink`

```rust
const MAX_ENTANGLE_LINKS: usize = 128;

struct EntangleLink {
    active:   bool,
    pid:      u32,      // owning process (both caps must belong to this process)
    cap_a:    u32,      // first capability ID
    cap_b:    u32,      // second capability ID
    group_id: u32,      // 0 = pairwise; > 0 = group tag
}
```

### 4.2 `EntangleTable`

```rust
struct EntangleTable {
    links:         [EntangleLink; 128],
    next_group_id: u32,   // starts at 1, increments per group allocation
}

static ENTANGLE_TABLE: Mutex<EntangleTable>
```

Total static allocation: $128 \times 17 \approx 2.2\text{ KiB}$.

### 4.3 `entangle_cascade_revoke`

```rust
pub fn entangle_cascade_revoke(pid: u32, cap_id: u32) {
    let peers: [u32; 32];
    let peer_count;

    // Phase 1: collect peers and deactivate links under lock
    {
        let mut table = ENTANGLE_TABLE.lock();
        peer_count = 0;
        for link in table.links.iter_mut() {
            if !link.active || link.pid != pid { continue; }
            if link.cap_a == cap_id {
                if peer_count < 32 { peers[peer_count] = link.cap_b; peer_count += 1; }
                link.active = false;
            } else if link.cap_b == cap_id {
                if peer_count < 32 { peers[peer_count] = link.cap_a; peer_count += 1; }
                link.active = false;
            }
        }
    }
    // Phase 2: revoke peers outside lock (prevents deadlock and re-entry)
    for i in 0..peer_count {
        serial_println!("[entangle] cascade-revoked cap {} (entangled with {}) for pid {}",
            peers[i], cap_id, pid);
        capability_manager().revoke_capability(ProcessId(pid), peers[i]);
    }
}
```

---

## 5. WASM Host ABI (IDs 125–128)

### ID 125 — `cap_entangle(cap_a: i32, cap_b: i32) → i32`

Creates a pairwise entanglement link between `cap_a` and `cap_b`:

1. Verifies `cap_a` exists via `query_capability(pid, cap_a)`. Returns `−1` if not found.
2. Verifies `cap_b` exists via `query_capability(pid, cap_b)`. Returns `−2` if not found.
3. Finds a free slot in `ENTANGLE_TABLE`. Returns `−3` if full (128 links).
4. Stores `EntangleLink { active: true, pid, cap_a, cap_b, group_id: 0 }`.
5. Returns `0`.

### ID 126 — `cap_entangle_group(group_ptr: i32, group_len: i32) → i32`

Creates a group entanglement with star topology:

1. Validates `2 ≤ group_len ≤ 32`. Returns `−1` if out of range.
2. Reads `group_len × 4` bytes from WASM memory at `group_ptr` as packed LE `u32` capability IDs.
3. Verifies all capabilities exist for the calling process. Returns `−2` if any are not found.
4. Checks that `ENTANGLE_TABLE` has at least `group_len − 1` free slots. Returns `−3` if not.
5. Allocates `group_id = next_group_id++`.
6. Creates `group_len − 1` links: $(p, \text{caps}[0], \text{caps}[i], \text{group\_id})$ for $i \in [1, \text{group\_len}-1]$.
7. Returns `group_id as i32`.

### ID 127 — `cap_disentangle(cap_id: i32) → i32`

Removes all entanglement links for `cap_id` without revoking the capability:

1. Scans `ENTANGLE_TABLE` for all active links where `cap_a == cap_id || cap_b == cap_id` and `pid == calling_pid`.
2. Marks each found link inactive.
3. Returns `0` if at least one link was removed, `−1` if no links were found.

### ID 128 — `cap_entangle_query(cap_id: i32, buf_ptr: i32, buf_len: i32) → i32`

Returns the set of capabilities entangled with `cap_id`:

1. `buf_len` is the number of `u32` slots available in the buffer (not byte count).
2. Scans `ENTANGLE_TABLE` for active links where `cap_a == cap_id || cap_b == cap_id`.
3. For each match, writes the peer cap ID (`cap_b` if `cap_a == cap_id`, else `cap_a`) as LE `u32` into WASM memory.
4. Returns the count of cap IDs written, or `−1` if none found.

---

## 6. SDK Usage

```rust
use oreulius_sdk::entangle::{self, EntangleGuard, EntangleList};

// ── Pairwise entanglement ───────────────────────────────────────────────────
entangle::entangle(session_cap, fs_cap).expect("entangle failed");

// Now revoking session_cap also revokes fs_cap, and vice versa.

// ── RAII pairwise entanglement (auto-disentangles on drop, NOT revoke) ──────
{
    let _guard = EntangleGuard::new(session_cap, fs_cap)
        .expect("entangle failed");
    // ... work with both capabilities ...
    // When _guard drops: disentangle called. Caps remain alive.
}

// ── Group entanglement ──────────────────────────────────────────────────────
let caps = [root_cap, child_a, child_b, child_c];
let group_id = entangle::entangle_group(&caps).expect("group failed");
// Revoking root_cap revokes all children in one pass.
// Revoking child_a revokes root_cap, which revokes child_b and child_c.

// ── Query entangled peers ───────────────────────────────────────────────────
if let Some(list) = entangle::entangle_query(root_cap) {
    for peer_cap in list.as_slice() {
        // peer_cap is entangled with root_cap
    }
}

// ── Disentangle before targeted revocation ─────────────────────────────────
entangle::disentangle(child_b).ok();  // remove child_b from group
// Now revoking child_b has no cascade.
// root_cap → child_a, child_c still entangled.

// ── SDK types ───────────────────────────────────────────────────────────────
pub fn entangle(cap_a: u32, cap_b: u32) -> Result<(), i32>
pub fn entangle_group(caps: &[u32]) -> Result<u32, i32>   // returns group_id
pub fn disentangle(cap_id: u32) -> Result<(), i32>
pub fn entangle_query(cap_id: u32) -> Option<EntangleList>

pub struct EntangleList { data: [u32; 32], len: usize }
impl EntangleList {
    pub fn as_slice(&self) -> &[u32] { &self.data[..self.len] }
    pub fn len(&self) -> usize        { self.len }
}

pub struct EntangleGuard { cap_a: u32, cap_b: u32 }
impl EntangleGuard {
    pub fn new(cap_a: u32, cap_b: u32) -> Result<Self, i32>
    pub fn leak(self)  // keep link alive (consumes guard without disentangling)
}
impl Drop for EntangleGuard {
    fn drop(&mut self) { let _ = entangle::disentangle(self.cap_a); }
}

pub struct GroupEntangleGuard { anchor_cap: u32 }
impl Drop for GroupEntangleGuard {
    fn drop(&mut self) { let _ = entangle::disentangle(self.anchor_cap); }
}
```

---

## 7. Use Cases

### 7.1 Session-scoped resource cleanup

A web service module creates a session capability and entangles it with all resource capabilities granted during that session (file handles, network channels, database cursors). When the session terminates and the session capability is revoked, all resources are automatically freed — no explicit cleanup enumeration required.

```rust
let session_cap = capability::grant(SESSION_TYPE, SESSION_RIGHTS)?;
let file_cap    = capability::grant(FILE_TYPE, READ_RIGHTS)?;
let net_cap     = capability::grant(NETWORK_TYPE, NET_RIGHTS)?;
entangle::entangle_group(&[session_cap, file_cap, net_cap])?;
// Session ends:
capability::revoke(session_cap)?;
// file_cap and net_cap are now automatically revoked.
```

### 7.2 Atomic capability set invalidation

A signing oracle module holds a set of signing keys as capabilities. When a compromise is detected, a single revocation of the root invalidates all keys simultaneously:

```rust
let keys = [key_a_cap, key_b_cap, key_c_cap, key_d_cap];
let group_id = entangle::entangle_group(&keys)?;
// On compromise:
capability::revoke(keys[0])?;  // revokes all 4 atomically
```

### 7.3 Guarded temporary delegation with automatic revocation

A process temporarily delegates a capability to a worker. The worker's capability is entangled with a sentinel capability held by the parent. When the parent decides the delegation window is over, it revokes the sentinel:

```rust
let sentinel   = temporal::cap_grant(SENTINEL_TYPE, 0, 5000)?; // 50-second deadline
let worker_cap = capability::delegate(my_cap)?;
entangle::entangle(sentinel, worker_cap)?;
// Either: sentinel expires (auto-revokes worker_cap via cascade)
// Or: parent manually revokes sentinel early.
```

---

## 8. Integration: `revoke_capability` Call Chain

```
CapabilityManager::revoke_capability(pid, cap_id):
    1. Remove cap_id from task capability table
    2. cap_graph::prune_edges_for(pid, cap_id)
    3. entangle_cascade_revoke(pid, cap_id)      ← HERE
       3a. Collect peers and deactivate links (under lock)
       3b. For each peer: revoke_capability(pid, peer)
           → Recursive call, but no infinite loop (links deactivated in 3a)
```

The cascade is depth-first and terminates because each link is marked inactive before its peer is revoked, preventing any link from being traversed twice.

---

## 9. Known Limitations

| Limitation | Detail |
|---|---|
| **128-link table** | `MAX_ENTANGLE_LINKS = 128`. A kernel with many heavily-entangled services can exhaust the table. |
| **32 caps per cascade collection** | `entangle_cascade_revoke` collects at most 32 peers per invocation. A capability linked to more than 32 others will have only the first 32 cascaded; the rest remain active. |
| **Star topology group semantics** | Non-anchor members can trigger full group revocation (Corollary E.9). Use `disentangle` before targeted revocation if partial group revocation is desired. |
| **Single-process constraint** | All capabilities in an entanglement link must be owned by the same process. Cross-process entanglement is not supported. |
| **No group membership query** | `cap_entangle_query` returns peer caps but not the `group_id`. There is no host function that lists all capabilities in a group by group ID. |
| **group_id counter overflow** | `next_group_id` is a `u32` starting at 1. After $2^{32} - 1$ group allocations it wraps. Old group IDs may be reused if groups were previously disentangled, but the links for old groups are already inactive. |
| **Disentangle-on-drop, not revoke** | `EntangleGuard::drop` calls `disentangle`, not `revoke`. The capabilities remain alive after the guard drops. This is intentional but may surprise users expecting cleanup. Use `temporal::TemporalCap` for revoke-on-drop semantics. |
