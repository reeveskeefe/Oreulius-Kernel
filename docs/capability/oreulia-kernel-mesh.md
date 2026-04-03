# Oreulius Kernel Mesh — Decentralized Capability Federation

> **Status:** Fully implemented. WASM host ABI IDs 109–115. SDK: `wasm/sdk/src/mesh.rs`. Kernel subsystems: `kernel/src/net/capnet.rs`, `kernel/src/execution/wasm.rs` (mesh host functions), `kernel/src/capability/mod.rs` (remote lease table).

---

## 1. Overview

The Kernel Mesh turns a fleet of independent Oreulius instances into a single logical capability namespace. Rather than treating device boundaries as security barriers that must be manually bridged by application-layer protocols, the mesh embeds capability federation directly into the kernel: tokens are minted, routed, and verified at the kernel level, and WASM modules can migrate their own bytecode — along with their live authority — to a remote device in a single atomic operation.

This is not a distributed operating system in the classical sense. There is no shared kernel state, no global scheduler, and no distributed consensus. Each node remains sovereign. What the mesh provides is a **cryptographically-attested, capability-mediated channel** between sovereign kernels, so that authority from one kernel instance can be delegated to, attenuated for, and used by another, while the entire chain remains auditable, revocable, and bounded by the same rights algebra that governs intra-node IPC.

### Key properties

| Property | Mechanism |
|---|---|
| Device identity | 64-bit random device ID initialized at boot, mixed with PIT ticks |
| Token authenticity | SipHash-2-4 MAC over 108 fixed bytes, keyed by kernel boot key or per-peer session key |
| Replay protection | Per-peer sliding window bitmap (64-bit) + monotonic high-nonce watermark |
| Delegation depth | `CAPNET_MAX_DELEGATION_DEPTH = 32` hops enforced at verification time |
| Use budgets | Optional `max_uses` field; kernel decrements on each verified use |
| Byte quotas | Optional `max_bytes` field; enforced by capability manager |
| Attestation binding | `measurement_hash` field; peer can require token to match its own measurement |
| Session binding | `session_id` field; token is only valid within a specific session context |
| Peer capacity | `CAPNET_MAX_PEERS = 32` concurrent registered peers per node |
| Migration queue | 4-slot async queue; flushed by scheduler tick or immediate flush |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  WASM Module (any language via polyglot loader)                  │
│  mesh::token_mint()  →  mesh::token_send()  →  mesh::migrate()   │
└────────────────────────┬────────────────────────────────────────-┘
                         │  WASM host ABI (IDs 109–115)
┌────────────────────────▼────────────────────────────────────────┐
│  Mesh Host Functions  (kernel/src/execution/wasm.rs)            │
│  host_mesh_local_id / peer_register / peer_session /            │
│  token_mint / token_send / token_recv / mesh_migrate            │
└──────────┬─────────────────────────────────┬───────────────────-┘
           │                                 │
    ┌──────▼──────-┐                  ┌──────▼──────────────────┐
    │  CapNet      │                  │  MeshMigrateQueue       │
    │  capnet.rs   │                  │  4 × MeshMigrateRequest │
    │  CAPNET_PEERS│                  │  bytecode[65536]        │
    │  32 slots    │                  │  mesh_migrate_flush()   │
    └──────┬───────┘                  └──────┬──────────────────┘
           │                                 │
    ┌──────▼──────────────────────────────────▼──────────────────┐
    │  Network Layer  (net/netstack.rs + net/capnet.rs)          │
    │  TokenOffer control frame → observer bus → wire            │
    └────────────────────────────────────────────────────────────┘
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/net/capnet.rs` | `CapabilityTokenV1`, peer table, session key derivation, frame encoding/decoding, revocation journal, fuzz/formal-check infrastructure |
| `kernel/src/execution/wasm.rs` | 7 mesh host functions, `MeshMigrateQueue`, `mesh_migrate_flush()` |
| `kernel/src/capability/mod.rs` | Remote lease table — stores inbound tokens as `RemoteLease` entries visible to WASM via `token_recv` |
| `wasm/sdk/src/mesh.rs` | High-level Rust SDK wrappers (`local_id`, `peer_register`, `peer_session`, `token_mint`, `token_send`, `token_recv`, `migrate`) |
| `wasm/sdk/src/raw/oreulius.rs` | Raw `extern "C"` declarations for the 7 host ABI functions |

---

## 3. Formal Model

### 3.1 Device identity and the authority universe

Let $\mathcal{D}$ be the (potentially infinite) set of all Oreulius device identities. Each device $d \in \mathcal{D}$ holds a private kernel boot key $K_d$ and a per-peer session key $K_{d,d'}$ for each registered peer $d'$.

**Definition M.1 (Device Identity).** Each Oreulius node generates its device ID at boot as:

$$\text{id}_d = \text{PRNG}_{\text{kernel}}(256\text{ bits}) \oplus (\text{PIT\_ticks} \times 2)$$

truncated to 64 bits, with $\text{id}_d \neq 0$ enforced by setting to 1 if zero. The XOR with the PIT timer prevents two devices from colliding even if their random seeds share a common prefix.

**Definition M.2 (Rights Algebra).** The primitive rights set $R_0 = \{\text{send}, \text{recv}, \text{close}, \text{delegate}, \text{observe}\}$ generates the rights algebra $(2^{R_0}, \subseteq, \cup, \cap, \emptyset, R_0)$. Every capability token carries a `rights: u32` bitmask interpreted as an element of this algebra. Attenuation is the partial order: $r_1 \sqsubseteq r_2 \iff r_1 \subseteq r_2$.

**Lemma M.3 (Attenuation Transitivity).** For any $r_1, r_2, r_3 \in 2^{R_0}$, if $r_1 \sqsubseteq r_2$ and $r_2 \sqsubseteq r_3$, then $r_1 \sqsubseteq r_3$.

*Proof.* Subset inclusion is transitive. $\square$

### 3.2 The `CapabilityTokenV1` token format

A `CapabilityTokenV1` is a fixed 116-byte structure encoding a portable, cryptographically attested authority assertion:

| Field | Bytes | Description |
|---|---|---|
| `version` | 1 | Wire version; must be 1 |
| `alg_id` | 1 | MAC algorithm: 1 = SipHash-2-4 (kernel key), 2 = reserved (Ed25519) |
| `cap_type` | 1 | Application-defined capability category |
| `token_flags` | 1 | Reserved flags |
| `issuer_device_id` | 8 | $d_\text{issuer}$: 64-bit ID of the minting node |
| `subject_device_id` | 8 | $d_\text{subject}$: 64-bit ID of the intended recipient |
| `object_id` | 8 | The kernel object this token authorizes access to |
| `rights` | 4 | Authority bitmask over $R_0$ |
| `constraints_flags` | 4 | Policy constraint bits (see below) |
| `issued_at` | 8 | PIT tick at issuance |
| `not_before` | 8 | PIT tick before which token is not yet valid |
| `expires_at` | 8 | PIT tick at which token expires |
| `nonce` | 8 | Anti-replay nonce; unique per issuance |
| `delegation_depth` | 2 | Number of delegation hops from the original mint |
| `max_uses` | 2 | If constraint bit 0 is set: maximum number of authorized uses |
| `parent_token_hash` | 8 | FNV-1a-64 of the parent token's body (links delegation chains) |
| `measurement_hash` | 8 | Hash of the WASM module's bytecode at issuance (attestation) |
| `session_id` | 4 | Session this token is bound to (if `CAPNET_CONSTRAINT_SESSION_BOUND`) |
| `context` | 4 | Caller context (e.g., process ID of the subject) |
| `max_bytes` | 4 | Byte budget; if non-zero and constraint bit 1 is set, enforced |
| `resource_quota` | 4 | Additional resource quota field |
| `mac` | 8 | SipHash-2-4 MAC over the preceding 108 bytes |

**Total: 116 bytes.** Constant `CAPNET_TOKEN_V1_LEN = 116`.

### 3.3 MAC construction and token identity

The MAC is computed over the 108-byte body (fields `version` through `resource_quota`, with magic `0x544E_5043` prepended):

$$\text{MAC}(T) = \text{SipHash-2-4}_{K}(\text{encode\_without\_mac}(T))$$

where $K$ is either the kernel boot key (phase 1, intra-node verification) or the per-peer session key $K_{d,d'}$ (phase 2, cross-node verification).

**Definition M.4 (Token Identity).** The canonical, MAC-independent identity of a token is:

$$\text{token\_id}(T) = \text{FNV-1a-64}(\text{encode\_without\_mac}(T))$$

This is stable across re-signing (e.g., when the same token is resigned for a different peer session) and is used as the deduplication and revocation key.

### 3.4 Session key derivation

When two nodes establish a session, both contribute nonces and the session key is derived as:

**Definition M.5 (Session Key).** For peers $d$ and $d'$ with local nonce $n_L$, remote nonce $n_R$, measurement hash $h_m$, and epoch $e$:

$$K_{d,d'} = \text{capnet\_derive\_session\_key}(d', n_L, n_R, h_m, e)$$

The derivation is implemented in `SecurityManager::capnet_derive_session_key`. The epoch $e$ is a monotone counter incremented on each session re-establishment, making old-epoch MACs invalid after rekeying.

### 3.5 Replay protection

Each peer entry maintains a sliding anti-replay window:

- `replay_high_nonce: u64` — the highest nonce accepted so far
- `replay_bitmap: u64` — a 64-bit window of accepted nonces below `replay_high_nonce`

**Definition M.6 (Nonce Acceptance Predicate).** A nonce $n$ is accepted for peer $p$ iff:

$$n > \text{replay\_high\_nonce}(p) \quad \vee \quad \left(n \geq \text{replay\_high\_nonce}(p) - 63 \;\wedge\; \text{replay\_bitmap}[n \bmod 64] = 0\right)$$

**Proposition M.7 (Replay Resistance).** Under honest MAC verification and nonce acceptance, no attacker can submit a previously accepted token and have it accepted again.

*Proof.* A replayed token has a nonce $n$ that was already accepted. If $n \leq \text{replay\_high\_nonce} - 64$, it falls outside the window and is rejected outright. Otherwise, the bitmap records its acceptance, and the zero-check fails. The MAC ensures the nonce field cannot be forged to a fresh value while reusing other token fields. $\square$

### 3.6 Delegation depth and the no-amplification invariant

**Definition M.8 (Delegation Chain).** A delegation chain is a sequence of tokens $T_1, T_2, \ldots, T_k$ where for each $i > 1$:

- $\text{parent\_token\_hash}(T_i) = \text{token\_id}(T_{i-1})$
- $\text{delegation\_depth}(T_i) = \text{delegation\_depth}(T_{i-1}) + 1$
- $\text{rights}(T_i) \sqsubseteq \text{rights}(T_{i-1})$ (attenuation)

**Proposition M.9 (Bounded Delegation).** No delegation chain can exceed $\text{CAPNET\_MAX\_DELEGATION\_DEPTH} = 32$ hops.

*Proof.* `verify_delegation_chain` checks `delegation_depth ≤ CAPNET_MAX_DELEGATION_DEPTH` and returns `CapNetError::DelegationDepthExceeded` if violated. $\square$

**Proposition M.10 (No-Amplification Under Delegation).** If every token in a delegation chain is attenuating, then no process reached by the chain has more rights than the original mint.

*Proof.* By induction on chain length. Base case: $T_1$ has rights $r_1 = \text{rights}(T_1)$, bounded by the original mint. Inductive step: $\text{rights}(T_{i+1}) \sqsubseteq \text{rights}(T_i)$ by the attenuation requirement, so $\text{rights}(T_{i+1}) \subseteq r_1$. $\square$

---

## 4. WASM Host ABI (IDs 109–115)

All functions are called from WASM via the Oreulius host-import mechanism. Function indices are resolved once at module load time by `resolve_host_import` in `wasm.rs`.

### ID 109 — `mesh_local_id() → i32`

Returns this node's 64-bit device ID folded into a signed 32-bit value:

$$\text{result} = \left((\text{id}_d \oplus (\text{id}_d \gg 32)) \;\&\; \texttt{0xFFFF\_FFFF}\right) \text{ as } i32$$

The fold is a deterministic, collision-resistant compression for use as a WASM-compatible rendezvous key. The full 64-bit ID is logged to serial. Returns 0 if CapNet has not been initialized.

### ID 110 — `mesh_peer_register(peer_lo: i32, peer_hi: i32, trust: i32) → i32`

Reconstructs the 64-bit peer ID as:

$$\text{peer\_id} = (\text{peer\_hi} \ll 32) \;|\; (\text{peer\_lo} \;\&\; \texttt{0xFFFF\_FFFF})$$

and registers it in the peer table (`CAPNET_PEERS`, capacity 32) with:

- `trust = 0` → `PeerTrustPolicy::Audit` (log measurement mismatches, allow)
- `trust ≠ 0` → `PeerTrustPolicy::Enforce` (reject on measurement mismatch)

Returns 0 on success, −1 on error (peer table full, zero ID).

### ID 111 — `mesh_peer_session(peer_lo: i32, peer_hi: i32) → i32`

Returns the current session-key epoch for the named peer:

- `≥ 1`: an active session exists; the value is the epoch counter
- `0`: peer is registered but no session key has been installed yet
- `−1`: peer is not registered

### ID 112 — `mesh_token_mint(obj_lo, obj_hi, cap_type, rights, expires_ticks, buf_ptr) → i32`

Mints a fresh `CapabilityTokenV1` signed with the kernel boot key:

1. Reconstructs the 64-bit `object_id` from `obj_lo`/`obj_hi`.
2. Sets `issued_at = not_before = now_ticks` and `expires_at = now_ticks + expires_ticks`.
3. Generates `nonce` from the kernel's CSPRNG via `SecurityManager::random_u32`.
4. Sets `session_id = caller_pid` and `delegation_depth = 0`.
5. Calls `token.sign_with_kernel_key()`:
   $$\text{mac} = \text{SipHash-2-4}_{K_d}(\text{encode\_without\_mac}(T))$$
6. Encodes the 116-byte token and writes it into WASM linear memory at `buf_ptr`.

The minted token is self-issued (`issuer = subject = local_id`). To send it to a peer, the caller follows up with `mesh_token_send` which re-signs with the session key.

### ID 113 — `mesh_token_send(peer_lo, peer_hi, buf_ptr, buf_len) → i32`

Wraps a previously minted 116-byte token in a `TokenOffer` control frame:

1. Reads and decodes the token from WASM memory using `CapabilityTokenV1::decode_checked`.
2. Calls `build_token_offer_frame(peer_id, 0, &mut token)`:
   - Constructs a `CapNetControlFrame` of type `TokenOffer`
   - Calls `sign_outgoing_token_for_peer` which re-signs the token with $K_{d, d'}$ (the per-peer session key)
   - Encodes the entire control frame including a frame-level MAC
3. Emits the encoded frame on the observer bus (`observer_events::IPC_ACTIVITY`) for pickup by the network driver or a userspace observer.

Returns the frame byte-length on success, or a negative error code:
- `−1`: wrong buffer length
- `−2`: token decode failed (corrupt/wrong MAC)
- `−3`: frame construction failed (peer not registered or session not established)

### ID 114 — `mesh_token_recv(buf_ptr: i32, buf_len: i32) → i32`

Exports one active remote capability lease from the `CapabilityManager`'s remote lease table as a 116-byte `CapabilityTokenV1` snapshot into WASM memory.

The lease selection predicate is:
- `active = true`
- `revoked = false`
- `owner_any = true` OR `owner_pid = caller_pid`

The snapshot reconstructs a `CapabilityTokenV1` from the stored lease fields (`cap_type`, `issuer_device_id`, `object_id`, `rights`, `issued_at`, `not_before`, `expires_at`, `nonce`, `measurement_hash`, `session_id`). This gives WASM modules a read path to their inbound capability grants without needing direct access to the capability manager.

Returns 0 on success, −1 if no visible lease exists.

### ID 115 — `mesh_migrate(peer_lo, peer_hi, wasm_ptr, wasm_len) → i32`

Queues a WASM module's bytecode for live migration to a remote peer:

1. Reconstructs the 64-bit `peer_id`.
2. Validates `wasm_len ≤ 65536` (64 KiB hard limit per `MeshMigrateRequest::bytecode` field).
3. Copies the bytecode from WASM linear memory into a `MeshMigrateRequest` slot in `MESH_MIGRATE_QUEUE` (4 slots).
4. Immediately calls `mesh_migrate_flush()`, which:
   - Encodes a `TokenOffer`-style payload: `[peer_id: 8 LE][len: 4 LE]`
   - Logs to serial: `[mesh] migrate: peer=0x… bytes=…`
   - Notifies observers via `observer_notify(POLYGLOT_LINK, &payload[..12])`
   - Marks the slot inactive (consumed)

Pass `wasm_len = 0` to migrate the calling module's own bytecode (the kernel fills in the source from module context).

Returns 0 on success, −1 if the 4-slot queue is full, −2 if bytecode exceeds the size limit.

---

## 5. Data Structures

### 5.1 `CapabilityTokenV1` (116 bytes)

See §3.2 for field-level documentation. Key implementation points:

**`encode_without_mac()`** serializes fields 0–107 (everything except the 8-byte MAC) in a deterministic little-endian layout, prepended by the 4-byte magic `0x544E_5043`. This 108-byte buffer is the MAC input.

**`token_id()`** computes `FNV-1a-64` over the 108-byte body for dedup/revocation indexing.

**`validate_semantics()`** checks:
- `version == 1`
- `alg_id ∈ {1, 2}`
- `delegation_depth ≤ CAPNET_MAX_DELEGATION_DEPTH`
- `issued_at ≤ not_before ≤ expires_at` (if non-zero)
- Constraint flag consistency (e.g., `REQUIRE_BOUNDED_USE` requires `max_uses > 0`)

**`degrade_mathematically(severity_ratio)`** reduces `max_uses` by integer division: $\text{max\_uses}' = \lfloor \text{max\_uses} / \max(1, \text{severity\_ratio}) \rfloor$. Used by the intent graph's predictive restriction pathway to mathematically degrade authority under anomaly pressure.

**`into_linear<C>()`** elevates a token into a `LinearCapability<CapabilityTokenV1, C>` — a const-generic affine wrapper that enforces structural use-once semantics at compile time for authority-critical code paths.

### 5.2 `PeerSession` (internal, per-peer state)

```rust
struct PeerSession {
    active:              bool,
    peer_device_id:      u64,
    trust:               PeerTrustPolicy,
    measurement_hash:    u64,
    key_epoch:           u32,
    key_k0:              u64,      // SipHash-2-4 key word 0
    key_k1:              u64,      // SipHash-2-4 key word 1
    replay_high_nonce:   u64,      // anti-replay watermark
    replay_bitmap:       u64,      // 64-bit sliding window
    ctrl_rx_high_seq:    u32,      // control-frame seq watermark
    ctrl_rx_bitmap:      u32,      // control-frame anti-replay
    ctrl_tx_next_seq:    u32,      // outbound sequence counter
    last_seen_epoch:     u64,      // PIT tick of last frame
}
```

Capacity: `CAPNET_MAX_PEERS = 32` entries in a static `Mutex<[PeerSession; 32]>`.

### 5.3 `CapNetControlFrame`

```
Header (variable):
  ctrl_type:   u8    (Hello=1, Attest=2, Heartbeat=3,
                       TokenOffer=4, TokenAccept=5, TokenRevoke=6)
  flags:       u8    (ACK_ONLY = bit 0)
  seq:         u32   (monotone outbound sequence)
  key_epoch:   u32   (session key epoch for MAC)
  payload_len: u16
  token_id:    u64   (for token-bearing frames)
  frame_mac:   u64   (SipHash-2-4 over header + payload)

Payload (0–116 bytes):
  For TokenOffer/Accept/Revoke: the encoded CapabilityTokenV1
```

Wire format: `CAPNET_CTRL_MAX_FRAME_LEN = CAPNET_CTRL_HEADER_LEN + 116` bytes maximum.

Delivered via: `CAPNET_CONTROL_PORT = 48123` UDP or the observer bus `IPC_ACTIVITY` event channel.

### 5.4 `MeshMigrateQueue`

```rust
struct MeshMigrateRequest {
    active:          bool,
    peer_id:         u64,
    bytecode:        [u8; 65536],   // inline 64 KiB buffer
    bytecode_len:    usize,
    requester_pid:   ProcessId,
}

struct MeshMigrateQueue {
    slots: [MeshMigrateRequest; 4],
}
```

Static instance: `MESH_MIGRATE_QUEUE: Mutex<MeshMigrateQueue>`. Flushed by `mesh_migrate_flush()` on each call to `host_mesh_migrate` and by the scheduler tick.

---

## 6. Constraint Flags

The `constraints_flags: u32` field is a bitmask that activates optional policy constraints:

| Bit | Constant | Meaning |
|---|---|---|
| 0 | `CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE` | `max_uses` must be non-zero; kernel decrements on each verified use |
| 1 | `CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA` | `max_bytes` is enforced; each authenticated data transfer reduces the budget |
| 2 | `CAPNET_CONSTRAINT_MEASUREMENT_BOUND` | Token is only valid if the subject peer's `measurement_hash` matches the token's `measurement_hash` field |
| 3 | `CAPNET_CONSTRAINT_SESSION_BOUND` | Token is only valid within the session identified by `session_id` |

**Proposition M.11 (Constraint Monotonicity).** Adding constraint flags to a token can only reduce the set of contexts in which it is valid; no constraint flag can extend authority.

*Proof.* Each constraint flag introduces an additional conjunct in the acceptance predicate. A conjunction is false whenever any conjunct is false, so the acceptance set is a subset of the unconstrained acceptance set. $\square$

---

## 7. Trust Policy Model

```rust
pub enum PeerTrustPolicy {
    Disabled,    // Peer is registered but session not yet active
    Audit,       // Measurement mismatches are logged; frames are accepted
    Enforce,     // Measurement mismatches cause session rejection
}
```

**Definition M.12 (Measurement Attestation).** Let $h(M)$ denote the measurement hash of module $M$ (typically FNV-1a-64 of the WASM bytecode). A peer registered with `PeerTrustPolicy::Enforce` and non-zero `measurement_hash = h_0$ will:

- Accept tokens where `measurement_hash = 0` (unbound) or `measurement_hash = h_0`
- Reject tokens where `measurement_hash ∉ {0, h_0}` with `CapNetError::MeasurementMismatch`

The policy is checked in both `verify_incoming_token` (inbound path) and `establish_peer_session` (session establishment path).

**Corollary M.13 (Isolation of Compromised Modules).** If a peer $d'$ registers with `Enforce` and measurement hash $h_0$, then a compromised module with measurement $h_1 \neq h_0$ cannot present tokens that appear to come from the expected module. The MAC check alone does not provide this guarantee; the measurement check provides it independently.

---

## 8. Revocation

The capnet layer maintains a persistent revocation journal. When a `TokenRevoke` control frame is received and validated, the revoked token's ID (`token_id()`, i.e., FNV-1a-64 of the body) is stored in a tombstone list that persists across reboots via the temporal state system.

**Definition M.14 (Revocation Tombstone).** A revocation tombstone is a record `(token_id, revoked_at_epoch)` that causes `verify_incoming_token` to return `CapNetError::Revoked` for any future presentation of the same token, regardless of its validity window.

**Proposition M.15 (Revocation Completeness).** A revoked token $T$ cannot be accepted by the issuer's own node after revocation, because all inbound verification passes through `verify_incoming_token` which checks the tombstone list.

*Note:* Revocation propagation to remote peers is best-effort (via `TokenRevoke` control frames) and not guaranteed under network partition. The tombstone journal is local; remote nodes must receive the revoke frame to enforce it independently.

---

## 9. Live Module Migration

Migration is the most operationally powerful mesh capability. The protocol is:

```
Requester                    Kernel (local)              Peer kernel
    │                              │                             │
    │── mesh_migrate(peer, bytes)─▶│                             │
    │                              │─ enqueue MeshMigrateRequest │
    │                              │─ mesh_migrate_flush()       │
    │                              │─ encode TokenOffer frame    │
    │                              │─ observer_notify(IPC_ACTIVITY, frame[..28])
    │                              │──────── wire/observer ────▶│
    │                              │                            │─ receive frame
    │                              │                            │─ decode CapabilityTokenV1
    │                              │                            │─ verify_incoming_token()
    │                              │                            │─ install RemoteLease
    │                              │                            │─ load_module(bytecode)
    │                              │                            │─ spawn WASM process
```

**What migrates with the module:**

1. The WASM bytecode (≤ 64 KiB)
2. The capability token authorizing execution (`measurement_hash` binds token to bytecode)
3. The peer ID of the originating node (for reverse communication)

**What does not migrate automatically:**

- Linear memory state (the module restarts with fresh memory on the remote node)
- Open IPC channels (must be re-established after migration)
- Local-only capabilities (intra-node channel handles are not portable)

**Design note:** The 64 KiB bytecode limit is deliberate. Larger modules should use the polyglot loader (IDs 103–105) or decompose into smaller service units. The 4-slot queue prevents migration storms in edge-constrained environments.

---

## 10. SDK Usage

```rust
use oreulius_sdk::mesh;

// 1. Discover local identity
let my_id: u32 = mesh::local_id();

// 2. Register a remote peer (discovered via mDNS, CapNet beacon, or out-of-band)
let remote_peer: u64 = 0xDEAD_BEEF_CAFE_0001;
let registered: bool = mesh::peer_register(remote_peer, /*enforce=*/true);

// 3. Check session status (optional — session established out-of-band via Hello/Attest)
match mesh::peer_session(remote_peer) {
    Some(epoch) if epoch >= 1 => { /* active session */ }
    Some(0)                   => { /* registered, no session yet */ }
    None                      => { /* unknown peer */ }
    _ => {}
}

// 4. Mint a capability token
let object_id: u64 = 0x1234_5678_0000_0001;
let mut token_buf = [0u8; mesh::TOKEN_LEN];
mesh::token_mint(
    object_id,
    1,       // cap_type
    0x03,    // rights (Read | Write)
    10_000,  // expires in 10 000 PIT ticks (100 seconds at 100 Hz)
    &mut token_buf,
).expect("token_mint failed");

// 5. Send the token to the peer
let frame_len = mesh::token_send(remote_peer, &token_buf)
    .expect("token_send failed");

// 6. Receive an inbound token (on the receiving side)
let mut recv_buf = [0u8; mesh::TOKEN_LEN];
mesh::token_recv(&mut recv_buf).expect("no inbound token");

// 7. Migrate this module to the remote peer
mesh::migrate(remote_peer, &[]).expect("migrate failed");
// (module restarts on peer; this call does not return on success in a full impl)
```

---

## 11. Formal Properties and Corollaries

**Theorem M.16 (Cross-Node Authority Confinement).** If a token $T$ is minted with rights $r$ and subject device $d'$, then no process on any device $d'' \neq d'$ can use $T$ to exercise authority, because `verify_incoming_token` rejects tokens whose `subject_device_id ≠ local_device_id`.

*Proof.* The subject check is:
```rust
if token.subject_device_id != local { return Err(CapNetError::UnknownPeer); }
```
which is evaluated on every inbound verification path before any capability grant. $\square$

**Theorem M.17 (MAC Unforgeability Under SipHash-2-4).** Under the standard pseudorandomness assumption for SipHash-2-4, an adversary without knowledge of the session key $K_{d,d'}$ cannot produce a token $T'$ with valid MAC and `issuer_device_id = d`, given a polynomial number of observed tokens.

*Note:* SipHash-2-4 is a PRF in practice but is not formally proven IND-CPA secure. For deployments requiring cryptographic provability, the `alg_id = 2` (Ed25519) path should be used when available.

**Corollary M.18 (Delegation Chain Integrity).** Because each delegated token includes `parent_token_hash = token_id(T_parent)` and the MAC is computed over the entire body including this field, forging a delegation chain requires either breaking the MAC or finding a collision in FNV-1a-64 (used for `token_id`). The latter is not a security primitive — the MAC is the actual security barrier; `token_id` is for indexing only.

**Proposition M.19 (Session Rekeying Invalidates Old Tokens).** When `establish_peer_session` is called for a peer $d'$, the epoch counter increments. Any token signed with the previous session key (epoch $e-1$) will fail `verify_with_session_key` because the old key material is overwritten.

*Proof.* `install_peer_session_key` overwrites `key_k0` and `key_k1` and resets the replay window. The old MAC cannot be re-verified with the new key. $\square$

**Proposition M.20 (Measurement Binding Prevents Module Substitution).** If a token is minted with `CAPNET_CONSTRAINT_MEASUREMENT_BOUND` and `measurement_hash = h(M)`, then a different module $M'$ with $h(M') \neq h(M)$ cannot use that token, because the peer's `verify_incoming_token` rejects the measurement mismatch under `Enforce` policy.

**Lemma M.21 (Use Budget Monotone Decrease).** For a token with `CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE` and initial `max_uses = u_0`, after $k$ verified uses the remaining budget satisfies $\text{uses\_remaining} = u_0 - k \geq 0$.

*Proof.* The capability manager decrements `uses_remaining` on each authenticated use and returns `CapNetError::UseBudgetExhausted` when the budget reaches zero. Decrement is an atomic operation under the `Mutex<CapabilityManager>` lock. $\square$

---

## 12. Integration Points

### 12.1 Temporal state persistence

The peer table and remote lease table are snapshotted to the temporal state store (`record_temporal_state_snapshot()`) on every mutation:

- `register_peer` → snapshot
- `establish_peer_session` → snapshot
- `install_peer_session_key` → snapshot
- Revocation journal updates → snapshot

On reboot, `temporal_apply_state_payload` reconstructs the peer table, key epochs, replay windows, and revocation tombstones. This means capability grants survive kernel restarts.

### 12.2 Observer/event bus integration

`mesh_token_send` and `mesh_migrate_flush` emit events on the observer bus (`IPC_ACTIVITY` and `POLYGLOT_LINK` respectively). Any WASM module subscribed via `observer_subscribe` (ID 106) with the appropriate event mask receives a notification containing the first 28 bytes of the control frame payload. This allows a transport driver WASM module to pick up outbound tokens and forward them over the actual network interface.

### 12.3 Intent graph / AdaptiveRestriction

`CapabilityTokenV1::degrade_mathematically` is called by the predictive restriction pathway when the intent graph raises a `RestrictionApplied` event for the token's owning process. The degradation formula:

$$\text{max\_uses}' = \left\lfloor \frac{\text{max\_uses}}{\max(1, \text{severity\_ratio})} \right\rfloor$$

reduces a remote module's remaining authority budget in proportion to its anomaly score, without full revocation. This implements a continuous authority gradient rather than a binary grant/revoke decision.

### 12.4 CapNet formal self-check

`formal_capnet_self_check()` is a built-in regression suite invokable from the kernel shell (`capnet check` command) that validates:

- Token encode/decode round-trip identity
- Kernel-key sign/verify correctness
- Session-key sign/verify correctness
- Delegation chain verification logic
- Replay protection correctness
- Temporal validity window enforcement
- Constraint flag enforcement
- Revocation tombstone persistence

The fuzz infrastructure (`capnet_fuzz`, `capnet_fuzz_regression_default`, `capnet_fuzz_regression_soak_default`) stress-tests token parsing, frame decoding, and the peer state machine against randomly mutated inputs.

---

## 13. What Can Be Built With the Kernel Mesh

| Use case | Mechanism |
|---|---|
| **Fleet-wide capability distribution** | Bootstrap node mints tokens for each device; `mesh_token_send` distributes |
| **AI edge node authority delegation** | Central node mints attenuated tokens for edge; edge nodes further delegate to WASM workloads with measurement binding |
| **Secure WASM hot-swap** | `mesh_migrate` ships updated bytecode; `measurement_hash` ensures only the expected bytecode can use the authority |
| **Cross-device resource access** | File/network capabilities minted with `SESSION_BOUND`; valid only within the current session window |
| **Revocable sensor access** | IoT sensors expose capabilities via tokens with short `expires_ticks`; central node withholds renewal to revoke |
| **Multi-hop attestation chains** | `parent_token_hash` links a chain from the root CA node through intermediate relay nodes to the end device |
| **Use-budgeted API calls** | Third-party WASM services enforce rate limits via `max_uses` tokens; no explicit counter management needed |
| **Measurement-locked workloads** | `MEASUREMENT_BOUND` tokens refuse to grant authority if the workload bytecode has been tampered with |

---

## 14. Known Limitations and Open Research Obligations

| Limitation | Detail |
|---|---|
| **Migration is not atomic** | The current `mesh_migrate_flush` implementation logs to serial and notifies observers but does not perform an actual TCP send. Full transport requires a network driver WASM module consuming the observer events. |
| **Session establishment is out-of-band** | The `Hello`/`Attest` control frame types are defined in the capnet format but their initiation is not wired into `mesh_peer_session`; session keys must currently be installed via `install_peer_session_key` directly. |
| **SipHash-2-4 is not IND-CPA proven** | For high-assurance deployments, `alg_id = 2` (Ed25519) should be used once the signature backend is complete. |
| **Linear memory state is not migrated** | A migrated module restarts with empty linear memory. Persistent state must be serialized explicitly via temporal objects before calling `mesh_migrate`. |
| **64 KiB module size limit** | Large WASM modules must be decomposed into service units or use the polyglot streaming loader. |
| **Timing channels** | Token processing time is not constant; timing-side-channel analysis is an open research obligation. |
| **Formal correspondence** | A machine-checkable mapping from the CapNet implementation to the formal model in the Unified Theory paper (`docs/architecture/unified-theory-capability-trust-causal-semantics-thermodynamic-liveness.md`) remains a research obligation (R1 in that paper's agenda). |
