# Oreulius Intensional Kernel: Policy-as-Contracts

> **Status:** Fully implemented. WASM host ABI IDs 121–124. Core: `kernel/src/execution/wasm.rs` (`POLICY_STORE`, `run_policy_contract`). OPOL stub format fully deterministic. Full WASM policy contracts run in a strict fail-closed sandbox and must export `policy_check(ctx_ptr, ctx_len) -> i32` without importing host functions. SDK: `wasm/sdk/src/policy.rs`.

---

## 1. Overview

A standard capability system is *extensional*: a capability either exists (you have it) or does not (you don't). There is no mechanism to express *conditions under which* a capability may be exercised. If a file-read capability exists in a process's capability table, the process can use it unconditionally.

Oreulius's Intensional Kernel extends capability semantics with **policy contracts** — small bytecode programs bound to specific capabilities that the kernel evaluates on every capability access. A capability can now be *conditionally valid*:

- A capability may be exercisable only when a specific context byte matches a required value.
- A capability may be restricted to certain time windows (via context bytes encoding the current clock region).
- A capability may require the process to present proof of recent authentication before exercising filesystem access.

The term "intensional" comes from logic: an *intension* is a rule or predicate that defines when something holds, as opposed to an *extension* (a set of items for which it holds). Policy contracts make capability authority a *predicate* rather than a *possession*.

### Key design decisions

| Decision | Rationale |
|---|---|
| **Bytecode stored in kernel** | Policy stays with the capability, not with the process. A delegated capability carries its policy to the delegatee. |
| **4 KiB bytecode limit** | Large enough for real policy logic; small enough to keep per-capability overhead bounded. |
| **Deny when no policy** | A capability without a bound policy is denied until an explicit policy is bound. |
| **OPOL stub for simple policies** | A deterministic, 8-byte stub format evaluates without a WASM engine for the common case (default-permit, context-byte check). |
| **Hash for integrity** | A multiplicative hash of the bytecode is stored alongside it. Changes to the policy after binding are detectable. |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  WASM Module                                                         │
│  policy::bind(cap_id, &bytecode)                                    │
│  policy::eval(cap_id, &context)   → PolicyResult                    │
│  policy::query(cap_id) / status(cap_id) → Option<PolicyInfo>        │
└─────────────────────────────┬────────────────────────────────────────┘
                              │  WASM host ABI (IDs 121–124)
┌─────────────────────────────▼────────────────────────────────────────┐
│  Policy Host Functions  (kernel/src/execution/wasm.rs)              │
│  host_policy_bind / policy_unbind / policy_eval / policy_query      │
└──────────┬──────────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────────┐
│  POLICY_STORE: Mutex<PolicyStore>                                   │
│  16 × PolicySlot { pid, cap_id, wasm_hash, wasm_len, bytecode[4096]}│
└──────────┬──────────────────────────────────────────────────────────┘
           │  run_policy_contract(bytecode, ctx)
    ┌──────┴────────────────────────────────────────────────────────┐
    │  Mode 2: OPOL stub (magic b'O','P','O','L' at bytes 0-3)     │
    │  Fully deterministic; no WASM engine required                │
    │                                                               │
    │  Mode 1: Full WASM policy sandbox (self-contained export)  │
    └───────────────────────────────────────────────────────────────┘

Hot path integration:
  CapabilityManager::access_capability() → policy_check_for_cap(pid, cap_id, ctx)
```

### Subsystem files

| File | Role |
|---|---|
| `kernel/src/execution/wasm.rs` | `PolicySlot`, `PolicyStore`, `POLICY_STORE`, host functions 121–124, `run_policy_contract`, `policy_check_for_cap` |
| `wasm/sdk/src/policy.rs` | SDK: `bind`, `unbind`, `eval`, `query`, `opol_stub`, `PolicyGuard`, `PolicyResult` |

---

## 3. Formal Model

### 3.1 Policy semantics

**Definition I.1 (Policy Contract).** A policy contract for capability $c$ in process $p$ is a partial function:

$$\text{policy}(c, p) : \text{Context} \to \{\text{Permit}, \text{Deny}\}$$

where $\text{Context}$ is a byte slice of at most 256 bytes provided by the caller at evaluation time.

**Definition I.2 (Closed Semantics).** When no policy is bound to $(p, c)$, the policy function is treated as the constant function $\lambda\_.\, \text{Deny}$. This preserves enforcement safety and requires an explicit binding before access is granted.

**Definition I.3 (Policy Binding).** A binding is a tuple $(p, c, \text{bytecode}, h)$ where $h$ is the multiplicative hash of `bytecode`.

**Invariant I.4 (Single Binding Per (pid, cap)).** At most one binding exists for any $(p, c)$ pair in `POLICY_STORE`. A re-bind replaces the existing entry.

*Proof.* `host_policy_bind` searches `POLICY_STORE` for an existing entry with matching `(pid, cap_id)` before inserting. If found, it overwrites it in-place. $\square$

### 3.2 OPOL stub semantics

**Definition I.5 (OPOL Stub).** An OPOL stub is an 8-byte bytecode sequence with magic header `b'O','P','O','L'` (bytes 0–3), interpreted as:

| Byte | Field | Meaning |
|---|---|---|
| 4 | `default_permit` | Return value when context is shorter than `min_ctx_len` |
| 5 | `min_ctx_len` | Minimum context length to trigger byte check |
| 6 | `ctx_byte0_eq` | If `1`, compare `ctx[0]` against `ctx_byte0_val` |
| 7 | `ctx_byte0_val` | Required value of `ctx[0]` |

**Definition I.6 (OPOL Evaluation Rule).**

$$\text{eval\_opol}(\text{stub}, \text{ctx}) = \begin{cases} \text{default\_permit} & \text{if } |\text{ctx}| < \text{min\_ctx\_len} \\ \text{ctx}[0] = \text{ctx\_byte0\_val} & \text{if ctx\_byte0\_eq} = 1 \\ \text{Permit} & \text{otherwise} \end{cases}$$

**Proposition I.7 (OPOL Determinism).** For any fixed OPOL stub and context, `run_policy_contract` returns the same result regardless of system state, time, or concurrent operations.

*Proof.* The OPOL branch in `run_policy_contract` performs only byte comparisons on its arguments. It reads no global mutable state. $\square$

### 3.3 Hash integrity

**Definition I.8 (Multiplicative Hash).** The policy bytecode hash is computed as:

$$h_0 = 0, \quad h_{i+1} = h_i \cdot \texttt{0x9E3779B97F4A7C15} + b_i \pmod{2^{64}}$$

where $b_i$ is the $i$-th byte of the bytecode. This is the Knuth multiplicative hash over $\text{GF}(2^{64})$.

**Definition I.9 (Status Query).** A caller can inspect the stored policy metadata via `policy::query(cap_id)` or its `status(cap_id)` alias and compare the returned hash against a freshly computed hash of the expected bytecode to verify the bound policy has not been replaced.

**Proposition I.10 (Collision Resistance — Informal).** The Knuth multiplicative hash provides practical pre-image resistance for policy verification purposes. It is not cryptographically secure but is sufficient for detecting accidental or unsophisticated policy substitution. For adversarial settings, bind a SHA-256 OPOL stub as a wrapper policy.

---

## 4. Data Structures

### 4.1 `PolicySlot`

```rust
const MAX_POLICY_SLOTS:   usize = 16;
const MAX_POLICY_WASM_LEN: usize = 4096;  // 4 KiB per policy

struct PolicySlot {
    active:    bool,
    pid:       u32,
    cap_id:    u32,
    wasm_hash: u64,           // multiplicative hash of bytecode
    wasm_len:  u16,
    bytecode:  [u8; 4096],
}

static POLICY_STORE: Mutex<PolicyStore>  // 16 × PolicySlot
```

Total static kernel allocation: $16 \times 4112 \approx 64\text{ KiB}$.

### 4.2 `run_policy_contract`

```rust
fn run_policy_contract(bytecode: &[u8], ctx: &[u8]) -> bool {
    // Mode 2: OPOL stub
    if bytecode.len() >= 8 && &bytecode[0..4] == b"OPOL" {
        let default_permit = bytecode[4] != 0;
        let min_ctx_len    = bytecode[5] as usize;
        let ctx_byte0_eq   = bytecode[6] != 0;
        let ctx_byte0_val  = bytecode[7];
        if ctx.len() < min_ctx_len {
            return default_permit;
        }
        if ctx_byte0_eq {
            return ctx[0] == ctx_byte0_val;
        }
        return true;
    }
    // Mode 1: full WASM policy sandbox — self-contained policy_check export
    // required; any parse, validation, instantiation, or execution failure
    // fails closed.
    false
}
```

### 4.3 `policy_check_for_cap` (hot path)

```rust
pub fn policy_check_for_cap(pid: u32, cap_id: u32, ctx: &[u8]) -> bool {
    // Snapshot bytecode under lock; evaluate outside lock
    let policy = POLICY_STORE.lock().find(pid, cap_id).map(|s| s.snapshot());
    match policy {
        None    => false,  // no policy bound → deny
        Some(b) => run_policy_contract(&b, ctx),
    }
}
```

Called from the capability access hot path in `CapabilityManager`. Context bytes are assembled by the caller and can encode any combination of: capability type, operation, requesting PID, current tick, or application-defined tokens.

---

## 5. WASM Host ABI (IDs 121–124)

### ID 121 — `policy_bind(cap_id: i32, wasm_ptr: i32, wasm_len: i32) → i32`

Binds a policy contract to `cap_id` for the calling process:

1. Verifies `cap_id` exists in the calling process's capability table. Returns `−1` if not found.
2. Reads `wasm_len` bytes from WASM memory at `wasm_ptr`. Returns `−2` if `wasm_len > 4096`.
3. Computes the multiplicative hash of the bytecode.
4. Searches `POLICY_STORE` for an existing binding on `(pid, cap_id)`. If found, replaces it (Invariant I.4).
5. If no existing binding, finds a free slot. Returns `−3` if `POLICY_STORE` is full (16 entries).
6. Stores `PolicySlot { active: true, pid, cap_id, wasm_hash, wasm_len, bytecode }`.
7. Returns `0`.

### ID 122 — `policy_unbind(cap_id: i32) → i32`

Removes the policy binding for `cap_id`:

1. Searches `POLICY_STORE` for an active entry with `(pid, cap_id)`.
2. Sets `entry.active = false`.
3. Returns `0` on success, `−1` if no binding was found.

After unbinding, subsequent capability accesses on `cap_id` deny until a new policy is bound (Invariant I.2).

### ID 123 — `policy_eval(cap_id: i32, ctx_ptr: i32, ctx_len: i32) → i32`

Evaluates the bound policy for `cap_id` against the provided context:

1. Reads `min(ctx_len, 256)` bytes from WASM memory at `ctx_ptr`.
2. Snapshots the policy bytecode under the `POLICY_STORE` lock.
3. Calls `run_policy_contract(bytecode, ctx)` outside the lock.
4. Returns `0` (Permit) or `1` (Deny). Unbound or unsupported policies deny by default.

This host function allows WASM modules to explicitly evaluate their own policies before invoking an operation, enabling proactive denial before the kernel hot path rejects the access.

### ID 124 — `policy_query(cap_id: i32, buf_ptr: i32, buf_len: i32) → i32`

Writes 16 bytes of policy metadata to WASM memory:

```
bytes  0– 7:  wasm_hash (u64 LE)
bytes  8– 9:  wasm_len  (u16 LE)
byte  10:     bound     (1 = active policy, 0 = no policy)
byte  11:     reserved  (0)
bytes 12–15:  cap_id    (u32 LE)
```

Returns `0` if a policy is bound, `−1` if no policy is bound for `cap_id`, `−2` if `buf_len < 16`.

---

## 6. OPOL Stub Constructor

The SDK provides a `const fn` for building OPOL stubs at compile time:

```rust
pub const fn opol_stub(
    default_permit: bool,
    min_ctx_len:    u8,
    check_byte0:    bool,
    byte0_val:      u8,
) -> [u8; 8] {
    [
        b'O', b'P', b'O', b'L',
        default_permit as u8,
        min_ctx_len,
        check_byte0 as u8,
        byte0_val,
    ]
}
```

This means the common case policy — "permit by default, but deny unless context byte 0 equals token `T`" — is a single `const` array instantiated at compile time, with zero runtime allocation.

---

## 7. SDK Usage

```rust
use oreulius_sdk::policy::{self, PolicyResult, PolicyGuard};

// ── Simple unconditional policy (default permit) ────────────────────────────
const ALWAYS_PERMIT: [u8; 8] = policy::opol_stub(true, 0, false, 0);
policy::bind(my_cap_id, &ALWAYS_PERMIT).expect("bind failed");

// ── Context-gated policy: require ctx[0] == 0x42 ───────────────────────────
const TOKEN_POLICY: [u8; 8] = policy::opol_stub(false, 1, true, 0x42);
policy::bind(my_cap_id, &TOKEN_POLICY).expect("bind failed");

// Probe the policy with a valid context
let ctx = [0x42u8];
match policy::eval(my_cap_id, &ctx) {
    PolicyResult::Permit => { /* proceed */ }
    PolicyResult::Deny   => { /* denied */ }
}

// ── Query bound policy metadata ─────────────────────────────────────────────
if let Some(info) = policy::status(my_cap_id) {
    let hash = info.hash;
    let len  = info.wasm_len;
    let bound = info.bound;
}

// ── Unbind ──────────────────────────────────────────────────────────────────
policy::unbind(my_cap_id).ok();

// ── RAII PolicyGuard (auto-unbind on drop) ──────────────────────────────────
{
    let _guard = PolicyGuard::bind(my_cap_id, &TOKEN_POLICY)
        .expect("bind failed");
    // ... use the capability with policy active ...
    // auto-unbind when _guard drops
}

// ── SDK types ───────────────────────────────────────────────────────────────
pub enum PolicyResult { Permit, Deny }
pub struct PolicyInfo { pub hash: u64, pub wasm_len: u16, pub bound: bool, pub cap_id: u32 }
pub struct PolicyGuard { cap_id: u32 }
impl PolicyGuard {
    pub fn bind(cap_id: u32, bytecode: &[u8]) -> Result<Self, i32>
}
impl Drop for PolicyGuard {
    fn drop(&mut self) { let _ = policy::unbind(self.cap_id); }
}
```

---

## 8. Use Cases

### 8.1 Time-window access control

Bind a policy to a FS_WRITE capability that only permits access during business hours. Context bytes encode the current hour (0–23). The OPOL stub checks `ctx[0] >= 8 && ctx[0] < 18`. Since OPOL is single-byte, the hour must be represented as a single byte; two-range checks require a short WASM program (full WASM engine, deny until integrated).

### 8.2 Authentication token verification

A service that grants a high-privilege capability binds an OPOL stub requiring `ctx[0] == auth_token`. The caller must present the token byte on every access. Token rotation involves rebinding with a new `byte0_val`.

### 8.3 Audit-only mode

Bind a policy that always returns `Permit` (`opol_stub(true, 0, false, 0)`) but with a different hash from the default. `policy_query` can then confirm the policy is in place — useful for validating that a policy was not accidentally stripped.

### 8.4 Progressive capability narrowing

As a module moves through processing phases, rebind its capability with an increasingly restrictive policy:
- Phase 1: default permit
- Phase 2: require `ctx[0] == PHASE_TWO_TOKEN`
- Phase 3: policy binds to a full WASM program that validates a cryptographic commitment

---

## 9. Hot Path Integration

`policy_check_for_cap(pid, cap_id, ctx)` is called from `CapabilityManager::access_capability`. The call overhead is:
- Lock `POLICY_STORE` (spinlock)
- Linear scan of 16 slots for `(pid, cap_id)` match
- If found: copy 4096 bytes for snapshot, unlock, call `run_policy_contract`
- If not found (common case): unlock immediately, return `false`

For the common no-policy case, this is a lock-acquire + linear scan of 16 u32 pairs + lock-release. For the OPOL case, it additionally copies 8 bytes (the stub is short so the 4096-byte buffer copy is wasteful; a future optimization is a separate fast path for stubs ≤ 8 bytes).

---

## 10. Known Limitations

| Limitation | Detail |
|---|---|
| **Full WASM policy sandbox** | Mode 1 (arbitrary WASM bytecode) executes only self-contained policies that export `policy_check(ctx_ptr, ctx_len) -> i32`; any parse/validation/runtime failure denies. |
| **4 KiB bytecode cap** | `MAX_POLICY_WASM_LEN = 4096`. Complex policies requiring more bytecode cannot be bound. |
| **16-slot limit** | `MAX_POLICY_SLOTS = 16`. A process with more than 16 simultaneously active capability policies exhausts the store. |
| **No policy delegation** | When a capability is delegated (transferred to another process), the policy binding is **not** automatically copied. The delegatee receives a capability with no policy and is denied until a policy is explicitly bound. |
| **Hash is not cryptographic** | The Knuth multiplicative hash can be preimage-attacked with moderate effort. It detects accidental replacement, not adversarial replacement. |
| **256-byte context cap** | `policy_eval` reads at most 256 context bytes. Policies requiring longer context must use a hash or commitment of the full context in the first 256 bytes. |
| **OPOL single-byte comparison** | The OPOL stub supports exactly one context byte comparison. More complex logic (range checks, multi-byte comparisons) requires full WASM mode (deny until integrated). |
