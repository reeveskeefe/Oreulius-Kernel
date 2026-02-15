# Oreulia Intent Graph with Predictive Revocation

**Status:** Implemented (kernel-integrated)  
**Primary implementation:** `kernel/src/intent_graph.rs`, `kernel/src/intent_wasm.rs`, `kernel/src/security.rs`, `kernel/src/capability.rs`, `kernel/src/ipc.rs`, `kernel/src/syscall.rs`, `kernel/src/commands.rs`

## 1. Abstract

Oreulia augments capability authorization with an online behavioral model called the **Intent Graph**. Instead of evaluating authority as a purely static predicate, the kernel computes per-process risk from event transitions and applies staged control:

1. predictive deny,
2. temporary capability quarantine with timed restore,
3. process-wide capability isolation under repeated abuse signatures,
4. termination recommendation consumed at syscall boundary.

The system is deliberately bounded and deterministic: fixed-size per-process state, fixed feature dimensionality, runtime-policy-controlled thresholds/durations, bounded scans, and lock-ordered mutation paths.

## 2. Scope and Design Goals

### 2.1 Goals

- Detect abuse drift before explicit capability policy violation dominates.
- Preserve capability-model rigor: no authority creation as a side effect of prediction.
- Keep policy path analyzable for kernel use (bounded CPU/memory, deterministic logic).
- Provide operator observability and controlled recovery (`security-intent*` commands).

### 2.2 Non-goals

- Full probabilistic/online ML training in kernel.
- Perfect anomaly detection accuracy.
- Cross-device remote-lease quarantine parity (current behavior revokes remote leases).

## 3. Threat Model

### 3.1 In-scope adversary

- Holds some valid capabilities and attempts privilege broadening through mixed valid/invalid sequences.
- Performs high-rate syscall/IPC activity to hide probing.
- Triggers object-access churn to discover new authority surfaces.

### 3.2 Out-of-scope adversary

- Prior full kernel compromise.
- Hardware backdoor / physical tampering.
- Microarchitectural attacks beyond this policy boundary.

## 4. Formal System Model

### 4.1 Symbols and Notation

| Symbol | Meaning |
|---|---|
| `p` | Process identifier |
| `t` | Logical time (ticks) |
| `H` | PIT frequency (`ticks/s`) |
| `S_p(t)` | Intent state for process `p` at time `t` |
| `e_t` | Intent event observed at `t` |
| `score_t` | Risk score after model and rule augmentation |
| `D_t` | Policy decision in `{Allow, Alert, Restrict}` |
| `R_p(t)` | Restriction state `(type_mask, rights_mask, until_tick)` |
| `Q_p(t)` | Quarantine set for process `p` |

### 4.2 Event Alphabet

Let:

```
N = {
  CapabilityProbe, CapabilityDenied, InvalidCapability,
  IpcSend, IpcRecv, WasmCall, FsRead, FsWrite, Syscall
}
```

Each event is:

```
e_t = (node_t, cap_type_t, rights_mask_t, object_hint_t)
```

### 4.3 Kernel Baseline Defaults

| Constant | Value | Source role |
|---|---:|---|
| `policy.window_seconds` | `8` | Sliding event window |
| `policy.alert_score` | `84` | Alert threshold |
| `policy.restrict_score` | `136` | Restrict threshold |
| `policy.isolate_restrictions` | `3` | Escalate to isolation |
| `policy.terminate_restrictions` | `6` | Emit termination recommendation |
| `policy.restrict_base_seconds` | `2` | Base restriction duration |
| `policy.restrict_max_seconds` | `12` | Max restriction duration |
| `policy.isolate_extension_seconds` | `20` | Isolation extension duration |
| `policy.alert_cooldown_ms` | `1000` | Alert emission throttle |
| `policy.restrict_cooldown_ms` | `500` | Restrict emission throttle |
| `INTENT_MODEL_FEATURES` | `10` | Feature vector length |
| `MAX_INTENT_PROCESSES` | `64` | Tracked processes |
| Bloom bits | `256` | Object novelty approximation |
| `MAX_QUARANTINED_CAPS` | `256` | Quarantine capacity |

Values above are defaults; runtime operators can tune them online via `security-intent-policy set ...`.

## 5. State Structure and Boundedness

### 5.1 Process-local state components

| Component | Type / bound | Semantics |
|---|---|---|
| Node counts | `9 x u16` | Per-node frequency in current window |
| Transition counts | `81 x u16` | Directed transition matrix over `N x N` |
| Event counters | bounded `u16` | denied/invalid/ipc/wasm/syscall/fs read/fs write/novel |
| Bloom filter | `4 x u64` | Approximate object novelty |
| Score stats | `u32` | `last_score`, `max_score` |
| Policy stats | `u32` | alerts/restrictions/isolations/termination rec totals |
| Restriction state | `u16 + u32 + u64` | type mask, rights mask, expiry tick |
| Escalation flags | bounded | window restriction count + terminate recommendation flag |

### 5.2 Window roll rule

Let `epoch(t) = floor(t / H)`.

Let `W = policy.window_seconds`.

Window reset condition:

```
if epoch(t) - epoch(window_start) >= W then clear_window()
```

`clear_window()` resets counters/transition matrix/novelty bloom and escalation window counter.

## 6. Feature Extraction

The model input is:

```
x_t = [x0,...,x9],  x_i in [0,255]
```

| Feature | Definition |
|---|---|
| `x0` | `window_events` |
| `x1` | `denied_events` |
| `x2` | `invalid_events` |
| `x3` | `ipc_events` |
| `x4` | `wasm_events` |
| `x5` | `2*fs_write + floor(fs_read/2)` |
| `x6` | `transition_novelty + min(transition_count,16) + 8*object_novelty` |
| `x7` | `popcount(rights_mask_t)` (capped at `31`) |
| `x8` | `syscall_events` |
| `x9` | `object_novel_events` |

All features are clamped to `[0,255]` before model evaluation.

### 6.1 Transition novelty term

For transition from node `i` to node `j`, let `C_ij` be the updated transition count:

```
transition_novelty = 24 * I[C_ij == 1]
```

### 6.2 Object novelty term

`object_novelty` is `1` only when a newly hashed bloom bit is first set during this window, otherwise `0`.

## 7. Object Novelty Bloom Estimator

### 7.1 Hash projection

```
h0 = object_hint
   xor (node << 56)
   xor (cap_type << 48)
   xor rotl64(rights_mask, 13)
h1 = mix64(h0)
bit_idx = h1 mod 256
```

### 7.2 False-positive behavior

For a one-hash bloom filter with `m=256` bits and `n` inserted unique projections in-window:

```
p_fp(n) = 1 - (1 - 1/m)^n  ≈ 1 - exp(-n/m)
```

This approximation bounds novelty undercount as window occupancy increases.

## 8. Inference Engine (WASM-style VM)

The model is executed by a tiny deterministic VM over bytecode equivalent to a linear form:

```
raw_t = w . x_t
w = [1, 6, 8, 2, 3, 5, 3, 4, 2, 5]
```

Post-transform:

```
centered_t = max(raw_t - 48, 0)
model_t = min(3 * centered_t, 255)
```

Fallback evaluation uses the same `w` to maintain equivalence if bytecode eval fails.

## 9. Rule-Based Score Augmentation

Indicator function `I[condition]` is `1` when true, else `0`.

```
boost_t =
  24 * I[denied>0 and invalid>0]
+ 10 * I[window_events>40]
+ 12 * I[fs_write > 2*fs_read and fs_write>3]
+ 10 * I[novel_object_events>24]
+ 14 * I[window_events>16 and novel_object_events > floor(window_events/2)]
```

Final score:

```
score_t = min(model_t + boost_t, 255)
```

### 9.1 Boost table

| Rule | Increment |
|---|---:|
| Mixed denied+invalid | 24 |
| High-volume window | 10 |
| Write-dominant pressure | 12 |
| Novelty burst | 10 |
| Novelty dominance | 14 |

## 10. Decision Policy and Timing

### 10.1 Threshold semantics

Let `A = policy.alert_score`, `R = policy.restrict_score`.

| Score range | Decision |
|---|---|
| `score < A` | `Allow` |
| `A <= score < R` | `Alert(score)` (rate-limited) |
| `score >= R` | `Restrict(score)` (rate-limited + state mutation) |

### 10.2 Emission throttling

Let `C_a = policy.alert_cooldown_ms`, `C_r = policy.restrict_cooldown_ms`.

| Emission | Min gap |
|---|---|
| Alert | `ceil(C_a * H / 1000)` ticks |
| Restrict | `ceil(C_r * H / 1000)` ticks |

## 11. Restriction Semantics

On a restrict decision:

```
restricted_cap_types |= cap_type_bit(cap_type_t)
restricted_rights |= rights_mask_t (or u32::MAX when rights_mask_t=0)
```

Duration extension:

```
severity = floor((score_t - R)/policy.severity_step_score)
duration_sec = min(policy.restrict_base_seconds + severity, policy.restrict_max_seconds)
restriction_until = max(restriction_until, t + duration_sec * H)
```

Kernel process (`PID=0`) is never restricted.

## 12. Escalation Ladder

### 12.1 Escalation table

| Trigger | Action |
|---|---|
| `window_restrictions >= policy.isolate_restrictions` | Full capability isolation (`types=all`, `rights=u32::MAX`, min extension `policy.isolate_extension_seconds * H`) |
| `window_restrictions >= policy.terminate_restrictions` | `terminate_recommended = true` |

### 12.2 Isolation equation

```
if window_restrictions >= policy.isolate_restrictions:
  restricted_cap_types = ALL_RESTRICTABLE_TYPES
  restricted_rights = 0xFFFF_FFFF
  restriction_until = max(restriction_until, t + policy.isolate_extension_seconds*H)
```

### 12.3 Termination recommendation semantics

- recommendation flag is raised once per recommendation cycle,
- consumed by syscall boundary logic (`take_*` semantics),
- can be cleared by operator recovery command.

## 13. Capability Quarantine Automaton

### 13.1 Local capability transition system

| Event | Transition |
|---|---|
| Restricted access on matching cap | `ActiveCap -> QuarantinedCap(restore_at)` |
| Capability check after `t >= restore_at` | `QuarantinedCap -> ActiveCap` (slot available) |
| Operator forced clear | `QuarantinedCap -> ActiveCap` (ignores timer) |
| Process teardown | `QuarantinedCap -> dropped` |

### 13.2 Restore time lower bound

If requested restore time is too early, kernel enforces:

```
restore_at >= t_now + H
```

This avoids immediate oscillation in same tick region.

### 13.3 Remote lease behavior

Remote leases are revoked, not quarantined, under predictive revoke path. This is conservative and intentionally asymmetric.

## 14. Kernel Enforcement Surface

### 14.1 Path-to-action table

| Path | Intent action | Policy effect |
|---|---|---|
| `check_capability` | probe + deny/invalid signals | restriction gate + quarantine/lease revoke |
| IPC send/recv | ipc send/recv + deny/invalid | defense-in-depth restriction enforcement |
| Syscall ingress | syscall signal + audit | early policy block |
| Syscall egress | termination recommendation consume | process terminate/remove |
| FS syscalls | fs read/write signals | workload-aware pressure signal |

### 14.2 Control commands

| Command | Function |
|---|---|
| `security-stats` | Global intent/anomaly summary |
| `security-intent [pid]` | Per-process deep snapshot |
| `security-intent-clear <pid>` | Clear restriction + clear termination recommendation + force restore quarantine |
| `security-intent-policy [show\|set\|reset]` | Live policy introspection/tuning for thresholds, cooldowns, and restriction durations |

### 14.3 Runtime policy tuning interface

Command grammar:

```
security-intent-policy show
security-intent-policy reset
security-intent-policy set <field> <value> [field value ...]
```

`set` is batch-applied: the kernel starts from current policy, applies all provided field/value pairs, validates the resulting policy, then commits atomically or rejects entirely.

#### Tunable fields and aliases

| Canonical field | Accepted aliases |
|---|---|
| `window_seconds` | `window`, `window_s`, `window_sec` |
| `alert_score` | `alert` |
| `restrict_score` | `restrict` |
| `isolate_restrictions` | `isolate` |
| `terminate_restrictions` | `terminate` |
| `restrict_base_seconds` | `restrict_base_s` |
| `restrict_max_seconds` | `restrict_max_s` |
| `isolate_extension_seconds` | `isolate_extension_s`, `isolate_seconds` |
| `severity_step_score` | `severity_step` |
| `alert_cooldown_ms` | (canonical only) |
| `restrict_cooldown_ms` | (canonical only) |

#### Validation constraints (reject-on-fail)

| Constraint | Condition |
|---|---|
| Window bound | `1 <= window_seconds <= 3600` |
| Score domain | `0 <= alert_score <= 255`, `0 <= restrict_score <= 255` |
| Threshold order | `restrict_score >= alert_score` |
| Escalation order | `isolate_restrictions >= 1`, `terminate_restrictions >= isolate_restrictions` |
| Duration bounds | `restrict_base_seconds >= 1`, `restrict_max_seconds >= restrict_base_seconds`, `isolate_extension_seconds >= restrict_base_seconds` |
| Severity step bound | `severity_step_score >= 1` |
| Cooldown bounds | `alert_cooldown_ms >= 1`, `restrict_cooldown_ms >= 1` |

#### Runtime effect semantics

- Existing per-process restriction expiries are not retroactively rewritten.
- New decisions (`Alert`/`Restrict`, escalation checks, cooldown gating) use updated policy immediately after commit.
- Window logic re-evaluates against the new `window_seconds` on subsequent signal ingestion.

## 15. Formal Properties: Lemmas and Corollaries

### Lemma 1 (Score boundedness)

For all `t`, `score_t in [0,255]`.

**Proof sketch.**  
`model_t` is clamped to `[0,255]`; `boost_t >= 0`; final score is clamped by `min(...,255)`.

### Corollary 1.1

No integer overflow in downstream threshold comparisons can increase policy permissiveness, since comparisons operate on bounded score domain.

### Lemma 2 (Restriction monotonicity between resets)

Between reset/clear events, `restricted_cap_types` and `restricted_rights` evolve monotonically under bitwise OR.

**Proof sketch.**  
Only OR writes occur on restrict path. Decreases occur only via explicit reset operations (expiry, manual clear, process deinit).

### Corollary 2.1 (Isolation dominance)

Once isolation trigger is reached in a window, process-local restriction state dominates any previously narrower right mask in that window epoch.

### Lemma 3 (No-rights amplification under quarantine restore)

Restoring a quarantined local capability cannot add rights beyond the originally quarantined capability.

**Proof sketch.**  
Restore payload is exact stored capability object; no transform path widens rights.

### Corollary 3.1

The local quarantine cycle preserves authority at most (minus remote lease revocations), never increases it.

### Lemma 4 (Slot overwrite safety)

Auto/forced restore does not overwrite occupied capability slots.

**Proof sketch.**  
Restore path checks slot occupancy and skips occupied slots.

### Corollary 4.1

Quarantine restoration cannot destroy unrelated live capabilities.

### Lemma 5 (Kernel non-restriction)

Process `PID=0` is never restricted by intent policy.

**Proof sketch.**  
Restriction predicate and record path include early kernel exclusions.

### Corollary 5.1

Intent policy cannot self-deprive kernel authority needed for recovery logic.

### Lemma 6 (Termination recommendation idempotence)

Recommendation consumption is single-shot per recommendation cycle.

**Proof sketch.**  
`take_termination_recommendation` returns `true` once then clears flag; subsequent calls return `false` until re-triggered.

### Corollary 6.1

A single recommendation cannot trigger unbounded repeated termination actions absent new restrict escalation.

### Lemma 7 (Bounded memory)

Intent and quarantine memory are bounded by compile-time constants.

**Proof sketch.**  
All containers are fixed arrays: tracked process states, transition arrays, bloom words, quarantine slots.

### Corollary 7.1

No allocator dependence exists in hot scoring path.

### Lemma 8 (Conditional deadlock freedom under lock order discipline)

If all multi-lock paths respect partial order:

```
cap_tables < quarantine_store < remote_leases
```

then no cycle exists among these locks.

**Proof sketch.**  
A strict global order precludes circular wait in this lock subset.

### Corollary 8.1

Capability teardown and predictive revoke paths can coexist without lock-order inversion when following this order.

### Lemma 9 (Eventual restore liveness under fair invocation)

For any quarantined cap `q` with `restore_at <= t*`, if process remains alive, slot is free, and capability checks continue after `t*`, then `q` is eventually restored.

**Proof sketch.**  
Restore check is executed on capability ingress; fair repeated ingress after expiry ensures restoration condition is revisited.

### Corollary 9.1

Quarantine is operationally temporary under active process behavior and non-conflicting slot state.

## 16. Complexity and Memory Budget

### 16.1 Time complexity summary

| Operation | Complexity |
|---|---|
| Event record + score update | `O(1)` |
| Restriction check | `O(1)` |
| Transition update | `O(1)` |
| Bloom novelty update | `O(1)` |
| Capability table scan | `O(MAX_CAPABILITIES)` |
| Quarantine scan | `O(MAX_QUARANTINED_CAPS)` |

### 16.2 Space summary (dominant bounded structures)

| Structure | Bound |
|---|---:|
| Process intent states | `64` |
| Node-transition counters per process | `81` |
| Bloom bits per process | `256` |
| Quarantine slots global | `256` |
| Capability slots per process | `256` |

## 17. Failure Modes and Residual Risks

| Risk | Description | Current mitigation |
|---|---|---|
| Bloom collisions | Novel object events may be undercounted | Multi-signal scoring and additional boost terms |
| False positive isolation | Benign burst may cross thresholds | Operator clear + forced restore command |
| Remote lease blast radius | Predictive path revokes remote leases (not quarantined) | Conservative safety posture, explicit documentation |
| Deferred termination consume | Recommendation consumed on syscall boundary | Most active processes cross boundary frequently |
| Manual misuse | Incorrect operator clear on malicious process | Audit trail + explicit command visibility |

## 18. Operator Playbooks

### 18.1 Investigate suspected abuse

1. Run `security-stats`.
2. Inspect candidate process using `security-intent <pid>`.
3. Confirm `window_restrictions`, `isolation`, and termination recommendation fields.

### 18.2 Recover known-benign process

1. `security-intent-clear <pid>`
2. Re-check with `security-intent <pid>`.
3. Observe if score quickly re-enters restrict path; if yes, inspect workload behavior.

### 18.3 Containment confirmation

1. Ensure capability operations on target PID return denies while restriction active.
2. Confirm quarantine restoration count after clear.
3. Verify audit trail entries for deny/revoke/anomaly.

## 19. Research Extensions

1. Online threshold adaptation under bounded-regret controller.
2. Formal refinement proof from policy equations to kernel implementation.
3. Multi-hash novelty estimator with bounded added cost.
4. Quarantine parity for remote leases with signed thaw evidence.
5. Policy profile versioning with reproducible replay metadata.

## 20. Implementation Mapping

| Concern | File(s) |
|---|---|
| Intent state machine, windows, escalation | `kernel/src/intent_graph.rs` |
| VM inference bytecode and fallback | `kernel/src/intent_wasm.rs` |
| Security manager integration and API exposure | `kernel/src/security.rs` |
| Quarantine/revoke/restore mechanics | `kernel/src/capability.rs` |
| IPC enforcement hooks | `kernel/src/ipc.rs` |
| Syscall-boundary audit/block/termination consume | `kernel/src/syscall.rs` |
| Operator command layer | `kernel/src/commands.rs` |

## 21. Conclusion

Oreulia's Intent Graph with Predictive Revocation realizes a kernel-native, behavior-aware capability control loop that is explicit, bounded, and mathematically inspectable. The current implementation already supports phased containment, reversible local authority quarantine, strong escalation semantics, and operator-grade observability. The architecture is suitable both for practical edge hardening and for further formalization work at research depth.
