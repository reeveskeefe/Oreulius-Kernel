# Oreulius WASM JIT Fuzz Pairwise Transition Coverage (Implemented)

## Purpose

This document specifies the **implemented** pairwise transition coverage system used by Oreulius's `jit_fuzz` harness in [kernel/src/execution/wasm.rs](/Users/keefereeves/Desktop/OreuliusKernel/TheActualKernelProject/oreulius/kernel/src/execution/wasm.rs).

It records the mathematics, the actual harness algorithm, and the current
coverage model used by the shipped runtime:

- default build: `20` guided bins
- `jit-fuzz-24bin` build: `24` guided bins
- full directed-pair universe size: `N^2`, where `N = JIT_FUZZ_OPCODE_BINS`

This is a **generator-structure coverage** metric for differential JIT fuzzing (interpreter vs JIT), not a claim of full WASM opcode or CFG coverage.

## Scope (What This Metric Measures)

The harness does **not** measure raw byte-level opcode adjacency. It measures adjacency over the guided generator's macro-choice trace (`choice_trace`) recorded in `jit_fuzz`.

Each fuzz-generated program emits a sequence of guided choices:

`T = (t_1, t_2, ..., t_n)`

where each `t_k` is a guided bin index.

A directed pairwise transition is counted when two consecutive emitted guided choices occur:

`(t_k, t_{k+1})`.

This metric therefore operates on the guided generator alphabet, not the final byte stream.

## Formal Definitions

Let:

- `B = {0, 1, ..., N-1}` be the guided-bin alphabet.
- `|B| = N`, where `N = JIT_FUZZ_OPCODE_BINS`.
- `T = (t_1, ..., t_n)` be the `choice_trace` for one generated program.

Define the full directed pair universe:

`E_full = B x B`

and therefore:

`|E_full| = |B|^2 = N^2`.

The harness records a pair `(i, j)` as observed iff:

`exists k in {1, ..., n-1} such that t_k = i and t_{k+1} = j`.

Let:

- `E_hit subseteq E_full` be the set of observed directed bin pairs.

Then the reported full-universe pairwise ratio is:

`C_full = |E_hit| / |E_full| = |E_hit| / 400`.

This is the source of the runtime line:

- `Opcode edges hit (full): X / N^2`

## Guided Bin Model

The current `jit_fuzz` guided generator uses either:
- **20 macro bins** in the default build
- **24 macro bins** when the `jit-fuzz-24bin` feature is enabled

The default 20-bin mapping is:

### Table 1. Guided bins (`B`, default size 20)

| Bin | Meaning (generator choice) | Notes |
|---:|---|---|
| 0 | `nop` | Emits `nop` |
| 1 | `drop` fallback / `i32.const` | `drop` if stack>0 else `i32.const` |
| 2 | `i32.const` | Emits constant |
| 3 | `i32.add` | stack >= 2 |
| 4 | `i32.sub` | stack >= 2 |
| 5 | `i32.mul` | stack >= 2 |
| 6 | `i32.and` | stack >= 2 |
| 7 | `i32.or` | stack >= 2 |
| 8 | `i32.xor` | stack >= 2 |
| 9 | `i32.eqz` | stack >= 1 |
| 10 | bounded `i32.load` macro | emits helper sequence + `i32.load` |
| 11 | bounded `i32.store` macro | emits helper sequence + `i32.store` |
| 12 | `local.get` | requires `locals_total > 0` |
| 13 | `local.set` | requires `locals_total > 0` and stack > 0 |
| 14 | `local.tee` | requires `locals_total > 0` and stack > 0 |
| 15 | `i32.eq` / `i32.ne` compare class | binary compare |
| 16 | signed compare class | one of `lt_s/gt_s/le_s/ge_s` |
| 17 | unsigned compare class | one of `lt_u/gt_u/le_u/ge_u` |
| 18 | shift class | one of `shl/shr_s/shr_u` |
| 19 | const-compare macro class | emits compare-oriented sequence with constant(s) |

## Admissible Edge Set (`E_adm`)

Because emission is constrained by:

- current abstract stack depth,
- local availability (`locals_total == 0` vs `> 0`),
- code-size budget / remaining room,
- per-bin preconditions,
- macro-expansion semantics,

not every pair in `E_full` is necessarily reachable in general.

We therefore define the admissible edge set:

`E_adm subseteq E_full`

as the set of directed pairs that are reachable under the generator's abstract transition semantics.

### Abstract State Model

The implemented admissibility computation uses a finite abstract state:

`q = (s, l, c)`

where:

- `s` = abstract stack-depth state (bounded)
- `l` = local-availability class (`0` or `>0`)
- `c` = code-budget bucket / remaining budget abstraction

Let `Q` be the finite set of abstract states.

For each guided bin `i in B`, the generator defines a partial transition:

`delta_i : Q -> Q union {bot}`

where `bot` means "choice not admissible / does not emit under this state".

Then:

`E_adm = { (i,j) in B x B : exists q in Q, delta_i(q) != bot and delta_j(delta_i(q)) != bot }`

and:

`|E_adm| = sum_(i,j in B) 1[(i,j) in E_adm]`.

The harness computes this matrix and reports:

- `Opcode edges hit (admissible): Y / |E_adm|`

## Implemented Coverage Metrics

The harness now tracks all of the following explicitly:

- `opcode_bins_hit = |{ i in B : i appears in choice_trace }|`
- `opcode_edges_hit_full = |E_hit|`
- `opcode_edges_admissible_total = |E_adm|`
- `opcode_edges_hit_admissible = |E_hit ∩ E_adm|`

with:

`C_adm = |E_hit ∩ E_adm| / |E_adm|`.

### Important Interpretation

- `C_full` answers: "How much of the unconstrained `20 x 20` universe has been hit?"
- `C_adm` answers: "How much of the actually reachable pair universe has been hit?"

For the default 20-bin implementation and observed milestone run, both are equal because:

`E_adm = E_full`

for the default 20-bin generator model under the implemented abstract state semantics.

## Deterministic Pair-Cover Prepass (Implemented)

The harness includes a deterministic pair-cover prepass before the stochastic fuzz phase.

### Goal

Reduce edge debt directly by synthesizing short programs that force targeted uncovered admissible pairs.

Define an edge-debt indicator:

`D[i,j] = 1 if (i,j) in E_adm and (i,j) notin E_hit else 0`.

The prepass iterates uncovered admissible pairs and attempts to build a witness program prefix that:

1. reaches a witness abstract state `q`,
2. emits `i`,
3. emits `j`,
4. finalizes to a valid bytecode program,
5. preserves differential validity (interpreter/JIT both run).

### Construction Basis

The implementation computes and stores witness information while constructing `E_adm`, then uses it to guide deterministic pair synthesis.

This is the practical realization of the constrained edge-cover strategy proposed in earlier design notes.

## Stochastic Phase (After Deterministic Cover)

After deterministic pair debt reduction, the existing guided fuzz phase continues to generate programs for:

- semantic diversity,
- trap-path exploration,
- regression discovery,
- differential equivalence checking.

This is why `Novel programs` remains meaningful even after pairwise coverage saturates.

## Mathematical Notes (Retained, Now Applied)

### Lemma 1 (Projection Correctness)

The harness edge metric equals the set of directed 2-grams of the guided `choice_trace`.

**Reason.** The harness marks exactly adjacent pairs in `choice_trace` into a boolean adjacency matrix indexed by `(i, j)`.

### Lemma 2 (Admissibility Characterization)

A pair `(i, j)` is admissible iff there exists an abstract state `q` such that `delta_i` and `delta_j` compose without hitting `bot`.

This is exactly the criterion used by the implemented `E_adm` computation.

### Theorem 1 (Unconstrained Lower Bound Intuition)

If all pairs are admissible and each emission contributed one symbol in an unconstrained model, then order-2 de Bruijn reasoning gives the cyclic lower-bound intuition of `|B|^2` pair occurrences.

For a guided alphabet of size `N`, the unconstrained directed-pair universe size is:

`N^2`.

Linearized de Bruijn order-2 length intuition:

`N^2 + 1` symbols.

Oreulius's actual harness is harder than this idealized case because it is constrained, macro-expanded, and semantically validated.

## Achieved Milestone (Default Build)

The default build has achieved complete pairwise coverage for the present 20-bin generator model in a differential fuzz run:

### Table 2. Achieved pairwise milestone

| Metric | Value |
|---|---:|
| `Opcode bins hit` | `20 / 20` |
| `Opcode edges hit (full)` | `400 / 400` |
| `Opcode edges hit (admissible)` | `400 / 400` |

This demonstrates:

1. the deterministic pair-cover prepass is effective,
2. the admissibility matrix computation is integrated and consistent,
3. the stochastic phase still contributes diversity (novel programs continue to rise),
4. the pairwise metric is no longer "hypothesis-only" for the default model.

## What This Does *Not* Prove

Pairwise guided-bin coverage is a strong structural milestone, but it does **not** imply:

- full WASM opcode coverage,
- full structured-control-flow (`if/else/br/br_if`) coverage,
- full backend parity across all opcodes,
- memory-shape completeness,
- long-sequence/stateful robustness,
- production-grade JIT correctness.

It is one axis in a larger validation strategy.

## Engineering Implications (Next Expansion Path)

The pairwise framework is now mature enough to scale with backend expansion:

1. add more guided bins (new opcode classes / macro classes),
2. recompute `E_adm`,
3. reuse deterministic pair-cover prepass,
4. preserve differential validity (interpreter + JIT support matrix alignment),
5. re-measure `C_full` and `C_adm`.

For a new bin count `N`, the full-universe denominator generalizes to:

`|E_full| = N^2`.

## Implementation Status Summary

This document describes a **completed and active** feature in the current codebase:

- `E_adm` computation: implemented
- `Opcode edges hit (full)` reporting: implemented
- `Opcode edges hit (admissible)` reporting: implemented
- deterministic pair-cover prepass: implemented
- 20-bin guided generator support: implemented
- 24-bin feature-expanded generator support: implemented
- observed `400/400` pairwise completion for default model: achieved

Future work is no longer "make pairwise possible"; it is "expand the modeled opcode/bin space while preserving differential correctness and pairwise completeness".
