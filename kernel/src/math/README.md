# `kernel/src/math` — Mathematical Abstractions

The `math` module provides the **formal mathematical underpinning** that the Oreulia capability system, scheduler, and SIMD-accelerated kernel subsystems build on. It is intentionally small — three files, ~380 lines total — because it supplies pure mathematical *types* and *traits*, not algorithms. The algorithms (entropy estimation, SIMD dispatch, capability flow) live in the subsystems that use these types.

---

## Design Philosophy

1. **Math defines correctness constraints; the type system enforces them.** `LinearCapability<T, CAPACITY>` encodes the capacity-flow invariant — that a capability cannot be created from nothing. The constraint `A + B == C` is checked at `affine_split` time, not at runtime in a caller's hot path.
2. **Exact arithmetic over approximations.** `Rational64` uses `u64` numerator and denominator with GCD reduction. It never silently truncates — operations that would overflow return an error.
3. **Architecture-polymorphic SIMD.** `SimdTensor<N>` is a trait. The `x86_64` module provides an `Avx2Tensor<N>` backed by `_mm256_*` intrinsics. The `aarch64` module provides a `NeonTensor<N>` backed by `vaddq_s32` / `vmulq_s32`. The scalar `ScalarTensor<i32, N>` is the no-SIMD fallback that compiles on all targets.
4. **Entropy evaluation is a kernel primitive.** The `EntropyEvaluator` trait captures the approximation of Markov state-transition entropy that the scheduler uses to weight EWMA yield/fault scoring.

---

## Source Layout

| File | Lines | Role |
|---|---|---|
| `mod.rs` | 8 | Re-exports `exact_rational` and `linear_capability` |
| `exact_rational.rs` | 94 | `Rational64`, `ExactRational<N, D>` trait, `Integer` trait |
| `linear_capability.rs` | 278 | `LinearCapability<T, C>`, `AffineSplit`, `SimdTensor`, `ScalarTensor`, `EntropyEvaluator`, `EevdfEntropy`, `x86_simd::Avx2Tensor`, `aarch64_simd::NeonTensor` |

---

## `exact_rational.rs` — Exact Arithmetic Types

### `Integer` Trait

A minimal numeric primitive constraint used as a type bound on `ExactRational`:

```rust
pub trait Integer: Copy + PartialEq + PartialOrd {
    fn zero() -> Self;
    fn one() -> Self;
    fn gcd(a: Self, b: Self) -> Self;
}
```

Implemented for `u64`.

### `ExactRational<N: Integer, D: Integer>`

The abstract interface for exact rational numbers:

```rust
pub trait ExactRational<N: Integer, D: Integer> {
    fn new(numerator: N, denominator: D) -> Result<Self, &'static str>
    where Self: Sized;
    fn numerator(&self) -> N;
    fn denominator(&self) -> D;
    fn add(&self, other: &Self) -> Result<Self, &'static str>
    where Self: Sized;
    fn mul(&self, other: &Self) -> Result<Self, &'static str>
    where Self: Sized;
    fn to_f64(&self) -> f64;
}
```

### `Rational64`

The canonical implementation: numerator and denominator stored as `u64`, always in reduced form (GCD applied on construction).

| Method | Description |
|---|---|
| `Rational64::new(n, d)` | Construct; returns `Err` if `d == 0` or if `n/gcd` or `d/gcd` would overflow |
| `numerator()` | Reduced numerator |
| `denominator()` | Reduced denominator |
| `add(other)` | `(a/b) + (c/d) = (a*d + c*b) / (b*d)` — returns `Err` on overflow |
| `mul(other)` | `(a/b) * (c/d) = (a*c) / (b*d)` — GCD pre-reduction to avoid overflow |
| `to_f64()` | Lossless for values within `f64` precision |

**Usage in the kernel:** Quota accounting in capability tokens where exact fractional budget tracking is required. For example, `byte_quota` constraints in CapNet tokens may be expressed as rationals to allow sub-byte measurements without truncation.

---

## `linear_capability.rs` — Affine Capability Types and SIMD Dispatch

### `LinearCapability<T, const CAPACITY: usize>`

An **affine type** — it can be created once and split, but never cloned or duplicated implicitly. The const parameter `CAPACITY` represents the total flow capacity for this token.

```rust
pub struct LinearCapability<T, const CAPACITY: usize> {
    pub resource: T,
    _marker: PhantomData<()>,
}
```

The `_marker` makes it impossible to `Copy` or `Clone` through `derive`. Combined with the `unsafe impl Send` (needed because `PhantomData<()>` kills auto-Send), ownership is **strictly linear**.

#### Key Methods

| Method | Description |
|---|---|
| `new(resource: T) -> Self` | Create a root capability token (called once per resource at boot) |
| `affine_split<A, B>(self)` | Split into two tokens with capacities `A` and `B` where `A + B == CAPACITY`. Returns `Err` on violation. Consumes `self`. |

The `affine_split` constraint ensures zero-sum capacity preservation: if you hold a capability over `N` units of a resource, you can delegate to two holders of `A` and `N-A` units, but the total always sums to `N`. This is the kernel's formal model of **Max-Flow capability attenuation**, as described in Polymorphic Mathematical Architecture §3.

### `AffineSplit<T, const C: usize>` Trait

```rust
pub trait AffineSplit<T, const C: usize>: Send + Sized {
    fn affine_split<const A: usize, const B: usize>(
        self,
    ) -> Result<(LinearCapability<T, A>, LinearCapability<T, B>), &'static str>
    where T: Clone;
}
```

`LinearCapability<T, C>` provides the blanket implementation. Future CHERI/Morello-backed hardware capability types may provide their own implementations.

---

### `SimdTensor<const N: usize>` Trait

A polymorphic tensor trait for fixed-size integer arrays. Used internally by the scheduler's entropy estimator and by the kernel's WASM SIMD emulation layer.

```rust
pub trait SimdTensor<const N: usize> {
    type Element;
    fn zeros() -> Self;
    fn add(&self, other: &Self) -> Self;
    fn dot_product(&self, other: &Self) -> Self::Element;
}
```

### `ScalarTensor<T, const N: usize>`

Fallback scalar implementation. Uses wrapping arithmetic (`wrapping_add`, `wrapping_mul`) to avoid overflow panics in `no_std`.

```rust
pub struct ScalarTensor<T, const N: usize> {
    pub data: [T; N],
}
```

Currently implemented for `T = i32`. Compiles on all architectures.

### `x86_simd::Avx2Tensor<N>` (x86-64 only)

An AVX2-backed `SimdTensor` storing `[__m256i; N]`. Each `__m256i` holds 8 × `i32` lanes.

| Method | Backend instruction | Description |
|---|---|---|
| `zeros_impl()` | `_mm256_setzero_si256` | Zero all lanes |
| `add_impl(other)` | `_mm256_add_epi32` | 8-wide parallel add |
| `dot_product_impl(other)` | `_mm256_mullo_epi32` + horizontal reduction | Full 8-lane dot product |

All methods are `#[target_feature(enable = "avx2")]` — they will not be called unless `has_avx()` returns `true` at runtime.

**Horizontal reduction** in `dot_product_impl` uses a 4-step lane-combining sequence: `_mm256_extracti128_si256` → `_mm_add_epi32` (twice) → `_mm_shuffle_epi32` (twice) → `_mm_cvtsi128_si32`.

### `aarch64_simd::NeonTensor<N>` (AArch64 only)

A NEON-backed `SimdTensor` storing `[int32x4_t; N]`. Each `int32x4_t` holds 4 × `i32` lanes.

| Method | Backend instruction | Description |
|---|---|---|
| `zeros_impl()` | `vdupq_n_s32(0)` | Zero all lanes |
| `add_impl(other)` | `vaddq_s32` | 4-wide parallel add |
| `dot_product_impl(other)` | `vmulq_s32` + `vpaddq_s32` | Full 4-lane dot product with pairwise reduction |

---

### `EntropyEvaluator` Trait

Models the Markov rate-matrix approximation used by the scheduler to estimate process entropy for EEVDF scheduling weight decay:

```rust
pub trait EntropyEvaluator {
    fn compute_entropy(shannon_base: u32, generator_rate: u32, dt: u32) -> u32;
}
```

The approximation is a linearized CTMC step: $P(t) \approx P(0) + Q \cdot P(0) \cdot \Delta t$ for small $\Delta t$.

### `EevdfEntropy`

The current production implementation of `EntropyEvaluator`. Computes:

```rust
fn compute_entropy(_shannon_base: u32, generator_rate: u32, dt: u32) -> u32 {
    generator_rate.wrapping_mul(dt)
}
```

The `_shannon_base` parameter is reserved for the full Markov model when the proof assistant validates the closed-form expression. The current scaffolded form provides a deterministic monotonic mock scalar for use in CI regression tests.

---

## Relationship to Other Modules

| Depending module | Uses |
|---|---|
| `capability` | `LinearCapability<T, C>` as the foundational token type for capability tokens |
| `scheduler` | `EevdfEntropy::compute_entropy` for EWMA yield/fault weight computation |
| `net::capnet` | `AffineSplit` for CapNet token attenuation and delegation depth constraint |
| `wasm` / JIT | `Avx2Tensor` / `NeonTensor` for WASM SIMD opcode emulation |
| `security` | `Rational64` for exact quota tracking |

---

## Architecture Guard Matrix

| Type / Module | x86-64 | AArch64 | All |
|---|---|---|---|
| `Rational64` | ✓ | ✓ | ✓ |
| `LinearCapability` | ✓ | ✓ | ✓ |
| `ScalarTensor` | ✓ | ✓ | ✓ |
| `x86_simd::Avx2Tensor` | ✓ | — | — |
| `aarch64_simd::NeonTensor` | — | ✓ | — |
| `EevdfEntropy` | ✓ | ✓ | ✓ |
