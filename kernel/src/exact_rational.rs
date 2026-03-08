/// Section 7: Exact Rational Arithmetic for JIT Confidence
///
/// Implementing a bounded Exact Rational Number arithmetic trait to compute
/// Bayesian JIT confidence without forcing Ring-0 into non-deterministic
/// IEEE-754 floating-point operations.

pub trait Integer: Copy + PartialEq + PartialOrd {
    fn zero() -> Self;
    fn one() -> Self;
}

impl Integer for u64 {
    fn zero() -> Self {
        0
    }
    fn one() -> Self {
        1
    }
}

/// A core trait forcing exact rational tracking for probabilities.
pub trait ExactRational<N: Integer, D: Integer> {
    fn numerator(&self) -> N;
    fn denominator(&self) -> D;
    fn simplify(&mut self);
}

/// A 64-bit precise Rational implementation mapping probability functions.
#[derive(Debug, Clone, Copy)]
pub struct Rational64 {
    pub n: u64,
    pub d: u64,
}

impl Rational64 {
    pub const fn new(n: u64, d: u64) -> Self {
        Self { n, d }
    }

    /// Euclid's algorithm for Greatest Common Divisor
    fn gcd(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    /// Simplify the logical fraction lazily to remain within u64 bounds
    pub fn simplify(&mut self) {
        if self.d == 0 {
            return;
        }
        let gcd = Self::gcd(self.n, self.d);
        if gcd > 1 {
            self.n /= gcd;
            self.d /= gcd;
        }
    }

    /// Exact Bayesian Update calculation: P(A|B) = P(B|A) * P(A) / P(B)
    /// Completely avoids JIT FMA subnormal drift by resolving fractionally.
    pub fn bayesian_update(prior_a: Self, prob_b_given_a: Self, prob_b: Self) -> Self {
        let mut result = Self {
            // (A.n * B|A.n) * B.d
            n: prior_a
                .n
                .saturating_mul(prob_b_given_a.n)
                .saturating_mul(prob_b.d),
            // (A.d * B|A.d) * B.n
            d: prior_a
                .d
                .saturating_mul(prob_b_given_a.d)
                .saturating_mul(prob_b.n),
        };
        result.simplify();
        result
    }
}

impl ExactRational<u64, u64> for Rational64 {
    fn numerator(&self) -> u64 {
        self.n
    }

    fn denominator(&self) -> u64 {
        self.d
    }

    fn simplify(&mut self) {
        Rational64::simplify(self)
    }
}
