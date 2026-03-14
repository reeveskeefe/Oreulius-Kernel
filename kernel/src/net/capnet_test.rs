pub trait LinearCapability<T, const C: usize>: Send {
    // Enforces mathematically affine splits via zero-sum node equations
    fn delegate<const A: usize, const B: usize>(self, target: Dest) -> SplitCap<T, A, B>
    where
        // Ideally we want A + B == C, which we can simulate via a const panic block or similar in implementation.
        Self: Sized;
}

pub struct SplitCap<T, const A: usize, const B: usize> {
    pub local: T,
    pub delegated: T,
}

pub struct Dest(pub u64);
