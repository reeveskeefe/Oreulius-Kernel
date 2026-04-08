#[test]
fn fence_ids_increase() {
    let a = crate::drivers::x86::gpu_support::GpuFence::alloc();
    let b = crate::drivers::x86::gpu_support::GpuFence::alloc();
    assert!(b.id > a.id);
}
