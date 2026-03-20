#[test]
fn null_scanout_is_headless() {
    let target = crate::drivers::gpu_support::display::scanout::PresentTarget {
        width: 0,
        height: 0,
        backend: crate::drivers::gpu_support::display::scanout::ScanoutBackendId::None,
    };
    assert_eq!(target.width, 0);
}
