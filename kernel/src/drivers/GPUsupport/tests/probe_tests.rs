#[test]
fn unknown_gpu_is_probe_only() {
    let dev = crate::pci::PciDevice {
        bus: 0,
        slot: 0,
        func: 0,
        vendor_id: 0xDEAD,
        device_id: 0xBEEF,
        class_code: 0x03,
        subclass: 0,
        prog_if: 0,
        revision: 0,
        interrupt_line: 0,
        interrupt_pin: 0,
    };
    let report = crate::drivers::gpu_support::probe::probe_pci_device(dev, 0);
    assert_eq!(report.tier, crate::drivers::gpu_support::GpuTier::ProbeOnly);
}
