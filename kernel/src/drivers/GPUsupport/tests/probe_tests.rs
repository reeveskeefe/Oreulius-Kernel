// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


#[test]
fn unknown_gpu_is_probe_only() {
    let dev = crate::drivers::x86::pci::PciDevice {
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
    let report = crate::drivers::x86::gpu_support::probe::probe_pci_device(dev, 0);
    assert_eq!(report.tier, crate::drivers::x86::gpu_support::GpuTier::ProbeOnly);
}
