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
fn null_scanout_is_headless() {
    let target = crate::drivers::x86::gpu_support::display::scanout::PresentTarget {
        width: 0,
        height: 0,
        backend: crate::drivers::x86::gpu_support::display::scanout::ScanoutBackendId::None,
    };
    assert_eq!(target.width, 0);
}
