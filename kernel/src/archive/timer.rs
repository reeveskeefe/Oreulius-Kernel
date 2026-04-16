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

use x86_64::instructions::port::Port;

pub fn init_pit() {
    // Set PIT to 1000 Hz
    let divisor = 1193182 / 1000;
    let mut command_port = Port::new(0x43);
    let mut data_port = Port::new(0x40);
    unsafe {
        command_port.write(0x36u8);
        data_port.write((divisor & 0xFF) as u8);
        data_port.write((divisor >> 8) as u8);
    }
}