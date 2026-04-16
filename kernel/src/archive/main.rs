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

#![no_std]
#![no_main]

extern crate oreulius_kernel;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Try to print panic message to serial (if lock available)
    if let Some(mut serial) = oreulius_kernel::serial::SERIAL1.try_lock() {
        use core::fmt::Write;
        let _ = writeln!(serial, "\n\nKERNEL PANIC:");
        let _ = writeln!(serial, "{}", info);
    } else {
        // If locked, try to force write to port directly to ensure message is seen
        // This is unsafe but we are panicking anyway
        unsafe {
            use oreulius_kernel::asm_bindings::{outb, inb};
            let msg = b"\nPANIC (LOCKED)\n";
            for &b in msg {
                // Simple wait loop
                 while (inb(0x3F8 + 5) & 0x20) == 0 {}
                 outb(0x3F8, b);
            }
        }
    }
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Call the actual kernel main function
    oreulius_kernel::rust_main()
}
