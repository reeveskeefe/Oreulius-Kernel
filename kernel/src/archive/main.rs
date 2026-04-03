/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

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
