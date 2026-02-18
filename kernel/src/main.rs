/*!
 * Oreulia Kernel Project
 * 
 *License-Identifier: Oreulius License (see LICENSE)
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

#![no_std]
#![no_main]

extern crate oreulia_kernel;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Try to print panic message to serial (if lock available)
    if let Some(mut serial) = oreulia_kernel::serial::SERIAL1.try_lock() {
        use core::fmt::Write;
        let _ = writeln!(serial, "\n\nKERNEL PANIC:");
        let _ = writeln!(serial, "{}", info);
    } else {
        // If locked, try to force write to port directly to ensure message is seen
        // This is unsafe but we are panicking anyway
        unsafe {
            use oreulia_kernel::asm_bindings::{outb, inb};
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
    oreulia_kernel::rust_main()
}
