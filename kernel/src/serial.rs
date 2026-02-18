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

use core::fmt;
use spin::Mutex;

/// Simple serial port implementation (COM1, 0x3F8)
pub struct SerialPort {
    data: u16,
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        Self { data: base }
    }

    fn init(&mut self) {
        unsafe {
            // Disable interrupts
            core::arch::asm!("out dx, al", in("al") 0u8, in("dx") self.data + 1, options(nostack, preserves_flags));
            // Enable DLAB
            core::arch::asm!("out dx, al", in("al") 0x80u8, in("dx") self.data + 3, options(nostack, preserves_flags));
            // Set divisor to 3 (38400 baud)
            core::arch::asm!("out dx, al", in("al") 3u8, in("dx") self.data, options(nostack, preserves_flags));
            core::arch::asm!("out dx, al", in("al") 0u8, in("dx") self.data + 1, options(nostack, preserves_flags));
            // 8 bits, no parity, one stop bit
            core::arch::asm!("out dx, al", in("al") 0x03u8, in("dx") self.data + 3, options(nostack, preserves_flags));
            // Enable FIFO, clear, with 14-byte threshold
            core::arch::asm!("out dx, al", in("al") 0xC7u8, in("dx") self.data + 2, options(nostack, preserves_flags));
        }
    }

    fn send_byte(&mut self, byte: u8) {
        unsafe {
            // Wait for transmit buffer to be empty
            loop {
                let status: u8;
                core::arch::asm!("in al, dx", out("al") status, in("dx") self.data + 5, options(nostack, preserves_flags));
                if (status & 0x20) != 0 {
                    break;
                }
            }
            // Send byte
            core::arch::asm!("out dx, al", in("al") byte, in("dx") self.data, options(nostack, preserves_flags));
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send_byte(byte);
        }
        Ok(())
    }
}

lazy_static::lazy_static! {
    pub static ref SERIAL1: Mutex<SerialPort> = {
        let mut serial_port = SerialPort::new(0x3F8);
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;

    // Use try_lock to avoid deadlocks in interrupt handlers
    if let Some(mut serial) = SERIAL1.try_lock() {
        let _ = serial.write_fmt(args);
    }
    // If locked, we drop the message to prevent deadlock
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($fmt:expr) => { $crate::serial_print!(concat!($fmt, "\n")) };
    ($fmt:expr, $($arg:tt)*) => { $crate::serial_print!(concat!($fmt, "\n"), $($arg)*) };
}
