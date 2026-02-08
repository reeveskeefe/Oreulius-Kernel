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

    SERIAL1
        .lock()
        .write_fmt(args)
        .expect("serial write failed");
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
