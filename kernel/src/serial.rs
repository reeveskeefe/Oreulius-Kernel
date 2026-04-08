/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

use core::fmt;
use spin::Mutex;
#[cfg(not(target_arch = "aarch64"))]
use core::cell::UnsafeCell;
#[cfg(not(target_arch = "aarch64"))]
use core::sync::atomic::{AtomicUsize, Ordering};

/// Simple serial port implementation (COM1, 0x3F8)
pub struct SerialPort {
    data: u16,
}

#[cfg(not(target_arch = "aarch64"))]
const COM1_BASE: u16 = 0x3F8;
#[cfg(not(target_arch = "aarch64"))]
const REG_DATA: u16 = COM1_BASE;
#[cfg(not(target_arch = "aarch64"))]
const REG_IER: u16 = COM1_BASE + 1;
#[cfg(not(target_arch = "aarch64"))]
const REG_FCR: u16 = COM1_BASE + 2;
#[cfg(not(target_arch = "aarch64"))]
const REG_LSR: u16 = COM1_BASE + 5;
#[cfg(not(target_arch = "aarch64"))]
const REG_MCR: u16 = COM1_BASE + 4;
#[cfg(not(target_arch = "aarch64"))]
const IER_RX_AVAILABLE: u8 = 1 << 0;
#[cfg(not(target_arch = "aarch64"))]
const FCR_ENABLE_CLEAR_1B: u8 = 0x07;
#[cfg(not(target_arch = "aarch64"))]
const LSR_DATA_READY: u8 = 1 << 0;
#[cfg(not(target_arch = "aarch64"))]
const LSR_OVERRUN_ERROR: u8 = 1 << 1;
#[cfg(not(target_arch = "aarch64"))]
const LSR_PARITY_ERROR: u8 = 1 << 2;
#[cfg(not(target_arch = "aarch64"))]
const LSR_FRAMING_ERROR: u8 = 1 << 3;
#[cfg(not(target_arch = "aarch64"))]
const LSR_BREAK_INTERRUPT: u8 = 1 << 4;
#[cfg(not(target_arch = "aarch64"))]
const MCR_DTR: u8 = 1 << 0;
#[cfg(not(target_arch = "aarch64"))]
const MCR_RTS: u8 = 1 << 1;
#[cfg(not(target_arch = "aarch64"))]
const MCR_OUT2: u8 = 1 << 3;
#[cfg(not(target_arch = "aarch64"))]
const RX_BUF_CAPACITY: usize = 2048;

#[cfg(not(target_arch = "aarch64"))]
const LSR_RX_ERROR_MASK: u8 =
    LSR_OVERRUN_ERROR | LSR_PARITY_ERROR | LSR_FRAMING_ERROR | LSR_BREAK_INTERRUPT;

#[cfg(not(target_arch = "aarch64"))]
struct RxRingBuffer {
    buf: UnsafeCell<[u8; RX_BUF_CAPACITY]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicUsize,
}

#[cfg(not(target_arch = "aarch64"))]
unsafe impl Sync for RxRingBuffer {}

#[cfg(not(target_arch = "aarch64"))]
impl RxRingBuffer {
    const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0; RX_BUF_CAPACITY]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn push_irq(&self, byte: u8) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let next = (head + 1) % RX_BUF_CAPACITY;
        if next == tail {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        unsafe {
            (*self.buf.get())[head] = byte;
        }
        self.head.store(next, Ordering::Release);
    }

    #[inline]
    fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let byte = unsafe { (*self.buf.get())[tail] };
        let next = (tail + 1) % RX_BUF_CAPACITY;
        self.tail.store(next, Ordering::Release);
        Some(byte)
    }

    #[inline]
    fn clear(&self) {
        let head = self.head.load(Ordering::Acquire);
        self.tail.store(head, Ordering::Release);
    }
}

#[cfg(not(target_arch = "aarch64"))]
static RX_RING: RxRingBuffer = RxRingBuffer::new();

#[cfg(not(target_arch = "aarch64"))]
#[inline]
unsafe fn outb(port: u16, value: u8) {
    crate::memory::asm_bindings::outb(port, value);
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
unsafe fn inb(port: u16) -> u8 {
    crate::memory::asm_bindings::inb(port)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn uart_try_read_byte() -> Option<(u8, u8)> {
    unsafe {
        let status = inb(REG_LSR);
        if (status & LSR_DATA_READY) == 0 {
            return None;
        }
        Some((inb(REG_DATA), status))
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn drain_uart_fifo_to_buffer() -> usize {
    let mut drained = 0usize;
    while let Some((byte, status)) = uart_try_read_byte() {
        if byte == 0 || (status & LSR_RX_ERROR_MASK) != 0 {
            continue;
        }
        RX_RING.push_irq(byte);
        drained += 1;
    }
    drained
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        Self { data: base }
    }

    #[cfg(not(target_arch = "aarch64"))]
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
            // Enable FIFO and clear both queues with the lowest trigger level.
            // CI commands are short and exact; prompt byte delivery is more
            // important than bulk UART throughput on legacy x86.
            core::arch::asm!("out dx, al", in("al") 0x07u8, in("dx") self.data + 2, options(nostack, preserves_flags));
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn init(&mut self) {
        let _ = self.data;
        crate::arch::aarch64::aarch64_pl011::early_uart().init_early();
    }

    #[cfg(not(target_arch = "aarch64"))]
    pub fn send_byte(&mut self, byte: u8) {
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

    #[cfg(target_arch = "aarch64")]
    pub fn send_byte(&mut self, byte: u8) {
        let _ = self.data;
        crate::arch::aarch64::aarch64_pl011::early_uart().write_byte(byte);
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

    pub static ref SERIAL2_TELEMETRY: Mutex<SerialPort> = {
        let mut serial_port = SerialPort::new(0x2F8);
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[cfg(not(target_arch = "aarch64"))]
pub fn enable_rx_interrupts() {
    let _ = &*SERIAL1;
    RX_RING.clear();
    unsafe {
        outb(REG_FCR, FCR_ENABLE_CLEAR_1B);
        outb(REG_MCR, MCR_DTR | MCR_RTS | MCR_OUT2);
        outb(REG_IER, IER_RX_AVAILABLE);
    }
    let _ = drain_uart_fifo_to_buffer();
}

#[cfg(target_arch = "aarch64")]
pub fn enable_rx_interrupts() {
    crate::arch::aarch64::aarch64_pl011::early_uart().enable_rx_interrupts();
}

#[cfg(not(target_arch = "aarch64"))]
pub fn disable_rx_interrupts() {
    unsafe {
        outb(REG_IER, 0);
        outb(REG_MCR, MCR_DTR | MCR_RTS);
    }
}

#[cfg(target_arch = "aarch64")]
pub fn disable_rx_interrupts() {
    crate::arch::aarch64::aarch64_pl011::early_uart().disable_interrupts();
}

#[cfg(not(target_arch = "aarch64"))]
pub fn try_read_rx_byte() -> Option<u8> {
    RX_RING.pop()
}

#[cfg(target_arch = "aarch64")]
pub fn try_read_rx_byte() -> Option<u8> {
    crate::arch::aarch64::aarch64_pl011::early_uart().try_read_buffered_byte()
}

pub fn drain_rx_into(buf: &mut [u8]) -> usize {
    let mut count = 0usize;
    while count < buf.len() {
        let Some(byte) = try_read_rx_byte() else {
            break;
        };
        buf[count] = byte;
        count += 1;
    }
    count
}

#[cfg(not(target_arch = "aarch64"))]
pub fn handle_com1_irq() {
    let _ = drain_uart_fifo_to_buffer();
}

#[cfg(target_arch = "aarch64")]
pub fn handle_com1_irq() {}

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

/// Cross-architecture kernel text output: VGA on x86/x86_64, PL011 on AArch64.
pub fn kprint_str(s: &str) {
    #[cfg(not(target_arch = "aarch64"))]
    crate::drivers::x86::vga::print_str(s);
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::aarch64_pl011::early_uart().write_str(s);
}

/// Cross-architecture single-character output.
pub fn kprint_char(c: char) {
    #[cfg(not(target_arch = "aarch64"))]
    crate::drivers::x86::vga::print_char(c);
    #[cfg(target_arch = "aarch64")]
    {
        let mut buf = [0u8; 4];
        crate::arch::aarch64::aarch64_pl011::early_uart().write_str(c.encode_utf8(&mut buf));
    }
}
