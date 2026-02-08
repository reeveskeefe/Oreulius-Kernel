//! Programmable Interval Timer (PIT) Driver
//! 
//! The PIT generates periodic timer interrupts for preemptive multitasking.
//! We configure it to fire IRQ0 at a configurable frequency (default 100 Hz).

use spin::Mutex;

// PIT I/O ports
const PIT_CHANNEL_0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;

// PIT frequency (1.193182 MHz)
const PIT_FREQUENCY: u32 = 1193182;

// Target interrupt frequency (100 Hz = 10ms ticks)
const TIMER_HZ: u32 = 100;

// Global tick counter
static TICKS: Mutex<u64> = Mutex::new(0);

/// Initialize the PIT timer
pub fn init() {
    let divisor = (PIT_FREQUENCY / TIMER_HZ) as u16;
    
    unsafe {
        // Command: Channel 0, Access mode lo/hi byte, Rate generator
        outb(PIT_COMMAND, 0x36);
        
        // Set frequency divisor
        outb(PIT_CHANNEL_0, (divisor & 0xFF) as u8);
        outb(PIT_CHANNEL_0, ((divisor >> 8) & 0xFF) as u8);
    }
}

/// Called by the timer interrupt handler
pub fn tick() {
    let mut ticks = TICKS.lock();
    *ticks += 1;
}

/// Get current tick count
pub fn get_ticks() -> u64 {
    *TICKS.lock()
}

/// Try to get ticks (non-blocking) - returns None if lock held
pub fn try_get_ticks() -> Option<u64> {
    TICKS.try_lock().map(|t| *t)
}

/// Get timer frequency in Hz
pub fn get_frequency() -> u32 {
    TIMER_HZ
}

/// Sleep for approximately N milliseconds
/// Note: This is a busy-wait for now, will be replaced with scheduler sleep
pub fn sleep_ms(ms: u32) {
    let start = get_ticks();
    let target_ticks = (ms as u64 * TIMER_HZ as u64) / 1000;
    
    while get_ticks() - start < target_ticks {
        unsafe {
            // Use HLT to save power while waiting
            core::arch::asm!("hlt");
        }
    }
}

// Port I/O functions
#[inline]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}
