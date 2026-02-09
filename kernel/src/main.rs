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
