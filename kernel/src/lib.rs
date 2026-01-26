#![no_std]

pub mod memory;
pub mod vga;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    // Minimal proof that Rust code is running (i686 mode).
    unsafe {
        let vga = 0xb8000 as *mut u16;
        *vga.add(0) = 0x2F52; // R
        *vga.add(1) = 0x2F55; // U
        *vga.add(2) = 0x2F53; // S
        *vga.add(3) = 0x2F54; // T
    }

    loop {
        core::hint::spin_loop();
    }
}
