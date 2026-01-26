#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        let vga = 0xb8000 as *mut u16;
        *vga.offset(0) = 0x4F4B; // K in white on red
        *vga.offset(1) = 0x4F45; // E
        *vga.offset(2) = 0x4F52; // R
        *vga.offset(3) = 0x4F4E; // N
    }
    loop {}
}
