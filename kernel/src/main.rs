#![no_std]
#![no_main]

extern crate oreulia_kernel;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Call the actual kernel main function
    oreulia_kernel::rust_main()
}
