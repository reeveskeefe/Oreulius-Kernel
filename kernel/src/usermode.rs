use crate::paging::{self, PAGE_SIZE};
use crate::gdt;
use core::sync::atomic::{AtomicU32, Ordering};

const USER_CODE_ADDR: usize = 0x0040_0000;
const USER_STACK_ADDR: usize = 0x0080_0000;

// mov eax, 3 (GetPid); int 0x80; ud2
const USER_STUB: [u8; 9] = [
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
    0xCD, 0x80,                   // int 0x80
    0x0F, 0x0B,                   // ud2
];

static CURRENT_WASM_MODULE: AtomicU32 = AtomicU32::new(0);

pub fn set_current_wasm_module(id: usize) {
    CURRENT_WASM_MODULE.store(id as u32, Ordering::Relaxed);
}

pub fn current_wasm_module() -> usize {
    CURRENT_WASM_MODULE.load(Ordering::Relaxed) as usize
}

pub fn enter_user_mode_test() -> Result<(), &'static str> {
    use crate::paging::KERNEL_ADDRESS_SPACE;

    let mut space_opt = KERNEL_ADDRESS_SPACE.lock();
    let space = space_opt.as_mut().ok_or("Paging not initialized")?;

    if !space.is_mapped(USER_CODE_ADDR) {
        paging::alloc_user_pages(space, USER_CODE_ADDR, 1, true)?;
    }

    if !space.is_mapped(USER_STACK_ADDR) {
        paging::alloc_user_pages(space, USER_STACK_ADDR, 1, true)?;
    }

    unsafe {
        let code_ptr = USER_CODE_ADDR as *mut u8;
        for (i, byte) in USER_STUB.iter().enumerate() {
            core::ptr::write_volatile(code_ptr.add(i), *byte);
        }
    }

    let user_stack_top = USER_STACK_ADDR + PAGE_SIZE - 4;

    unsafe {
        crate::process_asm::enter_user_mode(
            user_stack_top as u32,
            USER_CODE_ADDR as u32,
            gdt::USER_CS,
            gdt::USER_DS,
        );
    }

    Ok(())
}
