/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
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
