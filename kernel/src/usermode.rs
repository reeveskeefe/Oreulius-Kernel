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

#[cfg(target_arch = "x86")]
use crate::gdt;
#[cfg(target_arch = "x86_64")]
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "x86")]
const USER_CODE_ADDR: usize = 0x0040_0000;
#[cfg(target_arch = "x86")]
const USER_STACK_ADDR: usize = 0x0080_0000;

#[cfg(target_arch = "x86_64")]
const USER_CODE_ADDR: usize = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
const USER_STACK_ADDR: usize = 0x4001_0000;

// mov eax, 3 (GetPid); int 0x80; verify eax=0/edx=0; int3 on success; fault on failure
#[cfg(target_arch = "x86")]
const USER_STUB: [u8; 23] = [
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
    0xCD, 0x80, // int 0x80
    0x83, 0xF8, 0x00, // cmp eax, 0
    0x75, 0x07, // jne fail
    0x85, 0xD2, // test edx, edx
    0x75, 0x03, // jne fail
    0xCC, // int3
    0xEB, 0xFE, // jmp $
    0x31, 0xC0, // fail: xor eax, eax
    0x8B, 0x00, // mov eax, [eax]
];

// mov eax, 3 (GetPid); int 0x80; require pid>0 and errno=0; int3; then yield forever
#[cfg(target_arch = "x86_64")]
const USER_STUB: [u8; 31] = [
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
    0xCD, 0x80, // int 0x80
    0x85, 0xD2, // test edx, edx
    0x75, 0x10, // jne fail
    0x85, 0xC0, // test eax, eax
    0x74, 0x0C, // jz fail
    0xCC, // int3
    0xB8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (Yield)
    0x31, 0xDB, // xor ebx, ebx
    0xCD, 0x80, // int 0x80
    0xEB, 0xF5, // jmp yield_loop
    0x31, 0xC0, // fail: xor eax, eax
    0x8B, 0x00, // mov eax, [eax]
];

static CURRENT_WASM_MODULE: AtomicU32 = AtomicU32::new(0);

pub fn set_current_wasm_module(id: usize) {
    CURRENT_WASM_MODULE.store(id as u32, Ordering::Relaxed);
}

pub fn current_wasm_module() -> usize {
    CURRENT_WASM_MODULE.load(Ordering::Relaxed) as usize
}

#[cfg(target_arch = "x86")]
pub fn enter_user_mode_test() -> Result<(), &'static str> {
    #[cfg(target_arch = "x86")]
    let mut x86_space_guard = crate::paging::KERNEL_ADDRESS_SPACE.lock();
    #[cfg(target_arch = "x86")]
    let space = x86_space_guard.as_mut().ok_or("Paging not initialized")?;

    if !space.is_mapped(USER_CODE_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_CODE_ADDR, 1, true)?;
    }

    if !space.is_mapped(USER_STACK_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_STACK_ADDR, 1, true)?;
    }

    unsafe {
        let code_ptr = USER_CODE_ADDR as *mut u8;
        for (i, byte) in USER_STUB.iter().enumerate() {
            core::ptr::write_volatile(code_ptr.add(i), *byte);
        }
    }

    let user_stack_top = USER_STACK_ADDR + crate::arch::mmu::page_size() - 4;

    unsafe {
        crate::process_asm::enter_user_mode(
            user_stack_top as u32,
            USER_CODE_ADDR as u32,
            gdt::USER_CS,
            gdt::USER_DS,
        );
    }

    Err("enter_user_mode returned unexpectedly")
}

#[cfg(target_arch = "x86_64")]
fn copy_stub_to_user(
    space: &crate::arch::mmu::AddressSpace,
    vaddr: usize,
    data: &[u8],
) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
        core::ptr::copy_nonoverlapping(data.as_ptr(), vaddr as *mut u8, data.len());
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn prepare_user_test_space(
    space: &mut crate::arch::mmu::AddressSpace,
) -> Result<u32, &'static str> {
    let page_size = crate::arch::mmu::page_size();

    if !space.is_mapped(USER_CODE_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_CODE_ADDR, 1, true)?;
    }

    if !space.is_mapped(USER_STACK_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_STACK_ADDR, 1, true)?;
    }

    copy_stub_to_user(space, USER_CODE_ADDR, &USER_STUB)?;

    Ok((USER_STACK_ADDR + page_size - 16) as u32)
}

#[cfg(target_arch = "x86_64")]
fn allocate_user_test_pid() -> Result<crate::process::Pid, &'static str> {
    let scheduler = crate::quantum_scheduler::scheduler().lock();
    let pid_raw = (3..crate::process::MAX_PROCESSES as u32)
        .find(|raw| scheduler.get_process_info(crate::process::Pid::new(*raw)).is_none())
        .ok_or("No available user PID")?;
    Ok(crate::process::Pid::new(pid_raw))
}

#[cfg(target_arch = "x86_64")]
pub fn enter_user_mode_test() -> Result<(), &'static str> {
    let pid = allocate_user_test_pid()?;
    let mut space = crate::arch::mmu::AddressSpace::new()?;
    let user_stack = prepare_user_test_space(&mut space)?;

    crate::process::process_manager()
        .temporal_spawn_with_pid(pid, "user-test", None)
        .map_err(|e| e.as_str())?;

    let mut process = crate::process::Process::new(pid, "user-test", None);
    process.priority = crate::process::ProcessPriority::Normal;

    crate::quantum_scheduler::scheduler()
        .lock()
        .add_user_process(process, Box::new(space), USER_CODE_ADDR as u32, user_stack)?;

    crate::quantum_scheduler::yield_now();
    Ok(())
}
