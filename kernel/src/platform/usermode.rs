/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

#[cfg(target_arch = "x86")]
use crate::platform::gdt;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_arch = "x86")]
const USER_CODE_ADDR: usize = 0x0040_0000;
#[cfg(target_arch = "x86")]
const USER_STACK_ADDR: usize = 0x0080_0000;

#[cfg(target_arch = "x86_64")]
const USER_CODE_ADDR: usize = 0x4000_0000;
#[cfg(target_arch = "x86_64")]
const USER_DATA_ADDR: usize = 0x4000_1000;
#[cfg(target_arch = "x86_64")]
const USER_STACK_ADDR: usize = 0x4001_0000;

#[cfg(target_arch = "aarch64")]
const USER_CODE_ADDR: usize = 0x4000_0000;
#[cfg(target_arch = "aarch64")]
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

// mov x8,#3 (GetPid); svc #0; require errno==0 and pid>0; brk #0 on success;
// then yield forever. On failure trap with brk #1 and loop there.
#[cfg(target_arch = "aarch64")]
const USER_STUB: [u8; 44] = [
    0x68, 0x00, 0x80, 0xD2, // mov x8, #3
    0x01, 0x00, 0x00, 0xD4, // svc #0
    0xE1, 0x00, 0x00, 0xB5, // cbnz x1, fail
    0xC0, 0x00, 0x00, 0xB4, // cbz x0, fail
    0x00, 0x00, 0x20, 0xD4, // brk #0
    0x48, 0x00, 0x80, 0xD2, // mov x8, #2 (Yield)
    0x00, 0x00, 0x80, 0xD2, // mov x0, #0
    0x01, 0x00, 0x00, 0xD4, // svc #0
    0xFD, 0xFF, 0xFF, 0x17, // b yield_loop
    0x20, 0x00, 0x20, 0xD4, // fail: brk #1
    0xFF, 0xFF, 0xFF, 0x17, // b fail
];

// fork(); store fork return and getpid into a COW data page; parent writes
// 0xAA, child writes 0x55, then both yield forever so the kernel can inspect.
#[cfg(target_arch = "x86_64")]
const USER_FORK_STUB: [u8; 94] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (Fork)
    0x31, 0xDB, // xor ebx, ebx
    0xCD, 0x80, // int 0x80
    0x89, 0xC6, // mov esi, eax
    0x89, 0xD7, // mov edi, edx
    0xB9, 0x00, 0x10, 0x00, 0x40, // mov ecx, USER_DATA_ADDR
    0x85, 0xFF, // test edi, edi
    0x75, 0x3A, // jne fail
    0x89, 0x31, // mov [rcx], esi
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3 (GetPid)
    0xCD, 0x80, // int 0x80
    0x89, 0xD7, // mov edi, edx
    0x85, 0xFF, // test edi, edi
    0x75, 0x2B, // jne fail
    0xB9, 0x00, 0x10, 0x00, 0x40, // mov ecx, USER_DATA_ADDR
    0x89, 0x41, 0x04, // mov [rcx+4], eax
    0x85, 0xF6, // test esi, esi
    0x74, 0x0B, // jz child
    0xB9, 0x00, 0x10, 0x00, 0x40, // mov ecx, USER_DATA_ADDR
    0xC6, 0x41, 0x08, 0xAA, // mov byte [rcx+8], 0xAA
    0xEB, 0x09, // jmp yield_loop
    0xB9, 0x00, 0x10, 0x00, 0x40, // child: mov ecx, USER_DATA_ADDR
    0xC6, 0x41, 0x08, 0x55, // child: mov byte [rcx+8], 0x55
    0xB8, 0x02, 0x00, 0x00, 0x00, // yield_loop: mov eax, 2 (Yield)
    0x31, 0xDB, // xor ebx, ebx
    0xCD, 0x80, // int 0x80
    0xEB, 0xF5, // jmp yield_loop
    0xB9, 0x00, 0x10, 0x00, 0x40, // fail: mov ecx, USER_DATA_ADDR
    0x89, 0x79, 0x0C, // fail: mov [rcx+12], edi
    0xC6, 0x41, 0x08, 0xEE, // mov byte [rcx+8], 0xEE
    0xEB, 0xE7, // jmp yield_loop
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
    let mut x86_space_guard = crate::fs::paging::KERNEL_ADDRESS_SPACE.lock();
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
        crate::scheduler::process_asm::enter_user_mode(
            user_stack_top as u32,
            USER_CODE_ADDR as u32,
            gdt::USER_CS,
            gdt::USER_DS,
        );
    }

    Err("enter_user_mode returned unexpectedly")
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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
fn zero_user_page(
    space: &crate::arch::mmu::AddressSpace,
    vaddr: usize,
) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
        core::ptr::write_bytes(vaddr as *mut u8, 0, crate::arch::mmu::page_size());
    }
    crate::arch::mmu::set_page_table_root(old)?;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn copy_from_user(
    space: &crate::arch::mmu::AddressSpace,
    vaddr: usize,
    data: &mut [u8],
) -> Result<(), &'static str> {
    let old = crate::arch::mmu::current_page_table_root_addr();
    unsafe {
        space.activate();
        core::ptr::copy_nonoverlapping(vaddr as *const u8, data.as_mut_ptr(), data.len());
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
fn prepare_user_fork_test_space(
    space: &mut crate::arch::mmu::AddressSpace,
) -> Result<u32, &'static str> {
    let page_size = crate::arch::mmu::page_size();

    if !space.is_mapped(USER_CODE_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_CODE_ADDR, 1, true)?;
    }
    if !space.is_mapped(USER_DATA_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_DATA_ADDR, 1, true)?;
    }
    if !space.is_mapped(USER_STACK_ADDR) {
        crate::arch::mmu::alloc_user_pages(space, USER_STACK_ADDR, 1, true)?;
    }

    copy_stub_to_user(space, USER_CODE_ADDR, &USER_FORK_STUB)?;
    zero_user_page(space, USER_DATA_ADDR)?;

    Ok((USER_STACK_ADDR + page_size - 16) as u32)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn allocate_user_test_pid() -> Result<crate::scheduler::process::Pid, &'static str> {
    let scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    let pid_raw = (3..crate::scheduler::process::MAX_PROCESSES as u32)
        .find(|raw| {
            scheduler
                .get_process_info(crate::scheduler::process::Pid::new(*raw))
                .is_none()
        })
        .ok_or("No available user PID")?;
    Ok(crate::scheduler::process::Pid::new(pid_raw))
}

#[cfg(target_arch = "x86_64")]
fn cleanup_user_test_process(pid: crate::scheduler::process::Pid) {
    let _ = crate::scheduler::process::process_manager().terminate(pid);
    let _ = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .remove_process(pid);
    crate::scheduler::process::process_manager().reap();
}

#[cfg(target_arch = "x86_64")]
pub fn enter_user_mode_test() -> Result<(), &'static str> {
    let pid = allocate_user_test_pid()?;
    let mut space = crate::arch::mmu::AddressSpace::new()?;
    let user_stack = prepare_user_test_space(&mut space)?;
    let bp_before = crate::arch::x86::x86_64_runtime::exception_count(3);

    crate::scheduler::process::process_manager()
        .temporal_spawn_with_pid(pid, "user-test", None)
        .map_err(|e| e.as_str())?;

    let mut process = crate::scheduler::process::Process::new(pid, "user-test", None);
    process.priority = crate::scheduler::process::ProcessPriority::Normal;

    if let Err(err) = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .add_user_process(process, Box::new(space), USER_CODE_ADDR as u32, user_stack)
    {
        let _ = crate::scheduler::process::process_manager().terminate(pid);
        crate::scheduler::process::process_manager().reap();
        return Err(err);
    }

    let deadline = crate::scheduler::pit::get_ticks().saturating_add(300);
    while crate::scheduler::pit::get_ticks() < deadline {
        crate::scheduler::slice_scheduler::yield_now();
        if crate::arch::x86::x86_64_runtime::exception_count(3) == bp_before {
            continue;
        }
        cleanup_user_test_process(pid);
        return Ok(());
    }

    cleanup_user_test_process(pid);
    Err("user-test timed out")
}

#[cfg(target_arch = "aarch64")]
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

#[cfg(target_arch = "aarch64")]
fn cleanup_user_test_process(pid: crate::scheduler::process::Pid) {
    let _ = crate::scheduler::process::process_manager().terminate(pid);
    let _ = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .remove_process(pid);
    crate::scheduler::process::process_manager().reap();
}

#[cfg(target_arch = "aarch64")]
pub fn enter_user_mode_test() -> Result<(), &'static str> {
    let pid = allocate_user_test_pid()?;
    let mut space = crate::arch::mmu::AddressSpace::new_from_kernel_root()?;
    let user_stack = prepare_user_test_space(&mut space)?;
    let brk_before = crate::arch::aarch64::aarch64_vectors::brk_exception_count();

    crate::scheduler::process::process_manager()
        .temporal_spawn_with_pid(pid, "user-test", None)
        .map_err(|e| e.as_str())?;

    let mut process = crate::scheduler::process::Process::new(pid, "user-test", None);
    process.priority = crate::scheduler::process::ProcessPriority::Normal;

    if let Err(err) = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .add_user_process(process, Box::new(space), USER_CODE_ADDR as u32, user_stack)
    {
        let _ = crate::scheduler::process::process_manager().terminate(pid);
        return Err(err);
    }

    let deadline = crate::scheduler::pit::get_ticks().saturating_add(300);
    while crate::scheduler::pit::get_ticks() < deadline {
        crate::scheduler::slice_scheduler::yield_now();
        if crate::arch::aarch64::aarch64_vectors::brk_exception_count() == brk_before {
            continue;
        }

        let snap = crate::arch::aarch64::aarch64_vectors::last_brk_snapshot();
        let brk_imm = crate::arch::aarch64::aarch64_vectors::last_brk_imm16();
        cleanup_user_test_process(pid);

        if snap.slot != crate::arch::aarch64::aarch64_vectors::VectorSlot::LowerElA64Sync as u8 {
            return Err("user-test trap came from wrong vector slot");
        }
        if brk_imm == 0 {
            return Ok(());
        }
        return Err("user-test EL0 stub reported failure");
    }

    cleanup_user_test_process(pid);
    Err("user-test timed out")
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct ForkTestSnapshot {
    fork_ret: u32,
    observed_pid: u32,
    marker: u8,
    #[allow(dead_code)]
    errno: u32,
    phys: usize,
}

#[cfg(target_arch = "x86_64")]
fn snapshot_fork_test_page(
    space: &crate::arch::mmu::AddressSpace,
) -> Result<ForkTestSnapshot, &'static str> {
    let phys = space
        .virt_to_phys(USER_DATA_ADDR)
        .ok_or("fork-test data page not mapped")?;
    let mut buf = [0u8; 16];
    copy_from_user(space, USER_DATA_ADDR, &mut buf)?;
    Ok(ForkTestSnapshot {
        fork_ret: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        observed_pid: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        marker: buf[8],
        errno: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        phys,
    })
}

#[cfg(target_arch = "x86_64")]
fn find_child_fork_pid(parent_pid: crate::scheduler::process::Pid) -> Option<crate::scheduler::process::Pid> {
    let scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
    scheduler
        .list_processes()
        .into_iter()
        .find_map(|(pid, info)| {
            if pid != parent_pid
                && info.process.parent == Some(parent_pid)
                && info.process.name_str() == "fork-test"
            {
                Some(pid)
            } else {
                None
            }
        })
}

#[cfg(target_arch = "x86_64")]
fn cleanup_fork_test_process(pid: crate::scheduler::process::Pid) {
    let _ = crate::scheduler::process::process_manager().terminate(pid);
    let _ = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .remove_process(pid);
    crate::scheduler::process::process_manager().reap();
}

#[cfg(target_arch = "x86_64")]
pub fn run_fork_test() -> Result<(), &'static str> {
    let parent_pid = allocate_user_test_pid()?;
    let mut space = crate::arch::mmu::AddressSpace::new()?;
    let user_stack = prepare_user_fork_test_space(&mut space)?;

    crate::scheduler::process::process_manager()
        .temporal_spawn_with_pid(parent_pid, "fork-test", None)
        .map_err(|e| e.as_str())?;

    let mut process = crate::scheduler::process::Process::new(parent_pid, "fork-test", None);
    process.priority = crate::scheduler::process::ProcessPriority::Normal;

    if let Err(err) = crate::scheduler::slice_scheduler::scheduler()
        .lock()
        .add_user_process(process, Box::new(space), USER_CODE_ADDR as u32, user_stack)
    {
        let _ = crate::scheduler::process::process_manager().terminate(parent_pid);
        return Err(err);
    }

    let deadline = crate::scheduler::pit::get_ticks().saturating_add(300);
    let mut child_pid = None;

    while crate::scheduler::pit::get_ticks() < deadline {
        crate::scheduler::slice_scheduler::yield_now();

        if child_pid.is_none() {
            child_pid = find_child_fork_pid(parent_pid);
        }

        let Some(child_pid) = child_pid else {
            continue;
        };

        let (parent_snapshot, child_snapshot) = {
            let scheduler = crate::scheduler::slice_scheduler::scheduler().lock();
            let parent_space = scheduler
                .get_process_info(parent_pid)
                .and_then(|info| info.address_space.as_ref())
                .ok_or("fork-test parent missing")?;
            let child_space = scheduler
                .get_process_info(child_pid)
                .and_then(|info| info.address_space.as_ref())
                .ok_or("fork-test child missing")?;
            (
                snapshot_fork_test_page(parent_space)?,
                snapshot_fork_test_page(child_space)?,
            )
        };

        if parent_snapshot.marker == 0xEE || child_snapshot.marker == 0xEE {
            cleanup_fork_test_process(parent_pid);
            cleanup_fork_test_process(child_pid);
            return Err("fork-test user stub reported syscall failure");
        }

        if parent_snapshot.marker != 0xAA || child_snapshot.marker != 0x55 {
            continue;
        }

        let parent_ok =
            parent_snapshot.fork_ret == child_pid.0 && parent_snapshot.observed_pid == parent_pid.0;
        let child_ok = child_snapshot.fork_ret == 0 && child_snapshot.observed_pid == child_pid.0;
        let cow_ok = parent_snapshot.phys != child_snapshot.phys;

        cleanup_fork_test_process(parent_pid);
        cleanup_fork_test_process(child_pid);

        if !parent_ok {
            return Err("fork-test parent return mismatch");
        }
        if !child_ok {
            return Err("fork-test child return mismatch");
        }
        if !cow_ok {
            return Err("fork-test COW page did not diverge");
        }
        return Ok(());
    }

    cleanup_fork_test_process(parent_pid);
    if let Some(child_pid) = child_pid {
        cleanup_fork_test_process(child_pid);
    }
    Err("fork-test timed out")
}

#[cfg(not(target_arch = "x86_64"))]
pub fn run_fork_test() -> Result<(), &'static str> {
    Err("fork-test requires x86_64 user-mode runtime")
}
