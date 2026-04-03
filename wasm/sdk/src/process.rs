//! Process lifecycle management.

use crate::raw::{oreulius, wasi};

/// Terminate the current WASM process with the given exit code.
///
/// This calls `proc_exit` which never returns.
#[inline]
pub fn exit(code: u32) -> ! {
    unsafe { wasi::proc_exit(code) }
}

/// Spawn a child WASM process from a byte slice already in linear memory.
///
/// `wasm_bytes` must be a valid WASM binary.
///
/// Returns the child PID on success, or `None` if the spawn failed.
/// The child is started asynchronously — it enters the scheduler's ready
/// queue after the current host function returns.
///
/// # Safety
/// The bytes slice must live in the module's linear memory.
pub unsafe fn spawn(wasm_bytes: &[u8]) -> Option<u32> {
    let pid = oreulius::proc_spawn(wasm_bytes.as_ptr() as u32, wasm_bytes.len() as u32);
    if pid == 0 || pid == u32::MAX {
        None
    } else {
        Some(pid)
    }
}

/// Cooperatively yield the current CPU time slice to the scheduler.
///
/// Equivalent to `sched_yield` in POSIX.
pub fn yield_now() {
    unsafe { oreulius::proc_yield() }
}

/// Sleep for approximately `ms` milliseconds (1 PIT tick ≈ 1 ms).
pub fn sleep_ms(ms: u32) {
    unsafe { oreulius::proc_sleep(ms) }
}
