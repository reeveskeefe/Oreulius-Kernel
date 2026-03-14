//! Cooperative WASM thread helpers.

use crate::raw::oreulia;

/// Opaque cooperative WASM thread identifier.
pub type ThreadId = i32;

/// Result of a non-blocking thread join attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinStatus {
    /// The target thread is still running.
    Pending,
    /// The target thread no longer exists.
    NotFound,
    /// The target thread finished and returned an exit code.
    Done(i32),
}

/// Spawn a cooperative WASM thread at `func_idx` with one `i32` argument.
///
/// Returns the new thread ID on success.
pub unsafe fn spawn(func_idx: u32, arg: i32) -> Option<ThreadId> {
    let tid = oreulia::thread_spawn(func_idx as i32, arg);
    if tid < 0 {
        None
    } else {
        Some(tid)
    }
}

/// Attempt to join a cooperative WASM thread without blocking the whole module.
pub fn join(tid: ThreadId) -> JoinStatus {
    let result = unsafe { oreulia::thread_join(tid) };
    match result {
        -1 => JoinStatus::Pending,
        0 => JoinStatus::NotFound,
        code => JoinStatus::Done(code),
    }
}

/// Return the current cooperative WASM thread ID.
///
/// The main instance returns `0`.
pub fn current_id() -> ThreadId {
    unsafe { oreulia::thread_id() }
}

/// Yield the current CPU quantum.
pub fn yield_now() {
    unsafe { oreulia::thread_yield() }
}

/// Exit the current cooperative WASM thread.
pub fn exit(code: i32) {
    unsafe { oreulia::thread_exit(code) }
}
