//! # oreulius-sdk
//!
//! Typed, zero-overhead Rust bindings for the **Oreulius OS** WASM host ABI.
//!
//! ## Overview
//!
//! Oreulius exposes two sets of host functions to WASM modules:
//!
//! 1. **WASI Preview 1** (IDs 45–90) — standard `wasi_snapshot_preview1`
//!    functions: file I/O, clocks, sockets, environment, etc.
//! 2. **Oreulius native ABI** (IDs 0–44, 100–108) — capability messaging,
//!    process management, IPC channels, JIT-compiled capabilities,
//!    cross-language polyglot kernel services, and kernel observer events.
//!
//! This crate wraps both in safe-ish Rust types so you can write Oreulius
//! applications in Rust without calling raw WASM imports yourself.
//!
//! ## Quick-start
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//!
//! use oreulius_sdk::{io, process};
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     io::print("Hello from Oreulius SDK!\n");
//!     process::exit(0);
//! }
//! ```
//!
//! ## Build
//!
//! ```text
//! cargo build --target wasm32-wasi --release
//! ```
//!
//! Then load the resulting `.wasm` inside the Oreulius shell:
//! ```text
//! wasm myapp.wasm
//! ```
//!
//! ## Feature flags
//!
//! | Flag        | Default | Description |
//! |-------------|---------|-------------|
//! | `alloc`     | off     | Enable heap allocation via `wasm_alloc` |
//! | `panic_log` | off     | Forward panics to `fd_write(stderr)` instead of `unreachable` |

#![no_std]
#![allow(dead_code)]

// Pull in core + (optionally) alloc.
extern crate core;

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// Re-exported sub-modules
// ---------------------------------------------------------------------------

pub mod capgraph;
pub mod entangle;
pub mod fs;
pub mod io;
pub mod ipc;
pub mod mesh;
pub mod net;
pub mod observer;
pub mod policy;
pub mod polyglot;
pub mod process;
pub mod temporal;
pub mod thread;
pub mod time;

// ---------------------------------------------------------------------------
// Raw FFI layer — `unsafe` bindings directly to WASM host imports.
// Normal users should prefer the typed wrappers in the sub-modules above.
// ---------------------------------------------------------------------------

pub mod raw {
    pub mod oreulius;
    pub mod wasi;
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std binary crates)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In release builds we emit `unreachable` which traps the WASM instance.
    // Build with feature "panic_log" to get a textual error on stderr first.
    #[cfg(feature = "panic_log")]
    {
        let msg = b"PANIC\n";
        unsafe {
            // fd_write(stderr=2, iovec at scratch, 1 iovec, nwritten at scratch+8)
            // We can't heap-allocate here, so we use a fixed stack buffer.
            let mut scratch = [0u8; 16];
            let ptr = msg.as_ptr() as u32;
            let len = msg.len() as u32;
            scratch[0..4].copy_from_slice(&ptr.to_le_bytes());
            scratch[4..8].copy_from_slice(&len.to_le_bytes());
            raw::wasi::fd_write(2, scratch.as_ptr() as u32, 1, 8);
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::unreachable()
    }
    #[cfg(not(target_arch = "wasm32"))]
    loop {
        core::hint::spin_loop();
    }
}
