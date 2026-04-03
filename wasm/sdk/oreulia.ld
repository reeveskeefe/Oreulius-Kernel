//! Linker script for Oreulius WASM applications.
//!
//! The default `wasm-ld` layout already works for most apps.  This file
//! documents the expected memory layout and can be passed to `wasm-ld` via
//! `--script oreulius.ld` for custom builds.
//!
//! Linear memory layout:
//!
//! ```text
//!  Address  Size   Purpose
//!  0x0000    64    SDK scratch area (iovec, nwritten, clock scratch)
//!  0x0040   192    Reserved / user scratch
//!  0x0100   ---    DATA segment (read-write globals, string literals)
//!  ...      ---    BSS / zero-init
//!  ...      ---    Stack (grows down from top of initial memory page)
//!  0xFFFF   ---    Heap (grows up, only with `alloc` feature)
//! ```
//!
//! The first 64 bytes (0x0000–0x003F) are used by the SDK I/O helpers for
//! iovec construction.  **Do not store application data in that range.**
//!
//! # Custom entry points
//!
//! By default `wasm-ld` expects `_start` as the entry export.  The Oreulius
//! runtime calls `func[export "_start"]` after instantiation.  If you want a
//! different name, export it and call it from `_start`.
