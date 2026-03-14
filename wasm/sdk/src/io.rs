//! High-level I/O helpers.
//!
//! These functions allocate iovec structs on the WASM stack (as local
//! variables) so there is no heap allocation in the hot path.

use crate::raw::wasi;

// ---------------------------------------------------------------------------
// Scratch area for iovec pairs — we use fixed stack addresses in the first
// 64 bytes of linear memory.  Callers must not alias this range.
// ---------------------------------------------------------------------------

const IOVEC_PTR: u32 = 0; // iovec[0].buf_ptr (4 bytes)
const IOVEC_LEN: u32 = 4; // iovec[0].buf_len (4 bytes)
const NWRITTEN_PTR: u32 = 8; // nwritten output  (4 bytes)
const NREAD_PTR: u32 = 8; // nread   output   (4 bytes)

// ---------------------------------------------------------------------------
// Helpers to poke values into linear memory via WASM store instructions.
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn store_u32(addr: u32, val: u32) {
    let ptr = addr as usize as *mut u32;
    ptr.write_unaligned(val);
}

#[inline(always)]
unsafe fn load_u32(addr: u32) -> u32 {
    let ptr = addr as usize as *const u32;
    ptr.read_unaligned()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write a byte slice to the given file descriptor.
///
/// Returns the number of bytes actually written, or 0 on error.
///
/// # Safety
/// The iovec scratch area lives at linear-memory addresses 0–11.  Do not
/// use those bytes for other purposes concurrently.
pub unsafe fn write(fd: u32, data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    store_u32(IOVEC_PTR, data.as_ptr() as u32);
    store_u32(IOVEC_LEN, data.len() as u32);
    store_u32(NWRITTEN_PTR, 0);

    let errno = wasi::fd_write(fd, IOVEC_PTR, 1, NWRITTEN_PTR);
    if errno != 0 {
        return 0;
    }
    load_u32(NWRITTEN_PTR) as usize
}

/// Read bytes from the given file descriptor into `buf`.
///
/// Returns the number of bytes read (may be 0 if no data is available).
///
/// # Safety
/// Same scratch-area caveats as `write`.
pub unsafe fn read(fd: u32, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    store_u32(IOVEC_PTR, buf.as_mut_ptr() as u32);
    store_u32(IOVEC_LEN, buf.len() as u32);
    store_u32(NREAD_PTR, 0);

    let errno = wasi::fd_read(fd, IOVEC_PTR, 1, NREAD_PTR);
    if errno != 0 {
        return 0;
    }
    load_u32(NREAD_PTR) as usize
}

/// Write a string slice to stdout (fd 1).
pub unsafe fn print(s: &str) -> usize {
    write(1, s.as_bytes())
}

/// Write a string slice to stderr (fd 2).
pub unsafe fn eprint(s: &str) -> usize {
    write(2, s.as_bytes())
}

/// Write a string to stdout followed by a newline.
pub unsafe fn println(s: &str) -> usize {
    let n = write(1, s.as_bytes());
    write(1, b"\n");
    n + 1
}
