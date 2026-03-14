//! File-system helpers wrapping WASI path_open / fd_read / fd_write.

use crate::raw::wasi;

// WASI open flags
pub const OFLAGS_CREAT: u32 = 0x01;
pub const OFLAGS_DIRECTORY: u32 = 0x02;
pub const OFLAGS_EXCL: u32 = 0x04;
pub const OFLAGS_TRUNC: u32 = 0x08;

// WASI fdflags
pub const FDFLAGS_APPEND: u32 = 0x01;
pub const FDFLAGS_NONBLOCK: u32 = 0x02;

// fs_rights: read + write
const RIGHTS_RW: u64 = 0x0000_0000_0000_000F;

/// Open a file relative to the pre-opened root directory (fd 3).
///
/// Returns `None` if the path could not be opened.
pub fn open(path: &str, oflags: u32, fdflags: u32) -> Option<u32> {
    const FD_SCRATCH: u32 = 76;
    let errno = unsafe {
        wasi::path_open(
            3, // pre-opened root dir fd
            0, // LOOKUP_SYMLINK_FOLLOW
            path.as_ptr() as u32,
            path.len() as u32,
            oflags,
            RIGHTS_RW,
            RIGHTS_RW,
            fdflags,
            FD_SCRATCH,
        )
    };
    if errno != 0 {
        return None;
    }
    Some(unsafe { (FD_SCRATCH as usize as *const u32).read_unaligned() })
}

/// Read the entire contents of a file at `path` into `buf`.
/// Returns the number of bytes read.
pub fn read_all(path: &str, buf: &mut [u8]) -> usize {
    let fd = match open(path, 0, 0) {
        None => return 0,
        Some(f) => f,
    };
    let n = unsafe { crate::io::read(fd, buf) };
    unsafe { wasi::fd_close(fd) };
    n
}

/// Write `data` to a file at `path` (create or truncate).
pub fn write_all(path: &str, data: &[u8]) -> bool {
    let fd = match open(path, OFLAGS_CREAT | OFLAGS_TRUNC, 0) {
        None => return false,
        Some(f) => f,
    };
    let n = unsafe { crate::io::write(fd, data) };
    unsafe { wasi::fd_close(fd) };
    n == data.len()
}
