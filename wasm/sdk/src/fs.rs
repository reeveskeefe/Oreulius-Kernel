//! File-system helpers wrapping the Oreulius WASI Preview 1 surface.

use core::ops::{BitOr, BitOrAssign};

use crate::raw::wasi;
pub use crate::raw::wasi::Errno;

pub const PREOPEN_ROOT_FD: u32 = 3;

// WASI open flags
pub const OFLAGS_CREAT: u32 = 0x01;
pub const OFLAGS_DIRECTORY: u32 = 0x02;
pub const OFLAGS_EXCL: u32 = 0x04;
pub const OFLAGS_TRUNC: u32 = 0x08;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u64);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEEK: Self = Self(1 << 2);
    pub const TELL: Self = Self(1 << 3);
    pub const READ_WRITE: Self = Self(
        Self::READ.bits() | Self::WRITE.bits() | Self::SEEK.bits() | Self::TELL.bits(),
    );
    pub const ALL: Self = Self(u64::MAX);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 == u64::MAX || (self.0 & other.0) == other.0
    }
}

impl BitOr for Rights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Rights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct FdFlags(u16);

impl FdFlags {
    pub const NONE: Self = Self(0);
    pub const APPEND: Self = Self(0x01);
    pub const NONBLOCK: Self = Self(0x02);

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn from_bits_truncate(bits: u16) -> Self {
        Self(bits & (Self::APPEND.bits() | Self::NONBLOCK.bits()))
    }
}

impl BitOr for FdFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FdFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct FstFlags(u32);

impl FstFlags {
    pub const NONE: Self = Self(0);
    pub const ATIM: Self = Self(1 << 0);
    pub const ATIM_NOW: Self = Self(1 << 1);
    pub const MTIM: Self = Self(1 << 2);
    pub const MTIM_NOW: Self = Self(1 << 3);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for FstFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FstFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FdStat {
    pub filetype: u8,
    pub flags: FdFlags,
    pub rights_base: Rights,
    pub rights_inheriting: Rights,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub ino: u64,
    pub filetype: u8,
    pub nlink: u64,
    pub size: u64,
    pub atim: u64,
    pub mtim: u64,
    pub ctim: u64,
}

#[repr(C)]
struct RawFdStat {
    filetype: u8,
    _pad: u8,
    flags: u16,
    _pad2: u32,
    rights_base: u64,
    rights_inheriting: u64,
}

#[repr(C)]
struct RawFileStat {
    _dev: u64,
    ino: u64,
    filetype: u8,
    _pad: [u8; 7],
    nlink: u64,
    size: u64,
    atim: u64,
    mtim: u64,
    ctim: u64,
}

fn errno_result(code: u32) -> Result<(), Errno> {
    match Errno::from(code) {
        Errno::Success => Ok(()),
        err => Err(err),
    }
}

/// Open a file relative to the pre-opened root directory (fd 3).
pub fn open(path: &str, oflags: u32, fdflags: u32) -> Option<u32> {
    open_with(
        path,
        oflags,
        Rights::READ_WRITE,
        Rights::READ_WRITE,
        FdFlags::from_bits_truncate(fdflags as u16),
    )
    .ok()
}

/// Open a file with explicit rights and fdflags.
pub fn open_with(
    path: &str,
    oflags: u32,
    rights_base: Rights,
    rights_inheriting: Rights,
    fdflags: FdFlags,
) -> Result<u32, Errno> {
    let mut fd = 0u32;
    errno_result(unsafe {
        wasi::path_open(
            PREOPEN_ROOT_FD,
            0,
            path.as_ptr() as u32,
            path.len() as u32,
            oflags,
            rights_base.bits(),
            rights_inheriting.bits(),
            fdflags.bits() as u32,
            (&mut fd as *mut u32) as u32,
        )
    })?;
    Ok(fd)
}

pub fn fd_advise(fd: u32, offset: u64, len: u64) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_advise(fd, offset, len) })
}

pub fn fd_allocate(fd: u32, offset: u64, len: u64) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_allocate(fd, offset, len) })
}

pub fn fd_datasync(fd: u32) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_datasync(fd) })
}

pub fn fd_fdstat_get(fd: u32) -> Result<FdStat, Errno> {
    let mut raw = RawFdStat {
        filetype: 0,
        _pad: 0,
        flags: 0,
        _pad2: 0,
        rights_base: 0,
        rights_inheriting: 0,
    };
    errno_result(unsafe { wasi::fd_fdstat_get(fd, (&mut raw as *mut RawFdStat) as u32) })?;
    Ok(FdStat {
        filetype: raw.filetype,
        flags: FdFlags::from_bits_truncate(raw.flags),
        rights_base: Rights(raw.rights_base),
        rights_inheriting: Rights(raw.rights_inheriting),
    })
}

pub fn fd_fdstat_set_flags(fd: u32, flags: FdFlags) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_fdstat_set_flags(fd, flags.bits() as u32) })
}

pub fn fd_fdstat_set_rights(
    fd: u32,
    rights_base: Rights,
    rights_inheriting: Rights,
) -> Result<(), Errno> {
    errno_result(unsafe {
        wasi::fd_fdstat_set_rights(fd, rights_base.bits(), rights_inheriting.bits())
    })
}

pub fn fd_filestat_get(fd: u32) -> Result<FileStat, Errno> {
    let mut raw = RawFileStat {
        _dev: 0,
        ino: 0,
        filetype: 0,
        _pad: [0; 7],
        nlink: 0,
        size: 0,
        atim: 0,
        mtim: 0,
        ctim: 0,
    };
    errno_result(unsafe { wasi::fd_filestat_get(fd, (&mut raw as *mut RawFileStat) as u32) })?;
    Ok(FileStat {
        ino: raw.ino,
        filetype: raw.filetype,
        nlink: raw.nlink,
        size: raw.size,
        atim: raw.atim,
        mtim: raw.mtim,
        ctim: raw.ctim,
    })
}

pub fn fd_filestat_set_size(fd: u32, size: u64) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_filestat_set_size(fd, size) })
}

pub fn fd_filestat_set_times(
    fd: u32,
    atim: u64,
    mtim: u64,
    fst_flags: FstFlags,
) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_filestat_set_times(fd, atim, mtim, fst_flags.bits()) })
}

pub fn fd_renumber(fd: u32, to: u32) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_renumber(fd, to) })
}

pub fn fd_sync(fd: u32) -> Result<(), Errno> {
    errno_result(unsafe { wasi::fd_sync(fd) })
}

pub fn path_filestat_set_times(
    path: &str,
    atim: u64,
    mtim: u64,
    fst_flags: FstFlags,
) -> Result<(), Errno> {
    errno_result(unsafe {
        wasi::path_filestat_set_times(
            PREOPEN_ROOT_FD,
            path.as_ptr() as u32,
            path.len() as u32,
            atim,
            mtim,
            fst_flags.bits(),
        )
    })
}

pub fn proc_raise(signal: u32) -> Result<(), Errno> {
    errno_result(unsafe { wasi::proc_raise(signal) })
}

/// Read the entire contents of a file at `path` into `buf`.
/// Returns the number of bytes read.
pub fn read_all(path: &str, buf: &mut [u8]) -> usize {
    let fd = match open_with(path, 0, Rights::READ | Rights::SEEK | Rights::TELL, Rights::NONE, FdFlags::NONE) {
        Ok(fd) => fd,
        Err(_) => return 0,
    };
    let n = unsafe { crate::io::read(fd, buf) };
    unsafe { wasi::fd_close(fd) };
    n
}

/// Write `data` to a file at `path` (create or truncate).
pub fn write_all(path: &str, data: &[u8]) -> bool {
    let fd = match open_with(
        path,
        OFLAGS_CREAT | OFLAGS_TRUNC,
        Rights::READ_WRITE,
        Rights::READ_WRITE,
        FdFlags::NONE,
    ) {
        Ok(fd) => fd,
        Err(_) => return false,
    };
    let n = unsafe { crate::io::write(fd, data) };
    unsafe { wasi::fd_close(fd) };
    n == data.len()
}

#[cfg(test)]
mod tests {
    use super::{FdFlags, FstFlags, Rights};

    #[test]
    fn rights_and_flags_bitops_are_stable() {
        let rw = Rights::READ | Rights::WRITE;
        assert!(rw.contains(Rights::READ));
        assert!(rw.contains(Rights::WRITE));
        assert!(!rw.contains(Rights::SEEK));

        let flags = FdFlags::APPEND | FdFlags::NONBLOCK;
        assert!(flags.contains(FdFlags::APPEND));
        assert!(flags.contains(FdFlags::NONBLOCK));
        assert_eq!(flags.bits(), 0x03);
    }

    #[test]
    fn fstflags_bitops_are_stable() {
        let flags = FstFlags::ATIM | FstFlags::MTIM_NOW;
        assert!(flags.contains(FstFlags::ATIM));
        assert!(flags.contains(FstFlags::MTIM_NOW));
        assert!(!flags.contains(FstFlags::ATIM_NOW));
    }
}
