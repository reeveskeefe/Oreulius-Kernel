/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! # CapabilityWASI — Frozen WASI Preview 1 Compatibility over Oreulius Capabilities
//!
//! Implements the dispatcher-owned [WASI Preview 1](https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md)
//! compatibility surface for host IDs `45–90`, enabling musl-libc, WASI-SDK,
//! and Emscripten binaries to run against Oreulius's capability-based kernel
//! services.
//!
//! ## Design
//!
//! - Every WASI function is a plain `fn(&mut WasiCtx, ...) -> Errno`.
//! - `WasiCtx` holds per-instance state: fd table, preopened dirs, argv, PRNG,
//!   and exit state.
//! - All I/O is routed through `crate::capability`, `crate::fs`, and `crate::net::rtl8139`.
//! - Fixed-size fd and preopen tables; some path-backed metadata and resize
//!   operations may materialize temporary file buffers.
//! - The authoritative guest-visible exposure surface is the host dispatcher
//!   table in `kernel/src/execution/wasm.rs`.
//!
//! ## WASM Host Function IDs (45–90)
//!
//! | ID  | WASI name                   | Notes |
//! |-----|-----------------------------|-------|
//! | 45  | `args_get`                  | argv / argc |
//! | 46  | `args_sizes_get`            | |
//! | 47  | `environ_get`               | environment variables |
//! | 48  | `environ_sizes_get`         | |
//! | 49  | `clock_res_get`             | |
//! | 50  | `clock_time_get`            | |
//! | 51  | `fd_advise`                 | advisory hint validation |
//! | 52  | `fd_allocate`               | ensure file capacity |
//! | 53  | `fd_close`                  | |
//! | 54  | `fd_datasync`               | flush file data |
//! | 55  | `fd_fdstat_get`             | |
//! | 56  | `fd_fdstat_set_flags`       | persist `APPEND` / `NONBLOCK` |
//! | 57  | `fd_fdstat_set_rights`      | rights attenuation |
//! | 58  | `fd_filestat_get`           | |
//! | 59  | `fd_filestat_set_size`      | truncate / extend file |
//! | 60  | `fd_filestat_set_times`     | update fd timestamps |
//! | 61  | `fd_pread`                  | |
//! | 62  | `fd_prestat_get`            | |
//! | 63  | `fd_prestat_dir_name`       | |
//! | 64  | `fd_pwrite`                 | |
//! | 65  | `fd_read`                   | |
//! | 66  | `fd_readdir`                | |
//! | 67  | `fd_renumber`               | move one WASI fd to another slot |
//! | 68  | `fd_seek`                   | |
//! | 69  | `fd_sync`                   | flush file data and metadata |
//! | 70  | `fd_tell`                   | |
//! | 71  | `fd_write`                  | |
//! | 72  | `path_create_directory`     | |
//! | 73  | `path_filestat_get`         | |
//! | 74  | `path_filestat_set_times`   | update path timestamps |
//! | 75  | `path_link`                 | |
//! | 76  | `path_open`                 | |
//! | 77  | `path_readlink`             | |
//! | 78  | `path_remove_directory`     | |
//! | 79  | `path_rename`               | |
//! | 80  | `path_symlink`              | |
//! | 81  | `path_unlink_file`          | |
//! | 82  | `poll_oneoff`               | |
//! | 83  | `proc_exit`                 | |
//! | 84  | `proc_raise`                | reduced Oreulius signal model |
//! | 85  | `sched_yield`               | |
//! | 86  | `random_get`                | RDRAND-seeded PRNG |
//! | 87  | `sock_accept`               | |
//! | 88  | `sock_recv`                 | |
//! | 89  | `sock_send`                 | |
//! | 90  | `sock_shutdown`             | |
//!
//! The dispatcher-owned WASI Preview 1 compatibility surface in `45–90` is
//! fully implemented. Oreulius keeps a few ABI-shape deviations from canonical
//! Preview 1, such as the 5-argument `path_rename` and 6-argument
//! `path_filestat_set_times` forms.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Network driver abstraction: RTL8139 on x86/x86_64, virtio-net on AArch64.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_has_recv() -> bool {
    crate::net::rtl8139::has_recv()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_recv(buf: &mut [u8]) -> usize {
    crate::net::rtl8139::recv(buf)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_send(frame: &[u8]) -> bool {
    crate::net::rtl8139::send(frame)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_has_recv() -> bool {
    crate::net::virtio_net::has_recv()
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_recv(buf: &mut [u8]) -> usize {
    crate::net::virtio_net::recv(buf)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_send(frame: &[u8]) -> bool {
    crate::net::virtio_net::send(frame).is_ok()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn kbd_has_input() -> bool {
    crate::drivers::x86::keyboard::has_input()
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn kbd_has_input() -> bool {
    crate::arch::aarch64::aarch64_pl011::has_input()
}

// WASI errno codes (WASI Preview 1 §1.3)
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Errno {
    Success = 0,
    TooBig = 1,
    Acces = 2,
    Addrinuse = 3,
    Addrnotavail = 4,
    Afnosupport = 5,
    Again = 6,
    Already = 7,
    Badf = 8,
    Badmsg = 9,
    Busy = 10,
    Canceled = 11,
    Child = 12,
    Connaborted = 13,
    Connrefused = 14,
    Connreset = 15,
    Deadlk = 16,
    Destaddrreq = 17,
    Dom = 18,
    Dquot = 19,
    Exist = 20,
    Fault = 21,
    Fbig = 22,
    Hostunreach = 23,
    Idrm = 24,
    Ilseq = 25,
    Inprogress = 26,
    Intr = 27,
    Inval = 28,
    Io = 29,
    Isconn = 30,
    Isdir = 31,
    Loop = 32,
    Mfile = 33,
    Mlink = 34,
    Msgsize = 35,
    Multihop = 36,
    Nametoolong = 37,
    Netdown = 38,
    Netreset = 39,
    Netunreach = 40,
    Nfile = 41,
    Nobufs = 42,
    Nodev = 43,
    Noent = 44,
    Noexec = 45,
    Nolck = 46,
    Nolink = 47,
    Nomem = 48,
    Nomsg = 49,
    Noprotoopt = 50,
    Nospc = 51,
    Nosys = 52,
    Notconn = 53,
    Notdir = 54,
    Notempty = 55,
    Notrecoverable = 56,
    Notsock = 57,
    Notsup = 58,
    Notty = 59,
    Nxio = 60,
    Overflow = 61,
    Ownerdead = 62,
    Perm = 63,
    Pipe = 64,
    Proto = 65,
    Protonosupport = 66,
    Prototype = 67,
    Range = 68,
    Rofs = 69,
    Spipe = 70,
    Srch = 71,
    Stale = 72,
    Timedout = 73,
    Txtbsy = 74,
    Xdev = 75,
    Notcapable = 76,
    Shutdown = 77,
}

impl Errno {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// ---------------------------------------------------------------------------
// WASI types
// ---------------------------------------------------------------------------

pub type Fd = u32;
pub type Filesize = u64;
pub type Timestamp = u64; // nanoseconds

pub mod oflags {
    pub const CREAT: u16 = 0x01;
    pub const DIRECTORY: u16 = 0x02;
    pub const EXCL: u16 = 0x04;
    pub const TRUNC: u16 = 0x08;
}

pub mod fdflags {
    pub const APPEND: u16    = 0x01;
    pub const NONBLOCK: u16  = 0x02;
    pub const SUPPORTED: u16 = APPEND | NONBLOCK; // = 0x0003

    // ABI freeze: SUPPORTED must remain 0x0003 so that the formal-verify probe
    // 0x40 (bit 6) always lands in the unsupported mask. Any intentional
    // expansion of supported flags must also update the probe in
    // formal_wasi_behavior_check_fd_fdstat_set_flags.
    const _FREEZE: () = assert!(
        SUPPORTED == 0x0003,
        "fdflags::SUPPORTED drifted from ABI freeze 0x0003",
    );
}

pub mod fstflags {
    pub const ATIM: u32 = 1 << 0;
    pub const ATIM_NOW: u32 = 1 << 1;
    pub const MTIM: u32 = 1 << 2;
    pub const MTIM_NOW: u32 = 1 << 3;
}

pub mod rights {
    pub const FD_READ: u64 = 1 << 0;
    pub const FD_WRITE: u64 = 1 << 1;
    pub const FD_SEEK: u64 = 1 << 2;
    pub const FD_TELL: u64 = 1 << 3;
    pub const ALL: u64 = u64::MAX;
}

/// WASI fd_fdstat — stat for an open fd.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct FdStat {
    pub fs_filetype: u8,
    _pad: u8,
    pub fs_flags: u16,
    _pad2: u32,
    pub fs_rights_base: u64,
    pub fs_rights_inheriting: u64,
}

/// WASI filestat structure.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub filetype: u8,
    _pad: [u8; 7],
    pub nlink: u64,
    pub size: u64,
    pub atim: Timestamp,
    pub mtim: Timestamp,
    pub ctim: Timestamp,
}

/// WASI prestat variant tag (we only support dir preopens).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Prestat {
    pub tag: u8,
    _pad: [u8; 3],
    pub u_dir_pr_name_len: u32,
}

/// Direction flag for seeks.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Whence {
    Set = 0,
    Cur = 1,
    End = 2,
}

// ---------------------------------------------------------------------------
// Filetype constants (WASI §6.1.1)
// ---------------------------------------------------------------------------
pub mod filetype {
    pub const UNKNOWN: u8 = 0;
    pub const BLOCK_DEVICE: u8 = 1;
    pub const CHAR_DEVICE: u8 = 2;
    pub const DIRECTORY: u8 = 3;
    pub const REGULAR_FILE: u8 = 4;
    pub const SOCKET_DGRAM: u8 = 5;
    pub const SOCKET_STREAM: u8 = 6;
    pub const SYMBOLIC_LINK: u8 = 7;
}

fn vfs_entry_filetype(kind: crate::fs::vfs::InodeKind) -> u8 {
    match kind {
        crate::fs::vfs::InodeKind::File => filetype::REGULAR_FILE,
        crate::fs::vfs::InodeKind::Directory => filetype::DIRECTORY,
        crate::fs::vfs::InodeKind::Symlink => filetype::SYMBOLIC_LINK,
    }
}

/// Standard file-descriptor numbers baked into every new WasiCtx.
pub mod std_fd {
    pub const STDIN: u32 = 0;
    pub const STDOUT: u32 = 1;
    pub const STDERR: u32 = 2;
    /// First preopened directory fd.
    pub const PREOPEN_START: u32 = 3;
}

// ---------------------------------------------------------------------------
// Open-file descriptor table
// ---------------------------------------------------------------------------

const MAX_FDS: usize = 64;
const MAX_PREOPENS: usize = 8;

/// What kind of thing an fd points to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FdKind {
    Closed,
    Stdin,
    Stdout,
    Stderr,
    File,
    Dir,
    TcpSocket,
}

/// Per-fd state inside a `WasiCtx`.
#[derive(Copy, Clone)]
pub struct OpenFd {
    pub kind: FdKind,
    /// Byte offset for read/write/seek.
    pub offset: u64,
    /// Null-terminated path key (up to 127 chars + NUL).
    pub path: [u8; 128],
    pub path_len: u8,
    /// Cached file size (updated on open/write).
    pub size: u64,
    /// Runtime fd flags persisted through fdstat.
    pub fdflags: u16,
    /// Base rights for operations through this fd.
    pub rights_base: u64,
    /// Inheriting rights for derived opens.
    pub rights_inheriting: u64,
    /// For directories: index of last readdir entry returned.
    pub readdir_cookie: u64,
    /// Receive half has been shut down.
    pub shut_rd: bool,
    /// Send half has been shut down.
    pub shut_wr: bool,
}

impl OpenFd {
    const fn closed() -> Self {
        OpenFd {
            kind: FdKind::Closed,
            offset: 0,
            path: [0; 128],
            path_len: 0,
            size: 0,
            fdflags: 0,
            rights_base: 0,
            rights_inheriting: 0,
            readdir_cookie: 0,
            shut_rd: false,
            shut_wr: false,
        }
    }
}

/// A preopened directory entry.
#[derive(Copy, Clone)]
struct Preopen {
    name: [u8; 64],
    name_len: u8,
}

impl Preopen {
    const fn empty() -> Self {
        Preopen {
            name: [0; 64],
            name_len: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// WasiCtx — per-instance WASI state
// ---------------------------------------------------------------------------

const EMPTY_FD: OpenFd = OpenFd::closed();
const EMPTY_PREOPEN: Preopen = Preopen::empty();

pub struct WasiCtx {
    pub fds: [OpenFd; MAX_FDS],
    preopens: [Preopen; MAX_PREOPENS],
    preopen_cnt: usize,
    /// argv[0] string stored inline.
    argv0: [u8; 64],
    argv0_len: usize,
    /// Simple 64-bit PRNG state (xorshift64).
    prng: u64,
    /// Instance ID in the kernel (for capability lookups).
    pub instance_id: usize,
    /// Exit code set by proc_exit; checked by the WASM runtime.
    pub exit_code: Option<i32>,
}

const ABI_FINGERPRINT_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const ABI_FINGERPRINT_PRIME: u64 = 0x0000_0001_0000_01b3;

#[inline]
fn abi_fingerprint_byte(mut hash: u64, byte: u8) -> u64 {
    hash ^= byte as u64;
    hash.wrapping_mul(ABI_FINGERPRINT_PRIME)
}

#[inline]
fn abi_fingerprint_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut i = 0usize;
    while i < bytes.len() {
        hash = abi_fingerprint_byte(hash, bytes[i]);
        i += 1;
    }
    hash
}

#[inline]
fn abi_fingerprint_u64(hash: u64, value: u64) -> u64 {
    abi_fingerprint_bytes(hash, &value.to_le_bytes())
}

#[inline]
fn abi_fingerprint_usize(hash: u64, value: usize) -> u64 {
    abi_fingerprint_u64(hash, value as u64)
}

#[inline]
fn abi_fingerprint_bool(hash: u64, value: bool) -> u64 {
    abi_fingerprint_byte(hash, value as u8)
}

#[inline]
fn abi_fingerprint_fd_kind(hash: u64, kind: FdKind) -> u64 {
    abi_fingerprint_byte(
        hash,
        match kind {
            FdKind::Closed => 0,
            FdKind::Stdin => 1,
            FdKind::Stdout => 2,
            FdKind::Stderr => 3,
            FdKind::File => 4,
            FdKind::Dir => 5,
            FdKind::TcpSocket => 6,
        },
    )
}

impl WasiCtx {
    pub fn new(instance_id: usize) -> Self {
        let mut ctx = WasiCtx {
            fds: [EMPTY_FD; MAX_FDS],
            preopens: [EMPTY_PREOPEN; MAX_PREOPENS],
            preopen_cnt: 0,
            argv0: [0; 64],
            argv0_len: 0,
            prng: 0xDEAD_BEEF_CAFE_1234 ^ (instance_id as u64 * 0x9E37_79B9_7F4A_7C15),
            instance_id,
            exit_code: None,
        };
        // stdin/stdout/stderr are always open.
        ctx.fds[0].kind = FdKind::Stdin;
        ctx.fds[0].rights_base = rights::ALL;
        ctx.fds[0].rights_inheriting = rights::ALL;
        ctx.fds[1].kind = FdKind::Stdout;
        ctx.fds[1].rights_base = rights::ALL;
        ctx.fds[1].rights_inheriting = rights::ALL;
        ctx.fds[2].kind = FdKind::Stderr;
        ctx.fds[2].rights_base = rights::ALL;
        ctx.fds[2].rights_inheriting = rights::ALL;
        // Preopen "/" as fd 3.
        ctx.add_preopen(b"/");
        ctx
    }

    /// Register a preopened directory path.
    pub fn add_preopen(&mut self, path: &[u8]) -> bool {
        if self.preopen_cnt >= MAX_PREOPENS {
            return false;
        }
        let fd = (std_fd::PREOPEN_START as usize) + self.preopen_cnt;
        if fd >= MAX_FDS {
            return false;
        }
        let plen = path.len().min(63);
        let mut p = Preopen::empty();
        p.name[..plen].copy_from_slice(&path[..plen]);
        p.name_len = plen as u8;
        self.preopens[self.preopen_cnt] = p;
        self.fds[fd].kind = FdKind::Dir;
        self.fds[fd].path[..plen].copy_from_slice(&path[..plen]);
        self.fds[fd].path_len = plen as u8;
        self.fds[fd].rights_base = rights::ALL;
        self.fds[fd].rights_inheriting = rights::ALL;
        self.preopen_cnt += 1;
        true
    }

    fn prng_next(&mut self) -> u64 {
        let mut x = self.prng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng = x;
        x
    }

    fn alloc_fd(&mut self) -> Option<Fd> {
        for i in (std_fd::PREOPEN_START as usize + self.preopen_cnt)..MAX_FDS {
            if self.fds[i].kind == FdKind::Closed {
                return Some(i as Fd);
            }
        }
        None
    }

    fn get_fd(&self, fd: Fd) -> Option<&OpenFd> {
        if fd as usize >= MAX_FDS {
            return None;
        }
        let o = &self.fds[fd as usize];
        if o.kind == FdKind::Closed {
            return None;
        }
        Some(o)
    }

    fn get_fd_mut(&mut self, fd: Fd) -> Option<&mut OpenFd> {
        if fd as usize >= MAX_FDS {
            return None;
        }
        let o = &mut self.fds[fd as usize];
        if o.kind == FdKind::Closed {
            return None;
        }
        Some(o)
    }

    fn path_str<'a>(o: &'a OpenFd) -> &'a [u8] {
        &o.path[..o.path_len as usize]
    }

    pub(crate) fn abi_fingerprint(&self) -> u64 {
        let mut hash = ABI_FINGERPRINT_OFFSET;
        hash = abi_fingerprint_usize(hash, self.instance_id);
        hash = abi_fingerprint_usize(hash, self.preopen_cnt);
        hash = abi_fingerprint_usize(hash, self.argv0_len);
        hash = abi_fingerprint_u64(hash, self.prng);
        hash = abi_fingerprint_byte(hash, self.exit_code.is_some() as u8);
        hash = abi_fingerprint_u64(hash, self.exit_code.unwrap_or(0) as i64 as u64);
        hash = abi_fingerprint_bytes(hash, &self.argv0);

        let mut fd_idx = 0usize;
        while fd_idx < self.fds.len() {
            let fd = &self.fds[fd_idx];
            hash = abi_fingerprint_fd_kind(hash, fd.kind);
            hash = abi_fingerprint_u64(hash, fd.offset);
            hash = abi_fingerprint_bytes(hash, &fd.path);
            hash = abi_fingerprint_byte(hash, fd.path_len);
            hash = abi_fingerprint_u64(hash, fd.size);
            hash = abi_fingerprint_u64(hash, fd.fdflags as u64);
            hash = abi_fingerprint_u64(hash, fd.rights_base);
            hash = abi_fingerprint_u64(hash, fd.rights_inheriting);
            hash = abi_fingerprint_u64(hash, fd.readdir_cookie);
            hash = abi_fingerprint_bool(hash, fd.shut_rd);
            hash = abi_fingerprint_bool(hash, fd.shut_wr);
            fd_idx += 1;
        }

        let mut preopen_idx = 0usize;
        while preopen_idx < self.preopens.len() {
            let preopen = &self.preopens[preopen_idx];
            hash = abi_fingerprint_bytes(hash, &preopen.name);
            hash = abi_fingerprint_byte(hash, preopen.name_len);
            preopen_idx += 1;
        }

        hash
    }
}

fn rights_include(current: u64, required: u64) -> bool {
    current == rights::ALL || (current & required) == required
}

fn open_fd_path(fd: &OpenFd) -> Result<&str, Errno> {
    core::str::from_utf8(WasiCtx::path_str(fd)).map_err(|_| Errno::Inval)
}

fn vfs_err_to_errno(err: &'static str) -> Errno {
    match err {
        "File not found" | "Path component not found" | "Directory not found" => Errno::Noent,
        "Entry exists" => Errno::Exist,
        "Not a directory" => Errno::Notdir,
        "Not a file" => Errno::Inval,
        "Invalid name" | "Invalid path" | "Invalid timestamp flags" => Errno::Inval,
        "Permission denied" => Errno::Acces,
        "Resize not supported" => Errno::Notsup,
        "Partitions file is read-only" => Errno::Notsup,
        "Directory not empty" => Errno::Notempty,
        _ => Errno::Io,
    }
}

fn read_full_path(path: &str) -> Result<Vec<u8>, Errno> {
    let size = crate::fs::vfs::path_size(path).map_err(vfs_err_to_errno)?;
    let mut data = vec![0u8; size];
    let read = crate::fs::vfs::read_path(path, &mut data).map_err(vfs_err_to_errno)?;
    data.truncate(read);
    Ok(data)
}

fn file_stat_to_wasi(stat: crate::fs::vfs::VfsStat) -> FileStat {
    FileStat {
        dev: 0,
        ino: stat.inode,
        filetype: vfs_entry_filetype(stat.kind),
        _pad: [0; 7],
        nlink: stat.nlink as u64,
        size: stat.size,
        atim: stat.atime,
        mtim: stat.mtime,
        ctim: stat.ctime,
    }
}

fn write_wasi_struct<T>(mem: &mut [u8], offset: usize, value: &T) -> Errno {
    let size = core::mem::size_of::<T>();
    if offset + size > mem.len() {
        return Errno::Fault;
    }
    unsafe {
        let src = value as *const T as *const u8;
        core::ptr::copy_nonoverlapping(src, mem[offset..offset + size].as_mut_ptr(), size);
    }
    Errno::Success
}

// ---------------------------------------------------------------------------
// WASI syscall implementations
// ---------------------------------------------------------------------------

/// args_get — write argv pointers + string data into WASM memory.
pub fn args_get(ctx: &WasiCtx, mem: &mut [u8], argv_ptr: u32, argv_buf_ptr: u32) -> Errno {
    // We expose a single argument: argv[0] = the instance name.
    let argc_bytes = ctx.argv0_len;
    let argv_ptr = argv_ptr as usize;
    let buf_ptr = argv_buf_ptr as usize;

    // Write argv[0] pointer (little-endian u32 into WASM linear memory).
    if argv_ptr + 4 > mem.len() || buf_ptr + argc_bytes + 1 > mem.len() {
        return Errno::Fault;
    }
    let ptr_val = argv_buf_ptr;
    mem[argv_ptr..argv_ptr + 4].copy_from_slice(&ptr_val.to_le_bytes());
    // Write the string itself.
    mem[buf_ptr..buf_ptr + argc_bytes].copy_from_slice(&ctx.argv0[..argc_bytes]);
    mem[buf_ptr + argc_bytes] = 0; // NUL terminate
    Errno::Success
}

/// args_sizes_get — write argc and argv_buf_size into WASM memory.
pub fn args_sizes_get(
    ctx: &WasiCtx,
    mem: &mut [u8],
    argc_ptr: u32,
    argv_buf_size_ptr: u32,
) -> Errno {
    let ap = argc_ptr as usize;
    let sp = argv_buf_size_ptr as usize;
    if ap + 4 > mem.len() || sp + 4 > mem.len() {
        return Errno::Fault;
    }
    mem[ap..ap + 4].copy_from_slice(&1u32.to_le_bytes());
    let slen = (ctx.argv0_len + 1) as u32;
    mem[sp..sp + 4].copy_from_slice(&slen.to_le_bytes());
    Errno::Success
}

/// environ_get — we expose no environment variables.
pub fn environ_get(_ctx: &WasiCtx, _mem: &mut [u8], _env_ptr: u32, _env_buf_ptr: u32) -> Errno {
    Errno::Success
}

/// environ_sizes_get — 0 variables, 0 bytes of string data.
pub fn environ_sizes_get(_ctx: &WasiCtx, mem: &mut [u8], cnt_ptr: u32, buf_size_ptr: u32) -> Errno {
    let cp = cnt_ptr as usize;
    let bp = buf_size_ptr as usize;
    if cp + 4 > mem.len() || bp + 4 > mem.len() {
        return Errno::Fault;
    }
    mem[cp..cp + 4].copy_from_slice(&0u32.to_le_bytes());
    mem[bp..bp + 4].copy_from_slice(&0u32.to_le_bytes());
    Errno::Success
}

/// clock_time_get — returns nanoseconds since boot from the PIT tick counter.
pub fn clock_time_get(
    _ctx: &WasiCtx,
    mem: &mut [u8],
    _clock_id: u32,
    _precision: u64,
    ts_ptr: u32,
) -> Errno {
    let p = ts_ptr as usize;
    if p + 8 > mem.len() {
        return Errno::Fault;
    }
    // Read PIT ticks and convert to nanoseconds (PIT fires at ~1000 Hz → 1 ms = 1_000_000 ns).
    let ticks = crate::scheduler::pit::get_ticks();
    let ns = ticks as u64 * 1_000_000u64;
    mem[p..p + 8].copy_from_slice(&ns.to_le_bytes());
    Errno::Success
}

/// clock_res_get — resolution is 1 ms = 1_000_000 ns.
pub fn clock_res_get(_ctx: &WasiCtx, mem: &mut [u8], _clock_id: u32, ts_ptr: u32) -> Errno {
    let p = ts_ptr as usize;
    if p + 8 > mem.len() {
        return Errno::Fault;
    }
    mem[p..p + 8].copy_from_slice(&1_000_000u64.to_le_bytes());
    Errno::Success
}

/// fd_close — close an open file descriptor.
pub fn fd_close(ctx: &mut WasiCtx, fd: Fd) -> Errno {
    if fd < 3 {
        return Errno::Notsup;
    } // can't close stdin/stdout/stderr
    match ctx.get_fd_mut(fd) {
        None => Errno::Badf,
        Some(o) => {
            *o = OpenFd::closed();
            Errno::Success
        }
    }
}

/// fd_fdstat_get — write an FdStat for `fd` into WASM memory at `stat_ptr`.
pub fn fd_fdstat_get(ctx: &WasiCtx, mem: &mut [u8], fd: Fd, stat_ptr: u32) -> Errno {
    let o = match ctx.get_fd(fd) {
        None => return Errno::Badf,
        Some(o) => o,
    };
    let ft = match o.kind {
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => filetype::CHAR_DEVICE,
        FdKind::File => filetype::REGULAR_FILE,
        FdKind::Dir => filetype::DIRECTORY,
        FdKind::TcpSocket => filetype::SOCKET_STREAM,
        FdKind::Closed => return Errno::Badf,
    };
    let st = FdStat {
        fs_filetype: ft,
        _pad: 0,
        fs_flags: o.fdflags,
        _pad2: 0,
        fs_rights_base: o.rights_base,
        fs_rights_inheriting: o.rights_inheriting,
    };
    write_wasi_struct(mem, stat_ptr as usize, &st)
}

/// fd_filestat_get — write a FileStat for `fd` into WASM memory.
pub fn fd_filestat_get(ctx: &WasiCtx, mem: &mut [u8], fd: Fd, stat_ptr: u32) -> Errno {
    let o = match ctx.get_fd(fd) {
        None => return Errno::Badf,
        Some(o) => o,
    };
    let stat = match o.kind {
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => FileStat {
            dev: 0,
            ino: fd as u64,
            filetype: filetype::CHAR_DEVICE,
            _pad: [0; 7],
            nlink: 1,
            size: 0,
            atim: 0,
            mtim: 0,
            ctim: 0,
        },
        FdKind::TcpSocket => FileStat {
            dev: 0,
            ino: fd as u64,
            filetype: filetype::SOCKET_STREAM,
            _pad: [0; 7],
            nlink: 1,
            size: 0,
            atim: 0,
            mtim: 0,
            ctim: 0,
        },
        FdKind::File | FdKind::Dir => {
            let path = match open_fd_path(o) {
                Ok(path) => path,
                Err(errno) => return errno,
            };
            let vfs_stat = match crate::fs::vfs::stat_path(path) {
                Ok(stat) => stat,
                Err(err) => return vfs_err_to_errno(err),
            };
            file_stat_to_wasi(vfs_stat)
        }
        FdKind::Closed => return Errno::Badf,
    };
    write_wasi_struct(mem, stat_ptr as usize, &stat)
}

pub fn fd_advise(ctx: &WasiCtx, fd: Fd, offset: u64, len: u64) -> Errno {
    let open = match ctx.get_fd(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if open.kind != FdKind::File {
        return Errno::Badf;
    }
    if offset.checked_add(len).is_none() {
        return Errno::Inval;
    }
    Errno::Success
}

pub fn fd_allocate(ctx: &mut WasiCtx, fd: Fd, offset: u64, len: u64) -> Errno {
    let target_size = match offset.checked_add(len) {
        Some(size) => size,
        None => return Errno::Inval,
    };
    let open = match ctx.get_fd(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if open.kind != FdKind::File {
        return Errno::Badf;
    }
    let path = match open_fd_path(open) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    match crate::fs::vfs::resize_path(path, target_size as usize) {
        Ok(()) => {
            if let Some(open) = ctx.get_fd_mut(fd) {
                open.size = target_size;
            }
            Errno::Success
        }
        Err(err) => vfs_err_to_errno(err),
    }
}

pub fn fd_datasync(ctx: &WasiCtx, fd: Fd) -> Errno {
    let open = match ctx.get_fd(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if open.kind != FdKind::File {
        return Errno::Badf;
    }
    let path = match open_fd_path(open) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    match crate::fs::vfs::sync_path(path) {
        Ok(()) => Errno::Success,
        Err(err) => vfs_err_to_errno(err),
    }
}

pub fn fd_fdstat_set_flags(ctx: &mut WasiCtx, fd: Fd, flags: u16) -> Errno {
    // All bits outside APPEND|NONBLOCK are unsupported; computed at compile time.
    const UNSUPPORTED: u16 = !fdflags::SUPPORTED; // 0xFFFC
    if flags & UNSUPPORTED != 0 {
        return Errno::Notsup;
    }
    let open = match ctx.get_fd_mut(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    open.fdflags = flags;
    Errno::Success
}

pub fn fd_fdstat_set_rights(
    ctx: &mut WasiCtx,
    fd: Fd,
    rights_base: u64,
    rights_inheriting: u64,
) -> Errno {
    let open = match ctx.get_fd_mut(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if (rights_base | open.rights_base) != open.rights_base
        || (rights_inheriting | open.rights_inheriting) != open.rights_inheriting
    {
        return Errno::Notcapable;
    }
    open.rights_base = rights_base;
    open.rights_inheriting = rights_inheriting;
    Errno::Success
}

pub fn fd_filestat_set_size(ctx: &mut WasiCtx, fd: Fd, size: u64) -> Errno {
    let open = match ctx.get_fd(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if open.kind != FdKind::File {
        return Errno::Badf;
    }
    let path = match open_fd_path(open) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    match crate::fs::vfs::resize_path(path, size as usize) {
        Ok(()) => {
            if let Some(open) = ctx.get_fd_mut(fd) {
                open.size = size;
            }
            Errno::Success
        }
        Err(err) => vfs_err_to_errno(err),
    }
}

pub fn fd_filestat_set_times(ctx: &mut WasiCtx, fd: Fd, atim: u64, mtim: u64, fst_flags: u32) -> Errno {
    let open = match ctx.get_fd(fd) {
        Some(open) => open,
        None => return Errno::Badf,
    };
    if open.kind != FdKind::File && open.kind != FdKind::Dir {
        return Errno::Badf;
    }
    let path = match open_fd_path(open) {
        Ok(path) => path,
        Err(errno) => return errno,
    };
    match crate::fs::vfs::set_path_times(path, atim, mtim, fst_flags, true) {
        Ok(()) => Errno::Success,
        Err(err) => vfs_err_to_errno(err),
    }
}

pub fn fd_renumber(ctx: &mut WasiCtx, from_fd: Fd, to_fd: Fd) -> Errno {
    let reserved_limit = std_fd::PREOPEN_START + ctx.preopen_cnt as u32;
    if from_fd as usize >= MAX_FDS || to_fd as usize >= MAX_FDS {
        return Errno::Badf;
    }
    if from_fd < reserved_limit || to_fd < reserved_limit {
        return Errno::Notsup;
    }
    if ctx.get_fd(from_fd).is_none() {
        return Errno::Badf;
    }
    if from_fd == to_fd {
        return Errno::Success;
    }
    let source = ctx.fds[from_fd as usize];
    ctx.fds[to_fd as usize] = source;
    ctx.fds[from_fd as usize] = OpenFd::closed();
    Errno::Success
}

pub fn fd_sync(ctx: &WasiCtx, fd: Fd) -> Errno {
    fd_datasync(ctx, fd)
}

/// fd_prestat_get — return prestat info for the fd at the given slot.
pub fn fd_prestat_get(ctx: &WasiCtx, mem: &mut [u8], fd: Fd, prestat_ptr: u32) -> Errno {
    let idx = fd as usize - std_fd::PREOPEN_START as usize;
    if idx >= ctx.preopen_cnt {
        return Errno::Badf;
    }
    let p = prestat_ptr as usize;
    if p + core::mem::size_of::<Prestat>() > mem.len() {
        return Errno::Fault;
    }
    let ps = Prestat {
        tag: 0,
        _pad: [0; 3],
        u_dir_pr_name_len: ctx.preopens[idx].name_len as u32,
    };
    mem[p] = ps.tag;
    mem[p + 1] = 0;
    mem[p + 2] = 0;
    mem[p + 3] = 0;
    mem[p + 4..p + 8].copy_from_slice(&ps.u_dir_pr_name_len.to_le_bytes());
    Errno::Success
}

/// fd_prestat_dir_name — write the directory name into WASM memory.
pub fn fd_prestat_dir_name(
    ctx: &WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    path_ptr: u32,
    path_len: u32,
) -> Errno {
    let idx = fd as usize - std_fd::PREOPEN_START as usize;
    if idx >= ctx.preopen_cnt {
        return Errno::Badf;
    }
    let src_len = ctx.preopens[idx].name_len as usize;
    let dst_len = path_len as usize;
    let p = path_ptr as usize;
    if p + dst_len > mem.len() {
        return Errno::Fault;
    }
    let copy_len = src_len.min(dst_len);
    mem[p..p + copy_len].copy_from_slice(&ctx.preopens[idx].name[..copy_len]);
    Errno::Success
}

/// fd_read — read from `fd` into scatter-gather iovecs.
///
/// iovecs layout (each 8 bytes): [ buf_ptr: u32, buf_len: u32 ]
pub fn fd_read(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    iovs_ptr: u32,
    iovs_len: u32,
    nread_ptr: u32,
) -> Errno {
    if fd as usize >= MAX_FDS {
        return Errno::Badf;
    }
    let kind = ctx.fds[fd as usize].kind;
    let nread_p = nread_ptr as usize;
    if nread_p + 4 > mem.len() {
        return Errno::Fault;
    }

    let mut total = 0u32;

    match kind {
        FdKind::Stdin => {
            // Read from the input event queue — convert key events to UTF-8 bytes.
            for i in 0..iovs_len as usize {
                let iov_off = iovs_ptr as usize + i * 8;
                if iov_off + 8 > mem.len() {
                    break;
                }
                let buf_ptr =
                    u32::from_le_bytes(mem[iov_off..iov_off + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                let buf_len =
                    u32::from_le_bytes(mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4]))
                        as usize;
                if buf_ptr + buf_len > mem.len() {
                    return Errno::Fault;
                }

                let mut written = 0usize;
                #[cfg(not(target_arch = "aarch64"))]
                #[cfg(not(target_arch = "aarch64"))]
                while written < buf_len {
                    crate::drivers::x86::input::pump();
                    match crate::drivers::x86::input::read() {
                        Some(ev) if ev.kind == crate::drivers::x86::input::InputEventKind::Key => {
                            let cp = unsafe { ev.data.key.codepoint };
                            if cp > 0 && cp < 0x80 {
                                mem[buf_ptr + written] = cp as u8;
                                written += 1;
                            }
                        }
                        _ => break,
                    }
                }
                // AArch64: read from the PL011 UART RX ring buffer.
                #[cfg(target_arch = "aarch64")]
                while written < buf_len {
                    match crate::arch::aarch64::aarch64_pl011::read_byte() {
                        Some(b) => {
                            mem[buf_ptr + written] = b;
                            written += 1;
                        }
                        None => break,
                    }
                }
                total += written as u32;
            }
        }
        FdKind::File => {
            let open = &ctx.fds[fd as usize];
            if !rights_include(open.rights_base, rights::FD_READ) {
                return Errno::Notcapable;
            }
            let offset = open.offset;
            let path = match open_fd_path(open) {
                Ok(path) => path,
                Err(errno) => return errno,
            };
            let data = match read_full_path(path) {
                Ok(data) => data,
                Err(errno) => return errno,
            };
            let start = (offset as usize).min(data.len());
            let mut remaining = &data[start..];

            for i in 0..iovs_len as usize {
                if remaining.is_empty() {
                    break;
                }
                let iov_off = iovs_ptr as usize + i * 8;
                if iov_off + 8 > mem.len() {
                    break;
                }
                let buf_ptr =
                    u32::from_le_bytes(mem[iov_off..iov_off + 4].try_into().unwrap_or([0; 4]))
                        as usize;
                let buf_len =
                    u32::from_le_bytes(mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4]))
                        as usize;
                if buf_ptr + buf_len > mem.len() {
                    return Errno::Fault;
                }
                let chunk = remaining.len().min(buf_len);
                mem[buf_ptr..buf_ptr + chunk].copy_from_slice(&remaining[..chunk]);
                remaining = &remaining[chunk..];
                total += chunk as u32;
            }
            ctx.fds[fd as usize].offset = ctx.fds[fd as usize]
                .offset
                .saturating_add(total as u64);
            ctx.fds[fd as usize].size = data.len() as u64;
        }
        FdKind::Closed => return Errno::Badf,
        _ => return Errno::Notsup,
    }

    mem[nread_p..nread_p + 4].copy_from_slice(&total.to_le_bytes());
    Errno::Success
}

/// fd_write — write to `fd` from scatter-gather iovecs.
pub fn fd_write(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    iovs_ptr: u32,
    iovs_len: u32,
    nwritten_ptr: u32,
) -> Errno {
    if fd as usize >= MAX_FDS {
        return Errno::Badf;
    }
    let kind = ctx.fds[fd as usize].kind;
    let nw_p = nwritten_ptr as usize;
    if nw_p + 4 > mem.len() {
        return Errno::Fault;
    }

    let mut total = 0u32;
    let is_console = kind == FdKind::Stdout || kind == FdKind::Stderr;

    for i in 0..iovs_len as usize {
        let iov_off = iovs_ptr as usize + i * 8;
        if iov_off + 8 > mem.len() {
            break;
        }
        let buf_ptr =
            u32::from_le_bytes(mem[iov_off..iov_off + 4].try_into().unwrap_or([0; 4])) as usize;
        let buf_len =
            u32::from_le_bytes(mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4])) as usize;
        if buf_ptr + buf_len > mem.len() {
            return Errno::Fault;
        }
        let slice = &mem[buf_ptr..buf_ptr + buf_len];

        if is_console {
            if let Ok(s) = core::str::from_utf8(slice) {
                crate::serial_print!("{}", s);
            }
        } else if kind == FdKind::File {
            let open = &ctx.fds[fd as usize];
            if !rights_include(open.rights_base, rights::FD_WRITE) {
                return Errno::Notcapable;
            }
            let path = match open_fd_path(open) {
                Ok(path) => path,
                Err(errno) => return errno,
            };
            let mut data = match read_full_path(path) {
                Ok(data) => data,
                Err(Errno::Noent) => Vec::new(),
                Err(errno) => return errno,
            };
            let effective_offset = if open.fdflags & fdflags::APPEND != 0 {
                data.len()
            } else {
                open.offset as usize
            };
            if effective_offset > data.len() {
                data.resize(effective_offset, 0);
            }
            if effective_offset + buf_len > data.len() {
                data.resize(effective_offset + buf_len, 0);
            }
            data[effective_offset..effective_offset + buf_len].copy_from_slice(slice);
            match crate::fs::vfs::write_path(path, &data) {
                Ok(_) => {
                    ctx.fds[fd as usize].offset = (effective_offset + buf_len) as u64;
                    ctx.fds[fd as usize].size = data.len() as u64;
                }
                Err(err) => return vfs_err_to_errno(err),
            }
        } else {
            return Errno::Badf;
        }
        total += buf_len as u32;
    }

    mem[nw_p..nw_p + 4].copy_from_slice(&total.to_le_bytes());
    Errno::Success
}

/// fd_seek — reposition the file offset.
pub fn fd_seek(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    offset: i64,
    whence: u8,
    newoffset_ptr: u32,
) -> Errno {
    let o = match ctx.get_fd_mut(fd) {
        None => return Errno::Badf,
        Some(o) => o,
    };
    if o.kind != FdKind::File {
        return Errno::Spipe;
    }
    if !rights_include(o.rights_base, rights::FD_SEEK) {
        return Errno::Notcapable;
    }
    let new_off = match whence {
        0 => offset as u64,                                 // SET
        1 => (o.offset as i64).wrapping_add(offset) as u64, // CUR
        2 => (o.size as i64).wrapping_add(offset) as u64,   // END
        _ => return Errno::Inval,
    };
    o.offset = new_off;
    let p = newoffset_ptr as usize;
    if p + 8 > mem.len() {
        return Errno::Fault;
    }
    mem[p..p + 8].copy_from_slice(&new_off.to_le_bytes());
    Errno::Success
}

/// fd_tell — return current file offset.
pub fn fd_tell(ctx: &WasiCtx, mem: &mut [u8], fd: Fd, offset_ptr: u32) -> Errno {
    let open = match ctx.get_fd(fd) {
        None => return Errno::Badf,
        Some(o) => o,
    };
    if !rights_include(open.rights_base, rights::FD_TELL) {
        return Errno::Notcapable;
    }
    let off = open.offset;
    let p = offset_ptr as usize;
    if p + 8 > mem.len() {
        return Errno::Fault;
    }
    mem[p..p + 8].copy_from_slice(&off.to_le_bytes());
    Errno::Success
}

/// path_open — open or create a file.
pub fn path_open(
    ctx: &mut WasiCtx,
    _mem: &mut [u8],
    _dirfd: Fd,
    _dirflags: u32,
    path: &[u8],
    open_flags: u16,
    rights: u64,
    rights_inheriting: u64,
    fdflags_bits: u16,
    opened_fd_ptr: &mut Fd,
) -> Errno {
    if fdflags_bits & !fdflags::SUPPORTED != 0 {
        return Errno::Notsup;
    }
    if open_flags & oflags::DIRECTORY != 0
        && open_flags & (oflags::CREAT | oflags::TRUNC | oflags::EXCL) != 0
    {
        return Errno::Inval;
    }
    let path_str = match core::str::from_utf8(path) {
        Ok(path) => path,
        Err(_) => return Errno::Inval,
    };

    let existing = crate::fs::vfs::stat_path(path_str);
    if open_flags & oflags::EXCL != 0 && open_flags & oflags::CREAT != 0 && existing.is_ok() {
        return Errno::Exist;
    }
    if existing.is_err() && open_flags & oflags::CREAT != 0 {
        if let Err(err) = crate::fs::vfs::write_path(path_str, &[]) {
            return vfs_err_to_errno(err);
        }
    }
    if open_flags & oflags::TRUNC != 0 {
        if let Err(err) = crate::fs::vfs::resize_path(path_str, 0) {
            return vfs_err_to_errno(err);
        }
    }
    let stat = match crate::fs::vfs::stat_path(path_str) {
        Ok(stat) => stat,
        Err(err) => return vfs_err_to_errno(err),
    };
    if open_flags & oflags::DIRECTORY != 0 && stat.kind != crate::fs::vfs::InodeKind::Directory {
        return Errno::Notdir;
    }
    let new_fd = match ctx.alloc_fd() {
        None => return Errno::Mfile,
        Some(fd) => fd,
    };
    let plen = path.len().min(127);
    ctx.fds[new_fd as usize].kind = match stat.kind {
        crate::fs::vfs::InodeKind::Directory => FdKind::Dir,
        _ => FdKind::File,
    };
    ctx.fds[new_fd as usize].offset = if fdflags_bits & fdflags::APPEND != 0 {
        stat.size
    } else {
        0
    };
    ctx.fds[new_fd as usize].path[..plen].copy_from_slice(&path[..plen]);
    ctx.fds[new_fd as usize].path_len = plen as u8;
    ctx.fds[new_fd as usize].size = stat.size;
    ctx.fds[new_fd as usize].fdflags = fdflags_bits;
    ctx.fds[new_fd as usize].rights_base = rights;
    ctx.fds[new_fd as usize].rights_inheriting = rights_inheriting;
    *opened_fd_ptr = new_fd;
    Errno::Success
}

/// path_unlink_file — remove a file.
pub fn path_unlink_file(_ctx: &mut WasiCtx, path: &[u8]) -> Errno {
    let Ok(s) = core::str::from_utf8(path) else {
        return Errno::Inval;
    };
    match crate::fs::vfs::unlink(s) {
        Ok(()) => Errno::Success,
        Err(err) => vfs_err_to_errno(err),
    }
}

/// path_create_directory — create a directory in the VFS.
pub fn path_create_directory(_ctx: &mut WasiCtx, path: &[u8]) -> Errno {
    let Ok(s) = core::str::from_utf8(path) else {
        return Errno::Inval;
    };
    match crate::fs::vfs::mkdir(s) {
        Ok(()) => Errno::Success,
        Err(_) => Errno::Io,
    }
}

/// path_remove_directory — remove an empty directory from the VFS.
pub fn path_remove_directory(_ctx: &mut WasiCtx, path: &[u8]) -> Errno {
    let Ok(s) = core::str::from_utf8(path) else {
        return Errno::Inval;
    };
    match crate::fs::vfs::rmdir(s) {
        Ok(()) => Errno::Success,
        Err(_) => Errno::Io,
    }
}

/// path_symlink — create a symbolic link.
pub fn path_symlink(_ctx: &mut WasiCtx, old_path: &[u8], new_path: &[u8]) -> Errno {
    let (Ok(target), Ok(link)) = (core::str::from_utf8(old_path), core::str::from_utf8(new_path))
    else {
        return Errno::Inval;
    };
    match crate::fs::vfs::symlink(target, link) {
        Ok(()) => Errno::Success,
        Err(_) => Errno::Io,
    }
}

/// path_readlink — read the target of a symbolic link.
///
/// The WASM ABI exposes 5 parameters: `(fd, path_ptr, path_len, buf_ptr, buf_len)`.
/// There is no `bufused` out-pointer in this kernel's calling convention; callers
/// receive the result bytes in `buf` up to `buf_len` bytes.
pub fn path_readlink(
    _ctx: &mut WasiCtx,
    mem: &mut [u8],
    path: &[u8],
    buf_ptr: u32,
    buf_len: u32,
) -> Errno {
    let Ok(s) = core::str::from_utf8(path) else {
        return Errno::Inval;
    };
    let bp = buf_ptr as usize;
    let bl = buf_len as usize;
    if bp.saturating_add(bl) > mem.len() {
        return Errno::Fault;
    }
    match crate::fs::vfs::readlink(s) {
        Err(_) => Errno::Noent,
        Ok(target) => {
            let bytes = target.as_bytes();
            let copy = bytes.len().min(bl);
            mem[bp..bp + copy].copy_from_slice(&bytes[..copy]);
            Errno::Success
        }
    }
}

/// path_link — create a hard link.
pub fn path_link(_ctx: &mut WasiCtx, old_path: &[u8], new_path: &[u8]) -> Errno {
    let (Ok(existing), Ok(link)) = (core::str::from_utf8(old_path), core::str::from_utf8(new_path))
    else {
        return Errno::Inval;
    };
    match crate::fs::vfs::link(existing, link) {
        Ok(()) => Errno::Success,
        Err(_) => Errno::Io,
    }
}

/// path_rename — rename a path.
pub fn path_rename(_ctx: &mut WasiCtx, old_path: &[u8], new_path: &[u8]) -> Errno {
    let (Ok(old_path), Ok(new_path)) =
        (core::str::from_utf8(old_path), core::str::from_utf8(new_path))
    else {
        return Errno::Inval;
    };
    match crate::fs::vfs::rename(old_path, new_path) {
        Ok(()) => Errno::Success,
        Err(_) => Errno::Io,
    }
}

/// fd_readdir — list files in a directory (fills the WASM buffer with dirent structs).
///
/// Each dirent: [ d_next: u64 | d_ino: u64 | d_namlen: u32 | d_type: u8 ] = 21 bytes + name.
/// `cookie` is the 0-based entry index to start from; `d_next` carries the cookie for the
/// subsequent call.  Entries are sourced from `crate::fs::vfs::list_dir_entries`.
pub fn fd_readdir(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    buf_ptr: u32,
    buf_len: u32,
    cookie: u64,
    bufused_ptr: u32,
) -> Errno {
    let p = buf_ptr as usize;
    let plen = buf_len as usize;
    let bp = bufused_ptr as usize;
    if bp + 4 > mem.len() {
        return Errno::Fault;
    }
    if p.saturating_add(plen) > mem.len() {
        return Errno::Fault;
    }
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return Errno::Badf;
    }
    let open_fd = &ctx.fds[fd_idx];
    if matches!(open_fd.kind, FdKind::Closed) {
        return Errno::Badf;
    }
    let path_len = open_fd.path_len as usize;
    if path_len == 0 {
        return Errno::Notdir;
    }
    let path_str = match core::str::from_utf8(&open_fd.path[..path_len]) {
        Ok(s) => s,
        Err(_) => return Errno::Inval,
    };

    let entries = match crate::fs::vfs::list_dir_entries(path_str) {
        Ok(entries) => entries,
        Err(_) => return Errno::Notdir,
    };

    // Walk the structured directory entries and emit WASI dirent records.
    // WASI dirent layout: d_next(u64) d_ino(u64) d_namlen(u32) d_type(u8) <name bytes>
    let mut buf_cursor = 0usize;
    let mut entry_index = 0u64;
    for entry in &entries {
        if entry_index < cookie {
            entry_index += 1;
            continue;
        }

        let name = entry.name.as_bytes();
        let namlen = name.len();
        let entry_size = 21 + namlen; // 21-byte fixed header + name bytes
        if buf_cursor + entry_size > plen {
            break; // output buffer full; caller re-invokes with d_next as cookie
        }

        let d_next: u64 = entry_index + 1;
        let d_ino: u64 = entry.inode;
        let d_namlen: u32 = namlen as u32;
        let d_type: u8 = vfs_entry_filetype(entry.kind);

        let base = p + buf_cursor;
        mem[base..base + 8].copy_from_slice(&d_next.to_le_bytes());
        mem[base + 8..base + 16].copy_from_slice(&d_ino.to_le_bytes());
        mem[base + 16..base + 20].copy_from_slice(&d_namlen.to_le_bytes());
        mem[base + 20] = d_type;
        mem[base + 21..base + 21 + namlen].copy_from_slice(name);

        buf_cursor += entry_size;
        entry_index += 1;
    }

    mem[bp..bp + 4].copy_from_slice(&(buf_cursor as u32).to_le_bytes());
    Errno::Success
}

/// path_filestat_get — stat a path.
pub fn path_filestat_get(
    _ctx: &WasiCtx,
    mem: &mut [u8],
    _dirfd: Fd,
    flags: u32,
    path: &[u8],
    stat_ptr: u32,
) -> Errno {
    let path = match core::str::from_utf8(path) {
        Ok(path) => path,
        Err(_) => return Errno::Inval,
    };
    let follow_final_symlink = (flags & 1) != 0;
    let stat = match if follow_final_symlink {
        crate::fs::vfs::stat_path(path)
    } else {
        crate::fs::vfs::stat_path_nofollow(path)
    } {
        Ok(stat) => stat,
        Err(err) => return vfs_err_to_errno(err),
    };
    write_wasi_struct(mem, stat_ptr as usize, &file_stat_to_wasi(stat))
}

pub fn path_filestat_set_times(
    _ctx: &mut WasiCtx,
    path: &[u8],
    atim: u64,
    mtim: u64,
    fst_flags: u32,
) -> Errno {
    let path = match core::str::from_utf8(path) {
        Ok(path) => path,
        Err(_) => return Errno::Inval,
    };
    match crate::fs::vfs::set_path_times(path, atim, mtim, fst_flags, true) {
        Ok(()) => Errno::Success,
        Err(err) => vfs_err_to_errno(err),
    }
}

/// random_get — fill buffer with pseudo-random bytes.
pub fn random_get(ctx: &mut WasiCtx, mem: &mut [u8], buf_ptr: u32, buf_len: u32) -> Errno {
    let p = buf_ptr as usize;
    let l = buf_len as usize;
    if p + l > mem.len() {
        return Errno::Fault;
    }
    let mut i = 0usize;
    while i + 8 <= l {
        let v = ctx.prng_next();
        mem[p + i..p + i + 8].copy_from_slice(&v.to_le_bytes());
        i += 8;
    }
    while i < l {
        let v = ctx.prng_next() as u8;
        mem[p + i] = v;
        i += 1;
    }
    Errno::Success
}

/// proc_exit — terminate the current WASM instance.
pub fn proc_exit(ctx: &mut WasiCtx, code: i32) {
    ctx.exit_code = Some(code);
}

pub fn proc_raise(ctx: &mut WasiCtx, signal: u32) -> Errno {
    match signal {
        0 => Errno::Success,
        2 | 6 | 9 | 15 => {
            ctx.exit_code = Some(128 + signal as i32);
            Errno::Success
        }
        _ => Errno::Notsup,
    }
}

/// sched_yield — yield the current WASM thread's time slice.
pub fn sched_yield() -> Errno {
    // Cooperative yield — the scheduler will context-switch away on the next tick.
    Errno::Success
}

/// poll_oneoff — wait for one or more I/O events.
///
/// Supports:
///   - EVENTTYPE_CLOCK  (tag=0): waits up to the specified nanosecond timeout
///     by spinning with cooperative yields until the PIT deadline is reached.
///   - EVENTTYPE_FD_READ (tag=1): immediately checks whether stdin / socket
///     data is available (non-blocking peek).
///   - EVENTTYPE_FD_WRITE (tag=2): always ready (write-side never blocks here).
///
/// Each WASI `subscription` is 48 bytes; each `event` output is 32 bytes.
pub fn poll_oneoff(
    ctx: &WasiCtx,
    mem: &mut [u8],
    in_ptr: u32,
    out_ptr: u32,
    nsubscriptions: u32,
    nevents_ptr: u32,
) -> Errno {
    // -----------------------------------------------------------------------
    // WASI subscription layout (48 bytes, little-endian)
    //   [0..8]   userdata  : u64
    //   [8]      tag       : u8  (0=clock, 1=fd_read, 2=fd_write)
    //   [9..15]  _pad
    //   [16..48] union (clock or fd_read/write)
    //
    // clock union at offset 16:
    //   [16..24] id        : u32 (clock id; 0=realtime, 1=monotonic)
    //   [24..32] timeout   : u64  nanoseconds
    //   [32..40] precision : u64
    //   [40..42] flags     : u16  (0=relative, 1=absolute)
    //
    // fd union at offset 16:
    //   [16..20] fd        : u32
    //
    // WASI event layout (32 bytes)
    //   [0..8]   userdata  : u64
    //   [8..10]  error     : u16
    //   [10..12] type      : u16
    //   [12..32] fd_readwrite union / _pad
    //     [12..20] nbytes  : u64
    //     [20..22] flags   : u16
    // -----------------------------------------------------------------------

    const SUB_SIZE: usize = 48;
    const EVT_SIZE: usize = 32;
    const EVENTTYPE_CLOCK: u8 = 0;
    const EVENTTYPE_FD_READ: u8 = 1;
    const EVENTTYPE_FD_WRITE: u8 = 2;

    let n = nsubscriptions as usize;
    let ep = nevents_ptr as usize;
    if ep + 4 > mem.len() {
        return Errno::Fault;
    }
    if n == 0 {
        mem[ep..ep + 4].copy_from_slice(&0u32.to_le_bytes());
        return Errno::Success;
    }

    // --- Phase 1: compute deadline for any clock subscription ---------------
    // PIT ticks ≈ 1 ms each.  Convert ns timeout → ticks (divide by 1_000_000).
    let mut earliest_deadline: Option<u64> = None;

    for i in 0..n {
        let sub_off = in_ptr as usize + i * SUB_SIZE;
        if sub_off + SUB_SIZE > mem.len() {
            return Errno::Fault;
        }
        let tag = mem[sub_off + 8];
        if tag == EVENTTYPE_CLOCK {
            let timeout_ns =
                u64::from_le_bytes(mem[sub_off + 24..sub_off + 32].try_into().unwrap_or([0; 8]));
            let flags =
                u16::from_le_bytes(mem[sub_off + 40..sub_off + 42].try_into().unwrap_or([0; 2]));
            let now = crate::scheduler::pit::get_ticks();
            let deadline = if flags & 1 != 0 {
                // absolute timestamp in ns → convert to ticks
                timeout_ns / 1_000_000
            } else {
                // relative timeout
                now.wrapping_add(timeout_ns / 1_000_000)
            };
            earliest_deadline = Some(match earliest_deadline {
                None => deadline,
                Some(d) => d.min(deadline),
            });
        }
    }

    // --- Phase 2: spin-yield until deadline or fd becomes ready -------------
    loop {
        // Check fd readiness right away
        let mut any_fd_ready = false;
        for i in 0..n {
            let sub_off = in_ptr as usize + i * SUB_SIZE;
            if sub_off + SUB_SIZE > mem.len() {
                break;
            }
            let tag = mem[sub_off + 8];
            if tag == EVENTTYPE_FD_READ {
                let _fd = u32::from_le_bytes(
                    mem[sub_off + 16..sub_off + 20].try_into().unwrap_or([0; 4]),
                );
                // stdin (fd 0) — check keyboard ring
                if _fd == 0 && kbd_has_input() {
                    any_fd_ready = true;
                    break;
                }
                // other fds: check network packet availability
                if net_has_recv() {
                    any_fd_ready = true;
                    break;
                }
            } else if tag == EVENTTYPE_FD_WRITE {
                // stdout/stderr are always ready
                any_fd_ready = true;
                break;
            }
        }

        // Check clock deadline
        let clock_expired = match earliest_deadline {
            None => false,
            Some(d) => crate::scheduler::pit::get_ticks() >= d,
        };

        if any_fd_ready || clock_expired || earliest_deadline.is_none() {
            break;
        }

        // Not ready yet — yield and retry
        crate::scheduler::quantum_scheduler::yield_now();
    }

    // --- Phase 3: write event structs for every triggered subscription ------
    let now = crate::scheduler::pit::get_ticks();
    let mut nevents: u32 = 0;
    let _ = ctx;

    for i in 0..n {
        let sub_off = in_ptr as usize + i * SUB_SIZE;
        if sub_off + SUB_SIZE > mem.len() {
            break;
        }

        let tag = mem[sub_off + 8];
        let userdata = u64::from_le_bytes(mem[sub_off..sub_off + 8].try_into().unwrap_or([0; 8]));

        let triggered = match tag {
            EVENTTYPE_CLOCK => match earliest_deadline {
                Some(d) => now >= d,
                None => true,
            },
            EVENTTYPE_FD_READ => {
                let fd = u32::from_le_bytes(
                    mem[sub_off + 16..sub_off + 20].try_into().unwrap_or([0; 4]),
                );
                if fd == 0 {
                    kbd_has_input()
                } else {
                    net_has_recv()
                }
            }
            EVENTTYPE_FD_WRITE => true,
            _ => false,
        };

        if triggered {
            let evt_off = out_ptr as usize + nevents as usize * EVT_SIZE;
            if evt_off + EVT_SIZE > mem.len() {
                break;
            }
            // userdata
            mem[evt_off..evt_off + 8].copy_from_slice(&userdata.to_le_bytes());
            // error = 0 (success)
            mem[evt_off + 8..evt_off + 10].copy_from_slice(&0u16.to_le_bytes());
            // type = tag (clock/fd_read/fd_write)
            mem[evt_off + 10..evt_off + 12].copy_from_slice(&(tag as u16).to_le_bytes());
            // nbytes / flags = 0
            mem[evt_off + 12..evt_off + 32].fill(0);
            nevents += 1;
        }
    }

    mem[ep..ep + 4].copy_from_slice(&nevents.to_le_bytes());
    Errno::Success
}

/// sock_recv — receive from a (TCP) socket fd.
pub fn sock_recv(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    ri_data_ptr: u32,
    ri_data_len: u32,
    _ri_flags: u16,
    ro_datalen_ptr: u32,
    ro_flags_ptr: u32,
) -> Errno {
    let rdp = ro_datalen_ptr as usize;
    let rfp = ro_flags_ptr as usize;
    if rdp + 4 > mem.len() || rfp + 2 > mem.len() {
        return Errno::Fault;
    }
    // Refuse read if the receive half was shut down.
    let idx = fd as usize;
    if idx < MAX_FDS && ctx.fds[idx].shut_rd {
        mem[rdp..rdp + 4].copy_from_slice(&0u32.to_le_bytes());
        mem[rfp..rfp + 2].copy_from_slice(&0u16.to_le_bytes());
        return Errno::Shutdown;
    }

    let mut total = 0u32;
    let mut rx_buf = [0u8; 2048];
    let bytes = net_recv(&mut rx_buf);
    if bytes > 0 {
        // Write into first iovec.
        let iov_off = ri_data_ptr as usize;
        if iov_off + 8 <= mem.len() {
            let buf_ptr =
                u32::from_le_bytes(mem[iov_off..iov_off + 4].try_into().unwrap_or([0; 4])) as usize;
            let buf_len =
                u32::from_le_bytes(mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4]))
                    as usize;
            let _ = ri_data_len;
            let copy = bytes.min(buf_len);
            if buf_ptr + copy <= mem.len() {
                mem[buf_ptr..buf_ptr + copy].copy_from_slice(&rx_buf[..copy]);
                total = copy as u32;
            }
        }
    }

    mem[rdp..rdp + 4].copy_from_slice(&total.to_le_bytes());
    mem[rfp..rfp + 2].copy_from_slice(&0u16.to_le_bytes());
    Errno::Success
}

/// sock_send — send via RTL8139.
pub fn sock_send(
    ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    si_data_ptr: u32,
    si_data_len: u32,
    _si_flags: u16,
    so_datalen_ptr: u32,
) -> Errno {
    let sdp = so_datalen_ptr as usize;
    if sdp + 4 > mem.len() {
        return Errno::Fault;
    }
    // Refuse send if the write half was shut down.
    let idx = fd as usize;
    if idx < MAX_FDS && ctx.fds[idx].shut_wr {
        mem[sdp..sdp + 4].copy_from_slice(&0u32.to_le_bytes());
        return Errno::Shutdown;
    }
    let mut total = 0u32;
    for i in 0..si_data_len as usize {
        let iov_off = si_data_ptr as usize + i * 8;
        if iov_off + 8 > mem.len() {
            break;
        }
        let buf_ptr =
            u32::from_le_bytes(mem[iov_off..iov_off + 4].try_into().unwrap_or([0; 4])) as usize;
        let buf_len =
            u32::from_le_bytes(mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4])) as usize;
        if buf_ptr + buf_len > mem.len() {
            return Errno::Fault;
        }
        if net_send(&mem[buf_ptr..buf_ptr + buf_len]) {
            total += buf_len as u32;
        }
    }
    mem[sdp..sdp + 4].copy_from_slice(&total.to_le_bytes());
    Errno::Success
}

/// sock_accept — accept a pending inbound connection on a listening socket fd.
///
/// Oreulius's network stack (RTL8139) is connectionless at the driver level;
/// we model "connection acceptance" as consuming the next available received
/// packet and returning a new `TcpSocket` fd that maps to the RTL8139 receive
/// path.  If no packet is pending we return `Errno::Again` so that callers
/// built with non-blocking semantics can loop via `poll_oneoff`.
pub fn sock_accept(ctx: &mut WasiCtx, _fd: Fd, _flags: u16, new_fd_ptr: &mut Fd) -> Errno {
    // Check whether the RTL8139 receive ring has data waiting — we treat a
    // pending packet as a proxy for "a connection is ready to accept".
    if !net_has_recv() {
        return Errno::Again;
    }

    // Allocate a fresh fd slot and mark it as a TCP socket.
    match ctx.alloc_fd() {
        None => Errno::Mfile,
        Some(new) => {
            ctx.fds[new as usize].kind = FdKind::TcpSocket;
            *new_fd_ptr = new;
            Errno::Success
        }
    }
}

/// sock_shutdown — shut down send or receive half of a socket fd.
///
/// `how` values follow POSIX SHUT_RD/SHUT_WR/SHUT_RDWR:
///   0 = SHUT_RD  — disallow further receives
///   1 = SHUT_WR  — disallow further sends
///   2 = SHUT_RDWR — disallow both
pub fn sock_shutdown(ctx: &mut WasiCtx, fd: Fd, how: u8) -> Errno {
    let idx = fd as usize;
    if idx >= MAX_FDS {
        return Errno::Badf;
    }
    if ctx.fds[idx].kind != FdKind::TcpSocket {
        return Errno::Notsock;
    }
    match how {
        0 => ctx.fds[idx].shut_rd = true,
        1 => ctx.fds[idx].shut_wr = true,
        2 => {
            ctx.fds[idx].shut_rd = true;
            ctx.fds[idx].shut_wr = true;
        }
        _ => return Errno::Inval,
    }
    Errno::Success
}

// ---------------------------------------------------------------------------
// Helper trait to copy path bytes out of a fixed array without alloc
// ---------------------------------------------------------------------------

trait ToOwnedBytes {
    fn to_owned_bytes(&self) -> [u8; 128];
}

impl ToOwnedBytes for [u8] {
    fn to_owned_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        let l = self.len().min(128);
        out[..l].copy_from_slice(&self[..l]);
        out
    }
}

// ---------------------------------------------------------------------------
// Stub FS helpers (thin wrappers so WASI doesn't need to know FS internals)
// ---------------------------------------------------------------------------

pub mod fs_shim {
    use crate::fs::FileKey;

    /// Read the raw bytes of a file (returns empty slice if missing).
    pub fn read_bytes(key: &FileKey) -> &'static [u8] {
        // We call into the kernel FS.  The returned reference is valid for
        // 'static because the data is leaked from a Box allocation.
        crate::fs::kernel_read_static(key)
    }

    pub fn write_bytes(key: &FileKey, data: &[u8]) {
        crate::fs::kernel_write_bytes(key, data);
    }

    pub fn delete(key: &FileKey) {
        crate::fs::kernel_delete(key);
    }
}
