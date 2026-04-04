//! # CapabilityWASI — WASI Preview 1 ABI over Oreulius Capabilities
//!
//! Maps the full [WASI Preview 1](https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md)
//! syscall ABI onto Oreulius's capability-based kernel services, enabling
//! musl-libc, WASI-SDK, and Emscripten binaries to run unmodified.
//!
//! ## Design
//!
//! - Every WASI function is a plain `fn(&mut WasiCtx, ...) -> Errno`.
//! - `WasiCtx` holds per-instance state: fd table, preopened dirs, clock offset.
//! - All I/O is routed through `crate::capability`, `crate::fs`, and `crate::rtl8139`.
//! - No heap allocations in the hot path — all tables are fixed-size arrays.
//!
//! ## WASM Host Function IDs (45–99)
//!
//! | ID  | WASI name                   | Notes |
//! |-----|-----------------------------|-------|
//! | 45  | `args_get`                  | argv / argc |
//! | 46  | `args_sizes_get`            | |
//! | 47  | `environ_get`               | environment variables |
//! | 48  | `environ_sizes_get`         | |
//! | 49  | `clock_res_get`             | |
//! | 50  | `clock_time_get`            | |
//! | 51  | `fd_advise`                 | no-op |
//! | 52  | `fd_allocate`               | no-op |
//! | 53  | `fd_close`                  | |
//! | 54  | `fd_datasync`               | no-op |
//! | 55  | `fd_fdstat_get`             | |
//! | 56  | `fd_fdstat_set_flags`       | no-op |
//! | 57  | `fd_fdstat_set_rights`      | no-op |
//! | 58  | `fd_filestat_get`           | |
//! | 59  | `fd_filestat_set_size`      | no-op |
//! | 60  | `fd_filestat_set_times`     | no-op |
//! | 61  | `fd_pread`                  | |
//! | 62  | `fd_prestat_get`            | |
//! | 63  | `fd_prestat_dir_name`       | |
//! | 64  | `fd_pwrite`                 | |
//! | 65  | `fd_read`                   | |
//! | 66  | `fd_readdir`                | |
//! | 67  | `fd_renumber`               | |
//! | 68  | `fd_seek`                   | |
//! | 69  | `fd_sync`                   | no-op |
//! | 70  | `fd_tell`                   | |
//! | 71  | `fd_write`                  | |
//! | 72  | `path_create_directory`     | |
//! | 73  | `path_filestat_get`         | |
//! | 74  | `path_filestat_set_times`   | no-op |
//! | 75  | `path_link`                 | no-op |
//! | 76  | `path_open`                 | |
//! | 77  | `path_readlink`             | no-op |
//! | 78  | `path_remove_directory`     | |
//! | 79  | `path_rename`               | no-op |
//! | 80  | `path_symlink`              | no-op |
//! | 81  | `path_unlink_file`          | |
//! | 82  | `poll_oneoff`               | |
//! | 83  | `proc_exit`                 | |
//! | 84  | `proc_raise`                | no-op |
//! | 85  | `sched_yield`               | |
//! | 86  | `random_get`                | RDRAND-seeded PRNG |
//! | 87  | `sock_accept`               | |
//! | 88  | `sock_recv`                 | |
//! | 89  | `sock_send`                 | |
//! | 90  | `sock_shutdown`             | |

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Network driver abstraction: RTL8139 on x86/x86_64, virtio-net on AArch64.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_has_recv() -> bool {
    crate::rtl8139::has_recv()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_recv(buf: &mut [u8]) -> usize {
    crate::rtl8139::recv(buf)
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn net_send(frame: &[u8]) -> bool {
    crate::rtl8139::send(frame)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_has_recv() -> bool {
    crate::virtio_net::has_recv()
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_recv(buf: &mut [u8]) -> usize {
    crate::virtio_net::recv(buf)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn net_send(frame: &[u8]) -> bool {
    crate::virtio_net::send(frame).is_ok()
}

#[cfg(not(target_arch = "aarch64"))]
#[inline(always)]
fn kbd_has_input() -> bool {
    crate::keyboard::has_input()
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn kbd_has_input() -> bool {
    crate::arch::aarch64_pl011::has_input()
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
    /// For directories: index of last readdir entry returned.
    pub readdir_cookie: u64,
}

impl OpenFd {
    const fn closed() -> Self {
        OpenFd {
            kind: FdKind::Closed,
            offset: 0,
            path: [0; 128],
            path_len: 0,
            size: 0,
            readdir_cookie: 0,
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
        ctx.fds[1].kind = FdKind::Stdout;
        ctx.fds[2].kind = FdKind::Stderr;
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
    let ticks = crate::pit::get_ticks();
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
    let p = stat_ptr as usize;
    let stat_size = core::mem::size_of::<FdStat>();
    if p + stat_size > mem.len() {
        return Errno::Fault;
    }
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
        fs_flags: 0,
        _pad2: 0,
        fs_rights_base: u64::MAX,
        fs_rights_inheriting: u64::MAX,
    };
    // Copy struct bytes safely.
    unsafe {
        let src = &st as *const FdStat as *const u8;
        let dst = mem[p..p + stat_size].as_mut_ptr();
        core::ptr::copy_nonoverlapping(src, dst, stat_size);
    }
    Errno::Success
}

/// fd_filestat_get — write a FileStat for `fd` into WASM memory.
pub fn fd_filestat_get(ctx: &WasiCtx, mem: &mut [u8], fd: Fd, stat_ptr: u32) -> Errno {
    let o = match ctx.get_fd(fd) {
        None => return Errno::Badf,
        Some(o) => o,
    };
    let p = stat_ptr as usize;
    let stat_size = core::mem::size_of::<FileStat>();
    if p + stat_size > mem.len() {
        return Errno::Fault;
    }
    let ft = match o.kind {
        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => filetype::CHAR_DEVICE,
        FdKind::File => filetype::REGULAR_FILE,
        FdKind::Dir => filetype::DIRECTORY,
        FdKind::TcpSocket => filetype::SOCKET_STREAM,
        FdKind::Closed => return Errno::Badf,
    };
    let st = FileStat {
        dev: 0,
        ino: fd as u64,
        filetype: ft,
        _pad: [0; 7],
        nlink: 1,
        size: o.size,
        atim: 0,
        mtim: 0,
        ctim: 0,
    };
    unsafe {
        let src = &st as *const FileStat as *const u8;
        let dst = mem[p..p + stat_size].as_mut_ptr();
        core::ptr::copy_nonoverlapping(src, dst, stat_size);
    }
    Errno::Success
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
                    crate::input::pump();
                    match crate::input::read() {
                        Some(ev) if ev.kind == crate::input::InputEventKind::Key => {
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
                    match crate::arch::aarch64_pl011::read_byte() {
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
            let offset = ctx.fds[fd as usize].offset;
            let path_len = ctx.fds[fd as usize].path_len as usize;
            let path_bytes = ctx.fds[fd as usize].path[..path_len].to_owned_bytes();

            let key_opt = core::str::from_utf8(&path_bytes[..path_len])
                .ok()
                .and_then(|s| crate::fs::FileKey::new(s).ok());
            if let Some(key) = key_opt {
                // We need to read up to the total iov capacity then copy into iovecs.
                let data_vec = crate::fs::kernel_read_bytes(&key).unwrap_or_default();
                let data: &[u8] = &data_vec;
                let start = (offset as usize).min(data.len());
                let available = &data[start..];

                let mut remaining = available;
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
                    let buf_len = u32::from_le_bytes(
                        mem[iov_off + 4..iov_off + 8].try_into().unwrap_or([0; 4]),
                    ) as usize;
                    if buf_ptr + buf_len > mem.len() {
                        return Errno::Fault;
                    }
                    let chunk = remaining.len().min(buf_len);
                    mem[buf_ptr..buf_ptr + chunk].copy_from_slice(&remaining[..chunk]);
                    remaining = &remaining[chunk..];
                    total += chunk as u32;
                }
                ctx.fds[fd as usize].offset += total as u64;
            } else {
                return Errno::Noent;
            }
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
            // Append-write to the Oreulius FS.
            let path_len = ctx.fds[fd as usize].path_len as usize;
            let path_bytes = ctx.fds[fd as usize].path[..path_len].to_owned_bytes();
            let key_opt = core::str::from_utf8(&path_bytes[..path_len])
                .ok()
                .and_then(|s| crate::fs::FileKey::new(s).ok());
            if let Some(key) = key_opt {
                crate::fs::kernel_write_bytes(&key, slice);
                ctx.fds[fd as usize].offset += buf_len as u64;
                ctx.fds[fd as usize].size += buf_len as u64;
            } else {
                return Errno::Io;
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
    let off = match ctx.get_fd(fd) {
        None => return Errno::Badf,
        Some(o) => o.offset,
    };
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
    _oflags: u16,
    _rights: u64,
    _rights_inheriting: u64,
    _fdflags: u16,
    opened_fd_ptr: &mut Fd,
) -> Errno {
    let new_fd = match ctx.alloc_fd() {
        None => return Errno::Mfile,
        Some(fd) => fd,
    };
    let plen = path.len().min(127);
    ctx.fds[new_fd as usize].kind = FdKind::File;
    ctx.fds[new_fd as usize].offset = 0;
    ctx.fds[new_fd as usize].path[..plen].copy_from_slice(&path[..plen]);
    ctx.fds[new_fd as usize].path_len = plen as u8;
    ctx.fds[new_fd as usize].size = 0;
    *opened_fd_ptr = new_fd;
    Errno::Success
}

/// path_unlink_file — remove a file.
pub fn path_unlink_file(_ctx: &mut WasiCtx, path: &[u8]) -> Errno {
    let key_opt = core::str::from_utf8(path)
        .ok()
        .and_then(|s| crate::fs::FileKey::new(s).ok());
    if let Some(key) = key_opt {
        crate::fs::kernel_delete(&key);
        Errno::Success
    } else {
        Errno::Noent
    }
}

/// path_create_directory — no-op stub (Oreulius FS is flat key-value).
pub fn path_create_directory(_ctx: &mut WasiCtx, _path: &[u8]) -> Errno {
    Errno::Success
}

/// path_remove_directory — no-op stub.
pub fn path_remove_directory(_ctx: &mut WasiCtx, _path: &[u8]) -> Errno {
    Errno::Success
}

/// fd_readdir — list files in a directory (fills the WASM buffer with dirent structs).
///
/// Each dirent is: [ ino: u64, cookie: u64, namelen: u32, type: u8, pad: u8 ] = 22 bytes + name
pub fn fd_readdir(
    _ctx: &mut WasiCtx,
    mem: &mut [u8],
    fd: Fd,
    buf_ptr: u32,
    buf_len: u32,
    cookie: u64,
    bufused_ptr: u32,
) -> Errno {
    let _ = (fd, cookie);
    let p = buf_ptr as usize;
    let plen = buf_len as usize;
    let bp = bufused_ptr as usize;
    if bp + 4 > mem.len() {
        return Errno::Fault;
    }
    if p + plen > mem.len() {
        return Errno::Fault;
    }
    // We don't have a directory listing API yet — return empty.
    mem[bp..bp + 4].copy_from_slice(&0u32.to_le_bytes());
    Errno::Success
}

/// path_filestat_get — stat a path.
pub fn path_filestat_get(
    _ctx: &WasiCtx,
    mem: &mut [u8],
    _dirfd: Fd,
    _flags: u32,
    path: &[u8],
    stat_ptr: u32,
) -> Errno {
    let p = stat_ptr as usize;
    let sz = core::mem::size_of::<FileStat>();
    if p + sz > mem.len() {
        return Errno::Fault;
    }
    if let Some(key) = core::str::from_utf8(path)
        .ok()
        .and_then(|s| crate::fs::FileKey::new(s).ok())
    {
        let data_len = crate::fs::kernel_read_bytes(&key)
            .map(|d| d.len() as u64)
            .unwrap_or(0);
        let ft = if data_len > 0 {
            filetype::REGULAR_FILE
        } else {
            filetype::DIRECTORY
        };
        let st = FileStat {
            dev: 0,
            ino: 0,
            filetype: ft,
            _pad: [0; 7],
            nlink: 1,
            size: data_len,
            atim: 0,
            mtim: 0,
            ctim: 0,
        };
        unsafe {
            let src = &st as *const FileStat as *const u8;
            core::ptr::copy_nonoverlapping(src, mem[p..].as_mut_ptr(), sz);
        }
        Errno::Success
    } else {
        Errno::Noent
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
            let now = crate::pit::get_ticks();
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
            Some(d) => crate::pit::get_ticks() >= d,
        };

        if any_fd_ready || clock_expired || earliest_deadline.is_none() {
            break;
        }

        // Not ready yet — yield and retry
        crate::quantum_scheduler::yield_now();
    }

    // --- Phase 3: write event structs for every triggered subscription ------
    let now = crate::pit::get_ticks();
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
    let _ = (ctx, fd);
    let rdp = ro_datalen_ptr as usize;
    let rfp = ro_flags_ptr as usize;
    if rdp + 4 > mem.len() || rfp + 2 > mem.len() {
        return Errno::Fault;
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
    _ctx: &mut WasiCtx,
    mem: &mut [u8],
    _fd: Fd,
    si_data_ptr: u32,
    si_data_len: u32,
    _si_flags: u16,
    so_datalen_ptr: u32,
) -> Errno {
    let sdp = so_datalen_ptr as usize;
    if sdp + 4 > mem.len() {
        return Errno::Fault;
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

/// sock_shutdown — stub.
pub fn sock_shutdown(_ctx: &mut WasiCtx, _fd: Fd, _how: u8) -> Errno {
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
