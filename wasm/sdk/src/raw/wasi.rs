//! Raw WASI Preview 1 host-function bindings.
//!
//! The frozen Oreulius kernel exposes the WASI-shaped surface through the
//! `oreulius` host namespace, and the declarations below mirror the frozen
//! host table for IDs `45–90`.
//!
//! The SDK mirrors the fully implemented dispatcher-owned WASI surface so the
//! guest bindings stay in lockstep with the runtime contract.
//!
//! # Safety
//! All functions are `unsafe` because they cross the WASM / host boundary and
//! require the caller to pass valid linear-memory pointers and lengths.

#![allow(clippy::too_many_arguments)]

// ---------------------------------------------------------------------------
// WASI errno type
// ---------------------------------------------------------------------------

/// WASI errno — matches `wasi::Errno` in the spec.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Errno {
    Success = 0,
    TooBig = 1,
    Acces = 2,
    Again = 6,
    Badf = 8,
    Fault = 21,
    Inval = 28,
    Io = 29,
    Notsup = 58,
    Overflow = 61,
    // (add more as needed)
    Unknown = 0xFFFF,
}

impl From<u32> for Errno {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::TooBig,
            2 => Self::Acces,
            6 => Self::Again,
            8 => Self::Badf,
            21 => Self::Fault,
            28 => Self::Inval,
            29 => Self::Io,
            58 => Self::Notsup,
            61 => Self::Overflow,
            _ => Self::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// WASM imports — resolved by the runtime at link time via the import section.
// ---------------------------------------------------------------------------

#[link(wasm_import_module = "oreulius")]
extern "C" {
    /// Get command-line arguments (pointers).
    pub fn args_get(argv_ptr: u32, argv_buf_ptr: u32) -> u32;

    /// Get command-line argument buffer sizes.
    pub fn args_sizes_get(argc_ptr: u32, argv_buf_size_ptr: u32) -> u32;

    /// Get environment variable pointers.
    pub fn environ_get(environ_ptr: u32, environ_buf_ptr: u32) -> u32;

    /// Get environment variable buffer sizes.
    pub fn environ_sizes_get(environ_count_ptr: u32, environ_buf_size_ptr: u32) -> u32;

    /// Clock resolution query.
    pub fn clock_res_get(clock_id: u32, resolution_ptr: u32) -> u32;

    /// Monotonic / real-time clock query.
    pub fn clock_time_get(clock_id: u32, precision: u64, time_ptr: u32) -> u32;

    /// Close a file descriptor.
    pub fn fd_close(fd: u32) -> u32;

    /// Advisory hint over an open file descriptor.
    pub fn fd_advise(fd: u32, offset: u64, len: u64) -> u32;

    /// Ensure a file can hold `offset + len` bytes.
    pub fn fd_allocate(fd: u32, offset: u64, len: u64) -> u32;

    /// Flush file data to stable storage.
    pub fn fd_datasync(fd: u32) -> u32;

    /// Get file-descriptor status.
    pub fn fd_fdstat_get(fd: u32, stat_ptr: u32) -> u32;

    /// Persist fd flag changes such as APPEND / NONBLOCK.
    pub fn fd_fdstat_set_flags(fd: u32, flags: u32) -> u32;

    /// Attenuate rights on an open file descriptor.
    pub fn fd_fdstat_set_rights(
        fd: u32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
    ) -> u32;

    /// Get file stat (metadata).
    pub fn fd_filestat_get(fd: u32, stat_ptr: u32) -> u32;

    /// Truncate or extend a file to `size`.
    pub fn fd_filestat_set_size(fd: u32, size: u64) -> u32;

    /// Update file timestamps on an open descriptor.
    pub fn fd_filestat_set_times(fd: u32, atim: u64, mtim: u64, fst_flags: u32) -> u32;

    /// Positional read from a file descriptor.
    pub fn fd_pread(fd: u32, iovs_ptr: u32, iovs_len: u32, offset: i64, nread_ptr: u32) -> u32;

    /// Get pre-opened directory metadata.
    pub fn fd_prestat_get(fd: u32, buf_ptr: u32) -> u32;

    /// Get pre-opened directory name.
    pub fn fd_prestat_dir_name(fd: u32, path_ptr: u32, path_len: u32) -> u32;

    /// Positional write to a file descriptor.
    pub fn fd_pwrite(
        fd: u32,
        iovs_ptr: u32,
        iovs_len: u32,
        offset: i64,
        nwritten_ptr: u32,
    ) -> u32;

    /// Read bytes from a file descriptor.
    pub fn fd_read(fd: u32, iovs_ptr: u32, iovs_len: u32, nread_ptr: u32) -> u32;

    /// Directory listing.
    pub fn fd_readdir(fd: u32, buf_ptr: u32, buf_len: u32, cookie: u64, bufused_ptr: u32) -> u32;

    /// Atomically move one WASI fd to another slot.
    pub fn fd_renumber(fd: u32, to: u32) -> u32;

    /// Seek within a file.
    pub fn fd_seek(fd: u32, offset: i64, whence: u32, newoffset_ptr: u32) -> u32;

    /// Flush file data and metadata.
    pub fn fd_sync(fd: u32) -> u32;

    /// Tell current position within a file.
    pub fn fd_tell(fd: u32, offset_ptr: u32) -> u32;

    /// Write bytes to a file descriptor.
    /// Returns WASI errno (0 = success).
    pub fn fd_write(fd: u32, iovs_ptr: u32, iovs_len: u32, nwritten_ptr: u32) -> u32;

    /// Create a directory.
    pub fn path_create_directory(fd: u32, path_ptr: u32, path_len: u32) -> u32;

    /// Stat a path relative to a directory fd.
    pub fn path_filestat_get(fd: u32, flags: u32, path_ptr: u32, path_len: u32, stat_ptr: u32) -> u32;

    /// Update path timestamps using Oreulius's frozen 6-argument ABI shape.
    pub fn path_filestat_set_times(
        fd: u32,
        path_ptr: u32,
        path_len: u32,
        atim: u64,
        mtim: u64,
        fst_flags: u32,
    ) -> u32;

    /// Hard-link creation using Oreulius's absolute-path ABI.
    pub fn path_link(
        old_fd: u32,
        old_path_ptr: u32,
        old_path_len: u32,
        new_fd: u32,
        new_path_ptr: u32,
        new_path_len: u32,
    ) -> u32;

    /// Open or create a file relative to a directory fd.
    pub fn path_open(
        dirfd: u32,
        dirflags: u32,
        path_ptr: u32,
        path_len: u32,
        oflags: u32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fdflags: u32,
        fd_ptr: u32,
    ) -> u32;

    /// Read the target of a symbolic link.
    pub fn path_readlink(
        fd: u32,
        path_ptr: u32,
        path_len: u32,
        buf_ptr: u32,
        buf_len: u32,
    ) -> u32;

    /// Remove a directory.
    pub fn path_remove_directory(fd: u32, path_ptr: u32, path_len: u32) -> u32;

    /// Rename a path using Oreulius's frozen 5-argument ABI shape.
    pub fn path_rename(
        old_fd: u32,
        old_path_ptr: u32,
        old_path_len: u32,
        new_path_ptr: u32,
        new_path_len: u32,
    ) -> u32;

    /// Create a symbolic link.
    pub fn path_symlink(
        old_path_ptr: u32,
        old_path_len: u32,
        fd: u32,
        new_path_ptr: u32,
        new_path_len: u32,
    ) -> u32;

    /// Unlink (delete) a file.
    pub fn path_unlink_file(fd: u32, path_ptr: u32, path_len: u32) -> u32;

    /// Wait for I/O events.
    pub fn poll_oneoff(in_ptr: u32, out_ptr: u32, nsubscriptions: u32, nevents_ptr: u32) -> u32;

    /// Terminate the WASM process.
    pub fn proc_exit(rval: u32) -> !;

    /// Deliver a reduced Oreulius signal model to the current WASM process.
    pub fn proc_raise(signal: u32) -> u32;

    /// Fill a buffer with random bytes.
    pub fn random_get(buf_ptr: u32, buf_len: u32) -> u32;

    /// Accept a socket connection.
    pub fn sock_accept(fd: u32, flags: u32, new_fd_ptr: u32) -> u32;

    /// Receive data from a socket.
    pub fn sock_recv(
        fd: u32,
        ri_data_ptr: u32,
        ri_data_len: u32,
        ri_flags: u32,
        ro_datalen_ptr: u32,
        ro_flags_ptr: u32,
    ) -> u32;

    /// Send data via a socket.
    pub fn sock_send(
        fd: u32,
        si_data_ptr: u32,
        si_data_len: u32,
        si_flags: u32,
        so_datalen_ptr: u32,
    ) -> u32;

    /// Shut down send and/or receive on a socket.
    pub fn sock_shutdown(fd: u32, how: u32) -> u32;

    /// Cooperative yield.
    pub fn sched_yield() -> u32;
}
