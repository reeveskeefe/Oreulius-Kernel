//! Network socket helpers (thin wrapper over WASI sock_* and RTL8139 path).

use crate::raw::wasi;

/// A WASM file descriptor that refers to a socket.
pub struct Socket {
    fd: u32,
}

impl Socket {
    /// Wrap a raw WASI fd as a socket.
    pub const fn from_raw(fd: u32) -> Self {
        Self { fd }
    }

    /// Accept a pending connection on `listen_fd`.
    ///
    /// Returns `None` if no connection is available (`Errno::Again`).
    pub fn accept(listen_fd: u32) -> Option<Self> {
        // new_fd output at scratch address 72
        const NEW_FD_SCRATCH: u32 = 72;
        unsafe {
            (NEW_FD_SCRATCH as usize as *mut u32).write_unaligned(u32::MAX);
        }
        let errno = unsafe { wasi::sock_accept(listen_fd, 0, NEW_FD_SCRATCH) };
        if errno != 0 {
            return None;
        }
        let new_fd = unsafe { (NEW_FD_SCRATCH as usize as *const u32).read_unaligned() };
        if new_fd == u32::MAX {
            None
        } else {
            Some(Self { fd: new_fd })
        }
    }

    /// Send a byte slice.  Returns bytes sent or 0 on error.
    pub fn send(&self, data: &[u8]) -> usize {
        // iovec at [0..7], nwritten at [8..11]
        unsafe {
            (0usize as *mut u32).write_unaligned(data.as_ptr() as u32);
            (4usize as *mut u32).write_unaligned(data.len() as u32);
        }
        let errno = unsafe { wasi::sock_send(self.fd, 0, 1, 0, 8) };
        if errno != 0 {
            return 0;
        }
        unsafe { (8usize as *const u32).read_unaligned() as usize }
    }

    /// Receive into `buf`.  Returns bytes received or 0.
    pub fn recv(&self, buf: &mut [u8]) -> usize {
        // read iovec at [0..7], nread at [8..11], flags at [12..13]
        unsafe {
            (0usize as *mut u32).write_unaligned(buf.as_mut_ptr() as u32);
            (4usize as *mut u32).write_unaligned(buf.len() as u32);
        }
        let errno = unsafe { wasi::sock_recv(self.fd, 0, 1, 0, 8, 12) };
        if errno != 0 {
            return 0;
        }
        unsafe { (8usize as *const u32).read_unaligned() as usize }
    }

    /// Close the socket fd.
    pub fn close(self) {
        unsafe { wasi::fd_close(self.fd) };
        core::mem::forget(self);
    }

    pub fn fd(&self) -> u32 {
        self.fd
    }
}
