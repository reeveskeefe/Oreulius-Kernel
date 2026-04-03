//! IPC channel bindings.

use crate::raw::oreulius;

/// A handle to a named Oreulius IPC channel.
pub struct Channel {
    handle: u32,
}

impl Channel {
    /// Open a named IPC channel.  Returns `None` if the channel could not
    /// be opened (name too long, kernel table full, etc.).
    pub fn open(name: &str) -> Option<Self> {
        let handle = unsafe { oreulius::channel_open(name.as_ptr() as u32, name.len() as u32) };
        if handle == u32::MAX {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Send a byte payload over the channel.
    /// Returns `true` on success.
    pub fn send(&self, data: &[u8]) -> bool {
        unsafe { oreulius::channel_send(self.handle, data.as_ptr() as u32, data.len() as u32) == 0 }
    }

    /// Receive up to `buf.len()` bytes from the channel.
    /// Returns the number of bytes actually received.
    pub fn recv(&self, buf: &mut [u8]) -> usize {
        unsafe {
            oreulius::channel_recv(self.handle, buf.as_mut_ptr() as u32, buf.len() as u32) as usize
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { oreulius::channel_close(self.handle) }
    }
}
