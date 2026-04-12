//! IPC channel bindings.

use crate::raw::oreulius;

/// A handle to an Oreulius IPC channel capability.
///
/// The kernel owns channel creation and lifecycle. The SDK wrapper only
/// forwards send/receive operations against an existing channel handle.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    handle: u32,
}

impl Channel {
    /// Wrap an existing raw channel handle.
    pub const fn from_handle(handle: u32) -> Self {
        Self { handle }
    }

    /// Return the raw channel handle.
    pub const fn handle(&self) -> u32 {
        self.handle
    }

    /// Return `true` if the handle is non-zero.
    ///
    /// Channel IDs are kernel-minted and zero is reserved as invalid.
    pub const fn is_valid(&self) -> bool {
        self.handle != 0
    }

    /// Send a byte payload over the channel.
    /// Returns `true` on success.
    pub fn send(&self, data: &[u8]) -> bool {
        unsafe { oreulius::channel_send(self.handle, data.as_ptr() as u32, data.len() as u32) == 0 }
    }

    /// Send a byte payload and attach a capability handle.
    /// Returns `true` on success.
    pub fn send_cap(&self, data: &[u8], cap: u32) -> bool {
        unsafe {
            oreulius::channel_send_cap(self.handle, data.as_ptr() as u32, data.len() as u32, cap)
                == 0
        }
    }

    /// Receive up to `buf.len()` bytes from the channel.
    ///
    /// Returns the number of bytes actually received, or `Err(code)` if the
    /// host reports a negative error.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, i32> {
        let rc = unsafe {
            oreulius::channel_recv(self.handle, buf.as_mut_ptr() as u32, buf.len() as u32)
        };
        if rc >= 0 { Ok(rc as usize) } else { Err(rc) }
    }
}
