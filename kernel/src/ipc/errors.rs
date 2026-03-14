use core::fmt;

/// IPC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    InvalidCap,
    PermissionDenied,
    WouldBlock,
    Closed,
    /// The channel is in the `Draining` state: `close()` was called while
    /// in-flight messages remain.  Receivers should keep draining; new sends
    /// are refused with this error so callers can distinguish "channel is
    /// shutting down" from "channel is already fully sealed" (`Closed`).
    ChannelDraining,
    MessageTooLarge,
    TooManyCaps,
    TooManyChannels,
}

impl IpcError {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpcError::InvalidCap => "Invalid capability",
            IpcError::PermissionDenied => "Permission denied",
            IpcError::WouldBlock => "Would block",
            IpcError::Closed => "Channel closed",
            IpcError::ChannelDraining => "Channel draining",
            IpcError::MessageTooLarge => "Message too large",
            IpcError::TooManyCaps => "Too many capabilities",
            IpcError::TooManyChannels => "Too many channels",
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IpcError::InvalidCap => write!(f, "Invalid capability"),
            IpcError::PermissionDenied => write!(f, "Permission denied"),
            IpcError::WouldBlock => write!(f, "Would block"),
            IpcError::Closed => write!(f, "Channel closed"),
            IpcError::ChannelDraining => write!(f, "Channel draining"),
            IpcError::MessageTooLarge => write!(f, "Message too large"),
            IpcError::TooManyCaps => write!(f, "Too many capabilities"),
            IpcError::TooManyChannels => write!(f, "Too many channels"),
        }
    }
}
