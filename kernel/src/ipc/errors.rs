// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0


use core::fmt;

/// IPC errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    InvalidCap,
    PermissionDenied,
    ProtocolMismatch,
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
            IpcError::ProtocolMismatch => "Protocol mismatch",
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
            IpcError::ProtocolMismatch => write!(f, "Protocol mismatch"),
            IpcError::WouldBlock => write!(f, "Would block"),
            IpcError::Closed => write!(f, "Channel closed"),
            IpcError::ChannelDraining => write!(f, "Channel draining"),
            IpcError::MessageTooLarge => write!(f, "Message too large"),
            IpcError::TooManyCaps => write!(f, "Too many capabilities"),
            IpcError::TooManyChannels => write!(f, "Too many channels"),
        }
    }
}
