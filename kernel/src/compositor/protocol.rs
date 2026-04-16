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


//! Compositor IPC protocol types.
//!
//! Clients communicate with the compositor service by sending and receiving
//! `CompositorRequest` / `CompositorResponse` values over a kernel IPC channel
//! obtained from the service registry.
//!
//! All sizes are in pixels; coordinates are screen-space i32 values (negative
//! values are valid for partially off-screen windows).

#![allow(dead_code)]

use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Handle types
// ---------------------------------------------------------------------------

/// Opaque handle identifying a compositor session (one per client process).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SessionId(pub u32);

/// Opaque handle identifying a window within a session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WindowId(pub u32);

/// Opaque handle identifying a surface (pixel buffer) attached to a window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SurfaceId(pub u32);

/// Capability token vended to a client for a specific compositor resource.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompositorCap(pub u64);

impl CompositorCap {
    pub const INVALID: Self = CompositorCap(0);
    pub fn is_valid(self) -> bool {
        self.0 != 0
    }
}

// ---------------------------------------------------------------------------
// Requests (client → compositor)
// ---------------------------------------------------------------------------

/// Messages a GUI client sends to the compositor service.
#[derive(Copy, Clone, Debug)]
pub enum CompositorRequest {
    /// Ask the compositor to create a session for the calling process.
    /// On success the compositor responds with `SessionGranted`.
    OpenSession { pid: ProcessId },

    /// Close an existing session and destroy all its windows/surfaces.
    CloseSession {
        session: SessionId,
        cap: CompositorCap,
    },

    /// Create a window within a session.
    CreateWindow {
        session: SessionId,
        cap: CompositorCap,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
    },

    /// Destroy a window and its backing surface.
    DestroyWindow {
        window: WindowId,
        cap: CompositorCap,
    },

    /// Move a window to a new screen position.
    MoveWindow {
        window: WindowId,
        cap: CompositorCap,
        x: i32,
        y: i32,
    },

    /// Resize a window (replaces the backing surface).
    ResizeWindow {
        window: WindowId,
        cap: CompositorCap,
        new_width: u32,
        new_height: u32,
    },

    /// Change a window's paint order.
    SetZOrder {
        window: WindowId,
        cap: CompositorCap,
        z: u8,
    },

    /// Write one ARGB pixel into the window's surface.
    SetPixel {
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        argb: u32,
    },

    /// Fill a rectangle with a solid colour.
    FillRect {
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        argb: u32,
    },

    /// Draw text using the built-in 8×8 bitmap font.
    DrawText {
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        /// Text bytes (UTF-8 encoded, max 128 chars).
        text: [u8; 128],
        text_len: u8,
        fg_argb: u32,
    },

    /// Mark a damage region and request a present pass.
    CommitSurface {
        surface: SurfaceId,
        cap: CompositorCap,
        /// Dirty region within the surface (x, y, w, h).  Pass (0,0,0,0)
        /// to mark the whole surface dirty.
        dirty: (u32, u32, u32, u32),
    },

    /// Subscribe this session's event channel to keyboard/mouse input.
    SubscribeInput {
        session: SessionId,
        cap: CompositorCap,
    },

    /// Unsubscribe from input events.
    UnsubscribeInput {
        session: SessionId,
        cap: CompositorCap,
    },
}

// ---------------------------------------------------------------------------
// Responses (compositor → client)
// ---------------------------------------------------------------------------

/// Messages the compositor sends back to a client.
#[derive(Copy, Clone, Debug)]
pub enum CompositorResponse {
    /// Session successfully opened.
    SessionGranted {
        session: SessionId,
        /// Capability token the client must present for session operations.
        session_cap: CompositorCap,
        /// Capability token the client must present for input subscription.
        input_cap: CompositorCap,
    },

    /// Window successfully created.
    WindowCreated {
        window: WindowId,
        /// Capability token for window management operations.
        window_cap: CompositorCap,
        /// The backing surface ID.
        surface: SurfaceId,
        /// Capability token for surface write / commit operations.
        surface_cap: CompositorCap,
    },

    /// Window successfully resized.
    WindowResized {
        window: WindowId,
        /// New surface (old surface is invalidated).
        new_surface: SurfaceId,
        new_surface_cap: CompositorCap,
    },

    /// A present pass was scheduled / completed.
    PresentScheduled,

    /// Generic success acknowledgement.
    Ok,

    /// The requested operation failed.
    Error(CompositorError),
}

/// Compositor error codes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompositorError {
    /// The supplied capability token was invalid or revoked.
    InvalidCapability,
    /// The session ID was not found.
    InvalidSession,
    /// The window ID was not found.
    InvalidWindow,
    /// The surface ID was not found.
    InvalidSurface,
    /// The process quota for windows / surfaces has been reached.
    QuotaExceeded,
    /// Surface dimensions exceed the allowed maximum.
    DimensionsTooLarge,
    /// Width or height violates size constraints (zero, too large, etc.).
    InvalidSize,
    /// No surface allocator memory available.
    OutOfMemory,
    /// The operation is not permitted by policy.
    PermissionDenied,
    /// An internal compositor fault.
    InternalError,
}

impl CompositorError {
    pub fn as_str(self) -> &'static str {
        match self {
            CompositorError::InvalidCapability => "invalid capability",
            CompositorError::InvalidSession => "invalid session",
            CompositorError::InvalidWindow => "invalid window",
            CompositorError::InvalidSurface => "invalid surface",
            CompositorError::QuotaExceeded => "quota exceeded",
            CompositorError::DimensionsTooLarge => "dimensions too large",
            CompositorError::InvalidSize => "invalid size",
            CompositorError::OutOfMemory => "out of memory",
            CompositorError::PermissionDenied => "permission denied",
            CompositorError::InternalError => "internal error",
        }
    }
}

// ---------------------------------------------------------------------------
// Input events delivered to sessions
// ---------------------------------------------------------------------------

/// An input event delivered through the compositor to a focused window.
#[derive(Copy, Clone, Debug)]
pub enum CompositorInputEvent {
    Key {
        window: WindowId,
        codepoint: u32,
        scancode: u8,
        pressed: bool,
        modifiers: u8,
    },
    Pointer {
        window: WindowId,
        /// Pointer position in window-local coordinates.
        x: i32,
        y: i32,
        /// Relative motion.
        dx: i16,
        dy: i16,
        buttons: u8,
    },
    FocusGained {
        window: WindowId,
    },
    FocusLost {
        window: WindowId,
    },
}
