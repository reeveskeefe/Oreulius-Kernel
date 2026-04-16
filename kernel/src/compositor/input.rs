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


//! Input routing and focus management for the compositor.
//!
//! The `FocusState` tracks which window currently holds keyboard focus and
//! which (if any) has pointer capture.
//!
//! `route_input` is called once per input event from the kernel input ring.
//! It classifies the event, performs hit-testing for pointer events, updates
//! focus, and returns an optional `CompositorInputEvent` to be delivered to
//! the focused session.

#![allow(dead_code)]

use super::protocol::{CompositorInputEvent, WindowId};
use super::session::SessionTable;
use super::window::WindowTable;
use crate::drivers::x86::input::{InputEvent, InputEventKind, KeyState};

// ---------------------------------------------------------------------------
// Pointer cursor state (accumulated absolute position from relative deltas)
// ---------------------------------------------------------------------------

pub struct CursorState {
    pub x: i32,
    pub y: i32,
    pub buttons: u8,
}

impl CursorState {
    pub const fn new() -> Self {
        CursorState {
            x: 0,
            y: 0,
            buttons: 0,
        }
    }

    /// Apply a relative mouse delta, clamped to screen bounds.
    pub fn apply_delta(&mut self, dx: i16, dy: i16, buttons: u8, screen_w: u32, screen_h: u32) {
        self.x = (self.x + dx as i32).max(0).min(screen_w as i32 - 1);
        self.y = (self.y + dy as i32).max(0).min(screen_h as i32 - 1);
        self.buttons = buttons;
    }
}

// ---------------------------------------------------------------------------
// Focus state
// ---------------------------------------------------------------------------

pub struct FocusState {
    /// Window that currently has keyboard focus.
    focused: Option<WindowId>,
    /// Window that has pointer capture (mouse button held down).
    captured: Option<WindowId>,
}

impl FocusState {
    pub const fn new() -> Self {
        FocusState {
            focused: None,
            captured: None,
        }
    }

    pub fn focused_window(&self) -> Option<WindowId> {
        self.focused
    }

    /// Transfer keyboard focus to `wid`.
    /// Returns `(old_focus, new_focus)` so the caller can issue focus-change events.
    pub fn set_focus(&mut self, wid: Option<WindowId>) -> (Option<WindowId>, Option<WindowId>) {
        let old = self.focused;
        self.focused = wid;
        (old, wid)
    }

    /// Begin pointer capture (e.g. mouse button pressed).
    pub fn begin_capture(&mut self, wid: WindowId) {
        self.captured = Some(wid);
    }

    /// End pointer capture (e.g. all mouse buttons released).
    pub fn end_capture(&mut self) {
        self.captured = None;
    }

    pub fn captured_window(&self) -> Option<WindowId> {
        self.captured
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Routing result: an optional event to deliver to a specific session.
pub struct RoutedEvent {
    /// Slot index in the SessionTable of the target session.
    pub session_idx: usize,
    pub event: CompositorInputEvent,
}

/// Route a raw kernel input event.
///
/// `cursor` accumulates the absolute mouse position from relative deltas.
///
/// Returns:
/// - `Some(RoutedEvent)` — the compositor event to deliver to a session.
/// - `None` — the event was consumed with no routing needed.
pub fn route_input(
    raw: &InputEvent,
    windows: &WindowTable,
    sessions: &SessionTable,
    focus: &mut FocusState,
    cursor: &mut CursorState,
    screen_w: u32,
    screen_h: u32,
) -> Option<RoutedEvent> {
    match raw.kind {
        InputEventKind::Key => route_key(raw, windows, sessions, focus),
        InputEventKind::Mouse => {
            route_mouse(raw, windows, sessions, focus, cursor, screen_w, screen_h)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Key routing
// ---------------------------------------------------------------------------

fn route_key(
    raw: &InputEvent,
    windows: &WindowTable,
    sessions: &SessionTable,
    focus: &FocusState,
) -> Option<RoutedEvent> {
    let wid = focus.focused_window()?;
    let window = windows.find(wid)?;
    let session = sessions.get(window.session_idx)?;
    if !session.input_subscribed {
        return None;
    }

    // SAFETY: kind == Key, so the key union arm is valid.
    let key_ev = unsafe { raw.data.key };
    let pressed = key_ev.state == KeyState::Pressed;
    let compositor_ev = CompositorInputEvent::Key {
        window: wid,
        codepoint: key_ev.codepoint,
        scancode: key_ev.scancode,
        pressed,
        modifiers: key_ev.modifiers,
    };

    Some(RoutedEvent {
        session_idx: window.session_idx,
        event: compositor_ev,
    })
}

// ---------------------------------------------------------------------------
// Mouse routing
// ---------------------------------------------------------------------------

fn route_mouse(
    raw: &InputEvent,
    windows: &WindowTable,
    sessions: &SessionTable,
    focus: &mut FocusState,
    cursor: &mut CursorState,
    screen_w: u32,
    screen_h: u32,
) -> Option<RoutedEvent> {
    // SAFETY: kind == Mouse, so the mouse union arm is valid.
    let mouse_ev = unsafe { raw.data.mouse };
    let prev_buttons = cursor.buttons;
    cursor.apply_delta(
        mouse_ev.dx,
        mouse_ev.dy,
        mouse_ev.buttons,
        screen_w,
        screen_h,
    );
    let px = cursor.x;
    let py = cursor.y;

    // Button-press: any new button that wasn't held before.
    let newly_pressed = mouse_ev.buttons & !prev_buttons;
    let newly_released = prev_buttons & !mouse_ev.buttons;

    // Determine which window gets the event.
    let target_wid: WindowId = if let Some(cap) = focus.captured_window() {
        cap
    } else {
        windows.hit_test(px, py)?
    };

    // Update capture / focus on button press.
    if newly_pressed != 0 {
        focus.begin_capture(target_wid);
        // Transfer keyboard focus on click.
        focus.set_focus(Some(target_wid));
    }
    // Release capture once all buttons are released.
    if newly_released != 0 && mouse_ev.buttons == 0 {
        focus.end_capture();
    }

    let window = windows.find(target_wid)?;
    let session = sessions.get(window.session_idx)?;
    if !session.input_subscribed {
        return None;
    }

    let compositor_ev = CompositorInputEvent::Pointer {
        window: target_wid,
        x: px - window.x,
        y: py - window.y,
        dx: mouse_ev.dx,
        dy: mouse_ev.dy,
        buttons: mouse_ev.buttons,
    };

    Some(RoutedEvent {
        session_idx: window.session_idx,
        event: compositor_ev,
    })
}

// ---------------------------------------------------------------------------
// Focus-change event helpers
// ---------------------------------------------------------------------------

/// Build `FocusLost` event for the given window (if a session owns it and is
/// subscribed).
pub fn focus_lost_event(
    wid: WindowId,
    windows: &WindowTable,
    sessions: &SessionTable,
) -> Option<RoutedEvent> {
    let window = windows.find(wid)?;
    let session = sessions.get(window.session_idx)?;
    if !session.input_subscribed {
        return None;
    }
    Some(RoutedEvent {
        session_idx: window.session_idx,
        event: CompositorInputEvent::FocusLost { window: wid },
    })
}

/// Build `FocusGained` event for the given window.
pub fn focus_gained_event(
    wid: WindowId,
    windows: &WindowTable,
    sessions: &SessionTable,
) -> Option<RoutedEvent> {
    let window = windows.find(wid)?;
    let session = sessions.get(window.session_idx)?;
    if !session.input_subscribed {
        return None;
    }
    Some(RoutedEvent {
        session_idx: window.session_idx,
        event: CompositorInputEvent::FocusGained { window: wid },
    })
}

#[cfg(test)]
mod tests {
    use super::{route_input, CursorState, FocusState};
    use crate::compositor::protocol::CompositorInputEvent;
    use crate::compositor::session::SessionTable;
    use crate::compositor::window::WindowTable;
    use crate::drivers::x86::input::InputEvent;
    use crate::ipc::ProcessId;

    fn setup_session_and_window() -> (SessionTable, WindowTable) {
        let mut sessions = SessionTable::new();
        let session_idx = sessions.open(ProcessId(7)).unwrap();
        sessions.get_mut(session_idx).unwrap().input_subscribed = true;

        let mut windows = WindowTable::new();
        let window_id = windows.create(session_idx, 10, 20, 50, 50, 1).unwrap();
        windows.raise(window_id);

        (sessions, windows)
    }

    #[test]
    fn pointer_events_report_window_local_coordinates() {
        let (sessions, windows) = setup_session_and_window();
        let mut focus = FocusState::new();
        let mut cursor = CursorState::new();

        let routed = route_input(
            &InputEvent::mouse_event(15, 25, 0, 1),
            &windows,
            &sessions,
            &mut focus,
            &mut cursor,
            100,
            100,
        )
        .unwrap();

        match routed.event {
            CompositorInputEvent::Pointer { x, y, .. } => assert_eq!((x, y), (5, 5)),
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn pointer_capture_routes_until_all_buttons_released() {
        let (sessions, windows) = setup_session_and_window();
        let mut focus = FocusState::new();
        let mut cursor = CursorState::new();

        let press = route_input(
            &InputEvent::mouse_event(15, 25, 0, 1),
            &windows,
            &sessions,
            &mut focus,
            &mut cursor,
            100,
            100,
        )
        .unwrap();
        let captured = match press.event {
            CompositorInputEvent::Pointer { window, .. } => window,
            other => panic!("unexpected event: {:?}", other),
        };
        assert_eq!(focus.captured_window(), Some(captured));

        let moved = route_input(
            &InputEvent::mouse_event(70, 70, 0, 1),
            &windows,
            &sessions,
            &mut focus,
            &mut cursor,
            100,
            100,
        )
        .unwrap();
        match moved.event {
            CompositorInputEvent::Pointer { window, .. } => assert_eq!(window, captured),
            other => panic!("unexpected event: {:?}", other),
        }

        let released = route_input(
            &InputEvent::mouse_event(0, 0, 0, 0),
            &windows,
            &sessions,
            &mut focus,
            &mut cursor,
            100,
            100,
        )
        .unwrap();
        match released.event {
            CompositorInputEvent::Pointer {
                window, buttons, ..
            } => {
                assert_eq!(window, captured);
                assert_eq!(buttons, 0);
            }
            other => panic!("unexpected event: {:?}", other),
        }
        assert_eq!(focus.captured_window(), None);
    }
}
