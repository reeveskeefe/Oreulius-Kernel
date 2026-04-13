/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! Compositor service — global singleton and request dispatcher.
//!
//! `CompositorService` owns all compositor subsystems:
//!   - `SessionTable`       — client sessions
//!   - `WindowTable`        — window metadata
//!   - `SurfacePool`        — pixel buffers
//!   - `CompositorCapRegistry` — capability tokens
//!   - `DamageAccumulator`  — dirty regions
//!   - `FocusState`         — keyboard focus / pointer capture
//!   - `CursorState`        — accumulated absolute pointer position
//!   - `FbBackend`          — display output
//!   - `CompositorPolicy`   — quota and bounds checks
//!   - `AuditLog`           — event history ring buffer
//!
//! Public API:
//!   - `init(width, height)` — called once at boot after framebuffer init
//!   - `tick()`              — called every timer tick to pump input + present
//!   - `handle_request(req) → CompositorResponse` — process one IPC message

#![allow(dead_code)]

use spin::Mutex;

use super::audit::{AuditKind, AuditLog};
use super::backend::DisplayBackend;
use super::capability::{CapKind, CompositorCapRegistry};
use super::damage::DamageAccumulator;
use super::fb_backend::FbBackend;
use super::input::{route_input, CursorState, FocusState};
use super::policy::CompositorPolicy;
use super::present::present_frame;
use super::protocol::{
    CompositorCap, CompositorError, CompositorRequest, CompositorResponse, SessionId, SurfaceId,
    WindowId,
};
use super::session::SessionTable;
use super::surface::SurfacePool;
use super::window::WindowTable;
use crate::ipc::ProcessId;

// ---------------------------------------------------------------------------
// Global service singleton
// ---------------------------------------------------------------------------

pub static COMPOSITOR_SERVICE: Mutex<CompositorService> = Mutex::new(CompositorService::new());

// ---------------------------------------------------------------------------
// Service struct
// ---------------------------------------------------------------------------

pub struct CompositorService {
    sessions: SessionTable,
    windows: WindowTable,
    surfaces: SurfacePool,
    caps: CompositorCapRegistry,
    damage: DamageAccumulator,
    focus: FocusState,
    cursor: CursorState,
    backend: FbBackend,
    policy: CompositorPolicy,
    audit: AuditLog,
    screen_width: u32,
    screen_height: u32,
    initialised: bool,
}

impl CompositorService {
    pub const fn new() -> Self {
        CompositorService {
            sessions: SessionTable::new(),
            windows: WindowTable::new(),
            surfaces: SurfacePool::new(),
            caps: CompositorCapRegistry::new(),
            damage: DamageAccumulator::new(0, 0),
            focus: FocusState::new(),
            cursor: CursorState::new(),
            backend: FbBackend::new(0, 0),
            policy: CompositorPolicy::new(),
            audit: AuditLog::new(),
            screen_width: 0,
            screen_height: 0,
            initialised: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Boot init
// ---------------------------------------------------------------------------

/// Initialise the compositor subsystem.  Call once after the framebuffer
/// driver is ready.
pub fn init(width: u32, height: u32) {
    let mut svc = COMPOSITOR_SERVICE.lock();
    svc.backend.set_size(width, height);
    svc.damage.set_screen_size(width, height);
    svc.screen_width = width;
    svc.screen_height = height;
    svc.initialised = true;
    svc.audit.record_simple(AuditKind::PresentComplete);

    // Clear the framebuffer to solid black.
    if svc.backend.is_available() {
        svc.backend.fill_rect(0, 0, width, height, 0, 0, 0);
        svc.backend.flush();
    }
}

// ---------------------------------------------------------------------------
// Tick (called every kernel timer tick)
// ---------------------------------------------------------------------------

/// Per-tick pump: drain input events and present dirty windows.
pub fn tick() {
    let mut svc = COMPOSITOR_SERVICE.lock();
    if !svc.initialised {
        return;
    }

    // --- Input pump ---
    while let Some(ev) = crate::drivers::x86::input::read() {
        let sw = svc.screen_width;
        let sh = svc.screen_height;
        // The borrow checker cannot see that windows/sessions and focus/cursor
        // are disjoint fields inside the MutexGuard.  We use raw pointers to
        // convince it; all accesses happen synchronously within the lock.
        let routed = unsafe {
            let focus_ptr: *mut _ = &mut svc.focus;
            let cursor_ptr: *mut _ = &mut svc.cursor;
            route_input(
                &ev,
                &svc.windows,
                &svc.sessions,
                &mut *focus_ptr,
                &mut *cursor_ptr,
                sw,
                sh,
            )
        };
        if let Some(re) = routed {
            // In the future: push `re.event` onto session's event channel.
            // For now we just record the routing in the audit log.
            svc.audit
                .record(AuditKind::InputRouted, re.session_idx as i32, 0);
        }
    }

    // --- Present if dirty ---
    if svc.windows.any_dirty() || svc.damage.is_dirty() {
        // Collect dirty window regions first (immutable borrow of windows),
        // then add them to damage accumulator (mutable borrow of damage).
        let mut dirty_regions: [(i32, i32, u32, u32); super::window::MAX_WINDOWS] =
            [(0, 0, 0, 0); super::window::MAX_WINDOWS];
        let mut dirty_count = 0usize;
        let mut sorted_ids = [WindowId(0); super::window::MAX_WINDOWS];
        let count = svc.windows.sorted_ids(&mut sorted_ids);
        for &wid in &sorted_ids[..count] {
            if let Some(win) = svc.windows.find(wid) {
                if win.dirty {
                    dirty_regions[dirty_count] = (win.x, win.y, win.width, win.height);
                    dirty_count += 1;
                }
            }
        }
        // Now mutably borrow damage accumulator.
        for &(x, y, w, h) in &dirty_regions[..dirty_count] {
            svc.damage.add_region(x, y, w, h);
        }

        present_frame(&svc.damage, &svc.windows, &svc.surfaces, &svc.backend);
        svc.backend.flush();
        svc.damage.clear();
        svc.windows.clear_dirty_all();
        svc.audit.record_simple(AuditKind::PresentComplete);
    }
}

// ---------------------------------------------------------------------------
// Request dispatcher
// ---------------------------------------------------------------------------

/// Handle one compositor IPC request and return the response.
pub fn handle_request(req: CompositorRequest) -> CompositorResponse {
    let mut svc = COMPOSITOR_SERVICE.lock();
    if !svc.initialised {
        return CompositorResponse::Error(CompositorError::InternalError);
    }
    svc.dispatch(req)
}

// ---------------------------------------------------------------------------
// Dispatch impl (avoids borrow-checker split on the global lock)
// ---------------------------------------------------------------------------

impl CompositorService {
    fn dispatch(&mut self, req: CompositorRequest) -> CompositorResponse {
        match req {
            // ----------------------------------------------------------------
            CompositorRequest::OpenSession { pid } => self.do_open_session(pid),

            CompositorRequest::CloseSession { session, cap } => self.do_close_session(session, cap),

            CompositorRequest::CreateWindow {
                session,
                cap,
                x,
                y,
                width,
                height,
            } => self.do_create_window(session, cap, x, y, width, height),

            CompositorRequest::DestroyWindow { window, cap } => self.do_destroy_window(window, cap),

            CompositorRequest::MoveWindow { window, cap, x, y } => {
                self.do_move_window(window, cap, x, y)
            }

            CompositorRequest::ResizeWindow {
                window,
                cap,
                new_width,
                new_height,
            } => self.do_resize_window(window, cap, new_width, new_height),

            CompositorRequest::SetZOrder { window, cap, z } => self.do_set_z_order(window, cap, z),

            CompositorRequest::SetPixel {
                surface,
                cap,
                x,
                y,
                argb,
            } => self.do_set_pixel(surface, cap, x, y, argb),

            CompositorRequest::FillRect {
                surface,
                cap,
                x,
                y,
                width,
                height,
                argb,
            } => self.do_fill_rect(surface, cap, x, y, width, height, argb),

            CompositorRequest::DrawText {
                surface,
                cap,
                x,
                y,
                text,
                text_len,
                fg_argb,
            } => self.do_draw_text(surface, cap, x, y, &text, text_len as usize, fg_argb),

            CompositorRequest::CommitSurface {
                surface,
                cap,
                dirty,
            } => self.do_commit_surface(surface, cap, dirty),

            CompositorRequest::SubscribeInput { session, cap } => {
                self.do_subscribe_input(session, cap)
            }

            CompositorRequest::UnsubscribeInput { session, cap } => {
                self.do_unsubscribe_input(session, cap)
            }
        }
    }

    // ----------------------------------------------------------------
    // OpenSession
    // ----------------------------------------------------------------

    fn do_open_session(&mut self, pid: ProcessId) -> CompositorResponse {
        let idx = match self.sessions.open(pid) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::QuotaExceeded),
        };
        let session = self.sessions.get(idx).unwrap();
        let resp = CompositorResponse::SessionGranted {
            session: session.id,
            session_cap: session.cap,
            input_cap: session.input_cap,
        };
        self.audit
            .record(AuditKind::SessionOpened, idx as i32, pid.0 as u64);
        resp
    }

    // ----------------------------------------------------------------
    // CloseSession
    // ----------------------------------------------------------------

    fn do_close_session(&mut self, session: SessionId, cap: CompositorCap) -> CompositorResponse {
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::InvalidSession),
        };
        {
            let s = self.sessions.get(idx).unwrap();
            if !s.check_cap(cap) {
                return CompositorResponse::Error(CompositorError::InvalidCapability);
            }
        }

        // Destroy all windows and surfaces owned by this session.
        let mut wids_to_destroy = [WindowId(0); 64];
        let mut wcount = 0usize;
        {
            let mut sorted = [WindowId(0); super::window::MAX_WINDOWS];
            let n = self.windows.sorted_ids(&mut sorted);
            for &wid in &sorted[..n] {
                if let Some(win) = self.windows.find(wid) {
                    if win.session_idx == idx {
                        if wcount < 64 {
                            wids_to_destroy[wcount] = wid;
                            wcount += 1;
                        }
                    }
                }
            }
        }
        for &wid in &wids_to_destroy[..wcount] {
            self.destroy_window_internal(wid);
        }

        self.caps.revoke_session(idx);
        self.sessions.close(idx);
        self.audit.record(AuditKind::SessionClosed, idx as i32, 0);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // CreateWindow
    // ----------------------------------------------------------------

    fn do_create_window(
        &mut self,
        session: SessionId,
        cap: CompositorCap,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
    ) -> CompositorResponse {
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::InvalidSession),
        };
        {
            let s = self.sessions.get(idx).unwrap();
            if !s.check_cap(cap) {
                return CompositorResponse::Error(CompositorError::InvalidCapability);
            }
        }

        let win_count = self.windows.count_for_session(idx);
        if let Err(e) = self.policy.check_create_window(win_count, width, height) {
            return CompositorResponse::Error(e);
        }

        // Clamp position.
        let (cx, cy) =
            self.policy
                .clamp_position(x, y, width, height, self.screen_width, self.screen_height);

        // Allocate backing surface.
        let surface_idx = match self.surfaces.alloc(width, height) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::OutOfMemory),
        };

        // Allocate window record.
        let window_id = match self.windows.create(idx, cx, cy, width, height, surface_idx) {
            Some(id) => id,
            None => {
                self.surfaces.free(surface_idx);
                return CompositorResponse::Error(CompositorError::QuotaExceeded);
            }
        };

        // Bookkeep in session.
        self.sessions.get_mut(idx).unwrap().add_window(window_id);

        // Issue capabilities.
        let surface_id = SurfaceId(surface_idx as u32);
        let window_cap = self
            .caps
            .issue(CapKind::WindowManage, idx, window_id.0 as u64);
        let surface_cap = self
            .caps
            .issue(CapKind::SurfaceWrite, idx, surface_idx as u64);

        self.damage.add_region(cx, cy, width, height);
        self.audit
            .record(AuditKind::WindowCreated, idx as i32, window_id.0 as u64);

        CompositorResponse::WindowCreated {
            window: window_id,
            window_cap,
            surface: surface_id,
            surface_cap,
        }
    }

    // ----------------------------------------------------------------
    // DestroyWindow
    // ----------------------------------------------------------------

    fn do_destroy_window(&mut self, window: WindowId, cap: CompositorCap) -> CompositorResponse {
        // Validate capability.
        let (session_idx, resource_id) = match self.caps.validate(cap, CapKind::WindowManage) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != window.0 as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let win_meta = match self.windows.find(window) {
            Some(w) => *w,
            None => return CompositorResponse::Error(CompositorError::InvalidWindow),
        };
        if win_meta.session_idx != session_idx {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }

        self.destroy_window_internal(window);
        self.caps.revoke(cap);
        CompositorResponse::Ok
    }

    fn destroy_window_internal(&mut self, wid: WindowId) {
        if let Some(win) = self.windows.find(wid) {
            let sidx = win.session_idx;
            let surf_idx = win.surface_idx;
            // Add damage for the vacated area.
            self.damage.add_region(win.x, win.y, win.width, win.height);
            self.audit
                .record(AuditKind::WindowDestroyed, sidx as i32, wid.0 as u64);
            self.caps
                .revoke_resource(CapKind::WindowManage, sidx, wid.0 as u64);
            self.caps
                .revoke_resource(CapKind::SurfaceWrite, sidx, surf_idx as u64);
            self.surfaces.free(surf_idx);
            self.sessions.get_mut(sidx).map(|s| s.remove_window(wid));
        }
        self.windows.destroy(wid);
    }

    // ----------------------------------------------------------------
    // MoveWindow
    // ----------------------------------------------------------------

    fn do_move_window(
        &mut self,
        window: WindowId,
        cap: CompositorCap,
        x: i32,
        y: i32,
    ) -> CompositorResponse {
        let (session_idx, resource_id) = match self.caps.validate(cap, CapKind::WindowManage) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != window.0 as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let win = match self.windows.find(window) {
            Some(w) => *w,
            None => return CompositorResponse::Error(CompositorError::InvalidWindow),
        };
        if win.session_idx != session_idx {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }

        // Damage old position.
        self.damage.add_region(win.x, win.y, win.width, win.height);

        let (cx, cy) = self.policy.clamp_position(
            x,
            y,
            win.width,
            win.height,
            self.screen_width,
            self.screen_height,
        );
        self.windows.move_to(window, cx, cy);

        // Damage new position.
        self.damage.add_region(cx, cy, win.width, win.height);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // ResizeWindow
    // ----------------------------------------------------------------

    fn do_resize_window(
        &mut self,
        window: WindowId,
        cap: CompositorCap,
        new_width: u32,
        new_height: u32,
    ) -> CompositorResponse {
        let (session_idx, resource_id) = match self.caps.validate(cap, CapKind::WindowManage) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != window.0 as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let win = match self.windows.find(window) {
            Some(w) => *w,
            None => return CompositorResponse::Error(CompositorError::InvalidWindow),
        };
        if win.session_idx != session_idx {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }

        if let Err(e) = self.policy.check_window_size(new_width, new_height) {
            return CompositorResponse::Error(e);
        }

        // Damage old area.
        self.damage.add_region(win.x, win.y, win.width, win.height);

        // Allocate new surface; free old.
        let new_surf_idx = match self.surfaces.alloc(new_width, new_height) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::OutOfMemory),
        };
        self.caps
            .revoke_resource(CapKind::SurfaceWrite, session_idx, win.surface_idx as u64);
        self.surfaces.free(win.surface_idx);
        self.windows
            .resize(window, new_width, new_height, new_surf_idx);

        let new_surface_id = SurfaceId(new_surf_idx as u32);
        let new_surface_cap =
            self.caps
                .issue(CapKind::SurfaceWrite, session_idx, new_surf_idx as u64);

        self.damage.add_region(win.x, win.y, new_width, new_height);

        CompositorResponse::WindowResized {
            window,
            new_surface: new_surface_id,
            new_surface_cap,
        }
    }

    // ----------------------------------------------------------------
    // SetZOrder
    // ----------------------------------------------------------------

    fn do_set_z_order(
        &mut self,
        window: WindowId,
        cap: CompositorCap,
        z: u8,
    ) -> CompositorResponse {
        let (session_idx, resource_id) = match self.caps.validate(cap, CapKind::WindowManage) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != window.0 as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let win = match self.windows.find(window) {
            Some(w) => *w,
            None => return CompositorResponse::Error(CompositorError::InvalidWindow),
        };
        if win.session_idx != session_idx {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        self.windows.set_z_order(window, z as i32);
        self.damage.add_region(win.x, win.y, win.width, win.height);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // SetPixel
    // ----------------------------------------------------------------

    fn do_set_pixel(
        &mut self,
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        argb: u32,
    ) -> CompositorResponse {
        let surf_idx = surface.0 as usize;
        let (_, resource_id) = match self.caps.validate(cap, CapKind::SurfaceWrite) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != surf_idx as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let surf = match self.surfaces.get_mut(surf_idx) {
            Some(s) => s,
            None => return CompositorResponse::Error(CompositorError::InvalidSurface),
        };
        surf.set_pixel(x, y, argb);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // FillRect
    // ----------------------------------------------------------------

    fn do_fill_rect(
        &mut self,
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        argb: u32,
    ) -> CompositorResponse {
        let surf_idx = surface.0 as usize;
        let (_, resource_id) = match self.caps.validate(cap, CapKind::SurfaceWrite) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != surf_idx as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let surf = match self.surfaces.get_mut(surf_idx) {
            Some(s) => s,
            None => return CompositorResponse::Error(CompositorError::InvalidSurface),
        };
        surf.fill_rect(x, y, width, height, argb);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // DrawText
    // ----------------------------------------------------------------

    fn do_draw_text(
        &mut self,
        surface: SurfaceId,
        cap: CompositorCap,
        x: u32,
        y: u32,
        text: &[u8; 128],
        text_len: usize,
        fg_argb: u32,
    ) -> CompositorResponse {
        let surf_idx = surface.0 as usize;
        let (_, resource_id) = match self.caps.validate(cap, CapKind::SurfaceWrite) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != surf_idx as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        let surf = match self.surfaces.get_mut(surf_idx) {
            Some(s) => s,
            None => return CompositorResponse::Error(CompositorError::InvalidSurface),
        };
        let len = text_len.min(128);
        // Convert the fixed-size byte array to a &str (best-effort UTF-8).
        let text_str = core::str::from_utf8(&text[..len]).unwrap_or("");
        surf.draw_text(x, y, text_str, fg_argb);
        CompositorResponse::Ok
    }

    // ----------------------------------------------------------------
    // CommitSurface
    // ----------------------------------------------------------------

    fn do_commit_surface(
        &mut self,
        surface: SurfaceId,
        cap: CompositorCap,
        dirty: (u32, u32, u32, u32),
    ) -> CompositorResponse {
        let surf_idx = surface.0 as usize;
        let (_, resource_id) = match self.caps.validate(cap, CapKind::SurfaceWrite) {
            Some(v) => v,
            None => return CompositorResponse::Error(CompositorError::InvalidCapability),
        };
        if resource_id != surf_idx as u64 {
            return CompositorResponse::Error(CompositorError::InvalidCapability);
        }
        if self.surfaces.get(surf_idx).is_none() {
            return CompositorResponse::Error(CompositorError::InvalidSurface);
        }

        if let Some(win) = self.windows.find_by_surface_idx(surf_idx).copied() {
            self.windows.mark_dirty(win.id);
            if dirty.2 > 0 && dirty.3 > 0 {
                self.damage.add_region(
                    win.x + dirty.0 as i32,
                    win.y + dirty.1 as i32,
                    dirty.2,
                    dirty.3,
                );
            } else {
                self.damage.add_region(win.x, win.y, win.width, win.height);
            }
        }

        self.audit.record_simple(AuditKind::SurfaceCommit);
        CompositorResponse::PresentScheduled
    }

    // ----------------------------------------------------------------
    // SubscribeInput / UnsubscribeInput
    // ----------------------------------------------------------------

    fn do_subscribe_input(&mut self, session: SessionId, cap: CompositorCap) -> CompositorResponse {
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::InvalidSession),
        };
        {
            let s = self.sessions.get(idx).unwrap();
            if !s.check_input_cap(cap) {
                // Also accept a valid session cap for convenience.
                if !s.check_cap(cap) {
                    return CompositorResponse::Error(CompositorError::InvalidCapability);
                }
            }
        }
        if let Err(e) = self.policy.check_input_subscription() {
            return CompositorResponse::Error(e);
        }
        self.sessions.get_mut(idx).unwrap().input_subscribed = true;
        CompositorResponse::Ok
    }

    fn do_unsubscribe_input(
        &mut self,
        session: SessionId,
        cap: CompositorCap,
    ) -> CompositorResponse {
        let idx = match self.sessions.find(session) {
            Some(i) => i,
            None => return CompositorResponse::Error(CompositorError::InvalidSession),
        };
        {
            let s = self.sessions.get(idx).unwrap();
            if !s.check_input_cap(cap) && !s.check_cap(cap) {
                return CompositorResponse::Error(CompositorError::InvalidCapability);
            }
        }
        self.sessions.get_mut(idx).unwrap().input_subscribed = false;
        CompositorResponse::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static TEST_MEMORY_INIT: Once = Once::new();

    fn init_test_memory() {
        TEST_MEMORY_INIT.call_once(crate::memory::init);
    }

    fn test_service() -> CompositorService {
        init_test_memory();
        let mut svc = CompositorService::new();
        svc.screen_width = 800;
        svc.screen_height = 600;
        svc.backend.set_size(800, 600);
        svc.damage.set_screen_size(800, 600);
        svc.initialised = true;
        svc
    }

    fn expect_error(resp: CompositorResponse, expected: CompositorError) {
        match resp {
            CompositorResponse::Error(err) => assert_eq!(err, expected),
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn surface_caps_are_resource_bound() {
        let mut svc = test_service();
        let (session, session_cap) =
            match svc.dispatch(CompositorRequest::OpenSession { pid: ProcessId(1) }) {
                CompositorResponse::SessionGranted {
                    session,
                    session_cap,
                    ..
                } => (session, session_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        let (surface_a, _surface_cap_a) = match svc.dispatch(CompositorRequest::CreateWindow {
            session,
            cap: session_cap,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        }) {
            CompositorResponse::WindowCreated {
                surface,
                surface_cap,
                ..
            } => (surface, surface_cap),
            other => panic!("unexpected response: {:?}", other),
        };
        let (_surface_b, surface_cap_b) = match svc.dispatch(CompositorRequest::CreateWindow {
            session,
            cap: session_cap,
            x: 20,
            y: 20,
            width: 10,
            height: 10,
        }) {
            CompositorResponse::WindowCreated {
                surface,
                surface_cap,
                ..
            } => (surface, surface_cap),
            other => panic!("unexpected response: {:?}", other),
        };

        expect_error(
            svc.dispatch(CompositorRequest::SetPixel {
                surface: surface_a,
                cap: surface_cap_b,
                x: 0,
                y: 0,
                argb: 0xFFFF_FFFF,
            }),
            CompositorError::InvalidCapability,
        );
    }

    #[test]
    fn window_caps_are_resource_bound() {
        let mut svc = test_service();
        let (session, session_cap) =
            match svc.dispatch(CompositorRequest::OpenSession { pid: ProcessId(2) }) {
                CompositorResponse::SessionGranted {
                    session,
                    session_cap,
                    ..
                } => (session, session_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        let (window_a, _window_cap_a) = match svc.dispatch(CompositorRequest::CreateWindow {
            session,
            cap: session_cap,
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        }) {
            CompositorResponse::WindowCreated {
                window, window_cap, ..
            } => (window, window_cap),
            other => panic!("unexpected response: {:?}", other),
        };
        let (_window_b, window_cap_b) = match svc.dispatch(CompositorRequest::CreateWindow {
            session,
            cap: session_cap,
            x: 20,
            y: 20,
            width: 10,
            height: 10,
        }) {
            CompositorResponse::WindowCreated {
                window, window_cap, ..
            } => (window, window_cap),
            other => panic!("unexpected response: {:?}", other),
        };

        expect_error(
            svc.dispatch(CompositorRequest::MoveWindow {
                window: window_a,
                cap: window_cap_b,
                x: 30,
                y: 30,
            }),
            CompositorError::InvalidCapability,
        );
    }

    #[test]
    fn old_surface_caps_are_revoked_after_resize() {
        let mut svc = test_service();
        let (session, session_cap) =
            match svc.dispatch(CompositorRequest::OpenSession { pid: ProcessId(3) }) {
                CompositorResponse::SessionGranted {
                    session,
                    session_cap,
                    ..
                } => (session, session_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        let (window, window_cap, surface, surface_cap) =
            match svc.dispatch(CompositorRequest::CreateWindow {
                session,
                cap: session_cap,
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }) {
                CompositorResponse::WindowCreated {
                    window,
                    window_cap,
                    surface,
                    surface_cap,
                } => (window, window_cap, surface, surface_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        let (new_surface, new_surface_cap) = match svc.dispatch(CompositorRequest::ResizeWindow {
            window,
            cap: window_cap,
            new_width: 20,
            new_height: 20,
        }) {
            CompositorResponse::WindowResized {
                new_surface,
                new_surface_cap,
                ..
            } => (new_surface, new_surface_cap),
            other => panic!("unexpected response: {:?}", other),
        };

        expect_error(
            svc.dispatch(CompositorRequest::SetPixel {
                surface,
                cap: surface_cap,
                x: 0,
                y: 0,
                argb: 0xFFFF_FFFF,
            }),
            CompositorError::InvalidCapability,
        );

        match svc.dispatch(CompositorRequest::SetPixel {
            surface: new_surface,
            cap: new_surface_cap,
            x: 0,
            y: 0,
            argb: 0xFFFF_FFFF,
        }) {
            CompositorResponse::Ok => {}
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn destroyed_resources_revoke_caps() {
        let mut svc = test_service();
        let (session, session_cap) =
            match svc.dispatch(CompositorRequest::OpenSession { pid: ProcessId(4) }) {
                CompositorResponse::SessionGranted {
                    session,
                    session_cap,
                    ..
                } => (session, session_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        let (window, window_cap, surface, surface_cap) =
            match svc.dispatch(CompositorRequest::CreateWindow {
                session,
                cap: session_cap,
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            }) {
                CompositorResponse::WindowCreated {
                    window,
                    window_cap,
                    surface,
                    surface_cap,
                } => (window, window_cap, surface, surface_cap),
                other => panic!("unexpected response: {:?}", other),
            };

        match svc.dispatch(CompositorRequest::DestroyWindow {
            window,
            cap: window_cap,
        }) {
            CompositorResponse::Ok => {}
            other => panic!("unexpected response: {:?}", other),
        }

        expect_error(
            svc.dispatch(CompositorRequest::DestroyWindow {
                window,
                cap: window_cap,
            }),
            CompositorError::InvalidCapability,
        );
        expect_error(
            svc.dispatch(CompositorRequest::SetPixel {
                surface,
                cap: surface_cap,
                x: 0,
                y: 0,
                argb: 0xFFFF_FFFF,
            }),
            CompositorError::InvalidCapability,
        );
    }
}
