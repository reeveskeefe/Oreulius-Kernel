/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

#[cfg(not(target_arch = "aarch64"))]
pub use crate::ipc::{ChannelCapability, ProcessId as Pid};

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pid(pub u32);

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
pub struct ChannelCapability;

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn on_process_spawn(pid: Pid, parent: Option<Pid>, name: &str) {
    crate::security::security().init_process(pid);
    crate::capability::capability_manager().init_task(pid);

    if !crate::temporal::is_replay_active() {
        let _ = crate::temporal::record_process_event(
            pid.0,
            parent.map(|p| p.0),
            crate::temporal::TEMPORAL_PROCESS_EVENT_SPAWN,
            name,
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn on_process_spawn(_pid: Pid, _parent: Option<Pid>, _name: &str) {}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn on_process_terminate(pid: Pid) {
    let _ = crate::ipc::purge_channels_for_process(pid);
    let _ = crate::wasm::revoke_service_pointers_for_owner(pid);
    let _ = crate::wasm::unload_modules_for_owner(pid);
    crate::capability::capability_manager().deinit_task(pid);
    crate::security::security().terminate_process(pid);

    if !crate::temporal::is_replay_active() {
        let _ = crate::temporal::record_process_event(
            pid.0,
            None,
            crate::temporal::TEMPORAL_PROCESS_EVENT_TERMINATE,
            "",
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn on_process_terminate(_pid: Pid) {}

#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn on_process_restore_spawn(pid: Pid) {
    crate::security::security().init_process(pid);
    crate::capability::capability_manager().init_task(pid);
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn on_process_restore_spawn(_pid: Pid) {}

