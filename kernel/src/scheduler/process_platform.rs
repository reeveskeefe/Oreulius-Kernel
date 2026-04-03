/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

pub use crate::ipc::{ChannelCapability, ProcessId as Pid};
pub const TEMPORAL_PROCESS_EVENT_SPAWN: u8 = crate::temporal::TEMPORAL_PROCESS_EVENT_SPAWN;
pub const TEMPORAL_PROCESS_EVENT_TERMINATE: u8 = crate::temporal::TEMPORAL_PROCESS_EVENT_TERMINATE;
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

#[inline]
pub fn on_process_terminate(pid: Pid) {
    let _ = crate::ipc::purge_channels_for_process(pid);
    // WASM cleanup: wasm module is only available on x86; AArch64 uses
    // interpreter-only path which is handled separately in arch runtime.
    #[cfg(not(target_arch = "aarch64"))]
    let _ = crate::wasm::revoke_service_pointers_for_owner(pid);
    #[cfg(not(target_arch = "aarch64"))]
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

#[inline]
pub fn on_process_restore_spawn(pid: Pid) {
    crate::security::security().init_process(pid);
    crate::capability::capability_manager().init_task(pid);
}
