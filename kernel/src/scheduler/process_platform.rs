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
    let _ = crate::execution::wasm::revoke_service_pointers_for_owner(pid);
    #[cfg(not(target_arch = "aarch64"))]
    let _ = crate::execution::wasm::unload_modules_for_owner(pid);
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
