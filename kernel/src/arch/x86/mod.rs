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

//! x86 backend root for the arch subsystem.
//!
//! This module owns the x86-family boot/runtime entrypoints and keeps the
//! existing implementation files as thin `#[path]` shims during the transition.

pub(super) use super::{ArchPlatform, BootInfo, BootProtocol};

#[path = "../x86_legacy.rs"]
pub(crate) mod x86_legacy;

#[cfg(target_arch = "x86")]
#[path = "../x86_runtime.rs"]
pub(crate) mod x86_runtime;

#[cfg(target_arch = "x86_64")]
#[path = "../x86_64_runtime.rs"]
pub(crate) mod x86_64_runtime;

#[inline]
pub(crate) fn platform_name() -> &'static str {
    x86_legacy::PLATFORM.name()
}

#[inline]
pub(crate) fn boot_info() -> BootInfo {
    x86_legacy::PLATFORM.boot_info()
}

#[inline]
pub(crate) fn init_cpu_tables() {
    x86_legacy::PLATFORM.init_cpu_tables()
}

#[inline]
pub(crate) fn init_trap_table() {
    x86_legacy::PLATFORM.init_trap_table()
}

#[inline]
pub(crate) fn init_interrupt_controller() {
    x86_legacy::PLATFORM.init_interrupt_controller()
}

#[inline]
pub(crate) fn init_timer() {
    x86_legacy::PLATFORM.init_timer()
}

#[inline]
pub(crate) fn enable_interrupts() {
    x86_legacy::PLATFORM.enable_interrupts()
}

#[inline]
pub(crate) fn halt_loop() -> ! {
    x86_legacy::PLATFORM.halt_loop()
}

#[cfg(target_arch = "x86")]
#[inline]
pub(crate) fn enter_runtime() -> ! {
    x86_runtime::enter_runtime()
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn enter_runtime() -> ! {
    x86_64_runtime::enter_runtime()
}

#[cfg(target_arch = "x86")]
#[inline]
pub(crate) fn shell_loop() -> ! {
    x86_runtime::shell_loop()
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn shell_loop() -> ! {
    x86_64_runtime::run_serial_shell()
}
