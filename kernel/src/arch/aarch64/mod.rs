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

//! AArch64 backend root for the arch subsystem.
//!
//! This module owns the AArch64 boot/runtime entrypoints and keeps the current
//! implementation files in place as path-based shims while the facade settles.

pub(super) use super::{ArchPlatform, BootInfo};

#[path = "../aarch64_dtb.rs"]
pub(crate) mod aarch64_dtb;
#[path = "../aarch64_pl011.rs"]
pub(crate) mod aarch64_pl011;
#[path = "../aarch64_runtime.rs"]
pub(crate) mod aarch64_runtime;
#[path = "../aarch64_vectors.rs"]
pub(crate) mod aarch64_vectors;
#[path = "../aarch64_virt.rs"]
pub(crate) mod aarch64_virt;

#[inline]
pub(crate) fn platform_name() -> &'static str {
    aarch64_virt::PLATFORM.name()
}

#[inline]
pub(crate) fn boot_info() -> BootInfo {
    aarch64_virt::PLATFORM.boot_info()
}

#[inline]
pub(crate) fn init_cpu_tables() {
    aarch64_virt::PLATFORM.init_cpu_tables()
}

#[inline]
pub(crate) fn init_trap_table() {
    aarch64_virt::PLATFORM.init_trap_table()
}

#[inline]
pub(crate) fn init_interrupt_controller() {
    aarch64_virt::PLATFORM.init_interrupt_controller()
}

#[inline]
pub(crate) fn init_timer() {
    aarch64_virt::PLATFORM.init_timer()
}

#[inline]
pub(crate) fn enable_interrupts() {
    aarch64_virt::PLATFORM.enable_interrupts()
}

#[inline]
pub(crate) fn halt_loop() -> ! {
    aarch64_virt::PLATFORM.halt_loop()
}

#[inline]
pub(crate) fn enter_runtime() -> ! {
    aarch64_runtime::enter_runtime()
}

#[inline]
pub(crate) fn shell_loop() -> ! {
    aarch64_virt::run_serial_shell()
}
