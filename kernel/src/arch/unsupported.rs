/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

use super::{ArchPlatform, BootInfo};

pub(super) struct UnsupportedPlatform;

pub(super) static PLATFORM: UnsupportedPlatform = UnsupportedPlatform;

impl ArchPlatform for UnsupportedPlatform {
    fn name(&self) -> &'static str {
        "unsupported"
    }

    fn boot_info(&self) -> BootInfo {
        BootInfo::default()
    }

    fn init_cpu_tables(&self) {}

    fn init_trap_table(&self) {}

    fn init_interrupt_controller(&self) {}

    fn init_timer(&self) {}

    fn enable_interrupts(&self) {}

    fn halt_loop(&self) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }
}

#[inline]
pub(super) fn platform_name() -> &'static str {
    PLATFORM.name()
}

#[inline]
pub(super) fn boot_info() -> BootInfo {
    PLATFORM.boot_info()
}

#[inline]
pub(super) fn init_cpu_tables() {
    PLATFORM.init_cpu_tables()
}

#[inline]
pub(super) fn init_trap_table() {
    PLATFORM.init_trap_table()
}

#[inline]
pub(super) fn init_interrupt_controller() {
    PLATFORM.init_interrupt_controller()
}

#[inline]
pub(super) fn init_timer() {
    PLATFORM.init_timer()
}

#[inline]
pub(super) fn enable_interrupts() {
    PLATFORM.enable_interrupts()
}

#[inline]
pub(super) fn halt_loop() -> ! {
    PLATFORM.halt_loop()
}

#[inline]
pub(super) fn enter_runtime() -> ! {
    halt_loop()
}

#[inline]
pub(super) fn shell_loop() -> ! {
    halt_loop()
}
