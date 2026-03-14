/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
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
