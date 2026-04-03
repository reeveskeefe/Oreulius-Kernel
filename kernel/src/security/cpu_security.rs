/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! CPU hardening features: SMEP, SMAP, and KPTI coordination.
//!
//! This module enables CPU-enforced protections where supported and
//! provides guarded helpers for SMAP user-access toggling.

use crate::asm_bindings;
use core::sync::atomic::{AtomicBool, Ordering};

const CR4_SMEP: u32 = 1 << 20;
const CR4_SMAP: u32 = 1 << 21;

static SMEP_ENABLED: AtomicBool = AtomicBool::new(false);
static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init() {
    let smep = has_smep();
    let smap = has_smap();

    let mut cr4 = asm_bindings::read_cr4();
    if smep {
        cr4 |= CR4_SMEP;
    }
    if smap {
        cr4 |= CR4_SMAP;
    }
    asm_bindings::write_cr4(cr4);

    SMEP_ENABLED.store(smep, Ordering::SeqCst);
    SMAP_ENABLED.store(smap, Ordering::SeqCst);

    crate::vga::print_str("[CPU] SMEP: ");
    crate::vga::print_str(if smep { "enabled" } else { "unsupported" });
    crate::vga::print_str(", SMAP: ");
    crate::vga::print_str(if smap { "enabled" } else { "unsupported" });
    crate::vga::print_str("\n");
}

pub fn has_smep() -> bool {
    let max = asm_bindings::cpuid(0, 0).eax;
    if max < 7 {
        return false;
    }
    let res = asm_bindings::cpuid(7, 0);
    (res.ebx & (1 << 7)) != 0
}

pub fn has_smap() -> bool {
    let max = asm_bindings::cpuid(0, 0).eax;
    if max < 7 {
        return false;
    }
    let res = asm_bindings::cpuid(7, 0);
    (res.ebx & (1 << 20)) != 0
}

#[allow(dead_code)]
pub fn smep_enabled() -> bool {
    SMEP_ENABLED.load(Ordering::SeqCst)
}

#[allow(dead_code)]
pub fn smap_enabled() -> bool {
    SMAP_ENABLED.load(Ordering::SeqCst)
}

/// Run a closure with SMAP temporarily disabled for user-memory access.
#[allow(dead_code)]
pub fn with_user_access<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    if smap_enabled() {
        asm_bindings::stac();
        let out = f();
        asm_bindings::clac();
        out
    } else {
        f()
    }
}
