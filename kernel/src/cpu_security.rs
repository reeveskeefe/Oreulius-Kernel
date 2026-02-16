/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! CPU hardening features: SMEP, SMAP, and KPTI coordination.
//!
//! This module enables CPU-enforced protections where supported and
//! provides guarded helpers for SMAP user-access toggling.

use core::sync::atomic::{AtomicBool, Ordering};
use crate::asm_bindings;

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
