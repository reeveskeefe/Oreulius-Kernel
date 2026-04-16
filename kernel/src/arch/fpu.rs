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

//! Architecture-specific FPU / SIMD context save and restore.
//!
//! Implements §5.1 of the PMA: **Lazy FPU/Vector Context Switch**.
//!
//! ## Design
//!
//! The buffer size is **2816 bytes** — the full XSAVE extended state area
//! needed to cover AVX-512 (ZMM0-ZMM31, k0-k7, OPMASK, etc.) on x86_64,
//! and 512 bytes suffices for the Q0-Q31 NEON/SVE registers on AArch64
//! (padded to 2816 for a uniform type).
//!
//! Both functions are `unsafe` because:
//! - The caller must guarantee the buffer is 64-byte aligned.
//! - The caller must guarantee the scheduler lock is held (state is consistent).
//! - XSAVE/XRSTOR read/write MXCSR and may fault if the buffer is too small.
//!
//! ## Alignment
//! `ExtFpuState` carries `#[repr(align(64))]` which satisfies the XSAVE
//! alignment requirement (64 bytes) without any manual alignment juggling.

const EXT_FPU_STATE_BYTES: usize = 2816;

#[cfg(target_arch = "aarch64")]
const AARCH64_Q_BYTES: usize = 32 * 16;
#[cfg(target_arch = "aarch64")]
const AARCH64_FPSR_OFFSET: usize = AARCH64_Q_BYTES;
#[cfg(target_arch = "aarch64")]
const AARCH64_FPCR_OFFSET: usize = AARCH64_FPSR_OFFSET + core::mem::size_of::<u64>();
#[cfg(target_arch = "aarch64")]
const AARCH64_META_MAGIC_OFFSET: usize = AARCH64_FPCR_OFFSET + core::mem::size_of::<u64>();
#[cfg(target_arch = "aarch64")]
const AARCH64_META_VERSION_OFFSET: usize = AARCH64_META_MAGIC_OFFSET + core::mem::size_of::<u32>();
#[cfg(target_arch = "aarch64")]
const AARCH64_RESERVED_OFFSET: usize = AARCH64_META_VERSION_OFFSET + core::mem::size_of::<u32>();
#[cfg(target_arch = "aarch64")]
const AARCH64_STATE_MAGIC: u32 = u32::from_le_bytes(*b"AFPU");
#[cfg(target_arch = "aarch64")]
const AARCH64_STATE_VERSION: u32 = 1;

/// Full XSAVE extended state buffer — 2816 bytes, 64-byte aligned.
///
/// 2816 bytes covers:
///   - x87 FPU  (512 bytes via FXSAVE legacy area)
///   - SSE/AVX  (256–832 bytes, XSAVE standard area)
///   - AVX-512  (2048-byte XSAVE extended area for ZMM_Hi256 + Hi16_ZMM)
///
/// On AArch64 Q0-Q31 (512 bytes) + FPSR/FPCR (16 bytes) are stored directly.
/// The remaining bytes hold versioned metadata and reserved extension space so
/// save images stay deterministic and forward-compatible.
#[repr(C, align(64))]
pub struct ExtFpuState(pub [u8; EXT_FPU_STATE_BYTES]);

impl ExtFpuState {
    /// All-zero initialiser, usable in `const` context.
    pub const fn new() -> Self {
        ExtFpuState([0u8; EXT_FPU_STATE_BYTES])
    }
}

// ---------------------------------------------------------------------------
// x86_64 implementation
// ---------------------------------------------------------------------------

/// Save the full FPU/SIMD state to `buf` (must be 64-byte aligned, ≥ 2816 B).
///
/// Uses `XSAVE` with `edx:eax = 0xFFFF_FFFF:0xFFFF_FFFF` to save all
/// processor state components that are present on this CPU.
///
/// # Safety
/// - `buf` must point to a valid, 64-byte-aligned, ≥2816-byte writable buffer.
/// - Must be called with preemption disabled (kernel context).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn save_fpu_state_ext(buf: *mut u8) {
    core::arch::asm!(
        "xsave [{ptr}]",
        ptr = in(reg) buf,
        in("eax") 0xFFFF_FFFFu32,
        in("edx") 0xFFFF_FFFFu32,
        options(nostack, preserves_flags),
    );
}

/// Restore the full FPU/SIMD state from `buf` (must be 64-byte aligned, ≥ 2816 B).
///
/// Uses `XRSTOR` with the same component mask as `save_fpu_state_ext`.
///
/// # Safety
/// - `buf` must point to a valid, 64-byte-aligned, ≥2816-byte readable buffer
///   previously written by [`save_fpu_state_ext`].
/// - Must be called with preemption disabled (kernel context).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn restore_fpu_state_ext(buf: *const u8) {
    core::arch::asm!(
        "xrstor [{ptr}]",
        ptr = in(reg) buf,
        in("eax") 0xFFFF_FFFFu32,
        in("edx") 0xFFFF_FFFFu32,
        options(nostack, preserves_flags),
    );
}

/// Initialise the x87 FPU to a clean state (called for a brand-new process
/// that has never touched FP registers before).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn init_fpu_state() {
    // FNINIT: initialise x87 FPU without checking for pending exceptions.
    core::arch::asm!("fninit", options(nostack, preserves_flags));
    // LDMXCSR with the default MXCSR value (0x1F80) clears SSE exception flags
    // and sets the round-to-nearest / flush-to-zero defaults.
    let mxcsr: u32 = 0x1F80u32;
    core::arch::asm!(
        "ldmxcsr [{ptr}]",
        ptr = in(reg) &mxcsr as *const u32,
        options(nostack, preserves_flags),
    );
}

// ---------------------------------------------------------------------------
// AArch64 implementation
// ---------------------------------------------------------------------------

/// Save NEON/SIMD registers Q0-Q31 plus FPSR/FPCR into `buf`.
///
/// Buffer layout (all offsets from `buf`):
///   [   0 ..  512): Q0-Q31 (128-bit registers, 32 × 16 bytes)
///   [ 512 ..  520): FPSR (u64)
///   [ 520 ..  528): FPCR (u64)
///   [ 528 ..  532): state magic (`AFPU`)
///   [ 532 ..  536): layout version (u32)
///   [ 536 .. 2816): reserved / future architectural extension area
///
/// # Safety
/// See [`save_fpu_state_ext`].
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn save_fpu_state_ext(buf: *mut u8) {
    // Save Q registers in pairs (128-bit STP) — 16 pairs × 2 = 32 registers.
    core::arch::asm!(
        "stp  q0,  q1,  [{b}, #0]",
        "stp  q2,  q3,  [{b}, #32]",
        "stp  q4,  q5,  [{b}, #64]",
        "stp  q6,  q7,  [{b}, #96]",
        "stp  q8,  q9,  [{b}, #128]",
        "stp  q10, q11, [{b}, #160]",
        "stp  q12, q13, [{b}, #192]",
        "stp  q14, q15, [{b}, #224]",
        "stp  q16, q17, [{b}, #256]",
        "stp  q18, q19, [{b}, #288]",
        "stp  q20, q21, [{b}, #320]",
        "stp  q22, q23, [{b}, #352]",
        "stp  q24, q25, [{b}, #384]",
        "stp  q26, q27, [{b}, #416]",
        "stp  q28, q29, [{b}, #448]",
        "stp  q30, q31, [{b}, #480]",
        b = in(reg) buf,
        options(nostack),
    );
    // Save FPSR and FPCR
    let fpsr: u64;
    let fpcr: u64;
    core::arch::asm!("mrs {r}, fpsr", r = out(reg) fpsr, options(nostack));
    core::arch::asm!("mrs {r}, fpcr", r = out(reg) fpcr, options(nostack));
    core::ptr::write_unaligned(buf.add(AARCH64_FPSR_OFFSET) as *mut u64, fpsr);
    core::ptr::write_unaligned(buf.add(AARCH64_FPCR_OFFSET) as *mut u64, fpcr);
    core::ptr::write_unaligned(buf.add(AARCH64_META_MAGIC_OFFSET) as *mut u32, AARCH64_STATE_MAGIC);
    core::ptr::write_unaligned(
        buf.add(AARCH64_META_VERSION_OFFSET) as *mut u32,
        AARCH64_STATE_VERSION,
    );
    core::ptr::write_bytes(
        buf.add(AARCH64_RESERVED_OFFSET),
        0,
        EXT_FPU_STATE_BYTES - AARCH64_RESERVED_OFFSET,
    );
}

/// Restore NEON/SIMD registers Q0-Q31 plus FPSR/FPCR from `buf`.
///
/// # Safety
/// See [`restore_fpu_state_ext`].
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn restore_fpu_state_ext(buf: *const u8) {
    let magic = core::ptr::read_unaligned(buf.add(AARCH64_META_MAGIC_OFFSET) as *const u32);
    let version = core::ptr::read_unaligned(buf.add(AARCH64_META_VERSION_OFFSET) as *const u32);
    if magic != AARCH64_STATE_MAGIC || version != AARCH64_STATE_VERSION {
        init_fpu_state();
        return;
    }
    let fpsr = core::ptr::read_unaligned(buf.add(AARCH64_FPSR_OFFSET) as *const u64);
    let fpcr = core::ptr::read_unaligned(buf.add(AARCH64_FPCR_OFFSET) as *const u64);
    core::arch::asm!("msr fpsr, {r}", r = in(reg) fpsr, options(nostack));
    core::arch::asm!("msr fpcr, {r}", r = in(reg) fpcr, options(nostack));
    core::arch::asm!(
        "ldp  q0,  q1,  [{b}, #0]",
        "ldp  q2,  q3,  [{b}, #32]",
        "ldp  q4,  q5,  [{b}, #64]",
        "ldp  q6,  q7,  [{b}, #96]",
        "ldp  q8,  q9,  [{b}, #128]",
        "ldp  q10, q11, [{b}, #160]",
        "ldp  q12, q13, [{b}, #192]",
        "ldp  q14, q15, [{b}, #224]",
        "ldp  q16, q17, [{b}, #256]",
        "ldp  q18, q19, [{b}, #288]",
        "ldp  q20, q21, [{b}, #320]",
        "ldp  q22, q23, [{b}, #352]",
        "ldp  q24, q25, [{b}, #384]",
        "ldp  q26, q27, [{b}, #416]",
        "ldp  q28, q29, [{b}, #448]",
        "ldp  q30, q31, [{b}, #480]",
        b = in(reg) buf,
        options(nostack),
    );
}

/// Initialise FPU to a clean NEON default state on AArch64.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub unsafe fn init_fpu_state() {
    // Clear FPSR/FPCR to defaults (no exception flags, round-to-nearest).
    core::arch::asm!("msr fpsr, xzr", options(nostack));
    core::arch::asm!("msr fpcr, xzr", options(nostack));
}

// ---------------------------------------------------------------------------
// Unsupported architecture stubs
// ---------------------------------------------------------------------------

/// No-op save for unsupported architectures (I686, RISCV, etc.).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub unsafe fn save_fpu_state_ext(_buf: *mut u8) {}

/// No-op restore for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub unsafe fn restore_fpu_state_ext(_buf: *const u8) {}

/// No-op init for unsupported architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub unsafe fn init_fpu_state() {}
