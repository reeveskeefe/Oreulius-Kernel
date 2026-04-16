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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(crate) const VECTOR_TABLE_BYTES: usize = 2048;
const VECTOR_SLOT_COUNT: usize = 16;

const ESR_EC_SHIFT: u64 = 26;
const ESR_EC_MASK: u64 = 0x3F;
const EC_SVC64: u8 = 0x15;
const EC_HVC64: u8 = 0x16;
const EC_SMC64: u8 = 0x17;
const EC_BRK64: u8 = 0x3C;
const EC_FP_ASIMD_TRAP: u8 = 0x07;

#[repr(u8)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum VectorSlot {
    CurrentElSp0Sync = 0,
    CurrentElSp0Irq = 1,
    CurrentElSp0Fiq = 2,
    CurrentElSp0Serror = 3,
    CurrentElSpxSync = 4,
    CurrentElSpxIrq = 5,
    CurrentElSpxFiq = 6,
    CurrentElSpxSerror = 7,
    LowerElA64Sync = 8,
    LowerElA64Irq = 9,
    LowerElA64Fiq = 10,
    LowerElA64Serror = 11,
    LowerElA32Sync = 12,
    LowerElA32Irq = 13,
    LowerElA32Fiq = 14,
    LowerElA32Serror = 15,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LastExceptionSnapshot {
    pub slot: u8,
    pub esr_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub far_el1: u64,
}

static VECTORS_INSTALLED: AtomicBool = AtomicBool::new(false);

static LAST_SLOT: AtomicU64 = AtomicU64::new(0);
static LAST_ESR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_ELR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_SPSR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_FAR_EL1: AtomicU64 = AtomicU64::new(0);
/// SP_EL0 (user stack pointer) captured on every lower-EL sync exception.
/// Used by `fork_current_cow` to inherit the parent's user stack in the child.
static LAST_SP_EL0: AtomicU64 = AtomicU64::new(0);
static LAST_EC: AtomicU64 = AtomicU64::new(0);
static SYNC_EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_SLOT: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_ESR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_ELR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_SPSR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_FAR_EL1: AtomicU64 = AtomicU64::new(0);
static LAST_BRK_IMM16: AtomicU64 = AtomicU64::new(0);
static BRK_EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
static VECTOR_COUNTS: [AtomicU64; VECTOR_SLOT_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

extern "C" {
    static __oreulius_aarch64_vectors_start: u8;
}

#[inline]
pub(crate) fn vector_base() -> usize {
    unsafe { (&__oreulius_aarch64_vectors_start as *const u8) as usize }
}

#[inline]
fn is_sync_slot(slot: u8) -> bool {
    (slot & 0b11) == 0
}

#[inline]
fn is_irq_slot(slot: u8) -> bool {
    (slot & 0b11) == 1
}

#[inline]
fn slot_name(slot: u8) -> &'static str {
    match slot {
        0 => "cur-el-sp0-sync",
        1 => "cur-el-sp0-irq",
        2 => "cur-el-sp0-fiq",
        3 => "cur-el-sp0-serror",
        4 => "cur-el-spx-sync",
        5 => "cur-el-spx-irq",
        6 => "cur-el-spx-fiq",
        7 => "cur-el-spx-serror",
        8 => "lower-el-a64-sync",
        9 => "lower-el-a64-irq",
        10 => "lower-el-a64-fiq",
        11 => "lower-el-a64-serror",
        12 => "lower-el-a32-sync",
        13 => "lower-el-a32-irq",
        14 => "lower-el-a32-fiq",
        15 => "lower-el-a32-serror",
        _ => "unknown",
    }
}

#[inline]
fn ec_name(ec: u8) -> &'static str {
    match ec {
        EC_SVC64 => "SVC64",
        EC_HVC64 => "HVC64",
        EC_SMC64 => "SMC64",
        EC_BRK64 => "BRK64",
        EC_FP_ASIMD_TRAP => "FP_ASIMD_TRAP",
        0b100100 => "DATA_ABORT_LOWER_EL",
        0b100101 => "DATA_ABORT_SAME_EL",
        0b100000 => "INST_ABORT_LOWER_EL",
        0b100001 => "INST_ABORT_SAME_EL",
        _ => "other",
    }
}

fn uart_write_hex_u64(mut value: u64) {
    let uart = super::aarch64_pl011::early_uart();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[2 + i] = HEX[((value >> shift) & 0xF) as usize];
    }
    for &b in &buf {
        uart.write_byte(b);
    }
    value = 0;
    let _ = value;
}

fn log_sync_exception(slot: u8, esr_el1: u64, elr_el1: u64, spsr_el1: u64, far_el1: u64) {
    let ec = ((esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK) as u8;
    let uart = super::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str("[A64-EXC] slot=");
    uart.write_str(slot_name(slot));
    uart.write_str(" ec=");
    uart.write_str(ec_name(ec));
    uart.write_str(" (");
    uart_write_hex_u64(ec as u64);
    uart.write_str(") esr=");
    uart_write_hex_u64(esr_el1);
    uart.write_str(" elr=");
    uart_write_hex_u64(elr_el1);
    uart.write_str(" spsr=");
    uart_write_hex_u64(spsr_el1);
    uart.write_str(" far=");
    uart_write_hex_u64(far_el1);
    uart.write_str("\n");
}

#[inline]
fn brk_imm16(esr_el1: u64) -> u16 {
    (esr_el1 & 0xFFFF) as u16
}

#[inline]
fn should_log_sync_exception(slot: u8, ec: u8) -> bool {
    if ec == EC_FP_ASIMD_TRAP {
        return false;
    }
    !(slot == VectorSlot::LowerElA64Sync as u8 && ec == EC_SVC64)
}

pub(crate) fn install_stub_vectors() {
    let base = vector_base();
    unsafe {
        core::arch::asm!(
            "msr VBAR_EL1, {base}",
            "isb",
            base = in(reg) base,
            options(nostack),
        );
    }
    VECTORS_INSTALLED.store(true, Ordering::Relaxed);
}

#[inline]
pub(crate) fn vectors_installed() -> bool {
    VECTORS_INSTALLED.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn oreulius_aarch64_vector_dispatch(
    slot: u64,
    esr_el1: u64,
    elr_el1: u64,
    spsr_el1: u64,
    far_el1: u64,
    frame_ptr: u64,
) -> u64 {
    let slot_u8 = slot as u8;
    crate::observability::emit_trap_boundary(
        crate::observability::EventType::TrapBoundary,
        0x4100,
        b"aarch64_vector_entry",
    );

    if let Some(counter) = VECTOR_COUNTS.get(slot as usize) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    LAST_SLOT.store(slot, Ordering::Relaxed);
    LAST_ESR_EL1.store(esr_el1, Ordering::Relaxed);
    LAST_ELR_EL1.store(elr_el1, Ordering::Relaxed);
    LAST_SPSR_EL1.store(spsr_el1, Ordering::Relaxed);
    LAST_FAR_EL1.store(far_el1, Ordering::Relaxed);

    // Capture user stack pointer for fork() child setup.
    // SAFETY: reading SP_EL0 here is always safe at EL1 regardless of slot.
    #[cfg(not(any(test, feature = "host-tests")))]
    {
        let sp_el0: u64;
        unsafe { core::arch::asm!("mrs {}, SP_EL0", out(reg) sp_el0, options(nomem, nostack, preserves_flags)) };
        LAST_SP_EL0.store(sp_el0, Ordering::Relaxed);
    }

    let ec = ((esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK) as u8;
    LAST_EC.store(ec as u64, Ordering::Relaxed);

    if is_sync_slot(slot_u8) {
        SYNC_EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
        if should_log_sync_exception(slot_u8, ec) {
            log_sync_exception(slot_u8, esr_el1, elr_el1, spsr_el1, far_el1);
        }

        if ec == EC_FP_ASIMD_TRAP {
            crate::scheduler::slice_scheduler::handle_fpu_trap();
            return 0;
        }

        if ec == EC_BRK64 {
            BRK_EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
            LAST_BRK_SLOT.store(slot, Ordering::Relaxed);
            LAST_BRK_ESR_EL1.store(esr_el1, Ordering::Relaxed);
            LAST_BRK_ELR_EL1.store(elr_el1, Ordering::Relaxed);
            LAST_BRK_SPSR_EL1.store(spsr_el1, Ordering::Relaxed);
            LAST_BRK_FAR_EL1.store(far_el1, Ordering::Relaxed);
            LAST_BRK_IMM16.store(brk_imm16(esr_el1) as u64, Ordering::Relaxed);
            return 4;
        }

        if slot_u8 == VectorSlot::LowerElA64Sync as u8 && ec == EC_SVC64 {
            let frame_check = crate::invariants::syscall::check_user_frame(
                frame_ptr as usize,
                core::mem::size_of::<crate::platform::syscall::SavedRegisters>(),
                usize::MAX,
            );
            if !frame_check.valid {
                crate::invariants::enforce(frame_check, b"aarch64 vector syscall frame invalid");
                let _ = crate::failure::handle_failure(
                    crate::failure::FailureSubsystem::Syscall,
                    crate::failure::FailureKind::InvalidFrame,
                    b"vector syscall frame invalid",
                );
                return 4;
            }

            crate::observability::emit_trap_boundary(
                crate::observability::EventType::TrapBoundary,
                0x4101,
                b"aarch64_vector_svc64",
            );
            crate::platform::syscall::aarch64_syscall_from_exception(
                frame_ptr as *mut crate::platform::syscall::SavedRegisters,
            );
            return 4;
        }

        if matches!(ec, EC_BRK64 | EC_SVC64 | EC_HVC64 | EC_SMC64) {
            return 4;
        }
    }

    if is_irq_slot(slot_u8) {
        super::aarch64_virt::handle_irq_exception(slot_u8);
    }

    0
}

#[inline]
pub(crate) fn trigger_breakpoint() {
    unsafe {
        core::arch::asm!("brk #0", options(nomem, nostack));
    }
}

#[inline]
pub(crate) fn sync_exception_count() -> u64 {
    SYNC_EXCEPTION_COUNT.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn brk_exception_count() -> u64 {
    BRK_EXCEPTION_COUNT.load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn vector_count(slot: u8) -> u64 {
    VECTOR_COUNTS
        .get(slot as usize)
        .map(|v| v.load(Ordering::Relaxed))
        .unwrap_or(0)
}

#[inline]
pub(crate) fn last_exception_snapshot() -> LastExceptionSnapshot {
    LastExceptionSnapshot {
        slot: LAST_SLOT.load(Ordering::Relaxed) as u8,
        esr_el1: LAST_ESR_EL1.load(Ordering::Relaxed),
        elr_el1: LAST_ELR_EL1.load(Ordering::Relaxed),
        spsr_el1: LAST_SPSR_EL1.load(Ordering::Relaxed),
        far_el1: LAST_FAR_EL1.load(Ordering::Relaxed),
    }
}

#[inline]
pub(crate) fn last_brk_snapshot() -> LastExceptionSnapshot {
    LastExceptionSnapshot {
        slot: LAST_BRK_SLOT.load(Ordering::Relaxed) as u8,
        esr_el1: LAST_BRK_ESR_EL1.load(Ordering::Relaxed),
        elr_el1: LAST_BRK_ELR_EL1.load(Ordering::Relaxed),
        spsr_el1: LAST_BRK_SPSR_EL1.load(Ordering::Relaxed),
        far_el1: LAST_BRK_FAR_EL1.load(Ordering::Relaxed),
    }
}

#[inline]
pub(crate) fn last_brk_imm16() -> u16 {
    LAST_BRK_IMM16.load(Ordering::Relaxed) as u16
}

#[inline]
pub(crate) fn last_exception_ec() -> u8 {
    LAST_EC.load(Ordering::Relaxed) as u8
}

/// Returns the ELR_EL1 (exception return address) captured on the most recent
/// lower-EL sync exception (e.g. SVC).  Used by `fork_current_cow` to set the
/// child's user-space return address.
#[inline]
pub(crate) fn last_elr_el1() -> u64 {
    LAST_ELR_EL1.load(Ordering::Relaxed)
}

/// Returns the SPSR_EL1 captured on the most recent lower-EL sync exception.
#[inline]
pub(crate) fn last_spsr_el1() -> u64 {
    LAST_SPSR_EL1.load(Ordering::Relaxed)
}

/// Returns the SP_EL0 (user stack pointer) captured on the most recent
/// lower-EL sync exception.
#[inline]
pub(crate) fn last_sp_el0() -> u64 {
    LAST_SP_EL0.load(Ordering::Relaxed)
}

pub(crate) fn dump_last_exception() {
    let snap = last_exception_snapshot();
    let ec = last_exception_ec();
    let uart = super::aarch64_pl011::early_uart();
    uart.init_early();
    uart.write_str("[A64-EXC] last slot=");
    uart.write_str(slot_name(snap.slot));
    uart.write_str(" ec=");
    uart.write_str(ec_name(ec));
    uart.write_str(" esr=");
    uart_write_hex_u64(snap.esr_el1);
    uart.write_str(" elr=");
    uart_write_hex_u64(snap.elr_el1);
    uart.write_str(" spsr=");
    uart_write_hex_u64(snap.spsr_el1);
    uart.write_str(" far=");
    uart_write_hex_u64(snap.far_el1);
    uart.write_str("\n");
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::{oreulius_aarch64_vector_dispatch, VectorSlot, EC_SVC64};
    use crate::failure::policy::{last_failure_outcome, FailureAction, FailureSubsystem};
    use crate::observability::{ring_buffer, EventType};

    #[test]
    fn trap_negative_trace_closure_chain() {
        let expected = crate::invariants::syscall::check_user_frame(
            0,
            core::mem::size_of::<crate::platform::syscall::SavedRegisters>(),
            usize::MAX,
        );
        assert!(!expected.valid);
        assert_eq!(expected.id, "INV-SYSCALL-FRAME-001");
        assert_eq!(expected.severity, crate::invariants::InvariantSeverity::Safety);

        let esr_svc = (EC_SVC64 as u64) << 26;
        let before = ring_buffer::write_count();
        let ret = oreulius_aarch64_vector_dispatch(
            VectorSlot::LowerElA64Sync as u64,
            esr_svc,
            0,
            0,
            0,
            0,
        );
        assert_eq!(ret, 4);
        let after = ring_buffer::write_count();

        crate::observability::assert_closure_chain_closure(
            before,
            after,
            &[EventType::InvariantViolation, EventType::FailurePolicyAction],
            FailureSubsystem::Syscall,
            FailureAction::Isolate,
        );
    }
}
