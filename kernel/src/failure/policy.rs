/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

use crate::observability::{EventType, Subsystem};
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSubsystem {
    Scheduler,
    Mmu,
    Syscall,
    Trap,
    Dtb,
    Invariant,
    Capability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    InvalidState,
    MappingViolation,
    InvalidFrame,
    ParseError,
    EscalationAttempt,
    InternalFault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    FailStop,
    Degrade,
    Isolate,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailurePolicy {
    pub action: FailureAction,
    pub terminal_reason_code: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcome {
    pub policy: FailurePolicy,
    pub recursive_fallback: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcomeSnapshot {
    pub subsystem: FailureSubsystem,
    pub kind: FailureKind,
    pub action: FailureAction,
    pub terminal_reason_code: u16,
    pub recursive_fallback: bool,
}

static FAILURE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static LAST_SUBSYSTEM: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_KIND: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_ACTION: AtomicUsize = AtomicUsize::new(usize::MAX);
static LAST_REASON: AtomicUsize = AtomicUsize::new(0);
static LAST_RECURSIVE: AtomicUsize = AtomicUsize::new(0);

pub fn classify(subsystem: FailureSubsystem, kind: FailureKind) -> FailurePolicy {
    match (subsystem, kind) {
        (FailureSubsystem::Scheduler, FailureKind::InvalidState) => FailurePolicy {
            action: FailureAction::Isolate,
            terminal_reason_code: 0x1101,
        },
        (FailureSubsystem::Mmu, FailureKind::MappingViolation) => FailurePolicy {
            action: FailureAction::FailStop,
            terminal_reason_code: 0x2101,
        },
        (FailureSubsystem::Syscall, FailureKind::InvalidFrame) => FailurePolicy {
            action: FailureAction::Isolate,
            terminal_reason_code: 0x3101,
        },
        (FailureSubsystem::Dtb, FailureKind::ParseError) => FailurePolicy {
            action: FailureAction::Degrade,
            terminal_reason_code: 0x5101,
        },
        (FailureSubsystem::Capability, FailureKind::EscalationAttempt) => FailurePolicy {
            action: FailureAction::FailStop,
            terminal_reason_code: 0x6101,
        },
        _ => FailurePolicy {
            action: FailureAction::FailStop,
            terminal_reason_code: 0xFFFF,
        },
    }
}

pub fn handle_failure(subsystem: FailureSubsystem, kind: FailureKind, detail: &[u8]) -> FailureOutcome {
    let depth = FAILURE_DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    let recursive_fallback = depth > 1;
    let policy = if recursive_fallback {
        // Non-recursive failure-path rule: if policy or logging re-enters, force deterministic fail-stop.
        FailurePolicy {
            action: FailureAction::FailStop,
            terminal_reason_code: 0xDEAD,
        }
    } else {
        classify(subsystem, kind)
    };

    let obs_subsystem = match subsystem {
        FailureSubsystem::Scheduler => Subsystem::Scheduler,
        FailureSubsystem::Mmu => Subsystem::Mmu,
        FailureSubsystem::Syscall => Subsystem::Syscall,
        FailureSubsystem::Trap => Subsystem::TrapVector,
        FailureSubsystem::Dtb => Subsystem::Dtb,
        FailureSubsystem::Invariant => Subsystem::Invariant,
        FailureSubsystem::Capability => Subsystem::Capability,
    };

    crate::observability::logger::emit_structured(
        crate::observability::EventLevel::Error,
        obs_subsystem,
        EventType::FailurePolicyAction,
        policy.terminal_reason_code,
        detail,
    );

    if matches!(policy.action, FailureAction::FailStop) {
        crate::observability::logger::mark_terminal_failure(
            policy.terminal_reason_code,
            Subsystem::Failure,
            format_args!("terminal failure subsystem={:?} kind={:?}", subsystem, kind),
        );
    }

    LAST_SUBSYSTEM.store(subsystem as usize, Ordering::SeqCst);
    LAST_KIND.store(kind as usize, Ordering::SeqCst);
    LAST_ACTION.store(policy.action as usize, Ordering::SeqCst);
    LAST_REASON.store(policy.terminal_reason_code as usize, Ordering::SeqCst);
    LAST_RECURSIVE.store(recursive_fallback as usize, Ordering::SeqCst);

    FAILURE_DEPTH.fetch_sub(1, Ordering::SeqCst);

    FailureOutcome {
        policy,
        recursive_fallback,
    }
}

pub fn last_failure_outcome() -> Option<FailureOutcomeSnapshot> {
    let raw_subsystem = LAST_SUBSYSTEM.load(Ordering::SeqCst);
    let raw_kind = LAST_KIND.load(Ordering::SeqCst);
    let raw_action = LAST_ACTION.load(Ordering::SeqCst);
    if raw_subsystem == usize::MAX || raw_kind == usize::MAX || raw_action == usize::MAX {
        return None;
    }
    Some(FailureOutcomeSnapshot {
        subsystem: decode_subsystem(raw_subsystem),
        kind: decode_kind(raw_kind),
        action: decode_action(raw_action),
        terminal_reason_code: LAST_REASON.load(Ordering::SeqCst) as u16,
        recursive_fallback: LAST_RECURSIVE.load(Ordering::SeqCst) != 0,
    })
}

fn decode_subsystem(raw: usize) -> FailureSubsystem {
    match raw {
        x if x == FailureSubsystem::Scheduler as usize => FailureSubsystem::Scheduler,
        x if x == FailureSubsystem::Mmu as usize => FailureSubsystem::Mmu,
        x if x == FailureSubsystem::Syscall as usize => FailureSubsystem::Syscall,
        x if x == FailureSubsystem::Trap as usize => FailureSubsystem::Trap,
        x if x == FailureSubsystem::Dtb as usize => FailureSubsystem::Dtb,
        x if x == FailureSubsystem::Invariant as usize => FailureSubsystem::Invariant,
        x if x == FailureSubsystem::Capability as usize => FailureSubsystem::Capability,
        _ => FailureSubsystem::Invariant,
    }
}

fn decode_kind(raw: usize) -> FailureKind {
    match raw {
        x if x == FailureKind::InvalidState as usize => FailureKind::InvalidState,
        x if x == FailureKind::MappingViolation as usize => FailureKind::MappingViolation,
        x if x == FailureKind::InvalidFrame as usize => FailureKind::InvalidFrame,
        x if x == FailureKind::ParseError as usize => FailureKind::ParseError,
        x if x == FailureKind::EscalationAttempt as usize => FailureKind::EscalationAttempt,
        x if x == FailureKind::InternalFault as usize => FailureKind::InternalFault,
        _ => FailureKind::InternalFault,
    }
}

fn decode_action(raw: usize) -> FailureAction {
    match raw {
        x if x == FailureAction::FailStop as usize => FailureAction::FailStop,
        x if x == FailureAction::Degrade as usize => FailureAction::Degrade,
        x if x == FailureAction::Isolate as usize => FailureAction::Isolate,
        x if x == FailureAction::Retry as usize => FailureAction::Retry,
        _ => FailureAction::FailStop,
    }
}