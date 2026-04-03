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

//! Capability intent graph with predictive revocation.
//!
//! Tracks per-process behavioral intent transitions and predicts abuse risk.
//! High scores trigger temporary capability restrictions before full escalation.

#![allow(dead_code)]

use crate::capability::{CapabilityType, Rights};
use crate::intent_wasm::{self, INTENT_MODEL_FEATURES};
use crate::ipc::ProcessId;
use crate::linear_capability::{ScalarTensor, SimdTensor};

const MAX_INTENT_PROCESSES: usize = 64;
const INTENT_NODE_COUNT: usize = 9;
const INTENT_TRANSITION_COUNT: usize = INTENT_NODE_COUNT * INTENT_NODE_COUNT;
const INTENT_OBJECT_BLOOM_WORDS: usize = 4;

/// Sliding window size used by intent scoring.
pub const INTENT_WINDOW_SECONDS: u64 = 8;
/// Score threshold where alerts are emitted.
pub const INTENT_ALERT_SCORE: u32 = 84;
/// Score threshold where predictive revocation starts.
pub const INTENT_RESTRICT_SCORE: u32 = 136;
/// Number of restriction decisions in window before full capability isolation.
pub const INTENT_ISOLATE_RESTRICTIONS: u16 = 3;
/// Number of restriction decisions in window before termination is recommended.
pub const INTENT_TERMINATE_RESTRICTIONS: u16 = 6;
/// Base restriction duration (seconds).
pub const INTENT_RESTRICT_BASE_SECONDS: u16 = 2;
/// Maximum restriction duration (seconds).
pub const INTENT_RESTRICT_MAX_SECONDS: u16 = 12;
/// Isolation extension duration (seconds).
pub const INTENT_ISOLATION_EXTENSION_SECONDS: u16 = 20;
/// Score delta per duration severity step.
pub const INTENT_SEVERITY_STEP_SCORE: u16 = 16;
/// Minimum alert emission gap (milliseconds).
pub const INTENT_ALERT_COOLDOWN_MS: u16 = 1000;
/// Minimum restrict emission gap (milliseconds).
pub const INTENT_RESTRICT_COOLDOWN_MS: u16 = 500;

/// CTMC integer-scaled (×1024) generator matrix Q for the 9 IntentNode states.
///
/// Rows represent "from" states (indexed by IntentNode discriminant).
/// Columns represent "to" states.
/// Row sums must equal zero (holding time on diagonal = -sum of off-diagonal row).
///
/// Rates are empirical starting points; calibrate from production telemetry.
/// Fixed-point ×1024 allows first-order Euler steps in pure integer arithmetic:
///   P(t+dt) ≈ P(t) + P(t)·Q·dt   where dt is expressed in 1/1024-tick units.
///
/// Node index mapping (IntentNode discriminant):
///   0=CapabilityProbe  1=CapabilityDenied  2=InvalidCapability
///   3=IpcSend          4=IpcRecv           5=WasmCall
///   6=FsRead           7=FsWrite           8=Syscall
#[rustfmt::skip]
const CTMC_Q: [[i32; INTENT_NODE_COUNT]; INTENT_NODE_COUNT] = [
    // From CapabilityProbe: likely to Syscall or Denied
    [ -3072,  1024,   512,   256,   256,   256,   256,   256,   256 ],
    // From CapabilityDenied: high rate to InvalidCapability or stays (self-loop absorbed)
    [  256, -3072,  1536,   256,   256,   256,   256,   256,   256 - 256 + 256 ],
    // From InvalidCapability: high risk — tends toward Syscall anomaly
    [  256,   512, -3072,   256,   256,   256,   256,   256,  1024 ],
    // From IpcSend: mostly paired with IpcRecv
    [  256,   256,   256, -3072,  1536,   256,   256,   256,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From IpcRecv
    [  256,   256,   256,  1536, -3072,   256,   256,   256,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From WasmCall: can probe capabilities or hit syscall
    [  512,   256,   256,   256,   256, -3072,   256,   256,  1024 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From FsRead
    [  256,   256,   256,   256,   256,   256, -3072,   512,  1024 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From FsWrite: high correlation with capability checks
    [  512,   512,   256,   256,   256,   256,   512, -3072,   256 - 256 + 256 - 256 + 256 - 256 + 256 ],
    // From Syscall: returns to various states
    [  512,   256,   256,   384,   384,   256,   384,   384, -3072 - 256 + 256 - 256 + 256 - 256 + 256 ],
];

/// CTMC fixed-point scale factor.
const CTMC_SCALE: i32 = 1024;
/// Initial state vector: P(Syscall) = 1.0 (×CTMC_SCALE), all others 0.
/// Syscall is the entry node for all processes.
const CTMC_INIT: [i32; INTENT_NODE_COUNT] = [0, 0, 0, 0, 0, 0, 0, 0, CTMC_SCALE];

/// A mathematically bounded strict representation of capability access thresholds.
/// Converts sequential discrete capability comparisons into constant SIMD vector dot products.
#[derive(Clone, Copy)]
pub struct PolicyTensor<const N: usize> {
    pub weights: ScalarTensor<i32, N>,
    pub threshold: i32,
}

impl<const N: usize> PolicyTensor<N> {
    pub const fn new(weights: [i32; N], threshold: i32) -> Self {
        Self {
            weights: ScalarTensor { data: weights },
            threshold,
        }
    }

    /// Authorizes capability access by projecting policy conditions over real-time environmental intent
    /// behavior bounds, validating the equation via a strict mathematical threshold.
    pub fn authorize_vectorized(&self, environment_state: &ScalarTensor<i32, N>) -> bool {
        let risk_score = self.weights.dot_product(environment_state);
        risk_score < self.threshold
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntentPolicy {
    pub window_seconds: u64,
    pub alert_score: u32,
    pub restrict_score: u32,
    pub isolate_restrictions: u16,
    pub terminate_restrictions: u16,
    pub restrict_base_seconds: u16,
    pub restrict_max_seconds: u16,
    pub isolate_extension_seconds: u16,
    pub severity_step_score: u16,
    pub alert_cooldown_ms: u16,
    pub restrict_cooldown_ms: u16,
}

impl IntentPolicy {
    pub const fn baseline() -> Self {
        Self {
            window_seconds: INTENT_WINDOW_SECONDS,
            alert_score: INTENT_ALERT_SCORE,
            restrict_score: INTENT_RESTRICT_SCORE,
            isolate_restrictions: INTENT_ISOLATE_RESTRICTIONS,
            terminate_restrictions: INTENT_TERMINATE_RESTRICTIONS,
            restrict_base_seconds: INTENT_RESTRICT_BASE_SECONDS,
            restrict_max_seconds: INTENT_RESTRICT_MAX_SECONDS,
            isolate_extension_seconds: INTENT_ISOLATION_EXTENSION_SECONDS,
            severity_step_score: INTENT_SEVERITY_STEP_SCORE,
            alert_cooldown_ms: INTENT_ALERT_COOLDOWN_MS,
            restrict_cooldown_ms: INTENT_RESTRICT_COOLDOWN_MS,
        }
    }

    pub fn validate(&self) -> Result<(), IntentPolicyError> {
        if self.window_seconds == 0 || self.window_seconds > 3600 {
            return Err(IntentPolicyError::WindowSecondsOutOfRange);
        }
        if self.alert_score > 255 {
            return Err(IntentPolicyError::AlertScoreOutOfRange);
        }
        if self.restrict_score > 255 {
            return Err(IntentPolicyError::RestrictScoreOutOfRange);
        }
        if self.restrict_score < self.alert_score {
            return Err(IntentPolicyError::RestrictScoreBelowAlert);
        }
        if self.isolate_restrictions == 0 {
            return Err(IntentPolicyError::IsolateRestrictionsZero);
        }
        if self.terminate_restrictions < self.isolate_restrictions {
            return Err(IntentPolicyError::TerminateRestrictionsBelowIsolate);
        }
        if self.restrict_base_seconds == 0 {
            return Err(IntentPolicyError::RestrictBaseSecondsZero);
        }
        if self.restrict_max_seconds < self.restrict_base_seconds {
            return Err(IntentPolicyError::RestrictMaxBelowBase);
        }
        if self.isolate_extension_seconds < self.restrict_base_seconds {
            return Err(IntentPolicyError::IsolateExtensionBelowBase);
        }
        if self.severity_step_score == 0 {
            return Err(IntentPolicyError::SeverityStepZero);
        }
        if self.alert_cooldown_ms == 0 {
            return Err(IntentPolicyError::AlertCooldownZero);
        }
        if self.restrict_cooldown_ms == 0 {
            return Err(IntentPolicyError::RestrictCooldownZero);
        }
        Ok(())
    }
}

impl Default for IntentPolicy {
    fn default() -> Self {
        Self::baseline()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentPolicyError {
    WindowSecondsOutOfRange,
    AlertScoreOutOfRange,
    RestrictScoreOutOfRange,
    RestrictScoreBelowAlert,
    IsolateRestrictionsZero,
    TerminateRestrictionsBelowIsolate,
    RestrictBaseSecondsZero,
    RestrictMaxBelowBase,
    IsolateExtensionBelowBase,
    SeverityStepZero,
    AlertCooldownZero,
    RestrictCooldownZero,
}

impl IntentPolicyError {
    pub const fn as_str(self) -> &'static str {
        match self {
            IntentPolicyError::WindowSecondsOutOfRange => "window_seconds must be in 1..=3600",
            IntentPolicyError::AlertScoreOutOfRange => "alert_score must be in 0..=255",
            IntentPolicyError::RestrictScoreOutOfRange => "restrict_score must be in 0..=255",
            IntentPolicyError::RestrictScoreBelowAlert => "restrict_score must be >= alert_score",
            IntentPolicyError::IsolateRestrictionsZero => "isolate_restrictions must be >= 1",
            IntentPolicyError::TerminateRestrictionsBelowIsolate => {
                "terminate_restrictions must be >= isolate_restrictions"
            }
            IntentPolicyError::RestrictBaseSecondsZero => "restrict_base_seconds must be >= 1",
            IntentPolicyError::RestrictMaxBelowBase => {
                "restrict_max_seconds must be >= restrict_base_seconds"
            }
            IntentPolicyError::IsolateExtensionBelowBase => {
                "isolate_extension_seconds must be >= restrict_base_seconds"
            }
            IntentPolicyError::SeverityStepZero => "severity_step_score must be >= 1",
            IntentPolicyError::AlertCooldownZero => "alert_cooldown_ms must be >= 1",
            IntentPolicyError::RestrictCooldownZero => "restrict_cooldown_ms must be >= 1",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentNode {
    CapabilityProbe = 0,
    CapabilityDenied = 1,
    InvalidCapability = 2,
    IpcSend = 3,
    IpcRecv = 4,
    WasmCall = 5,
    FsRead = 6,
    FsWrite = 7,
    Syscall = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntentSignal {
    pub node: IntentNode,
    pub cap_type: CapabilityType,
    pub rights_mask: u32,
    pub object_hint: u64,
}

impl IntentSignal {
    pub const fn capability_probe(
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) -> Self {
        Self {
            node: IntentNode::CapabilityProbe,
            cap_type,
            rights_mask,
            object_hint,
        }
    }

    pub const fn capability_denied(
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) -> Self {
        Self {
            node: IntentNode::CapabilityDenied,
            cap_type,
            rights_mask,
            object_hint,
        }
    }

    pub const fn invalid_capability(
        cap_type: CapabilityType,
        rights_mask: u32,
        object_hint: u64,
    ) -> Self {
        Self {
            node: IntentNode::InvalidCapability,
            cap_type,
            rights_mask,
            object_hint,
        }
    }

    pub const fn ipc_send(channel_id: u64) -> Self {
        Self {
            node: IntentNode::IpcSend,
            cap_type: CapabilityType::Channel,
            rights_mask: Rights::CHANNEL_SEND,
            object_hint: channel_id,
        }
    }

    pub const fn ipc_recv(channel_id: u64) -> Self {
        Self {
            node: IntentNode::IpcRecv,
            cap_type: CapabilityType::Channel,
            rights_mask: Rights::CHANNEL_RECEIVE,
            object_hint: channel_id,
        }
    }

    pub const fn wasm_call(host_fn: u64) -> Self {
        Self {
            node: IntentNode::WasmCall,
            cap_type: CapabilityType::Reserved,
            rights_mask: 0,
            object_hint: host_fn,
        }
    }

    pub const fn fs_read(object_hint: u64) -> Self {
        Self {
            node: IntentNode::FsRead,
            cap_type: CapabilityType::Filesystem,
            rights_mask: Rights::FS_READ,
            object_hint,
        }
    }

    pub const fn fs_write(object_hint: u64) -> Self {
        Self {
            node: IntentNode::FsWrite,
            cap_type: CapabilityType::Filesystem,
            rights_mask: Rights::FS_WRITE,
            object_hint,
        }
    }

    pub const fn syscall(syscall_no: u64, cap_type: CapabilityType, rights_mask: u32) -> Self {
        Self {
            node: IntentNode::Syscall,
            cap_type,
            rights_mask,
            object_hint: syscall_no,
        }
    }
}

pub enum IntentDecision {
    Allow,
    Alert(u32),
    Restrict(u32),
}

#[derive(Clone, Copy)]
struct IntentProcessState {
    active: bool,
    pid: ProcessId,
    window_epoch_sec: u64,
    window_events: u16,
    denied_events: u16,
    invalid_events: u16,
    ipc_events: u16,
    wasm_events: u16,
    syscall_events: u16,
    fs_read_events: u16,
    fs_write_events: u16,
    object_novel_events: u16,
    node_counts: [u16; INTENT_NODE_COUNT],
    transition_counts: [u16; INTENT_TRANSITION_COUNT],
    object_bloom: [u64; INTENT_OBJECT_BLOOM_WORDS],
    /// CTMC probability state vector, fixed-point ×CTMC_SCALE.
    /// `ctmc_state_vec[i]` ≈ P(process is in node i) × 1024.
    ctmc_state_vec: [i32; INTENT_NODE_COUNT],
    has_last_node: bool,
    last_node: u8,
    last_score: u32,
    max_score: u32,
    alerts_total: u32,
    restrictions_total: u32,
    isolations_total: u32,
    terminate_recommendations_total: u32,
    window_restrictions: u16,
    terminate_recommended: bool,
    last_alert_tick: u64,
    last_restrict_tick: u64,
    restriction_until_tick: u64,
    restricted_cap_types: u16,
    restricted_rights: u32,
}

impl IntentProcessState {
    const fn empty() -> Self {
        Self {
            active: false,
            pid: ProcessId(0),
            window_epoch_sec: 0,
            window_events: 0,
            denied_events: 0,
            invalid_events: 0,
            ipc_events: 0,
            wasm_events: 0,
            syscall_events: 0,
            fs_read_events: 0,
            fs_write_events: 0,
            object_novel_events: 0,
            node_counts: [0; INTENT_NODE_COUNT],
            transition_counts: [0; INTENT_TRANSITION_COUNT],
            object_bloom: [0; INTENT_OBJECT_BLOOM_WORDS],
            ctmc_state_vec: CTMC_INIT,
            has_last_node: false,
            last_node: 0,
            last_score: 0,
            max_score: 0,
            alerts_total: 0,
            restrictions_total: 0,
            isolations_total: 0,
            terminate_recommendations_total: 0,
            window_restrictions: 0,
            terminate_recommended: false,
            last_alert_tick: 0,
            last_restrict_tick: 0,
            restriction_until_tick: 0,
            restricted_cap_types: 0,
            restricted_rights: 0,
        }
    }

    fn clear_window(&mut self, epoch_sec: u64) {
        self.window_epoch_sec = epoch_sec;
        self.window_events = 0;
        self.denied_events = 0;
        self.invalid_events = 0;
        self.ipc_events = 0;
        self.wasm_events = 0;
        self.syscall_events = 0;
        self.fs_read_events = 0;
        self.fs_write_events = 0;
        self.object_novel_events = 0;
        self.node_counts = [0; INTENT_NODE_COUNT];
        self.transition_counts = [0; INTENT_TRANSITION_COUNT];
        self.object_bloom = [0; INTENT_OBJECT_BLOOM_WORDS];
        self.ctmc_state_vec = CTMC_INIT;
        self.window_restrictions = 0;
        self.has_last_node = false;
        self.last_node = 0;
    }

    fn clear_restriction_if_expired(&mut self, now_ticks: u64) {
        if self.restriction_until_tick != 0 && now_ticks >= self.restriction_until_tick {
            self.restriction_until_tick = 0;
            self.restricted_cap_types = 0;
            self.restricted_rights = 0;
        }
    }
}

#[derive(Clone, Copy)]
pub struct IntentGraphStats {
    pub tracked_processes: u32,
    pub restricted_processes: u32,
    pub alerts_total: u32,
    pub restrictions_total: u32,
    pub highest_score: u32,
    pub latest_score: u32,
}

#[derive(Clone, Copy)]
pub struct IntentProcessSnapshot {
    pub pid: ProcessId,
    pub last_score: u32,
    pub max_score: u32,
    pub alerts_total: u32,
    pub restrictions_total: u32,
    pub isolations_total: u32,
    pub terminate_recommendations_total: u32,
    pub window_restrictions: u16,
    pub terminate_recommended: bool,
    pub window_events: u16,
    pub denied_events: u16,
    pub invalid_events: u16,
    pub ipc_events: u16,
    pub wasm_events: u16,
    pub syscall_events: u16,
    pub fs_read_events: u16,
    pub fs_write_events: u16,
    pub novel_object_events: u16,
    pub restriction_until_tick: u64,
    pub restricted_cap_types: u16,
    pub restricted_rights: u32,
}

// ============================================================================
// AdaptiveRestriction — Def A.31 named restriction entity
// ============================================================================

/// Maximum number of capability IDs that can be quarantined in one
/// `AdaptiveRestriction`.  Mirrors the inline quarantine array capacity in
/// `capability::CapabilityManager::predictive_revoke_capabilities`.
pub const ADAPTIVE_RESTRICTION_MAX_QUARANTINE: usize = 32;

/// A first-class, auditable description of an active predictive restriction on
/// a process (implements the concept named `AdaptiveRestriction` in the
/// capability theory documents).
///
/// Previously this state was spread across several fields of
/// `IntentProcessState` with no single named type.  Bundling it here makes
/// restrictions serialisable, comparable, and easy to log as a single audit
/// event.
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveRestriction {
    /// The restricted process.
    pub process: ProcessId,
    /// Behavioural score that triggered this restriction.
    pub score_at_trigger: u32,
    /// Tick at which the restriction was applied.
    pub began_at_tick: u64,
    /// Tick at which the restriction expires (0 = already expired).
    pub expires_at_tick: u64,
    /// Capability-type bitmask of restricted types.
    pub restricted_cap_types: u16,
    /// Rights bitmask that is restricted.
    pub restricted_rights: u32,
    /// IDs of capabilities quarantined when the restriction was applied.
    pub quarantined_caps: [u32; ADAPTIVE_RESTRICTION_MAX_QUARANTINE],
    /// Number of valid entries in `quarantined_caps`.
    pub qcount: usize,
}

impl AdaptiveRestriction {
    /// Construct from the fields extracted from `IntentProcessState`.
    pub fn from_process_state(
        pid: ProcessId,
        score: u32,
        began_at: u64,
        expires_at: u64,
        cap_types: u16,
        rights: u32,
    ) -> Self {
        AdaptiveRestriction {
            process: pid,
            score_at_trigger: score,
            began_at_tick: began_at,
            expires_at_tick: expires_at,
            restricted_cap_types: cap_types,
            restricted_rights: rights,
            quarantined_caps: [0u32; ADAPTIVE_RESTRICTION_MAX_QUARANTINE],
            qcount: 0,
        }
    }

    /// Returns `true` if the restriction is still active at `now_ticks`.
    #[inline]
    pub fn is_active(&self, now_ticks: u64) -> bool {
        self.expires_at_tick != 0 && now_ticks < self.expires_at_tick
    }

    /// Serialize to a fixed-size byte array for inclusion in audit log or
    /// temporal persistence store.
    ///
    /// Layout (little-endian):
    /// ```text
    /// [0..4]   process.0 (u32)
    /// [4..8]   score_at_trigger (u32)
    /// [8..16]  began_at_tick (u64)
    /// [16..24] expires_at_tick (u64)
    /// [24..26] restricted_cap_types (u16)
    /// [26..30] restricted_rights (u32)
    /// [30]     qcount as u8
    /// [31..]   quarantined cap IDs (qcount × 4 bytes)
    /// ```
    /// Returns bytes written.
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        const HEADER: usize = 31;
        if out.len() < HEADER {
            return 0;
        }
        out[0..4].copy_from_slice(&self.process.0.to_le_bytes());
        out[4..8].copy_from_slice(&self.score_at_trigger.to_le_bytes());
        out[8..16].copy_from_slice(&self.began_at_tick.to_le_bytes());
        out[16..24].copy_from_slice(&self.expires_at_tick.to_le_bytes());
        out[24..26].copy_from_slice(&self.restricted_cap_types.to_le_bytes());
        out[26..30].copy_from_slice(&self.restricted_rights.to_le_bytes());
        out[30] = self.qcount.min(ADAPTIVE_RESTRICTION_MAX_QUARANTINE) as u8;
        let mut pos = HEADER;
        let mut i = 0usize;
        while i < self.qcount && i < ADAPTIVE_RESTRICTION_MAX_QUARANTINE {
            if pos + 4 > out.len() {
                break;
            }
            out[pos..pos + 4].copy_from_slice(&self.quarantined_caps[i].to_le_bytes());
            pos += 4;
            i += 1;
        }
        pos
    }

    /// Deserialize from a byte slice previously produced by [`serialize`].
    /// Returns `None` if the slice is too short.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        const HEADER: usize = 31;
        if data.len() < HEADER {
            return None;
        }
        let pid = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let score = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let began = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let expires = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let cap_types = u16::from_le_bytes(data[24..26].try_into().ok()?);
        let rights = u32::from_le_bytes(data[26..30].try_into().ok()?);
        let qcount = data[30] as usize;
        let mut quarantined_caps = [0u32; ADAPTIVE_RESTRICTION_MAX_QUARANTINE];
        let mut pos = HEADER;
        let mut i = 0usize;
        while i < qcount && i < ADAPTIVE_RESTRICTION_MAX_QUARANTINE && pos + 4 <= data.len() {
            quarantined_caps[i] = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
            pos += 4;
            i += 1;
        }
        Some(AdaptiveRestriction {
            process: ProcessId(pid),
            score_at_trigger: score,
            began_at_tick: began,
            expires_at_tick: expires,
            restricted_cap_types: cap_types,
            restricted_rights: rights,
            quarantined_caps,
            qcount: i,
        })
    }
}

pub struct IntentGraph {
    processes: [IntentProcessState; MAX_INTENT_PROCESSES],
    policy: IntentPolicy,
}

impl IntentGraph {
    pub const fn new() -> Self {
        Self {
            processes: [IntentProcessState::empty(); MAX_INTENT_PROCESSES],
            policy: IntentPolicy::baseline(),
        }
    }

    fn epoch_sec(now_ticks: u64) -> u64 {
        let hz = crate::pit::get_frequency() as u64;
        if hz == 0 {
            now_ticks
        } else {
            now_ticks / hz
        }
    }

    fn process_mut(&mut self, pid: ProcessId, allocate: bool) -> Option<&mut IntentProcessState> {
        let mut existing_idx = None;
        let mut free_idx = None;

        let mut i = 0usize;
        while i < self.processes.len() {
            let slot = &self.processes[i];
            if slot.active && slot.pid == pid {
                existing_idx = Some(i);
                break;
            }
            if !slot.active && free_idx.is_none() {
                free_idx = Some(i);
            }
            i += 1;
        }

        if let Some(idx) = existing_idx {
            return Some(&mut self.processes[idx]);
        }

        if !allocate {
            return None;
        }

        let idx = free_idx?;
        self.processes[idx] = IntentProcessState {
            active: true,
            pid,
            ..IntentProcessState::empty()
        };
        Some(&mut self.processes[idx])
    }

    fn process_ref(&self, pid: ProcessId) -> Option<&IntentProcessState> {
        let mut i = 0usize;
        while i < self.processes.len() {
            let slot = &self.processes[i];
            if slot.active && slot.pid == pid {
                return Some(slot);
            }
            i += 1;
        }
        None
    }

    fn cap_type_bit(cap_type: CapabilityType) -> u16 {
        match cap_type {
            CapabilityType::Channel => 1 << 0,
            CapabilityType::Task => 1 << 1,
            CapabilityType::Spawner => 1 << 2,
            CapabilityType::Console => 1 << 3,
            CapabilityType::Clock => 1 << 4,
            CapabilityType::Store => 1 << 5,
            CapabilityType::Filesystem => 1 << 6,
            CapabilityType::ServicePointer => 1 << 7,
            CapabilityType::CrossLanguage => 1 << 8,
            CapabilityType::Reserved => 0,
        }
    }

    fn all_restrictable_cap_bits() -> u16 {
        (1 << 0)
            | (1 << 1)
            | (1 << 2)
            | (1 << 3)
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
    }

    fn roll_window(state: &mut IntentProcessState, now_ticks: u64, window_seconds: u64) {
        let epoch = Self::epoch_sec(now_ticks);
        if state.window_epoch_sec == 0 {
            state.clear_window(epoch);
            return;
        }

        if epoch.saturating_sub(state.window_epoch_sec) >= window_seconds {
            state.clear_window(epoch);
        }
    }

    /// Advance the CTMC state vector by one event tick using first-order Euler integration.
    ///
    /// P(t + dt) ≈ P(t) + P(t)·Q·dt
    ///
    /// `dt` here is 1 (one event = one "tick" in the intent graph's discrete sense).
    /// All arithmetic is fixed-point ×CTMC_SCALE to stay integer-only.
    ///
    /// The state vector is renormalised after each step to prevent drift due to
    /// truncation.
    fn ctmc_step(state_vec: &mut [i32; INTENT_NODE_COUNT]) {
        let mut delta = [0i32; INTENT_NODE_COUNT];
        // delta[j] = sum_i( state_vec[i] * Q[i][j] ) / CTMC_SCALE
        for i in 0..INTENT_NODE_COUNT {
            for j in 0..INTENT_NODE_COUNT {
                // scale down: Q is already ×1024, state_vec is ×1024, product is ×(1024²)
                // divide by CTMC_SCALE once to keep result in ×1024 range.
                delta[j] = delta[j]
                    .saturating_add((state_vec[i].saturating_mul(CTMC_Q[i][j])) / CTMC_SCALE);
            }
        }
        // Apply delta, clamp to [0, CTMC_SCALE]
        let mut total = 0i32;
        for j in 0..INTENT_NODE_COUNT {
            state_vec[j] = (state_vec[j].saturating_add(delta[j])).max(0);
            total = total.saturating_add(state_vec[j]);
        }
        // Renormalise so the vector sums to CTMC_SCALE (avoid probability mass drift).
        if total > 0 && total != CTMC_SCALE {
            for j in 0..INTENT_NODE_COUNT {
                state_vec[j] = (state_vec[j] * CTMC_SCALE) / total;
            }
        }
    }

    /// Extract an anomaly proximity score from the CTMC state vector.
    ///
    /// Returns a value in [0, 64] that is added to the heuristic score.
    /// Weights CapabilityDenied (idx 1) and InvalidCapability (idx 2) most heavily
    /// because sustained probability mass in those states predicts abuse.
    #[inline]
    fn ctmc_anomaly_score(state_vec: &[i32; INTENT_NODE_COUNT]) -> u32 {
        // P(CapabilityDenied) + P(InvalidCapability) in [0, 2×CTMC_SCALE]
        let anomaly_mass = state_vec[1].saturating_add(state_vec[2]).max(0) as u32;
        // Map to [0, 64]: (anomaly_mass * 64) / (2 * CTMC_SCALE)
        (anomaly_mass.saturating_mul(64)) / (2 * CTMC_SCALE as u32)
    }

    fn millis_to_ticks(ms: u16, hz: u64) -> u64 {
        let ticks = (ms as u64).saturating_mul(hz).saturating_add(999) / 1000;
        ticks.max(1)
    }

    pub fn policy(&self) -> IntentPolicy {
        self.policy
    }

    pub fn set_policy(&mut self, policy: IntentPolicy) -> Result<(), IntentPolicyError> {
        policy.validate()?;
        self.policy = policy;
        Ok(())
    }

    pub fn reset_policy(&mut self) {
        self.policy = IntentPolicy::baseline();
    }

    fn record_object_novelty(state: &mut IntentProcessState, signal: IntentSignal) -> u32 {
        if signal.object_hint == 0 {
            return 0;
        }

        // Tiny bloom-based novelty estimate (deterministic, allocation-free).
        let mut h = signal.object_hint
            ^ ((signal.node as u64) << 56)
            ^ ((signal.cap_type as u64) << 48)
            ^ (signal.rights_mask as u64).rotate_left(13);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        let bit_idx = (h as usize) & ((INTENT_OBJECT_BLOOM_WORDS * 64) - 1);
        let word_idx = bit_idx / 64;
        let bit = 1u64 << (bit_idx % 64);

        if (state.object_bloom[word_idx] & bit) != 0 {
            return 0;
        }
        state.object_bloom[word_idx] |= bit;
        state.object_novel_events = state.object_novel_events.saturating_add(1);
        1
    }

    /// Ensure a process has a slot allocated in the graph.
    pub fn init_process(&mut self, pid: ProcessId) {
        let _ = self.process_mut(pid, true);
    }

    /// Record a behavioral signal and return a policy decision.
    pub fn record(
        &mut self,
        pid: ProcessId,
        signal: IntentSignal,
        now_ticks: u64,
    ) -> IntentDecision {
        if pid.0 == 0 {
            return IntentDecision::Allow;
        }

        let policy = self.policy;
        let state = match self.process_mut(pid, true) {
            Some(s) => s,
            None => return IntentDecision::Allow,
        };

        Self::roll_window(state, now_ticks, policy.window_seconds);
        state.clear_restriction_if_expired(now_ticks);

        let node_idx = signal.node as usize;
        state.window_events = state.window_events.saturating_add(1);
        state.node_counts[node_idx] = state.node_counts[node_idx].saturating_add(1);

        let mut transition_count = 0u16;
        let mut transition_novelty = 0u32;
        if state.has_last_node {
            let from = state.last_node as usize;
            let t_idx = from
                .saturating_mul(INTENT_NODE_COUNT)
                .saturating_add(node_idx);
            if t_idx < state.transition_counts.len() {
                let count = state.transition_counts[t_idx].saturating_add(1);
                state.transition_counts[t_idx] = count;
                transition_count = count;
                if count <= 1 {
                    transition_novelty = 24;
                }
            }
        }
        state.has_last_node = true;
        state.last_node = signal.node as u8;

        match signal.node {
            IntentNode::CapabilityDenied => {
                state.denied_events = state.denied_events.saturating_add(1)
            }
            IntentNode::InvalidCapability => {
                state.invalid_events = state.invalid_events.saturating_add(1)
            }
            IntentNode::IpcSend | IntentNode::IpcRecv => {
                state.ipc_events = state.ipc_events.saturating_add(1);
            }
            IntentNode::WasmCall => state.wasm_events = state.wasm_events.saturating_add(1),
            IntentNode::Syscall => state.syscall_events = state.syscall_events.saturating_add(1),
            IntentNode::FsRead => state.fs_read_events = state.fs_read_events.saturating_add(1),
            IntentNode::FsWrite => state.fs_write_events = state.fs_write_events.saturating_add(1),
            IntentNode::CapabilityProbe => {}
        }

        let object_novelty = Self::record_object_novelty(state, signal);

        // --- CTMC step: advance the Markov chain by one event and extract anomaly score ---
        Self::ctmc_step(&mut state.ctmc_state_vec);
        let ctmc_bonus = Self::ctmc_anomaly_score(&state.ctmc_state_vec);

        let mut features = [0u32; INTENT_MODEL_FEATURES];
        features[0] = state.window_events.min(255) as u32;
        features[1] = state.denied_events.min(255) as u32;
        features[2] = state.invalid_events.min(255) as u32;
        features[3] = state.ipc_events.min(255) as u32;
        features[4] = state.wasm_events.min(255) as u32;
        let write_pressure = state
            .fs_write_events
            .saturating_mul(2)
            .saturating_add(state.fs_read_events / 2);
        features[5] = write_pressure.min(255) as u32;
        features[6] = transition_novelty
            .saturating_add((transition_count as u32).min(16))
            .saturating_add(object_novelty.saturating_mul(8));
        features[7] = signal.rights_mask.count_ones().min(31);
        features[8] = state.syscall_events.min(255) as u32;
        features[9] = state.object_novel_events.min(255) as u32;

        let mut score = intent_wasm::infer_score(&features);
        if state.denied_events > 0 && state.invalid_events > 0 {
            score = score.saturating_add(24);
        }
        if state.window_events > 40 {
            score = score.saturating_add(10);
        }
        if state.fs_write_events > state.fs_read_events.saturating_mul(2)
            && state.fs_write_events > 3
        {
            score = score.saturating_add(12);
        }
        if state.object_novel_events > 24 {
            score = score.saturating_add(10);
        }
        if state.window_events > 16 && state.object_novel_events > (state.window_events / 2) {
            score = score.saturating_add(14);
        }
        // Inject CTMC anomaly proximity bonus (max +64).
        score = score.saturating_add(ctmc_bonus);
        score = score.min(255);

        state.last_score = score;
        if score > state.max_score {
            state.max_score = score;
        }

        // Push telemetry event to the lock-free ring (best-effort; dropped if full).
        let event = crate::wait_free_ring::TelemetryEvent::new(
            pid.0,
            signal.node as u8,
            signal.cap_type as u8,
            score as u8,
            now_ticks,
        );
        let _ = crate::wait_free_ring::TELEMETRY_RING.push(event);

        let hz = (crate::pit::get_frequency() as u64).max(1);
        let alert_gap = Self::millis_to_ticks(policy.alert_cooldown_ms, hz);
        let restrict_gap = Self::millis_to_ticks(policy.restrict_cooldown_ms, hz);

        if score >= policy.restrict_score {
            let cap_mask = Self::cap_type_bit(signal.cap_type);
            if cap_mask != 0 {
                state.restricted_cap_types |= cap_mask;
                state.restricted_rights |= if signal.rights_mask == 0 {
                    u32::MAX
                } else {
                    signal.rights_mask
                };

                // Policy is validated on updates, but keep this path panic-free even if
                // memory corruption or partial restores ever yield an invalid policy.
                let step = (policy.severity_step_score as u32).max(1);
                let severity = ((score - policy.restrict_score) / step) as u64;
                let duration_sec = (policy.restrict_base_seconds as u64)
                    .saturating_add(severity)
                    .min(policy.restrict_max_seconds as u64);
                let until = now_ticks.saturating_add(duration_sec.saturating_mul(hz));
                if until > state.restriction_until_tick {
                    state.restriction_until_tick = until;
                }
            }

            if state.last_restrict_tick == 0
                || now_ticks.saturating_sub(state.last_restrict_tick) >= restrict_gap
            {
                state.last_restrict_tick = now_ticks;
                state.restrictions_total = state.restrictions_total.saturating_add(1);
                state.alerts_total = state.alerts_total.saturating_add(1);

                state.window_restrictions = state.window_restrictions.saturating_add(1);

                if state.window_restrictions >= policy.isolate_restrictions {
                    if state.window_restrictions == policy.isolate_restrictions {
                        state.isolations_total = state.isolations_total.saturating_add(1);
                    }
                    state.restricted_cap_types = Self::all_restrictable_cap_bits();
                    state.restricted_rights = u32::MAX;
                    let isolate_until = now_ticks.saturating_add(
                        (policy.isolate_extension_seconds as u64).saturating_mul(hz),
                    );
                    if isolate_until > state.restriction_until_tick {
                        state.restriction_until_tick = isolate_until;
                    }
                }

                if state.window_restrictions >= policy.terminate_restrictions
                    && !state.terminate_recommended
                {
                    state.terminate_recommended = true;
                    state.terminate_recommendations_total =
                        state.terminate_recommendations_total.saturating_add(1);
                }

                return IntentDecision::Restrict(score);
            }
        } else if score >= policy.alert_score {
            if state.last_alert_tick == 0
                || now_ticks.saturating_sub(state.last_alert_tick) >= alert_gap
            {
                state.last_alert_tick = now_ticks;
                state.alerts_total = state.alerts_total.saturating_add(1);
                return IntentDecision::Alert(score);
            }
        }

        IntentDecision::Allow
    }

    /// Check whether a capability access should be predictively restricted.
    pub fn is_restricted(
        &mut self,
        pid: ProcessId,
        cap_type: CapabilityType,
        rights_mask: u32,
        now_ticks: u64,
    ) -> bool {
        if pid.0 == 0 {
            return false;
        }

        let state = match self.process_mut(pid, false) {
            Some(s) => s,
            None => return false,
        };

        state.clear_restriction_if_expired(now_ticks);
        if state.restriction_until_tick == 0 {
            return false;
        }

        let cap_mask = Self::cap_type_bit(cap_type);
        if cap_mask == 0 || (state.restricted_cap_types & cap_mask) == 0 {
            return false;
        }

        if state.restricted_rights == u32::MAX || rights_mask == 0 {
            return true;
        }

        (state.restricted_rights & rights_mask) != 0
    }

    pub fn stats(&mut self, now_ticks: u64) -> IntentGraphStats {
        let mut tracked = 0u32;
        let mut restricted = 0u32;
        let mut alerts = 0u32;
        let mut restrictions = 0u32;
        let mut highest = 0u32;
        let mut latest = 0u32;

        let mut i = 0usize;
        while i < self.processes.len() {
            let slot = &mut self.processes[i];
            if slot.active {
                tracked = tracked.saturating_add(1);
                slot.clear_restriction_if_expired(now_ticks);
                if slot.restriction_until_tick != 0 {
                    restricted = restricted.saturating_add(1);
                }
                alerts = alerts.saturating_add(slot.alerts_total);
                restrictions = restrictions.saturating_add(slot.restrictions_total);
                if slot.max_score > highest {
                    highest = slot.max_score;
                }
                if slot.last_score > latest {
                    latest = slot.last_score;
                }
            }
            i += 1;
        }

        IntentGraphStats {
            tracked_processes: tracked,
            restricted_processes: restricted,
            alerts_total: alerts,
            restrictions_total: restrictions,
            highest_score: highest,
            latest_score: latest,
        }
    }

    pub fn process_snapshot(
        &mut self,
        pid: ProcessId,
        now_ticks: u64,
    ) -> Option<IntentProcessSnapshot> {
        let state = self.process_mut(pid, false)?;
        state.clear_restriction_if_expired(now_ticks);
        Some(IntentProcessSnapshot {
            pid: state.pid,
            last_score: state.last_score,
            max_score: state.max_score,
            alerts_total: state.alerts_total,
            restrictions_total: state.restrictions_total,
            isolations_total: state.isolations_total,
            terminate_recommendations_total: state.terminate_recommendations_total,
            window_restrictions: state.window_restrictions,
            terminate_recommended: state.terminate_recommended,
            window_events: state.window_events,
            denied_events: state.denied_events,
            invalid_events: state.invalid_events,
            ipc_events: state.ipc_events,
            wasm_events: state.wasm_events,
            syscall_events: state.syscall_events,
            fs_read_events: state.fs_read_events,
            fs_write_events: state.fs_write_events,
            novel_object_events: state.object_novel_events,
            restriction_until_tick: state.restriction_until_tick,
            restricted_cap_types: state.restricted_cap_types,
            restricted_rights: state.restricted_rights,
        })
    }

    pub fn process_snapshot_readonly(&self, pid: ProcessId) -> Option<IntentProcessSnapshot> {
        let state = self.process_ref(pid)?;
        Some(IntentProcessSnapshot {
            pid: state.pid,
            last_score: state.last_score,
            max_score: state.max_score,
            alerts_total: state.alerts_total,
            restrictions_total: state.restrictions_total,
            isolations_total: state.isolations_total,
            terminate_recommendations_total: state.terminate_recommendations_total,
            window_restrictions: state.window_restrictions,
            terminate_recommended: state.terminate_recommended,
            window_events: state.window_events,
            denied_events: state.denied_events,
            invalid_events: state.invalid_events,
            ipc_events: state.ipc_events,
            wasm_events: state.wasm_events,
            syscall_events: state.syscall_events,
            fs_read_events: state.fs_read_events,
            fs_write_events: state.fs_write_events,
            novel_object_events: state.object_novel_events,
            restriction_until_tick: state.restriction_until_tick,
            restricted_cap_types: state.restricted_cap_types,
            restricted_rights: state.restricted_rights,
        })
    }

    pub fn deinit_process(&mut self, pid: ProcessId) -> bool {
        let mut i = 0usize;
        while i < self.processes.len() {
            if self.processes[i].active && self.processes[i].pid == pid {
                self.processes[i] = IntentProcessState::empty();
                return true;
            }
            i += 1;
        }
        false
    }

    /// Consume a pending termination recommendation for a process.
    pub fn take_termination_recommendation(&mut self, pid: ProcessId) -> bool {
        let state = match self.process_mut(pid, false) {
            Some(state) => state,
            None => return false,
        };
        if !state.terminate_recommended {
            return false;
        }
        state.terminate_recommended = false;
        true
    }

    pub fn clear_restriction(&mut self, pid: ProcessId, now_ticks: u64) -> bool {
        let state = match self.process_mut(pid, false) {
            Some(state) => state,
            None => return false,
        };

        state.clear_restriction_if_expired(now_ticks);
        if state.restriction_until_tick == 0 {
            return false;
        }

        state.restriction_until_tick = 0;
        state.restricted_cap_types = 0;
        state.restricted_rights = 0;
        state.window_restrictions = 0;
        state.terminate_recommended = false;
        true
    }

    // -------------------------------------------------------------------------
    // AdaptiveRestriction accessors (Def §1.3)
    // -------------------------------------------------------------------------

    /// Return an [`AdaptiveRestriction`] snapshot for `pid` if a restriction is
    /// currently active at `now_ticks`, or `None` otherwise.
    ///
    /// Internally this calls `clear_restriction_if_expired` so that callers
    /// always receive a live view — an expired restriction returns `None`.
    pub fn active_restriction(
        &mut self,
        pid: ProcessId,
        now_ticks: u64,
    ) -> Option<AdaptiveRestriction> {
        let state = self.process_mut(pid, false)?;
        state.clear_restriction_if_expired(now_ticks);
        if state.restriction_until_tick == 0 {
            return None;
        }
        Some(AdaptiveRestriction::from_process_state(
            pid,
            state.last_score,
            state.last_restrict_tick,
            state.restriction_until_tick,
            state.restricted_cap_types,
            state.restricted_rights,
        ))
    }

    /// Return `true` if `pid` has an active `AdaptiveRestriction` at `now_ticks`.
    ///
    /// This is a cheap read-path shortcut; for the full restriction record use
    /// [`active_restriction`].
    pub fn has_active_restriction(&mut self, pid: ProcessId, now_ticks: u64) -> bool {
        self.active_restriction(pid, now_ticks).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_graph_triggers_and_expires_restriction() {
        let pid = ProcessId(7);
        let mut graph = IntentGraph::new();
        graph.init_process(pid);

        let mut decision = IntentDecision::Allow;
        let mut now = 100u64;
        for i in 0..64u64 {
            now = now.saturating_add(1);
            let signal = if i % 2 == 0 {
                IntentSignal::capability_denied(
                    CapabilityType::Filesystem,
                    Rights::FS_WRITE,
                    0x1000 + i,
                )
            } else {
                IntentSignal::invalid_capability(
                    CapabilityType::Filesystem,
                    Rights::FS_WRITE,
                    0x1000 + i,
                )
            };
            decision = graph.record(pid, signal, now);
            if matches!(decision, IntentDecision::Restrict(_)) {
                break;
            }
        }

        assert!(matches!(decision, IntentDecision::Restrict(_)));
        assert!(graph.is_restricted(pid, CapabilityType::Filesystem, Rights::FS_WRITE, now));

        // Restriction should expire after enough ticks pass.
        let far_future = now.saturating_add(5_000);
        assert!(!graph.is_restricted(
            pid,
            CapabilityType::Filesystem,
            Rights::FS_WRITE,
            far_future
        ));
    }

    #[test]
    fn intent_graph_keeps_kernel_unrestricted() {
        let mut graph = IntentGraph::new();
        let decision = graph.record(
            ProcessId::KERNEL,
            IntentSignal::capability_denied(CapabilityType::Channel, Rights::CHANNEL_SEND, 1),
            10,
        );

        assert!(matches!(decision, IntentDecision::Allow));
        assert!(!graph.is_restricted(
            ProcessId::KERNEL,
            CapabilityType::Channel,
            Rights::CHANNEL_SEND,
            20
        ));
    }

    #[test]
    fn intent_policy_rejects_invalid_threshold_ordering() {
        let mut policy = IntentPolicy::baseline();
        policy.alert_score = 140;
        policy.restrict_score = 120;
        assert_eq!(
            policy.validate(),
            Err(IntentPolicyError::RestrictScoreBelowAlert)
        );
    }

    #[test]
    fn intent_policy_tuning_changes_restrict_trigger() {
        let pid = ProcessId(11);
        let mut graph = IntentGraph::new();
        graph.init_process(pid);

        let mut policy = graph.policy();
        policy.alert_score = 32;
        policy.restrict_score = 48;
        policy.severity_step_score = 8;
        policy.restrict_base_seconds = 1;
        policy.restrict_max_seconds = 4;
        assert!(graph.set_policy(policy).is_ok());

        let mut decision = IntentDecision::Allow;
        let mut now = 10u64;
        for i in 0..32u64 {
            now = now.saturating_add(1);
            decision = graph.record(
                pid,
                IntentSignal::invalid_capability(
                    CapabilityType::Filesystem,
                    Rights::FS_WRITE,
                    0x2000 + i,
                ),
                now,
            );
            if matches!(decision, IntentDecision::Restrict(_)) {
                break;
            }
        }

        assert!(matches!(decision, IntentDecision::Restrict(_)));
    }
}
