/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Intent-graph runtime and state machine.

use crate::capability::CapabilityType;
use crate::execution::intent_wasm::{self, INTENT_MODEL_FEATURES};
use crate::ipc::ProcessId;
use crate::memory::wait_free_ring;
use crate::scheduler::pit;
use crate::security::intent_graph_data::{CTMC_Q, CTMC_SCALE, INTENT_NODE_COUNT};

use super::model::{
    AdaptiveRestriction, IntentDecision, IntentGraphStats, IntentNode, IntentProcessSnapshot,
    IntentSignal,
};
use super::policy::{IntentPolicy, IntentPolicyError};

const MAX_INTENT_PROCESSES: usize = 64;
const INTENT_TRANSITION_COUNT: usize = INTENT_NODE_COUNT * INTENT_NODE_COUNT;
const INTENT_OBJECT_BLOOM_WORDS: usize = 4;
/// Initial state vector: P(Syscall) = 1.0 (×CTMC_SCALE), all others 0.
/// Syscall is the entry node for all processes.
const CTMC_INIT: [i32; INTENT_NODE_COUNT] = [0, 0, 0, 0, 0, 0, 0, 0, CTMC_SCALE];

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
        let hz = pit::get_frequency() as u64;
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

    fn ctmc_step(state_vec: &mut [i32; INTENT_NODE_COUNT]) {
        let mut delta = [0i32; INTENT_NODE_COUNT];
        for i in 0..INTENT_NODE_COUNT {
            for j in 0..INTENT_NODE_COUNT {
                delta[j] = delta[j]
                    .saturating_add((state_vec[i].saturating_mul(CTMC_Q[i][j])) / CTMC_SCALE);
            }
        }
        let mut total = 0i32;
        for j in 0..INTENT_NODE_COUNT {
            state_vec[j] = (state_vec[j].saturating_add(delta[j])).max(0);
            total = total.saturating_add(state_vec[j]);
        }
        if total > 0 && total != CTMC_SCALE {
            for j in 0..INTENT_NODE_COUNT {
                state_vec[j] = (state_vec[j] * CTMC_SCALE) / total;
            }
        }
    }

    #[inline]
    fn ctmc_anomaly_score(state_vec: &[i32; INTENT_NODE_COUNT]) -> u32 {
        let anomaly_mass = state_vec[1].saturating_add(state_vec[2]).max(0) as u32;
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

    pub fn init_process(&mut self, pid: ProcessId) {
        let _ = self.process_mut(pid, true);
    }

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
        score = score.saturating_add(ctmc_bonus);
        score = score.min(255);

        state.last_score = score;
        if score > state.max_score {
            state.max_score = score;
        }

        let event = wait_free_ring::TelemetryEvent::new(
            pid.0,
            signal.node as u8,
            signal.cap_type as u8,
            score as u8,
            now_ticks,
        );
        let _ = wait_free_ring::TELEMETRY_RING.push(event);

        let hz = (pit::get_frequency() as u64).max(1);
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
