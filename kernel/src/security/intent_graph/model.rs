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

//! Intent-graph data model.
//!
//! This module owns the public node/state types, decisions, snapshots, and
//! adaptive restriction record used by the runtime graph.

use crate::capability::{CapabilityType, Rights};
use crate::ipc::ProcessId;

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

/// Maximum number of capability IDs that can be quarantined in one
/// `AdaptiveRestriction`.
pub const ADAPTIVE_RESTRICTION_MAX_QUARANTINE: usize = 32;

/// A first-class, auditable description of an active predictive restriction on
/// a process.
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveRestriction {
    pub process: ProcessId,
    pub score_at_trigger: u32,
    pub began_at_tick: u64,
    pub expires_at_tick: u64,
    pub restricted_cap_types: u16,
    pub restricted_rights: u32,
    pub quarantined_caps: [u32; ADAPTIVE_RESTRICTION_MAX_QUARANTINE],
    pub qcount: usize,
}

impl AdaptiveRestriction {
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

    #[inline]
    pub fn is_active(&self, now_ticks: u64) -> bool {
        self.expires_at_tick != 0 && now_ticks < self.expires_at_tick
    }

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
