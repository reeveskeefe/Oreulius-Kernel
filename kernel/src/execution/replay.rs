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

/*!
 * Oreulius Kernel Project
 *
 *License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 *
 * Deterministic replay support for WASM host calls.
 */

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::temporal::{TemporalDelta, TemporalFunctor, TemporalState};

/// Functorial State Replay Engine (Category Theory Section 4)
/// Maps historical states consistently ensuring no floating point or pointer drift.
pub struct AlgebraicReplayEngine<S: TemporalState, D: TemporalDelta, F: TemporalFunctor<S, D>> {
    pub initial_state: S,
    pub morphism_trace: alloc::vec::Vec<D>,
    _functor: core::marker::PhantomData<F>,
}

impl<S: TemporalState, D: TemporalDelta, F: TemporalFunctor<S, D>> AlgebraicReplayEngine<S, D, F> {
    pub fn new(state: S) -> Self {
        Self {
            initial_state: state,
            morphism_trace: alloc::vec::Vec::new(),
            _functor: core::marker::PhantomData,
        }
    }

    pub fn record_morphism(&mut self, delta: D) {
        self.morphism_trace.push(delta);
    }

    /// Prove total trace via structural category laws to ensure 0-drift equivalence
    pub fn replay_strict(&self) -> Result<S, &'static str> {
        let mut current = self.initial_state.clone();

        for i in 0..self.morphism_trace.len() {
            let next_delta = &self.morphism_trace[i];

            // Periodically verify functoral identity across adjacent pairs dynamically to prevent hardware bit-rot
            if i > 0 {
                let prev_delta = &self.morphism_trace[i - 1];
                F::verify_composition_law(&current, prev_delta, next_delta)?;
            }

            current = F::apply_morphism(&current, next_delta);
        }

        Ok(current)
    }
}

use spin::Mutex;

const MAGIC: [u8; 4] = *b"ORET";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 32;
const EVENT_KIND_HOST_CALL: u8 = 1;
const EVENT_HEADER_LEN: usize = 1 + 1 + 2 + 8 + 4 + 4;
const MAX_EVENTS: usize = 4096;
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    Off,
    Record,
    Replay,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReplayEventStatus {
    Ok = 0,
    Err = 1,
}

pub struct ReplayOutput {
    pub status: ReplayEventStatus,
    pub result: i32,
    pub data: Vec<u8>,
}

pub struct ReplayStatus {
    pub mode: ReplayMode,
    pub events: usize,
    pub cursor: usize,
    pub module_hash: u64,
    pub event_hash: u64,
}

struct HostCallEvent {
    func_idx: u16,
    args_hash: u64,
    status: ReplayEventStatus,
    result: i32,
    data: Vec<u8>,
}

struct ReplaySession {
    mode: ReplayMode,
    module_hash: u64,
    module_len: u32,
    events: Vec<HostCallEvent>,
    cursor: usize,
    event_hash: u64,
    total_bytes: usize,
}

struct ReplayManager {
    sessions: [Option<ReplaySession>; 8],
}

impl ReplayManager {
    const fn new() -> Self {
        ReplayManager {
            sessions: [None, None, None, None, None, None, None, None],
        }
    }
}

static REPLAY: Mutex<ReplayManager> = Mutex::new(ReplayManager::new());

const TEMPORAL_REPLAY_SCHEMA_V1: u8 = 1;
const TEMPORAL_REPLAY_CHUNK_BYTES: usize = 240 * 1024;

fn temporal_replay_mode_to_u8(mode: ReplayMode) -> u8 {
    match mode {
        ReplayMode::Off => 0,
        ReplayMode::Record => 1,
        ReplayMode::Replay => 2,
    }
}

fn temporal_replay_mode_from_u8(v: u8) -> Option<ReplayMode> {
    match v {
        0 => Some(ReplayMode::Off),
        1 => Some(ReplayMode::Record),
        2 => Some(ReplayMode::Replay),
        _ => None,
    }
}

fn temporal_append_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_append_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_append_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn temporal_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn temporal_read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset.saturating_add(4) > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn temporal_read_u64(data: &[u8], offset: usize) -> Option<u64> {
    if offset.saturating_add(8) > data.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

fn temporal_transcript_chunk_key(instance_id: usize, chunk_index: usize) -> String {
    alloc::format!("/replay/transcript/{}/{}", instance_id, chunk_index)
}

pub fn mode(instance_id: usize) -> ReplayMode {
    let mgr = REPLAY.lock();
    if instance_id >= mgr.sessions.len() {
        return ReplayMode::Off;
    }
    mgr.sessions[instance_id]
        .as_ref()
        .map(|s| s.mode)
        .unwrap_or(ReplayMode::Off)
}

pub fn start_record(
    instance_id: usize,
    module_hash: u64,
    module_len: usize,
) -> Result<(), &'static str> {
    if instance_id >= 8 {
        return Err("Invalid instance id");
    }
    let mut mgr = REPLAY.lock();
    let session = ReplaySession {
        mode: ReplayMode::Record,
        module_hash,
        module_len: module_len as u32,
        events: Vec::new(),
        cursor: 0,
        event_hash: fnv1a64_init(),
        total_bytes: 0,
    };
    mgr.sessions[instance_id] = Some(session);
    record_temporal_replay_manager_snapshot_locked(&mgr);
    Ok(())
}

pub fn stop(instance_id: usize) -> Result<(), &'static str> {
    let mut mgr = REPLAY.lock();
    let session = mgr
        .sessions
        .get_mut(instance_id)
        .ok_or("Invalid instance id")?
        .as_mut()
        .ok_or("No replay session")?;
    session.mode = ReplayMode::Off;
    session.cursor = 0;
    record_temporal_replay_manager_snapshot_locked(&mgr);
    Ok(())
}

pub fn clear(instance_id: usize) {
    let mut mgr = REPLAY.lock();
    if instance_id < mgr.sessions.len() {
        mgr.sessions[instance_id] = None;
    }
    record_temporal_replay_manager_snapshot_locked(&mgr);
}

pub fn status(instance_id: usize) -> Option<ReplayStatus> {
    let mgr = REPLAY.lock();
    let session = mgr.sessions.get(instance_id)?.as_ref()?;
    Some(ReplayStatus {
        mode: session.mode,
        events: session.events.len(),
        cursor: session.cursor,
        module_hash: session.module_hash,
        event_hash: session.event_hash,
    })
}

pub fn is_complete(instance_id: usize) -> Option<bool> {
    let mgr = REPLAY.lock();
    let session = mgr.sessions.get(instance_id)?.as_ref()?;
    Some(session.cursor >= session.events.len())
}

pub fn record_host_call(
    instance_id: usize,
    func_idx: u16,
    args_hash: u64,
    status: ReplayEventStatus,
    result: i32,
    data: &[u8],
) -> Result<(), &'static str> {
    let mut mgr = REPLAY.lock();
    let session = match mgr.sessions.get_mut(instance_id) {
        Some(Some(s)) => s,
        _ => return Ok(()),
    };
    if session.mode != ReplayMode::Record {
        return Ok(());
    }
    if session.events.len() >= MAX_EVENTS {
        return Err("Replay log full");
    }
    if data.len() > u32::MAX as usize {
        return Err("Replay data too large");
    }
    let event_bytes = EVENT_HEADER_LEN + data.len();
    if session.total_bytes.saturating_add(event_bytes) > MAX_BYTES {
        return Err("Replay buffer full");
    }
    session.total_bytes = session.total_bytes.saturating_add(event_bytes);
    session.event_hash = update_event_hash(
        session.event_hash,
        func_idx,
        args_hash,
        status,
        result,
        data,
    );
    session.events.push(HostCallEvent {
        func_idx,
        args_hash,
        status,
        result,
        data: data.to_vec(),
    });
    if session.events.len() % 32 == 0 {
        record_temporal_replay_manager_snapshot_locked(&mgr);
    }
    Ok(())
}

pub fn replay_host_call(
    instance_id: usize,
    func_idx: u16,
    args_hash: u64,
) -> Result<ReplayOutput, &'static str> {
    let mut mgr = REPLAY.lock();
    let (output, snapshot) = {
        let session = mgr
            .sessions
            .get_mut(instance_id)
            .ok_or("Invalid instance id")?
            .as_mut()
            .ok_or("No replay session")?;
        if session.mode != ReplayMode::Replay {
            return Err("Replay not active");
        }
        if session.cursor >= session.events.len() {
            return Err("Replay exhausted");
        }
        let (status, result, data) = {
            let event = &session.events[session.cursor];
            if event.func_idx != func_idx || event.args_hash != args_hash {
                return Err("Replay mismatch");
            }
            (event.status, event.result, event.data.clone())
        };
        session.cursor += 1;
        let snapshot = session.cursor == session.events.len() || session.cursor % 64 == 0;
        (
            ReplayOutput {
                status,
                result,
                data,
            },
            snapshot,
        )
    };
    if snapshot {
        record_temporal_replay_manager_snapshot_locked(&mgr);
    }
    Ok(output)
}

fn export_transcript_from_session(session: &ReplaySession) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(HEADER_LEN + session.total_bytes);

    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&session.module_hash.to_le_bytes());
    buf.extend_from_slice(&(session.module_len).to_le_bytes());
    buf.extend_from_slice(&(session.events.len() as u32).to_le_bytes());
    buf.extend_from_slice(&session.event_hash.to_le_bytes());

    for event in session.events.iter() {
        encode_event(&mut buf, event);
    }

    buf
}

pub fn export_transcript(instance_id: usize) -> Result<Vec<u8>, &'static str> {
    let mgr = REPLAY.lock();
    let session = mgr
        .sessions
        .get(instance_id)
        .ok_or("Invalid instance id")?
        .as_ref()
        .ok_or("No replay session")?;
    Ok(export_transcript_from_session(session))
}

fn decode_transcript_checked(
    module_hash: u64,
    module_len: usize,
    data: &[u8],
) -> Result<(Vec<HostCallEvent>, u64, usize), &'static str> {
    if data.len() < HEADER_LEN {
        return Err("Transcript too short");
    }
    if &data[0..4] != MAGIC {
        return Err("Invalid transcript header");
    }
    let version = data[4];
    if version != VERSION {
        return Err("Unsupported transcript version");
    }
    let header_module_hash = read_u64(data, 8)?;
    let header_module_len = read_u32(data, 16)? as usize;
    let header_event_count = read_u32(data, 20)? as usize;
    let header_event_hash = read_u64(data, 24)?;

    if header_event_count > MAX_EVENTS {
        return Err("Transcript too large");
    }

    if header_module_hash != module_hash || header_module_len != module_len {
        return Err("Transcript module mismatch");
    }

    let mut events = Vec::new();
    let mut cursor = HEADER_LEN;
    let mut computed_hash = fnv1a64_init();
    let mut total_bytes = 0usize;

    for _ in 0..header_event_count {
        let start = cursor;
        let (event, next) = decode_event(data, cursor)?;
        cursor = next;
        let end = cursor;
        computed_hash = fnv1a64_update(computed_hash, &data[start..end]);
        total_bytes = total_bytes.saturating_add(end - start);
        if total_bytes > MAX_BYTES {
            return Err("Transcript too large");
        }
        events.push(event);
    }

    if computed_hash != header_event_hash {
        return Err("Transcript hash mismatch");
    }
    if cursor != data.len() {
        return Err("Transcript has trailing data");
    }

    Ok((events, header_event_hash, total_bytes))
}

pub fn load_transcript(
    instance_id: usize,
    module_hash: u64,
    module_len: usize,
    data: &[u8],
) -> Result<(), &'static str> {
    if instance_id >= 8 {
        return Err("Invalid instance id");
    }
    let (events, event_hash, total_bytes) =
        decode_transcript_checked(module_hash, module_len, data)?;

    let session = ReplaySession {
        mode: ReplayMode::Replay,
        module_hash,
        module_len: module_len as u32,
        events,
        cursor: 0,
        event_hash,
        total_bytes,
    };
    let mut mgr = REPLAY.lock();
    mgr.sessions[instance_id] = Some(session);
    record_temporal_replay_manager_snapshot_locked(&mgr);
    Ok(())
}

fn record_temporal_replay_manager_snapshot_locked(mgr: &ReplayManager) {
    if crate::temporal::is_replay_active() {
        return;
    }

    #[derive(Clone, Copy)]
    struct ChunkDesc {
        idx: u16,
        len: u32,
        version_id: u64,
    }

    struct SessionDesc {
        present: bool,
        mode: ReplayMode,
        module_hash: u64,
        module_len: u32,
        cursor: u32,
        event_hash: u64,
        event_count: u32,
        transcript_len: u32,
        chunks: Vec<ChunkDesc>,
    }

    let slots = mgr.sessions.len();
    let mut descs: Vec<SessionDesc> = Vec::with_capacity(slots);

    for instance_id in 0..slots {
        let Some(session) = mgr.sessions[instance_id].as_ref() else {
            descs.push(SessionDesc {
                present: false,
                mode: ReplayMode::Off,
                module_hash: 0,
                module_len: 0,
                cursor: 0,
                event_hash: 0,
                event_count: 0,
                transcript_len: 0,
                chunks: Vec::new(),
            });
            continue;
        };

        let transcript = export_transcript_from_session(session);
        let mut chunks: Vec<ChunkDesc> = Vec::new();
        let mut chunk_index = 0usize;
        for chunk in transcript.chunks(TEMPORAL_REPLAY_CHUNK_BYTES) {
            let key = temporal_transcript_chunk_key(instance_id, chunk_index);
            let version_id = match crate::temporal::record_object_write(&key, chunk) {
                Ok(v) => v,
                Err(_) => return,
            };
            if chunk_index > u16::MAX as usize {
                return;
            }
            chunks.push(ChunkDesc {
                idx: chunk_index as u16,
                len: chunk.len() as u32,
                version_id,
            });
            chunk_index += 1;
        }

        descs.push(SessionDesc {
            present: true,
            mode: session.mode,
            module_hash: session.module_hash,
            module_len: session.module_len,
            cursor: session.cursor.min(u32::MAX as usize) as u32,
            event_hash: session.event_hash,
            event_count: session.events.len().min(u32::MAX as usize) as u32,
            transcript_len: transcript.len().min(u32::MAX as usize) as u32,
            chunks,
        });
    }

    let mut total_len = 8usize.saturating_add(slots.saturating_mul(40));
    for desc in descs.iter() {
        total_len = total_len.saturating_add(desc.chunks.len().saturating_mul(16));
    }
    if total_len > crate::temporal::MAX_TEMPORAL_VERSION_BYTES {
        return;
    }

    let mut payload = Vec::with_capacity(total_len);
    payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(crate::temporal::TEMPORAL_REPLAY_MANAGER_OBJECT);
    payload.push(crate::temporal::TEMPORAL_REPLAY_MANAGER_EVENT_STATE);
    payload.push(TEMPORAL_REPLAY_SCHEMA_V1);
    temporal_append_u16(&mut payload, slots as u16);
    temporal_append_u16(&mut payload, 0);

    for desc in descs.iter() {
        payload.push(if desc.present { 1 } else { 0 });
        payload.push(temporal_replay_mode_to_u8(desc.mode));
        temporal_append_u16(&mut payload, 0);
        temporal_append_u64(&mut payload, desc.module_hash);
        temporal_append_u32(&mut payload, desc.module_len);
        temporal_append_u32(&mut payload, desc.cursor);
        temporal_append_u64(&mut payload, desc.event_hash);
        temporal_append_u32(&mut payload, desc.event_count);
        temporal_append_u32(&mut payload, desc.transcript_len);
        temporal_append_u16(&mut payload, desc.chunks.len() as u16);
        temporal_append_u16(&mut payload, 0);

        for chunk in desc.chunks.iter() {
            temporal_append_u16(&mut payload, chunk.idx);
            temporal_append_u16(&mut payload, 0);
            temporal_append_u32(&mut payload, chunk.len);
            temporal_append_u64(&mut payload, chunk.version_id);
        }
    }

    let _ = crate::temporal::record_replay_state_event(&payload);
}

pub fn temporal_apply_replay_manager_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < 8 {
        return Err("temporal replay payload too short");
    }
    if payload[3] != TEMPORAL_REPLAY_SCHEMA_V1 {
        return Err("temporal replay schema unsupported");
    }
    let slots = temporal_read_u16(payload, 4).ok_or("temporal replay slots missing")? as usize;
    if slots != 8 {
        return Err("temporal replay slots mismatch");
    }

    let mut offset = 8usize;
    let mut restored: Vec<Option<ReplaySession>> = Vec::with_capacity(slots);
    for instance_id in 0..slots {
        if offset.saturating_add(40) > payload.len() {
            return Err("temporal replay entry truncated");
        }

        let present = payload[offset] != 0;
        let mode_raw = payload[offset + 1];
        let mode = temporal_replay_mode_from_u8(mode_raw).ok_or("temporal replay mode invalid")?;
        let module_hash =
            temporal_read_u64(payload, offset + 4).ok_or("temporal replay module hash missing")?;
        let module_len =
            temporal_read_u32(payload, offset + 12).ok_or("temporal replay module len missing")?;
        let cursor =
            temporal_read_u32(payload, offset + 16).ok_or("temporal replay cursor missing")?;
        let event_hash =
            temporal_read_u64(payload, offset + 20).ok_or("temporal replay event hash missing")?;
        let event_count =
            temporal_read_u32(payload, offset + 28).ok_or("temporal replay event count missing")?;
        let transcript_len = temporal_read_u32(payload, offset + 32)
            .ok_or("temporal replay transcript len missing")?;
        let chunk_count = temporal_read_u16(payload, offset + 36)
            .ok_or("temporal replay chunk count missing")? as usize;
        offset = offset.saturating_add(40);

        if chunk_count > 64 {
            return Err("temporal replay chunk count out of range");
        }

        let mut chunks: Vec<(u16, u32, u64)> = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            if offset.saturating_add(16) > payload.len() {
                return Err("temporal replay chunk truncated");
            }
            let chunk_idx =
                temporal_read_u16(payload, offset).ok_or("temporal replay chunk idx missing")?;
            let chunk_len = temporal_read_u32(payload, offset + 4)
                .ok_or("temporal replay chunk len missing")?;
            let version_id = temporal_read_u64(payload, offset + 8)
                .ok_or("temporal replay chunk version missing")?;
            chunks.push((chunk_idx, chunk_len, version_id));
            offset = offset.saturating_add(16);
        }

        if !present {
            restored.push(None);
            continue;
        }

        let mut transcript = Vec::new();
        transcript.reserve(transcript_len as usize);
        for (chunk_idx, chunk_len, version_id) in chunks.iter().copied() {
            let key = temporal_transcript_chunk_key(instance_id, chunk_idx as usize);
            let data = crate::temporal::read_version(&key, version_id)
                .map_err(|_| "temporal replay chunk read failed")?;
            if data.len() != chunk_len as usize {
                return Err("temporal replay chunk length mismatch");
            }
            transcript.extend_from_slice(&data);
        }
        if transcript.len() != transcript_len as usize {
            return Err("temporal replay transcript length mismatch");
        }

        let (events, decoded_hash, total_bytes) =
            decode_transcript_checked(module_hash, module_len as usize, &transcript)?;
        if decoded_hash != event_hash {
            return Err("temporal replay event hash mismatch");
        }
        if events.len() != event_count as usize {
            return Err("temporal replay event count mismatch");
        }
        if cursor as usize > events.len() {
            return Err("temporal replay cursor out of range");
        }

        restored.push(Some(ReplaySession {
            mode,
            module_hash,
            module_len,
            events,
            cursor: cursor as usize,
            event_hash: decoded_hash,
            total_bytes,
        }));
    }

    if offset != payload.len() {
        return Err("temporal replay payload trailing bytes");
    }

    let mut mgr = REPLAY.lock();
    for i in 0..slots {
        mgr.sessions[i] = restored[i].take();
    }
    Ok(())
}

pub fn fnv1a64_init() -> u64 {
    14695981039346656037
}

pub fn fnv1a64_update(mut hash: u64, data: &[u8]) -> u64 {
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

pub fn hash_u32(mut hash: u64, value: u32) -> u64 {
    hash = fnv1a64_update(hash, &value.to_le_bytes());
    hash
}

pub fn hash_u16(mut hash: u64, value: u16) -> u64 {
    hash = fnv1a64_update(hash, &value.to_le_bytes());
    hash
}

pub fn hash_u8(mut hash: u64, value: u8) -> u64 {
    hash = fnv1a64_update(hash, &[value]);
    hash
}

pub fn hash_i32(mut hash: u64, value: i32) -> u64 {
    hash = fnv1a64_update(hash, &value.to_le_bytes());
    hash
}

pub fn hash_bytes(hash: u64, data: &[u8]) -> u64 {
    fnv1a64_update(hash, data)
}

fn update_event_hash(
    hash: u64,
    func_idx: u16,
    args_hash: u64,
    status: ReplayEventStatus,
    result: i32,
    data: &[u8],
) -> u64 {
    let mut h = hash;
    h = hash_u8(h, EVENT_KIND_HOST_CALL);
    h = hash_u8(h, status as u8);
    h = hash_u16(h, func_idx);
    h = fnv1a64_update(h, &args_hash.to_le_bytes());
    h = hash_i32(h, result);
    h = hash_u32(h, data.len() as u32);
    h = hash_bytes(h, data);
    h
}

fn encode_event(buf: &mut Vec<u8>, event: &HostCallEvent) {
    buf.push(EVENT_KIND_HOST_CALL);
    buf.push(event.status as u8);
    buf.extend_from_slice(&event.func_idx.to_le_bytes());
    buf.extend_from_slice(&event.args_hash.to_le_bytes());
    buf.extend_from_slice(&event.result.to_le_bytes());
    buf.extend_from_slice(&(event.data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&event.data);
}

fn decode_event(data: &[u8], mut cursor: usize) -> Result<(HostCallEvent, usize), &'static str> {
    if cursor + EVENT_HEADER_LEN > data.len() {
        return Err("Transcript truncated");
    }
    let kind = data[cursor];
    cursor += 1;
    if kind != EVENT_KIND_HOST_CALL {
        return Err("Unknown event kind");
    }
    let status = data[cursor];
    cursor += 1;
    let func_idx = read_u16(data, cursor)?;
    cursor += 2;
    let args_hash = read_u64(data, cursor)?;
    cursor += 8;
    let result = read_i32(data, cursor)?;
    cursor += 4;
    let data_len = read_u32(data, cursor)? as usize;
    cursor += 4;
    if cursor + data_len > data.len() {
        return Err("Transcript truncated");
    }
    let payload = data[cursor..cursor + data_len].to_vec();
    cursor += data_len;

    let status = match status {
        0 => ReplayEventStatus::Ok,
        1 => ReplayEventStatus::Err,
        _ => return Err("Invalid event status"),
    };

    Ok((
        HostCallEvent {
            func_idx,
            args_hash,
            status,
            result,
            data: payload,
        },
        cursor,
    ))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, &'static str> {
    if offset + 2 > data.len() {
        return Err("Transcript truncated");
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, &'static str> {
    if offset + 4 > data.len() {
        return Err("Transcript truncated");
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32, &'static str> {
    if offset + 4 > data.len() {
        return Err("Transcript truncated");
    }
    Ok(i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, &'static str> {
    if offset + 8 > data.len() {
        return Err("Transcript truncated");
    }
    Ok(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}
