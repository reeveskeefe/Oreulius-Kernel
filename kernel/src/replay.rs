/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 *
 * Deterministic replay support for WASM host calls.
 */

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
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

pub fn start_record(instance_id: usize, module_hash: u64, module_len: usize) -> Result<(), &'static str> {
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
    Ok(())
}

pub fn clear(instance_id: usize) {
    let mut mgr = REPLAY.lock();
    if instance_id < mgr.sessions.len() {
        mgr.sessions[instance_id] = None;
    }
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
    Ok(())
}

pub fn replay_host_call(
    instance_id: usize,
    func_idx: u16,
    args_hash: u64,
) -> Result<ReplayOutput, &'static str> {
    let mut mgr = REPLAY.lock();
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
    let event = &session.events[session.cursor];
    if event.func_idx != func_idx || event.args_hash != args_hash {
        return Err("Replay mismatch");
    }
    session.cursor += 1;
    Ok(ReplayOutput {
        status: event.status,
        result: event.result,
        data: event.data.clone(),
    })
}

pub fn export_transcript(instance_id: usize) -> Result<Vec<u8>, &'static str> {
    let mgr = REPLAY.lock();
    let session = mgr
        .sessions
        .get(instance_id)
        .ok_or("Invalid instance id")?
        .as_ref()
        .ok_or("No replay session")?;
    let mut buf = Vec::new();
    buf.reserve(HEADER_LEN + session.total_bytes);

    // Header
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&session.module_hash.to_le_bytes());
    buf.extend_from_slice(&(session.module_len).to_le_bytes());
    buf.extend_from_slice(&(session.events.len() as u32).to_le_bytes());
    buf.extend_from_slice(&session.event_hash.to_le_bytes());

    // Events
    for event in session.events.iter() {
        encode_event(&mut buf, event);
    }
    Ok(buf)
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

    let session = ReplaySession {
        mode: ReplayMode::Replay,
        module_hash,
        module_len: module_len as u32,
        events,
        cursor: 0,
        event_hash: header_event_hash,
        total_bytes,
    };
    let mut mgr = REPLAY.lock();
    mgr.sessions[instance_id] = Some(session);
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
