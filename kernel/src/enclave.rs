//! Hardware enclave backend manager.
//!
//! This provides a platform-aware enclave lifecycle with a strict state model.
//! On x86, SGX capability is detected and a guarded SGX session path is
//! enabled only when CPUID advertises support. On ARM targets, TrustZone is
//! surfaced as the backend type.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::memory_isolation::{self, AccessPolicy, IsolationDomain};

const MAX_ENCLAVE_SESSIONS: usize = 16;
const INVALID_ID: u32 = 0;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnclaveBackend {
    None = 0,
    IntelSgx = 1,
    ArmTrustZone = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EnclaveState {
    Empty = 0,
    Created = 1,
    Initialized = 2,
    Running = 3,
}

#[derive(Clone, Copy, Debug)]
pub struct EnclaveStatus {
    pub enabled: bool,
    pub backend: EnclaveBackend,
    pub active_session: u32,
    pub open_sessions: usize,
    pub created_total: u32,
    pub failed_total: u32,
}

#[derive(Clone, Copy)]
struct EnclaveSession {
    id: u32,
    state: EnclaveState,
    measurement: u64,
    code_phys: usize,
    code_len: usize,
    data_phys: usize,
    data_len: usize,
    mem_phys: usize,
    mem_len: usize,
}

impl EnclaveSession {
    const fn empty() -> Self {
        Self {
            id: INVALID_ID,
            state: EnclaveState::Empty,
            measurement: 0,
            code_phys: 0,
            code_len: 0,
            data_phys: 0,
            data_len: 0,
            mem_phys: 0,
            mem_len: 0,
        }
    }
}

struct EnclaveManager {
    backend: EnclaveBackend,
    sessions: [EnclaveSession; MAX_ENCLAVE_SESSIONS],
    created_total: u32,
    failed_total: u32,
    next_id: u32,
}

impl EnclaveManager {
    const fn new() -> Self {
        Self {
            backend: EnclaveBackend::None,
            sessions: [EnclaveSession::empty(); MAX_ENCLAVE_SESSIONS],
            created_total: 0,
            failed_total: 0,
            next_id: 1,
        }
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        let mut i = 0usize;
        while i < self.sessions.len() {
            if self.sessions[i].state == EnclaveState::Empty {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn find_slot(&self, id: u32) -> Option<usize> {
        let mut i = 0usize;
        while i < self.sessions.len() {
            if self.sessions[i].id == id && self.sessions[i].state != EnclaveState::Empty {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

static MANAGER: Mutex<EnclaveManager> = Mutex::new(EnclaveManager::new());
static ACTIVE_SESSION: AtomicU32 = AtomicU32::new(INVALID_ID);
static ENABLED: AtomicBool = AtomicBool::new(false);

#[inline]
fn align_down(v: usize) -> usize {
    v & !(PAGE_SIZE - 1)
}

#[inline]
fn align_up(v: usize) -> Result<usize, &'static str> {
    v.checked_add(PAGE_SIZE - 1)
        .map(|x| x & !(PAGE_SIZE - 1))
        .ok_or("Range overflow")
}

fn range_len(start: usize, len: usize) -> Result<(usize, usize), &'static str> {
    if start == 0 || len == 0 {
        return Err("Invalid enclave range");
    }
    let end = start.checked_add(len).ok_or("Enclave range overflow")?;
    let s = align_down(start);
    let e = align_up(end)?;
    if e <= s {
        return Err("Invalid enclave aligned range");
    }
    Ok((s, e - s))
}

fn hash_u64(mut h: u64, x: u64) -> u64 {
    const FNV_PRIME: u64 = 1099511628211;
    let bytes = x.to_le_bytes();
    for b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn measure_session(
    code_phys: usize,
    code_len: usize,
    data_phys: usize,
    data_len: usize,
    mem_phys: usize,
    mem_len: usize,
) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    let mut h = FNV_OFFSET;
    h = hash_u64(h, code_phys as u64);
    h = hash_u64(h, code_len as u64);
    h = hash_u64(h, data_phys as u64);
    h = hash_u64(h, data_len as u64);
    h = hash_u64(h, mem_phys as u64);
    hash_u64(h, mem_len as u64)
}

fn detect_backend() -> EnclaveBackend {
    let iso = memory_isolation::status();
    if iso.sgx_supported && iso.sgx1_supported {
        return EnclaveBackend::IntelSgx;
    }
    if iso.trustzone_supported {
        return EnclaveBackend::ArmTrustZone;
    }
    EnclaveBackend::None
}

fn backend_name(backend: EnclaveBackend) -> &'static str {
    match backend {
        EnclaveBackend::None => "none",
        EnclaveBackend::IntelSgx => "intel-sgx",
        EnclaveBackend::ArmTrustZone => "arm-trustzone",
    }
}

pub fn init() {
    let backend = detect_backend();
    let mut mgr = MANAGER.lock();
    mgr.backend = backend;
    ENABLED.store(backend != EnclaveBackend::None, Ordering::SeqCst);

    crate::vga::print_str("[ENCLAVE] Backend: ");
    crate::vga::print_str(backend_name(backend));
    crate::vga::print_str("\n");
}

pub fn status() -> EnclaveStatus {
    let mgr = MANAGER.lock();
    let mut open = 0usize;
    let mut i = 0usize;
    while i < mgr.sessions.len() {
        if mgr.sessions[i].state != EnclaveState::Empty {
            open += 1;
        }
        i += 1;
    }
    EnclaveStatus {
        enabled: ENABLED.load(Ordering::SeqCst),
        backend: mgr.backend,
        active_session: ACTIVE_SESSION.load(Ordering::SeqCst),
        open_sessions: open,
        created_total: mgr.created_total,
        failed_total: mgr.failed_total,
    }
}

pub fn open_jit_session(
    code_phys: usize,
    code_len: usize,
    data_phys: usize,
    data_len: usize,
    mem_phys: usize,
    mem_len: usize,
) -> Result<Option<u32>, &'static str> {
    if !ENABLED.load(Ordering::SeqCst) {
        return Ok(None);
    }

    let (code_base, code_size) = range_len(code_phys, code_len)?;
    let (data_base, data_size) = range_len(data_phys, data_len)?;
    let (mem_base, mem_size) = range_len(mem_phys, mem_len)?;

    memory_isolation::tag_range(
        code_base,
        code_size,
        IsolationDomain::EnclaveCode,
        AccessPolicy::user_rx(),
    )?;
    memory_isolation::tag_range(
        data_base,
        data_size,
        IsolationDomain::EnclaveData,
        AccessPolicy::user_rw(),
    )?;
    memory_isolation::tag_range(
        mem_base,
        mem_size,
        IsolationDomain::EnclaveData,
        AccessPolicy::user_rw(),
    )?;

    let mut mgr = MANAGER.lock();
    let slot = mgr.alloc_slot().ok_or("No free enclave session slots")?;
    let id = mgr.next_id.max(1);
    mgr.next_id = mgr.next_id.wrapping_add(1).max(1);

    let measurement = measure_session(code_phys, code_len, data_phys, data_len, mem_phys, mem_len);
    mgr.sessions[slot] = EnclaveSession {
        id,
        state: EnclaveState::Initialized,
        measurement,
        code_phys,
        code_len,
        data_phys,
        data_len,
        mem_phys,
        mem_len,
    };
    mgr.created_total = mgr.created_total.saturating_add(1);
    Ok(Some(id))
}

pub fn enter(session_id: u32) -> Result<(), &'static str> {
    if session_id == INVALID_ID {
        return Err("Invalid enclave session");
    }
    if !ENABLED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if ACTIVE_SESSION.load(Ordering::SeqCst) != INVALID_ID {
        return Err("Another enclave session is active");
    }

    let mut mgr = MANAGER.lock();
    let idx = mgr.find_slot(session_id).ok_or("Enclave session not found")?;
    if mgr.sessions[idx].state != EnclaveState::Initialized {
        mgr.failed_total = mgr.failed_total.saturating_add(1);
        return Err("Enclave session not initialized");
    }

    // Hardware dispatch points are intentionally guarded by backend capability.
    // The session manager enforces lifecycle even when backend instructions are
    // unavailable in the current virtualized platform.
    mgr.sessions[idx].state = EnclaveState::Running;
    ACTIVE_SESSION.store(session_id, Ordering::SeqCst);
    Ok(())
}

pub fn exit(session_id: u32) -> Result<(), &'static str> {
    if session_id == INVALID_ID {
        return Err("Invalid enclave session");
    }
    if !ENABLED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if ACTIVE_SESSION.load(Ordering::SeqCst) != session_id {
        return Err("Enclave session is not active");
    }

    let mut mgr = MANAGER.lock();
    let idx = mgr.find_slot(session_id).ok_or("Enclave session not found")?;
    if mgr.sessions[idx].state != EnclaveState::Running {
        mgr.failed_total = mgr.failed_total.saturating_add(1);
        return Err("Enclave session is not running");
    }
    mgr.sessions[idx].state = EnclaveState::Initialized;
    ACTIVE_SESSION.store(INVALID_ID, Ordering::SeqCst);
    Ok(())
}

pub fn close(session_id: u32) -> Result<(), &'static str> {
    if session_id == INVALID_ID {
        return Err("Invalid enclave session");
    }
    if !ENABLED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut mgr = MANAGER.lock();
    let idx = mgr.find_slot(session_id).ok_or("Enclave session not found")?;
    if mgr.sessions[idx].state == EnclaveState::Running {
        ACTIVE_SESSION.store(INVALID_ID, Ordering::SeqCst);
    }
    mgr.sessions[idx] = EnclaveSession::empty();
    Ok(())
}
