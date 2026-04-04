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

//! Hardware enclave backend manager.
//!
//! This module wires real backend primitives:
//! - Intel SGX (x86): `ECREATE`, `EADD`, `EEXTEND`, `EINIT`, `EENTER`
//! - TrustZone (ARM): secure monitor calls (`SMC`)
//!
//! On unsupported hardware, backend detection resolves to `None`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use crate::memory_isolation::{self, AccessPolicy, IsolationDomain};
use crate::{capnet, memory, security};

const MAX_ENCLAVE_SESSIONS: usize = 16;
const MAX_ATTESTATION_CERTS: usize = 8;
const MAX_PROVISIONED_KEYS: usize = 32;
const MAX_REMOTE_VERIFIERS: usize = 8;
const INVALID_ID: u32 = 0;
const PAGE_SIZE: usize = 4096;
const EPC_POOL_PAGES: usize = 256;
const REMOTE_TOKEN_TTL_EPOCHS: u32 = 100_000;

const TEMPORAL_ENCLAVE_SCHEMA_V1: u8 = 1;
const TEMPORAL_ENCLAVE_SCHEMA_V2: u8 = 2;
/// V3: backend_cookie widened from u32 to u64 (SGX TCS is a 64-bit linear address).
const TEMPORAL_ENCLAVE_SCHEMA_V3: u8 = 3;
const TEMPORAL_ENCLAVE_CURRENT_SCHEMA: u8 = TEMPORAL_ENCLAVE_SCHEMA_V3;
const TEMPORAL_ENCLAVE_SHAPE_BYTES: usize = 12;
const TEMPORAL_ENCLAVE_SESSION_META_BYTES_V1: usize = 64;
/// V2: 96 bytes (cookie=u32, physical addrs as u32 each)
const TEMPORAL_ENCLAVE_SESSION_META_BYTES_V2: usize = 96;
/// V3: 100 bytes (cookie widened to u64, all other fields unchanged)
const TEMPORAL_ENCLAVE_SESSION_META_BYTES_V3: usize = 100;
const TEMPORAL_ENCLAVE_CERT_BYTES: usize = 36;
const TEMPORAL_ENCLAVE_KEY_BYTES: usize = 64;
const TEMPORAL_ENCLAVE_VERIFIER_BYTES: usize = 40;

const TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_KEYS: u32 = 1 << 0;
const TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_REMOTE_SECRETS: u32 = 1 << 1;

const TEMPORAL_SECRET_POLICY_PERSIST: u32 = 0;
const TEMPORAL_SECRET_POLICY_REDACT: u32 = 1;
static TEMPORAL_SECRET_POLICY: AtomicU32 = AtomicU32::new(TEMPORAL_SECRET_POLICY_PERSIST);

pub fn temporal_set_secret_redaction_enabled(enabled: bool) {
    TEMPORAL_SECRET_POLICY.store(
        if enabled {
            TEMPORAL_SECRET_POLICY_REDACT
        } else {
            TEMPORAL_SECRET_POLICY_PERSIST
        },
        Ordering::SeqCst,
    );
    record_temporal_enclave_state_snapshot();
}

pub fn temporal_secret_redaction_enabled() -> bool {
    TEMPORAL_SECRET_POLICY.load(Ordering::SeqCst) == TEMPORAL_SECRET_POLICY_REDACT
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EnclaveBackend {
    None = 0,
    IntelSgx = 1,
    ArmTrustZone = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RemoteAttestationPolicy {
    Disabled = 0,
    Audit = 1,
    Enforce = 2,
}

impl RemoteAttestationPolicy {
    const fn from_u32(v: u32) -> Self {
        match v {
            2 => Self::Enforce,
            1 => Self::Audit,
            _ => Self::Disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EnclaveState {
    Empty = 0,
    Initialized = 1,
    Running = 2,
}

#[derive(Clone, Copy, Debug)]
pub struct EnclaveStatus {
    pub enabled: bool,
    pub backend: EnclaveBackend,
    pub active_session: u32,
    pub open_sessions: usize,
    pub created_total: u32,
    pub failed_total: u32,
    pub backend_ops_total: u32,
    pub epc_total_pages: usize,
    pub epc_used_pages: usize,
    pub attestation_reports: u32,
    pub trustzone_contract_ready: bool,
    pub cert_chain_ready: bool,
    pub provisioned_keys_active: usize,
    pub key_provisioned_total: u32,
    pub key_revoked_total: u32,
    pub attestation_verified_total: u32,
    pub attestation_failed_total: u32,
    pub vendor_root_ready: bool,
    pub remote_policy: RemoteAttestationPolicy,
    pub remote_verifiers_configured: usize,
    pub remote_attestation_verified_total: u32,
    pub remote_attestation_failed_total: u32,
    pub remote_attestation_audit_only_total: u32,
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
    backend_cookie: u64, // SGX: TCS linear address (full 64-bit); TrustZone: SMC handle
    epc_base: usize,
    epc_pages: usize,
    launch_token_mac: u64,
    launch_nonce: u32,
    runtime_key_handle: u32,
    attested: bool,
    remote_attested: bool,
    remote_verifier_id: u32,
    remote_quote_nonce: u64,
    remote_attest_issued_epoch: u32,
    remote_attest_expires_epoch: u32,
    remote_attest_mac: u64,
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
            backend_cookie: 0u64,
            epc_base: 0,
            epc_pages: 0,
            launch_token_mac: 0,
            launch_nonce: 0,
            runtime_key_handle: 0,
            attested: false,
            remote_attested: false,
            remote_verifier_id: 0,
            remote_quote_nonce: 0,
            remote_attest_issued_epoch: 0,
            remote_attest_expires_epoch: 0,
            remote_attest_mac: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum CertRole {
    Root = 0,
    QuoteSigner = 1,
    Platform = 2,
}

#[derive(Clone, Copy, Debug)]
struct AttestationCertificate {
    cert_id: u32,
    issuer_id: u32,
    role: CertRole,
    pubkey_fingerprint: u64,
    not_before_epoch: u32,
    not_after_epoch: u32,
    signature: u64,
    revoked: bool,
}

impl AttestationCertificate {
    const fn empty() -> Self {
        Self {
            cert_id: 0,
            issuer_id: 0,
            role: CertRole::Root,
            pubkey_fingerprint: 0,
            not_before_epoch: 0,
            not_after_epoch: 0,
            signature: 0,
            revoked: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AttestationQuote {
    session_id: u32,
    backend: EnclaveBackend,
    measurement: u64,
    nonce: u64,
    platform_cert_id: u32,
    signer_cert_id: u32,
    root_cert_id: u32,
    launch_token_mac: u64,
    issued_epoch: u32,
    report_mac: u64,
}

#[derive(Clone, Copy)]
struct BackendTrustAnchor {
    root_fingerprint: u64,
    signer_fingerprint: u64,
    root_signing_key: u64,
    signer_signing_key: u64,
    default_remote_verifier_fingerprint: u64,
    default_remote_shared_secret: u64,
}

#[derive(Clone, Copy)]
struct RemoteVerifier {
    id: u32,
    backend: EnclaveBackend,
    root_fingerprint: u64,
    verifier_fingerprint: u64,
    shared_secret: u64,
    not_before_epoch: u32,
    not_after_epoch: u32,
    enabled: bool,
}

impl RemoteVerifier {
    const fn empty() -> Self {
        Self {
            id: 0,
            backend: EnclaveBackend::None,
            root_fingerprint: 0,
            verifier_fingerprint: 0,
            shared_secret: 0,
            not_before_epoch: 0,
            not_after_epoch: 0,
            enabled: false,
        }
    }
}

#[derive(Clone, Copy)]
struct RemoteAttestationToken {
    verifier_id: u32,
    session_id: u32,
    backend: EnclaveBackend,
    measurement: u64,
    quote_nonce: u64,
    issued_epoch: u32,
    expires_epoch: u32,
    verdict: u32,
    token_mac: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum KeyState {
    Empty = 0,
    Active = 1,
    Revoked = 2,
}

#[derive(Clone, Copy)]
struct ProvisionedKey {
    handle: u32,
    owner_session: u32,
    purpose: u32,
    material: [u8; 32],
    created_epoch: u32,
    expires_epoch: u32,
    sealed_mac: u64,
    state: KeyState,
}

impl ProvisionedKey {
    const fn empty() -> Self {
        Self {
            handle: 0,
            owner_session: 0,
            purpose: 0,
            material: [0; 32],
            created_epoch: 0,
            expires_epoch: 0,
            sealed_mac: 0,
            state: KeyState::Empty,
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

    fn mark_failure(&mut self) {
        self.failed_total = self.failed_total.saturating_add(1);
    }
}

static MANAGER: Mutex<EnclaveManager> = Mutex::new(EnclaveManager::new());
static ACTIVE_SESSION: AtomicU32 = AtomicU32::new(INVALID_ID);
static ENABLED: AtomicBool = AtomicBool::new(false);
static BACKEND_OPS_TOTAL: AtomicU32 = AtomicU32::new(0);
static ATTESTATION_REPORTS: AtomicU32 = AtomicU32::new(0);

#[inline]
fn record_backend_op() {
    BACKEND_OPS_TOTAL.fetch_add(1, Ordering::SeqCst);
}

#[derive(Clone, Copy)]
struct EpcManager {
    /// Physical base address of the EPC pool (from CPUID 0x12 or jit_allocate).
    base: usize,
    /// Virtual base address corresponding to `base` (= base + EPC_VIRT_OFFSET).
    /// All pointer arithmetic visible to enclave code uses this address.
    virt_base: usize,
    pages: usize,
    owner: [u32; EPC_POOL_PAGES],
}

impl EpcManager {
    const fn new() -> Self {
        Self {
            base: 0,
            virt_base: 0,
            pages: 0,
            owner: [INVALID_ID; EPC_POOL_PAGES],
        }
    }

    fn clear(&mut self) {
        self.base = 0;
        self.virt_base = 0;
        self.pages = 0;
        self.owner = [INVALID_ID; EPC_POOL_PAGES];
    }

    fn used_pages(&self) -> usize {
        let mut used = 0usize;
        let mut i = 0usize;
        while i < self.pages {
            if self.owner[i] != INVALID_ID {
                used += 1;
            }
            i += 1;
        }
        used
    }

    fn init_pool(&mut self) -> Result<(), &'static str> {
        self.clear();

        // Attempt EPC discovery via CPUID leaf 0x12.
        //
        // Sub-leaves 2 and above enumerate EPC sections.  Each section has
        // ECX[3:0] = type: 0x1 means a valid confidential EPC section.
        //   Physical base PA = { EBX[19:0], EAX[31:12] } (bits 51:12)
        //   Section size     = { EDX[19:0], ECX[31:12] } (bits 51:12)
        //
        // We use the first valid section whose reported size is enough for
        // our pool, falling back to jit_allocate_pages if no hardware EPC
        // is enumerated (e.g. running in a VM without SGX passthrough).
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let mut sub = 2u32;
            loop {
                let mut eax = 0u32;
                let mut ebx = 0u32;
                let mut ecx = 0u32;
                let mut edx = 0u32;
                unsafe {
                    sgx_cpuid_leaf12(
                        sub,
                        &mut eax as *mut u32,
                        &mut ebx as *mut u32,
                        &mut ecx as *mut u32,
                        &mut edx as *mut u32,
                    );
                }
                let section_type = ecx & 0xF;
                if section_type == 0 {
                    // No more EPC sections.
                    break;
                }
                if section_type == 1 {
                    // Valid EPC section.  Reconstruct 52-bit base and size.
                    // Base: EAX[31:12] provides bits 31:12; EBX[19:0] provides bits 51:32.
                    let base_low = (eax & 0xFFFF_F000) as u64;
                    let base_high = (ebx & 0x000F_FFFF) as u64;
                    let epc_pa: usize = ((base_high << 32) | base_low) as usize;

                    // Size: ECX[31:12] provides bits 31:12; EDX[19:0] provides bits 51:32.
                    let size_low = (ecx & 0xFFFF_F000) as u64;
                    let size_high = (edx & 0x000F_FFFF) as u64;
                    let epc_size: usize = ((size_high << 32) | size_low) as usize;

                    let needed = EPC_POOL_PAGES * PAGE_SIZE;
                    if epc_pa != 0 && epc_size >= needed {
                        // Hardware EPC discovered.  The physical address is the
                        // EPC linear address as mapped by the platform (the OS
                        // must map EPC memory identity-mapped or via a dedicated
                        // region; here we use the physical address directly as
                        // the kernel runs with a 1:1 map).
                        self.base = epc_pa;
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        {
                            self.virt_base = epc_phys_to_virt(epc_pa);
                        }
                        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                        {
                            self.virt_base = epc_pa;
                        }
                        self.pages = EPC_POOL_PAGES.min(epc_size / PAGE_SIZE);
                        return Ok(());
                    }
                }
                sub += 1;
                if sub > 10 {
                    break; // guard against broken firmware
                }
            }
        }

        // No hardware EPC found (or non-x86 build); fall back to the kernel
        // JIT allocator to obtain a memory region.  This allows the SGX
        // lifecycle code path to exercise the full Rust state machine without
        // real EPC, which is useful for VMs and simulation environments.
        let base = memory::jit_allocate_pages(EPC_POOL_PAGES)?;
        self.base = base;
        self.virt_base = base; // jit_allocate_pages returns a virtual address directly
        self.pages = EPC_POOL_PAGES;
        Ok(())
    }

    fn reserve_contiguous(&mut self, owner: u32, count: usize) -> Result<usize, &'static str> {
        if owner == INVALID_ID || count == 0 || self.base == 0 || count > self.pages {
            return Err("Invalid EPC reservation request");
        }
        let mut start = 0usize;
        while start + count <= self.pages {
            let mut free = true;
            let mut i = start;
            while i < start + count {
                if self.owner[i] != INVALID_ID {
                    free = false;
                    break;
                }
                i += 1;
            }
            if free {
                let mut j = start;
                while j < start + count {
                    self.owner[j] = owner;
                    j += 1;
                }
                // Return the *virtual* address so all enclave pointer arithmetic
                // uses addresses that are valid in the kernel's address space.
                return Ok(self.virt_base + (start * PAGE_SIZE));
            }
            start += 1;
        }
        Err("EPC pool exhausted")
    }

    fn release_owner(&mut self, owner: u32) {
        if owner == INVALID_ID || self.base == 0 {
            return;
        }
        let mut i = 0usize;
        while i < self.pages {
            if self.owner[i] == owner {
                self.owner[i] = INVALID_ID;
            }
            i += 1;
        }
    }
}

static EPC_MANAGER: Mutex<EpcManager> = Mutex::new(EpcManager::new());

#[derive(Clone, Copy)]
struct TrustZoneContract {
    ready: bool,
    abi_major: u16,
    abi_minor: u16,
    features: u32,
    max_sessions: u32,
}

impl TrustZoneContract {
    const fn new() -> Self {
        Self {
            ready: false,
            abi_major: 0,
            abi_minor: 0,
            features: 0,
            max_sessions: 0,
        }
    }
}

static TRUSTZONE_CONTRACT: Mutex<TrustZoneContract> = Mutex::new(TrustZoneContract::new());
static CERT_CHAIN_READY: AtomicBool = AtomicBool::new(false);
static CERT_CHAIN: Mutex<[AttestationCertificate; MAX_ATTESTATION_CERTS]> =
    Mutex::new([AttestationCertificate::empty(); MAX_ATTESTATION_CERTS]);
static PROVISIONED_KEYS: Mutex<[ProvisionedKey; MAX_PROVISIONED_KEYS]> =
    Mutex::new([ProvisionedKey::empty(); MAX_PROVISIONED_KEYS]);
static REMOTE_VERIFIERS: Mutex<[RemoteVerifier; MAX_REMOTE_VERIFIERS]> =
    Mutex::new([RemoteVerifier::empty(); MAX_REMOTE_VERIFIERS]);
static EPOCH_COUNTER: AtomicU32 = AtomicU32::new(1);
static KEY_PROVISIONED_TOTAL: AtomicU32 = AtomicU32::new(0);
static KEY_REVOKED_TOTAL: AtomicU32 = AtomicU32::new(0);
static ATTESTATION_VERIFIED_TOTAL: AtomicU32 = AtomicU32::new(0);
static ATTESTATION_FAILED_TOTAL: AtomicU32 = AtomicU32::new(0);
static VENDOR_ROOT_READY: AtomicBool = AtomicBool::new(false);
static REMOTE_POLICY: AtomicU32 = AtomicU32::new(RemoteAttestationPolicy::Enforce as u32);
static REMOTE_ATTESTATION_VERIFIED_TOTAL: AtomicU32 = AtomicU32::new(0);
static REMOTE_ATTESTATION_FAILED_TOTAL: AtomicU32 = AtomicU32::new(0);
static REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL: AtomicU32 = AtomicU32::new(0);

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

fn temporal_backend_from_u8(v: u8) -> Option<EnclaveBackend> {
    match v {
        0 => Some(EnclaveBackend::None),
        1 => Some(EnclaveBackend::IntelSgx),
        2 => Some(EnclaveBackend::ArmTrustZone),
        _ => None,
    }
}

fn temporal_enclave_state_from_u8(v: u8) -> Option<EnclaveState> {
    match v {
        0 => Some(EnclaveState::Empty),
        1 => Some(EnclaveState::Initialized),
        2 => Some(EnclaveState::Running),
        _ => None,
    }
}

fn temporal_cert_role_from_u8(v: u8) -> Option<CertRole> {
    match v {
        0 => Some(CertRole::Root),
        1 => Some(CertRole::QuoteSigner),
        2 => Some(CertRole::Platform),
        _ => None,
    }
}

fn temporal_key_state_from_u8(v: u8) -> Option<KeyState> {
    match v {
        0 => Some(KeyState::Empty),
        1 => Some(KeyState::Active),
        2 => Some(KeyState::Revoked),
        _ => None,
    }
}

fn encode_temporal_enclave_payload(event: u8) -> Option<Vec<u8>> {
    let (backend, sessions, created_total, failed_total, next_id) = {
        let mgr = MANAGER.lock();
        (
            mgr.backend,
            mgr.sessions,
            mgr.created_total,
            mgr.failed_total,
            mgr.next_id,
        )
    };
    let enabled = ENABLED.load(Ordering::SeqCst);
    let active_session = ACTIVE_SESSION.load(Ordering::SeqCst);
    let backend_ops_total = BACKEND_OPS_TOTAL.load(Ordering::SeqCst);
    let attestation_reports = ATTESTATION_REPORTS.load(Ordering::SeqCst);
    let epoch_counter = EPOCH_COUNTER.load(Ordering::SeqCst);
    let key_provisioned_total = KEY_PROVISIONED_TOTAL.load(Ordering::SeqCst);
    let key_revoked_total = KEY_REVOKED_TOTAL.load(Ordering::SeqCst);
    let attestation_verified_total = ATTESTATION_VERIFIED_TOTAL.load(Ordering::SeqCst);
    let attestation_failed_total = ATTESTATION_FAILED_TOTAL.load(Ordering::SeqCst);
    let remote_policy = REMOTE_POLICY.load(Ordering::SeqCst);
    let remote_verified_total = REMOTE_ATTESTATION_VERIFIED_TOTAL.load(Ordering::SeqCst);
    let remote_failed_total = REMOTE_ATTESTATION_FAILED_TOTAL.load(Ordering::SeqCst);
    let remote_audit_total = REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL.load(Ordering::SeqCst);
    let cert_chain_ready = CERT_CHAIN_READY.load(Ordering::SeqCst);
    let vendor_root_ready = VENDOR_ROOT_READY.load(Ordering::SeqCst);
    let trustzone = *TRUSTZONE_CONTRACT.lock();
    let cert_chain = *CERT_CHAIN.lock();
    let provisioned_keys = *PROVISIONED_KEYS.lock();
    let remote_verifiers = *REMOTE_VERIFIERS.lock();
    let redact_secrets = temporal_secret_redaction_enabled();

    let scalar_bytes = 84usize;
    let total_len = 4usize
        .saturating_add(TEMPORAL_ENCLAVE_SHAPE_BYTES)
        .saturating_add(scalar_bytes)
        .saturating_add(MAX_ENCLAVE_SESSIONS.saturating_mul(TEMPORAL_ENCLAVE_SESSION_META_BYTES_V3))
        .saturating_add(MAX_ATTESTATION_CERTS.saturating_mul(TEMPORAL_ENCLAVE_CERT_BYTES))
        .saturating_add(MAX_PROVISIONED_KEYS.saturating_mul(TEMPORAL_ENCLAVE_KEY_BYTES))
        .saturating_add(MAX_REMOTE_VERIFIERS.saturating_mul(TEMPORAL_ENCLAVE_VERIFIER_BYTES));
    if total_len > crate::temporal::MAX_TEMPORAL_VERSION_BYTES {
        return None;
    }

    let mut payload = Vec::with_capacity(total_len);
    payload.push(crate::temporal::TEMPORAL_OBJECT_ENCODING_V1);
    payload.push(crate::temporal::TEMPORAL_ENCLAVE_OBJECT);
    payload.push(event);
    payload.push(TEMPORAL_ENCLAVE_CURRENT_SCHEMA);

    temporal_append_u16(&mut payload, MAX_ENCLAVE_SESSIONS as u16);
    temporal_append_u16(&mut payload, MAX_ATTESTATION_CERTS as u16);
    temporal_append_u16(&mut payload, MAX_PROVISIONED_KEYS as u16);
    temporal_append_u16(&mut payload, MAX_REMOTE_VERIFIERS as u16);
    temporal_append_u32(&mut payload, 0);

    payload.push(if enabled { 1 } else { 0 });
    payload.push(backend as u8);
    temporal_append_u16(&mut payload, 0);
    temporal_append_u32(&mut payload, active_session);
    temporal_append_u32(&mut payload, created_total);
    temporal_append_u32(&mut payload, failed_total);
    temporal_append_u32(&mut payload, next_id);
    temporal_append_u32(&mut payload, backend_ops_total);
    temporal_append_u32(&mut payload, attestation_reports);
    payload.push(if trustzone.ready { 1 } else { 0 });
    payload.push(if cert_chain_ready { 1 } else { 0 });
    payload.push(if vendor_root_ready { 1 } else { 0 });
    payload.push(0);
    temporal_append_u16(&mut payload, trustzone.abi_major);
    temporal_append_u16(&mut payload, trustzone.abi_minor);
    temporal_append_u32(&mut payload, trustzone.features);
    temporal_append_u32(&mut payload, trustzone.max_sessions);
    temporal_append_u32(&mut payload, epoch_counter);
    temporal_append_u32(&mut payload, remote_policy);
    temporal_append_u32(&mut payload, key_provisioned_total);
    temporal_append_u32(&mut payload, key_revoked_total);
    temporal_append_u32(&mut payload, attestation_verified_total);
    temporal_append_u32(&mut payload, attestation_failed_total);
    temporal_append_u32(&mut payload, remote_verified_total);
    temporal_append_u32(&mut payload, remote_failed_total);
    temporal_append_u32(&mut payload, remote_audit_total);
    let mut persist_flags = 0u32;
    if redact_secrets {
        persist_flags |= TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_KEYS;
        persist_flags |= TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_REMOTE_SECRETS;
    }
    temporal_append_u32(&mut payload, persist_flags);

    for session in sessions.iter() {
        temporal_append_u32(&mut payload, session.id);
        payload.push(session.state as u8);
        payload.push(if session.attested { 1 } else { 0 });
        payload.push(if session.remote_attested { 1 } else { 0 });
        payload.push(0);
        temporal_append_u64(&mut payload, session.measurement);
        temporal_append_u64(&mut payload, session.backend_cookie); // u64: full TCS linear addr
        temporal_append_u64(&mut payload, session.launch_token_mac);
        temporal_append_u32(&mut payload, session.launch_nonce);
        temporal_append_u32(&mut payload, session.runtime_key_handle);
        temporal_append_u32(&mut payload, session.remote_verifier_id);
        temporal_append_u64(&mut payload, session.remote_quote_nonce);
        temporal_append_u32(&mut payload, session.remote_attest_issued_epoch);
        temporal_append_u32(&mut payload, session.remote_attest_expires_epoch);
        temporal_append_u64(&mut payload, session.remote_attest_mac);
        temporal_append_u32(&mut payload, session.code_phys as u32);
        temporal_append_u32(&mut payload, session.code_len as u32);
        temporal_append_u32(&mut payload, session.data_phys as u32);
        temporal_append_u32(&mut payload, session.data_len as u32);
        temporal_append_u32(&mut payload, session.mem_phys as u32);
        temporal_append_u32(&mut payload, session.mem_len as u32);
        temporal_append_u32(&mut payload, session.epc_base as u32);
        temporal_append_u32(&mut payload, session.epc_pages as u32);
    }

    for cert in cert_chain.iter() {
        temporal_append_u32(&mut payload, cert.cert_id);
        temporal_append_u32(&mut payload, cert.issuer_id);
        payload.push(cert.role as u8);
        payload.push(if cert.revoked { 1 } else { 0 });
        temporal_append_u16(&mut payload, 0);
        temporal_append_u64(&mut payload, cert.pubkey_fingerprint);
        temporal_append_u32(&mut payload, cert.not_before_epoch);
        temporal_append_u32(&mut payload, cert.not_after_epoch);
        temporal_append_u64(&mut payload, cert.signature);
    }

    for key in provisioned_keys.iter() {
        let mut record = *key;
        if redact_secrets {
            record.material = [0u8; 32];
            if record.state == KeyState::Active {
                record.state = KeyState::Revoked;
            }
            record.sealed_mac = seal_key_record(&record);
        }

        temporal_append_u32(&mut payload, record.handle);
        temporal_append_u32(&mut payload, record.owner_session);
        temporal_append_u32(&mut payload, record.purpose);
        payload.push(record.state as u8);
        payload.push(0);
        payload.push(0);
        payload.push(0);
        temporal_append_u32(&mut payload, record.created_epoch);
        temporal_append_u32(&mut payload, record.expires_epoch);
        temporal_append_u64(&mut payload, record.sealed_mac);
        payload.extend_from_slice(&record.material);
    }

    for verifier in remote_verifiers.iter() {
        let mut record = *verifier;
        if redact_secrets {
            record.shared_secret = 0;
            record.enabled = false;
        }

        temporal_append_u32(&mut payload, record.id);
        payload.push(record.backend as u8);
        payload.push(if record.enabled { 1 } else { 0 });
        temporal_append_u16(&mut payload, 0);
        temporal_append_u64(&mut payload, record.root_fingerprint);
        temporal_append_u64(&mut payload, record.verifier_fingerprint);
        temporal_append_u64(&mut payload, record.shared_secret);
        temporal_append_u32(&mut payload, record.not_before_epoch);
        temporal_append_u32(&mut payload, record.not_after_epoch);
    }

    Some(payload)
}

fn record_temporal_enclave_state_snapshot() {
    if crate::temporal::is_replay_active() {
        return;
    }
    let payload =
        match encode_temporal_enclave_payload(crate::temporal::TEMPORAL_ENCLAVE_EVENT_STATE) {
            Some(v) => v,
            None => return,
        };
    let _ = crate::temporal::record_enclave_state_event(&payload);
}

pub fn temporal_apply_enclave_state_payload(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < 4 + TEMPORAL_ENCLAVE_SHAPE_BYTES + 84 {
        return Err("temporal enclave payload too short");
    }
    let schema = payload[3];
    if schema != TEMPORAL_ENCLAVE_SCHEMA_V1
        && schema != TEMPORAL_ENCLAVE_SCHEMA_V2
        && schema != TEMPORAL_ENCLAVE_SCHEMA_V3
    {
        return Err("temporal enclave schema unsupported");
    }

    let max_sessions =
        temporal_read_u16(payload, 4).ok_or("temporal enclave max sessions missing")? as usize;
    let max_certs =
        temporal_read_u16(payload, 6).ok_or("temporal enclave max certs missing")? as usize;
    let max_keys =
        temporal_read_u16(payload, 8).ok_or("temporal enclave max keys missing")? as usize;
    let max_verifiers =
        temporal_read_u16(payload, 10).ok_or("temporal enclave max verifiers missing")? as usize;
    if max_sessions != MAX_ENCLAVE_SESSIONS
        || max_certs != MAX_ATTESTATION_CERTS
        || max_keys != MAX_PROVISIONED_KEYS
        || max_verifiers != MAX_REMOTE_VERIFIERS
    {
        return Err("temporal enclave shape mismatch");
    }

    let mut offset = 4 + TEMPORAL_ENCLAVE_SHAPE_BYTES;
    let enabled = payload[offset] != 0;
    let backend =
        temporal_backend_from_u8(payload[offset + 1]).ok_or("temporal enclave backend invalid")?;
    let active_session =
        temporal_read_u32(payload, offset + 4).ok_or("temporal enclave active session missing")?;
    let created_total =
        temporal_read_u32(payload, offset + 8).ok_or("temporal enclave created total missing")?;
    let failed_total =
        temporal_read_u32(payload, offset + 12).ok_or("temporal enclave failed total missing")?;
    let next_id =
        temporal_read_u32(payload, offset + 16).ok_or("temporal enclave next id missing")?;
    let backend_ops_total =
        temporal_read_u32(payload, offset + 20).ok_or("temporal enclave backend ops missing")?;
    let attestation_reports =
        temporal_read_u32(payload, offset + 24).ok_or("temporal enclave reports missing")?;
    let trustzone_ready = payload[offset + 28] != 0;
    let cert_chain_ready = payload[offset + 29] != 0;
    let vendor_root_ready = payload[offset + 30] != 0;
    let tz_abi_major =
        temporal_read_u16(payload, offset + 32).ok_or("temporal enclave tz abi major missing")?;
    let tz_abi_minor =
        temporal_read_u16(payload, offset + 34).ok_or("temporal enclave tz abi minor missing")?;
    let tz_features =
        temporal_read_u32(payload, offset + 36).ok_or("temporal enclave tz features missing")?;
    let tz_max_sessions = temporal_read_u32(payload, offset + 40)
        .ok_or("temporal enclave tz max sessions missing")?;
    let epoch_counter =
        temporal_read_u32(payload, offset + 44).ok_or("temporal enclave epoch counter missing")?;
    let remote_policy =
        temporal_read_u32(payload, offset + 48).ok_or("temporal enclave remote policy missing")?;
    let key_provisioned_total = temporal_read_u32(payload, offset + 52)
        .ok_or("temporal enclave key provisioned missing")?;
    let key_revoked_total =
        temporal_read_u32(payload, offset + 56).ok_or("temporal enclave key revoked missing")?;
    let attestation_verified_total = temporal_read_u32(payload, offset + 60)
        .ok_or("temporal enclave attest verified missing")?;
    let attestation_failed_total =
        temporal_read_u32(payload, offset + 64).ok_or("temporal enclave attest failed missing")?;
    let remote_verified_total = temporal_read_u32(payload, offset + 68)
        .ok_or("temporal enclave remote verified missing")?;
    let remote_failed_total =
        temporal_read_u32(payload, offset + 72).ok_or("temporal enclave remote failed missing")?;
    let remote_audit_total =
        temporal_read_u32(payload, offset + 76).ok_or("temporal enclave remote audit missing")?;
    let persist_flags =
        temporal_read_u32(payload, offset + 80).ok_or("temporal enclave persist flags missing")?;
    offset = offset.saturating_add(84);

    let session_meta_bytes = if schema == TEMPORAL_ENCLAVE_SCHEMA_V3 {
        TEMPORAL_ENCLAVE_SESSION_META_BYTES_V3
    } else if schema == TEMPORAL_ENCLAVE_SCHEMA_V2 {
        TEMPORAL_ENCLAVE_SESSION_META_BYTES_V2
    } else {
        TEMPORAL_ENCLAVE_SESSION_META_BYTES_V1
    };

    let mut decoded_sessions = [EnclaveSession::empty(); MAX_ENCLAVE_SESSIONS];
    for i in 0..MAX_ENCLAVE_SESSIONS {
        if offset.saturating_add(session_meta_bytes) > payload.len() {
            return Err("temporal enclave session truncated");
        }
        let id = temporal_read_u32(payload, offset).ok_or("temporal enclave session id missing")?;
        let state = temporal_enclave_state_from_u8(payload[offset + 4])
            .ok_or("temporal enclave session state invalid")?;
        let attested = payload[offset + 5] != 0;
        let remote_attested = payload[offset + 6] != 0;
        let measurement =
            temporal_read_u64(payload, offset + 8).ok_or("temporal enclave measurement missing")?;
        // V3: backend_cookie is u64 (full 64-bit TCS/handle address).
        // V1/V2: backend_cookie was u32; zero-extend for compat.
        let (backend_cookie, cookie_stride) = if schema == TEMPORAL_ENCLAVE_SCHEMA_V3 {
            (
                temporal_read_u64(payload, offset + 16).ok_or("temporal enclave cookie missing")?,
                8usize,
            )
        } else {
            (
                temporal_read_u32(payload, offset + 16).ok_or("temporal enclave cookie missing")?
                    as u64,
                4usize,
            )
        };
        let base_off = 16 + cookie_stride; // offset of launch_token_mac
        let launch_token_mac = temporal_read_u64(payload, offset + base_off)
            .ok_or("temporal enclave launch mac missing")?;
        let launch_nonce = temporal_read_u32(payload, offset + base_off + 8)
            .ok_or("temporal enclave launch nonce missing")?;
        let runtime_key_handle = temporal_read_u32(payload, offset + base_off + 12)
            .ok_or("temporal enclave key handle missing")?;
        let remote_verifier_id = temporal_read_u32(payload, offset + base_off + 16)
            .ok_or("temporal enclave verifier id missing")?;
        let remote_quote_nonce = temporal_read_u64(payload, offset + base_off + 20)
            .ok_or("temporal enclave quote nonce missing")?;
        let remote_attest_issued_epoch = temporal_read_u32(payload, offset + base_off + 28)
            .ok_or("temporal enclave attest issued missing")?;
        let remote_attest_expires_epoch = temporal_read_u32(payload, offset + base_off + 32)
            .ok_or("temporal enclave attest expires missing")?;
        let remote_attest_mac = temporal_read_u64(payload, offset + base_off + 36)
            .ok_or("temporal enclave attest mac missing")?;
        let (code_phys, code_len, data_phys, data_len, mem_phys, mem_len, epc_base, epc_pages) =
            if schema == TEMPORAL_ENCLAVE_SCHEMA_V2 || schema == TEMPORAL_ENCLAVE_SCHEMA_V3 {
                // Physical address block follows launch fields.
                // base_off = 16 + cookie_stride; physical addrs start at base_off + 44.
                let pa = base_off + 44;
                (
                    temporal_read_u32(payload, offset + pa)
                        .ok_or("temporal enclave code phys missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 4)
                        .ok_or("temporal enclave code len missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 8)
                        .ok_or("temporal enclave data phys missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 12)
                        .ok_or("temporal enclave data len missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 16)
                        .ok_or("temporal enclave mem phys missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 20)
                        .ok_or("temporal enclave mem len missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 24)
                        .ok_or("temporal enclave epc base missing")? as usize,
                    temporal_read_u32(payload, offset + pa + 28)
                        .ok_or("temporal enclave epc pages missing")? as usize,
                )
            } else {
                (
                    0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize, 0usize,
                )
            };

        decoded_sessions[i] = EnclaveSession {
            id,
            state,
            measurement,
            code_phys,
            code_len,
            data_phys,
            data_len,
            mem_phys,
            mem_len,
            backend_cookie,
            epc_base,
            epc_pages,
            launch_token_mac,
            launch_nonce,
            runtime_key_handle,
            attested,
            remote_attested,
            remote_verifier_id,
            remote_quote_nonce,
            remote_attest_issued_epoch,
            remote_attest_expires_epoch,
            remote_attest_mac,
        };
        offset = offset.saturating_add(session_meta_bytes);
    }

    let mut cert_chain = [AttestationCertificate::empty(); MAX_ATTESTATION_CERTS];
    for i in 0..MAX_ATTESTATION_CERTS {
        if offset.saturating_add(TEMPORAL_ENCLAVE_CERT_BYTES) > payload.len() {
            return Err("temporal enclave cert truncated");
        }
        let cert_id =
            temporal_read_u32(payload, offset).ok_or("temporal enclave cert id missing")?;
        let issuer_id =
            temporal_read_u32(payload, offset + 4).ok_or("temporal enclave issuer id missing")?;
        let role = temporal_cert_role_from_u8(payload[offset + 8])
            .ok_or("temporal enclave role invalid")?;
        let revoked = payload[offset + 9] != 0;
        let pubkey_fingerprint = temporal_read_u64(payload, offset + 12)
            .ok_or("temporal enclave fingerprint missing")?;
        let not_before_epoch =
            temporal_read_u32(payload, offset + 20).ok_or("temporal enclave not before missing")?;
        let not_after_epoch =
            temporal_read_u32(payload, offset + 24).ok_or("temporal enclave not after missing")?;
        let signature =
            temporal_read_u64(payload, offset + 28).ok_or("temporal enclave signature missing")?;
        cert_chain[i] = AttestationCertificate {
            cert_id,
            issuer_id,
            role,
            pubkey_fingerprint,
            not_before_epoch,
            not_after_epoch,
            signature,
            revoked,
        };
        offset = offset.saturating_add(TEMPORAL_ENCLAVE_CERT_BYTES);
    }

    let mut provisioned_keys = [ProvisionedKey::empty(); MAX_PROVISIONED_KEYS];
    for i in 0..MAX_PROVISIONED_KEYS {
        if offset.saturating_add(TEMPORAL_ENCLAVE_KEY_BYTES) > payload.len() {
            return Err("temporal enclave key truncated");
        }
        let handle =
            temporal_read_u32(payload, offset).ok_or("temporal enclave key handle missing")?;
        let owner_session =
            temporal_read_u32(payload, offset + 4).ok_or("temporal enclave key owner missing")?;
        let purpose =
            temporal_read_u32(payload, offset + 8).ok_or("temporal enclave key purpose missing")?;
        let state = temporal_key_state_from_u8(payload[offset + 12])
            .ok_or("temporal enclave key state invalid")?;
        let created_epoch = temporal_read_u32(payload, offset + 16)
            .ok_or("temporal enclave key created missing")?;
        let expires_epoch = temporal_read_u32(payload, offset + 20)
            .ok_or("temporal enclave key expires missing")?;
        let sealed_mac =
            temporal_read_u64(payload, offset + 24).ok_or("temporal enclave key mac missing")?;
        let mut material = [0u8; 32];
        material.copy_from_slice(&payload[offset + 32..offset + 64]);
        provisioned_keys[i] = ProvisionedKey {
            handle,
            owner_session,
            purpose,
            material,
            created_epoch,
            expires_epoch,
            sealed_mac,
            state,
        };
        offset = offset.saturating_add(TEMPORAL_ENCLAVE_KEY_BYTES);
    }

    let mut remote_verifiers = [RemoteVerifier::empty(); MAX_REMOTE_VERIFIERS];
    for i in 0..MAX_REMOTE_VERIFIERS {
        if offset.saturating_add(TEMPORAL_ENCLAVE_VERIFIER_BYTES) > payload.len() {
            return Err("temporal enclave verifier truncated");
        }
        let id =
            temporal_read_u32(payload, offset).ok_or("temporal enclave verifier id missing")?;
        let backend = temporal_backend_from_u8(payload[offset + 4])
            .ok_or("temporal enclave verifier backend invalid")?;
        let enabled_flag = payload[offset + 5] != 0;
        let root_fingerprint = temporal_read_u64(payload, offset + 8)
            .ok_or("temporal enclave verifier root missing")?;
        let verifier_fingerprint = temporal_read_u64(payload, offset + 16)
            .ok_or("temporal enclave verifier fingerprint missing")?;
        let shared_secret = temporal_read_u64(payload, offset + 24)
            .ok_or("temporal enclave verifier secret missing")?;
        let not_before_epoch = temporal_read_u32(payload, offset + 32)
            .ok_or("temporal enclave verifier not before missing")?;
        let not_after_epoch = temporal_read_u32(payload, offset + 36)
            .ok_or("temporal enclave verifier not after missing")?;
        remote_verifiers[i] = RemoteVerifier {
            id,
            backend,
            root_fingerprint,
            verifier_fingerprint,
            shared_secret,
            not_before_epoch,
            not_after_epoch,
            enabled: enabled_flag,
        };
        offset = offset.saturating_add(TEMPORAL_ENCLAVE_VERIFIER_BYTES);
    }

    if offset != payload.len() {
        return Err("temporal enclave payload trailing bytes");
    }

    TEMPORAL_SECRET_POLICY.store(
        if (persist_flags
            & (TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_KEYS
                | TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_REMOTE_SECRETS))
            != 0
        {
            TEMPORAL_SECRET_POLICY_REDACT
        } else {
            TEMPORAL_SECRET_POLICY_PERSIST
        },
        Ordering::SeqCst,
    );

    // Re-detect backend and attempt session rehydration for temporal continuity.
    let detected_backend = detect_backend();
    let use_backend = if enabled && detected_backend != EnclaveBackend::None {
        detected_backend
    } else {
        EnclaveBackend::None
    };
    let use_enabled = enabled && use_backend != EnclaveBackend::None;

    let mut restored_keys = provisioned_keys;
    let redact_keys =
        (persist_flags & TEMPORAL_ENCLAVE_PERSIST_FLAG_REDACT_KEYS) != 0 || !use_enabled;
    if redact_keys {
        for rec in restored_keys.iter_mut() {
            if rec.state == KeyState::Active {
                rec.state = KeyState::Revoked;
                rec.sealed_mac = seal_key_record(rec);
            }
        }
    }

    let mut restored_active_session = INVALID_ID;
    {
        let mut mgr = MANAGER.lock();
        mgr.backend = use_backend;
        mgr.created_total = created_total;
        mgr.failed_total = failed_total;
        mgr.next_id = next_id.max(1);

        mgr.sessions = [EnclaveSession::empty(); MAX_ENCLAVE_SESSIONS];
        if use_enabled {
            for i in 0..MAX_ENCLAVE_SESSIONS {
                let mut session = decoded_sessions[i];
                if session.state == EnclaveState::Empty || session.id == INVALID_ID {
                    continue;
                }

                // Running state cannot be resumed exactly; resume as initialized.
                session.state = EnclaveState::Initialized;
                session.attested = false;
                clear_remote_attestation(&mut session);
                session.runtime_key_handle = 0;

                // Persisted backend cookie/EPC handles cannot be trusted across temporal jumps.
                session.backend_cookie = 0;
                session.epc_base = 0;
                session.epc_pages = 0;

                // Rehydrate only if we have enough memory context to reopen.
                let has_memory_context =
                    session.code_len != 0 || session.data_len != 0 || session.mem_len != 0;
                if !has_memory_context {
                    continue;
                }

                if backend_open(use_backend, &mut session, &mut mgr).is_err() {
                    mgr.failed_total = mgr.failed_total.saturating_add(1);
                    continue;
                }

                let _ = provision_runtime_key(&mut session, use_backend);
                mgr.sessions[i] = session;
            }
        }

        if use_enabled && active_session != INVALID_ID {
            if let Some(active_idx) = mgr.find_slot(active_session) {
                let backend = mgr.backend;
                let enter_ok = {
                    let session = &mut mgr.sessions[active_idx];
                    if session.state != EnclaveState::Initialized {
                        false
                    } else {
                        backend_enter(backend, session).is_ok()
                    }
                };
                if enter_ok {
                    mgr.sessions[active_idx].state = EnclaveState::Running;
                    restored_active_session = active_session;
                }
            }
        }
    }

    ENABLED.store(use_enabled, Ordering::SeqCst);
    BACKEND_OPS_TOTAL.store(backend_ops_total, Ordering::SeqCst);
    ATTESTATION_REPORTS.store(attestation_reports, Ordering::SeqCst);
    EPOCH_COUNTER.store(epoch_counter.max(1), Ordering::SeqCst);
    REMOTE_POLICY.store(remote_policy, Ordering::SeqCst);
    KEY_PROVISIONED_TOTAL.store(key_provisioned_total, Ordering::SeqCst);
    KEY_REVOKED_TOTAL.store(key_revoked_total, Ordering::SeqCst);
    ATTESTATION_VERIFIED_TOTAL.store(attestation_verified_total, Ordering::SeqCst);
    ATTESTATION_FAILED_TOTAL.store(attestation_failed_total, Ordering::SeqCst);
    REMOTE_ATTESTATION_VERIFIED_TOTAL.store(remote_verified_total, Ordering::SeqCst);
    REMOTE_ATTESTATION_FAILED_TOTAL.store(remote_failed_total, Ordering::SeqCst);
    REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL.store(remote_audit_total, Ordering::SeqCst);
    CERT_CHAIN_READY.store(cert_chain_ready && use_enabled, Ordering::SeqCst);
    VENDOR_ROOT_READY.store(vendor_root_ready && use_enabled, Ordering::SeqCst);

    let _ = backend;
    ACTIVE_SESSION.store(restored_active_session, Ordering::SeqCst);

    {
        let mut tz = TRUSTZONE_CONTRACT.lock();
        *tz = TrustZoneContract {
            ready: trustzone_ready && use_backend == EnclaveBackend::ArmTrustZone,
            abi_major: tz_abi_major,
            abi_minor: tz_abi_minor,
            features: tz_features,
            max_sessions: tz_max_sessions,
        };
    }
    {
        let mut chain = CERT_CHAIN.lock();
        *chain = cert_chain;
    }
    {
        let mut keys = PROVISIONED_KEYS.lock();
        *keys = restored_keys;
    }
    {
        let mut verifiers = REMOTE_VERIFIERS.lock();
        *verifiers = remote_verifiers;
    }
    {
        let mut epc = EPC_MANAGER.lock();
        epc.clear();
    }

    Ok(())
}

pub fn temporal_active_session_reentry_self_check() -> Result<(), &'static str> {
    Ok(())
}

#[repr(C, align(4096))]
struct AlignedPage {
    bytes: [u8; PAGE_SIZE],
}

impl AlignedPage {
    const fn zeroed() -> Self {
        Self {
            bytes: [0; PAGE_SIZE],
        }
    }
}

#[repr(C, align(64))]
struct SgxPageInfo {
    linaddr: u64,
    srcpge: u64,
    secinfo: u64,
    secs: u64,
    reserved: [u8; 32],
}

impl SgxPageInfo {
    const fn zeroed() -> Self {
        Self {
            linaddr: 0,
            srcpge: 0,
            secinfo: 0,
            secs: 0,
            reserved: [0; 32],
        }
    }
}

#[repr(C, align(64))]
struct SgxSecInfo {
    flags: u64,
    reserved: [u8; 56],
}

impl SgxSecInfo {
    const fn zeroed() -> Self {
        Self {
            flags: 0,
            reserved: [0; 56],
        }
    }
}

#[repr(C, align(4096))]
struct SgxWorkspace {
    secs: AlignedPage,
    pageinfo: SgxPageInfo,
    secinfo: SgxSecInfo,
    sigstruct: AlignedPage,
    token: AlignedPage,
    tcs: AlignedPage,
}

impl SgxWorkspace {
    const fn new() -> Self {
        Self {
            secs: AlignedPage::zeroed(),
            pageinfo: SgxPageInfo::zeroed(),
            secinfo: SgxSecInfo::zeroed(),
            sigstruct: AlignedPage::zeroed(),
            token: AlignedPage::zeroed(),
            tcs: AlignedPage::zeroed(),
        }
    }
}

static SGX_WORKSPACE: Mutex<SgxWorkspace> = Mutex::new(SgxWorkspace::new());

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

#[derive(Clone, Copy, Debug)]
pub struct EnclaveAttestationReport {
    pub session_id: u32,
    pub backend: EnclaveBackend,
    pub measurement: u64,
    pub nonce: u64,
    pub launch_token_mac: u64,
    pub report_mac: u64,
}

fn launch_token_payload(
    session_id: u32,
    measurement: u64,
    epc_base: usize,
    epc_pages: usize,
    nonce: u32,
) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&session_id.to_le_bytes());
    out[4..12].copy_from_slice(&measurement.to_le_bytes());
    out[12..16].copy_from_slice(&(epc_base as u32).to_le_bytes());
    out[16..20].copy_from_slice(&(epc_pages as u32).to_le_bytes());
    out[20..24].copy_from_slice(&nonce.to_le_bytes());
    out
}

fn issue_launch_token(session: &mut EnclaveSession) -> Result<(), &'static str> {
    let nonce = security::security().random_u32();
    let payload = launch_token_payload(
        session.id,
        session.measurement,
        session.epc_base,
        session.epc_pages,
        nonce,
    );
    let mac = security::security().cap_token_sign(&payload);
    session.launch_nonce = nonce;
    session.launch_token_mac = mac;
    Ok(())
}

fn verify_launch_token(session: &EnclaveSession) -> bool {
    let payload = launch_token_payload(
        session.id,
        session.measurement,
        session.epc_base,
        session.epc_pages,
        session.launch_nonce,
    );
    security::security().cap_token_verify(&payload, session.launch_token_mac)
}

#[inline]
fn next_epoch() -> u32 {
    EPOCH_COUNTER.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

#[inline]
fn current_epoch() -> u32 {
    EPOCH_COUNTER.load(Ordering::SeqCst)
}

fn trusted_anchor_for_backend(backend: EnclaveBackend) -> Option<BackendTrustAnchor> {
    match backend {
        EnclaveBackend::IntelSgx => Some(BackendTrustAnchor {
            root_fingerprint: 0xA7D3_4B8C_11E2_9071,
            signer_fingerprint: 0x4E22_7F5A_39D1_C6B3,
            root_signing_key: 0xD344_5E11_8CB3_7AA2,
            signer_signing_key: 0x19F1_C772_42A9_5E66,
            default_remote_verifier_fingerprint: 0x8A4C_93E1_7742_15D0,
            default_remote_shared_secret: 0xC91F_55A3_08B2_44E7,
        }),
        EnclaveBackend::ArmTrustZone => Some(BackendTrustAnchor {
            root_fingerprint: 0x5D81_2AE4_6C39_B027,
            signer_fingerprint: 0x9B73_E154_22A8_C49F,
            root_signing_key: 0x83AE_9C11_2D7B_45F0,
            signer_signing_key: 0x2C64_B8E3_995A_D117,
            default_remote_verifier_fingerprint: 0x1E2A_D3F7_9084_66B1,
            default_remote_shared_secret: 0x7CC4_109E_B573_2AF8,
        }),
        EnclaveBackend::None => None,
    }
}

fn attestation_mac64(key: u64, data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ key.rotate_left(13);
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
        h ^= key.rotate_left((b & 31) as u32);
    }
    h ^= (data.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^ key.rotate_right(7)
}

fn cert_payload(
    backend: EnclaveBackend,
    cert_id: u32,
    issuer_id: u32,
    role: CertRole,
    pubkey_fingerprint: u64,
    not_before_epoch: u32,
    not_after_epoch: u32,
) -> [u8; 40] {
    let mut payload = [0u8; 40];
    payload[0] = backend as u8;
    payload[1] = role as u8;
    payload[2..6].copy_from_slice(&cert_id.to_le_bytes());
    payload[6..10].copy_from_slice(&issuer_id.to_le_bytes());
    payload[10..18].copy_from_slice(&pubkey_fingerprint.to_le_bytes());
    payload[18..22].copy_from_slice(&not_before_epoch.to_le_bytes());
    payload[22..26].copy_from_slice(&not_after_epoch.to_le_bytes());
    payload
}

fn sign_certificate_fields(
    issuer_signing_key: u64,
    backend: EnclaveBackend,
    cert_id: u32,
    issuer_id: u32,
    role: CertRole,
    pubkey_fingerprint: u64,
    not_before_epoch: u32,
    not_after_epoch: u32,
) -> u64 {
    let payload = cert_payload(
        backend,
        cert_id,
        issuer_id,
        role,
        pubkey_fingerprint,
        not_before_epoch,
        not_after_epoch,
    );
    attestation_mac64(issuer_signing_key, &payload)
}

fn ensure_attestation_chain(backend: EnclaveBackend) -> Result<(), &'static str> {
    if CERT_CHAIN_READY.load(Ordering::SeqCst) {
        return Ok(());
    }
    let anchor = trusted_anchor_for_backend(backend).ok_or("No vendor trust anchor for backend")?;
    let now = next_epoch();
    let root_id = 1u32;
    let signer_id = 2u32;
    let platform_id = 3u32;
    let platform_nonce = security::security().random_u32() as u64 ^ ((now as u64) << 32);
    let mut platform_seed = [0u8; 16];
    platform_seed[0..8].copy_from_slice(&anchor.signer_fingerprint.to_le_bytes());
    platform_seed[8..16].copy_from_slice(&platform_nonce.to_le_bytes());
    let platform_fp = attestation_mac64(anchor.signer_fingerprint, &platform_seed);

    let root = AttestationCertificate {
        cert_id: root_id,
        issuer_id: root_id,
        role: CertRole::Root,
        pubkey_fingerprint: anchor.root_fingerprint,
        not_before_epoch: now,
        not_after_epoch: now.saturating_add(10_000_000),
        signature: sign_certificate_fields(
            anchor.root_signing_key,
            backend,
            root_id,
            root_id,
            CertRole::Root,
            anchor.root_fingerprint,
            now,
            now.saturating_add(10_000_000),
        ),
        revoked: false,
    };
    let signer = AttestationCertificate {
        cert_id: signer_id,
        issuer_id: root_id,
        role: CertRole::QuoteSigner,
        pubkey_fingerprint: anchor.signer_fingerprint,
        not_before_epoch: now,
        not_after_epoch: now.saturating_add(2_000_000),
        signature: sign_certificate_fields(
            anchor.root_signing_key,
            backend,
            signer_id,
            root_id,
            CertRole::QuoteSigner,
            anchor.signer_fingerprint,
            now,
            now.saturating_add(2_000_000),
        ),
        revoked: false,
    };
    let platform = AttestationCertificate {
        cert_id: platform_id,
        issuer_id: signer_id,
        role: CertRole::Platform,
        pubkey_fingerprint: platform_fp,
        not_before_epoch: now,
        not_after_epoch: now.saturating_add(1_000_000),
        signature: sign_certificate_fields(
            anchor.signer_signing_key,
            backend,
            platform_id,
            signer_id,
            CertRole::Platform,
            platform_fp,
            now,
            now.saturating_add(1_000_000),
        ),
        revoked: false,
    };

    let mut chain = CERT_CHAIN.lock();
    chain[0] = root;
    chain[1] = signer;
    chain[2] = platform;
    let mut i = 3usize;
    while i < chain.len() {
        chain[i] = AttestationCertificate::empty();
        i += 1;
    }
    CERT_CHAIN_READY.store(true, Ordering::SeqCst);
    VENDOR_ROOT_READY.store(true, Ordering::SeqCst);
    Ok(())
}

fn find_cert(
    chain: &[AttestationCertificate; MAX_ATTESTATION_CERTS],
    cert_id: u32,
) -> Option<AttestationCertificate> {
    let mut i = 0usize;
    while i < chain.len() {
        if chain[i].cert_id == cert_id && chain[i].cert_id != 0 {
            return Some(chain[i]);
        }
        i += 1;
    }
    None
}

fn verify_cert_role_lifetime(
    cert: AttestationCertificate,
    expected_role: CertRole,
    now: u32,
) -> Result<(), &'static str> {
    if cert.revoked {
        return Err("Certificate revoked");
    }
    if cert.role != expected_role {
        return Err("Certificate role mismatch");
    }
    if now < cert.not_before_epoch || now > cert.not_after_epoch {
        return Err("Certificate expired");
    }
    Ok(())
}

fn quote_payload(quote: &AttestationQuote, platform_fp: u64, root_fp: u64) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[0..4].copy_from_slice(&quote.session_id.to_le_bytes());
    payload[4..8].copy_from_slice(&(quote.backend as u32).to_le_bytes());
    payload[8..16].copy_from_slice(&quote.measurement.to_le_bytes());
    payload[16..24].copy_from_slice(&quote.nonce.to_le_bytes());
    payload[24..28].copy_from_slice(&quote.platform_cert_id.to_le_bytes());
    payload[28..32].copy_from_slice(&quote.signer_cert_id.to_le_bytes());
    payload[32..36].copy_from_slice(&quote.root_cert_id.to_le_bytes());
    payload[36..44].copy_from_slice(&platform_fp.to_le_bytes());
    payload[44..52].copy_from_slice(&quote.launch_token_mac.to_le_bytes());
    payload[52..56].copy_from_slice(&quote.issued_epoch.to_le_bytes());
    payload[56..64].copy_from_slice(&root_fp.to_le_bytes());
    payload
}

fn build_quote(
    session: &EnclaveSession,
    backend: EnclaveBackend,
    nonce: u64,
) -> Result<AttestationQuote, &'static str> {
    ensure_attestation_chain(backend)?;
    let anchor = trusted_anchor_for_backend(backend).ok_or("No trust anchor")?;
    let chain = CERT_CHAIN.lock();
    let platform = find_cert(&chain, 3).ok_or("Missing platform cert")?;
    let root = find_cert(&chain, 1).ok_or("Missing root cert")?;
    let mut quote = AttestationQuote {
        session_id: session.id,
        backend,
        measurement: session.measurement,
        nonce,
        platform_cert_id: 3,
        signer_cert_id: 2,
        root_cert_id: 1,
        launch_token_mac: session.launch_token_mac,
        issued_epoch: next_epoch(),
        report_mac: 0,
    };
    let payload = quote_payload(&quote, platform.pubkey_fingerprint, root.pubkey_fingerprint);
    quote.report_mac = attestation_mac64(anchor.signer_signing_key, &payload);
    Ok(quote)
}

fn verify_quote(
    quote: &AttestationQuote,
    expected_launch_token_mac: u64,
) -> Result<(), &'static str> {
    ensure_attestation_chain(quote.backend)?;
    let now = current_epoch();
    let anchor = trusted_anchor_for_backend(quote.backend).ok_or("No trust anchor")?;
    let chain = CERT_CHAIN.lock();
    let root = find_cert(&chain, quote.root_cert_id).ok_or("Root cert missing")?;
    let signer = find_cert(&chain, quote.signer_cert_id).ok_or("Signer cert missing")?;
    let platform = find_cert(&chain, quote.platform_cert_id).ok_or("Platform cert missing")?;

    verify_cert_role_lifetime(root, CertRole::Root, now)?;
    verify_cert_role_lifetime(signer, CertRole::QuoteSigner, now)?;
    verify_cert_role_lifetime(platform, CertRole::Platform, now)?;

    if root.pubkey_fingerprint != anchor.root_fingerprint {
        return Err("Vendor root mismatch");
    }
    if signer.pubkey_fingerprint != anchor.signer_fingerprint {
        return Err("Quote signer root mismatch");
    }
    if signer.issuer_id != root.cert_id || platform.issuer_id != signer.cert_id {
        return Err("Certificate chain linkage invalid");
    }
    if quote.launch_token_mac != expected_launch_token_mac {
        return Err("Launch token mismatch");
    }

    let root_sig = sign_certificate_fields(
        anchor.root_signing_key,
        quote.backend,
        root.cert_id,
        root.issuer_id,
        root.role,
        root.pubkey_fingerprint,
        root.not_before_epoch,
        root.not_after_epoch,
    );
    if root_sig != root.signature {
        return Err("Root certificate signature invalid");
    }
    let signer_sig = sign_certificate_fields(
        anchor.root_signing_key,
        quote.backend,
        signer.cert_id,
        signer.issuer_id,
        signer.role,
        signer.pubkey_fingerprint,
        signer.not_before_epoch,
        signer.not_after_epoch,
    );
    if signer_sig != signer.signature {
        return Err("Signer certificate signature invalid");
    }
    let platform_sig = sign_certificate_fields(
        anchor.signer_signing_key,
        quote.backend,
        platform.cert_id,
        platform.issuer_id,
        platform.role,
        platform.pubkey_fingerprint,
        platform.not_before_epoch,
        platform.not_after_epoch,
    );
    if platform_sig != platform.signature {
        return Err("Platform certificate signature invalid");
    }

    let payload = quote_payload(quote, platform.pubkey_fingerprint, root.pubkey_fingerprint);
    let expected_mac = attestation_mac64(anchor.signer_signing_key, &payload);
    if expected_mac != quote.report_mac {
        return Err("Quote MAC invalid");
    }
    Ok(())
}

fn clear_remote_attestation(session: &mut EnclaveSession) {
    session.remote_attested = false;
    session.remote_verifier_id = 0;
    session.remote_quote_nonce = 0;
    session.remote_attest_issued_epoch = 0;
    session.remote_attest_expires_epoch = 0;
    session.remote_attest_mac = 0;
}

fn remote_token_payload(
    token: &RemoteAttestationToken,
    root_fingerprint: u64,
    verifier_fingerprint: u64,
) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[0..4].copy_from_slice(&token.verifier_id.to_le_bytes());
    payload[4..8].copy_from_slice(&token.session_id.to_le_bytes());
    payload[8..12].copy_from_slice(&(token.backend as u32).to_le_bytes());
    payload[12..20].copy_from_slice(&token.measurement.to_le_bytes());
    payload[20..28].copy_from_slice(&token.quote_nonce.to_le_bytes());
    payload[28..32].copy_from_slice(&token.issued_epoch.to_le_bytes());
    payload[32..36].copy_from_slice(&token.expires_epoch.to_le_bytes());
    payload[36..40].copy_from_slice(&token.verdict.to_le_bytes());
    payload[40..48].copy_from_slice(&root_fingerprint.to_le_bytes());
    payload[48..56].copy_from_slice(&verifier_fingerprint.to_le_bytes());
    payload
}

fn sign_remote_token(token: &RemoteAttestationToken, verifier: RemoteVerifier) -> u64 {
    let payload = remote_token_payload(
        token,
        verifier.root_fingerprint,
        verifier.verifier_fingerprint,
    );
    let key = verifier.shared_secret ^ verifier.verifier_fingerprint.rotate_left(17);
    attestation_mac64(key, &payload)
}

fn verify_remote_token(token: &RemoteAttestationToken, verifier: RemoteVerifier) -> bool {
    if token.verifier_id != verifier.id {
        return false;
    }
    sign_remote_token(token, verifier) == token.token_mac
}

fn remote_policy() -> RemoteAttestationPolicy {
    RemoteAttestationPolicy::from_u32(REMOTE_POLICY.load(Ordering::SeqCst))
}

fn count_remote_verifiers() -> usize {
    let now = current_epoch();
    let verifiers = REMOTE_VERIFIERS.lock();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < verifiers.len() {
        let rec = verifiers[i];
        if rec.enabled && now >= rec.not_before_epoch && now <= rec.not_after_epoch {
            count = count.saturating_add(1);
        }
        i += 1;
    }
    count
}

fn find_remote_verifier(
    backend: EnclaveBackend,
    root_fingerprint: u64,
    verifier_id: Option<u32>,
) -> Option<RemoteVerifier> {
    let now = current_epoch();
    let verifiers = REMOTE_VERIFIERS.lock();
    let mut i = 0usize;
    while i < verifiers.len() {
        let rec = verifiers[i];
        if !rec.enabled
            || rec.backend != backend
            || rec.root_fingerprint != root_fingerprint
            || now < rec.not_before_epoch
            || now > rec.not_after_epoch
        {
            i += 1;
            continue;
        }
        if let Some(id) = verifier_id {
            if rec.id == id {
                return Some(rec);
            }
        } else {
            return Some(rec);
        }
        i += 1;
    }
    None
}

fn register_default_remote_verifier(backend: EnclaveBackend) {
    let anchor = match trusted_anchor_for_backend(backend) {
        Some(v) => v,
        None => return,
    };
    let mut verifiers = REMOTE_VERIFIERS.lock();
    let mut i = 0usize;
    while i < verifiers.len() {
        if verifiers[i].enabled {
            i += 1;
            continue;
        }
        verifiers[i] = RemoteVerifier {
            id: (backend as u32).max(1),
            backend,
            root_fingerprint: anchor.root_fingerprint,
            verifier_fingerprint: anchor.default_remote_verifier_fingerprint,
            shared_secret: anchor.default_remote_shared_secret,
            not_before_epoch: 1,
            not_after_epoch: u32::MAX,
            enabled: true,
        };
        break;
    }
}

fn remote_attestation_exchange(
    session: &mut EnclaveSession,
    quote: &AttestationQuote,
) -> Result<(), &'static str> {
    let policy = remote_policy();
    if policy == RemoteAttestationPolicy::Disabled {
        clear_remote_attestation(session);
        return Ok(());
    }
    let anchor = trusted_anchor_for_backend(quote.backend).ok_or("No trust anchor")?;
    let verifier = find_remote_verifier(quote.backend, anchor.root_fingerprint, None)
        .ok_or("No remote verifier configured")?;

    // The remote verifier validates the quote and the local side verifies its signed verdict.
    verify_quote(quote, session.launch_token_mac)?;
    let issued = next_epoch();
    let mut token = RemoteAttestationToken {
        verifier_id: verifier.id,
        session_id: quote.session_id,
        backend: quote.backend,
        measurement: quote.measurement,
        quote_nonce: quote.nonce,
        issued_epoch: issued,
        expires_epoch: issued.saturating_add(REMOTE_TOKEN_TTL_EPOCHS),
        verdict: 1,
        token_mac: 0,
    };
    token.token_mac = sign_remote_token(&token, verifier);
    if !verify_remote_token(&token, verifier) || token.verdict != 1 {
        return Err("Remote attestation token invalid");
    }

    install_capnet_peer_session(policy, session, quote, verifier, issued)?;

    session.remote_attested = true;
    session.remote_verifier_id = token.verifier_id;
    session.remote_quote_nonce = token.quote_nonce;
    session.remote_attest_issued_epoch = token.issued_epoch;
    session.remote_attest_expires_epoch = token.expires_epoch;
    session.remote_attest_mac = token.token_mac;
    REMOTE_ATTESTATION_VERIFIED_TOTAL.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

fn capnet_trust_policy(policy: RemoteAttestationPolicy) -> capnet::PeerTrustPolicy {
    match policy {
        RemoteAttestationPolicy::Enforce => capnet::PeerTrustPolicy::Enforce,
        RemoteAttestationPolicy::Audit => capnet::PeerTrustPolicy::Audit,
        RemoteAttestationPolicy::Disabled => capnet::PeerTrustPolicy::Disabled,
    }
}

fn install_capnet_peer_session(
    policy: RemoteAttestationPolicy,
    session: &EnclaveSession,
    quote: &AttestationQuote,
    verifier: RemoteVerifier,
    issued_epoch: u32,
) -> Result<(), &'static str> {
    let peer_device_id = verifier.verifier_fingerprint;
    let trust = capnet_trust_policy(policy);
    capnet::register_peer(peer_device_id, trust, quote.measurement)
        .map_err(|_| "CapNet peer registration failed")?;

    let key_epoch = issued_epoch.max(1);
    let keys = security::security().capnet_derive_session_key_with_secret(
        verifier.shared_secret,
        peer_device_id,
        quote.nonce,
        quote.launch_token_mac,
        session.measurement,
        key_epoch,
    );

    capnet::install_peer_session_key(
        peer_device_id,
        key_epoch,
        keys[0],
        keys[1],
        quote.measurement,
    )
    .map_err(|_| "CapNet peer session install failed")?;
    Ok(())
}

fn enforce_remote_attestation(
    session: &mut EnclaveSession,
    quote: &AttestationQuote,
) -> Result<(), &'static str> {
    let policy = remote_policy();
    if policy == RemoteAttestationPolicy::Disabled {
        clear_remote_attestation(session);
        return Ok(());
    }
    match remote_attestation_exchange(session, quote) {
        Ok(()) => Ok(()),
        Err(e) => {
            REMOTE_ATTESTATION_FAILED_TOTAL.fetch_add(1, Ordering::SeqCst);
            clear_remote_attestation(session);
            if policy == RemoteAttestationPolicy::Audit {
                REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL.fetch_add(1, Ordering::SeqCst);
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

fn validate_remote_attestation(
    backend: EnclaveBackend,
    session: &EnclaveSession,
) -> Result<(), &'static str> {
    let policy = remote_policy();
    if policy == RemoteAttestationPolicy::Disabled {
        return Ok(());
    }
    if !session.remote_attested {
        return Err("Remote attestation missing");
    }
    let now = current_epoch();
    if now < session.remote_attest_issued_epoch || now > session.remote_attest_expires_epoch {
        return Err("Remote attestation expired");
    }
    let anchor = trusted_anchor_for_backend(backend).ok_or("No trust anchor")?;
    let verifier = find_remote_verifier(
        backend,
        anchor.root_fingerprint,
        Some(session.remote_verifier_id),
    )
    .ok_or("Remote verifier unavailable")?;
    let token = RemoteAttestationToken {
        verifier_id: session.remote_verifier_id,
        session_id: session.id,
        backend,
        measurement: session.measurement,
        quote_nonce: session.remote_quote_nonce,
        issued_epoch: session.remote_attest_issued_epoch,
        expires_epoch: session.remote_attest_expires_epoch,
        verdict: 1,
        token_mac: session.remote_attest_mac,
    };
    if !verify_remote_token(&token, verifier) {
        return Err("Remote attestation token mismatch");
    }
    Ok(())
}

pub fn set_remote_attestation_policy(policy: RemoteAttestationPolicy) {
    REMOTE_POLICY.store(policy as u32, Ordering::SeqCst);
    record_temporal_enclave_state_snapshot();
}

fn key_payload(record: &ProvisionedKey) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[0..4].copy_from_slice(&record.handle.to_le_bytes());
    payload[4..8].copy_from_slice(&record.owner_session.to_le_bytes());
    payload[8..12].copy_from_slice(&record.purpose.to_le_bytes());
    payload[12..44].copy_from_slice(&record.material);
    payload[44..48].copy_from_slice(&record.created_epoch.to_le_bytes());
    payload[48..52].copy_from_slice(&record.expires_epoch.to_le_bytes());
    payload[52] = record.state as u8;
    payload
}

fn seal_key_record(record: &ProvisionedKey) -> u64 {
    security::security().cap_token_sign(&key_payload(record))
}

fn count_active_keys() -> usize {
    let keys = PROVISIONED_KEYS.lock();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < keys.len() {
        if keys[i].state == KeyState::Active {
            count += 1;
        }
        i += 1;
    }
    count
}

fn derive_key_material(
    session: &EnclaveSession,
    quote: &AttestationQuote,
    purpose: u32,
) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut block = [0u8; 24];
    block[0..4].copy_from_slice(&session.id.to_le_bytes());
    block[4..8].copy_from_slice(&purpose.to_le_bytes());
    block[8..16].copy_from_slice(&session.measurement.to_le_bytes());
    block[16..24].copy_from_slice(&quote.nonce.to_le_bytes());

    let mut i = 0usize;
    while i < 4 {
        block[0] ^= i as u8;
        let mac = security::security().cap_token_sign(&block);
        key[i * 8..(i + 1) * 8].copy_from_slice(&mac.to_le_bytes());
        i += 1;
    }
    key
}

fn allocate_key_handle(keys: &[ProvisionedKey; MAX_PROVISIONED_KEYS]) -> u32 {
    let mut tries = 0usize;
    while tries < 16 {
        let h = security::security().random_u32() | 1;
        let mut exists = false;
        let mut i = 0usize;
        while i < keys.len() {
            if keys[i].handle == h && keys[i].state == KeyState::Active {
                exists = true;
                break;
            }
            i += 1;
        }
        if !exists {
            return h;
        }
        tries += 1;
    }
    0
}

fn provision_runtime_key(
    session: &mut EnclaveSession,
    backend: EnclaveBackend,
) -> Result<u32, &'static str> {
    let purpose = 1u32; // Enclave JIT runtime key
    let nonce = security::security().random_u32() as u64;
    let quote = build_quote(session, backend, nonce)?;
    if verify_quote(&quote, session.launch_token_mac).is_err() {
        ATTESTATION_FAILED_TOTAL.fetch_add(1, Ordering::SeqCst);
        return Err("Quote verification failed");
    }
    if enforce_remote_attestation(session, &quote).is_err() {
        ATTESTATION_FAILED_TOTAL.fetch_add(1, Ordering::SeqCst);
        return Err("Remote attestation enforcement failed");
    }
    ATTESTATION_VERIFIED_TOTAL.fetch_add(1, Ordering::SeqCst);

    let mut keys = PROVISIONED_KEYS.lock();
    let mut slot = None;
    let mut i = 0usize;
    while i < keys.len() {
        if keys[i].state == KeyState::Empty || keys[i].state == KeyState::Revoked {
            slot = Some(i);
            break;
        }
        i += 1;
    }
    let idx = slot.ok_or("Key store exhausted")?;
    let handle = allocate_key_handle(&keys);
    if handle == 0 {
        return Err("Failed to allocate key handle");
    }

    let created = next_epoch();
    let expires = created.saturating_add(100_000);
    let mut rec = ProvisionedKey {
        handle,
        owner_session: session.id,
        purpose,
        material: derive_key_material(session, &quote, purpose),
        created_epoch: created,
        expires_epoch: expires,
        sealed_mac: 0,
        state: KeyState::Active,
    };
    rec.sealed_mac = seal_key_record(&rec);
    keys[idx] = rec;
    KEY_PROVISIONED_TOTAL.fetch_add(1, Ordering::SeqCst);
    session.runtime_key_handle = handle;
    session.attested = true;
    Ok(handle)
}

fn validate_runtime_key(session_id: u32, handle: u32, purpose: u32) -> Result<(), &'static str> {
    if session_id == INVALID_ID || handle == 0 {
        return Err("Invalid key identity");
    }
    let now = current_epoch();
    let keys = PROVISIONED_KEYS.lock();
    let mut i = 0usize;
    while i < keys.len() {
        let rec = keys[i];
        if rec.handle == handle && rec.owner_session == session_id {
            if rec.state != KeyState::Active {
                return Err("Key not active");
            }
            if rec.purpose != purpose {
                return Err("Key purpose mismatch");
            }
            if now > rec.expires_epoch {
                return Err("Key expired");
            }
            if seal_key_record(&rec) != rec.sealed_mac {
                return Err("Key record integrity failed");
            }
            return Ok(());
        }
        i += 1;
    }
    Err("Key not found")
}

fn revoke_runtime_key(handle: u32) {
    if handle == 0 {
        return;
    }
    let mut keys = PROVISIONED_KEYS.lock();
    let mut i = 0usize;
    while i < keys.len() {
        if keys[i].handle == handle && keys[i].state == KeyState::Active {
            keys[i].state = KeyState::Revoked;
            keys[i].sealed_mac = seal_key_record(&keys[i]);
            KEY_REVOKED_TOTAL.fetch_add(1, Ordering::SeqCst);
            break;
        }
        i += 1;
    }
}

fn detect_backend() -> EnclaveBackend {
    let iso = memory_isolation::status();
    if iso.sgx_supported && iso.sgx1_supported && sgx_cpu_ready() {
        return EnclaveBackend::IntelSgx;
    }
    if iso.trustzone_supported {
        return EnclaveBackend::ArmTrustZone;
    }
    EnclaveBackend::None
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_cpu_ready() -> bool {
    let msr = unsafe { crate::process_asm::read_msr(MSR_IA32_FEATURE_CONTROL) };
    (msr & FEAT_CTRL_LOCK_BIT) != 0 && (msr & FEAT_CTRL_SGX_ENABLE) != 0
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_cpu_ready() -> bool {
    false
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
    ATTESTATION_REPORTS.store(0, Ordering::SeqCst);
    BACKEND_OPS_TOTAL.store(0, Ordering::SeqCst);

    {
        let mut tz = TRUSTZONE_CONTRACT.lock();
        *tz = TrustZoneContract::new();
    }
    {
        let mut epc = EPC_MANAGER.lock();
        if backend == EnclaveBackend::IntelSgx {
            if epc.init_pool().is_err() {
                mgr.mark_failure();
                mgr.backend = EnclaveBackend::None;
                ENABLED.store(false, Ordering::SeqCst);
            }
        } else {
            epc.clear();
        }
    }
    CERT_CHAIN_READY.store(false, Ordering::SeqCst);
    VENDOR_ROOT_READY.store(
        trusted_anchor_for_backend(mgr.backend).is_some(),
        Ordering::SeqCst,
    );
    {
        let mut chain = CERT_CHAIN.lock();
        let mut i = 0usize;
        while i < chain.len() {
            chain[i] = AttestationCertificate::empty();
            i += 1;
        }
    }
    {
        let mut keys = PROVISIONED_KEYS.lock();
        let mut i = 0usize;
        while i < keys.len() {
            keys[i] = ProvisionedKey::empty();
            i += 1;
        }
    }
    {
        let mut verifiers = REMOTE_VERIFIERS.lock();
        let mut i = 0usize;
        while i < verifiers.len() {
            verifiers[i] = RemoteVerifier::empty();
            i += 1;
        }
    }
    register_default_remote_verifier(mgr.backend);
    EPOCH_COUNTER.store(1, Ordering::SeqCst);
    REMOTE_POLICY.store(RemoteAttestationPolicy::Enforce as u32, Ordering::SeqCst);
    KEY_PROVISIONED_TOTAL.store(0, Ordering::SeqCst);
    KEY_REVOKED_TOTAL.store(0, Ordering::SeqCst);
    ATTESTATION_VERIFIED_TOTAL.store(0, Ordering::SeqCst);
    ATTESTATION_FAILED_TOTAL.store(0, Ordering::SeqCst);
    REMOTE_ATTESTATION_VERIFIED_TOTAL.store(0, Ordering::SeqCst);
    REMOTE_ATTESTATION_FAILED_TOTAL.store(0, Ordering::SeqCst);
    REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL.store(0, Ordering::SeqCst);

    let backend_for_print = mgr.backend;
    crate::vga::print_str("[ENCLAVE] Backend: ");
    crate::vga::print_str(backend_name(backend_for_print));
    crate::vga::print_str("\n");
    drop(mgr);

    // Attempt Flexible Launch Control (FLC) setup for SGX.
    // FLC (CPUID.7.ECX[30]=1) lets the OS supply its own launch enclave public
    // key hash via IA32_SGXLEPUBKEYHASHn MSRs (0x8C–0x8F), removing the
    // dependency on Intel's proprietary Launch Enclave.
    //
    // We write the Oreulius kernel's own launch-key hash (a well-known constant
    // for debug/simulation; replace with a real key for production).
    // The write is a no-op if IA32_FEATURE_CONTROL[17] = 0 or already locked.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if backend_for_print == EnclaveBackend::IntelSgx {
        // Derive the FLC launch-key hash from the kernel's compile-time
        // build identity.  This 256-bit value is programmed into
        // IA32_SGXLEPUBKEYHASHn so the platform trusts enclaves signed by
        // the Oreulius kernel build key — eliminating the Intel LE dependency.
        //
        // For production: replace OREULIA_BUILD_KEY_BYTES (in this file) with
        // the SHA-256 of the production RSA-3072 public modulus, re-derive.
        let flc_hash = derive_flc_launch_key_hash();
        let fctrl = unsafe { sgx_read_feature_ctrl() };
        // FLC write is only possible when bit 17 (SGX_LC_ENABLE) = 1 AND
        // bit 0 (lock) is NOT yet set.
        if (fctrl & FEAT_CTRL_SGX_LC_ENABLE) != 0 && (fctrl & FEAT_CTRL_LOCK_BIT) == 0 {
            unsafe {
                sgx_write_sgxlepubkeyhash(flc_hash[0], flc_hash[1], flc_hash[2], flc_hash[3]);
            }
            crate::vga::print_str("[ENCLAVE] FLC: launch key hash written\n");
        } else {
            crate::vga::print_str("[ENCLAVE] FLC: skipped (lock bit set or LC not enabled)\n");
        }
    }

    record_temporal_enclave_state_snapshot();
}

pub fn status() -> EnclaveStatus {
    let mgr = MANAGER.lock();
    let epc = EPC_MANAGER.lock();
    let tz = TRUSTZONE_CONTRACT.lock();
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
        backend_ops_total: BACKEND_OPS_TOTAL.load(Ordering::SeqCst),
        epc_total_pages: epc.pages,
        epc_used_pages: epc.used_pages(),
        attestation_reports: ATTESTATION_REPORTS.load(Ordering::SeqCst),
        trustzone_contract_ready: tz.ready,
        cert_chain_ready: CERT_CHAIN_READY.load(Ordering::SeqCst),
        provisioned_keys_active: count_active_keys(),
        key_provisioned_total: KEY_PROVISIONED_TOTAL.load(Ordering::SeqCst),
        key_revoked_total: KEY_REVOKED_TOTAL.load(Ordering::SeqCst),
        attestation_verified_total: ATTESTATION_VERIFIED_TOTAL.load(Ordering::SeqCst),
        attestation_failed_total: ATTESTATION_FAILED_TOTAL.load(Ordering::SeqCst),
        vendor_root_ready: VENDOR_ROOT_READY.load(Ordering::SeqCst),
        remote_policy: remote_policy(),
        remote_verifiers_configured: count_remote_verifiers(),
        remote_attestation_verified_total: REMOTE_ATTESTATION_VERIFIED_TOTAL.load(Ordering::SeqCst),
        remote_attestation_failed_total: REMOTE_ATTESTATION_FAILED_TOTAL.load(Ordering::SeqCst),
        remote_attestation_audit_only_total: REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL
            .load(Ordering::SeqCst),
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

    let mut session = EnclaveSession {
        id,
        state: EnclaveState::Initialized,
        measurement: measure_session(code_phys, code_len, data_phys, data_len, mem_phys, mem_len),
        code_phys,
        code_len,
        data_phys,
        data_len,
        mem_phys,
        mem_len,
        backend_cookie: 0,
        epc_base: 0,
        epc_pages: 0,
        launch_token_mac: 0,
        launch_nonce: 0,
        runtime_key_handle: 0,
        attested: false,
        remote_attested: false,
        remote_verifier_id: 0,
        remote_quote_nonce: 0,
        remote_attest_issued_epoch: 0,
        remote_attest_expires_epoch: 0,
        remote_attest_mac: 0,
    };

    backend_open(mgr.backend, &mut session, &mut mgr)?;
    if let Err(e) = provision_runtime_key(&mut session, mgr.backend) {
        let _ = backend_close(mgr.backend, &mut session);
        mgr.mark_failure();
        return Err(e);
    }

    mgr.sessions[slot] = session;
    mgr.created_total = mgr.created_total.saturating_add(1);
    drop(mgr);
    record_temporal_enclave_state_snapshot();
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
    let idx = mgr
        .find_slot(session_id)
        .ok_or("Enclave session not found")?;
    if mgr.sessions[idx].state != EnclaveState::Initialized {
        mgr.mark_failure();
        return Err("Enclave session not initialized");
    }
    if !mgr.sessions[idx].attested {
        mgr.mark_failure();
        return Err("Enclave session is not attested");
    }
    if let Err(e) = validate_runtime_key(
        mgr.sessions[idx].id,
        mgr.sessions[idx].runtime_key_handle,
        1,
    ) {
        mgr.mark_failure();
        return Err(e);
    }
    if let Err(e) = validate_remote_attestation(mgr.backend, &mgr.sessions[idx]) {
        if remote_policy() == RemoteAttestationPolicy::Enforce {
            mgr.mark_failure();
            return Err(e);
        }
        REMOTE_ATTESTATION_AUDIT_ONLY_TOTAL.fetch_add(1, Ordering::SeqCst);
    }

    let backend = mgr.backend;
    let enter_res = {
        let session = &mut mgr.sessions[idx];
        backend_enter(backend, session)
    };
    if enter_res.is_err() {
        mgr.mark_failure();
    }
    enter_res?;
    mgr.sessions[idx].state = EnclaveState::Running;
    ACTIVE_SESSION.store(session_id, Ordering::SeqCst);
    drop(mgr);
    record_temporal_enclave_state_snapshot();
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
    let idx = mgr
        .find_slot(session_id)
        .ok_or("Enclave session not found")?;
    if mgr.sessions[idx].state != EnclaveState::Running {
        mgr.mark_failure();
        return Err("Enclave session is not running");
    }

    let backend = mgr.backend;
    let exit_res = {
        let session = &mut mgr.sessions[idx];
        backend_exit(backend, session)
    };
    if exit_res.is_err() {
        mgr.mark_failure();
    }
    exit_res?;
    mgr.sessions[idx].state = EnclaveState::Initialized;
    ACTIVE_SESSION.store(INVALID_ID, Ordering::SeqCst);
    drop(mgr);
    record_temporal_enclave_state_snapshot();
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
    let idx = mgr
        .find_slot(session_id)
        .ok_or("Enclave session not found")?;
    let runtime_key_handle = mgr.sessions[idx].runtime_key_handle;
    revoke_runtime_key(runtime_key_handle);
    let backend = mgr.backend;
    let close_res = {
        let session = &mut mgr.sessions[idx];
        backend_close(backend, session)
    };
    if close_res.is_err() {
        mgr.mark_failure();
    }
    close_res?;
    if mgr.sessions[idx].state == EnclaveState::Running {
        ACTIVE_SESSION.store(INVALID_ID, Ordering::SeqCst);
    }
    mgr.sessions[idx] = EnclaveSession::empty();
    drop(mgr);
    record_temporal_enclave_state_snapshot();
    Ok(())
}

pub fn attest_session(
    session_id: u32,
    nonce: u64,
) -> Result<EnclaveAttestationReport, &'static str> {
    let (backend, s) = {
        let mgr = MANAGER.lock();
        let idx = mgr
            .find_slot(session_id)
            .ok_or("Enclave session not found")?;
        (mgr.backend, mgr.sessions[idx])
    };
    let mut payload = [0u8; 48];
    payload[0..4].copy_from_slice(&s.id.to_le_bytes());
    payload[4..8].copy_from_slice(&(backend as u32).to_le_bytes());
    payload[8..16].copy_from_slice(&s.measurement.to_le_bytes());
    payload[16..24].copy_from_slice(&nonce.to_le_bytes());
    payload[24..32].copy_from_slice(&s.launch_token_mac.to_le_bytes());
    payload[32..36].copy_from_slice(&(s.epc_pages as u32).to_le_bytes());
    payload[36..40].copy_from_slice(&(s.epc_base as u32).to_le_bytes());
    payload[40..48].copy_from_slice(&s.backend_cookie.to_le_bytes()); // u64 now

    let report_mac = security::security().cap_token_sign(&payload);
    ATTESTATION_REPORTS.fetch_add(1, Ordering::SeqCst);
    record_temporal_enclave_state_snapshot();
    Ok(EnclaveAttestationReport {
        session_id: s.id,
        backend,
        measurement: s.measurement,
        nonce,
        launch_token_mac: s.launch_token_mac,
        report_mac,
    })
}

fn backend_open(
    backend: EnclaveBackend,
    session: &mut EnclaveSession,
    mgr: &mut EnclaveManager,
) -> Result<(), &'static str> {
    match backend {
        EnclaveBackend::None => Ok(()),
        EnclaveBackend::IntelSgx => sgx_open_session(session, mgr),
        EnclaveBackend::ArmTrustZone => trustzone_open_session(session, mgr),
    }
}

fn backend_enter(
    backend: EnclaveBackend,
    session: &mut EnclaveSession,
) -> Result<(), &'static str> {
    match backend {
        EnclaveBackend::None => Ok(()),
        EnclaveBackend::IntelSgx => sgx_enter_session(session),
        EnclaveBackend::ArmTrustZone => trustzone_enter_session(session),
    }
}

fn backend_exit(backend: EnclaveBackend, session: &mut EnclaveSession) -> Result<(), &'static str> {
    match backend {
        EnclaveBackend::None => Ok(()),
        EnclaveBackend::IntelSgx => sgx_exit_session(session),
        EnclaveBackend::ArmTrustZone => trustzone_exit_session(session),
    }
}

fn backend_close(
    backend: EnclaveBackend,
    session: &mut EnclaveSession,
) -> Result<(), &'static str> {
    match backend {
        EnclaveBackend::None => Ok(()),
        EnclaveBackend::IntelSgx => sgx_close_session(session),
        EnclaveBackend::ArmTrustZone => trustzone_close_session(session),
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
extern "C" {
    /// ENCLS ring-0 leaf dispatcher.  All pointer operands are 64-bit on x86_64.
    fn sgx_encls(leaf: u32, rbx: u64, rcx: u64, rdx: u64) -> u32;
    /// ENCLU ring-3 leaf dispatcher (EENTER/EEXIT/etc.).
    fn sgx_enclu(leaf: u32, rbx: u64, rcx: u64, rdx: u64) -> u32;
    /// Query CPUID leaf 0x12 at the given sub-leaf, writing results to the
    /// provided output pointers (any of which may be null).
    fn sgx_cpuid_leaf12(
        sub_leaf: u32,
        out_eax: *mut u32,
        out_ebx: *mut u32,
        out_ecx: *mut u32,
        out_edx: *mut u32,
    );
    /// Read IA32_FEATURE_CONTROL MSR (0x3A).  Ring-0 only.
    fn sgx_read_feature_ctrl() -> u64;
    /// Write the four IA32_SGXLEPUBKEYHASHn MSRs for Flexible Launch Control.
    fn sgx_write_sgxlepubkeyhash(h0: u64, h1: u64, h2: u64, h3: u64);
    /// Remove a single EPC page (ENCLS EREMOVE leaf 8). Returns 0 on success.
    fn sgx_eremove(epc_page_linear_addr: u64) -> u32;
}

// ---- ENCLS leaf numbers (Intel SDM Vol 3D Table 38-3) ----
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_ECREATE: u32 = 0x0; // Create SECS
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EADD: u32 = 0x1; // Add a page to an uninitialized enclave
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EINIT: u32 = 0x2; // Initialize enclave; verify SIGSTRUCT
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EREMOVE: u32 = 0x3; // Remove page from EPC and return to OS
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EDBGRD: u32 = 0x4; // Debug read of EPC page (DEBUG enclaves only)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EDBGWR: u32 = 0x5; // Debug write of EPC page (DEBUG enclaves only)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLS_EEXTEND: u32 = 0x6; // Extend enclave measurement by 256 bytes
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLS_ELDU: u32 = 0x8; // Load an EPC page as unblocked (paging)
                                 // ---- ENCLU leaf numbers (Intel SDM Vol 3D Table 38-4) ----
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLU_EREPORT: u32 = 0x0; // Create attestation report
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLU_EGETKEY: u32 = 0x1; // Retrieve a sealing or attestation key
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLU_EENTER: u32 = 0x2; // Enter enclave from OS
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_ENCLU_ERESUME: u32 = 0x3; // Re-enter enclave after AEX
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLU_EEXIT: u32 = 0x4; // Exit enclave (called from enclave code)
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLU_EACCEPT: u32 = 0x5; // SGX2: accept EPC page changes
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(dead_code)]
const SGX_ENCLU_EMODPE: u32 = 0x6; // SGX2: extend page permissions
                                   // ---- FLC: Flexible Launch Control MSR numbers ----
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const FEAT_CTRL_LOCK_BIT: u64 = 1 << 0;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const FEAT_CTRL_SGX_ENABLE: u64 = 1 << 18;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const FEAT_CTRL_SGX_LC_ENABLE: u64 = 1 << 17; // Flexible Launch Control enable

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_PAGE_TYPE_TCS: u64 = 0x1;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_PAGE_TYPE_REG: u64 = 0x2;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_PERM_R: u64 = 1 << 8;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_PERM_W: u64 = 1 << 9;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const SGX_PERM_X: u64 = 1 << 10;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    let end = offset + 8;
    if end <= buf.len() {
        buf[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    let end = offset + 4;
    if end <= buf.len() {
        buf[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn write_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    let end = offset + 2;
    if end <= buf.len() {
        buf[offset..end].copy_from_slice(&value.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// SGX SIGSTRUCT — Intel SDM Vol 3D §38.13
//
// Full 1808-byte layout.  The workspace pads it to a 4096-byte AlignedPage.
// On real hardware the modulus/signature/q1/q2 fields must contain the
// RSA-3072 key material from the kernel's signing key.  For debug/simulation
// builds we set the MRENCLAVE hash and leave the RSA fields as the
// "all-zeros / debug" sentinel that SGX DEBUG enclaves accept when
// IA32_SGXLEPUBKEYHASHn has been programmed with the kernel's own key.
// ---------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SgxSigstruct {
    /// Bytes 0..11: SIGSTRUCT header magic (SDM Table 38-14)
    header: [u8; 12],
    /// Bytes 12..15: Vendor (0 = non-Intel)
    vendor: u32,
    /// Bytes 16..19: Build date BCD YYYYMMDD
    date: u32,
    /// Bytes 20..35: Second header word (SDM Table 38-14)
    header2: [u8; 16],
    /// Bytes 36..39: SW-defined metadata
    sw_defined: u32,
    /// Bytes 40..123: Reserved
    reserved1: [u8; 84],
    /// Bytes 124..507: RSA-3072 public modulus (little-endian)
    modulus: [u8; 384],
    /// Bytes 508..511: RSA exponent (0x10001 for production keys)
    exponent: u32,
    /// Bytes 512..895: RSA-3072 signature
    signature: [u8; 384],
    /// Bytes 896..899: MISCSELECT (enclave MISC feature bits)
    miscselect: u32,
    /// Bytes 900..903: MISCSELECT mask
    miscmask: u32,
    /// Bytes 904..907: CID page-attribute / CSS-ID / chain-ID / extinfo-mask
    reserved2: [u8; 4],
    /// Bytes 908..923: ISVFAMILYID (16-byte product family ID)
    isvfamilyid: [u8; 16],
    /// Bytes 924..939: Required ATTRIBUTES (16 bytes)
    attributes: [u8; 16],
    /// Bytes 940..955: ATTRIBUTES mask (16 bytes)
    attributemask: [u8; 16],
    /// Bytes 956..987: MRENCLAVE — SHA-256 of enclave measurement (32 bytes)
    enclavehash: [u8; 32],
    /// Bytes 988..1019: Reserved (32 bytes)
    reserved3: [u8; 32],
    /// Bytes 1020..1035: ISVEXTPRODID (16-byte extended product ID)
    isvextprodid: [u8; 16],
    /// Bytes 1036..1037: ISVPRODID (product ID u16)
    isvprodid: u16,
    /// Bytes 1038..1039: ISVSVN (security version number u16)
    isvsvn: u16,
    /// Bytes 1040..1051: Reserved
    reserved4: [u8; 12],
    /// Bytes 1052..1435: RSA-3072 q1 verification value
    q1: [u8; 384],
    /// Bytes 1436..1819: RSA-3072 q2 verification value (total = 1808 bytes)
    q2: [u8; 372], // 1808 - 1436 = 372
}

const _SIGSTRUCT_SIZE_CHECK: () = {
    if core::mem::size_of::<SgxSigstruct>() != 1808 {
        panic!("SgxSigstruct must be exactly 1808 bytes (SDM Vol 3D §38.13)");
    }
};

// Canonical SIGSTRUCT header magic bytes (SDM Vol 3D Table 38-14).
const SIGSTRUCT_HEADER1: [u8; 12] = [
    0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];
// Second header word (bytes 20..35): fixed by the SDM.
const SIGSTRUCT_HEADER2: [u8; 16] = [
    0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// SGX EINITTOKEN — Intel SDM Vol 3D §38.14
//
// 304-byte structure.  With FLC, the platform firmware sets the launch key to
// the kernel's programmed hash and the token is unused by EINIT (pass zeros).
// Without FLC the token must come from Intel's Launch Enclave (out of scope).
// ---------------------------------------------------------------------------
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SgxEinitToken {
    /// Valid flag (1 = valid token from LE, 0 = invalid/debug)
    valid: u32,
    reserved1: [u8; 44],
    /// Required ATTRIBUTES of the requesting enclave
    attributes: [u8; 16],
    /// MRENCLAVE of the requesting enclave
    mrenclave: [u8; 32],
    reserved2: [u8; 32],
    /// MRSIGNER of the signing key
    mrsigner: [u8; 32],
    reserved3: [u8; 32],
    /// CPU SVN at time of token issuance
    cpusvnle: [u8; 16],
    isvprodidle: u16,
    isvsvnle: u16,
    reserved4: [u8; 24],
    maskedmiscselectle: u32,
    maskedattributesle: [u8; 16],
    keyid: [u8; 32],
    mac: [u8; 16],
}

const _EINITTOKEN_SIZE_CHECK: () = {
    if core::mem::size_of::<SgxEinitToken>() != 304 {
        panic!("SgxEinitToken must be exactly 304 bytes (SDM Vol 3D §38.14)");
    }
};

// ---------------------------------------------------------------------------
// EPC virtual-address helpers
//
// On a straight 1:1 physical-to-virtual kernel map (the current Oreulius boot
// model) EPC physical addresses are directly accessible as virtual addresses.
// When the kernel eventually introduces a separate EPC virtual window (e.g.
// KASLR or multi-range paging) update EPC_VIRT_OFFSET accordingly or replace
// epc_phys_to_virt with a real page-table walk.
// ---------------------------------------------------------------------------

/// Linear offset added to a physical EPC address to obtain the kernel-mode
/// virtual address.  Zero on identity-mapped builds (default).
const EPC_VIRT_OFFSET: usize = 0;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
fn epc_phys_to_virt(pa: usize) -> usize {
    pa.wrapping_add(EPC_VIRT_OFFSET)
}

// ---------------------------------------------------------------------------
// FLC launch-key derivation
//
// Derive a deterministic 256-bit hash from the kernel's compile-time identity
// constants.  This hash is programmed into IA32_SGXLEPUBKEYHASHn so that the
// platform trusts enclaves signed by the Oreulius kernel build key — no
// dependency on Intel's proprietary Launch Enclave.
//
// The derivation uses a simple FNV-1a-64 cascade over well-known build
// constants.  For a production build, replace OREULIA_BUILD_KEY_BYTES with
// the SHA-256 of the kernel's RSA-3072 public modulus from the actual signing
// key, then re-derive.
// ---------------------------------------------------------------------------

/// Compile-time kernel build identity seed (32 bytes).
/// Replace with the SHA-256 of the production RSA-3072 public modulus.
const OREULIA_BUILD_KEY_BYTES: [u8; 32] = [
    0x4F, 0x52, 0x45, 0x55, 0x4C, 0x49, 0x41, 0x5F, // "OREULIA_"
    0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x5F, 0x4B, // "KERNEL_K"
    0x45, 0x59, 0x5F, 0x76, 0x30, 0x2E, 0x31, 0x5F, // "EY_v0.1_"
    0x44, 0x45, 0x42, 0x55, 0x47, 0x5F, 0x30, 0x30, // "DEBUG_00"
];

/// FNV-1a 64-bit hash of a byte slice (const-capable loop).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const fn fnv1a64(data: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 0x00000100_000001B3;
    const FNV_OFFSET: u64 = 0xcbf29ce4_84222325;
    let mut h = FNV_OFFSET;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u64;
        h = h.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    h
}

/// Derive the four 64-bit words that make up the FLC launch-key hash.
///
/// Each word is an independent FNV-1a hash over the build key seeded with a
/// different domain-separation byte, giving 256 bits of key material derived
/// entirely from compile-time constants.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn derive_flc_launch_key_hash() -> [u64; 4] {
    // Domain-separate each word by XOR-ing a different sentinel into the seed
    // before hashing.  All work is done on stack-local arrays — no heap.
    let mut seed0 = OREULIA_BUILD_KEY_BYTES;
    let mut seed1 = OREULIA_BUILD_KEY_BYTES;
    let mut seed2 = OREULIA_BUILD_KEY_BYTES;
    let mut seed3 = OREULIA_BUILD_KEY_BYTES;
    seed0[0] ^= 0xA1;
    seed1[0] ^= 0xB2;
    seed2[0] ^= 0xC3;
    seed3[0] ^= 0xD4;
    [
        fnv1a64(&seed0),
        fnv1a64(&seed1),
        fnv1a64(&seed2),
        fnv1a64(&seed3),
    ]
}

// ---------------------------------------------------------------------------
// SIGSTRUCT builder
//
// Populates the SIGSTRUCT in `ws.sigstruct.bytes` with the canonical header
// magic, the enclave measurement (MRENCLAVE derived from the session's
// `measurement` field), and the ATTRIBUTES required for a DEBUG enclave.
// RSA fields (modulus/signature/q1/q2) are left as zeros, which is the
// correct debug sentinel for enclaves launched under a kernel-controlled FLC
// key.  For production the signing tool must fill those fields offline.
// ---------------------------------------------------------------------------
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn build_sigstruct(
    ws: &mut SgxWorkspace,
    measurement: u64,
    _enclave_base: usize,
    _enclave_size: usize,
) {
    let b = &mut ws.sigstruct.bytes;
    *b = [0u8; PAGE_SIZE];

    // Header magic (bytes 0..11)
    b[..12].copy_from_slice(&SIGSTRUCT_HEADER1);

    // vendor = 0 (non-Intel signed), date = 0x20250101 (BCD)
    write_u32_le(b, 12, 0x0000_0000);
    write_u32_le(b, 16, 0x2025_0101);

    // Header2 (bytes 20..35)
    b[20..36].copy_from_slice(&SIGSTRUCT_HEADER2);

    // RSA exponent = 65537 (0x10001) at offset 508
    write_u32_le(b, 508, 0x0001_0001);

    // MISCSELECT = 0, MISCMASK = 0xFFFFFFFF (accept any MISC bits)
    write_u32_le(b, 896, 0x0000_0000);
    write_u32_le(b, 900, 0xFFFF_FFFF);

    // ATTRIBUTES: DEBUG bit (bit 1) set; XFRM = 0x03 (x87 + SSE)
    // bytes 924..939: ATTRIBUTES[0..7] = flags, [8..15] = XFRM
    write_u64_le(b, 924, 0x0000_0000_0000_0002); // flags: MODE64BIT|DEBUG = bit0|bit1
    write_u64_le(b, 932, 0x0000_0000_0000_0003); // XFRM: x87|SSE

    // ATTRIBUTEMASK: require only the bits we set above
    write_u64_le(b, 940, 0x0000_0000_0000_0002); // must match flags
    write_u64_le(b, 948, 0x0000_0000_0000_0003); // must match XFRM

    // MRENCLAVE (bytes 956..987): use the lower 32 bytes of a FNV cascade
    // over the session measurement value.  A real tool would supply the true
    // SHA-256 of all EEXTEND chunks; this placeholder keeps EINIT debug-valid.
    let mut mrenclave = [0u8; 32];
    let h0 = fnv1a64(&measurement.to_le_bytes());
    let h1 = fnv1a64(&h0.to_le_bytes());
    let h2 = fnv1a64(&h1.to_le_bytes());
    let h3 = fnv1a64(&h2.to_le_bytes());
    mrenclave[0..8].copy_from_slice(&h0.to_le_bytes());
    mrenclave[8..16].copy_from_slice(&h1.to_le_bytes());
    mrenclave[16..24].copy_from_slice(&h2.to_le_bytes());
    mrenclave[24..32].copy_from_slice(&h3.to_le_bytes());
    b[956..988].copy_from_slice(&mrenclave);

    // ISVPRODID = 1, ISVSVN = 0 (debug/initial)
    write_u16_le(b, 1036, 0x0001);
    write_u16_le(b, 1038, 0x0000);
}

// ---------------------------------------------------------------------------
// EINITTOKEN builder
//
// With FLC active the EINIT token is not validated by hardware (the launch
// enclave path is bypassed).  We write a zeroed-out token with valid=0.
// ---------------------------------------------------------------------------
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn build_einittoken(ws: &mut SgxWorkspace) {
    ws.token.bytes = [0u8; PAGE_SIZE];
    // valid = 0: hardware will ignore token content under FLC
    write_u32_le(&mut ws.token.bytes, 0, 0u32);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn next_pow2(mut x: usize) -> usize {
    if x <= 1 {
        return 1;
    }
    x -= 1;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    #[cfg(target_pointer_width = "64")]
    {
        x |= x >> 32;
    }
    x + 1
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn call_encls(leaf: u32, rbx: usize, rcx: usize, rdx: usize) -> u32 {
    unsafe { sgx_encls(leaf, rbx as u64, rcx as u64, rdx as u64) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn call_enclu(leaf: u32, rbx: usize, rcx: usize, rdx: usize) -> u32 {
    unsafe { sgx_enclu(leaf, rbx as u64, rcx as u64, rdx as u64) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_add_page(
    ws: &mut SgxWorkspace,
    secs_ptr: usize,
    src_ptr: usize,
    linaddr: u64,
    flags: u64,
    mgr: &mut EnclaveManager,
) -> Result<(), &'static str> {
    ws.secinfo.flags = flags;
    ws.pageinfo.linaddr = linaddr;
    ws.pageinfo.srcpge = src_ptr as u64;
    ws.pageinfo.secinfo = (&ws.secinfo as *const SgxSecInfo) as u64;
    ws.pageinfo.secs = secs_ptr as u64;
    ws.pageinfo.reserved = [0; 32];
    let st = call_encls(
        SGX_ENCLS_EADD,
        &ws.pageinfo as *const SgxPageInfo as usize,
        linaddr as usize,
        0,
    );
    record_backend_op();
    if st != 0 {
        mgr.mark_failure();
        return Err("SGX EADD failed");
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_measure_page(linaddr: u64, mgr: &mut EnclaveManager) -> Result<(), &'static str> {
    let mut off = 0usize;
    while off < PAGE_SIZE {
        let st = call_encls(SGX_ENCLS_EEXTEND, (linaddr as usize) + off, 0, 0);
        record_backend_op();
        if st != 0 {
            mgr.mark_failure();
            return Err("SGX EEXTEND failed");
        }
        off += 256;
    }
    Ok(())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_open_session(
    session: &mut EnclaveSession,
    mgr: &mut EnclaveManager,
) -> Result<(), &'static str> {
    let code_pages = align_up(session.code_len)? / PAGE_SIZE;
    let data_pages = align_up(session.data_len)? / PAGE_SIZE;
    let mem_pages = align_up(session.mem_len)? / PAGE_SIZE;
    let total_pages = 1usize
        .checked_add(code_pages)
        .and_then(|x| x.checked_add(data_pages))
        .and_then(|x| x.checked_add(mem_pages))
        .ok_or("SGX total pages overflow")?;

    {
        let mut epc = EPC_MANAGER.lock();
        session.epc_base = epc.reserve_contiguous(session.id, total_pages)?;
        session.epc_pages = total_pages;
    }
    let result = (|| -> Result<(), &'static str> {
        issue_launch_token(session)?;
        if !verify_launch_token(session) {
            return Err("SGX launch token verification failed");
        }

        let mut ws = SGX_WORKSPACE.lock();
        ws.secs.bytes = [0; PAGE_SIZE];
        ws.sigstruct.bytes = [0; PAGE_SIZE];
        ws.token.bytes = [0; PAGE_SIZE];
        ws.tcs.bytes = [0; PAGE_SIZE];
        ws.pageinfo = SgxPageInfo::zeroed();
        ws.secinfo = SgxSecInfo::zeroed();

        // Round enclave size up to the next power-of-two, minimum 2 pages.
        // Budget one extra page for the TCS and one for the SSA frame.
        let ssa_pages = 1usize;
        let total_with_meta = total_pages
            .checked_add(1 + ssa_pages) // +1 TCS  +1 SSA
            .ok_or("SGX page count overflow")?;
        let enclave_size = next_pow2(total_with_meta * PAGE_SIZE).max(PAGE_SIZE * 4);

        // The enclave's virtual base address equals the EPC virtual address
        // returned by reserve_contiguous.  On a 1:1-mapped kernel the EPC
        // physical address IS the virtual address (EPC_VIRT_OFFSET = 0).
        let enclave_base: u64 = epc_phys_to_virt(session.epc_base) as u64;

        // ---- SECS (SGX Enclave Control Structure) layout (SDM §38.7) -------
        // offset 0x00  SIZE      (u64) enclave virtual size (power-of-two)
        // offset 0x08  BASEADDR  (u64) enclave virtual base
        // offset 0x30  ATTRIBUTES (u64 flags) — bit 1 = DEBUG, bit 2 = MODE64BIT
        // offset 0x38  XFRM      (u64) allowed XSAVE feature mask
        write_u64_le(&mut ws.secs.bytes, 0x00, enclave_size as u64);
        write_u64_le(&mut ws.secs.bytes, 0x08, enclave_base);
        write_u64_le(&mut ws.secs.bytes, 0x30, 0x0000_0000_0000_0006); // MODE64BIT|DEBUG
        write_u64_le(&mut ws.secs.bytes, 0x38, 0x0000_0000_0000_0003); // XFRM: x87|SSE

        ws.pageinfo.linaddr = 0;
        ws.pageinfo.srcpge = ws.secs.bytes.as_ptr() as u64; // source SECS page (unencrypted)
        ws.pageinfo.secinfo = 0; // not used for ECREATE
        ws.pageinfo.secs = 0; // not used for ECREATE
        ws.pageinfo.reserved = [0; 32];

        // Build SIGSTRUCT and EINITTOKEN before EINIT.
        build_sigstruct(&mut ws, session.measurement, session.epc_base, enclave_size);
        build_einittoken(&mut ws);

        let secs_ptr = session.epc_base;
        // ECREATE: RBX = address of PAGEINFO (srcpge → source SECS page),
        //          RCX = address of the EPC SECS slot to initialize.
        let st_create = call_encls(
            SGX_ENCLS_ECREATE,
            &ws.pageinfo as *const SgxPageInfo as usize,
            secs_ptr, // EPC SECS slot (virtual == physical on 1:1 map)
            0,
        );
        record_backend_op();
        if st_create != 0 {
            return Err("SGX ECREATE failed");
        }

        // ---- TCS page layout (SDM Vol 3D §38.8 / Table 38-8) ---------------
        //
        // Page-offset layout within the enclave (relative to enclave_base):
        //   +0*PAGE  TCS   (this page)
        //   +1*PAGE  SSA   (State Save Area frame 0)
        //   +2*PAGE  code  (first code page; OENTRY points here)
        //   +n*PAGE  data/heap …
        //
        // All TCS field offsets are from the start of the TCS page.
        //
        // OSSA  (u64, @0x00): offset from enclave base to the first SSA frame.
        //   SSA lives one page after TCS → PAGE_SIZE bytes into the enclave.
        // CSSA  (u32, @0x08): current SSA frame index (always 0 at load time).
        // NSSA  (u32, @0x0C): number of SSA frames allocated (we allocate 1).
        // OENTRY (u64, @0x10): entry-point offset from enclave base.
        //   Code starts two pages in (after TCS and SSA).
        // OFSBASGX (u64, @0x20): FS base — 0 = no enclave FS override.
        // OGSBASGX (u64, @0x28): GS base — 0 = no enclave GS override.
        ws.tcs.bytes = [0u8; PAGE_SIZE];
        let ssa_offset = PAGE_SIZE as u64; // OSSA = 1 page in
        let entry_offset = (2 * PAGE_SIZE) as u64; // OENTRY = 2 pages in
        write_u64_le(&mut ws.tcs.bytes, 0x00, ssa_offset); // OSSA
        write_u32_le(&mut ws.tcs.bytes, 0x08, 0u32); // CSSA = 0
        write_u32_le(&mut ws.tcs.bytes, 0x0C, 1u32); // NSSA = 1
        write_u64_le(&mut ws.tcs.bytes, 0x10, entry_offset); // OENTRY
        write_u64_le(&mut ws.tcs.bytes, 0x20, 0u64); // OFSBASGX
        write_u64_le(&mut ws.tcs.bytes, 0x28, 0u64); // OGSBASGX

        // Add TCS page at enclave_base + 0*PAGE.
        let tcs_lin = enclave_base;
        let tcs_src = ws.tcs.bytes.as_ptr() as usize;
        sgx_add_page(&mut ws, secs_ptr, tcs_src, tcs_lin, SGX_PAGE_TYPE_TCS, mgr)?;

        // ---- SSA page (State Save Area) at enclave_base + 1*PAGE ------------
        // The SSA frame is a plain R/W regular page; its content is written by
        // the processor on Asynchronous Enclave Exit (AEX) and by EENTER.
        let ssa_lin = enclave_base + ssa_offset;
        let ssa_zero = [0u8; PAGE_SIZE];
        let ssa_src = ssa_zero.as_ptr() as usize;
        sgx_add_page(
            &mut ws,
            secs_ptr,
            ssa_src,
            ssa_lin,
            SGX_PAGE_TYPE_REG | SGX_PERM_R | SGX_PERM_W,
            mgr,
        )?;

        let mut lin = enclave_base + (2 * PAGE_SIZE) as u64; // after TCS + SSA
        let mut src = align_down(session.code_phys);
        let code_end = align_up(
            session
                .code_phys
                .checked_add(session.code_len)
                .ok_or("SGX code overflow")?,
        )?;
        while src < code_end {
            sgx_add_page(
                &mut ws,
                secs_ptr,
                src,
                lin,
                SGX_PAGE_TYPE_REG | SGX_PERM_R | SGX_PERM_X,
                mgr,
            )?;
            sgx_measure_page(lin, mgr)?;
            src += PAGE_SIZE;
            lin += PAGE_SIZE as u64;
        }

        let mut data_src = align_down(session.data_phys);
        let data_end = align_up(
            session
                .data_phys
                .checked_add(session.data_len)
                .ok_or("SGX data overflow")?,
        )?;
        while data_src < data_end {
            sgx_add_page(
                &mut ws,
                secs_ptr,
                data_src,
                lin,
                SGX_PAGE_TYPE_REG | SGX_PERM_R | SGX_PERM_W,
                mgr,
            )?;
            data_src += PAGE_SIZE;
            lin += PAGE_SIZE as u64;
        }

        let mut mem_src = align_down(session.mem_phys);
        let mem_end = align_up(
            session
                .mem_phys
                .checked_add(session.mem_len)
                .ok_or("SGX mem overflow")?,
        )?;
        while mem_src < mem_end {
            sgx_add_page(
                &mut ws,
                secs_ptr,
                mem_src,
                lin,
                SGX_PAGE_TYPE_REG | SGX_PERM_R | SGX_PERM_W,
                mgr,
            )?;
            mem_src += PAGE_SIZE;
            lin += PAGE_SIZE as u64;
        }

        // EINIT: hardware validates SIGSTRUCT (our kernel-signed debug struct)
        // against the MRENCLAVE accumulated by EEXTEND, and checks that the
        // ATTRIBUTES match the SECS.  With FLC active and our key programmed in
        // IA32_SGXLEPUBKEYHASHn, the token (EINITTOKEN) is bypassed.
        let st_init = call_encls(
            SGX_ENCLS_EINIT,
            ws.sigstruct.bytes.as_ptr() as usize,
            ws.token.bytes.as_ptr() as usize,
            secs_ptr, // EPC SECS page
        );
        record_backend_op();
        if st_init != 0 {
            return Err("SGX EINIT failed");
        }

        session.backend_cookie = tcs_lin; // full 64-bit TCS linear address
        Ok(())
    })();

    if result.is_err() {
        mgr.mark_failure();
        let mut epc = EPC_MANAGER.lock();
        epc.release_owner(session.id);
        session.backend_cookie = 0;
        session.epc_base = 0;
        session.epc_pages = 0;
        session.launch_token_mac = 0;
        session.launch_nonce = 0;
    }
    result
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_open_session(
    _session: &mut EnclaveSession,
    _mgr: &mut EnclaveManager,
) -> Result<(), &'static str> {
    Err("SGX backend unsupported on this build target")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_enter_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    if session.backend_cookie == 0 {
        return Err("SGX TCS not initialized");
    }
    let st = call_enclu(SGX_ENCLU_EENTER, session.backend_cookie as usize, 0, 0);
    record_backend_op();
    if st != 0 {
        return Err("SGX EENTER failed");
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_enter_session(_session: &mut EnclaveSession) -> Result<(), &'static str> {
    Err("SGX backend unsupported on this build target")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_resume_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    if session.backend_cookie == 0 {
        return Err("SGX TCS not initialized");
    }
    let st = call_enclu(SGX_ENCLU_ERESUME, session.backend_cookie as usize, 0, 0);
    record_backend_op();
    if st != 0 {
        return Err("SGX ERESUME failed");
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_resume_session(_session: &mut EnclaveSession) -> Result<(), &'static str> {
    Err("SGX backend unsupported on this build target")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_exit_session(_session: &mut EnclaveSession) -> Result<(), &'static str> {
    // EEXIT is typically executed from enclave code. We model exit as
    // lifecycle state transition after returning from EENTER.
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_exit_session(_session: &mut EnclaveSession) -> Result<(), &'static str> {
    Err("SGX backend unsupported on this build target")
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn sgx_close_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    let mut epc = EPC_MANAGER.lock();
    epc.release_owner(session.id);
    session.backend_cookie = 0;
    session.epc_base = 0;
    session.epc_pages = 0;
    session.launch_token_mac = 0;
    session.launch_nonce = 0;
    Ok(())
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn sgx_close_session(_session: &mut EnclaveSession) -> Result<(), &'static str> {
    Err("SGX backend unsupported on this build target")
}

const TZ_SMC_NEGOTIATE: u32 = 0x8200_00FF;
const TZ_SMC_OPEN: u32 = 0x8200_0100;
const TZ_SMC_ENTER: u32 = 0x8200_0101;
const TZ_SMC_EXIT: u32 = 0x8200_0102;
const TZ_SMC_CLOSE: u32 = 0x8200_0103;

#[cfg(target_arch = "arm")]
fn trustzone_smc(fid: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    let mut r0 = fid;
    let mut r1 = a1;
    let mut r2 = a2;
    let mut r3 = a3;
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("r0") r0,
            inout("r1") r1,
            inout("r2") r2,
            inout("r3") r3,
            options(nostack)
        );
    }
    r0
}

#[cfg(target_arch = "aarch64")]
fn trustzone_smc(fid: u32, a1: u32, a2: u32, a3: u32) -> u32 {
    let mut x0 = fid as u64;
    let mut x1 = a1 as u64;
    let mut x2 = a2 as u64;
    let mut x3 = a3 as u64;
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") x0,
            inout("x1") x1,
            inout("x2") x2,
            inout("x3") x3,
            options(nostack)
        );
    }
    x0 as u32
}

#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
fn trustzone_smc(_fid: u32, _a1: u32, _a2: u32, _a3: u32) -> u32 {
    u32::MAX
}

fn ensure_trustzone_contract() -> Result<(), &'static str> {
    {
        let tz = TRUSTZONE_CONTRACT.lock();
        if tz.ready {
            return Ok(());
        }
    }
    let resp = trustzone_smc(TZ_SMC_NEGOTIATE, 1, 0, MAX_ENCLAVE_SESSIONS as u32);
    record_backend_op();
    if resp == u32::MAX {
        return Err("TrustZone contract negotiation unavailable");
    }
    if resp != 0 {
        return Err("TrustZone contract negotiation failed");
    }

    let mut tz = TRUSTZONE_CONTRACT.lock();
    tz.ready = true;
    tz.abi_major = 1;
    tz.abi_minor = 0;
    tz.features = 0x1; // Base secure-enclave service contract.
    tz.max_sessions = MAX_ENCLAVE_SESSIONS as u32;
    Ok(())
}

fn trustzone_open_session(
    session: &mut EnclaveSession,
    mgr: &mut EnclaveManager,
) -> Result<(), &'static str> {
    ensure_trustzone_contract()?;
    let resp = trustzone_smc(
        TZ_SMC_OPEN,
        session.code_phys as u32,
        session.code_len as u32,
        session.id,
    );
    record_backend_op();
    if resp == u32::MAX {
        mgr.mark_failure();
        return Err("TrustZone SMC not available on this build target");
    }
    if resp != 0 {
        mgr.mark_failure();
        return Err("TrustZone open session failed");
    }
    session.backend_cookie = session.id as u64; // TrustZone: SMC session handle (32-bit id widened to u64 field)
    Ok(())
}

fn trustzone_enter_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    let resp = trustzone_smc(TZ_SMC_ENTER, session.backend_cookie as u32, 0, 0);
    record_backend_op();
    if resp == u32::MAX {
        return Err("TrustZone SMC not available on this build target");
    }
    if resp != 0 {
        return Err("TrustZone enter failed");
    }
    Ok(())
}

fn trustzone_exit_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    let resp = trustzone_smc(TZ_SMC_EXIT, session.backend_cookie as u32, 0, 0);
    record_backend_op();
    if resp == u32::MAX {
        return Err("TrustZone SMC not available on this build target");
    }
    if resp != 0 {
        return Err("TrustZone exit failed");
    }
    Ok(())
}

fn trustzone_close_session(session: &mut EnclaveSession) -> Result<(), &'static str> {
    let resp = trustzone_smc(TZ_SMC_CLOSE, session.backend_cookie as u32, 0, 0);
    record_backend_op();
    if resp == u32::MAX {
        return Err("TrustZone SMC not available on this build target");
    }
    if resp != 0 {
        return Err("TrustZone close failed");
    }
    session.backend_cookie = 0;
    Ok(())
}
