/*!
 * Oreulia Kernel Project
 * 
 * SPDX-License-Identifier: MIT
 * 
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 * 
 * ---------------------------------------------------------------------------
 */

//! CapNet v1: Portable network capability token format.
//!
//! Phase 1 scope:
//! - Canonical fixed-width token format for cross-device transport.
//! - Checked encoder/decoder with fail-closed parsing.
//! - Deterministic token-id hashing over canonical bytes.
//! - Kernel-key MAC helpers (boot-key SipHash path) for local testing.
//! - Phase 2: peer trust/session table and replay-window verification.

#![allow(dead_code)]

use crate::ipc::ProcessId;
use crate::security::{self, AuditEntry, SecurityEvent};
use spin::Mutex;
use crate::persistence;

pub const CAPNET_TOKEN_MAGIC: u32 = 0x544E_5043; // "CPNT" (little-endian storage)
pub const CAPNET_TOKEN_VERSION_V1: u8 = 1;

pub const CAPNET_ALG_SIPHASH24_KERNEL: u8 = 1;
pub const CAPNET_ALG_RESERVED_ED25519: u8 = 2;

pub const CAPNET_MAX_DELEGATION_DEPTH: u16 = 32;

pub const CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE: u32 = 1 << 0;
pub const CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA: u32 = 1 << 1;
pub const CAPNET_CONSTRAINT_MEASUREMENT_BOUND: u32 = 1 << 2;
pub const CAPNET_CONSTRAINT_SESSION_BOUND: u32 = 1 << 3;

/// Fixed serialized length of `CapabilityTokenV1` in bytes.
pub const CAPNET_TOKEN_V1_LEN: usize = 116;
const CAPNET_TOKEN_V1_BODY_LEN: usize = CAPNET_TOKEN_V1_LEN - 8;

pub const CAPNET_MAX_PEERS: usize = 32;

pub const CAPNET_CONTROL_PORT: u16 = 48123;
const CAPNET_CTRL_MAGIC: u32 = 0x3146_4E43; // "CNF1"
const CAPNET_CTRL_VERSION: u8 = 1;
pub const CAPNET_CTRL_MAX_PAYLOAD: usize = CAPNET_TOKEN_V1_LEN;
const CAPNET_CTRL_HEADER_NO_MAC_LEN: usize = 48;
const CAPNET_CTRL_HEADER_LEN: usize = 56;
pub const CAPNET_CTRL_MAX_FRAME_LEN: usize = CAPNET_CTRL_HEADER_LEN + CAPNET_CTRL_MAX_PAYLOAD;
const CAPNET_CTRL_FLAG_ACK_ONLY: u8 = 1 << 0;

const CAPNET_MAX_DELEGATION_RECORDS: usize = 128;
const CAPNET_MAX_REVOCATION_TOMBSTONES: usize = 256;

const CAPNET_REVOKE_LOG_MAGIC: u32 = 0x4B56_5243; // "CRVK"
const CAPNET_REVOKE_LOG_VERSION: u8 = 1;
const CAPNET_REVOKE_LOG_PAYLOAD_LEN: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CapNetControlType {
    Hello = 1,
    Attest = 2,
    TokenOffer = 3,
    TokenAccept = 4,
    TokenRevoke = 5,
    Heartbeat = 6,
}

impl CapNetControlType {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(CapNetControlType::Hello),
            2 => Some(CapNetControlType::Attest),
            3 => Some(CapNetControlType::TokenOffer),
            4 => Some(CapNetControlType::TokenAccept),
            5 => Some(CapNetControlType::TokenRevoke),
            6 => Some(CapNetControlType::Heartbeat),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct CapNetControlFrame {
    pub msg_type: CapNetControlType,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub issuer_device_id: u64,
    pub subject_device_id: u64,
    pub token_id: u64,
    pub key_epoch: u32,
    pub payload_len: u16,
    pub payload: [u8; CAPNET_CTRL_MAX_PAYLOAD],
    pub frame_mac: u64,
}

impl CapNetControlFrame {
    pub const fn empty() -> Self {
        CapNetControlFrame {
            msg_type: CapNetControlType::Hello,
            flags: 0,
            seq: 0,
            ack: 0,
            issuer_device_id: 0,
            subject_device_id: 0,
            token_id: 0,
            key_epoch: 0,
            payload_len: 0,
            payload: [0u8; CAPNET_CTRL_MAX_PAYLOAD],
            frame_mac: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct EncodedControlFrame {
    pub len: usize,
    pub bytes: [u8; CAPNET_CTRL_MAX_FRAME_LEN],
    pub seq: u32,
    pub token_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRxResult {
    pub msg_type: CapNetControlType,
    pub peer_device_id: u64,
    pub seq: u32,
    pub ack: u32,
    pub token_id: u64,
    pub ack_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerTrustPolicy {
    Disabled = 0,
    Audit = 1,
    Enforce = 2,
}

impl PeerTrustPolicy {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            1 => PeerTrustPolicy::Audit,
            2 => PeerTrustPolicy::Enforce,
            _ => PeerTrustPolicy::Disabled,
        }
    }
}

#[derive(Clone, Copy)]
struct PeerSession {
    active: bool,
    peer_device_id: u64,
    trust: PeerTrustPolicy,
    measurement_hash: u64,
    key_epoch: u32,
    key_k0: u64,
    key_k1: u64,
    replay_high_nonce: u64,
    replay_bitmap: u64,
    ctrl_rx_high_seq: u32,
    ctrl_rx_bitmap: u64,
    ctrl_tx_next_seq: u32,
    last_seen_epoch: u64,
}

impl PeerSession {
    const fn empty() -> Self {
        PeerSession {
            active: false,
            peer_device_id: 0,
            trust: PeerTrustPolicy::Disabled,
            measurement_hash: 0,
            key_epoch: 0,
            key_k0: 0,
            key_k1: 0,
            replay_high_nonce: 0,
            replay_bitmap: 0,
            ctrl_rx_high_seq: 0,
            ctrl_rx_bitmap: 0,
            ctrl_tx_next_seq: 0,
            last_seen_epoch: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PeerSessionSnapshot {
    pub active: bool,
    pub peer_device_id: u64,
    pub trust: PeerTrustPolicy,
    pub measurement_hash: u64,
    pub key_epoch: u32,
    pub replay_high_nonce: u64,
    pub replay_bitmap: u64,
    pub last_seen_epoch: u64,
}

#[derive(Clone, Copy)]
struct DelegationRecord {
    active: bool,
    token_id: u64,
    issuer_device_id: u64,
    parent_token_hash: u64,
    cap_type: u8,
    delegation_depth: u16,
    rights: u32,
    constraints_flags: u32,
    max_uses: u16,
    max_bytes: u32,
    object_id: u64,
    not_before: u64,
    expires_at: u64,
    accepted_at: u64,
    revoked_epoch: u32,
}

impl DelegationRecord {
    const fn empty() -> Self {
        Self {
            active: false,
            token_id: 0,
            issuer_device_id: 0,
            parent_token_hash: 0,
            cap_type: 0,
            delegation_depth: 0,
            rights: 0,
            constraints_flags: 0,
            max_uses: 0,
            max_bytes: 0,
            object_id: 0,
            not_before: 0,
            expires_at: 0,
            accepted_at: 0,
            revoked_epoch: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct RevocationTombstone {
    active: bool,
    token_id: u64,
    issuer_device_id: u64,
    revocation_epoch: u32,
    revoked_at: u64,
}

impl RevocationTombstone {
    const fn empty() -> Self {
        Self {
            active: false,
            token_id: 0,
            issuer_device_id: 0,
            revocation_epoch: 0,
            revoked_at: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapNetJournalStats {
    pub delegation_records_active: usize,
    pub revocation_tombstones_active: usize,
    pub max_revocation_epoch: u32,
    pub next_revocation_epoch: u32,
}

const CAPNET_FUZZ_SAMPLE_LEN: usize = 32;
const CAPNET_FUZZ_MAX_ITERS: u32 = 10_000;

/// Stable external corpus seeds for CapNet regression replay.
pub const CAPNET_FUZZ_REGRESSION_SEEDS: [u64; 10] = [
    0,
    107_427_055,
    2_105_703_400,
    2_788_077_538,
    2_901_516_716,
    3_418_704_842,
    3_609_752_155,
    3_870_443_198,
    3_735_928_559,
    4_294_967_295,
];

#[derive(Clone, Copy)]
pub struct CapNetFuzzFailure {
    pub iteration: u32,
    pub stage: &'static str,
    pub reason: &'static str,
    pub sample_len: u8,
    pub sample: [u8; CAPNET_FUZZ_SAMPLE_LEN],
}

#[derive(Clone, Copy)]
pub struct CapNetFuzzStats {
    pub iterations: u32,
    pub valid_path_ok: u32,
    pub replay_rejects: u32,
    pub constraint_rejects: u32,
    pub token_decode_ok: u32,
    pub token_decode_err: u32,
    pub control_decode_ok: u32,
    pub control_decode_err: u32,
    pub process_ok: u32,
    pub process_err: u32,
    pub failures: u32,
    pub first_failure: Option<CapNetFuzzFailure>,
}

#[derive(Clone, Copy)]
pub struct CapNetFuzzRegressionStats {
    pub seeds_total: u32,
    pub seeds_passed: u32,
    pub seeds_failed: u32,
    pub total_failures: u32,
    pub total_valid_path_ok: u32,
    pub total_replay_rejects: u32,
    pub total_constraint_rejects: u32,
    pub total_token_decode_err: u32,
    pub total_control_decode_err: u32,
    pub total_process_err: u32,
    pub first_failed_seed: Option<u64>,
    pub first_failure: Option<CapNetFuzzFailure>,
}

#[derive(Clone, Copy)]
pub struct CapNetFuzzSoakStats {
    pub rounds: u32,
    pub rounds_passed: u32,
    pub rounds_failed: u32,
    pub seed_passes: u32,
    pub seed_failures: u32,
    pub total_failures: u32,
    pub total_valid_path_ok: u32,
    pub total_replay_rejects: u32,
    pub total_constraint_rejects: u32,
    pub first_failed_round: Option<u32>,
    pub first_failed_seed: Option<u64>,
    pub first_failure: Option<CapNetFuzzFailure>,
}

static CAPNET_LOCAL_DEVICE_ID: Mutex<u64> = Mutex::new(0);
static CAPNET_PEERS: Mutex<[PeerSession; CAPNET_MAX_PEERS]> =
    Mutex::new([PeerSession::empty(); CAPNET_MAX_PEERS]);
static CAPNET_DELEGATION_RECORDS: Mutex<[DelegationRecord; CAPNET_MAX_DELEGATION_RECORDS]> =
    Mutex::new([DelegationRecord::empty(); CAPNET_MAX_DELEGATION_RECORDS]);
static CAPNET_REVOCATION_TOMBSTONES: Mutex<[RevocationTombstone; CAPNET_MAX_REVOCATION_TOMBSTONES]> =
    Mutex::new([RevocationTombstone::empty(); CAPNET_MAX_REVOCATION_TOMBSTONES]);
static CAPNET_NEXT_REVOCATION_EPOCH: Mutex<u32> = Mutex::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapNetError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    InvalidTemporalWindow,
    InvalidDelegationDepth,
    InvalidUseBudget,
    InvalidByteBudget,
    DecodeOverflow,
    UnknownPeer,
    SessionNotEstablished,
    ReplayDetected,
    MacMismatch,
    MeasurementMismatch,
    TokenExpired,
    LocalIdentityUnset,
    PeerTableFull,
    InvalidControlFrame,
    UnsupportedControlType,
    ControlSequenceReplay,
    ControlMacMismatch,
    PayloadTooLarge,
    TokenIdMismatch,
    LeaseInstallFailed,
    RevokedToken,
    DelegationParentMissing,
    DelegationDepthMismatch,
    DelegationRightsEscalation,
    DelegationTypeMismatch,
    DelegationObjectMismatch,
    DelegationTemporalWindowViolation,
    DelegationConstraintViolation,
    JournalDecodeFailed,
}

impl CapNetError {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapNetError::InvalidLength => "Invalid token length",
            CapNetError::InvalidMagic => "Invalid token magic",
            CapNetError::UnsupportedVersion => "Unsupported token version",
            CapNetError::UnsupportedAlgorithm => "Unsupported token algorithm",
            CapNetError::InvalidTemporalWindow => "Invalid token temporal window",
            CapNetError::InvalidDelegationDepth => "Invalid token delegation depth",
            CapNetError::InvalidUseBudget => "Invalid token use budget",
            CapNetError::InvalidByteBudget => "Invalid token byte budget",
            CapNetError::DecodeOverflow => "Token decoder overflow",
            CapNetError::UnknownPeer => "Unknown CapNet peer",
            CapNetError::SessionNotEstablished => "Peer session not established",
            CapNetError::ReplayDetected => "Token replay detected",
            CapNetError::MacMismatch => "Token MAC verification failed",
            CapNetError::MeasurementMismatch => "Peer measurement mismatch",
            CapNetError::TokenExpired => "Token expired or not yet valid",
            CapNetError::LocalIdentityUnset => "Local CapNet identity not initialized",
            CapNetError::PeerTableFull => "CapNet peer table full",
            CapNetError::InvalidControlFrame => "Invalid CapNet control frame",
            CapNetError::UnsupportedControlType => "Unsupported CapNet control type",
            CapNetError::ControlSequenceReplay => "CapNet control sequence replay",
            CapNetError::ControlMacMismatch => "CapNet control MAC verification failed",
            CapNetError::PayloadTooLarge => "CapNet control payload too large",
            CapNetError::TokenIdMismatch => "CapNet token_id mismatch",
            CapNetError::LeaseInstallFailed => "Remote lease install failed",
            CapNetError::RevokedToken => "CapNet token is revoked",
            CapNetError::DelegationParentMissing => "CapNet delegation parent missing",
            CapNetError::DelegationDepthMismatch => "CapNet delegation depth mismatch",
            CapNetError::DelegationRightsEscalation => "CapNet delegation rights escalation",
            CapNetError::DelegationTypeMismatch => "CapNet delegation type mismatch",
            CapNetError::DelegationObjectMismatch => "CapNet delegation object mismatch",
            CapNetError::DelegationTemporalWindowViolation => "CapNet delegation temporal window violation",
            CapNetError::DelegationConstraintViolation => "CapNet delegation constraint violation",
            CapNetError::JournalDecodeFailed => "CapNet revocation journal decode failed",
        }
    }
}

/// Portable network capability token.
///
/// Semantics:
/// - `issuer_device_id` and `subject_device_id` identify delegation endpoints.
/// - `rights` and `cap_type` define authority.
/// - `parent_token_hash` links delegation chains.
/// - `measurement_hash` and `session_id` support attestation/session binding.
/// - `constraints_flags`, `max_uses`, `max_bytes`, `resource_quota` define policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityTokenV1 {
    pub version: u8,
    pub alg_id: u8,
    pub cap_type: u8,
    pub token_flags: u8,
    pub issuer_device_id: u64,
    pub subject_device_id: u64,
    pub object_id: u64,
    pub rights: u32,
    pub constraints_flags: u32,
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub nonce: u64,
    pub delegation_depth: u16,
    pub max_uses: u16,
    pub parent_token_hash: u64,
    pub measurement_hash: u64,
    pub session_id: u32,
    pub context: u32,
    pub max_bytes: u32,
    pub resource_quota: u32,
    pub mac: u64,
}

impl CapabilityTokenV1 {
    pub const fn empty() -> Self {
        CapabilityTokenV1 {
            version: CAPNET_TOKEN_VERSION_V1,
            alg_id: CAPNET_ALG_SIPHASH24_KERNEL,
            cap_type: 0,
            token_flags: 0,
            issuer_device_id: 0,
            subject_device_id: 0,
            object_id: 0,
            rights: 0,
            constraints_flags: 0,
            issued_at: 0,
            not_before: 0,
            expires_at: 0,
            nonce: 0,
            delegation_depth: 0,
            max_uses: 0,
            parent_token_hash: 0,
            measurement_hash: 0,
            session_id: 0,
            context: 0,
            max_bytes: 0,
            resource_quota: 0,
            mac: 0,
        }
    }

    pub fn is_temporally_valid(&self, now_epoch: u64) -> bool {
        now_epoch >= self.not_before && now_epoch <= self.expires_at
    }

    pub fn validate_semantics(&self) -> Result<(), CapNetError> {
        if self.version != CAPNET_TOKEN_VERSION_V1 {
            return Err(CapNetError::UnsupportedVersion);
        }
        if self.alg_id != CAPNET_ALG_SIPHASH24_KERNEL {
            return Err(CapNetError::UnsupportedAlgorithm);
        }
        if self.not_before < self.issued_at || self.expires_at < self.not_before {
            return Err(CapNetError::InvalidTemporalWindow);
        }
        if self.delegation_depth > CAPNET_MAX_DELEGATION_DEPTH {
            return Err(CapNetError::InvalidDelegationDepth);
        }
        if (self.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE) != 0 && self.max_uses == 0 {
            return Err(CapNetError::InvalidUseBudget);
        }
        if (self.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA) != 0 && self.max_bytes == 0 {
            return Err(CapNetError::InvalidByteBudget);
        }
        Ok(())
    }

    /// Canonical deterministic identifier for dedup/revocation indexing.
    /// This excludes the MAC so the ID remains stable across re-signing.
    pub fn token_id(&self) -> u64 {
        fnv1a64(self.encode_without_mac().as_slice())
    }

    /// Canonical bytes used for MAC/signature input.
    pub fn encode_without_mac(&self) -> [u8; CAPNET_TOKEN_V1_BODY_LEN] {
        let mut out = [0u8; CAPNET_TOKEN_V1_BODY_LEN];
        let mut offset = 0usize;

        write_u32(&mut out, &mut offset, CAPNET_TOKEN_MAGIC);
        write_u8(&mut out, &mut offset, self.version);
        write_u8(&mut out, &mut offset, self.alg_id);
        write_u8(&mut out, &mut offset, self.cap_type);
        write_u8(&mut out, &mut offset, self.token_flags);
        write_u64(&mut out, &mut offset, self.issuer_device_id);
        write_u64(&mut out, &mut offset, self.subject_device_id);
        write_u64(&mut out, &mut offset, self.object_id);
        write_u32(&mut out, &mut offset, self.rights);
        write_u32(&mut out, &mut offset, self.constraints_flags);
        write_u64(&mut out, &mut offset, self.issued_at);
        write_u64(&mut out, &mut offset, self.not_before);
        write_u64(&mut out, &mut offset, self.expires_at);
        write_u64(&mut out, &mut offset, self.nonce);
        write_u16(&mut out, &mut offset, self.delegation_depth);
        write_u16(&mut out, &mut offset, self.max_uses);
        write_u64(&mut out, &mut offset, self.parent_token_hash);
        write_u64(&mut out, &mut offset, self.measurement_hash);
        write_u32(&mut out, &mut offset, self.session_id);
        write_u32(&mut out, &mut offset, self.context);
        write_u32(&mut out, &mut offset, self.max_bytes);
        write_u32(&mut out, &mut offset, self.resource_quota);

        out
    }

    pub fn encode(&self) -> [u8; CAPNET_TOKEN_V1_LEN] {
        let mut out = [0u8; CAPNET_TOKEN_V1_LEN];
        let body = self.encode_without_mac();
        out[..CAPNET_TOKEN_V1_BODY_LEN].copy_from_slice(&body);
        out[CAPNET_TOKEN_V1_BODY_LEN..CAPNET_TOKEN_V1_LEN].copy_from_slice(&self.mac.to_le_bytes());
        out
    }

    pub fn decode_checked(bytes: &[u8]) -> Result<Self, CapNetError> {
        if bytes.len() != CAPNET_TOKEN_V1_LEN {
            return Err(CapNetError::InvalidLength);
        }

        let mut offset = 0usize;
        let magic = read_u32(bytes, &mut offset)?;
        if magic != CAPNET_TOKEN_MAGIC {
            return Err(CapNetError::InvalidMagic);
        }

        let token = CapabilityTokenV1 {
            version: read_u8(bytes, &mut offset)?,
            alg_id: read_u8(bytes, &mut offset)?,
            cap_type: read_u8(bytes, &mut offset)?,
            token_flags: read_u8(bytes, &mut offset)?,
            issuer_device_id: read_u64(bytes, &mut offset)?,
            subject_device_id: read_u64(bytes, &mut offset)?,
            object_id: read_u64(bytes, &mut offset)?,
            rights: read_u32(bytes, &mut offset)?,
            constraints_flags: read_u32(bytes, &mut offset)?,
            issued_at: read_u64(bytes, &mut offset)?,
            not_before: read_u64(bytes, &mut offset)?,
            expires_at: read_u64(bytes, &mut offset)?,
            nonce: read_u64(bytes, &mut offset)?,
            delegation_depth: read_u16(bytes, &mut offset)?,
            max_uses: read_u16(bytes, &mut offset)?,
            parent_token_hash: read_u64(bytes, &mut offset)?,
            measurement_hash: read_u64(bytes, &mut offset)?,
            session_id: read_u32(bytes, &mut offset)?,
            context: read_u32(bytes, &mut offset)?,
            max_bytes: read_u32(bytes, &mut offset)?,
            resource_quota: read_u32(bytes, &mut offset)?,
            mac: read_u64(bytes, &mut offset)?,
        };

        token.validate_semantics()?;
        Ok(token)
    }

    /// Phase 1 helper: sign with kernel boot key.
    pub fn sign_with_kernel_key(&mut self) {
        let payload = self.encode_without_mac();
        self.mac = security::security().cap_token_sign(&payload);
    }

    /// Phase 1 helper: verify with kernel boot key.
    pub fn verify_with_kernel_key(&self) -> bool {
        let payload = self.encode_without_mac();
        security::security().cap_token_verify(&payload, self.mac)
    }

    /// Phase 2 helper: sign with per-peer session key.
    pub fn sign_with_session_key(&mut self, k0: u64, k1: u64) {
        let payload = self.encode_without_mac();
        self.mac = security::security().cap_token_sign_with_key(k0, k1, &payload);
    }

    /// Phase 2 helper: verify with per-peer session key.
    pub fn verify_with_session_key(&self, k0: u64, k1: u64) -> bool {
        let payload = self.encode_without_mac();
        security::security().cap_token_verify_with_key(k0, k1, &payload, self.mac)
    }
}

fn audit_capnet(event: SecurityEvent, context: u64) {
    security::security().log_event(
        AuditEntry::new(event, ProcessId(0), 0).with_context(context),
    );
}

fn control_mac_input(
    frame: &CapNetControlFrame,
    out: &mut [u8; CAPNET_CTRL_HEADER_NO_MAC_LEN + CAPNET_CTRL_MAX_PAYLOAD],
) -> Result<usize, CapNetError> {
    let payload_len = frame.payload_len as usize;
    if payload_len > CAPNET_CTRL_MAX_PAYLOAD {
        return Err(CapNetError::PayloadTooLarge);
    }

    let mut offset = 0usize;
    write_u32(out, &mut offset, CAPNET_CTRL_MAGIC);
    write_u8(out, &mut offset, CAPNET_CTRL_VERSION);
    write_u8(out, &mut offset, frame.msg_type as u8);
    write_u8(out, &mut offset, frame.flags);
    write_u8(out, &mut offset, 0);
    write_u32(out, &mut offset, frame.seq);
    write_u32(out, &mut offset, frame.ack);
    write_u64(out, &mut offset, frame.issuer_device_id);
    write_u64(out, &mut offset, frame.subject_device_id);
    write_u64(out, &mut offset, frame.token_id);
    write_u32(out, &mut offset, frame.key_epoch);
    write_u16(out, &mut offset, frame.payload_len);
    write_u16(out, &mut offset, 0);
    out[offset..offset + payload_len].copy_from_slice(&frame.payload[..payload_len]);
    offset += payload_len;
    Ok(offset)
}

fn compute_control_mac(k0: u64, k1: u64, frame: &CapNetControlFrame) -> Result<u64, CapNetError> {
    let mut input = [0u8; CAPNET_CTRL_HEADER_NO_MAC_LEN + CAPNET_CTRL_MAX_PAYLOAD];
    let len = control_mac_input(frame, &mut input)?;
    Ok(security::security().cap_token_sign_with_key(k0, k1, &input[..len]))
}

fn encode_control_frame(frame: &CapNetControlFrame) -> Result<([u8; CAPNET_CTRL_MAX_FRAME_LEN], usize), CapNetError> {
    let payload_len = frame.payload_len as usize;
    if payload_len > CAPNET_CTRL_MAX_PAYLOAD {
        return Err(CapNetError::PayloadTooLarge);
    }

    let mut out = [0u8; CAPNET_CTRL_MAX_FRAME_LEN];
    let mut offset = 0usize;
    write_u32(&mut out, &mut offset, CAPNET_CTRL_MAGIC);
    write_u8(&mut out, &mut offset, CAPNET_CTRL_VERSION);
    write_u8(&mut out, &mut offset, frame.msg_type as u8);
    write_u8(&mut out, &mut offset, frame.flags);
    write_u8(&mut out, &mut offset, 0);
    write_u32(&mut out, &mut offset, frame.seq);
    write_u32(&mut out, &mut offset, frame.ack);
    write_u64(&mut out, &mut offset, frame.issuer_device_id);
    write_u64(&mut out, &mut offset, frame.subject_device_id);
    write_u64(&mut out, &mut offset, frame.token_id);
    write_u32(&mut out, &mut offset, frame.key_epoch);
    write_u16(&mut out, &mut offset, frame.payload_len);
    write_u16(&mut out, &mut offset, 0);
    write_u64(&mut out, &mut offset, frame.frame_mac);
    out[offset..offset + payload_len].copy_from_slice(&frame.payload[..payload_len]);
    offset += payload_len;
    Ok((out, offset))
}

pub fn decode_control_frame(bytes: &[u8]) -> Result<CapNetControlFrame, CapNetError> {
    if bytes.len() < CAPNET_CTRL_HEADER_LEN {
        return Err(CapNetError::InvalidControlFrame);
    }

    let mut offset = 0usize;
    let magic = read_u32(bytes, &mut offset)?;
    if magic != CAPNET_CTRL_MAGIC {
        return Err(CapNetError::InvalidControlFrame);
    }
    let version = read_u8(bytes, &mut offset)?;
    if version != CAPNET_CTRL_VERSION {
        return Err(CapNetError::InvalidControlFrame);
    }
    let msg_raw = read_u8(bytes, &mut offset)?;
    let msg_type = CapNetControlType::from_u8(msg_raw).ok_or(CapNetError::UnsupportedControlType)?;
    let flags = read_u8(bytes, &mut offset)?;
    let _reserved = read_u8(bytes, &mut offset)?;
    let seq = read_u32(bytes, &mut offset)?;
    let ack = read_u32(bytes, &mut offset)?;
    let issuer_device_id = read_u64(bytes, &mut offset)?;
    let subject_device_id = read_u64(bytes, &mut offset)?;
    let token_id = read_u64(bytes, &mut offset)?;
    let key_epoch = read_u32(bytes, &mut offset)?;
    let payload_len = read_u16(bytes, &mut offset)?;
    let _reserved2 = read_u16(bytes, &mut offset)?;
    let frame_mac = read_u64(bytes, &mut offset)?;

    let payload_len_usize = payload_len as usize;
    if payload_len_usize > CAPNET_CTRL_MAX_PAYLOAD {
        return Err(CapNetError::PayloadTooLarge);
    }
    let expected = CAPNET_CTRL_HEADER_LEN
        .checked_add(payload_len_usize)
        .ok_or(CapNetError::InvalidControlFrame)?;
    if bytes.len() != expected {
        return Err(CapNetError::InvalidControlFrame);
    }
    let mut payload = [0u8; CAPNET_CTRL_MAX_PAYLOAD];
    if payload_len_usize > 0 {
        payload[..payload_len_usize].copy_from_slice(&bytes[offset..expected]);
    }

    Ok(CapNetControlFrame {
        msg_type,
        flags,
        seq,
        ack,
        issuer_device_id,
        subject_device_id,
        token_id,
        key_epoch,
        payload_len,
        payload,
        frame_mac,
    })
}

fn next_control_tx_seq(peer: &mut PeerSession) -> u32 {
    let next = peer.ctrl_tx_next_seq.wrapping_add(1).max(1);
    peer.ctrl_tx_next_seq = next;
    next
}

fn accept_control_seq(peer: &mut PeerSession, seq: u32) -> bool {
    if seq == 0 {
        return false;
    }
    if peer.ctrl_rx_high_seq == 0 {
        peer.ctrl_rx_high_seq = seq;
        peer.ctrl_rx_bitmap = 1;
        return true;
    }
    if seq > peer.ctrl_rx_high_seq {
        let shift = (seq - peer.ctrl_rx_high_seq) as u64;
        if shift >= 64 {
            peer.ctrl_rx_bitmap = 1;
        } else {
            peer.ctrl_rx_bitmap = (peer.ctrl_rx_bitmap << shift) | 1;
        }
        peer.ctrl_rx_high_seq = seq;
        return true;
    }
    let delta = (peer.ctrl_rx_high_seq - seq) as u64;
    if delta >= 64 {
        return false;
    }
    let bit = 1u64 << delta;
    if (peer.ctrl_rx_bitmap & bit) != 0 {
        return false;
    }
    peer.ctrl_rx_bitmap |= bit;
    true
}

fn build_control_frame_for_peer(
    peer_device_id: u64,
    msg_type: CapNetControlType,
    flags: u8,
    ack: u32,
    token_id: u64,
    payload: &[u8],
) -> Result<EncodedControlFrame, CapNetError> {
    if payload.len() > CAPNET_CTRL_MAX_PAYLOAD {
        return Err(CapNetError::PayloadTooLarge);
    }
    let local = local_device_id().ok_or(CapNetError::LocalIdentityUnset)?;
    let mut peers = CAPNET_PEERS.lock();
    let idx = find_peer_index_mut(&mut peers, peer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = &mut peers[idx];
    if peer.key_epoch == 0 {
        return Err(CapNetError::SessionNotEstablished);
    }

    let seq = next_control_tx_seq(peer);
    let mut frame = CapNetControlFrame::empty();
    frame.msg_type = msg_type;
    frame.flags = flags;
    frame.seq = seq;
    frame.ack = ack;
    frame.issuer_device_id = local;
    frame.subject_device_id = peer_device_id;
    frame.token_id = token_id;
    frame.key_epoch = peer.key_epoch;
    frame.payload_len = payload.len() as u16;
    if !payload.is_empty() {
        frame.payload[..payload.len()].copy_from_slice(payload);
    }
    frame.frame_mac = compute_control_mac(peer.key_k0, peer.key_k1, &frame)?;
    peer.last_seen_epoch = crate::pit::get_ticks() as u64;
    let (bytes, len) = encode_control_frame(&frame)?;
    Ok(EncodedControlFrame {
        len,
        bytes,
        seq,
        token_id,
    })
}

pub fn build_hello_frame(peer_device_id: u64, ack: u32) -> Result<EncodedControlFrame, CapNetError> {
    build_control_frame_for_peer(peer_device_id, CapNetControlType::Hello, 0, ack, 0, &[])
}

pub fn build_attest_frame(peer_device_id: u64, ack: u32) -> Result<EncodedControlFrame, CapNetError> {
    build_control_frame_for_peer(peer_device_id, CapNetControlType::Attest, 0, ack, 0, &[])
}

pub fn build_heartbeat_frame(
    peer_device_id: u64,
    ack: u32,
    ack_only: bool,
) -> Result<EncodedControlFrame, CapNetError> {
    let flags = if ack_only { CAPNET_CTRL_FLAG_ACK_ONLY } else { 0 };
    build_control_frame_for_peer(peer_device_id, CapNetControlType::Heartbeat, flags, ack, 0, &[])
}

pub fn build_token_offer_frame(
    peer_device_id: u64,
    ack: u32,
    token: &mut CapabilityTokenV1,
) -> Result<EncodedControlFrame, CapNetError> {
    sign_outgoing_token_for_peer(peer_device_id, token)?;
    let token_id = token.token_id();
    let payload = token.encode();
    build_control_frame_for_peer(
        peer_device_id,
        CapNetControlType::TokenOffer,
        0,
        ack,
        token_id,
        &payload,
    )
}

pub fn build_token_accept_frame(
    peer_device_id: u64,
    ack: u32,
    token_id: u64,
) -> Result<EncodedControlFrame, CapNetError> {
    build_control_frame_for_peer(
        peer_device_id,
        CapNetControlType::TokenAccept,
        CAPNET_CTRL_FLAG_ACK_ONLY,
        ack,
        token_id,
        &[],
    )
}

pub fn build_token_revoke_frame(
    peer_device_id: u64,
    ack: u32,
    token_id: u64,
) -> Result<EncodedControlFrame, CapNetError> {
    build_control_frame_for_peer(
        peer_device_id,
        CapNetControlType::TokenRevoke,
        0,
        ack,
        token_id,
        &[],
    )
}

fn is_token_revoked(issuer_device_id: u64, token_id: u64) -> bool {
    let tombstones = CAPNET_REVOCATION_TOMBSTONES.lock();
    let mut i = 0usize;
    while i < tombstones.len() {
        let t = tombstones[i];
        if t.active && t.token_id == token_id && t.issuer_device_id == issuer_device_id {
            return true;
        }
        i += 1;
    }
    false
}

fn verify_delegation_chain(token: &CapabilityTokenV1, now_epoch: u64) -> Result<(), CapNetError> {
    if token.delegation_depth == 0 {
        if token.parent_token_hash != 0 {
            return Err(CapNetError::DelegationParentMissing);
        }
        return Ok(());
    }

    if token.parent_token_hash == 0 {
        return Err(CapNetError::DelegationParentMissing);
    }

    let records = CAPNET_DELEGATION_RECORDS.lock();
    let mut parent = None;
    let mut i = 0usize;
    while i < records.len() {
        let rec = records[i];
        if rec.active
            && rec.token_id == token.parent_token_hash
            && rec.issuer_device_id == token.issuer_device_id
        {
            parent = Some(rec);
            break;
        }
        i += 1;
    }
    let parent = parent.ok_or(CapNetError::DelegationParentMissing)?;

    if parent.revoked_epoch != 0 {
        return Err(CapNetError::RevokedToken);
    }
    if now_epoch < parent.not_before || now_epoch > parent.expires_at {
        return Err(CapNetError::TokenExpired);
    }
    if token.delegation_depth != parent.delegation_depth.saturating_add(1) {
        return Err(CapNetError::DelegationDepthMismatch);
    }
    if token.cap_type != parent.cap_type {
        return Err(CapNetError::DelegationTypeMismatch);
    }
    if token.object_id != parent.object_id {
        return Err(CapNetError::DelegationObjectMismatch);
    }
    if (token.rights & !parent.rights) != 0 {
        return Err(CapNetError::DelegationRightsEscalation);
    }
    if token.not_before < parent.not_before || token.expires_at > parent.expires_at {
        return Err(CapNetError::DelegationTemporalWindowViolation);
    }
    if (parent.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE) != 0 {
        if (token.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE) == 0 {
            return Err(CapNetError::DelegationConstraintViolation);
        }
        if token.max_uses == 0 || token.max_uses > parent.max_uses {
            return Err(CapNetError::DelegationConstraintViolation);
        }
    }
    if (parent.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA) != 0 {
        if (token.constraints_flags & CAPNET_CONSTRAINT_REQUIRE_BYTE_QUOTA) == 0 {
            return Err(CapNetError::DelegationConstraintViolation);
        }
        if token.max_bytes == 0 || token.max_bytes > parent.max_bytes {
            return Err(CapNetError::DelegationConstraintViolation);
        }
    }

    Ok(())
}

fn record_accepted_token(token: &CapabilityTokenV1, now_epoch: u64) {
    let token_id = token.token_id();
    let mut records = CAPNET_DELEGATION_RECORDS.lock();

    let mut existing_idx = None;
    let mut free_idx = None;
    let mut oldest_idx = 0usize;
    let mut oldest_at = u64::MAX;
    let mut i = 0usize;
    while i < records.len() {
        let rec = records[i];
        if rec.active
            && rec.token_id == token_id
            && rec.issuer_device_id == token.issuer_device_id
        {
            existing_idx = Some(i);
            break;
        }
        if !rec.active && free_idx.is_none() {
            free_idx = Some(i);
        }
        if rec.accepted_at < oldest_at {
            oldest_at = rec.accepted_at;
            oldest_idx = i;
        }
        i += 1;
    }

    let idx = existing_idx.or(free_idx).unwrap_or(oldest_idx);
    records[idx] = DelegationRecord {
        active: true,
        token_id,
        issuer_device_id: token.issuer_device_id,
        parent_token_hash: token.parent_token_hash,
        cap_type: token.cap_type,
        delegation_depth: token.delegation_depth,
        rights: token.rights,
        constraints_flags: token.constraints_flags,
        max_uses: token.max_uses,
        max_bytes: token.max_bytes,
        object_id: token.object_id,
        not_before: token.not_before,
        expires_at: token.expires_at,
        accepted_at: now_epoch,
        revoked_epoch: 0,
    };
}

fn put_tombstone(
    token_id: u64,
    issuer_device_id: u64,
    revocation_epoch: u32,
    revoked_at: u64,
) {
    let mut tombstones = CAPNET_REVOCATION_TOMBSTONES.lock();
    let mut existing_idx = None;
    let mut free_idx = None;
    let mut oldest_idx = 0usize;
    let mut oldest_at = u64::MAX;

    let mut i = 0usize;
    while i < tombstones.len() {
        let t = tombstones[i];
        if t.active && t.token_id == token_id && t.issuer_device_id == issuer_device_id {
            existing_idx = Some(i);
            break;
        }
        if !t.active && free_idx.is_none() {
            free_idx = Some(i);
        }
        if t.revoked_at < oldest_at {
            oldest_at = t.revoked_at;
            oldest_idx = i;
        }
        i += 1;
    }

    let idx = existing_idx.or(free_idx).unwrap_or(oldest_idx);
    tombstones[idx] = RevocationTombstone {
        active: true,
        token_id,
        issuer_device_id,
        revocation_epoch,
        revoked_at,
    };
}

fn append_revocation_log(
    token_id: u64,
    issuer_device_id: u64,
    revocation_epoch: u32,
    revoked_at: u64,
) {
    let mut payload = [0u8; CAPNET_REVOKE_LOG_PAYLOAD_LEN];
    payload[0..4].copy_from_slice(&CAPNET_REVOKE_LOG_MAGIC.to_le_bytes());
    payload[4] = CAPNET_REVOKE_LOG_VERSION;
    payload[5] = 0;
    payload[6] = 0;
    payload[7] = 0;
    payload[8..16].copy_from_slice(&token_id.to_le_bytes());
    payload[16..24].copy_from_slice(&issuer_device_id.to_le_bytes());
    payload[24..28].copy_from_slice(&revocation_epoch.to_le_bytes());
    payload[28..36].copy_from_slice(&revoked_at.to_le_bytes());

    if let Ok(record) =
        persistence::LogRecord::new(persistence::RecordType::ComponentEvent, &payload)
    {
        let cap = persistence::StoreCapability::new(0xCA70_0001, persistence::StoreRights::all());
        let mut service = persistence::persistence().lock();
        if service.append_log(&cap, record).is_err() {
            audit_capnet(SecurityEvent::IntegrityCheckFailed, token_id);
        }
    }
}

fn decode_revocation_log(payload: &[u8]) -> Option<RevocationTombstone> {
    if payload.len() != CAPNET_REVOKE_LOG_PAYLOAD_LEN {
        return None;
    }
    let magic = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    if magic != CAPNET_REVOKE_LOG_MAGIC {
        return None;
    }
    if payload[4] != CAPNET_REVOKE_LOG_VERSION {
        return None;
    }
    let token_id = u64::from_le_bytes(payload[8..16].try_into().ok()?);
    let issuer_device_id = u64::from_le_bytes(payload[16..24].try_into().ok()?);
    let revocation_epoch = u32::from_le_bytes(payload[24..28].try_into().ok()?);
    let revoked_at = u64::from_le_bytes(payload[28..36].try_into().ok()?);
    Some(RevocationTombstone {
        active: true,
        token_id,
        issuer_device_id,
        revocation_epoch,
        revoked_at,
    })
}

fn rebuild_revocation_journal() {
    {
        let mut tombstones = CAPNET_REVOCATION_TOMBSTONES.lock();
        let mut i = 0usize;
        while i < tombstones.len() {
            tombstones[i] = RevocationTombstone::empty();
            i += 1;
        }
    }

    let cap = persistence::StoreCapability::new(0xCA70_0001, persistence::StoreRights::all());
    let mut max_epoch = 0u32;
    let service = persistence::persistence().lock();
    if let Ok(records) = service.read_log(&cap, 0, persistence::MAX_LOG_RECORDS) {
        for rec in records {
            if let Some(tombstone) = decode_revocation_log(rec.payload()) {
                if tombstone.revocation_epoch > max_epoch {
                    max_epoch = tombstone.revocation_epoch;
                }
                put_tombstone(
                    tombstone.token_id,
                    tombstone.issuer_device_id,
                    tombstone.revocation_epoch,
                    tombstone.revoked_at,
                );
            }
        }
    }
    drop(service);
    let mut next = CAPNET_NEXT_REVOCATION_EPOCH.lock();
    *next = max_epoch.saturating_add(1).max(1);
}

fn apply_token_revocation(
    issuer_device_id: u64,
    token_id: u64,
    now_epoch: u64,
) -> u32 {
    let revocation_epoch = {
        let mut next = CAPNET_NEXT_REVOCATION_EPOCH.lock();
        let epoch = (*next).max(1);
        *next = (*next).saturating_add(1).max(1);
        epoch
    };

    let mut revoked_ids = [0u64; CAPNET_MAX_DELEGATION_RECORDS];
    let mut revoked_count = 1usize;
    revoked_ids[0] = token_id;

    {
        let mut records = CAPNET_DELEGATION_RECORDS.lock();
        let mut changed = true;
        while changed {
            changed = false;
            let mut i = 0usize;
            while i < records.len() {
                let rec = &mut records[i];
                if !rec.active || rec.issuer_device_id != issuer_device_id {
                    i += 1;
                    continue;
                }

                let mut should_revoke = false;
                let mut j = 0usize;
                while j < revoked_count {
                    if rec.token_id == revoked_ids[j] || rec.parent_token_hash == revoked_ids[j] {
                        should_revoke = true;
                        break;
                    }
                    j += 1;
                }

                if should_revoke {
                    rec.revoked_epoch = revocation_epoch;
                    let mut seen = false;
                    let mut k = 0usize;
                    while k < revoked_count {
                        if revoked_ids[k] == rec.token_id {
                            seen = true;
                            break;
                        }
                        k += 1;
                    }
                    if !seen && revoked_count < revoked_ids.len() {
                        revoked_ids[revoked_count] = rec.token_id;
                        revoked_count += 1;
                        changed = true;
                    }
                }
                i += 1;
            }
        }
    }

    let mut i = 0usize;
    while i < revoked_count {
        let id = revoked_ids[i];
        put_tombstone(id, issuer_device_id, revocation_epoch, now_epoch);
        append_revocation_log(id, issuer_device_id, revocation_epoch, now_epoch);
        let _ = crate::capability::revoke_remote_lease_by_token(id);
        i += 1;
    }

    revocation_epoch
}

pub fn process_incoming_control_payload(
    bytes: &[u8],
    now_epoch: u64,
) -> Result<ControlRxResult, CapNetError> {
    let frame = decode_control_frame(bytes)?;
    let local = local_device_id().ok_or(CapNetError::LocalIdentityUnset)?;
    if frame.subject_device_id != local {
        audit_capnet(SecurityEvent::InvalidCapability, frame.issuer_device_id);
        return Err(CapNetError::UnknownPeer);
    }
    let mut peers = CAPNET_PEERS.lock();
    let idx = find_peer_index_mut(&mut peers, frame.issuer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = &mut peers[idx];
    if peer.key_epoch == 0 || frame.key_epoch != peer.key_epoch {
        audit_capnet(SecurityEvent::InvalidCapability, frame.issuer_device_id);
        return Err(CapNetError::SessionNotEstablished);
    }
    let expected = compute_control_mac(peer.key_k0, peer.key_k1, &frame)?;
    if expected != frame.frame_mac {
        audit_capnet(SecurityEvent::IntegrityCheckFailed, frame.issuer_device_id);
        return Err(CapNetError::ControlMacMismatch);
    }
    if !accept_control_seq(peer, frame.seq) {
        audit_capnet(SecurityEvent::RateLimitExceeded, frame.issuer_device_id);
        return Err(CapNetError::ControlSequenceReplay);
    }
    peer.last_seen_epoch = now_epoch;
    drop(peers);

    match frame.msg_type {
        CapNetControlType::Hello | CapNetControlType::Attest | CapNetControlType::Heartbeat => {
            if frame.payload_len != 0 {
                audit_capnet(SecurityEvent::InvalidCapability, frame.token_id);
                return Err(CapNetError::InvalidControlFrame);
            }
        }
        CapNetControlType::TokenOffer => {
            if frame.payload_len as usize != CAPNET_TOKEN_V1_LEN {
                audit_capnet(SecurityEvent::InvalidCapability, frame.token_id);
                return Err(CapNetError::InvalidControlFrame);
            }
            let token = CapabilityTokenV1::decode_checked(&frame.payload[..CAPNET_TOKEN_V1_LEN])?;
            if token.token_id() != frame.token_id {
                audit_capnet(SecurityEvent::IntegrityCheckFailed, frame.token_id);
                return Err(CapNetError::TokenIdMismatch);
            }
            verify_incoming_token(&token, now_epoch)?;
            if is_token_revoked(token.issuer_device_id, token.token_id()) {
                audit_capnet(SecurityEvent::CapabilityRevoked, frame.token_id);
                return Err(CapNetError::RevokedToken);
            }
            verify_delegation_chain(&token, now_epoch)?;
            crate::capability::install_remote_lease_from_capnet_token(&token)
                .map_err(|_| CapNetError::LeaseInstallFailed)?;
            record_accepted_token(&token, now_epoch);
            audit_capnet(SecurityEvent::CapabilityTransferred, frame.token_id);
        }
        CapNetControlType::TokenAccept => {
            if frame.payload_len != 0 {
                audit_capnet(SecurityEvent::InvalidCapability, frame.token_id);
                return Err(CapNetError::InvalidControlFrame);
            }
            audit_capnet(SecurityEvent::CapabilityUsed, frame.token_id);
        }
        CapNetControlType::TokenRevoke => {
            if frame.payload_len != 0 {
                audit_capnet(SecurityEvent::InvalidCapability, frame.token_id);
                return Err(CapNetError::InvalidControlFrame);
            }
            let _ = apply_token_revocation(frame.issuer_device_id, frame.token_id, now_epoch);
            audit_capnet(SecurityEvent::CapabilityRevoked, frame.token_id);
        }
    }

    Ok(ControlRxResult {
        msg_type: frame.msg_type,
        peer_device_id: frame.issuer_device_id,
        seq: frame.seq,
        ack: frame.ack,
        token_id: frame.token_id,
        ack_only: (frame.flags & CAPNET_CTRL_FLAG_ACK_ONLY) != 0,
    })
}

pub fn init() {
    let mut local = CAPNET_LOCAL_DEVICE_ID.lock();
    if *local != 0 {
        return;
    }

    let hi = security::security().random_u32() as u64;
    let lo = security::security().random_u32() as u64;
    let mut device_id = (hi << 32) | lo;
    device_id ^= (crate::pit::get_ticks() as u64) << 1;
    if device_id == 0 {
        device_id = 1;
    }
    *local = device_id;
    drop(local);

    // Load persisted revocation tombstones so revoked token IDs remain denied
    // after reboot/restart.
    rebuild_revocation_journal();
}

pub fn local_device_id() -> Option<u64> {
    let local = *CAPNET_LOCAL_DEVICE_ID.lock();
    if local == 0 {
        None
    } else {
        Some(local)
    }
}

pub fn register_peer(
    peer_device_id: u64,
    trust: PeerTrustPolicy,
    measurement_hash: u64,
) -> Result<(), CapNetError> {
    if peer_device_id == 0 {
        return Err(CapNetError::UnknownPeer);
    }

    let mut peers = CAPNET_PEERS.lock();
    let mut empty_idx = None;
    let mut i = 0usize;
    while i < peers.len() {
        let entry = &mut peers[i];
        if entry.active && entry.peer_device_id == peer_device_id {
            entry.trust = trust;
            entry.measurement_hash = measurement_hash;
            return Ok(());
        }
        if !entry.active && empty_idx.is_none() {
            empty_idx = Some(i);
        }
        i += 1;
    }

    if let Some(idx) = empty_idx {
        peers[idx] = PeerSession {
            active: true,
            peer_device_id,
            trust,
            measurement_hash,
            key_epoch: 0,
            key_k0: 0,
            key_k1: 0,
            replay_high_nonce: 0,
            replay_bitmap: 0,
            ctrl_rx_high_seq: 0,
            ctrl_rx_bitmap: 0,
            ctrl_tx_next_seq: 0,
            last_seen_epoch: 0,
        };
        Ok(())
    } else {
        Err(CapNetError::PeerTableFull)
    }
}

pub fn establish_peer_session(
    peer_device_id: u64,
    nonce_local: u64,
    nonce_remote: u64,
    measurement_hash: u64,
) -> Result<u32, CapNetError> {
    if peer_device_id == 0 {
        return Err(CapNetError::UnknownPeer);
    }

    let mut peers = CAPNET_PEERS.lock();
    let idx = find_peer_index_mut(&mut peers, peer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = &mut peers[idx];

    if peer.measurement_hash != 0 && measurement_hash != 0 && peer.measurement_hash != measurement_hash {
        if peer.trust == PeerTrustPolicy::Enforce {
            return Err(CapNetError::MeasurementMismatch);
        }
    } else if measurement_hash != 0 {
        peer.measurement_hash = measurement_hash;
    }

    let next_epoch = peer.key_epoch.wrapping_add(1).max(1);
    let key = security::security().capnet_derive_session_key(
        peer_device_id,
        nonce_local,
        nonce_remote,
        peer.measurement_hash,
        next_epoch,
    );
    peer.key_epoch = next_epoch;
    peer.key_k0 = key[0];
    peer.key_k1 = key[1];
    peer.replay_high_nonce = 0;
    peer.replay_bitmap = 0;
    peer.ctrl_rx_high_seq = 0;
    peer.ctrl_rx_bitmap = 0;
    peer.ctrl_tx_next_seq = 0;
    peer.last_seen_epoch = crate::pit::get_ticks() as u64;
    Ok(next_epoch)
}

pub fn install_peer_session_key(
    peer_device_id: u64,
    key_epoch: u32,
    k0: u64,
    k1: u64,
    measurement_hash: u64,
) -> Result<(), CapNetError> {
    if peer_device_id == 0 || key_epoch == 0 {
        return Err(CapNetError::UnknownPeer);
    }

    let mut peers = CAPNET_PEERS.lock();
    let idx = find_peer_index_mut(&mut peers, peer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = &mut peers[idx];
    peer.key_epoch = key_epoch;
    peer.key_k0 = k0;
    peer.key_k1 = k1;
    if measurement_hash != 0 {
        peer.measurement_hash = measurement_hash;
    }
    peer.replay_high_nonce = 0;
    peer.replay_bitmap = 0;
    peer.ctrl_rx_high_seq = 0;
    peer.ctrl_rx_bitmap = 0;
    peer.ctrl_tx_next_seq = 0;
    peer.last_seen_epoch = crate::pit::get_ticks() as u64;
    Ok(())
}

pub fn verify_incoming_token(
    token: &CapabilityTokenV1,
    now_epoch: u64,
) -> Result<(), CapNetError> {
    token.validate_semantics()?;
    if !token.is_temporally_valid(now_epoch) {
        return Err(CapNetError::TokenExpired);
    }

    let local = local_device_id().ok_or(CapNetError::LocalIdentityUnset)?;
    if token.subject_device_id != local {
        return Err(CapNetError::UnknownPeer);
    }

    let mut peers = CAPNET_PEERS.lock();
    let idx = find_peer_index_mut(&mut peers, token.issuer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = &mut peers[idx];
    if peer.key_epoch == 0 {
        return Err(CapNetError::SessionNotEstablished);
    }

    if (token.constraints_flags & CAPNET_CONSTRAINT_MEASUREMENT_BOUND) != 0
        && peer.measurement_hash != 0
        && token.measurement_hash != peer.measurement_hash
    {
        if peer.trust == PeerTrustPolicy::Enforce {
            return Err(CapNetError::MeasurementMismatch);
        }
    }

    if !token.verify_with_session_key(peer.key_k0, peer.key_k1) {
        return Err(CapNetError::MacMismatch);
    }

    if !accept_nonce(peer, token.nonce) {
        return Err(CapNetError::ReplayDetected);
    }

    peer.last_seen_epoch = now_epoch;
    Ok(())
}

pub fn sign_outgoing_token_for_peer(
    peer_device_id: u64,
    token: &mut CapabilityTokenV1,
) -> Result<(), CapNetError> {
    let local = local_device_id().ok_or(CapNetError::LocalIdentityUnset)?;
    token.issuer_device_id = local;
    token.subject_device_id = peer_device_id;

    let peers = CAPNET_PEERS.lock();
    let idx = find_peer_index(&peers, peer_device_id).ok_or(CapNetError::UnknownPeer)?;
    let peer = peers[idx];
    if peer.key_epoch == 0 {
        return Err(CapNetError::SessionNotEstablished);
    }
    token.sign_with_session_key(peer.key_k0, peer.key_k1);
    Ok(())
}

pub fn peer_snapshot(peer_device_id: u64) -> Option<PeerSessionSnapshot> {
    let peers = CAPNET_PEERS.lock();
    let idx = find_peer_index(&peers, peer_device_id)?;
    let p = peers[idx];
    Some(PeerSessionSnapshot {
        active: p.active,
        peer_device_id: p.peer_device_id,
        trust: p.trust,
        measurement_hash: p.measurement_hash,
        key_epoch: p.key_epoch,
        replay_high_nonce: p.replay_high_nonce,
        replay_bitmap: p.replay_bitmap,
        last_seen_epoch: p.last_seen_epoch,
    })
}

pub fn peer_snapshots() -> [Option<PeerSessionSnapshot>; CAPNET_MAX_PEERS] {
    let peers = CAPNET_PEERS.lock();
    let mut out = [None; CAPNET_MAX_PEERS];
    let mut i = 0usize;
    while i < peers.len() {
        if peers[i].active {
            let p = peers[i];
            out[i] = Some(PeerSessionSnapshot {
                active: p.active,
                peer_device_id: p.peer_device_id,
                trust: p.trust,
                measurement_hash: p.measurement_hash,
                key_epoch: p.key_epoch,
                replay_high_nonce: p.replay_high_nonce,
                replay_bitmap: p.replay_bitmap,
                last_seen_epoch: p.last_seen_epoch,
            });
        }
        i += 1;
    }
    out
}

pub fn journal_stats() -> CapNetJournalStats {
    let records = CAPNET_DELEGATION_RECORDS.lock();
    let tombstones = CAPNET_REVOCATION_TOMBSTONES.lock();
    let next_epoch = *CAPNET_NEXT_REVOCATION_EPOCH.lock();

    let mut active_records = 0usize;
    let mut i = 0usize;
    while i < records.len() {
        if records[i].active {
            active_records += 1;
        }
        i += 1;
    }

    let mut active_tombstones = 0usize;
    let mut max_epoch = 0u32;
    let mut j = 0usize;
    while j < tombstones.len() {
        let t = tombstones[j];
        if t.active {
            active_tombstones += 1;
            if t.revocation_epoch > max_epoch {
                max_epoch = t.revocation_epoch;
            }
        }
        j += 1;
    }

    CapNetJournalStats {
        delegation_records_active: active_records,
        revocation_tombstones_active: active_tombstones,
        max_revocation_epoch: max_epoch,
        next_revocation_epoch: next_epoch,
    }
}

#[derive(Clone, Copy)]
struct CapNetFuzzRng {
    state: u64,
}

impl CapNetFuzzRng {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0usize;
        while i < out.len() {
            let chunk = self.next_u64().to_le_bytes();
            let mut j = 0usize;
            while j < chunk.len() && i < out.len() {
                out[i] = chunk[j];
                i += 1;
                j += 1;
            }
        }
    }
}

fn build_fuzz_token(loopback_peer: u64, nonce: u64) -> CapabilityTokenV1 {
    let mut token = CapabilityTokenV1::empty();
    token.cap_type = crate::capability::CapabilityType::Filesystem as u8;
    token.issuer_device_id = loopback_peer;
    token.subject_device_id = loopback_peer;
    token.object_id = 0x4341_504E_4554_4655;
    token.rights = crate::capability::Rights::FS_READ;
    token.issued_at = 1;
    token.not_before = 1;
    token.expires_at = u64::MAX - 1024;
    token.nonce = nonce;
    token.delegation_depth = 0;
    token.parent_token_hash = 0;
    token.context = 0;
    token.constraints_flags = CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE;
    token.max_uses = 4;
    token
}

fn build_fuzz_overflow_control_frame() -> [u8; CAPNET_CTRL_HEADER_LEN] {
    let mut bytes = [0u8; CAPNET_CTRL_HEADER_LEN];
    let mut off = 0usize;
    write_u32(&mut bytes, &mut off, CAPNET_CTRL_MAGIC);
    write_u8(&mut bytes, &mut off, CAPNET_CTRL_VERSION);
    write_u8(&mut bytes, &mut off, CapNetControlType::Hello as u8);
    write_u8(&mut bytes, &mut off, 0);
    write_u8(&mut bytes, &mut off, 0);
    write_u32(&mut bytes, &mut off, 1);
    write_u32(&mut bytes, &mut off, 0);
    write_u64(&mut bytes, &mut off, 1);
    write_u64(&mut bytes, &mut off, 1);
    write_u64(&mut bytes, &mut off, 0);
    write_u32(&mut bytes, &mut off, 1);
    write_u16(&mut bytes, &mut off, (CAPNET_CTRL_MAX_PAYLOAD + 1) as u16);
    write_u16(&mut bytes, &mut off, 0);
    write_u64(&mut bytes, &mut off, 0);
    bytes
}

fn record_fuzz_failure(
    stats: &mut CapNetFuzzStats,
    iteration: u32,
    stage: &'static str,
    reason: &'static str,
    sample: &[u8],
) {
    stats.failures = stats.failures.saturating_add(1);
    if stats.first_failure.is_some() {
        return;
    }
    let mut first = CapNetFuzzFailure {
        iteration,
        stage,
        reason,
        sample_len: 0,
        sample: [0u8; CAPNET_FUZZ_SAMPLE_LEN],
    };
    let len = core::cmp::min(sample.len(), CAPNET_FUZZ_SAMPLE_LEN);
    first.sample_len = len as u8;
    if len > 0 {
        first.sample[..len].copy_from_slice(&sample[..len]);
    }
    stats.first_failure = Some(first);
}

/// Coverage-style CapNet parser/enforcer fuzzing.
///
/// This exercises:
/// - token decode + semantic constraints,
/// - control frame decode including overflow/truncation shapes,
/// - process path replay rejection invariants.
pub fn capnet_fuzz(iterations: u32, seed: u64) -> Result<CapNetFuzzStats, &'static str> {
    if iterations == 0 || iterations > CAPNET_FUZZ_MAX_ITERS {
        return Err("iterations must be 1..=10000");
    }

    init();
    let local = local_device_id().ok_or("CapNet local identity unavailable")?;
    register_peer(local, PeerTrustPolicy::Audit, 0).map_err(|e| e.as_str())?;

    let mut rng = CapNetFuzzRng::new(seed ^ 0xC4A9_7E11_42D8_F00D);
    let mut k0 = seed ^ 0xA5A5_A5A5_A5A5_A5A5;
    let mut k1 = seed.rotate_left(17) ^ 0x5A5A_5A5A_5A5A_5A5A;
    if k0 == 0 && k1 == 0 {
        k0 = 1;
    }
    if k1 == 0 {
        k1 = 1;
    }

    let base_nonce = seed ^ 0xBADC_0FFE_C0DE_FEED;
    let mut stats = CapNetFuzzStats {
        iterations,
        valid_path_ok: 0,
        replay_rejects: 0,
        constraint_rejects: 0,
        token_decode_ok: 0,
        token_decode_err: 0,
        control_decode_ok: 0,
        control_decode_err: 0,
        process_ok: 0,
        process_err: 0,
        failures: 0,
        first_failure: None,
    };

    let overflow = build_fuzz_overflow_control_frame();
    let mut random_token = [0u8; CAPNET_TOKEN_V1_LEN];
    let mut random_frame = [0u8; CAPNET_CTRL_MAX_FRAME_LEN];

    let mut i = 0u32;
    while i < iterations {
        let epoch = i.saturating_add(1).max(1);
        install_peer_session_key(local, epoch, k0, k1, 0).map_err(|e| e.as_str())?;

        let mut token = build_fuzz_token(local, base_nonce);
        let offer = match build_token_offer_frame(local, 0, &mut token) {
            Ok(v) => v,
            Err(e) => {
                record_fuzz_failure(&mut stats, i, "valid-offer-build", e.as_str(), &[]);
                i = i.saturating_add(1);
                continue;
            }
        };
        match process_incoming_control_payload(&offer.bytes[..offer.len], 1024 + i as u64) {
            Ok(rx) if rx.msg_type == CapNetControlType::TokenOffer => {
                stats.valid_path_ok = stats.valid_path_ok.saturating_add(1);
            }
            Ok(_) => {
                record_fuzz_failure(
                    &mut stats,
                    i,
                    "valid-offer-process",
                    "unexpected control type",
                    &offer.bytes[..offer.len],
                );
            }
            Err(e) => {
                record_fuzz_failure(
                    &mut stats,
                    i,
                    "valid-offer-process",
                    e.as_str(),
                    &offer.bytes[..offer.len],
                );
            }
        }

        let replay = match build_heartbeat_frame(local, 0, false) {
            Ok(v) => v,
            Err(e) => {
                record_fuzz_failure(&mut stats, i, "replay-build", e.as_str(), &[]);
                i = i.saturating_add(1);
                continue;
            }
        };
        if let Err(e) = process_incoming_control_payload(&replay.bytes[..replay.len], 2048 + i as u64) {
            record_fuzz_failure(
                &mut stats,
                i,
                "replay-first-process",
                e.as_str(),
                &replay.bytes[..replay.len],
            );
        } else {
            match process_incoming_control_payload(&replay.bytes[..replay.len], 2049 + i as u64) {
                Err(CapNetError::ControlSequenceReplay) => {
                    stats.replay_rejects = stats.replay_rejects.saturating_add(1);
                }
                Err(e) => {
                    record_fuzz_failure(
                        &mut stats,
                        i,
                        "replay-second-process",
                        e.as_str(),
                        &replay.bytes[..replay.len],
                    );
                }
                Ok(_) => {
                    record_fuzz_failure(
                        &mut stats,
                        i,
                        "replay-second-process",
                        "replay accepted",
                        &replay.bytes[..replay.len],
                    );
                }
            }
        }

        let mut invalid_budget = build_fuzz_token(local, base_nonce ^ (i as u64).rotate_left(9));
        invalid_budget.max_uses = 0;
        match invalid_budget.validate_semantics() {
            Err(CapNetError::InvalidUseBudget) => {
                stats.constraint_rejects = stats.constraint_rejects.saturating_add(1);
            }
            Err(e) => {
                record_fuzz_failure(&mut stats, i, "constraint-budget", e.as_str(), &[]);
            }
            Ok(()) => {
                record_fuzz_failure(
                    &mut stats,
                    i,
                    "constraint-budget",
                    "invalid bounded-use token accepted",
                    &[],
                );
            }
        }

        let mut invalid_temporal = build_fuzz_token(local, base_nonce ^ (i as u64).rotate_left(13));
        invalid_temporal.issued_at = 20;
        invalid_temporal.not_before = 10;
        invalid_temporal.expires_at = 30;
        match invalid_temporal.validate_semantics() {
            Err(CapNetError::InvalidTemporalWindow) => {
                stats.constraint_rejects = stats.constraint_rejects.saturating_add(1);
            }
            Err(e) => {
                record_fuzz_failure(&mut stats, i, "constraint-temporal", e.as_str(), &[]);
            }
            Ok(()) => {
                record_fuzz_failure(
                    &mut stats,
                    i,
                    "constraint-temporal",
                    "invalid temporal token accepted",
                    &[],
                );
            }
        }

        rng.fill_bytes(&mut random_token);
        match CapabilityTokenV1::decode_checked(&random_token) {
            Ok(_) => {
                stats.token_decode_ok = stats.token_decode_ok.saturating_add(1);
            }
            Err(_) => {
                stats.token_decode_err = stats.token_decode_err.saturating_add(1);
            }
        }

        rng.fill_bytes(&mut random_frame);
        let random_len = (rng.next_u32() as usize) % (CAPNET_CTRL_MAX_FRAME_LEN + 1);
        match decode_control_frame(&random_frame[..random_len]) {
            Ok(_) => {
                stats.control_decode_ok = stats.control_decode_ok.saturating_add(1);
            }
            Err(_) => {
                stats.control_decode_err = stats.control_decode_err.saturating_add(1);
            }
        }

        match process_incoming_control_payload(&random_frame[..random_len], 4096 + i as u64) {
            Ok(_) => {
                stats.process_ok = stats.process_ok.saturating_add(1);
            }
            Err(_) => {
                stats.process_err = stats.process_err.saturating_add(1);
            }
        }

        match decode_control_frame(&overflow) {
            Err(CapNetError::PayloadTooLarge) => {}
            Err(e) => {
                record_fuzz_failure(&mut stats, i, "decode-overflow", e.as_str(), &overflow);
            }
            Ok(_) => {
                record_fuzz_failure(
                    &mut stats,
                    i,
                    "decode-overflow",
                    "overflow payload accepted",
                    &overflow,
                );
            }
        }

        i = i.saturating_add(1);
    }

    Ok(stats)
}

pub fn capnet_fuzz_regression_default(
    iterations_per_seed: u32,
) -> Result<CapNetFuzzRegressionStats, &'static str> {
    if iterations_per_seed == 0 || iterations_per_seed > CAPNET_FUZZ_MAX_ITERS {
        return Err("iterations_per_seed must be 1..=10000");
    }

    let mut out = CapNetFuzzRegressionStats {
        seeds_total: CAPNET_FUZZ_REGRESSION_SEEDS.len() as u32,
        seeds_passed: 0,
        seeds_failed: 0,
        total_failures: 0,
        total_valid_path_ok: 0,
        total_replay_rejects: 0,
        total_constraint_rejects: 0,
        total_token_decode_err: 0,
        total_control_decode_err: 0,
        total_process_err: 0,
        first_failed_seed: None,
        first_failure: None,
    };

    let mut i = 0usize;
    while i < CAPNET_FUZZ_REGRESSION_SEEDS.len() {
        let seed = CAPNET_FUZZ_REGRESSION_SEEDS[i];
        let stats = capnet_fuzz(iterations_per_seed, seed)?;
        out.total_failures = out.total_failures.saturating_add(stats.failures);
        out.total_valid_path_ok = out.total_valid_path_ok.saturating_add(stats.valid_path_ok);
        out.total_replay_rejects = out.total_replay_rejects.saturating_add(stats.replay_rejects);
        out.total_constraint_rejects = out
            .total_constraint_rejects
            .saturating_add(stats.constraint_rejects);
        out.total_token_decode_err = out
            .total_token_decode_err
            .saturating_add(stats.token_decode_err);
        out.total_control_decode_err = out
            .total_control_decode_err
            .saturating_add(stats.control_decode_err);
        out.total_process_err = out.total_process_err.saturating_add(stats.process_err);

        if stats.failures == 0 {
            out.seeds_passed = out.seeds_passed.saturating_add(1);
        } else {
            out.seeds_failed = out.seeds_failed.saturating_add(1);
            if out.first_failed_seed.is_none() {
                out.first_failed_seed = Some(seed);
                out.first_failure = stats.first_failure;
            }
        }

        i += 1;
    }

    Ok(out)
}

pub fn capnet_fuzz_regression_soak_default(
    iterations_per_seed: u32,
    rounds: u32,
) -> Result<CapNetFuzzSoakStats, &'static str> {
    if iterations_per_seed == 0 || iterations_per_seed > CAPNET_FUZZ_MAX_ITERS {
        return Err("iterations_per_seed must be 1..=10000");
    }
    if rounds == 0 || rounds > 100 {
        return Err("rounds must be 1..=100");
    }

    let mut out = CapNetFuzzSoakStats {
        rounds,
        rounds_passed: 0,
        rounds_failed: 0,
        seed_passes: 0,
        seed_failures: 0,
        total_failures: 0,
        total_valid_path_ok: 0,
        total_replay_rejects: 0,
        total_constraint_rejects: 0,
        first_failed_round: None,
        first_failed_seed: None,
        first_failure: None,
    };

    let mut r = 0u32;
    while r < rounds {
        let stats = capnet_fuzz_regression_default(iterations_per_seed)?;
        out.seed_passes = out.seed_passes.saturating_add(stats.seeds_passed);
        out.seed_failures = out.seed_failures.saturating_add(stats.seeds_failed);
        out.total_failures = out.total_failures.saturating_add(stats.total_failures);
        out.total_valid_path_ok = out
            .total_valid_path_ok
            .saturating_add(stats.total_valid_path_ok);
        out.total_replay_rejects = out
            .total_replay_rejects
            .saturating_add(stats.total_replay_rejects);
        out.total_constraint_rejects = out
            .total_constraint_rejects
            .saturating_add(stats.total_constraint_rejects);

        if stats.seeds_failed == 0 {
            out.rounds_passed = out.rounds_passed.saturating_add(1);
        } else {
            out.rounds_failed = out.rounds_failed.saturating_add(1);
            if out.first_failed_round.is_none() {
                out.first_failed_round = Some(r);
                out.first_failed_seed = stats.first_failed_seed;
                out.first_failure = stats.first_failure;
            }
        }

        r = r.saturating_add(1);
    }

    Ok(out)
}

/// Formal CapNet proof obligations used by `formal-verify`.
///
/// Obligations:
/// - Delegation attenuation monotonicity (subset required).
/// - Temporal validity checks reject malformed intervals.
/// - Replay window rejects duplicate control sequence.
/// - Revocation precedence blocks descendants after parent revocation.
pub fn formal_capnet_self_check() -> Result<(), &'static str> {
    init();
    let local = local_device_id().ok_or("CapNet local identity unavailable")?;
    register_peer(local, PeerTrustPolicy::Audit, 0).map_err(|e| e.as_str())?;

    let nonce_base = ((crate::pit::get_ticks() as u64) << 16)
        ^ (security::security().random_u32() as u64)
        ^ 0xCA70_0000_0000_0000u64;
    let k0 = 0x1111_2222_3333_4444u64 ^ nonce_base;
    let mut k1 = 0x9999_AAAA_BBBB_CCCCu64 ^ nonce_base.rotate_left(13);
    if k1 == 0 {
        k1 = 1;
    }

    install_peer_session_key(local, 1, k0, k1, 0).map_err(|e| e.as_str())?;

    let mut parent = build_fuzz_token(local, nonce_base.wrapping_add(1));
    parent.rights = crate::capability::Rights::FS_READ | crate::capability::Rights::FS_WRITE;
    parent.max_uses = 16;
    parent.constraints_flags = CAPNET_CONSTRAINT_REQUIRE_BOUNDED_USE;
    let parent_offer = build_token_offer_frame(local, 0, &mut parent).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(&parent_offer.bytes[..parent_offer.len], 10_000) {
        Ok(v) if v.msg_type == CapNetControlType::TokenOffer => {}
        Ok(_) => return Err("Formal CapNet self-check: parent offer wrong control type"),
        Err(e) => return Err(e.as_str()),
    }

    install_peer_session_key(local, 2, k0, k1, 0).map_err(|e| e.as_str())?;
    let mut child = parent;
    child.delegation_depth = 1;
    child.parent_token_hash = parent.token_id();
    child.rights = crate::capability::Rights::FS_READ;
    child.max_uses = 4;
    child.nonce = nonce_base.wrapping_add(2);
    let child_offer = build_token_offer_frame(local, 0, &mut child).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(&child_offer.bytes[..child_offer.len], 10_001) {
        Ok(v) if v.msg_type == CapNetControlType::TokenOffer => {}
        Ok(_) => return Err("Formal CapNet self-check: child offer wrong control type"),
        Err(e) => return Err(e.as_str()),
    }

    install_peer_session_key(local, 3, k0, k1, 0).map_err(|e| e.as_str())?;
    let mut escalated = child;
    escalated.nonce = nonce_base.wrapping_add(3);
    escalated.rights = parent.rights | crate::capability::Rights::FS_DELETE;
    let escalated_offer =
        build_token_offer_frame(local, 0, &mut escalated).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(&escalated_offer.bytes[..escalated_offer.len], 10_002) {
        Err(CapNetError::DelegationRightsEscalation) => {}
        Err(e) => return Err(e.as_str()),
        Ok(_) => return Err("Formal CapNet self-check: rights escalation accepted"),
    }

    install_peer_session_key(local, 4, k0, k1, 0).map_err(|e| e.as_str())?;
    let replay = build_heartbeat_frame(local, 0, false).map_err(|e| e.as_str())?;
    process_incoming_control_payload(&replay.bytes[..replay.len], 10_003).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(&replay.bytes[..replay.len], 10_004) {
        Err(CapNetError::ControlSequenceReplay) => {}
        Err(e) => return Err(e.as_str()),
        Ok(_) => return Err("Formal CapNet self-check: duplicate control sequence accepted"),
    }

    let mut invalid_temporal = build_fuzz_token(local, nonce_base.wrapping_add(4));
    invalid_temporal.issued_at = 20;
    invalid_temporal.not_before = 10;
    invalid_temporal.expires_at = 30;
    match invalid_temporal.validate_semantics() {
        Err(CapNetError::InvalidTemporalWindow) => {}
        Err(e) => return Err(e.as_str()),
        Ok(()) => return Err("Formal CapNet self-check: invalid temporal window accepted"),
    }

    install_peer_session_key(local, 5, k0, k1, 0).map_err(|e| e.as_str())?;
    let revoke = build_token_revoke_frame(local, 0, parent.token_id()).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(&revoke.bytes[..revoke.len], 10_005) {
        Ok(v) if v.msg_type == CapNetControlType::TokenRevoke => {}
        Ok(_) => return Err("Formal CapNet self-check: revoke wrong control type"),
        Err(e) => return Err(e.as_str()),
    }

    install_peer_session_key(local, 6, k0, k1, 0).map_err(|e| e.as_str())?;
    let child_offer_after_revoke =
        build_token_offer_frame(local, 0, &mut child).map_err(|e| e.as_str())?;
    match process_incoming_control_payload(
        &child_offer_after_revoke.bytes[..child_offer_after_revoke.len],
        10_006,
    ) {
        Err(CapNetError::RevokedToken) => {}
        Err(e) => return Err(e.as_str()),
        Ok(_) => return Err("Formal CapNet self-check: revoked delegation accepted"),
    }

    Ok(())
}

fn find_peer_index(peers: &[PeerSession; CAPNET_MAX_PEERS], peer_device_id: u64) -> Option<usize> {
    let mut i = 0usize;
    while i < peers.len() {
        if peers[i].active && peers[i].peer_device_id == peer_device_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_peer_index_mut(
    peers: &mut [PeerSession; CAPNET_MAX_PEERS],
    peer_device_id: u64,
) -> Option<usize> {
    let mut i = 0usize;
    while i < peers.len() {
        if peers[i].active && peers[i].peer_device_id == peer_device_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn accept_nonce(peer: &mut PeerSession, nonce: u64) -> bool {
    if peer.replay_high_nonce == 0 {
        peer.replay_high_nonce = nonce;
        peer.replay_bitmap = 1;
        return true;
    }

    if nonce > peer.replay_high_nonce {
        let shift = nonce - peer.replay_high_nonce;
        if shift >= 64 {
            peer.replay_bitmap = 1;
        } else {
            peer.replay_bitmap = (peer.replay_bitmap << shift) | 1;
        }
        peer.replay_high_nonce = nonce;
        return true;
    }

    let delta = peer.replay_high_nonce - nonce;
    if delta >= 64 {
        return false;
    }
    let bit = 1u64 << delta;
    if (peer.replay_bitmap & bit) != 0 {
        return false;
    }
    peer.replay_bitmap |= bit;
    true
}

#[inline]
fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = 14695981039346656037u64;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211u64);
    }
    hash
}

#[inline]
fn write_u8(buf: &mut [u8], offset: &mut usize, value: u8) {
    buf[*offset] = value;
    *offset += 1;
}

#[inline]
fn write_u16(buf: &mut [u8], offset: &mut usize, value: u16) {
    let end = *offset + 2;
    buf[*offset..end].copy_from_slice(&value.to_le_bytes());
    *offset = end;
}

#[inline]
fn write_u32(buf: &mut [u8], offset: &mut usize, value: u32) {
    let end = *offset + 4;
    buf[*offset..end].copy_from_slice(&value.to_le_bytes());
    *offset = end;
}

#[inline]
fn write_u64(buf: &mut [u8], offset: &mut usize, value: u64) {
    let end = *offset + 8;
    buf[*offset..end].copy_from_slice(&value.to_le_bytes());
    *offset = end;
}

#[inline]
fn read_u8(buf: &[u8], offset: &mut usize) -> Result<u8, CapNetError> {
    let i = *offset;
    let value = *buf.get(i).ok_or(CapNetError::DecodeOverflow)?;
    *offset = i + 1;
    Ok(value)
}

#[inline]
fn read_u16(buf: &[u8], offset: &mut usize) -> Result<u16, CapNetError> {
    let start = *offset;
    let end = start.checked_add(2).ok_or(CapNetError::DecodeOverflow)?;
    let bytes = buf.get(start..end).ok_or(CapNetError::DecodeOverflow)?;
    *offset = end;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

#[inline]
fn read_u32(buf: &[u8], offset: &mut usize) -> Result<u32, CapNetError> {
    let start = *offset;
    let end = start.checked_add(4).ok_or(CapNetError::DecodeOverflow)?;
    let bytes = buf.get(start..end).ok_or(CapNetError::DecodeOverflow)?;
    *offset = end;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[inline]
fn read_u64(buf: &[u8], offset: &mut usize) -> Result<u64, CapNetError> {
    let start = *offset;
    let end = start.checked_add(8).ok_or(CapNetError::DecodeOverflow)?;
    let bytes = buf.get(start..end).ok_or(CapNetError::DecodeOverflow)?;
    *offset = end;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
