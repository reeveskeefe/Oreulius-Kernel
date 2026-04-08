/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */

//! Oreulius Persistence v0
//!
//! Provides append-only logs, snapshots, and replay-based recovery
//! for durable state management.

#![allow(dead_code)]

extern crate alloc;

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum log record size (64 KiB)
pub const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Maximum number of log records (for v0 RAM-backed)
#[cfg(target_arch = "x86")]
pub const MAX_LOG_RECORDS: usize = 64;
#[cfg(not(target_arch = "x86"))]
pub const MAX_LOG_RECORDS: usize = 1024;

/// Log record magic number for validation
pub const LOG_MAGIC: u32 = 0x4F52_4555; // "OREU"

/// Log record version
pub const LOG_VERSION: u16 = 1;

// ============================================================================
// Log Record Types
// ============================================================================

/// Types of log records
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    /// External input: clock read
    ExternalInputClockRead = 1,
    /// External input: console input
    ExternalInputConsoleIn = 2,
    /// Component event
    ComponentEvent = 3,
    /// Supervisor checkpoint
    SupervisorCheckpoint = 4,
    /// Filesystem operation
    FilesystemOp = 10,
    /// Kernel panic / crash report
    CrashReport = 20,
    /// OTA update lifecycle event
    OtaUpdate = 21,
    /// Boot-time event (one per boot)
    BootEvent = 22,
    /// Remote attestation bundle
    AttestationRecord = 23,
    /// System health snapshot
    HealthSnapshot = 24,
}

impl RecordType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(RecordType::ExternalInputClockRead),
            2 => Some(RecordType::ExternalInputConsoleIn),
            3 => Some(RecordType::ComponentEvent),
            4 => Some(RecordType::SupervisorCheckpoint),
            10 => Some(RecordType::FilesystemOp),
            20 => Some(RecordType::CrashReport),
            21 => Some(RecordType::OtaUpdate),
            22 => Some(RecordType::BootEvent),
            23 => Some(RecordType::AttestationRecord),
            24 => Some(RecordType::HealthSnapshot),
            _ => None,
        }
    }
}

// ============================================================================
// Log Record Structure
// ============================================================================

/// A log record header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// Magic number (for validation)
    pub magic: u32,
    /// Record format version
    pub version: u16,
    /// Record type
    pub record_type: u16,
    /// Payload length
    pub len: u32,
}

impl RecordHeader {
    pub fn new(record_type: RecordType, len: u32) -> Self {
        RecordHeader {
            magic: LOG_MAGIC,
            version: LOG_VERSION,
            record_type: record_type as u16,
            len,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == LOG_MAGIC && self.version == LOG_VERSION
    }
}

/// A complete log record
#[derive(Clone, Copy)]
pub struct LogRecord {
    /// Record header
    pub header: RecordHeader,
    /// Payload data
    pub payload: [u8; MAX_RECORD_SIZE],
    /// CRC32 checksum (for integrity)
    pub crc32: u32,
}

impl LogRecord {
    /// Create a new log record
    pub fn new(record_type: RecordType, payload: &[u8]) -> Result<Self, PersistenceError> {
        if payload.len() > MAX_RECORD_SIZE {
            return Err(PersistenceError::RecordTooLarge);
        }

        let mut payload_buf = [0u8; MAX_RECORD_SIZE];
        payload_buf[..payload.len()].copy_from_slice(payload);

        let header = RecordHeader::new(record_type, payload.len() as u32);
        let crc32 = Self::compute_crc32(&payload_buf[..payload.len()]);

        Ok(LogRecord {
            header,
            payload: payload_buf,
            crc32,
        })
    }

    /// Compute CRC32 checksum (simple implementation for v0)
    fn compute_crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    /// Verify the record's integrity
    pub fn verify(&self) -> bool {
        if !self.header.is_valid() {
            return false;
        }

        let computed_crc = Self::compute_crc32(&self.payload[..self.header.len as usize]);
        computed_crc == self.crc32
    }

    /// Get the payload as a slice
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.header.len as usize]
    }
}

// ============================================================================
// Append-Only Log
// ============================================================================

/// An append-only log
pub struct AppendLog {
    /// Log records
    records: [Option<LogRecord>; MAX_LOG_RECORDS],
    /// Current offset (number of records)
    offset: usize,
}

impl AppendLog {
    /// Create a new empty log
    pub const fn new() -> Self {
        AppendLog {
            records: [None; MAX_LOG_RECORDS],
            offset: 0,
        }
    }

    /// Append a record to the log
    pub fn append(&mut self, record: LogRecord) -> Result<usize, PersistenceError> {
        if self.offset >= MAX_LOG_RECORDS {
            return Err(PersistenceError::LogFull);
        }

        self.records[self.offset] = Some(record);
        let offset = self.offset;
        self.offset += 1;

        Ok(offset)
    }

    /// Read records starting from an offset
    pub fn read(&self, from_offset: usize, max_records: usize) -> impl Iterator<Item = &LogRecord> {
        self.records[from_offset..]
            .iter()
            .take(max_records)
            .filter_map(|r| r.as_ref())
    }

    /// Get the current offset
    pub fn current_offset(&self) -> usize {
        self.offset
    }

    /// Get total number of records
    pub fn count(&self) -> usize {
        self.offset
    }
}

// ============================================================================
// Snapshot
// ============================================================================

/// Maximum snapshot size.
///
/// The 32-bit x86 build keeps this smaller so the Multiboot image stays within
/// what GRUB can comfortably allocate during CI boot.
#[cfg(target_arch = "x86")]
pub const MAX_SNAPSHOT_SIZE: usize = 256 * 1024;
#[cfg(not(target_arch = "x86"))]
pub const MAX_SNAPSHOT_SIZE: usize = 1024 * 1024;
const SNAPSHOT_DISK_MAGIC: u32 = 0x4F_52_53_50; // "ORSP"
const SNAPSHOT_DISK_VERSION_V1: u16 = 1;
const SNAPSHOT_DISK_VERSION_V2: u16 = 2;
const SNAPSHOT_DISK_HEADER_BYTES: usize = 64;
const SNAPSHOT_DISK_SLOT_GENERIC: u16 = 1;
const SNAPSHOT_DISK_SLOT_TEMPORAL: u16 = 2;
const SNAPSHOT_DISK_SLOT_VFS: u16 = 3;
const SNAPSHOT_DISK_SECTOR_BYTES: usize = 512;
const SNAPSHOT_FILE_PATH_GENERIC: &str = "/.oreulius_snapshot_generic";
const SNAPSHOT_FILE_PATH_TEMPORAL: &str = "/.oreulius_snapshot_temporal";
const SNAPSHOT_IO_SCRATCH_BYTES: usize =
    ((SNAPSHOT_DISK_HEADER_BYTES + MAX_SNAPSHOT_SIZE + SNAPSHOT_DISK_SECTOR_BYTES - 1)
        / SNAPSHOT_DISK_SECTOR_BYTES)
        * SNAPSHOT_DISK_SECTOR_BYTES;

const SNAPSHOT_V2_FLAG_SEALED: u32 = 1 << 0;
const SNAPSHOT_V2_FLAG_ENCRYPTED: u32 = 1 << 1;

// Monotonic nonce used for AES-CTR. Updated on recovery to avoid nonce reuse across reboots.
static NEXT_SNAPSHOT_NONCE: spin::Mutex<u64> = spin::Mutex::new(1);
static SNAPSHOT_CRYPTO_TRACE_COUNT: AtomicU32 = AtomicU32::new(0);
static SNAPSHOT_IO_SCRATCH: spin::Mutex<SnapshotIoScratch> =
    spin::Mutex::new(SnapshotIoScratch::new());

struct SnapshotIoScratch {
    image: [u8; SNAPSHOT_IO_SCRATCH_BYTES],
}

impl SnapshotIoScratch {
    const fn new() -> Self {
        SnapshotIoScratch {
            image: [0u8; SNAPSHOT_IO_SCRATCH_BYTES],
        }
    }
}

#[inline]
fn addr_in_range(addr: usize, len: usize, start: usize, end: usize) -> bool {
    if start == 0 || end <= start {
        return false;
    }
    if len == 0 {
        return addr >= start && addr < end;
    }
    match addr.checked_add(len) {
        Some(last) => addr >= start && last <= end,
        None => false,
    }
}

fn trace_snapshot_crypto(label: &str, slot_id: u16, ptr: *const u8, len: usize, span_len: usize) {
    let seq = SNAPSHOT_CRYPTO_TRACE_COUNT
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    let addr = ptr as usize;
    let addr_end = addr.checked_add(len).unwrap_or(0);
    let (heap_start, heap_end) = crate::runtime_heap_range();
    let (jit_start, jit_end) = crate::runtime_jit_arena_range();
    let in_heap = addr_in_range(addr, len, heap_start, heap_end);
    let in_jit = addr_in_range(addr, len, jit_start, jit_end);
    let suspicious = len > MAX_SNAPSHOT_SIZE
        || addr_end == 0
        || span_len > MAX_SNAPSHOT_SIZE.saturating_add(SNAPSHOT_DISK_HEADER_BYTES);
    if suspicious || seq <= 64 {
        crate::serial::_print(format_args!(
            "[PERSIST-DBG] aes seq={} op={} slot={} ptr=0x{:08x} len={} span={} heap={} jit={}\n",
            seq,
            label,
            slot_id,
            addr as u32,
            len,
            span_len,
            if in_heap { 1 } else { 0 },
            if in_jit { 1 } else { 0 },
        ));
    }
}

fn seed_snapshot_nonce() {
    // Mix hardware RNG (if present) with cycle counter to avoid nonce reuse across reboot even
    // when no prior snapshot is readable (e.g., corruption).
    let mut seed = 0xA5A5_5A5A_F00D_CAFE_u64;
    #[cfg(target_arch = "x86_64")]
    {
        seed ^= crate::memory::asm_bindings::read_timestamp();
        seed ^= 0x9E37_79B9_7F4A_7C15u64.rotate_left(7);
    }
    #[cfg(all(not(target_arch = "aarch64"), not(target_arch = "x86_64")))]
    {
        seed ^= crate::memory::asm_bindings::rdtsc_begin();
        if let Some(r) = crate::memory::asm_bindings::try_rdrand() {
            seed ^= ((r as u64) << 32) | (r as u64);
        }
        seed ^= crate::memory::asm_bindings::rdtsc_end();
    }
    #[cfg(target_arch = "aarch64")]
    {
        seed ^= crate::scheduler::pit::get_ticks();
        seed ^= crate::arch::aarch64::aarch64_virt::timer_frequency_hz();
    }

    let mut slot = NEXT_SNAPSHOT_NONCE.lock();
    let mixed = (*slot) ^ seed;
    *slot = mixed.max(1);
}

fn next_snapshot_nonce() -> u64 {
    let mut slot = NEXT_SNAPSHOT_NONCE.lock();
    let current = (*slot).max(1);
    *slot = current.saturating_add(1).max(1);
    current
}

fn observe_snapshot_nonce(observed: u64) {
    let next = observed.max(1).saturating_add(1).max(1);
    let mut slot = NEXT_SNAPSHOT_NONCE.lock();
    if *slot < next {
        *slot = next;
    }
}

/// A snapshot captures point-in-time state
pub struct Snapshot {
    /// Snapshot data
    pub data: [u8; MAX_SNAPSHOT_SIZE],
    /// Actual data length
    pub data_len: usize,
    /// Last log offset included in this snapshot
    pub last_offset: usize,
    /// Snapshot timestamp (placeholder)
    pub timestamp: u64,
}

impl Snapshot {
    /// Create a new empty snapshot
    pub const fn new() -> Self {
        Snapshot {
            data: [0u8; MAX_SNAPSHOT_SIZE],
            data_len: 0,
            last_offset: 0,
            timestamp: 0,
        }
    }

    /// Write snapshot data
    pub fn write(&mut self, data: &[u8], last_offset: usize) -> Result<(), PersistenceError> {
        if data.len() > MAX_SNAPSHOT_SIZE {
            return Err(PersistenceError::SnapshotTooLarge);
        }

        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        self.last_offset = last_offset;
        self.timestamp = crate::scheduler::pit::get_ticks();

        Ok(())
    }

    /// Read snapshot data
    pub fn read(&self) -> (&[u8], usize) {
        (&self.data[..self.data_len], self.last_offset)
    }
}

#[derive(Clone, Copy)]
pub struct SnapshotBackend {
    pub write: fn(slot_id: u16, snapshot: &Snapshot) -> Result<(), PersistenceError>,
    pub read: fn(slot_id: u16, out: &mut Snapshot) -> Result<bool, PersistenceError>,
}

#[derive(Clone, Copy)]
struct SnapshotDiskHeader {
    magic: u32,
    version: u16,
    slot_id: u16,
    data_len: u32,
    last_offset: u64,
    timestamp: u64,
    crc32: u32,
}

#[derive(Clone, Copy)]
struct SnapshotDiskHeaderV2 {
    magic: u32,
    version: u16,
    slot_id: u16,
    data_len: u32,
    last_offset: u64,
    timestamp: u64,
    flags: u32,
    nonce: u64,
    mac16: [u8; 16],
}

fn snapshot_slot_sectors() -> u64 {
    let bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(MAX_SNAPSHOT_SIZE);
    ((bytes + SNAPSHOT_DISK_SECTOR_BYTES - 1) / SNAPSHOT_DISK_SECTOR_BYTES) as u64
}

fn snapshot_slot_base_lba(slot_id: u16) -> Option<u64> {
    let capacity = crate::fs::virtio_blk::capacity_sectors()?;
    let slot_sectors = snapshot_slot_sectors();
    let total_reserved = slot_sectors.saturating_mul(3).saturating_add(1);
    if capacity <= total_reserved {
        return None;
    }
    let base = capacity.saturating_sub(slot_sectors.saturating_mul(3));
    match slot_id {
        SNAPSHOT_DISK_SLOT_GENERIC => Some(base),
        SNAPSHOT_DISK_SLOT_TEMPORAL => Some(base.saturating_add(slot_sectors)),
        SNAPSHOT_DISK_SLOT_VFS => Some(base.saturating_add(slot_sectors.saturating_mul(2))),
        _ => None,
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    if offset.saturating_add(2) > data.len() {
        return None;
    }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
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

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
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

fn encode_snapshot_header_v1(header: SnapshotDiskHeader) -> [u8; SNAPSHOT_DISK_HEADER_BYTES] {
    let mut out = [0u8; SNAPSHOT_DISK_HEADER_BYTES];
    out[0..4].copy_from_slice(&header.magic.to_le_bytes());
    out[4..6].copy_from_slice(&header.version.to_le_bytes());
    out[6..8].copy_from_slice(&header.slot_id.to_le_bytes());
    out[8..12].copy_from_slice(&header.data_len.to_le_bytes());
    out[12..20].copy_from_slice(&header.last_offset.to_le_bytes());
    out[20..28].copy_from_slice(&header.timestamp.to_le_bytes());
    out[28..32].copy_from_slice(&header.crc32.to_le_bytes());
    out
}

fn decode_snapshot_header_v1(data: &[u8]) -> Option<SnapshotDiskHeader> {
    if data.len() < SNAPSHOT_DISK_HEADER_BYTES {
        return None;
    }
    Some(SnapshotDiskHeader {
        magic: read_u32(data, 0)?,
        version: read_u16(data, 4)?,
        slot_id: read_u16(data, 6)?,
        data_len: read_u32(data, 8)?,
        last_offset: read_u64(data, 12)?,
        timestamp: read_u64(data, 20)?,
        crc32: read_u32(data, 28)?,
    })
}

fn encode_snapshot_header_v2(header: SnapshotDiskHeaderV2) -> [u8; SNAPSHOT_DISK_HEADER_BYTES] {
    let mut out = [0u8; SNAPSHOT_DISK_HEADER_BYTES];
    out[0..4].copy_from_slice(&header.magic.to_le_bytes());
    out[4..6].copy_from_slice(&header.version.to_le_bytes());
    out[6..8].copy_from_slice(&header.slot_id.to_le_bytes());
    out[8..12].copy_from_slice(&header.data_len.to_le_bytes());
    out[12..20].copy_from_slice(&header.last_offset.to_le_bytes());
    out[20..28].copy_from_slice(&header.timestamp.to_le_bytes());
    out[28..32].copy_from_slice(&header.flags.to_le_bytes());
    out[32..40].copy_from_slice(&header.nonce.to_le_bytes());
    out[40..56].copy_from_slice(&header.mac16);
    out
}

fn decode_snapshot_header_v2(data: &[u8]) -> Option<SnapshotDiskHeaderV2> {
    if data.len() < SNAPSHOT_DISK_HEADER_BYTES {
        return None;
    }
    let mut mac16 = [0u8; 16];
    mac16.copy_from_slice(&data[40..56]);
    Some(SnapshotDiskHeaderV2 {
        magic: read_u32(data, 0)?,
        version: read_u16(data, 4)?,
        slot_id: read_u16(data, 6)?,
        data_len: read_u32(data, 8)?,
        last_offset: read_u64(data, 12)?,
        timestamp: read_u64(data, 20)?,
        flags: read_u32(data, 28)?,
        nonce: read_u64(data, 32)?,
        mac16,
    })
}

fn derive_snapshot_seal_keys(slot_id: u16) -> ([u8; 16], [u8; 32]) {
    let master = crate::security::persistence_seal_key();

    let mut enc = crate::crypto::Sha256::new();
    enc.update(b"oreulius:persist:enc:");
    enc.update(&slot_id.to_le_bytes());
    enc.update(&master);
    let enc_digest = enc.finalize();
    let mut enc_key = [0u8; 16];
    enc_key.copy_from_slice(&enc_digest[..16]);

    let mut mac = crate::crypto::Sha256::new();
    mac.update(b"oreulius:persist:mac:");
    mac.update(&slot_id.to_le_bytes());
    mac.update(&master);
    let mac_key = mac.finalize();

    (enc_key, mac_key)
}

fn compute_snapshot_mac_v2(
    mac_key: &[u8; 32],
    header_bytes: &[u8; SNAPSHOT_DISK_HEADER_BYTES],
    payload: &[u8],
) -> [u8; 16] {
    let mut h = crate::crypto::HmacSha256::new(mac_key);
    h.update(header_bytes);
    h.update(payload);
    h.finalize_trunc16()
}

// ============================================================================
// Store Capabilities
// ============================================================================

/// Store capability rights
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreRights {
    bits: u32,
}

impl StoreRights {
    pub const NONE: u32 = 0;
    pub const APPEND_LOG: u32 = 1 << 0;
    pub const READ_LOG: u32 = 1 << 1;
    pub const WRITE_SNAPSHOT: u32 = 1 << 2;
    pub const READ_SNAPSHOT: u32 = 1 << 3;
    pub const ALL: u32 =
        Self::APPEND_LOG | Self::READ_LOG | Self::WRITE_SNAPSHOT | Self::READ_SNAPSHOT;

    pub const fn new(bits: u32) -> Self {
        StoreRights { bits }
    }

    pub const fn has(&self, right: u32) -> bool {
        (self.bits & right) != 0
    }

    pub const fn all() -> Self {
        StoreRights { bits: Self::ALL }
    }
}

/// A capability to access the persistence store
#[derive(Debug, Clone, Copy)]
pub struct StoreCapability {
    pub cap_id: u32,
    pub rights: StoreRights,
}

impl StoreCapability {
    pub fn new(cap_id: u32, rights: StoreRights) -> Self {
        StoreCapability { cap_id, rights }
    }
}

// ============================================================================
// Persistence Service
// ============================================================================

/// The persistence service manages logs and snapshots
pub struct PersistenceService {
    /// The append-only log
    log: AppendLog,
    /// The current snapshot
    snapshot: Snapshot,
    /// Dedicated temporal-object snapshot state
    temporal_snapshot: Snapshot,
    /// Dedicated VFS snapshot state
    vfs_snapshot: Snapshot,
    /// True once we have attempted snapshot recovery from all durable backends.
    durable_recovery_attempted: bool,
}

impl PersistenceService {
    /// Create a new persistence service
    pub const fn new() -> Self {
        PersistenceService {
            log: AppendLog::new(),
            snapshot: Snapshot::new(),
            temporal_snapshot: Snapshot::new(),
            vfs_snapshot: Snapshot::new(),
            durable_recovery_attempted: false,
        }
    }

    /// Append a record to the log
    pub fn append_log(
        &mut self,
        capability: &StoreCapability,
        record: LogRecord,
    ) -> Result<usize, PersistenceError> {
        if !capability.rights.has(StoreRights::APPEND_LOG) {
            return Err(PersistenceError::PermissionDenied);
        }

        self.log.append(record)
    }

    /// Read log records
    pub fn read_log(
        &self,
        capability: &StoreCapability,
        from_offset: usize,
        max_records: usize,
    ) -> Result<impl Iterator<Item = &LogRecord>, PersistenceError> {
        if !capability.rights.has(StoreRights::READ_LOG) {
            return Err(PersistenceError::PermissionDenied);
        }

        Ok(self.log.read(from_offset, max_records))
    }

    /// Write a snapshot
    pub fn write_snapshot(
        &mut self,
        capability: &StoreCapability,
        data: &[u8],
        last_offset: usize,
    ) -> Result<(), PersistenceError> {
        if !capability.rights.has(StoreRights::WRITE_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }

        self.snapshot.write(data, last_offset)?;
        let _ = Self::write_snapshot_to_durable(SNAPSHOT_DISK_SLOT_GENERIC, &self.snapshot);
        Ok(())
    }

    /// Read the current snapshot
    pub fn read_snapshot(
        &self,
        capability: &StoreCapability,
    ) -> Result<(&[u8], usize), PersistenceError> {
        if !capability.rights.has(StoreRights::READ_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }

        Ok(self.snapshot.read())
    }

    /// Write temporal-object snapshot bytes.
    pub fn write_temporal_snapshot(
        &mut self,
        capability: &StoreCapability,
        data: &[u8],
        last_offset: usize,
    ) -> Result<(), PersistenceError> {
        if !capability.rights.has(StoreRights::WRITE_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }
        self.temporal_snapshot.write(data, last_offset)?;
        // Avoid the file-backed fallback here: temporal writes are often issued while the
        // caller already holds the VFS lock, and the file backend re-enters VFS.
        let _ = Self::write_snapshot_to_preferred_durable(
            SNAPSHOT_DISK_SLOT_TEMPORAL,
            &self.temporal_snapshot,
        );
        Ok(())
    }

    /// Read temporal-object snapshot bytes.
    pub fn read_temporal_snapshot(
        &self,
        capability: &StoreCapability,
    ) -> Result<(&[u8], usize), PersistenceError> {
        if !capability.rights.has(StoreRights::READ_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }
        Ok(self.temporal_snapshot.read())
    }

    /// Write VFS snapshot bytes to durable storage.
    pub fn write_vfs_snapshot(
        &mut self,
        capability: &StoreCapability,
        data: &[u8],
        last_offset: usize,
    ) -> Result<(), PersistenceError> {
        if !capability.rights.has(StoreRights::WRITE_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }
        self.vfs_snapshot.write(data, last_offset)?;
        Self::write_snapshot_to_preferred_durable(SNAPSHOT_DISK_SLOT_VFS, &self.vfs_snapshot)
    }

    /// Read VFS snapshot bytes from the last recovered durable state.
    pub fn read_vfs_snapshot(
        &self,
        capability: &StoreCapability,
    ) -> Result<(&[u8], usize), PersistenceError> {
        if !capability.rights.has(StoreRights::READ_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }
        Ok(self.vfs_snapshot.read())
    }

    /// Get log statistics
    pub fn log_stats(&self) -> (usize, usize) {
        (self.log.count(), MAX_LOG_RECORDS)
    }

    fn write_snapshot_to_durable(
        slot_id: u16,
        snapshot: &Snapshot,
    ) -> Result<(), PersistenceError> {
        match Self::write_snapshot_to_disk(slot_id, snapshot) {
            Ok(()) => Ok(()),
            Err(PersistenceError::BackendUnavailable) => {
                match Self::write_snapshot_to_external(slot_id, snapshot) {
                    Ok(()) => Ok(()),
                    Err(PersistenceError::BackendUnavailable) => {
                        Self::write_snapshot_to_file(slot_id, snapshot)
                    }
                    Err(_) => Self::write_snapshot_to_file(slot_id, snapshot),
                }
            }
            Err(primary_err) => match Self::write_snapshot_to_file(slot_id, snapshot) {
                Ok(()) => Ok(()),
                Err(_) => Err(primary_err),
            },
        }
    }

    fn write_snapshot_to_preferred_durable(
        slot_id: u16,
        snapshot: &Snapshot,
    ) -> Result<(), PersistenceError> {
        match Self::write_snapshot_to_disk(slot_id, snapshot) {
            Ok(()) => Ok(()),
            Err(PersistenceError::BackendUnavailable) => {
                Self::write_snapshot_to_external(slot_id, snapshot)
            }
            Err(primary_err) => match Self::write_snapshot_to_external(slot_id, snapshot) {
                Ok(()) => Ok(()),
                Err(PersistenceError::BackendUnavailable) => Err(primary_err),
                Err(_) => Err(primary_err),
            },
        }
    }

    fn read_snapshot_from_durable(
        slot_id: u16,
        out: &mut Snapshot,
    ) -> Result<bool, PersistenceError> {
        match Self::read_snapshot_from_disk(slot_id, out) {
            Ok(true) => Ok(true),
            Ok(false) | Err(PersistenceError::BackendUnavailable) => {
                match Self::read_snapshot_from_external(slot_id, out) {
                    Ok(true) => Ok(true),
                    Ok(false) | Err(PersistenceError::BackendUnavailable) => {
                        Self::read_snapshot_from_file(slot_id, out)
                    }
                    Err(_) => Self::read_snapshot_from_file(slot_id, out),
                }
            }
            Err(primary_err) => match Self::read_snapshot_from_file(slot_id, out) {
                Ok(true) => Ok(true),
                Ok(false) => Err(primary_err),
                Err(_) => Err(primary_err),
            },
        }
    }

    fn read_snapshot_from_preferred_durable(
        slot_id: u16,
        out: &mut Snapshot,
    ) -> Result<bool, PersistenceError> {
        match Self::read_snapshot_from_disk(slot_id, out) {
            Ok(true) => Ok(true),
            Ok(false) | Err(PersistenceError::BackendUnavailable) => {
                Self::read_snapshot_from_external(slot_id, out)
            }
            Err(primary_err) => match Self::read_snapshot_from_external(slot_id, out) {
                Ok(found) => Ok(found),
                Err(PersistenceError::BackendUnavailable) => Err(primary_err),
                Err(_) => Err(primary_err),
            },
        }
    }

    fn write_snapshot_to_disk(slot_id: u16, snapshot: &Snapshot) -> Result<(), PersistenceError> {
        if !crate::fs::virtio_blk::is_present() {
            return Err(PersistenceError::BackendUnavailable);
        }

        let base_lba = snapshot_slot_base_lba(slot_id).ok_or(PersistenceError::InvalidRecord)?;
        let max_slot_bytes =
            (snapshot_slot_sectors() as usize).saturating_mul(SNAPSHOT_DISK_SECTOR_BYTES);
        let total_bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(snapshot.data_len);
        if total_bytes > max_slot_bytes {
            return Err(PersistenceError::SnapshotTooLarge);
        }

        let data_len = snapshot.data_len;
        let total_bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(data_len);

        let (enc_key, mac_key) = derive_snapshot_seal_keys(slot_id);
        let nonce = next_snapshot_nonce();
        let mut header_bytes = encode_snapshot_header_v2(SnapshotDiskHeaderV2 {
            magic: SNAPSHOT_DISK_MAGIC,
            version: SNAPSHOT_DISK_VERSION_V2,
            slot_id,
            data_len: data_len as u32,
            last_offset: snapshot.last_offset as u64,
            timestamp: snapshot.timestamp,
            flags: SNAPSHOT_V2_FLAG_SEALED | SNAPSHOT_V2_FLAG_ENCRYPTED,
            nonce,
            mac16: [0u8; 16],
        });

        let sectors = (total_bytes + SNAPSHOT_DISK_SECTOR_BYTES - 1) / SNAPSHOT_DISK_SECTOR_BYTES;
        let image_len = sectors.saturating_mul(SNAPSHOT_DISK_SECTOR_BYTES);
        if image_len > SNAPSHOT_IO_SCRATCH_BYTES {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let mut scratch = SNAPSHOT_IO_SCRATCH.lock();
        let image = &mut scratch.image[..image_len];
        image.fill(0);
        image[..SNAPSHOT_DISK_HEADER_BYTES].copy_from_slice(&header_bytes);
        if data_len != 0 {
            let off = SNAPSHOT_DISK_HEADER_BYTES;
            image[off..off + data_len].copy_from_slice(&snapshot.data[..data_len]);
            {
                let image_len = image.len();
                let payload = &mut image[off..off + data_len];
                trace_snapshot_crypto(
                    "disk-write-enc",
                    slot_id,
                    payload.as_ptr(),
                    payload.len(),
                    image_len,
                );
                crate::crypto::aes128_ctr_xor(&enc_key, nonce, payload);
            }
            let mac = compute_snapshot_mac_v2(&mac_key, &header_bytes, &image[off..off + data_len]);
            image[40..56].copy_from_slice(&mac);
            header_bytes[40..56].copy_from_slice(&mac);
        } else {
            let mac = compute_snapshot_mac_v2(&mac_key, &header_bytes, &[]);
            image[40..56].copy_from_slice(&mac);
            header_bytes[40..56].copy_from_slice(&mac);
        }

        let mut i = 0usize;
        while i < sectors {
            let start = i * SNAPSHOT_DISK_SECTOR_BYTES;
            let end = start + SNAPSHOT_DISK_SECTOR_BYTES;
            crate::fs::virtio_blk::write_sector(base_lba + i as u64, &image[start..end])
                .map_err(|_| PersistenceError::InvalidRecord)?;
            i += 1;
        }
        Ok(())
    }

    fn read_snapshot_from_disk(slot_id: u16, out: &mut Snapshot) -> Result<bool, PersistenceError> {
        if !crate::fs::virtio_blk::is_present() {
            return Err(PersistenceError::BackendUnavailable);
        }

        let base_lba = match snapshot_slot_base_lba(slot_id) {
            Some(v) => v,
            None => return Ok(false),
        };

        let mut first_sector = [0u8; SNAPSHOT_DISK_SECTOR_BYTES];
        crate::fs::virtio_blk::read_sector(base_lba, &mut first_sector)
            .map_err(|_| PersistenceError::InvalidRecord)?;
        let magic = match read_u32(&first_sector, 0) {
            Some(v) => v,
            None => return Ok(false),
        };
        let version = match read_u16(&first_sector, 4) {
            Some(v) => v,
            None => return Ok(false),
        };
        if magic != SNAPSHOT_DISK_MAGIC {
            return Ok(false);
        }

        if version == SNAPSHOT_DISK_VERSION_V1 {
            let header = match decode_snapshot_header_v1(&first_sector) {
                Some(h) => h,
                None => return Ok(false),
            };
            if header.slot_id != slot_id {
                return Ok(false);
            }

            let data_len = header.data_len as usize;
            if data_len > MAX_SNAPSHOT_SIZE {
                return Err(PersistenceError::SnapshotTooLarge);
            }

            let total_bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(data_len);
            let sectors =
                (total_bytes + SNAPSHOT_DISK_SECTOR_BYTES - 1) / SNAPSHOT_DISK_SECTOR_BYTES;
            let image_len = sectors.saturating_mul(SNAPSHOT_DISK_SECTOR_BYTES);
            if image_len > SNAPSHOT_IO_SCRATCH_BYTES {
                return Err(PersistenceError::SnapshotTooLarge);
            }
            let mut scratch = SNAPSHOT_IO_SCRATCH.lock();
            let image = &mut scratch.image[..image_len];
            image.fill(0);
            image[..SNAPSHOT_DISK_SECTOR_BYTES].copy_from_slice(&first_sector);

            let mut i = 1usize;
            while i < sectors {
                let start = i * SNAPSHOT_DISK_SECTOR_BYTES;
                let end = start + SNAPSHOT_DISK_SECTOR_BYTES;
                crate::fs::virtio_blk::read_sector(base_lba + i as u64, &mut image[start..end])
                    .map_err(|_| PersistenceError::InvalidRecord)?;
                i += 1;
            }

            let payload_off = SNAPSHOT_DISK_HEADER_BYTES;
            let payload_end = payload_off.saturating_add(data_len);
            let payload = &image[payload_off..payload_end];
            if LogRecord::compute_crc32(payload) != header.crc32 {
                return Err(PersistenceError::CrcMismatch);
            }

            if !payload.is_empty() {
                out.data[..payload.len()].copy_from_slice(payload);
            }
            out.data_len = payload.len();
            out.last_offset = header.last_offset as usize;
            out.timestamp = header.timestamp;
            return Ok(true);
        }

        if version != SNAPSHOT_DISK_VERSION_V2 {
            return Ok(false);
        }

        let header = match decode_snapshot_header_v2(&first_sector) {
            Some(h) => h,
            None => return Ok(false),
        };
        if header.slot_id != slot_id {
            return Ok(false);
        }
        if (header.flags & SNAPSHOT_V2_FLAG_SEALED) == 0 {
            return Err(PersistenceError::InvalidRecord);
        }

        let data_len = header.data_len as usize;
        if data_len > MAX_SNAPSHOT_SIZE {
            return Err(PersistenceError::SnapshotTooLarge);
        }

        let total_bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(data_len);
        let sectors = (total_bytes + SNAPSHOT_DISK_SECTOR_BYTES - 1) / SNAPSHOT_DISK_SECTOR_BYTES;
        let image_len = sectors.saturating_mul(SNAPSHOT_DISK_SECTOR_BYTES);
        if image_len > SNAPSHOT_IO_SCRATCH_BYTES {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let mut scratch = SNAPSHOT_IO_SCRATCH.lock();
        let image = &mut scratch.image[..image_len];
        image.fill(0);
        image[..SNAPSHOT_DISK_SECTOR_BYTES].copy_from_slice(&first_sector);

        let mut i = 1usize;
        while i < sectors {
            let start = i * SNAPSHOT_DISK_SECTOR_BYTES;
            let end = start + SNAPSHOT_DISK_SECTOR_BYTES;
            crate::fs::virtio_blk::read_sector(base_lba + i as u64, &mut image[start..end])
                .map_err(|_| PersistenceError::InvalidRecord)?;
            i += 1;
        }

        let payload_off = SNAPSHOT_DISK_HEADER_BYTES;
        let payload_end = payload_off.saturating_add(data_len);
        let payload = &image[payload_off..payload_end];

        let (_, mac_key) = derive_snapshot_seal_keys(slot_id);
        let mut header_mac_input = [0u8; SNAPSHOT_DISK_HEADER_BYTES];
        header_mac_input.copy_from_slice(&image[..SNAPSHOT_DISK_HEADER_BYTES]);
        header_mac_input[40..56].fill(0);
        let expected_mac = compute_snapshot_mac_v2(&mac_key, &header_mac_input, payload);
        if !crate::crypto::ct_eq(&expected_mac, &header.mac16) {
            return Err(PersistenceError::IntegrityMismatch);
        }

        observe_snapshot_nonce(header.nonce);

        if data_len != 0 {
            out.data[..data_len].copy_from_slice(payload);
            if (header.flags & SNAPSHOT_V2_FLAG_ENCRYPTED) != 0 {
                let (enc_key, _) = derive_snapshot_seal_keys(slot_id);
                {
                    let payload = &mut out.data[..data_len];
                    trace_snapshot_crypto(
                        "disk-read-dec",
                        slot_id,
                        payload.as_ptr(),
                        payload.len(),
                        image.len(),
                    );
                    crate::crypto::aes128_ctr_xor(&enc_key, header.nonce, payload);
                }
            }
        }
        out.data_len = data_len;
        out.last_offset = header.last_offset as usize;
        out.timestamp = header.timestamp;
        Ok(true)
    }

    fn snapshot_file_path(slot_id: u16) -> Option<&'static str> {
        match slot_id {
            SNAPSHOT_DISK_SLOT_GENERIC => Some(SNAPSHOT_FILE_PATH_GENERIC),
            SNAPSHOT_DISK_SLOT_TEMPORAL => Some(SNAPSHOT_FILE_PATH_TEMPORAL),
            _ => None,
        }
    }

    fn write_snapshot_to_file(slot_id: u16, snapshot: &Snapshot) -> Result<(), PersistenceError> {
        let path = Self::snapshot_file_path(slot_id).ok_or(PersistenceError::InvalidRecord)?;
        let total_bytes = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(snapshot.data_len);
        if total_bytes > MAX_SNAPSHOT_SIZE.saturating_add(SNAPSHOT_DISK_HEADER_BYTES) {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let data_len = snapshot.data_len;
        let (enc_key, mac_key) = derive_snapshot_seal_keys(slot_id);
        let nonce = next_snapshot_nonce();
        let mut header_bytes = encode_snapshot_header_v2(SnapshotDiskHeaderV2 {
            magic: SNAPSHOT_DISK_MAGIC,
            version: SNAPSHOT_DISK_VERSION_V2,
            slot_id,
            data_len: data_len as u32,
            last_offset: snapshot.last_offset as u64,
            timestamp: snapshot.timestamp,
            flags: SNAPSHOT_V2_FLAG_SEALED | SNAPSHOT_V2_FLAG_ENCRYPTED,
            nonce,
            mac16: [0u8; 16],
        });

        if total_bytes > SNAPSHOT_IO_SCRATCH_BYTES {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let mut scratch = SNAPSHOT_IO_SCRATCH.lock();
        let image = &mut scratch.image[..total_bytes];
        image.fill(0);
        image[..SNAPSHOT_DISK_HEADER_BYTES].copy_from_slice(&header_bytes);
        if data_len != 0 {
            let off = SNAPSHOT_DISK_HEADER_BYTES;
            image[off..off + data_len].copy_from_slice(&snapshot.data[..data_len]);
            {
                let image_len = image.len();
                let payload = &mut image[off..off + data_len];
                trace_snapshot_crypto(
                    "file-write-enc",
                    slot_id,
                    payload.as_ptr(),
                    payload.len(),
                    image_len,
                );
                crate::crypto::aes128_ctr_xor(&enc_key, nonce, payload);
            }
            let mac = compute_snapshot_mac_v2(&mac_key, &header_bytes, &image[off..off + data_len]);
            image[40..56].copy_from_slice(&mac);
            header_bytes[40..56].copy_from_slice(&mac);
        } else {
            let mac = compute_snapshot_mac_v2(&mac_key, &header_bytes, &[]);
            image[40..56].copy_from_slice(&mac);
            header_bytes[40..56].copy_from_slice(&mac);
        }

        crate::fs::vfs::write_path_untracked(path, &image)
            .map(|_| ())
            .map_err(|_| PersistenceError::InvalidRecord)
    }

    fn write_snapshot_to_external(
        slot_id: u16,
        snapshot: &Snapshot,
    ) -> Result<(), PersistenceError> {
        let backend = {
            let guard = EXTERNAL_SNAPSHOT_BACKEND.lock();
            *guard
        };
        match backend {
            Some(backend) => (backend.write)(slot_id, snapshot),
            None => Err(PersistenceError::BackendUnavailable),
        }
    }

    fn read_snapshot_from_file(slot_id: u16, out: &mut Snapshot) -> Result<bool, PersistenceError> {
        let path = match Self::snapshot_file_path(slot_id) {
            Some(path) => path,
            None => return Ok(false),
        };

        let read_cap = SNAPSHOT_DISK_HEADER_BYTES.saturating_add(MAX_SNAPSHOT_SIZE);
        if read_cap > SNAPSHOT_IO_SCRATCH_BYTES {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let mut scratch = SNAPSHOT_IO_SCRATCH.lock();
        let image_mut = &mut scratch.image[..read_cap];
        image_mut.fill(0);
        let read = match crate::fs::vfs::read_path(path, image_mut) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };
        if read < SNAPSHOT_DISK_HEADER_BYTES {
            return Ok(false);
        }
        let image = &scratch.image[..read];

        let magic = match read_u32(&image, 0) {
            Some(v) => v,
            None => return Ok(false),
        };
        let version = match read_u16(&image, 4) {
            Some(v) => v,
            None => return Ok(false),
        };
        if magic != SNAPSHOT_DISK_MAGIC {
            return Ok(false);
        }

        if version == SNAPSHOT_DISK_VERSION_V1 {
            let header = match decode_snapshot_header_v1(&image[..SNAPSHOT_DISK_HEADER_BYTES]) {
                Some(h) => h,
                None => return Ok(false),
            };
            if header.slot_id != slot_id {
                return Ok(false);
            }

            let data_len = header.data_len as usize;
            if data_len > MAX_SNAPSHOT_SIZE {
                return Err(PersistenceError::SnapshotTooLarge);
            }
            let payload_off = SNAPSHOT_DISK_HEADER_BYTES;
            let payload_end = payload_off.saturating_add(data_len);
            if payload_end > image.len() {
                return Err(PersistenceError::InvalidRecord);
            }
            let payload = &image[payload_off..payload_end];
            if LogRecord::compute_crc32(payload) != header.crc32 {
                return Err(PersistenceError::CrcMismatch);
            }

            if data_len != 0 {
                out.data[..data_len].copy_from_slice(payload);
            }
            out.data_len = data_len;
            out.last_offset = header.last_offset as usize;
            out.timestamp = header.timestamp;
            return Ok(true);
        }

        if version != SNAPSHOT_DISK_VERSION_V2 {
            return Ok(false);
        }

        let header = match decode_snapshot_header_v2(&image[..SNAPSHOT_DISK_HEADER_BYTES]) {
            Some(h) => h,
            None => return Ok(false),
        };
        if header.slot_id != slot_id {
            return Ok(false);
        }
        if (header.flags & SNAPSHOT_V2_FLAG_SEALED) == 0 {
            return Err(PersistenceError::InvalidRecord);
        }

        let data_len = header.data_len as usize;
        if data_len > MAX_SNAPSHOT_SIZE {
            return Err(PersistenceError::SnapshotTooLarge);
        }
        let payload_off = SNAPSHOT_DISK_HEADER_BYTES;
        let payload_end = payload_off.saturating_add(data_len);
        if payload_end > image.len() {
            return Err(PersistenceError::InvalidRecord);
        }
        let payload = &image[payload_off..payload_end];

        let (_, mac_key) = derive_snapshot_seal_keys(slot_id);
        let mut header_mac_input = [0u8; SNAPSHOT_DISK_HEADER_BYTES];
        header_mac_input.copy_from_slice(&image[..SNAPSHOT_DISK_HEADER_BYTES]);
        header_mac_input[40..56].fill(0);
        let expected_mac = compute_snapshot_mac_v2(&mac_key, &header_mac_input, payload);
        if !crate::crypto::ct_eq(&expected_mac, &header.mac16) {
            return Err(PersistenceError::IntegrityMismatch);
        }

        observe_snapshot_nonce(header.nonce);

        if data_len != 0 {
            out.data[..data_len].copy_from_slice(payload);
            if (header.flags & SNAPSHOT_V2_FLAG_ENCRYPTED) != 0 {
                let (enc_key, _) = derive_snapshot_seal_keys(slot_id);
                {
                    let payload = &mut out.data[..data_len];
                    trace_snapshot_crypto(
                        "file-read-dec",
                        slot_id,
                        payload.as_ptr(),
                        payload.len(),
                        image.len(),
                    );
                    crate::crypto::aes128_ctr_xor(&enc_key, header.nonce, payload);
                }
            }
        }
        out.data_len = data_len;
        out.last_offset = header.last_offset as usize;
        out.timestamp = header.timestamp;
        Ok(true)
    }

    fn read_snapshot_from_external(
        slot_id: u16,
        out: &mut Snapshot,
    ) -> Result<bool, PersistenceError> {
        let backend = {
            let guard = EXTERNAL_SNAPSHOT_BACKEND.lock();
            *guard
        };
        match backend {
            Some(backend) => (backend.read)(slot_id, out),
            None => Err(PersistenceError::BackendUnavailable),
        }
    }

    fn recover_snapshots_from_durable(&mut self) {
        let durable_backend_available =
            crate::fs::virtio_blk::is_present() || EXTERNAL_SNAPSHOT_BACKEND.lock().is_some();
        if self.durable_recovery_attempted || !durable_backend_available {
            return;
        }
        if self.snapshot.data_len == 0 {
            let _ =
                Self::read_snapshot_from_durable(SNAPSHOT_DISK_SLOT_GENERIC, &mut self.snapshot);
        }
        if self.temporal_snapshot.data_len == 0 {
            let _ = Self::read_snapshot_from_durable(
                SNAPSHOT_DISK_SLOT_TEMPORAL,
                &mut self.temporal_snapshot,
            );
        }
        if self.vfs_snapshot.data_len == 0 {
            let _ = Self::read_snapshot_from_preferred_durable(
                SNAPSHOT_DISK_SLOT_VFS,
                &mut self.vfs_snapshot,
            );
        }
        self.durable_recovery_attempted = true;
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Persistence errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceError {
    /// Record too large
    RecordTooLarge,
    /// Log is full
    LogFull,
    /// Snapshot too large
    SnapshotTooLarge,
    /// Permission denied
    PermissionDenied,
    /// Invalid record
    InvalidRecord,
    /// CRC mismatch
    CrcMismatch,
    /// Cryptographic integrity check failed
    IntegrityMismatch,
    /// Durable backend unavailable
    BackendUnavailable,
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PersistenceError::RecordTooLarge => write!(f, "Record too large"),
            PersistenceError::LogFull => write!(f, "Log is full"),
            PersistenceError::SnapshotTooLarge => write!(f, "Snapshot too large"),
            PersistenceError::PermissionDenied => write!(f, "Permission denied"),
            PersistenceError::InvalidRecord => write!(f, "Invalid record"),
            PersistenceError::CrcMismatch => write!(f, "CRC mismatch"),
            PersistenceError::IntegrityMismatch => write!(f, "Integrity mismatch"),
            PersistenceError::BackendUnavailable => write!(f, "Durable backend unavailable"),
        }
    }
}

// ============================================================================
// Global Persistence Instance
// ============================================================================

use spin::Mutex;

/// Global persistence service instance
static PERSISTENCE: Mutex<PersistenceService> = Mutex::new(PersistenceService::new());
static EXTERNAL_SNAPSHOT_BACKEND: Mutex<Option<SnapshotBackend>> = Mutex::new(None);

/// Get a reference to the global persistence service
pub fn persistence() -> &'static Mutex<PersistenceService> {
    &PERSISTENCE
}

pub fn register_snapshot_backend(backend: SnapshotBackend) {
    let mut slot = EXTERNAL_SNAPSHOT_BACKEND.lock();
    *slot = Some(backend);
}

pub fn clear_snapshot_backend() {
    let mut slot = EXTERNAL_SNAPSHOT_BACKEND.lock();
    *slot = None;
}

/// Initialize the persistence service
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    crate::serial_println!("[PERSIST] init begin");
    seed_snapshot_nonce();
    #[cfg(target_arch = "x86_64")]
    crate::serial_println!("[PERSIST] seed complete");
    let mut svc = PERSISTENCE.lock();
    svc.recover_snapshots_from_durable();
    #[cfg(target_arch = "x86_64")]
    crate::serial_println!("[PERSIST] recovery complete");
}
