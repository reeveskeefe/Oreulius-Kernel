//! Oreulia Persistence v0
//!
//! Provides append-only logs, snapshots, and replay-based recovery
//! for durable state management.

#![allow(dead_code)]

use core::fmt;

/// Maximum log record size (64 KiB)
pub const MAX_RECORD_SIZE: usize = 64 * 1024;

/// Maximum number of log records (for v0 RAM-backed)
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
}

impl RecordType {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            1 => Some(RecordType::ExternalInputClockRead),
            2 => Some(RecordType::ExternalInputConsoleIn),
            3 => Some(RecordType::ComponentEvent),
            4 => Some(RecordType::SupervisorCheckpoint),
            10 => Some(RecordType::FilesystemOp),
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

/// Maximum snapshot size (1 MiB for v0)
pub const MAX_SNAPSHOT_SIZE: usize = 1024 * 1024;

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
        self.timestamp = 0; // TODO: get from timer

        Ok(())
    }

    /// Read snapshot data
    pub fn read(&self) -> (&[u8], usize) {
        (&self.data[..self.data_len], self.last_offset)
    }
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
    pub const ALL: u32 = Self::APPEND_LOG | Self::READ_LOG | Self::WRITE_SNAPSHOT | Self::READ_SNAPSHOT;

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
}

impl PersistenceService {
    /// Create a new persistence service
    pub const fn new() -> Self {
        PersistenceService {
            log: AppendLog::new(),
            snapshot: Snapshot::new(),
        }
    }

    /// Append a record to the log
    pub fn append_log(&mut self, capability: &StoreCapability, record: LogRecord) -> Result<usize, PersistenceError> {
        if !capability.rights.has(StoreRights::APPEND_LOG) {
            return Err(PersistenceError::PermissionDenied);
        }

        self.log.append(record)
    }

    /// Read log records
    pub fn read_log(&self, capability: &StoreCapability, from_offset: usize, max_records: usize) -> Result<impl Iterator<Item = &LogRecord>, PersistenceError> {
        if !capability.rights.has(StoreRights::READ_LOG) {
            return Err(PersistenceError::PermissionDenied);
        }

        Ok(self.log.read(from_offset, max_records))
    }

    /// Write a snapshot
    pub fn write_snapshot(&mut self, capability: &StoreCapability, data: &[u8], last_offset: usize) -> Result<(), PersistenceError> {
        if !capability.rights.has(StoreRights::WRITE_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }

        self.snapshot.write(data, last_offset)
    }

    /// Read the current snapshot
    pub fn read_snapshot(&self, capability: &StoreCapability) -> Result<(&[u8], usize), PersistenceError> {
        if !capability.rights.has(StoreRights::READ_SNAPSHOT) {
            return Err(PersistenceError::PermissionDenied);
        }

        Ok(self.snapshot.read())
    }

    /// Get log statistics
    pub fn log_stats(&self) -> (usize, usize) {
        (self.log.count(), MAX_LOG_RECORDS)
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
        }
    }
}

// ============================================================================
// Global Persistence Instance
// ============================================================================

use spin::Mutex;

/// Global persistence service instance
static PERSISTENCE: Mutex<PersistenceService> = Mutex::new(PersistenceService::new());

/// Get a reference to the global persistence service
pub fn persistence() -> &'static Mutex<PersistenceService> {
    &PERSISTENCE
}

/// Initialize the persistence service
pub fn init() {
    // In v0, persistence is RAM-backed and statically initialized
    // In future versions, this would:
    // - Mount storage device (virtio block)
    // - Load snapshots from disk
    // - Replay logs for recovery
}
