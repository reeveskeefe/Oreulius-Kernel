//! Cross-language polyglot kernel service bindings.
//!
//! Oreulius allows WASM modules written in **any** language to register
//! themselves as named kernel services and to call each other securely via
//! capability handoffs — even across language boundaries.
//!
//! ## How it works
//!
//! 1. A WASM module embeds the `oreulius_lang` custom section (see
//!    [`docs/runtime/oreulius-wasm-abi.md`]) to declare its language and version.
//! 2. At startup it calls [`register`] to publish its name in the kernel's
//!    polyglot registry (IDs 103–105).
//! 3. A *caller* module calls [`resolve`] to look up the target by name and
//!    obtain its instance ID, then calls [`link`] to receive a capability
//!    handle backed by a durable kernel lineage record. That handle can be
//!    passed to `oreulius_sdk::service::ServicePointer` for typed invocation
//!    or called directly through [`ServiceHandle::invoke_typed`].
//! 4. For audit and transition control, [`lineage_lookup`],
//!    [`lineage_lookup_object`], [`lineage_status`], [`lineage_status_object`],
//!    [`lineage_rebind`], [`lineage_revoke`], [`lineage_query_page`], and
//!    [`lineage_event_query`] expose the latest lifecycle record, page-based
//!    audit scans, and explicit `Live`, `Rebound`, `Revoked`, and `TornDown`
//!    semantics.
//!
//! ## Example — service side (e.g. a Python-via-Pyodide module)
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//!
//! use oreulius_sdk::polyglot;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     polyglot::register("py_math").expect("failed to register service");
//!     // … serve requests …
//! }
//! ```
//!
//! ## Example — client side
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//!
//! use oreulius_sdk::polyglot;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     let handle = polyglot::ServiceHandle::link("py_math", "add")
//!         .expect("py_math service not found");
//!     let _ = handle.invoke_typed(&[]).expect("invoke failed");
//! }
//! ```
//!
//! ## Error codes returned by the kernel
//!
//! | Value | Meaning |
//! |-------|---------|
//! |   0   | Success (register) |
//! |  ≥ 0  | Instance ID (resolve) or cap handle (link) |
//! |  -1   | Bad arguments (null pointer, zero length, name > 32 bytes) |
//! |  -2   | Registry full (register) **or** name not found (resolve / link) |
//! |  -3   | Name already taken by a different, non-singleton module (register) **or** service has no registered export (link) |
//! |  -4   | Capability table full (link) |

use crate::raw::oreulius;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolyglotError {
    InvalidArgument,
    RegistryFull,
    NameConflict,
    NotFound,
    ExportNotFound,
    CapabilityTableFull,
    Unexpected(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolyglotLineageFilter<'a> {
    All,
    SourcePid(u32),
    TargetInstance(u32),
    Lifecycle(u8),
    ExportName(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolyglotLifecycleBucket {
    Registered = 0,
    Linked = 1,
    Live = 2,
    Revoked = 3,
    TornDown = 4,
    Rebound = 5,
    Restored = 6,
}

impl PolyglotLifecycleBucket {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Registered),
            1 => Some(Self::Linked),
            2 => Some(Self::Live),
            3 => Some(Self::Revoked),
            4 => Some(Self::TornDown),
            5 => Some(Self::Rebound),
            6 => Some(Self::Restored),
            _ => None,
        }
    }
}

impl<'a> PolyglotLineageFilter<'a> {
    #[inline]
    pub const fn all() -> Self {
        Self::All
    }

    #[inline]
    pub const fn source_pid(pid: u32) -> Self {
        Self::SourcePid(pid)
    }

    #[inline]
    pub const fn target_instance(instance: u32) -> Self {
        Self::TargetInstance(instance)
    }

    #[inline]
    /// Filter lineage entries that are currently `Live`.
    pub const fn live() -> Self {
        Self::Lifecycle(PolyglotLifecycleBucket::Live.as_u8())
    }

    #[inline]
    /// Filter lineage entries that were rebound during teardown.
    pub const fn rebound() -> Self {
        Self::Lifecycle(PolyglotLifecycleBucket::Rebound.as_u8())
    }

    #[inline]
    /// Filter lineage entries that were torn down.
    pub const fn torn_down() -> Self {
        Self::Lifecycle(PolyglotLifecycleBucket::TornDown.as_u8())
    }

    #[inline]
    pub const fn lifecycle(code: u8) -> Self {
        Self::Lifecycle(code)
    }

    #[inline]
    pub fn export_name(name: &'a str) -> Self {
        Self::ExportName(name)
    }
}

/// Packed lineage record returned by `lineage_query`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyglotLineageRecord {
    pub record_id: u64,
    pub source_pid: u32,
    pub source_instance: u32,
    pub target_instance: u32,
    pub object_id: u64,
    pub cap_id: u32,
    pub language_tag: u8,
    pub export_name_len: u8,
    pub export_name: [u8; 32],
    pub rights: u32,
    pub lifecycle: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Compact lifecycle summary returned by the status ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyglotLineageStatus {
    pub live: bool,
    pub lifecycle: PolyglotLifecycleBucket,
    pub record_id: u64,
    pub object_id: u64,
    pub target_instance: u32,
    pub updated_at: u64,
}

/// A paginated lineage snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyglotLineagePage {
    records: [PolyglotLineageRecord; 64],
    len: usize,
    version: u8,
    next_cursor: u64,
}

impl PolyglotLineagePage {
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn version(&self) -> u8 { self.version }
    pub fn next_cursor(&self) -> u64 { self.next_cursor }
    pub fn iter(&self) -> core::slice::Iter<'_, PolyglotLineageRecord> { self.records[..self.len].iter() }
}

/// Iterator over cursor-paginated lineage pages.
pub struct PolyglotLineagePageIter {
    cursor: u64,
    limit: usize,
    finished: bool,
}

impl PolyglotLineagePageIter {
    #[inline]
    pub const fn new(limit: usize) -> Self {
        Self { cursor: 0, limit, finished: false }
    }
}

impl Iterator for PolyglotLineagePageIter {
    type Item = Result<PolyglotLineagePage, i32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let page = match lineage_query_page(self.cursor, self.limit) {
            Ok(page) => page,
            Err(err) => return Some(Err(err)),
        };
        self.cursor = page.next_cursor();
        if page.is_empty() {
            self.finished = true;
        }
        Some(Ok(page))
    }
}

/// A cursor-paginated batch of lineage transition events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyglotLineageEventBatch {
    events: [PolyglotLineageEvent; 64],
    len: usize,
    next_cursor: u64,
}

impl PolyglotLineageEventBatch {
    #[inline]
    pub fn len(&self) -> usize { self.len }

    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    #[inline]
    pub fn next_cursor(&self) -> u64 { self.next_cursor }

    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, PolyglotLineageEvent> {
        self.events[..self.len].iter()
    }
}

/// Iterator over cursor-paginated lineage event batches.
pub struct PolyglotLineageEventIter {
    cursor: u64,
    limit: usize,
    finished: bool,
}

impl PolyglotLineageEventIter {
    #[inline]
    pub const fn new(limit: usize) -> Self {
        Self { cursor: 0, limit, finished: false }
    }
}

impl Iterator for PolyglotLineageEventIter {
    type Item = Result<PolyglotLineageEventBatch, i32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let (next_cursor, events, len) = match lineage_event_query(self.cursor, self.limit) {
            Ok(value) => value,
            Err(err) => return Some(Err(err)),
        };
        self.cursor = next_cursor;
        let batch = PolyglotLineageEventBatch { events, len, next_cursor };
        if batch.is_empty() {
            self.finished = true;
        }
        Some(Ok(batch))
    }
}

/// A compact transition event record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyglotLineageEvent {
    pub event_id: u64,
    pub object_id: u64,
    pub target_instance: u32,
    pub lifecycle: PolyglotLifecycleBucket,
    pub previous_lifecycle: PolyglotLifecycleBucket,
    pub live: bool,
    pub updated_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageEventWireV1 {
    event_id: u64,
    object_id: u64,
    target_instance: u32,
    lifecycle: u8,
    previous_lifecycle: u8,
    live: u8,
    reserved: u8,
    reserved2: u64,
    reserved3: u64,
    updated_at: u64,
}

impl PolyglotLineageEventWireV1 {
    const BYTES: usize = 40;
    fn decode(buf: &[u8]) -> Result<Self, i32> {
        if buf.len() < Self::BYTES { return Err(-2); }
        let mut event_id = [0u8; 8];
        event_id.copy_from_slice(&buf[0..8]);
        let mut object_id = [0u8; 8];
        object_id.copy_from_slice(&buf[8..16]);
        let mut target_instance = [0u8; 4];
        target_instance.copy_from_slice(&buf[16..20]);
        let mut updated_at = [0u8; 8];
        updated_at.copy_from_slice(&buf[24..32]);
        Ok(Self {
            event_id: u64::from_le_bytes(event_id),
            object_id: u64::from_le_bytes(object_id),
            target_instance: u32::from_le_bytes(target_instance),
            lifecycle: buf[20],
            previous_lifecycle: buf[21],
            live: buf[22],
            reserved: buf[23],
            reserved2: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            reserved3: 0,
            updated_at: u64::from_le_bytes([
                buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
            ]),
        })
    }
}

impl PolyglotLineageRecord {
    #[inline]
    pub fn lifecycle_bucket(&self) -> Option<PolyglotLifecycleBucket> {
        PolyglotLifecycleBucket::from_u8(self.lifecycle)
    }

    #[inline]
    pub fn is_live(&self) -> bool {
        self.lifecycle == PolyglotLifecycleBucket::Live.as_u8()
    }

    #[inline]
    pub fn is_rebound(&self) -> bool {
        self.lifecycle == PolyglotLifecycleBucket::Rebound.as_u8()
    }

    #[inline]
    pub fn is_revoked(&self) -> bool {
        self.lifecycle == PolyglotLifecycleBucket::Revoked.as_u8()
    }

    #[inline]
    pub fn is_torn_down(&self) -> bool {
        self.lifecycle == PolyglotLifecycleBucket::TornDown.as_u8()
    }

    #[inline]
    pub fn is_terminal(&self) -> bool {
        self.is_revoked() || self.is_torn_down()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageWireHeaderV1 {
    version: u8,
    count: u8,
    max_records: u16,
    next_record_id: u32,
}

impl PolyglotLineageWireHeaderV1 {
    const BYTES: usize = 8;

    fn decode(buf: &[u8]) -> Result<Self, i32> {
        if buf.len() < Self::BYTES {
            return Err(-2);
        }
        let mut max_records = [0u8; 2];
        max_records.copy_from_slice(&buf[2..4]);
        let mut next_record_id = [0u8; 4];
        next_record_id.copy_from_slice(&buf[4..8]);
        Ok(Self {
            version: buf[0],
            count: buf[1],
            max_records: u16::from_le_bytes(max_records),
            next_record_id: u32::from_le_bytes(next_record_id),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageWireRecordV1 {
    live: u8,
    lifecycle: u8,
    record_id: u64,
    source_pid: u32,
    source_instance: u32,
    target_instance: u32,
    object_id: u64,
    cap_id: u32,
    language_tag: u8,
    export_name_len: u8,
    export_name: [u8; 32],
    rights: u32,
    created_at: u64,
    updated_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolyglotLineageStatusWireV1 {
    live: u8,
    lifecycle: u8,
    record_id: u64,
    object_id: u64,
    target_instance: u32,
    updated_at: u64,
}

impl PolyglotLineageStatusWireV1 {
    const BYTES: usize = 32;

    fn decode(buf: &[u8]) -> Result<Self, i32> {
        if buf.len() < Self::BYTES {
            return Err(-2);
        }
        let mut record_id = [0u8; 8];
        record_id.copy_from_slice(&buf[4..12]);
        let mut object_id = [0u8; 8];
        object_id.copy_from_slice(&buf[12..20]);
        let mut target_instance = [0u8; 4];
        target_instance.copy_from_slice(&buf[20..24]);
        let mut updated_at = [0u8; 8];
        updated_at.copy_from_slice(&buf[24..32]);
        Ok(Self {
            live: buf[0],
            lifecycle: buf[1],
            record_id: u64::from_le_bytes(record_id),
            object_id: u64::from_le_bytes(object_id),
            target_instance: u32::from_le_bytes(target_instance),
            updated_at: u64::from_le_bytes(updated_at),
        })
    }
}

impl PolyglotLineageWireRecordV1 {
    const BYTES: usize = 96;

    fn decode(buf: &[u8]) -> Result<Self, i32> {
        if buf.len() < Self::BYTES {
            return Err(-2);
        }
        let mut record_id = [0u8; 8];
        record_id.copy_from_slice(&buf[4..12]);
        let mut source_pid = [0u8; 4];
        source_pid.copy_from_slice(&buf[12..16]);
        let mut source_instance = [0u8; 4];
        source_instance.copy_from_slice(&buf[16..20]);
        let mut target_instance = [0u8; 4];
        target_instance.copy_from_slice(&buf[20..24]);
        let mut object_id = [0u8; 8];
        object_id.copy_from_slice(&buf[24..32]);
        let mut cap_id = [0u8; 4];
        cap_id.copy_from_slice(&buf[32..36]);
        let mut export_name = [0u8; 32];
        export_name.copy_from_slice(&buf[38..70]);
        let mut rights = [0u8; 4];
        rights.copy_from_slice(&buf[70..74]);
        let mut created_at = [0u8; 8];
        created_at.copy_from_slice(&buf[74..82]);
        let mut updated_at = [0u8; 8];
        updated_at.copy_from_slice(&buf[82..90]);
        Ok(Self {
            live: buf[0],
            lifecycle: buf[1],
            record_id: u64::from_le_bytes(record_id),
            source_pid: u32::from_le_bytes(source_pid),
            source_instance: u32::from_le_bytes(source_instance),
            target_instance: u32::from_le_bytes(target_instance),
            object_id: u64::from_le_bytes(object_id),
            cap_id: u32::from_le_bytes(cap_id),
            language_tag: buf[36],
            export_name_len: buf[37],
            export_name,
            rights: u32::from_le_bytes(rights),
            created_at: u64::from_le_bytes(created_at),
            updated_at: u64::from_le_bytes(updated_at),
        })
    }
}

/// A decoded snapshot of active polyglot lineage records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolyglotLineageSnapshot {
    records: [PolyglotLineageRecord; 64],
    len: usize,
    version: u8,
}

impl PolyglotLineageSnapshot {
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, PolyglotLineageRecord> {
        self.records[..self.len].iter()
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    pub fn records(&self) -> &[PolyglotLineageRecord] {
        &self.records[..self.len]
    }
}

impl PolyglotError {
    #[inline]
    const fn from_register(code: i32) -> Self {
        match code {
            -1 => Self::InvalidArgument,
            -2 => Self::RegistryFull,
            -3 => Self::NameConflict,
            other => Self::Unexpected(other),
        }
    }

    #[inline]
    const fn from_resolve(code: i32) -> Self {
        match code {
            -1 => Self::InvalidArgument,
            -2 => Self::NotFound,
            other => Self::Unexpected(other),
        }
    }

    #[inline]
    const fn from_link(code: i32) -> Self {
        match code {
            -1 => Self::InvalidArgument,
            -2 => Self::NotFound,
            -3 => Self::ExportNotFound,
            -4 => Self::CapabilityTableFull,
            other => Self::Unexpected(other),
        }
    }
}

// ---------------------------------------------------------------------------
// High-level typed wrappers
// ---------------------------------------------------------------------------

/// Register this WASM module as a named polyglot kernel service.
///
/// The `name` must be ≤ 32 bytes of UTF-8.  The kernel records the module's
/// language tag (from the `oreulius_lang` custom section) alongside the name.
///
/// **Singletons**: Python (`0x04`) and JavaScript (`0x05`) modules are
/// treated as *singleton* language runtimes — subsequent calls with the same
/// name and language simply refresh the instance/owner reference instead of
/// returning an error.
///
/// Returns `Ok(())` on success, or a typed kernel error.
#[inline]
pub fn register(name: &str) -> Result<(), PolyglotError> {
    match unsafe { oreulius::polyglot_register(name.as_ptr() as i32, name.len() as i32) } {
        0 => Ok(()),
        rc => Err(PolyglotError::from_register(rc)),
    }
}

/// Resolve a registered polyglot service by name.
///
/// Returns the live provider `instance_id` if the name is found.
/// The returned `instance_id` can be used with `polyglot_link` or typed
/// service helpers.
#[inline]
pub fn resolve(name: &str) -> Result<i32, PolyglotError> {
    let result = unsafe {
        oreulius::polyglot_resolve(name.as_ptr() as i32, name.len() as i32)
    };
    if result >= 0 { Ok(result) } else { Err(PolyglotError::from_resolve(result)) }
}

/// Obtain a capability handle for calling `export_name` on `module_name`.
///
/// Both `module_name` and `export_name` must be ≤ 32 bytes of UTF-8.
/// The kernel resolves `export_name` against the target module's export table,
/// matches it to a registered service pointer, and injects a cross-language
/// `ServicePointer` capability into this module's capability table while also
/// recording durable polyglot lineage in the kernel.
///
/// Returns `Ok(cap_handle)` on success, or a typed kernel error.
/// Pass the returned handle to `oreulius_sdk::service::ServicePointer`
/// for invocation.
#[inline]
pub fn link(module_name: &str, export_name: &str) -> Result<u32, PolyglotError> {
    let result = unsafe {
        oreulius::polyglot_link(
            module_name.as_ptr()  as i32, module_name.len()  as i32,
            export_name.as_ptr()  as i32, export_name.len()  as i32,
        )
    };
    if result >= 0 { Ok(result as u32) } else { Err(PolyglotError::from_link(result)) }
}

// ---------------------------------------------------------------------------
// Convenience builder types
// ---------------------------------------------------------------------------

/// A handle to a registered polyglot service, obtained via [`register`].
///
/// Dropping this value does *not* unregister the service — the kernel entry
/// persists until the module instance is torn down.
pub struct PolyglotService {
    name: &'static str,
}

impl PolyglotService {
    /// Register a service and return a handle.  Returns `None` on error.
    #[inline]
    pub fn register(name: &'static str) -> Result<Self, PolyglotError> {
        register(name)?;
        Ok(Self { name })
    }

    /// The name this service was registered under.
    #[inline]
    pub fn name(&self) -> &str {
        self.name
    }
}

/// A capability handle obtained via [`link`] that can be used to call a
/// specific export on a remote polyglot service. The handle represents live
/// authority; the kernel keeps a separate durable lineage record for audit.
pub struct ServiceHandle {
    /// The raw capability handle (index into this module's cap table).
    pub cap: u32,
    /// Name of the remote module, for diagnostics.
    pub module_name: &'static str,
    /// Name of the remote export, for diagnostics.
    pub export_name: &'static str,
}

impl ServiceHandle {
    /// Resolve and link to `export_name` on `module_name`.
    #[inline]
    pub fn link(module_name: &'static str, export_name: &'static str) -> Result<Self, PolyglotError> {
        let cap = link(module_name, export_name)?;
        Ok(Self { cap, module_name, export_name })
    }

    /// Convert this handle into the typed service-pointer wrapper.
    #[inline]
    pub fn service_pointer(&self) -> crate::service::ServicePointer {
        crate::service::ServicePointer::from_handle(self.cap)
    }

    /// Invoke the linked service export with typed service slots.
    #[inline]
    pub fn invoke_typed(
        &self,
        args: &[crate::service::ServiceValue],
    ) -> Result<crate::service::ServiceResult, i32> {
        self.service_pointer().invoke_typed(args)
    }

    /// Explicitly revoke this handle's live authority.
    #[inline]
    pub fn revoke(&self) -> Result<(), i32> {
        lineage_revoke(self.cap)
    }

    /// Explicitly rebind this handle to a verified compatible target instance.
    #[inline]
    pub fn rebind_to(&self, target_instance: u32) -> Result<u32, i32> {
        lineage_rebind(self.cap, target_instance)
    }
}

/// Return the number of active polyglot lineage records currently tracked by
/// the kernel.
#[inline]
pub fn lineage_count() -> usize {
    unsafe { oreulius::polyglot_lineage_count().max(0) as usize }
}

/// Query the active polyglot lineage records.
///
/// The kernel returns a packed snapshot that can be decoded into a fixed-size
/// array without heap allocation.
#[inline]
pub fn lineage_query() -> Result<PolyglotLineageSnapshot, i32> {
    let mut buf = [0u8; 8 + 64 * 96];
    let rc = unsafe { oreulius::polyglot_lineage_query(buf.as_mut_ptr() as i32, buf.len() as i32) };
    if rc < 0 {
        return Err(rc);
    }
    let written = rc as usize;
    if written > 64 {
        return Err(-2);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 {
        return Err(-3);
    }
    if header.max_records as usize != 64 {
        return Err(-4);
    }
    let snapshot_count = header.count as usize;
    let version = header.version;
    let mut records = [PolyglotLineageRecord {
        record_id: 0,
        source_pid: 0,
        source_instance: 0,
        target_instance: 0,
        object_id: 0,
        cap_id: 0,
        language_tag: 0,
        export_name_len: 0,
        export_name: [0; 32],
        rights: 0,
        lifecycle: 0,
        created_at: 0,
        updated_at: 0,
    }; 64];
    let mut cursor = 8usize;
    let mut i = 0usize;
    while i < snapshot_count {
        let wire = PolyglotLineageWireRecordV1::decode(&buf[cursor..cursor + PolyglotLineageWireRecordV1::BYTES])?;
        records[i] = PolyglotLineageRecord {
            record_id: wire.record_id,
            source_pid: wire.source_pid,
            source_instance: wire.source_instance,
            target_instance: wire.target_instance,
            object_id: wire.object_id,
            cap_id: wire.cap_id,
            language_tag: wire.language_tag,
            export_name_len: wire.export_name_len,
            export_name: wire.export_name,
            rights: wire.rights,
            lifecycle: wire.lifecycle,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        cursor += PolyglotLineageWireRecordV1::BYTES;
        i += 1;
    }
    Ok(PolyglotLineageSnapshot { records, len: snapshot_count, version })
}

/// Query lineage records with a kernel-side filter.
///
/// ```rust,no_run
/// let source = oreulius_sdk::polyglot::lineage_query_filtered(
///     oreulius_sdk::polyglot::PolyglotLineageFilter::source_pid(60),
/// );
/// let export = oreulius_sdk::polyglot::lineage_query_filtered(
///     oreulius_sdk::polyglot::PolyglotLineageFilter::export_name("add"),
/// );
/// let live = oreulius_sdk::polyglot::lineage_query_filtered(
///     oreulius_sdk::polyglot::PolyglotLineageFilter::live(),
/// );
/// let torn_down = oreulius_sdk::polyglot::lineage_query_filtered(
///     oreulius_sdk::polyglot::PolyglotLineageFilter::torn_down(),
/// );
/// ```
#[inline]
pub fn lineage_query_filtered(
    filter: PolyglotLineageFilter<'_>,
) -> Result<PolyglotLineageSnapshot, i32> {
    let mut buf = [0u8; 8 + 64 * 96];
    let (filter_kind, filter_a, filter_b) = match filter {
        PolyglotLineageFilter::All => (0, 0, 0),
        PolyglotLineageFilter::SourcePid(pid) => (1, pid as i32, 0),
        PolyglotLineageFilter::TargetInstance(instance) => (2, instance as i32, 0),
        PolyglotLineageFilter::Lifecycle(lifecycle) => (3, lifecycle as i32, 0),
        PolyglotLineageFilter::ExportName(name) => (4, name.as_ptr() as i32, name.len() as i32),
    };
    let rc = unsafe {
        oreulius::polyglot_lineage_query_filtered(
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
            filter_kind,
            filter_a,
            filter_b,
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    let written = rc as usize;
    if written > 64 {
        return Err(-2);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 {
        return Err(-3);
    }
    if header.max_records as usize != 64 {
        return Err(-4);
    }
    let snapshot_count = header.count as usize;
    let version = header.version;
    let mut records = [PolyglotLineageRecord {
        record_id: 0,
        source_pid: 0,
        source_instance: 0,
        target_instance: 0,
        object_id: 0,
        cap_id: 0,
        language_tag: 0,
        export_name_len: 0,
        export_name: [0; 32],
        rights: 0,
        lifecycle: 0,
        created_at: 0,
        updated_at: 0,
    }; 64];
    let mut cursor = 8usize;
    let mut i = 0usize;
    while i < snapshot_count {
        let wire = PolyglotLineageWireRecordV1::decode(&buf[cursor..cursor + PolyglotLineageWireRecordV1::BYTES])?;
        records[i] = PolyglotLineageRecord {
            record_id: wire.record_id,
            source_pid: wire.source_pid,
            source_instance: wire.source_instance,
            target_instance: wire.target_instance,
            object_id: wire.object_id,
            cap_id: wire.cap_id,
            language_tag: wire.language_tag,
            export_name_len: wire.export_name_len,
            export_name: wire.export_name,
            rights: wire.rights,
            lifecycle: wire.lifecycle,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        cursor += PolyglotLineageWireRecordV1::BYTES;
        i += 1;
    }
    Ok(PolyglotLineageSnapshot { records, len: snapshot_count, version })
}

/// Look up the latest lineage record associated with a live capability handle.
///
/// ```rust,no_run
/// let live = oreulius_sdk::polyglot::lineage_lookup(cap_handle)?;
/// ```
#[inline]
pub fn lineage_lookup(cap_handle: u32) -> Result<PolyglotLineageRecord, i32> {
    let mut buf = [0u8; 8 + 96];
    let rc = unsafe {
        oreulius::polyglot_lineage_lookup(cap_handle as i32, buf.as_mut_ptr() as i32, buf.len() as i32)
    };
    if rc < 0 {
        return Err(rc);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 || header.count != 1 {
        return Err(-3);
    }
    let wire = PolyglotLineageWireRecordV1::decode(&buf[8..8 + 96])?;
    Ok(PolyglotLineageRecord {
        record_id: wire.record_id,
        source_pid: wire.source_pid,
        source_instance: wire.source_instance,
        target_instance: wire.target_instance,
        object_id: wire.object_id,
        cap_id: wire.cap_id,
        language_tag: wire.language_tag,
        export_name_len: wire.export_name_len,
        export_name: wire.export_name,
        rights: wire.rights,
        lifecycle: wire.lifecycle,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

/// Look up the latest lineage record for a persistent object id.
///
/// ```rust,no_run
/// let torn = oreulius_sdk::polyglot::lineage_lookup_object(object_id)?;
/// ```
#[inline]
pub fn lineage_lookup_object(object_id: u64) -> Result<PolyglotLineageRecord, i32> {
    let mut buf = [0u8; 8 + 96];
    let rc = unsafe {
        oreulius::polyglot_lineage_lookup_object(
            object_id as i32,
            (object_id >> 32) as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 || header.count != 1 {
        return Err(-3);
    }
    let wire = PolyglotLineageWireRecordV1::decode(&buf[8..8 + 96])?;
    Ok(PolyglotLineageRecord {
        record_id: wire.record_id,
        source_pid: wire.source_pid,
        source_instance: wire.source_instance,
        target_instance: wire.target_instance,
        object_id: wire.object_id,
        cap_id: wire.cap_id,
        language_tag: wire.language_tag,
        export_name_len: wire.export_name_len,
        export_name: wire.export_name,
        rights: wire.rights,
        lifecycle: wire.lifecycle,
        created_at: wire.created_at,
        updated_at: wire.updated_at,
    })
}

/// Query a compact lifecycle summary for a live capability handle.
#[inline]
pub fn lineage_status(cap_handle: u32) -> Result<PolyglotLineageStatus, i32> {
    let mut buf = [0u8; 8 + 32];
    let rc = unsafe {
        oreulius::polyglot_lineage_status(cap_handle as i32, buf.as_mut_ptr() as i32, buf.len() as i32)
    };
    if rc < 0 {
        return Err(rc);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 || header.count != 1 {
        return Err(-3);
    }
    let wire = PolyglotLineageStatusWireV1::decode(&buf[8..8 + 32])?;
    Ok(PolyglotLineageStatus {
        live: wire.live != 0,
        lifecycle: PolyglotLifecycleBucket::from_u8(wire.lifecycle).ok_or(-4)?,
        record_id: wire.record_id,
        object_id: wire.object_id,
        target_instance: wire.target_instance,
        updated_at: wire.updated_at,
    })
}

/// Query a compact lifecycle summary for a persistent object id.
#[inline]
pub fn lineage_status_object(object_id: u64) -> Result<PolyglotLineageStatus, i32> {
    let mut buf = [0u8; 8 + 32];
    let rc = unsafe {
        oreulius::polyglot_lineage_status_object(
            object_id as i32,
            (object_id >> 32) as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    if header.version != 1 || header.count != 1 {
        return Err(-3);
    }
    let wire = PolyglotLineageStatusWireV1::decode(&buf[8..8 + 32])?;
    Ok(PolyglotLineageStatus {
        live: wire.live != 0,
        lifecycle: PolyglotLifecycleBucket::from_u8(wire.lifecycle).ok_or(-4)?,
        record_id: wire.record_id,
        object_id: wire.object_id,
        target_instance: wire.target_instance,
        updated_at: wire.updated_at,
    })
}

/// Query the latest lineage record for each object id.
#[inline]
pub fn lineage_query_page(cursor: u64, limit: usize) -> Result<PolyglotLineagePage, i32> {
    let mut buf = [0u8; 8 + 64 * 96];
    let rc = unsafe {
        oreulius::polyglot_lineage_query_page(
            cursor as i32,
            limit as i32,
            buf.as_mut_ptr() as i32,
            buf.len() as i32,
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    let snapshot_count = header.count as usize;
    let mut records = [PolyglotLineageRecord {
        record_id: 0,
        source_pid: 0,
        source_instance: 0,
        target_instance: 0,
        object_id: 0,
        cap_id: 0,
        language_tag: 0,
        export_name_len: 0,
        export_name: [0; 32],
        rights: 0,
        lifecycle: 0,
        created_at: 0,
        updated_at: 0,
    }; 64];
    let mut cursor_off = 8usize;
    let mut i = 0usize;
    while i < snapshot_count {
        let wire = PolyglotLineageWireRecordV1::decode(&buf[cursor_off..cursor_off + PolyglotLineageWireRecordV1::BYTES])?;
        records[i] = PolyglotLineageRecord {
            record_id: wire.record_id,
            source_pid: wire.source_pid,
            source_instance: wire.source_instance,
            target_instance: wire.target_instance,
            object_id: wire.object_id,
            cap_id: wire.cap_id,
            language_tag: wire.language_tag,
            export_name_len: wire.export_name_len,
            export_name: wire.export_name,
            rights: wire.rights,
            lifecycle: wire.lifecycle,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
        };
        cursor_off += PolyglotLineageWireRecordV1::BYTES;
        i += 1;
    }
    Ok(PolyglotLineagePage {
        records,
        len: snapshot_count,
        version: header.version,
        next_cursor: header.next_record_id as u64,
    })
}

/// Return an iterator that walks lineage pages until exhaustion.
///
/// ```rust,no_run
/// let mut pages = oreulius_sdk::polyglot::lineage_pages(16);
/// while let Some(page) = pages.next() {
///     let page = page.expect("lineage page");
///     for record in page.iter() {
///         let _ = record.record_id;
///     }
/// }
/// ```
#[inline]
pub fn lineage_pages(limit: usize) -> PolyglotLineagePageIter {
    PolyglotLineagePageIter::new(limit)
}

/// Query rebinding/revocation events after a cursor.
#[inline]
pub fn lineage_event_query(cursor: u64, limit: usize) -> Result<(u64, [PolyglotLineageEvent; 64], usize), i32> {
    let mut buf = [0u8; 8 + 64 * 40];
    let rc = unsafe {
        oreulius::polyglot_lineage_event_query(cursor as i32, limit as i32, buf.as_mut_ptr() as i32, buf.len() as i32)
    };
    if rc < 0 { return Err(rc); }
    let header = PolyglotLineageWireHeaderV1::decode(&buf)?;
    let mut events = [PolyglotLineageEvent {
        event_id: 0, object_id: 0, target_instance: 0, lifecycle: PolyglotLifecycleBucket::Linked,
        previous_lifecycle: PolyglotLifecycleBucket::Linked, live: false, updated_at: 0,
    }; 64];
    let mut cursor_off = 8usize;
    let mut i = 0usize;
    while i < header.count as usize {
        let wire = PolyglotLineageEventWireV1::decode(&buf[cursor_off..cursor_off + PolyglotLineageEventWireV1::BYTES])?;
        events[i] = PolyglotLineageEvent {
            event_id: wire.event_id, object_id: wire.object_id, target_instance: wire.target_instance,
            lifecycle: PolyglotLifecycleBucket::from_u8(wire.lifecycle).ok_or(-4)?,
            previous_lifecycle: PolyglotLifecycleBucket::from_u8(wire.previous_lifecycle).ok_or(-5)?,
            live: wire.live != 0, updated_at: wire.updated_at,
        };
        cursor_off += PolyglotLineageEventWireV1::BYTES;
        i += 1;
    }
    Ok((header.next_record_id as u64, events, header.count as usize))
}

/// Return an iterator that walks lineage transition-event batches.
///
/// ```rust,no_run
/// let mut events = oreulius_sdk::polyglot::lineage_events(16);
/// while let Some(batch) = events.next() {
///     let batch = batch.expect("lineage events");
///     for event in batch.iter() {
///         let _ = event.event_id;
///     }
/// }
/// ```
#[inline]
pub fn lineage_events(limit: usize) -> PolyglotLineageEventIter {
    PolyglotLineageEventIter::new(limit)
}

/// Explicitly revoke a live service-pointer capability.
#[inline]
pub fn lineage_revoke(cap_handle: u32) -> Result<(), i32> {
    let rc = unsafe { oreulius::polyglot_lineage_revoke(cap_handle as i32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

/// Rebind a live service-pointer capability to a compatible replacement.
#[inline]
pub fn lineage_rebind(cap_handle: u32, target_instance: u32) -> Result<u32, i32> {
    let rc = unsafe { oreulius::polyglot_lineage_rebind(cap_handle as i32, target_instance as i32) };
    if rc >= 0 {
        Ok(rc as u32)
    } else {
        Err(rc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polyglot_error_mapping_is_stable() {
        assert_eq!(PolyglotError::from_register(-1), PolyglotError::InvalidArgument);
        assert_eq!(PolyglotError::from_register(-2), PolyglotError::RegistryFull);
        assert_eq!(PolyglotError::from_register(-3), PolyglotError::NameConflict);
        assert_eq!(PolyglotError::from_resolve(-2), PolyglotError::NotFound);
        assert_eq!(PolyglotError::from_link(-3), PolyglotError::ExportNotFound);
        assert_eq!(PolyglotError::from_link(-4), PolyglotError::CapabilityTableFull);
    }

    #[test]
    fn lifecycle_helpers_map_to_expected_codes() {
        assert_eq!(PolyglotLineageFilter::live(), PolyglotLineageFilter::Lifecycle(2));
        assert_eq!(PolyglotLineageFilter::rebound(), PolyglotLineageFilter::Lifecycle(5));
        assert_eq!(PolyglotLineageFilter::torn_down(), PolyglotLineageFilter::Lifecycle(4));
        assert_eq!(PolyglotLifecycleBucket::Live.as_u8(), 2);
        assert_eq!(PolyglotLifecycleBucket::Rebound.as_u8(), 5);
        assert_eq!(PolyglotLifecycleBucket::TornDown.as_u8(), 4);
    }

    #[test]
    fn lineage_record_helpers_map_lifecycle() {
        let record = PolyglotLineageRecord {
            record_id: 1,
            source_pid: 1,
            source_instance: 1,
            target_instance: 1,
            object_id: 1,
            cap_id: 1,
            language_tag: 1,
            export_name_len: 0,
            export_name: [0; 32],
            rights: 0,
            lifecycle: PolyglotLifecycleBucket::Rebound.as_u8(),
            created_at: 0,
            updated_at: 0,
        };
        assert!(record.is_rebound());
        assert_eq!(record.lifecycle_bucket(), Some(PolyglotLifecycleBucket::Rebound));
        assert!(!record.is_live());
        assert!(!record.is_terminal());
    }
}
