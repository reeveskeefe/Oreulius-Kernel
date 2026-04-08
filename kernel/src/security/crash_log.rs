/*!
 * Oreulius Kernel — Crash Logging
 *
 * A lock-free in-kernel crash record ring buffer that is safe to write from
 * the panic handler (where spinlocks may already be held).
 *
 * Architecture:
 *   - `CRASH_RING`: a fixed-size `[CrashSlot; RING_CAP]` array.
 *   - `WRITE_SEQ`: `AtomicUsize` monotonic counter; slot = seq % RING_CAP.
 *   - `CRASH_COUNT`: total panics seen this boot session.
 *   - Each slot is written with `SeqCst` atomics on individual fields to avoid
 *     needing a lock.
 *   - On clean boot, `flush_to_persistence()` copies live slots into the
 *     persistence log (RecordType::CrashReport) and emits a BootEvent.
 */

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

#[cfg(target_has_atomic = "64")]
type CrashTickAtomic = core::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type CrashTickAtomic = AtomicUsize;

// ============================================================================
// Constants
// ============================================================================

/// Number of crash slots in the ring (power of two for cheap modulo).
pub const RING_CAP: usize = 8;
/// Maximum bytes stored for a panic message or location string.
pub const MSG_CAP: usize = 128;
/// Magic sentinel written into every live slot.
pub const SLOT_MAGIC: u32 = 0x43524153; // "CRAS"

// ============================================================================
// CrashSlot — one recorded panic
// ============================================================================

/// A single crash record, stored inline in the ring.
///
/// All fields are plain integer / byte-array types so the struct is
/// `Sync` without any explicit unsafe impl.
pub struct CrashSlot {
    /// SLOT_MAGIC when this slot contains a valid record, 0 otherwise.
    pub magic: AtomicU32,
    /// Monotonic tick at the time of the panic (from `crate::arch::time::ticks()`).
    pub tick: CrashTickAtomic,
    /// Boot session counter (incremented once per `rust_main` entry).
    pub boot_session: AtomicU32,
    /// Sequence number assigned by the writer.
    pub seq: AtomicUsize,
    /// Null-padded UTF-8 bytes of the panic location (file:line).
    pub location: [AtomicU8Byte; MSG_CAP],
    /// Null-padded UTF-8 bytes of the panic message.
    pub message: [AtomicU8Byte; MSG_CAP],
}

/// A single atomic byte — `AtomicU8` is not `Default` in older nightly, so
/// we wrap it in a newtype that is `Default`.
pub struct AtomicU8Byte(core::sync::atomic::AtomicU8);

impl AtomicU8Byte {
    pub const fn new(v: u8) -> Self {
        Self(core::sync::atomic::AtomicU8::new(v))
    }
    pub fn load(&self) -> u8 {
        self.0.load(Ordering::SeqCst)
    }
    pub fn store(&self, v: u8) {
        self.0.store(v, Ordering::SeqCst);
    }
}

// Safety: CrashSlot fields are either atomics or arrays of AtomicU8Byte,
// all of which are Send + Sync.
unsafe impl Sync for CrashSlot {}
unsafe impl Send for CrashSlot {}

#[inline]
fn crash_tick_store(dst: &CrashTickAtomic, value: u64) {
    #[cfg(target_has_atomic = "64")]
    dst.store(value, Ordering::SeqCst);

    #[cfg(not(target_has_atomic = "64"))]
    dst.store(value.min(usize::MAX as u64) as usize, Ordering::SeqCst);
}

#[inline]
fn crash_tick_load(src: &CrashTickAtomic) -> u64 {
    #[cfg(target_has_atomic = "64")]
    {
        src.load(Ordering::SeqCst)
    }

    #[cfg(not(target_has_atomic = "64"))]
    {
        src.load(Ordering::SeqCst) as u64
    }
}

// We need a const initialiser for the location/message arrays.
#[allow(unused_macros)]
macro_rules! zero_atomic_bytes {
    ($n:expr) => {{
        // Build the array with const initialisation.
        const ZERO: AtomicU8Byte = AtomicU8Byte::new(0);
        [ZERO; $n]
    }};
}

impl CrashSlot {
    pub const fn new() -> Self {
        CrashSlot {
            magic: AtomicU32::new(0),
            tick: CrashTickAtomic::new(0),
            boot_session: AtomicU32::new(0),
            seq: AtomicUsize::new(0),
            location: {
                const ZERO: AtomicU8Byte = AtomicU8Byte::new(0);
                [ZERO; MSG_CAP]
            },
            message: {
                const ZERO: AtomicU8Byte = AtomicU8Byte::new(0);
                [ZERO; MSG_CAP]
            },
        }
    }

    /// Copy a byte slice into the atomic byte array, padding the rest with 0.
    fn write_bytes(dest: &[AtomicU8Byte; MSG_CAP], src: &[u8]) {
        let n = src.len().min(MSG_CAP);
        for i in 0..n {
            dest[i].store(src[i]);
        }
        for i in n..MSG_CAP {
            dest[i].store(0);
        }
    }

    /// Read the atomic byte array back into a fixed-size stack buffer.
    pub fn read_bytes(src: &[AtomicU8Byte; MSG_CAP], out: &mut [u8; MSG_CAP]) {
        for i in 0..MSG_CAP {
            out[i] = src[i].load();
        }
    }
}

// ============================================================================
// Static ring buffer
// ============================================================================

static CRASH_RING: [CrashSlot; RING_CAP] = {
    const SLOT: CrashSlot = CrashSlot::new();
    [SLOT; RING_CAP]
};

/// Monotonic write-sequence counter.
static WRITE_SEQ: AtomicUsize = AtomicUsize::new(0);
/// Total panics recorded this session (capped at u32::MAX).
static CRASH_COUNT: AtomicU32 = AtomicU32::new(0);
/// Current boot session number (incremented by `on_boot()`).
static BOOT_SESSION: AtomicU32 = AtomicU32::new(0);
/// Set once persistence flush has been attempted this boot.
static FLUSHED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Public API
// ============================================================================

/// Called once during kernel init (after persistence is ready) to:
///   1. Increment the boot session counter.
///   2. Flush any crash records from the previous session into persistence.
///   3. Emit a BootEvent persistence record.
pub fn on_boot() {
    let session = BOOT_SESSION.fetch_add(1, Ordering::SeqCst) + 1;
    flush_to_persistence();
    emit_boot_event(session);
}

/// Record a panic from the panic handler.
///
/// **Must be lock-free**: this may be called while arbitrary spinlocks are
/// held.  We use `SeqCst` atomics throughout.
pub fn record_panic(info: &core::panic::PanicInfo) {
    CRASH_COUNT.fetch_add(1, Ordering::SeqCst);
    let seq = WRITE_SEQ.fetch_add(1, Ordering::SeqCst);
    let slot = &CRASH_RING[seq % RING_CAP];

    // Clear the magic first so a concurrent reader doesn't see a half-written slot.
    slot.magic.store(0, Ordering::SeqCst);

    // Write tick (best-effort — if the timer lock is held, we get 0).
    #[cfg(not(target_arch = "aarch64"))]
    {
        let t = crate::memory::asm_bindings::rdtsc_begin();
        crash_tick_store(&slot.tick, t);
    }
    #[cfg(target_arch = "aarch64")]
    crash_tick_store(&slot.tick, 0);

    slot.boot_session
        .store(BOOT_SESSION.load(Ordering::SeqCst), Ordering::SeqCst);
    slot.seq.store(seq, Ordering::SeqCst);

    // Encode location string "file:line" into the slot.
    let mut loc_buf = [0u8; MSG_CAP];
    let loc_len = if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        let n = file.len().min(MSG_CAP - 12);
        loc_buf[..n].copy_from_slice(&file[..n]);
        let mut cursor = n;
        // append ':' + line number
        if cursor < MSG_CAP {
            loc_buf[cursor] = b':';
            cursor += 1;
        }
        let line = loc.line();
        let mut digits = [0u8; 10];
        let dlen = format_u32_decimal(line, &mut digits);
        let copy = dlen.min(MSG_CAP - cursor);
        loc_buf[cursor..cursor + copy].copy_from_slice(&digits[..copy]);
        cursor + copy
    } else {
        let s = b"<unknown>";
        let n = s.len().min(MSG_CAP);
        loc_buf[..n].copy_from_slice(&s[..n]);
        n
    };
    CrashSlot::write_bytes(&slot.location, &loc_buf[..loc_len]);

    // Encode the panic message (Display impl writes into a tiny stack buffer).
    let mut msg_buf = [0u8; MSG_CAP];
    let msg_len = format_panic_message(info, &mut msg_buf);
    CrashSlot::write_bytes(&slot.message, &msg_buf[..msg_len]);

    // Publish the slot atomically.
    slot.magic.store(SLOT_MAGIC, Ordering::SeqCst);

    // Notify the wait-free telemetry ring so the userspace CTMC daemon sees
    // the crash event.  push() is lock-free and safe to call from a panic
    // handler.  We silently drop the event if the ring is full.
    let tick_raw = CRASH_COUNT.load(Ordering::SeqCst) as u64; // use count as a proxy tick
    let ev = crate::memory::wait_free_ring::TelemetryEvent::new(
        0xFFFF_FFFF, // sentinel PID: kernel / panic
        0,           // node 0 = Error / initial state in the CTMC
        0xFC,        // cap_type 0xFC = reserved for crash events
        255,         // score = max (anomaly signal)
        tick_raw,
    );
    let _ = crate::memory::wait_free_ring::TELEMETRY_RING.push(ev);
}

/// Return the number of panics recorded since boot.
pub fn crash_count() -> u32 {
    CRASH_COUNT.load(Ordering::SeqCst)
}

/// Return the current boot session number.
pub fn boot_session() -> u32 {
    BOOT_SESSION.load(Ordering::SeqCst)
}

/// Iterate over live crash slots and call `f` for each.
/// `f` receives (seq, tick, boot_session, location_bytes, message_bytes).
pub fn for_each_crash<F: FnMut(usize, u64, u32, [u8; MSG_CAP], [u8; MSG_CAP])>(mut f: F) {
    for slot in &CRASH_RING {
        if slot.magic.load(Ordering::SeqCst) != SLOT_MAGIC {
            continue;
        }
        let seq = slot.seq.load(Ordering::SeqCst);
        let tick = crash_tick_load(&slot.tick);
        let session = slot.boot_session.load(Ordering::SeqCst);
        let mut loc = [0u8; MSG_CAP];
        let mut msg = [0u8; MSG_CAP];
        CrashSlot::read_bytes(&slot.location, &mut loc);
        CrashSlot::read_bytes(&slot.message, &mut msg);
        f(seq, tick, session, loc, msg);
    }
}

// ============================================================================
// Persistence integration (called on clean boot, NOT from panic handler)
// ============================================================================

/// Flush the in-memory crash ring into the persistence log.
/// Safe to call only when persistence is initialised and no panic is in flight.
pub fn flush_to_persistence() {
    if FLUSHED.swap(true, Ordering::SeqCst) {
        return; // Already flushed this session.
    }

    let cap =
        crate::temporal::persistence::StoreCapability::new(0xCCCC, crate::temporal::persistence::StoreRights::all());

    for_each_crash(|seq, tick, session, loc, msg| {
        // Build a 8 + MSG_CAP + MSG_CAP = 264-byte payload.
        // Layout: [seq:u32LE, tick_lo:u32LE, tick_hi:u32LE, session:u32LE, loc[128], msg[128]]
        let mut payload = [0u8; 4 + 4 + 4 + 4 + MSG_CAP + MSG_CAP];
        payload[0..4].copy_from_slice(&(seq as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&(tick as u32).to_le_bytes());
        payload[8..12].copy_from_slice(&((tick >> 32) as u32).to_le_bytes());
        payload[12..16].copy_from_slice(&session.to_le_bytes());
        payload[16..16 + MSG_CAP].copy_from_slice(&loc);
        payload[16 + MSG_CAP..16 + MSG_CAP * 2].copy_from_slice(&msg);

        if let Ok(record) = crate::temporal::persistence::LogRecord::new(
            crate::temporal::persistence::RecordType::CrashReport,
            &payload,
        ) {
            let mut svc = crate::temporal::persistence::persistence().lock();
            let _ = svc.append_log(&cap, record);
        }
    });
}

/// Emit a BootEvent record into persistence.
fn emit_boot_event(session: u32) {
    let cap =
        crate::temporal::persistence::StoreCapability::new(0xBBBB, crate::temporal::persistence::StoreRights::all());
    // Payload: [session:u32LE, crash_count:u32LE]
    let mut payload = [0u8; 8];
    payload[0..4].copy_from_slice(&session.to_le_bytes());
    payload[4..8].copy_from_slice(&CRASH_COUNT.load(Ordering::SeqCst).to_le_bytes());

    if let Ok(record) =
        crate::temporal::persistence::LogRecord::new(crate::temporal::persistence::RecordType::BootEvent, &payload)
    {
        let mut svc = crate::temporal::persistence::persistence().lock();
        let _ = svc.append_log(&cap, record);
    }
}

// ============================================================================
// Private helpers — must be no_std / no-alloc / no-lock
// ============================================================================

/// Format a `u32` in decimal into `buf`; returns the number of bytes written.
fn format_u32_decimal(mut n: u32, buf: &mut [u8; 10]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // reverse
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

// ============================================================================
// CrashClass — structured crash taxonomy
// ============================================================================

/// Structured classification of a kernel panic.
///
/// Used for structured telemetry output (`[PANIC] class=…`), OTA rollback
/// decisions, and formal-verification evidence tagging.  The `as_str()`
/// representation is emitted verbatim on the serial console so fleet
/// management tooling can regex-grep across logs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CrashClass {
    /// An explicit `unreachable!()` / `panic!("…")` assertion in kernel code.
    KernelAssert,
    /// Out-of-bounds memory access (slice index, buffer overflow).
    MemoryBounds,
    /// Integer arithmetic overflow (debug builds, explicit overflow check).
    ArithmeticOverflow,
    /// Stack overflow / stack smashing detected.
    StackOverflow,
    /// Global allocator out-of-memory.
    AllocOom,
    /// Capability / permission check failed at runtime.
    CapabilityViolation,
    /// WASM bytecode validation or execution fault.
    WasmFault,
    /// ELF loader rejected an image.
    ElfLoadError,
    /// Hardware exception forwarded from the arch exception handler.
    HardwareFault,
    /// None of the above patterns matched.
    Unknown,
}

impl CrashClass {
    /// Returns the canonical telemetry string for this class.
    pub fn as_str(self) -> &'static str {
        match self {
            CrashClass::KernelAssert => "kernel_assert",
            CrashClass::MemoryBounds => "memory_bounds",
            CrashClass::ArithmeticOverflow => "arithmetic_overflow",
            CrashClass::StackOverflow => "stack_overflow",
            CrashClass::AllocOom => "alloc_oom",
            CrashClass::CapabilityViolation => "capability_violation",
            CrashClass::WasmFault => "wasm_fault",
            CrashClass::ElfLoadError => "elf_load_error",
            CrashClass::HardwareFault => "hardware_fault",
            CrashClass::Unknown => "unknown",
        }
    }
}

/// Classify a panic by inspecting its message and source location.
///
/// This is intentionally simple (substring matching on the formatted
/// message) so it can run during the panic handler before any lock is
/// acquired.  Call this *before* `record_panic`.
pub fn classify_panic(info: &core::panic::PanicInfo) -> CrashClass {
    // Format into a stack buffer — no heap involved.
    let mut buf = [0u8; MSG_CAP];
    let n = format_panic_message(info, &mut buf);
    let msg = &buf[..n];

    // Location string check.
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        if contains(file, b"wasm") {
            return CrashClass::WasmFault;
        }
        if contains(file, b"elf") {
            return CrashClass::ElfLoadError;
        }
        if contains(file, b"capability") || contains(file, b"cap_graph") {
            return CrashClass::CapabilityViolation;
        }
        if contains(file, b"hardened_allocator") || contains(file, b"alloc") {
            return CrashClass::AllocOom;
        }
    }

    // Message content check.
    if contains(msg, b"index out of bounds")
        || contains(msg, b"slice index")
        || contains(msg, b"out of range")
    {
        return CrashClass::MemoryBounds;
    }
    if contains(msg, b"overflow")
        || contains(msg, b"attempt to add")
        || contains(msg, b"attempt to sub")
        || contains(msg, b"attempt to mul")
    {
        return CrashClass::ArithmeticOverflow;
    }
    if contains(msg, b"stack overflow") || contains(msg, b"stack smash") {
        return CrashClass::StackOverflow;
    }
    if contains(msg, b"OOM") || contains(msg, b"out of memory") || contains(msg, b"alloc fail") {
        return CrashClass::AllocOom;
    }
    if contains(msg, b"capability")
        || contains(msg, b"cap violation")
        || contains(msg, b"permission denied")
    {
        return CrashClass::CapabilityViolation;
    }
    if contains(msg, b"wasm") || contains(msg, b"WASM") {
        return CrashClass::WasmFault;
    }
    if contains(msg, b"hardware") || contains(msg, b"exception") || contains(msg, b"fault") {
        return CrashClass::HardwareFault;
    }

    CrashClass::Unknown
}

/// Simple byte-slice substring search, no_std compatible.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Format a `PanicInfo` into a fixed-size byte buffer.  Returns the number of
/// bytes written.  Never allocates; safe to call from the panic handler.
fn format_panic_message(info: &core::panic::PanicInfo, buf: &mut [u8; MSG_CAP]) -> usize {
    let mut w = ByteWriter { buf, pos: 0 };
    use core::fmt::Write;
    let _ = core::write!(w, "{}", info);
    w.pos
}

struct ByteWriter<'a> {
    buf: &'a mut [u8; MSG_CAP],
    pos: usize,
}

impl<'a> core::fmt::Write for ByteWriter<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let avail = MSG_CAP.saturating_sub(self.pos);
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}
