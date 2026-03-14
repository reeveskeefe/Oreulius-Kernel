//! # Kernel Observer API
//!
//! WASM modules can register as **kernel observers** to receive real-time
//! event notifications from the Oreulia kernel.  Events are delivered over
//! a per-observer IPC channel and can be drained at any time via
//! [`query`].
//!
//! ## Event types
//!
//! | Constant               | Bit | Description                              |
//! |------------------------|-----|------------------------------------------|
//! | [`CAPABILITY_OP`]      | 0   | A capability was granted or revoked      |
//! | [`PROCESS_LIFECYCLE`]  | 1   | A process was spawned or exited          |
//! | [`ANOMALY_DETECTED`]   | 2   | SecurityManager detected an anomaly      |
//! | [`IPC_ACTIVITY`]       | 3   | A channel send/recv completed            |
//! | [`MEMORY_PRESSURE`]    | 4   | Memory pressure threshold exceeded       |
//! | [`POLYGLOT_LINK`]      | 5   | A cross-language polyglot link was made  |
//! | [`ALL`]                | —   | Subscribe to every event category        |
//!
//! ## Example
//!
//! ```rust,no_run
//! #![no_std]
//! #![no_main]
//! use oreulia_sdk::observer::{self, ObserverEvent, ALL};
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     let _channel_id = observer::subscribe(ALL).expect("observer subscribe failed");
//!
//!     let mut events = [ObserverEvent::default(); 8];
//!     loop {
//!         let n = observer::query(&mut events);
//!         for i in 0..n {
//!             // act on events[i]
//!         }
//!         oreulia_sdk::process::yield_now();
//!     }
//! }
//! ```

use crate::raw::oreulia;

// ── Event mask constants ─────────────────────────────────────────────────────

/// A capability was granted or revoked.
pub const CAPABILITY_OP:     u32 = 1 << 0;
/// A process was spawned or exited.
pub const PROCESS_LIFECYCLE: u32 = 1 << 1;
/// The security manager detected an anomaly.
pub const ANOMALY_DETECTED:  u32 = 1 << 2;
/// An IPC channel send or receive completed.
pub const IPC_ACTIVITY:      u32 = 1 << 3;
/// Memory pressure exceeded a threshold.
pub const MEMORY_PRESSURE:   u32 = 1 << 4;
/// A cross-language polyglot link was established.
pub const POLYGLOT_LINK:     u32 = 1 << 5;
/// Subscribe to all event categories.
pub const ALL:               u32 = 0x0000_003F;

// ── Event encoding ───────────────────────────────────────────────────────────

/// A single kernel event as decoded from the 32-byte IPC message.
///
/// Layout of the raw 32-byte message delivered by the kernel:
///   `[0..3]`  `event_type: u32 LE`
///   `[4..7]`  `field_a: u32 LE`  (meaning is event-specific)
///   `[8..11]` `field_b: u32 LE`  (meaning is event-specific)
///   `[12..31]` reserved / zero
#[derive(Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct ObserverEvent {
    /// Event type — one of the `CAPABILITY_OP` / `ANOMALY_DETECTED` / … constants.
    pub event_type: u32,
    /// First event-specific field:
    ///   - `CAPABILITY_OP`: PID that owns the capability.
    ///   - `PROCESS_LIFECYCLE`: parent PID (0 = kernel).
    ///   - `ANOMALY_DETECTED`: PID of the anomalous process.
    ///   - others: unspecified.
    pub field_a: u32,
    /// Second event-specific field:
    ///   - `CAPABILITY_OP`: capability type tag (0 = Channel, 1 = Service, …).
    ///   - `PROCESS_LIFECYCLE`: spawned/exited child PID.
    ///   - `ANOMALY_DETECTED`: anomaly score (0–255).
    ///   - others: unspecified.
    pub field_b: u32,
    _reserved: [u8; 20],
}

impl ObserverEvent {
    /// Decode an `ObserverEvent` from a 32-byte raw buffer.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        ObserverEvent {
            event_type: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            field_a:    u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            field_b:    u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            _reserved:  [0u8; 20],
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Register this WASM module as a kernel observer for the events described
/// by `event_mask` (a bitwise OR of the mask constants above).
///
/// Returns the IPC channel ID used for event delivery on success, or `None`
/// if the kernel observer table is full or an error occurred.
pub fn subscribe(event_mask: u32) -> Option<u32> {
    let result = unsafe { oreulia::observer_subscribe(event_mask as i32) };
    if result >= 0 {
        Some(result as u32)
    } else {
        None
    }
}

/// Deregister this WASM module as a kernel observer and release its delivery
/// channel.  Returns `true` on success.
pub fn unsubscribe() -> bool {
    let result = unsafe { oreulia::observer_unsubscribe() };
    result == 0
}

/// Drain pending kernel events into the provided `events` slice.
///
/// Decodes up to `events.len()` events from the caller's observer channel
/// and writes them into `events`.  Returns the number of events actually
/// written.  Returns `0` if there are no pending events or if the caller is
/// not subscribed.
pub fn query(events: &mut [ObserverEvent]) -> usize {
    if events.is_empty() {
        return 0;
    }
    // The raw buffer must be `events.len() * 32` bytes.
    let buf_ptr  = events.as_mut_ptr() as i32;
    let buf_len  = (events.len() * 32) as i32;
    let result   = unsafe { oreulia::observer_query(buf_ptr, buf_len) };
    if result < 0 {
        0
    } else {
        result as usize
    }
}
