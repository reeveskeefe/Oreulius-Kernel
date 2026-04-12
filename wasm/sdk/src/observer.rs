//! # Kernel Observer API
//!
//! WASM modules can register as **kernel observers** to receive real-time
//! event notifications from the Oreulius kernel.  Events are delivered over
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
//! use oreulius_sdk::observer::{self, ObserverEvent, ALL};
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     let _channel_id = observer::subscribe(ALL).expect("observer subscribe failed");
//!
//!     let mut events = [ObserverEvent::default(); 8];
//!     loop {
//!         let n = observer::query(&mut events).expect("observer query failed");
//!         for i in 0..n {
//!             // act on events[i]
//!         }
//!         oreulius_sdk::process::yield_now();
//!     }
//! }
//!
//! // Or, if you want batch iteration:
//! // let mut batches = observer::events();
//! // while let Some(batch) = batches.next() { /* inspect batch.iter() */ }
//! ```

use crate::raw::oreulius;

const OBSERVER_EVENT_BYTES: usize = 32;

#[inline]
fn positive_channel_id_from_rc(result: i32) -> Result<u32, i32> {
    match result {
        rc if rc > 0 => Ok(rc as u32),
        rc if rc < 0 => Err(rc),
        _ => Err(-1),
    }
}

#[inline]
fn event_count_from_rc(result: i32, capacity: usize) -> Result<usize, i32> {
    if result < 0 {
        return Err(result);
    }

    let count = result as usize;
    if count > capacity {
        Err(-2)
    } else {
        Ok(count)
    }
}

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
#[must_use]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
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
/// Returns the observer IPC channel ID on success or the kernel error code
/// on failure.
#[must_use]
pub fn subscribe(event_mask: u32) -> Result<u32, i32> {
    let result = unsafe { oreulius::observer_subscribe(event_mask as i32) };
    positive_channel_id_from_rc(result)
}

/// Deregister this WASM module as a kernel observer and release its delivery
/// channel.
#[must_use]
pub fn unsubscribe() -> Result<(), i32> {
    let result = unsafe { oreulius::observer_unsubscribe() };
    if result == 0 { Ok(()) } else { Err(result) }
}

/// Drain pending kernel events into the provided `events` slice.
///
/// Decodes up to `events.len()` events from the caller's observer channel
/// and writes them into `events`.  Returns the number of events actually
/// written.  Returns `Ok(0)` when there are no pending events.
#[must_use]
pub fn query(events: &mut [ObserverEvent]) -> Result<usize, i32> {
    if events.is_empty() {
        return Ok(0);
    }
    // The raw buffer must be `events.len() * 32` bytes.
    let buf_ptr  = events.as_mut_ptr() as i32;
    let buf_len  = (events.len() * OBSERVER_EVENT_BYTES) as i32;
    let result   = unsafe { oreulius::observer_query(buf_ptr, buf_len) };
    event_count_from_rc(result, events.len())
}

/// A fixed-capacity batch of observer events.
#[must_use]
#[derive(Clone, Copy)]
pub struct ObserverEventBatch {
    events: [ObserverEvent; 32],
    len: usize,
}

impl ObserverEventBatch {
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, ObserverEvent> {
        self.events[..self.len].iter()
    }
}

/// Iterator that drains observer events in fixed-size batches.
pub struct ObserverEventIter {
    finished: bool,
}

impl ObserverEventIter {
    #[inline]
    pub const fn new() -> Self {
        Self { finished: false }
    }
}

impl Iterator for ObserverEventIter {
    type Item = Result<ObserverEventBatch, i32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let mut events = [ObserverEvent::default(); 32];
        match query(&mut events) {
            Ok(0) => {
                self.finished = true;
                None
            }
            Ok(len) => {
                let batch = ObserverEventBatch { events, len };
                if batch.is_empty() {
                    self.finished = true;
                }
                Some(Ok(batch))
            }
            Err(err) => Some(Err(err)),
        }
    }
}

/// Return an iterator that drains observer events batch-by-batch.
///
/// This is a convenience wrapper over [`query`] that presents the observer
/// bus as a cursorless batch iterator.
#[inline]
pub fn events() -> ObserverEventIter {
    ObserverEventIter::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_channel_id_from_rc_rejects_zero_and_preserves_errors() {
        assert_eq!(positive_channel_id_from_rc(7), Ok(7));
        assert_eq!(positive_channel_id_from_rc(0), Err(-1));
        assert_eq!(positive_channel_id_from_rc(-3), Err(-3));
    }

    #[test]
    fn event_count_from_rc_rejects_negative_and_overlarge_counts() {
        assert_eq!(event_count_from_rc(0, 4), Ok(0));
        assert_eq!(event_count_from_rc(3, 4), Ok(3));
        assert_eq!(event_count_from_rc(-1, 4), Err(-1));
        assert_eq!(event_count_from_rc(5, 4), Err(-2));
    }

    #[test]
    fn observer_event_decodes_the_first_three_words() {
        let bytes = [
            1, 0, 0, 0,
            2, 0, 0, 0,
            3, 0, 0, 0,
            9, 9, 9, 9,
            8, 8, 8, 8,
            7, 7, 7, 7,
            6, 6, 6, 6,
            5, 5, 5, 5,
        ];
        let event = ObserverEvent::from_bytes(&bytes);
        assert_eq!(event.event_type, 1);
        assert_eq!(event.field_a, 2);
        assert_eq!(event.field_b, 3);
    }
}
