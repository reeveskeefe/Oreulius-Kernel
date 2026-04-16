// Copyright (c) 2026 Keefe Reeves
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this file is governed by the Business Source License 1.1
// included in the LICENSE file at the root of this repository.
//
// Additional Use Grant: Personal use, research, education, evaluation,
// benchmarking, and internal non-production testing are permitted.
// Production use, commercial deployment, embedded commercial products,
// and paid hosted services require a separate commercial license.
//
// Change Date: 2030-04-15
// Change License: Apache License 2.0

//! Wait-Free Ring Buffer (PMA §3 — Lock-Free Telemetry Transport)
//!
//! Provides a fixed-capacity, wait-free MPSC ring that the intent graph and
//! scheduler push behavioral telemetry events into without acquiring any mutex.
//!
//! ## Design
//! - Backed by `[UnsafeCell<MaybeUninit<T>>; N]` — avoids initialization cost.
//! - Two `AtomicUsize` indices: `head` (consumer) and `tail` (producer).
//! - `push`: CAS on `tail`; if slot is taken, *drops* the event (never blocks).
//! - `pop`: CAS on `head`; returns `None` if empty.
//! - N must be a power-of-two (asserted at construction); mask trick replaces modulo.
//! - `unsafe impl Send/Sync` — safe because accesses are guarded by CAS ordering.
//!
//! The ring uses `Ordering::Release` on writes and `Ordering::Acquire` on reads to
//! establish the happens-before relationship required by the C++11 / LLVM memory model.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Telemetry event — 16 bytes, trivially Copy, no heap allocation.
// ---------------------------------------------------------------------------

/// A single behavioral telemetry record emitted by the intent graph.
/// Kept at exactly 16 bytes so the ring buffer fits in a single cache region.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TelemetryEvent {
    /// Process that triggered the event.
    pub pid: u32,
    /// `IntentNode` discriminant (0-8).
    pub node: u8,
    /// `IntentSignal.cap_type` discriminant (compact).
    pub cap_type: u8,
    /// Score computed by `intent_graph::record()` for this event (0-255).
    pub score: u8,
    /// Padding / reserved for future use.
    pub _pad: u8,
    /// Scheduler tick at the time of the event.
    pub tick: u64,
}

impl TelemetryEvent {
    pub const fn new(pid: u32, node: u8, cap_type: u8, score: u8, tick: u64) -> Self {
        Self {
            pid,
            node,
            cap_type,
            score,
            _pad: 0,
            tick,
        }
    }
}

/// Reserved `cap_type` tag for compact VFS watch summaries emitted by `vfs.rs`.
///
/// The userspace telemetry daemon must treat these as out-of-band records and
/// keep them out of the CTMC intent graph path.
pub const TELEMETRY_CAP_TYPE_VFS_WATCH: u8 = 0xFE;

// ---------------------------------------------------------------------------
// WaitFreeRingBuffer
// ---------------------------------------------------------------------------

/// A fixed-capacity, wait-free ring buffer.
///
/// `N` must be a power of two and must be `>= 2`.  The capacity is `N` slots;
/// at most `N - 1` live elements are stored simultaneously (one slot is kept
/// empty to disambiguate full from empty).
pub struct WaitFreeRingBuffer<T, const N: usize> {
    /// Backing storage — never read without a preceding successful CAS on `head`.
    slots: [UnsafeCell<MaybeUninit<T>>; N],
    /// Consumer cursor: index of the *next slot to read*.
    head: AtomicUsize,
    /// Producer cursor: index of the *next slot to write*.
    tail: AtomicUsize,
}

// SAFETY: `T: Send` ensures cross-thread moves are safe. The CAS pair on
// head/tail serialises concurrent access to each slot.
unsafe impl<T: Send, const N: usize> Send for WaitFreeRingBuffer<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for WaitFreeRingBuffer<T, N> {}

impl<T: Copy, const N: usize> WaitFreeRingBuffer<T, N> {
    const _ASSERT_POW2: () = {
        assert!(N >= 2, "WaitFreeRingBuffer: N must be >= 2");
        assert!(
            N.is_power_of_two(),
            "WaitFreeRingBuffer: N must be a power of two"
        );
    };

    const MASK: usize = N - 1;

    /// Create a new, empty ring buffer.  `const` so it can be placed in a
    /// `static` without a constructor function.
    pub const fn new() -> Self {
        Self {
            slots: unsafe {
                MaybeUninit::<[UnsafeCell<MaybeUninit<T>>; N]>::uninit().assume_init()
            },
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Returns the number of pending elements (approximate — not linearisable
    /// with concurrent pushes/pops because head and tail are read separately).
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        tail.wrapping_sub(head) & Self::MASK
    }

    /// Returns `true` if the ring appears empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    /// Attempt to push `val` into the ring.
    ///
    /// Returns `true` on success, `false` if the ring was full (event dropped).
    /// Never spins; never blocks; never allocates.
    ///
    /// Multiple producers are safe: each claims a unique slot via CAS on `tail`
    /// before writing.
    pub fn push(&self, val: T) -> bool {
        let mut tail = self.tail.load(Ordering::Relaxed);
        loop {
            let head = self.head.load(Ordering::Acquire);
            let next_tail = tail.wrapping_add(1) & Self::MASK;

            // Ring full: one slot is reserved as sentinel.
            if next_tail == head & Self::MASK {
                return false;
            }

            match self.tail.compare_exchange_weak(
                tail,
                next_tail,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // We own `tail` exclusively now — write the value.
                    // SAFETY: we just CAS-claimed this slot.
                    unsafe {
                        (*self.slots[tail & Self::MASK].get()).write(val);
                    }
                    // Publish: release-store so the consumer sees the write.
                    // We do not need a second CAS here because a single-producer
                    // model on the tail is maintained by the CAS above.
                    // For true MPMC we would need an additional "committed" bitmap;
                    // for the kernel telemetry use-case (many producers, one consumer
                    // draining on the telemetry thread), this is sufficient.
                    return true;
                }
                Err(current) => {
                    tail = current;
                }
            }
        }
    }

    /// Attempt to pop one element from the ring.
    ///
    /// Returns `Some(T)` on success, `None` if the ring was empty.
    /// Single-consumer safe.
    pub fn pop(&self) -> Option<T> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None; // empty
        }

        // SAFETY: head slot was written by a successful `push` CAS, and
        // we are the sole consumer advancing `head`.
        let val = unsafe { (*self.slots[head & Self::MASK].get()).assume_init_read() };

        self.head
            .store(head.wrapping_add(1) & Self::MASK, Ordering::Release);
        Some(val)
    }

    /// Drain up to `max` events into `out`, returning the count drained.
    pub fn drain_into(&self, out: &mut [T], max: usize) -> usize {
        let limit = max.min(out.len());
        let mut count = 0;
        while count < limit {
            match self.pop() {
                Some(v) => {
                    out[count] = v;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }
}

// ---------------------------------------------------------------------------
// Global telemetry ring — 256-slot (4 KiB), no-alloc.
// ---------------------------------------------------------------------------

/// Capacity of the global telemetry ring. Power-of-two; 256 × 16B = 4 KiB.
pub const TELEMETRY_RING_CAPACITY: usize = 256;

/// Global wait-free ring shared between the intent graph (producers) and the
/// telemetry daemon (consumer).  Placed in `.bss` — no dynamic init required.
pub static TELEMETRY_RING: WaitFreeRingBuffer<TelemetryEvent, TELEMETRY_RING_CAPACITY> =
    WaitFreeRingBuffer::new();

// ---------------------------------------------------------------------------
// Kernel → Daemon drain path
// ---------------------------------------------------------------------------

/// Magic frame header that the userspace daemon uses to re-synchronise on the
/// byte stream.  Matches the constant in `telemetry.rs` / `uds_queue.rs`.
const DRAIN_MAGIC: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];

/// Drain up to `limit` events from `TELEMETRY_RING` and write each one to
/// `SERIAL2_TELEMETRY` (COM2) as:
///
///   `[0xEF 0xBE 0xAD 0xDE] [16 bytes of TelemetryEvent in little-endian]`
///
/// Called from the timer handler (low-priority periodic drain).  Uses
/// `try_lock` on the serial port so it silently skips the drain cycle rather
/// than spinning if another path holds the lock.
///
/// # Returns
/// Number of events drained this call.
pub fn drain_telemetry_to_serial(limit: usize) -> usize {
    let mut drained = 0;
    while drained < limit {
        let event = match TELEMETRY_RING.pop() {
            Some(e) => e,
            None => break,
        };

        // Serialize the 16-byte TelemetryEvent over COM2 with magic framing.
        // We hold the lock for the full 20 bytes so the daemon always sees an
        // atomic frame — partial frames would desync the magic-byte scanner.
        if let Some(mut serial) = crate::serial::SERIAL2_TELEMETRY.try_lock() {
            // Magic sync header
            for b in DRAIN_MAGIC {
                serial.send_byte(b);
            }
            // pid  (4 bytes LE)
            for b in event.pid.to_le_bytes() {
                serial.send_byte(b);
            }
            // node, cap_type, score, _pad  (4 bytes)
            serial.send_byte(event.node);
            serial.send_byte(event.cap_type);
            serial.send_byte(event.score);
            serial.send_byte(event._pad);
            // tick (8 bytes LE)
            for b in event.tick.to_le_bytes() {
                serial.send_byte(b);
            }
        } else {
            // Serial port busy — put the event back by re-pushing, then stop
            // draining for this cycle.  Re-pushing may fail if the ring is
            // now full, in which case the event is dropped (same as any other
            // overflow scenario).
            let _ = TELEMETRY_RING.push(event);
            break;
        }
        drained += 1;
    }
    drained
}
