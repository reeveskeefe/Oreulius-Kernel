//! Clock and time utilities.

use crate::raw::wasi;

/// WASI clock IDs.
pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;

/// Get the current monotonic clock time in nanoseconds.
///
/// Returns `None` if the clock query fails.
pub fn monotonic_ns() -> Option<u64> {
    // Store the result at scratch address 64 (avoids clobbering the iovec area at 0-11).
    const SCRATCH: u32 = 64;
    let errno = unsafe { wasi::clock_time_get(CLOCK_MONOTONIC, 1, SCRATCH) };
    if errno != 0 {
        return None;
    }
    let lo = unsafe { (SCRATCH as usize as *const u32).read_unaligned() } as u64;
    let hi = unsafe { ((SCRATCH + 4) as usize as *const u32).read_unaligned() } as u64;
    Some(lo | (hi << 32))
}

/// Get the current real-time clock value in nanoseconds since Unix epoch.
pub fn realtime_ns() -> Option<u64> {
    const SCRATCH: u32 = 64;
    let errno = unsafe { wasi::clock_time_get(CLOCK_REALTIME, 1, SCRATCH) };
    if errno != 0 {
        return None;
    }
    let lo = unsafe { (SCRATCH as usize as *const u32).read_unaligned() } as u64;
    let hi = unsafe { ((SCRATCH + 4) as usize as *const u32).read_unaligned() } as u64;
    Some(lo | (hi << 32))
}

/// Block until at least `ns` nanoseconds have elapsed (relative).
///
/// Uses `poll_oneoff` with a CLOCK_MONOTONIC subscription.  The Oreulia
/// kernel honours this with cooperative yielding (no busy-spin in kernel).
///
/// # Safety
/// Uses linear-memory addresses 0–95 as scratch space.
pub unsafe fn sleep_ns(ns: u64) {
    // Subscription at [0..48], event output at [48..80], nevents at [80..84]
    // Subscription layout (48 bytes):
    //   [0..7]   userdata  u64
    //   [8]      tag       u8   (0 = clock)
    //   [9..15]  _pad
    //   [16..19] clock_id  u32  (1 = monotonic)
    //   [24..31] timeout   u64  (nanoseconds, relative)
    //   [32..39] precision u64
    //   [40..41] flags     u16  (0 = relative)

    let sub = 0usize as *mut u8;
    // userdata = 1
    (sub as *mut u64).write_unaligned(1u64);
    // tag = 0 (clock)
    sub.add(8).write(0u8);
    // clock_id = 1 (monotonic)
    (sub.add(16) as *mut u32).write_unaligned(1u32);
    // timeout (ns)
    (sub.add(24) as *mut u64).write_unaligned(ns);
    // precision = 0
    (sub.add(32) as *mut u64).write_unaligned(0u64);
    // flags = 0 (relative)
    (sub.add(40) as *mut u16).write_unaligned(0u16);

    wasi::poll_oneoff(0, 48, 1, 80);
}

/// Block until at least `ms` milliseconds have elapsed.
pub unsafe fn sleep_ms(ms: u64) {
    sleep_ns(ms * 1_000_000)
}
