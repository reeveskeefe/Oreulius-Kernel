/*!
 * Oreulia Kernel Project
 *
 * License-Identifier: Oreulia Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulia.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! PS/2 Mouse Driver + USB HID Mouse Interface
//!
//! # PS/2 Mouse
//!
//! Implements the full PS/2 AUX port protocol:
//!   - Initialisation: Enable AUX device, set stream mode, enable data reporting
//!   - Packet decoding: Standard 3-byte packets + optional 4th byte (IntelliMouse wheel)
//!   - Overflow detection and sign-extension of 9-bit delta values
//!
//! IRQ12 → [`handle_irq`] → accumulates bytes into [`PS2_MOUSE`].
//!
//! # USB HID Mouse
//!
//! Provides [`UsbMouseReport`] and [`submit_usb_report`] so the USB HID class
//! driver (usb.rs) can push decoded reports into the same event pipeline.
//!
//! # Event Queue
//!
//! Both input sources push [`MouseEvent`] into a lock-free ring buffer.
//! Consumers call [`pop_event`] or [`get_state`] from any context.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicUsize, Ordering};

// ============================================================================
// I/O helpers
// ============================================================================

const KBD_DATA: u16 = 0x60;
const KBD_STATUS: u16 = 0x64;
const KBD_CMD: u16 = 0x64;

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    v
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

/// Spin-wait for the PS/2 controller input buffer to be empty (bit 1 clear).
#[inline(always)]
unsafe fn wait_input_empty() {
    for _ in 0..100_000u32 {
        if inb(KBD_STATUS) & 0x02 == 0 {
            return;
        }
    }
}

/// Spin-wait for the PS/2 controller output buffer to have data (bit 0 set).
#[inline(always)]
unsafe fn wait_output_full() -> bool {
    for _ in 0..100_000u32 {
        if inb(KBD_STATUS) & 0x01 != 0 {
            return true;
        }
    }
    false
}

/// Send a command byte to the PS/2 controller command port.
#[inline(always)]
unsafe fn cmd(byte: u8) {
    wait_input_empty();
    outb(KBD_CMD, byte);
}

/// Send a data byte to the PS/2 controller data port.
#[inline(always)]
unsafe fn data(byte: u8) {
    wait_input_empty();
    outb(KBD_DATA, byte);
}

/// Send a byte directly to the mouse (prefix 0xD4 routes to AUX port).
unsafe fn mouse_write(byte: u8) {
    cmd(0xD4);
    data(byte);
}

/// Read one byte from the PS/2 output buffer, waiting up to ~100ms.
unsafe fn mouse_read() -> Option<u8> {
    if wait_output_full() {
        Some(inb(KBD_DATA))
    } else {
        None
    }
}

// ============================================================================
// Mouse button bitmask
// ============================================================================

/// Bitmask of currently-pressed mouse buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseButtons(pub u8);

impl MouseButtons {
    pub const LEFT: u8 = 0x01;
    pub const RIGHT: u8 = 0x02;
    pub const MIDDLE: u8 = 0x04;
    pub const BTN4: u8 = 0x08;
    pub const BTN5: u8 = 0x10;

    pub fn left(self) -> bool {
        self.0 & Self::LEFT != 0
    }
    pub fn right(self) -> bool {
        self.0 & Self::RIGHT != 0
    }
    pub fn middle(self) -> bool {
        self.0 & Self::MIDDLE != 0
    }
}

// ============================================================================
// Mouse event / state
// ============================================================================

/// A single decoded mouse event.
#[derive(Debug, Clone, Copy)]
pub struct MouseEvent {
    /// Signed horizontal delta (pixels, right-positive).
    pub dx: i16,
    /// Signed vertical delta (pixels, down-positive).
    pub dy: i16,
    /// Scroll wheel delta (up-positive).
    pub dwheel: i8,
    /// Button state at the time of this event.
    pub buttons: MouseButtons,
}

/// Absolute cursor position accumulated from all deltas.
pub struct MouseState {
    pub x: AtomicI32,
    pub y: AtomicI32,
    pub buttons: AtomicU8,
}

static MOUSE_STATE: MouseState = MouseState {
    x: AtomicI32::new(0),
    y: AtomicI32::new(0),
    buttons: AtomicU8::new(0),
};

// ============================================================================
// Lock-free event ring buffer
// ============================================================================

const EVT_BUF_SIZE: usize = 128;

struct MouseEventRing {
    buf: UnsafeCell<[MouseEvent; EVT_BUF_SIZE]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

unsafe impl Sync for MouseEventRing {}

impl MouseEventRing {
    const fn new() -> Self {
        MouseEventRing {
            buf: UnsafeCell::new(
                [MouseEvent {
                    dx: 0,
                    dy: 0,
                    dwheel: 0,
                    buttons: MouseButtons(0),
                }; EVT_BUF_SIZE],
            ),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, ev: MouseEvent) {
        let tail = self.tail.load(Ordering::Acquire);
        let next = (tail + 1) % EVT_BUF_SIZE;
        if next == self.head.load(Ordering::Acquire) {
            return;
        } // full, drop
        unsafe {
            (*self.buf.get())[tail] = ev;
        }
        self.tail.store(next, Ordering::Release);
    }

    fn pop(&self) -> Option<MouseEvent> {
        let head = self.head.load(Ordering::Acquire);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        let ev = unsafe { (*self.buf.get())[head] };
        self.head
            .store((head + 1) % EVT_BUF_SIZE, Ordering::Release);
        Some(ev)
    }
}

static EVENT_RING: MouseEventRing = MouseEventRing::new();

// ============================================================================
// PS/2 Mouse controller
// ============================================================================

/// Initialisation state of the PS/2 mouse.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InitState {
    Uninit,
    Standard,
    IntelliMouse,
}

/// IRQ-driven PS/2 mouse packet assembler.
pub struct Ps2Mouse {
    init_state: InitState,
    /// Packet byte accumulator (up to 4 bytes).
    packet: [u8; 4],
    /// Number of bytes collected so far for the current packet.
    packet_len: u8,
    /// Expected packet size: 3 (standard) or 4 (IntelliMouse with scroll).
    packet_size: u8,
    overflow_cnt: u32,
}

impl Ps2Mouse {
    const fn new() -> Self {
        Ps2Mouse {
            init_state: InitState::Uninit,
            packet: [0; 4],
            packet_len: 0,
            packet_size: 3,
            overflow_cnt: 0,
        }
    }

    // ----------------------------------------------------------------
    // Initialisation
    // ----------------------------------------------------------------

    /// Initialise the PS/2 AUX port and attempt IntelliMouse detection.
    ///
    /// Must be called once, from a non-interrupt context, before any IRQ
    /// arrives. The keyboard controller IRQ1 must already be enabled.
    pub fn init(&mut self) {
        unsafe {
            // Enable the AUX port.
            cmd(0xA8);

            // Enable AUX interrupt in the CW byte.
            cmd(0x20); // read current CW
            let mut cw = inb(KBD_DATA);
            cw |= 0x02; // enable AUX IRQ (bit 1)
            cw &= !0x20; // clear "disable mouse clock" (bit 5)
            cmd(0x60); // write CW
            data(cw);

            // Reset the mouse.
            mouse_write(0xFF);
            // Expect ACK (0xFA) + BAT result (0xAA) + device ID (0x00).
            for _ in 0..3 {
                let _ = mouse_read();
            }

            // Attempt to enable IntelliMouse (Z-axis / scroll wheel):
            //   Set sample rate 200, 100, 80 → then GET_DEVICE_ID.
            //   If ID == 0x03, scroll wheel is available.
            for rate in [200u8, 100, 80] {
                mouse_write(0xF3);
                let _ = mouse_read(); // SET_SAMPLE_RATE + ACK
                mouse_write(rate);
                let _ = mouse_read(); // rate value + ACK
            }
            mouse_write(0xF2);
            let _ = mouse_read(); // GET_DEVICE_ID + ACK
            let dev_id = mouse_read().unwrap_or(0);
            if dev_id == 0x03 {
                self.packet_size = 4;
                self.init_state = InitState::IntelliMouse;
            } else {
                self.packet_size = 3;
                self.init_state = InitState::Standard;
            }

            // Set default resolution (4 counts/mm) and sample rate (100 Hz).
            mouse_write(0xE8);
            let _ = mouse_read(); // SET_RESOLUTION
            mouse_write(0x02);
            let _ = mouse_read(); // 4 counts/mm
            mouse_write(0xF3);
            let _ = mouse_read(); // SET_SAMPLE_RATE
            mouse_write(100);
            let _ = mouse_read(); // 100 Hz

            // Enable data reporting (stream mode).
            mouse_write(0xF4);
            let _ = mouse_read();
        }

        crate::serial_println!(
            "[MOUSE] PS/2 {} mouse initialised (packet_size={})",
            if self.init_state == InitState::IntelliMouse {
                "IntelliMouse"
            } else {
                "standard"
            },
            self.packet_size
        );
    }

    // ----------------------------------------------------------------
    // IRQ byte handler
    // ----------------------------------------------------------------

    /// Called from IRQ12 handler with each incoming AUX byte.
    pub fn handle_byte(&mut self, byte: u8) {
        let idx = self.packet_len as usize;

        // Byte 0 — flag/button byte.  Bit 3 must always be set; if not,
        // we've lost sync.  Discard and wait for a valid start byte.
        if idx == 0 {
            if byte & 0x08 == 0 {
                // Out of sync — drop and re-sync.
                return;
            }
        }

        self.packet[idx] = byte;
        self.packet_len += 1;

        if self.packet_len >= self.packet_size {
            self.decode_packet();
            self.packet_len = 0;
        }
    }

    // ----------------------------------------------------------------
    // Packet decode
    // ----------------------------------------------------------------

    fn decode_packet(&mut self) {
        let flags = self.packet[0];
        let raw_dx = self.packet[1] as i16;
        let raw_dy = self.packet[2] as i16;

        // Detect overflow; if set the deltas are unreliable — clamp to zero.
        if flags & 0xC0 != 0 {
            self.overflow_cnt += 1;
            let ev = MouseEvent {
                dx: 0,
                dy: 0,
                dwheel: 0,
                buttons: MouseButtons(flags & 0x07),
            };
            EVENT_RING.push(ev);
            MOUSE_STATE.buttons.store(flags & 0x07, Ordering::Release);
            return;
        }

        // Sign-extend the 9-bit deltas using the sign bits in the flags byte.
        let dx = if flags & 0x10 != 0 {
            raw_dx | !0xFF
        } else {
            raw_dx
        };
        // Y is inverted: PS/2 positive Y = up, screen positive Y = down.
        let dy_raw = if flags & 0x20 != 0 {
            raw_dy | !0xFF
        } else {
            raw_dy
        };
        let dy = -dy_raw;

        let dwheel: i8 = if self.packet_size == 4 {
            // Bits 7:4 of byte 3 encode button 4/5 (ignore here).
            // Bits 3:0 are the signed scroll delta.
            let w = (self.packet[3] & 0x0F) as i8;
            // Sign-extend 4-bit value.
            if w & 0x08 != 0 {
                w | !0x07
            } else {
                w
            }
        } else {
            0
        };

        let buttons = MouseButtons(flags & 0x07);

        // Update absolute position (unbounded; GUI layer clamps to screen).
        MOUSE_STATE.x.fetch_add(dx as i32, Ordering::Relaxed);
        MOUSE_STATE.y.fetch_add(dy as i32, Ordering::Relaxed);
        MOUSE_STATE.buttons.store(buttons.0, Ordering::Release);

        EVENT_RING.push(MouseEvent {
            dx,
            dy,
            dwheel,
            buttons,
        });
    }
}

/// Global PS/2 mouse instance (accessed from IRQ context).
static mut PS2_MOUSE_INNER: Ps2Mouse = Ps2Mouse::new();
/// Guards initialisation; the IRQ handler is safe once this is `true`.
static MOUSE_INIT: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Public API
// ============================================================================

/// Initialise the PS/2 mouse.  Call once during kernel boot.
pub fn init() {
    unsafe {
        PS2_MOUSE_INNER.init();
    }
    MOUSE_INIT.store(true, Ordering::Release);
}

/// Called from the IRQ12 (AUX) handler.
///
/// # Safety
/// Must only be called from an interrupt handler on the CPU that owns IRQ12.
pub unsafe fn handle_irq() {
    if !MOUSE_INIT.load(Ordering::Acquire) {
        return;
    }

    let status = inb(KBD_STATUS);
    if status & 0x01 == 0 {
        return;
    } // no data
    if status & 0x20 == 0 {
        return;
    } // data is from keyboard, not mouse

    let byte = inb(KBD_DATA);
    PS2_MOUSE_INNER.handle_byte(byte);
}

/// Pop the oldest unprocessed [`MouseEvent`] from the ring buffer.
/// Returns `None` if the queue is empty.
#[inline]
pub fn pop_event() -> Option<MouseEvent> {
    EVENT_RING.pop()
}

/// Snapshot the current absolute cursor position and button state.
#[inline]
pub fn get_state() -> (i32, i32, MouseButtons) {
    (
        MOUSE_STATE.x.load(Ordering::Acquire),
        MOUSE_STATE.y.load(Ordering::Acquire),
        MouseButtons(MOUSE_STATE.buttons.load(Ordering::Acquire)),
    )
}

/// Reset the absolute position to a known coordinate (e.g., screen centre).
pub fn set_position(x: i32, y: i32) {
    MOUSE_STATE.x.store(x, Ordering::Release);
    MOUSE_STATE.y.store(y, Ordering::Release);
}

// ============================================================================
// USB HID Mouse interface
// ============================================================================

/// Raw 4-byte USB HID Boot Protocol mouse report.
///
/// Boot Protocol (HID spec §B.2) layout:
///   byte 0: button bitmask
///   byte 1: X displacement (signed)
///   byte 2: Y displacement (signed)
///   byte 3: scroll wheel (signed)
#[derive(Clone, Copy, Default)]
pub struct UsbMouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
    pub dwheel: i8,
}

/// Submit a USB HID mouse report into the shared event pipeline.
///
/// Called by the USB HID class driver after decoding a boot-protocol report.
pub fn submit_usb_report(report: UsbMouseReport) {
    let buttons = MouseButtons(report.buttons & 0x07);

    MOUSE_STATE.x.fetch_add(report.dx as i32, Ordering::Relaxed);
    MOUSE_STATE.y.fetch_add(report.dy as i32, Ordering::Relaxed);
    MOUSE_STATE.buttons.store(buttons.0, Ordering::Release);

    EVENT_RING.push(MouseEvent {
        dx: report.dx as i16,
        dy: -(report.dy as i16), // HID Y is down-positive; flip for screen coords
        dwheel: report.dwheel,
        buttons,
    });
}

// ============================================================================
// Diagnostics
// ============================================================================

/// Number of PS/2 overflow packets seen since boot.
pub fn overflow_count() -> u32 {
    // Only access if initialised.
    if MOUSE_INIT.load(Ordering::Acquire) {
        unsafe { PS2_MOUSE_INNER.overflow_cnt }
    } else {
        0
    }
}

/// Number of events currently waiting in the ring buffer.
pub fn pending_events() -> usize {
    let head = EVENT_RING.head.load(Ordering::Acquire);
    let tail = EVENT_RING.tail.load(Ordering::Acquire);
    tail.wrapping_sub(head) % EVT_BUF_SIZE
}
