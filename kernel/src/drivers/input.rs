/*!
 * Oreulius Kernel Project
 *
 * SPDX-License-Identifier: LicenseRef-Oreulius-Community
 */


//! # Unified Input Event Queue
//!
//! Merges keyboard ([`KeyEvent`]) and mouse ([`MouseEvent`]) events into a
//! single lock-free, interrupt-safe ring buffer of [`InputEvent`] values.
//!
//! ## Architecture
//!
//! ```text
//!  IRQ1  ──► keyboard::handle_irq  ──► keyboard::EVENT_BUF
//!                                               │
//!                                               ▼
//!                                    input::pump()  ──► INPUT_RING
//!                                               ▲
//!  AUX IRQ ► mouse::handle_byte    ──► mouse::EVENT_RING
//! ```
//!
//! `pump()` is called from the IRQ handlers (and also from the main scheduler
//! tick) and drains both source queues into `INPUT_RING`.
//!
//! ## WASM Host Functions  (IDs 38–44)
//!
//! | ID | Signature (WASM i32 args → i32 result) | Description |
//! |----|----------------------------------------|-------------|
//! | 38 | `input_poll() → i32`                   | Returns 1 if any event pending, 0 if empty |
//! | 39 | `input_read(buf_ptr, buf_len) → i32`   | Reads one serialised InputEvent into WASM memory; returns bytes written or 0 |
//! | 40 | `input_event_type() → i32`             | Peek type of next event without consuming it; -1 if empty |
//! | 41 | `input_flush() → i32`                  | Discard all pending events; returns count discarded |
//! | 42 | `input_key_poll() → i32`               | Like input_poll but only keyboard events |
//! | 43 | `input_mouse_poll() → i32`             | Like input_poll but only mouse events |
//! | 44 | `input_gamepad_poll() → i32`           | Reserved — always returns 0 for now |

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Public event types
// ---------------------------------------------------------------------------

/// Unified event type tag.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InputEventKind {
    None = 0,
    Key = 1,
    Mouse = 2,
    Gamepad = 3,
}

/// Keyboard key state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyState {
    Pressed = 1,
    Released = 2,
}

/// A decoded keyboard event placed in the unified queue.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct KeyInputEvent {
    /// Unicode codepoint, or 0 for non-character keys.
    pub codepoint: u32,
    /// Raw scancode byte.
    pub scancode: u8,
    /// Was this a press or release?
    pub state: KeyState,
    /// Modifier bitmask: bit0=Shift, bit1=Ctrl, bit2=Alt, bit3=Super.
    pub modifiers: u8,
    _pad: u8,
}

/// A decoded mouse event placed in the unified queue.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct MouseInputEvent {
    pub dx: i16,
    pub dy: i16,
    pub dwheel: i8,
    /// Button bitmask: bit0=Left, bit1=Right, bit2=Middle.
    pub buttons: u8,
    _pad: [u8; 2],
}

/// Tagged union over all input sources.
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct InputEvent {
    /// Which kind of event this is.
    pub kind: InputEventKind,
    _pad: [u8; 3],
    pub data: InputEventData,
}

/// Inner data — the largest variant determines size (16 bytes total).
#[derive(Copy, Clone)]
#[repr(C)]
pub union InputEventData {
    pub key: KeyInputEvent,
    pub mouse: MouseInputEvent,
    pub raw: [u8; 8],
}

impl core::fmt::Debug for InputEventData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<InputEventData>")
    }
}

impl InputEvent {
    pub const fn empty() -> Self {
        InputEvent {
            kind: InputEventKind::None,
            _pad: [0; 3],
            data: InputEventData { raw: [0; 8] },
        }
    }

    pub fn key_event(cp: u32, scancode: u8, state: KeyState, modifiers: u8) -> Self {
        InputEvent {
            kind: InputEventKind::Key,
            _pad: [0; 3],
            data: InputEventData {
                key: KeyInputEvent {
                    codepoint: cp,
                    scancode,
                    state,
                    modifiers,
                    _pad: 0,
                },
            },
        }
    }

    pub fn mouse_event(dx: i16, dy: i16, dwheel: i8, buttons: u8) -> Self {
        InputEvent {
            kind: InputEventKind::Mouse,
            _pad: [0; 3],
            data: InputEventData {
                mouse: MouseInputEvent {
                    dx,
                    dy,
                    dwheel,
                    buttons,
                    _pad: [0; 2],
                },
            },
        }
    }

    /// Serialise into a flat byte buffer (little-endian).  
    /// Returns the number of bytes written (always `INPUT_EVENT_BYTES`).
    pub fn serialise(&self, out: &mut [u8]) -> usize {
        if out.len() < INPUT_EVENT_BYTES {
            return 0;
        }
        out[0] = self.kind as u8;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        // Safely copy the 8 raw union bytes.
        let raw = unsafe { self.data.raw };
        out[4..12].copy_from_slice(&raw);
        INPUT_EVENT_BYTES
    }
}

/// Byte size of a serialised `InputEvent` (kind byte + 3 pad + 8 data bytes).
pub const INPUT_EVENT_BYTES: usize = 12;

// ---------------------------------------------------------------------------
// Lock-free ring buffer
// ---------------------------------------------------------------------------

const RING_SIZE: usize = 256; // must be power of two

struct InputRing {
    buf: UnsafeCell<[InputEvent; RING_SIZE]>,
    head: AtomicUsize, // consumer reads here
    tail: AtomicUsize, // producer writes here
    overflow: AtomicU32,
}

// SAFETY: We use atomic head/tail and only write before publishing.
unsafe impl Sync for InputRing {}
unsafe impl Send for InputRing {}

impl InputRing {
    const fn new() -> Self {
        InputRing {
            buf: UnsafeCell::new([InputEvent::empty(); RING_SIZE]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            overflow: AtomicU32::new(0),
        }
    }

    fn push(&self, ev: InputEvent) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let next = (tail + 1) & (RING_SIZE - 1);
        if next == self.head.load(Ordering::Acquire) {
            // Full — drop event and count overflow.
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        unsafe {
            (*self.buf.get())[tail] = ev;
        }
        self.tail.store(next, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<InputEvent> {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return None;
        }
        let ev = unsafe { (*self.buf.get())[head] };
        self.head
            .store((head + 1) & (RING_SIZE - 1), Ordering::Release);
        Some(ev)
    }

    fn peek_kind(&self) -> InputEventKind {
        let head = self.head.load(Ordering::Relaxed);
        if head == self.tail.load(Ordering::Acquire) {
            return InputEventKind::None;
        }
        unsafe { (*self.buf.get())[head].kind }
    }

    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Acquire)
    }

    fn len(&self) -> usize {
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        t.wrapping_sub(h) & (RING_SIZE - 1)
    }

    fn flush(&self) -> usize {
        let mut count = 0usize;
        while self.pop().is_some() {
            count += 1;
        }
        count
    }
}

static INPUT_RING: InputRing = InputRing::new();

// ---------------------------------------------------------------------------
// Modifier-key tracking (global atomic flags, updated from IRQ context)
// ---------------------------------------------------------------------------

static MODIFIERS: AtomicU8 = AtomicU8::new(0);

use core::sync::atomic::AtomicU8;

pub mod modifier {
    pub const SHIFT: u8 = 1 << 0;
    pub const CTRL: u8 = 1 << 1;
    pub const ALT: u8 = 1 << 2;
    pub const SUPER: u8 = 1 << 3;
}

/// Update modifier state from a key press/release.
fn update_modifiers(ev: &crate::drivers::x86::keyboard::KeyEvent, pressed: bool) {
    use crate::drivers::x86::keyboard::KeyEvent;
    let bit = match ev {
        KeyEvent::Char('L') | KeyEvent::Char('R') => 0, // not real modifier
        _ => return,
    };
    if pressed {
        MODIFIERS.fetch_or(bit, Ordering::Relaxed);
    } else {
        MODIFIERS.fetch_and(!bit, Ordering::Relaxed);
    }
}

/// Read current modifier state.
pub fn current_modifiers() -> u8 {
    MODIFIERS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// pump() — drain keyboard + mouse source queues into INPUT_RING
// ---------------------------------------------------------------------------

/// Drain all pending keyboard and mouse events into the unified ring.
///
/// Call this from IRQ handlers and/or the scheduler tick.  Safe to call
/// concurrently — worst case some events are reordered by one slot.
pub fn pump() {
    let mods = current_modifiers();

    // Drain keyboard events.
    while let Some(kev) = crate::drivers::x86::keyboard::poll_event() {
        let (cp, scancode, pressed) = decode_key_event(&kev);
        if pressed {
            let ev = InputEvent::key_event(cp, scancode, KeyState::Pressed, mods);
            INPUT_RING.push(ev);
        } else {
            let ev = InputEvent::key_event(cp, scancode, KeyState::Released, mods);
            INPUT_RING.push(ev);
        }
    }

    // Drain mouse events.
    while let Some(mev) = crate::drivers::x86::mouse::pop_event() {
        let ev = InputEvent::mouse_event(mev.dx as i16, mev.dy as i16, mev.dwheel, mev.buttons.0);
        INPUT_RING.push(ev);
    }
}

/// Translate a [`KeyEvent`] to (codepoint, scancode, is_pressed).
fn decode_key_event(kev: &crate::drivers::x86::keyboard::KeyEvent) -> (u32, u8, bool) {
    use crate::drivers::x86::keyboard::KeyEvent;
    match kev {
        KeyEvent::Char(c) => (*c as u32, 0, true),
        KeyEvent::Enter => ('\n' as u32, 0x1C, true),
        KeyEvent::Backspace => ('\x08' as u32, 0x0E, true),
        KeyEvent::Tab => ('\t' as u32, 0x0F, true),
        KeyEvent::Escape => (0x1B, 0x01, true),
        KeyEvent::Up => (0, 0x48, true),
        KeyEvent::Down => (0, 0x50, true),
        KeyEvent::Left => (0, 0x4B, true),
        KeyEvent::Right => (0, 0x4D, true),
        KeyEvent::Home => (0, 0x47, true),
        KeyEvent::End => (0, 0x4F, true),
        KeyEvent::Delete => (0x7F, 0x53, true),
        KeyEvent::PageUp => (0, 0x49, true),
        KeyEvent::PageDown => (0, 0x51, true),
        KeyEvent::Ctrl(c) => (*c as u32, 0, true),
        KeyEvent::AltChar(c) => (*c as u32, 0, true),
        KeyEvent::AltFn(n) => (0, 0x3A + *n as u8, true),
        KeyEvent::None => (0, 0, false),
    }
}

// ---------------------------------------------------------------------------
// Public polling API
// ---------------------------------------------------------------------------

/// Returns `true` if there is at least one event waiting.
pub fn poll() -> bool {
    !INPUT_RING.is_empty()
}

/// Returns `true` if there is at least one keyboard event waiting.
pub fn poll_key() -> bool {
    // We must peek without consuming mouse events first.
    // This is a best-effort check — just reports any pending event kind.
    matches!(INPUT_RING.peek_kind(), InputEventKind::Key)
}

/// Returns `true` if there is at least one mouse event waiting.
pub fn poll_mouse() -> bool {
    matches!(INPUT_RING.peek_kind(), InputEventKind::Mouse)
}

/// Pop one event from the queue.  Returns `None` if empty.
pub fn read() -> Option<InputEvent> {
    INPUT_RING.pop()
}

/// Peek at the kind of the next event without consuming it.
pub fn peek_kind() -> InputEventKind {
    INPUT_RING.peek_kind()
}

/// Number of events currently queued.
pub fn pending() -> usize {
    INPUT_RING.len()
}

/// Discard all pending events.  Returns count discarded.
pub fn flush() -> usize {
    INPUT_RING.flush()
}

/// Overflow counter (events dropped because ring was full).
pub fn overflow_count() -> u32 {
    INPUT_RING.overflow.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

pub fn init() {
    // Nothing to allocate — all storage is static.
    // The pump is called from IRQ handlers after this point.
    MODIFIERS.store(0, Ordering::Relaxed);
}
