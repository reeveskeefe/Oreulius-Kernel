/*!
 * Oreulia Kernel Project
 *
 *License-Identifier: Oreulius License (see LICENSE)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulia Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Contributing:
 * - By contributing to this file, you agree to license your work under the same terms.
 * - Please see CONTRIBUTING.md for code style and review guidelines.
 *
 * ---------------------------------------------------------------------------
 */

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

static DROPPED_PACKETS: AtomicUsize = AtomicUsize::new(0);
static LAST_DROP_WARNING: AtomicUsize = AtomicUsize::new(0);

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;

// Lock-free keyboard state using atomics
static SHIFT_PRESSED: AtomicBool = AtomicBool::new(false);
static CAPS_LOCK: AtomicBool = AtomicBool::new(false);
static CTRL_PRESSED: AtomicBool = AtomicBool::new(false);
static ALT_PRESSED: AtomicBool = AtomicBool::new(false);
static EXTENDED: AtomicBool = AtomicBool::new(false);
static RELEASE_PREFIX: AtomicBool = AtomicBool::new(false);
static SET2_ACTIVE: AtomicBool = AtomicBool::new(false);

const KEY_BUFFER_SIZE: usize = 256;

struct KeyBuffer {
    buf: UnsafeCell<[u8; KEY_BUFFER_SIZE]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl KeyBuffer {
    const fn new() -> Self {
        KeyBuffer {
            buf: UnsafeCell::new([0; KEY_BUFFER_SIZE]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, byte: u8) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % KEY_BUFFER_SIZE;

        if next_tail == head {
            // Buffer full
            let old_count = DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
            if old_count == 0 || old_count % 100 == 0 {
                show_drop_warning();
            }
            return false;
        }

        unsafe {
            (*self.buf.get())[tail] = byte;
        }
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<u8> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        let byte = unsafe { (*self.buf.get())[head] };
        let next_head = (head + 1) % KEY_BUFFER_SIZE;
        self.head.store(next_head, Ordering::Release);
        Some(byte)
    }

    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if tail >= head {
            tail - head
        } else {
            KEY_BUFFER_SIZE - head + tail
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }
}

// SAFETY: KeyBuffer uses atomics for synchronization, making it safe to share across threads
unsafe impl Sync for KeyBuffer {}

static KEY_BUFFER: KeyBuffer = KeyBuffer::new();

/// Check if keyboard buffer has input available
pub fn has_input() -> bool {
    !KEY_BUFFER.is_empty()
}

/// Get number of bytes available in keyboard buffer
pub fn available_bytes() -> usize {
    KEY_BUFFER.len()
}

const EVENT_BUFFER_SIZE: usize = 64;

struct EventBuffer {
    buf: UnsafeCell<[KeyEvent; EVENT_BUFFER_SIZE]>,
    head: AtomicUsize,
    tail: AtomicUsize,
}

impl EventBuffer {
    const fn new() -> Self {
        EventBuffer {
            buf: UnsafeCell::new([KeyEvent::None; EVENT_BUFFER_SIZE]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    fn push(&self, ev: KeyEvent) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % EVENT_BUFFER_SIZE;

        if next_tail == head {
            // Buffer full
            let old_count = DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
            if old_count == 0 || old_count % 100 == 0 {
                show_drop_warning();
            }
            return false;
        }

        unsafe {
            (*self.buf.get())[tail] = ev;
        }
        self.tail.store(next_tail, Ordering::Release);
        true
    }

    fn pop(&self) -> Option<KeyEvent> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        let ev = unsafe { (*self.buf.get())[head] };
        let next_head = (head + 1) % EVENT_BUFFER_SIZE;
        self.head.store(next_head, Ordering::Release);
        Some(ev)
    }

    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if tail >= head {
            tail - head
        } else {
            EVENT_BUFFER_SIZE - head + tail
        }
    }
}

// SAFETY: EventBuffer uses atomics for synchronization, making it safe to share across threads
unsafe impl Sync for EventBuffer {}

static EVENT_BUFFER: EventBuffer = EventBuffer::new();

// Debug counters for the keyboard pipeline
static IRQ_COUNT: AtomicUsize = AtomicUsize::new(0);
static SCANCODE_COUNT: AtomicUsize = AtomicUsize::new(0);
static EVENTS_PUSHED: AtomicUsize = AtomicUsize::new(0);
static EVENTS_POPPED: AtomicUsize = AtomicUsize::new(0);
static EVENTS_NONE: AtomicUsize = AtomicUsize::new(0);
static ERROR_STATUS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    None,
    Char(char),
    Enter,
    Backspace,
    Tab,
    Escape,
    Ctrl(char),
    AltFn(u8),
    AltChar(char),
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
}

/// Visual warning for dropped packets (direct VGA write, interrupt-safe)
/// Only shows warning with cooldown to prevent spam
fn show_drop_warning() {
    // Get current drop count
    let current = DROPPED_PACKETS.load(Ordering::Relaxed);
    let last_warning = LAST_DROP_WARNING.load(Ordering::Relaxed);

    // Only show warning every 50 drops to avoid spam
    if current >= last_warning + 50 {
        LAST_DROP_WARNING.store(current, Ordering::Relaxed);

        unsafe {
            let vga = 0xB8000 as *mut u16;
            // Flash "DROP!" at top-right corner (row 0, col 74-78) in red
            let row_offset = 0;
            *vga.add(row_offset + 74) = 0x4F44; // D (white on red)
            *vga.add(row_offset + 75) = 0x4F52; // R
            *vga.add(row_offset + 76) = 0x4F4F; // O
            *vga.add(row_offset + 77) = 0x4F50; // P
            *vga.add(row_offset + 78) = 0x4F21; // !
        }
    }
}

pub struct Keyboard {
    // This struct is now just a placeholder for the handle_scancode method
    // All state is stored in global atomics
}

impl Keyboard {
    pub fn reset_state() {
        SHIFT_PRESSED.store(false, Ordering::Relaxed);
        CAPS_LOCK.store(false, Ordering::Relaxed);
        CTRL_PRESSED.store(false, Ordering::Relaxed);
        ALT_PRESSED.store(false, Ordering::Relaxed);
        EXTENDED.store(false, Ordering::Relaxed);
        RELEASE_PREFIX.store(false, Ordering::Relaxed);
        SET2_ACTIVE.store(false, Ordering::Relaxed);
    }

    fn handle_scancode(scancode: u8) -> Option<KeyEvent> {
        // Handle Set 2 release prefix (0xF0)
        if scancode == 0xF0 {
            RELEASE_PREFIX.store(true, Ordering::Relaxed);
            // DO NOT force switch to Set 2 mode based on seeing 0xF0.
            // If we are in translated mode, 0xF0 shouldn't appear, or might be data.
            // Trust the configuration set in init().
            // SET2_ACTIVE.store(true, Ordering::Relaxed);
            return None;
        }

        if scancode == 0xE0 {
            EXTENDED.store(true, Ordering::Relaxed);
            return None;
        }

        let mut is_release = false;
        let mut code = scancode;
        if RELEASE_PREFIX.swap(false, Ordering::Relaxed) {
            is_release = true;
        }

        let set2 = SET2_ACTIVE.load(Ordering::Relaxed);
        if set2 {
            if let Some(mapped) = set2_to_set1(code) {
                code = mapped;
            } else {
                // Unknown set 2 code, drop to avoid mis-mapping into set 1
                if EXTENDED.load(Ordering::Relaxed) {
                    EXTENDED.store(false, Ordering::Relaxed);
                }
                return None;
            }
        } else if code & 0x80 != 0 {
            is_release = true;
            code &= 0x7F;
        }

        if is_release {
            if EXTENDED.load(Ordering::Relaxed) {
                EXTENDED.store(false, Ordering::Relaxed);
                // Handle release of extended keys if needed
                match code {
                    0x1D => CTRL_PRESSED.store(false, Ordering::Relaxed), // Right Ctrl
                    0x38 => ALT_PRESSED.store(false, Ordering::Relaxed),  // Right Alt
                    _ => {}
                }
                return None;
            }

            match code {
                0x2A | 0x36 => SHIFT_PRESSED.store(false, Ordering::Relaxed),
                0x1D => CTRL_PRESSED.store(false, Ordering::Relaxed),
                0x38 => ALT_PRESSED.store(false, Ordering::Relaxed),
                _ => {}
            }
            return None;
        }

        // Force Reset on F12 (set1 code 0x58)
        if code == 0x58 {
            Self::reset_state();
            return None;
        }

        // Handle extended keys (pressed)
        if EXTENDED.load(Ordering::Relaxed) {
            EXTENDED.store(false, Ordering::Relaxed);
            match code {
                0x48 => return Some(KeyEvent::Up),
                0x50 => return Some(KeyEvent::Down),
                0x4B => return Some(KeyEvent::Left),
                0x4D => return Some(KeyEvent::Right),
                0x47 => return Some(KeyEvent::Home),
                0x4F => return Some(KeyEvent::End),
                0x1D => {
                    CTRL_PRESSED.store(true, Ordering::Relaxed);
                    return None;
                } // Right Ctrl
                0x38 => {
                    ALT_PRESSED.store(true, Ordering::Relaxed);
                    return None;
                } // Right Alt
                // TODO: Delete, PageUp, PageDown
                _ => return None,
            }
        }

        match code {
            // Shift pressed
            0x2A | 0x36 => {
                SHIFT_PRESSED.store(true, Ordering::Relaxed);
                return None;
            }
            // Shift released
            0xAA | 0xB6 => {
                SHIFT_PRESSED.store(false, Ordering::Relaxed);
                return None;
            }
            // Caps Lock
            0x3A => {
                let old = CAPS_LOCK.load(Ordering::Relaxed);
                CAPS_LOCK.store(!old, Ordering::Relaxed);
                return None;
            }
            // Ctrl pressed
            0x1D => {
                CTRL_PRESSED.store(true, Ordering::Relaxed);
                return None;
            }
            // Alt pressed
            0x38 => {
                ALT_PRESSED.store(true, Ordering::Relaxed);
                return None;
            }
            // Left Windows Key (Super)
            0x5B => {
                // Ignore for now
                return None;
            }

            // Regular key press (ignore releases)
            code if code < 0x80 => {
                let shift_pressed = SHIFT_PRESSED.load(Ordering::Relaxed);
                let caps_lock = CAPS_LOCK.load(Ordering::Relaxed);
                let ctrl_pressed = CTRL_PRESSED.load(Ordering::Relaxed);
                let alt_pressed = ALT_PRESSED.load(Ordering::Relaxed);

                if alt_pressed {
                    if let Some(fn_key) = scancode_to_fn(code) {
                        return Some(KeyEvent::AltFn(fn_key));
                    }
                }
                let base = SCANCODE_MAP[code as usize];
                if base == '\0' {
                    // Helps us verify keyboard activity even if mapping is incomplete.
                    return Some(KeyEvent::Char('?'));
                }

                let mut out = if shift_pressed {
                    SCANCODE_MAP_SHIFT[code as usize]
                } else if caps_lock && base.is_ascii_alphabetic() {
                    // Caps Lock logic: Invert case if Shift is pressed
                    if shift_pressed {
                        base.to_ascii_lowercase()
                    } else {
                        base.to_ascii_uppercase()
                    }
                } else {
                    base
                };
                if ctrl_pressed && out.is_ascii_alphabetic() {
                    out = out.to_ascii_lowercase();
                    return Some(KeyEvent::Ctrl(out));
                }
                if alt_pressed {
                    return Some(KeyEvent::AltChar(out));
                }
                match out {
                    '\n' => Some(KeyEvent::Enter),
                    '\x08' => Some(KeyEvent::Backspace),
                    '\t' => Some(KeyEvent::Tab),
                    '\x1B' => Some(KeyEvent::Escape),
                    _ => Some(KeyEvent::Char(out)),
                }
            }
            _ => None,
        }
    }
}

// Removed unused read_scancode and is_data_available functions to prevent race conditions with IRQ handler
// Input is now exclusively interrupt-driven via EVENT_BUFFER

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
fn wait_write() {
    let mut timeout = 100000;
    while unsafe { inb(STATUS_PORT) } & 0x02 != 0 {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 {
            break;
        }
    }
}

#[inline]
fn wait_read() -> bool {
    let mut timeout = 100000;
    while unsafe { inb(STATUS_PORT) } & 0x01 == 0 {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 {
            return false;
        }
    }
    true
}

/// Initialize the PS/2 keyboard
/// This forces the controller into a known state (Scancode Set 1 translation)
pub fn init() {
    unsafe {
        // Disable keyboard port
        wait_write();
        outb(STATUS_PORT, 0xAD);

        // Read Controller Configuration Byte
        wait_write();
        outb(STATUS_PORT, 0x20);

        if wait_read() {
            let mut config = inb(DATA_PORT);
            // Enable IRQ1 (bit 0) and Translation (bit 6)
            config |= 0x01 | 0x40;
            // Ensure keyboard (bit 4) is enabled
            config &= !(1 << 4);
            // Disable mouse port + mouse IRQ to avoid AUX data blocking keyboard
            config |= 1 << 5;
            config &= !(1 << 1);

            // Write Controller Configuration Byte
            wait_write();
            outb(STATUS_PORT, 0x60);
            wait_write();
            outb(DATA_PORT, config);

            // Track whether translation is actually enabled
            if (config & 0x40) != 0 {
                SET2_ACTIVE.store(false, Ordering::Relaxed);
            } else {
                SET2_ACTIVE.store(true, Ordering::Relaxed);
            }
        }

        // Enable keyboard port
        wait_write();
        outb(STATUS_PORT, 0xAE);

        // Disable scanning
        wait_write();
        outb(DATA_PORT, 0xF5);
        if wait_read() {
            let _ack = inb(DATA_PORT);
        }

        // Enable scanning (0xF4)
        wait_write();
        outb(DATA_PORT, 0xF4);
        // Wait for ACK (0xFA)
        if wait_read() {
            let _ack = inb(DATA_PORT);
        }

        // Flush any pending data
        let mut timeout = 1000;
        while (inb(STATUS_PORT) & 0x01 != 0) && timeout > 0 {
            inb(DATA_PORT);
            timeout -= 1;
        }
    }
    crate::vga::print_str("[KEYBOARD] PS/2 Controller initialized (Translation enabled)\n");
}

/// Poll the PS/2 controller and return a character (Set 1 scancodes).
pub fn poll() -> Option<char> {
    KEY_BUFFER.pop().map(|byte| byte as char)
}

// DEBUG: Track last raw scancode
static LAST_SCANCODE: AtomicU8 = AtomicU8::new(0);

pub fn get_last_scancode() -> u8 {
    LAST_SCANCODE.load(Ordering::Relaxed)
}

// DEBUG: Get Flags state

// DEBUG: Get Flags state (now lock-free!)
pub fn get_flags() -> (bool, bool, bool, bool) {
    (
        CTRL_PRESSED.load(Ordering::Relaxed),
        ALT_PRESSED.load(Ordering::Relaxed),
        SHIFT_PRESSED.load(Ordering::Relaxed),
        EXTENDED.load(Ordering::Relaxed),
    )
}

/// Poll the PS/2 controller and return a higher-level key event.
pub fn poll_event() -> Option<KeyEvent> {
    let ev = EVENT_BUFFER.pop();
    if ev.is_some() {
        EVENTS_POPPED.fetch_add(1, Ordering::Relaxed);
        return ev;
    }

    // Fallback: poll the controller directly if IRQs are not firing
    // REMOVED: Polling causes race conditions with IRQ handler (double typing)
    // if !is_data_available() {
    //     return None;
    // }
    // let status = unsafe { inb(STATUS_PORT) };
    // let scancode = unsafe { inb(DATA_PORT) };

    // Return None if buffer is empty
    None
}

/// Get event buffer length
pub fn event_buffer_len() -> usize {
    EVENT_BUFFER.len()
}

pub fn get_dropped_packets() -> usize {
    DROPPED_PACKETS.load(Ordering::Relaxed)
}

/// Debug: get event pipeline counters
pub fn get_event_stats() -> (usize, usize, usize, usize) {
    (
        EVENTS_PUSHED.load(Ordering::Relaxed),
        EVENTS_POPPED.load(Ordering::Relaxed),
        EVENTS_NONE.load(Ordering::Relaxed),
        ERROR_STATUS.load(Ordering::Relaxed),
    )
}

/// Handle keyboard IRQ (IRQ1) - Fully lock-free with atomic ring buffers!
pub unsafe fn handle_irq() {
    IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
    // Always read status first
    let status = inb(STATUS_PORT);

    // If Output Buffer Full (bit 0) is set, we MUST read data port
    if (status & 0x01) != 0 {
        let scancode = inb(DATA_PORT);
        SCANCODE_COUNT.fetch_add(1, Ordering::Relaxed);

        // Ignore AUX (mouse) bytes for now
        if (status & 0x20) != 0 {
            ERROR_STATUS.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Ignore controller ACK/RESEND responses
        if scancode == 0xFA || scancode == 0xFE {
            return;
        }

        // Save last scancode for debugging
        LAST_SCANCODE.store(scancode, Ordering::Relaxed);
        // Check for errors AFTER reading (don't skip the read!)
        // If error bits are set, still attempt to process to avoid dropping all input.
        if status & 0xC0 != 0 {
            ERROR_STATUS.fetch_add(1, Ordering::Relaxed);
            let old_count = DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
            if old_count == 0 || old_count % 100 == 0 {
                show_drop_warning();
            }
        }

        // Ignore invalid/phantom scancodes
        if scancode == 0 || scancode == 0xFF {
            return;
        }

        // Process scancode WITHOUT holding any locks (lock-free!)
        let ev = Keyboard::handle_scancode(scancode);

        // Push to buffers - now truly lock-free!
        if let Some(event) = ev {
            EVENTS_PUSHED.fetch_add(1, Ordering::Relaxed);
            // Push to event buffer
            let _pushed = EVENT_BUFFER.push(event);

            // Push character representation
            if let Some(c) = event_to_char(event) {
                let _pushed = KEY_BUFFER.push(c as u8);
            }
        } else {
            EVENTS_NONE.fetch_add(1, Ordering::Relaxed);
        }
    }
    // If no data available (bit 0 clear), just return - controller is fine
}

/// Handle PS/2 mouse/AUX IRQ (IRQ12) by draining a pending byte.
pub unsafe fn handle_aux_irq() {
    let status = inb(STATUS_PORT);
    if (status & 0x01) != 0 {
        let _ = inb(DATA_PORT);
        ERROR_STATUS.fetch_add(1, Ordering::Relaxed);
    }
}

fn event_to_char(ev: KeyEvent) -> Option<char> {
    match ev {
        KeyEvent::Char(c) => Some(c),
        KeyEvent::Enter => Some('\n'),
        KeyEvent::Backspace => Some('\x08'),
        KeyEvent::Tab => Some('\t'),
        _ => None,
    }
}

fn scancode_to_fn(sc: u8) -> Option<u8> {
    match sc {
        0x3B => Some(1),
        0x3C => Some(2),
        0x3D => Some(3),
        0x3E => Some(4),
        0x3F => Some(5),
        0x40 => Some(6),
        _ => None,
    }
}

// Translate PS/2 Set 2 scancodes into Set 1 equivalents (subset used by shell).
fn set2_to_set1(sc: u8) -> Option<u8> {
    match sc {
        0x76 => Some(0x01), // Esc
        0x16 => Some(0x02), // 1
        0x1E => Some(0x03), // 2
        0x26 => Some(0x04), // 3
        0x25 => Some(0x05), // 4
        0x2E => Some(0x06), // 5
        0x36 => Some(0x07), // 6
        0x3D => Some(0x08), // 7
        0x3E => Some(0x09), // 8
        0x46 => Some(0x0A), // 9
        0x45 => Some(0x0B), // 0
        0x4E => Some(0x0C), // -
        0x55 => Some(0x0D), // =
        0x66 => Some(0x0E), // Backspace
        0x0D => Some(0x0F), // Tab
        0x15 => Some(0x10), // Q
        0x1D => Some(0x11), // W
        0x24 => Some(0x12), // E
        0x2D => Some(0x13), // R
        0x2C => Some(0x14), // T
        0x35 => Some(0x15), // Y
        0x3C => Some(0x16), // U
        0x43 => Some(0x17), // I
        0x44 => Some(0x18), // O
        0x4D => Some(0x19), // P
        0x54 => Some(0x1A), // [
        0x5B => Some(0x1B), // ]
        0x5A => Some(0x1C), // Enter (and keypad Enter with E0)
        0x14 => Some(0x1D), // Ctrl (L/R depends on E0)
        0x1C => Some(0x1E), // A
        0x1B => Some(0x1F), // S
        0x23 => Some(0x20), // D
        0x2B => Some(0x21), // F
        0x34 => Some(0x22), // G
        0x33 => Some(0x23), // H
        0x3B => Some(0x24), // J
        0x42 => Some(0x25), // K
        0x4B => Some(0x26), // L
        0x4C => Some(0x27), // ;
        0x52 => Some(0x28), // '
        0x0E => Some(0x29), // `
        0x12 => Some(0x2A), // Left Shift
        0x5D => Some(0x2B), // \
        0x1A => Some(0x2C), // Z
        0x22 => Some(0x2D), // X
        0x21 => Some(0x2E), // C
        0x2A => Some(0x2F), // V
        0x32 => Some(0x30), // B
        0x31 => Some(0x31), // N
        0x3A => Some(0x32), // M
        0x41 => Some(0x33), // ,
        0x49 => Some(0x34), // .
        0x4A => Some(0x35), // /
        0x59 => Some(0x36), // Right Shift
        0x7C => Some(0x37), // Keypad *
        0x11 => Some(0x38), // Alt (L/R depends on E0)
        0x29 => Some(0x39), // Space
        0x58 => Some(0x3A), // Caps Lock
        0x05 => Some(0x3B), // F1
        0x06 => Some(0x3C), // F2
        0x04 => Some(0x3D), // F3
        0x0C => Some(0x3E), // F4
        0x03 => Some(0x3F), // F5
        0x0B => Some(0x40), // F6
        0x83 => Some(0x41), // F7
        0x0A => Some(0x42), // F8
        0x01 => Some(0x43), // F9
        0x09 => Some(0x44), // F10
        0x77 => Some(0x45), // Num Lock
        0x7E => Some(0x46), // Scroll Lock
        0x78 => Some(0x57), // F11
        0x07 => Some(0x58), // F12
        // Extended (E0-prefixed) keys
        0x75 => Some(0x48), // Up
        0x72 => Some(0x50), // Down
        0x6B => Some(0x4B), // Left
        0x74 => Some(0x4D), // Right
        0x6C => Some(0x47), // Home
        0x69 => Some(0x4F), // End
        0x7D => Some(0x49), // Page Up
        0x7A => Some(0x51), // Page Down
        0x70 => Some(0x52), // Insert
        0x71 => Some(0x53), // Delete
        _ => None,
    }
}

// US QWERTY scancode set 1 maps.
const SCANCODE_MAP: [char; 128] = [
    '\0', '\x1B', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', '\t', 'q',
    'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', '\0', 'a', 's', 'd', 'f', 'g',
    'h', 'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.',
    '/', '\0', '*', '\0', ' ', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
];

const SCANCODE_MAP_SHIFT: [char; 128] = [
    '\0', '\x1B', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', '\t', 'Q',
    'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', '\0', 'A', 'S', 'D', 'F', 'G',
    'H', 'J', 'K', 'L', ':', '"', '~', '\0', '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',
    '\0', '*', '\0', ' ', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
];
