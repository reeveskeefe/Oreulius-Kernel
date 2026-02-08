use spin::Mutex;

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;

static KEYBOARD: Mutex<Keyboard> = Mutex::new(Keyboard::new());

const KEY_BUFFER_SIZE: usize = 128;

struct KeyBuffer {
    buf: [u8; KEY_BUFFER_SIZE],
    head: usize,
    tail: usize,
    len: usize,
}

impl KeyBuffer {
    const fn new() -> Self {
        KeyBuffer {
            buf: [0; KEY_BUFFER_SIZE],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, byte: u8) -> bool {
        if self.len == KEY_BUFFER_SIZE {
            return false;
        }
        self.buf[self.tail] = byte;
        self.tail = (self.tail + 1) % KEY_BUFFER_SIZE;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let byte = self.buf[self.head];
        self.head = (self.head + 1) % KEY_BUFFER_SIZE;
        self.len -= 1;
        Some(byte)
    }
}

static KEY_BUFFER: Mutex<KeyBuffer> = Mutex::new(KeyBuffer::new());

const EVENT_BUFFER_SIZE: usize = 64;

struct EventBuffer {
    buf: [KeyEvent; EVENT_BUFFER_SIZE],
    head: usize,
    tail: usize,
    len: usize,
}

impl EventBuffer {
    const fn new() -> Self {
        EventBuffer {
            buf: [KeyEvent::None; EVENT_BUFFER_SIZE],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, ev: KeyEvent) -> bool {
        if self.len == EVENT_BUFFER_SIZE {
            return false;
        }
        self.buf[self.tail] = ev;
        self.tail = (self.tail + 1) % EVENT_BUFFER_SIZE;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<KeyEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.buf[self.head];
        self.head = (self.head + 1) % EVENT_BUFFER_SIZE;
        self.len -= 1;
        Some(ev)
    }
}

static EVENT_BUFFER: Mutex<EventBuffer> = Mutex::new(EventBuffer::new());

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

pub struct Keyboard {
    shift_pressed: bool,
    caps_lock: bool,
    ctrl_pressed: bool,
    alt_pressed: bool,
    extended: bool,
}

impl Keyboard {
    const fn new() -> Self {
        Self {
            shift_pressed: false,
            caps_lock: false,
            ctrl_pressed: false,
            alt_pressed: false,
            extended: false,
        }
    }

    fn handle_scancode(&mut self, scancode: u8) -> Option<KeyEvent> {
        if scancode == 0xE0 {
            self.extended = true;
            return None;
        }

        let is_release = scancode & 0x80 != 0;
        let code = scancode & 0x7F;

        if is_release {
            if self.extended {
                self.extended = false;
                // Handle release of extended keys if needed
                match code {
                    0x1D => self.ctrl_pressed = false, // Right Ctrl
                    0x38 => self.alt_pressed = false,  // Right Alt
                    _ => {}
                }
                return None;
            }

            match code {
                0x2A | 0x36 => self.shift_pressed = false,
                0x1D => self.ctrl_pressed = false,
                0x38 => self.alt_pressed = false,
                _ => {}
            }
            return None;
        }

        // Handle extended keys (pressed)
        if self.extended {
            self.extended = false;
            match code {
                0x48 => return Some(KeyEvent::Up),
                0x50 => return Some(KeyEvent::Down),
                0x4B => return Some(KeyEvent::Left),
                0x4D => return Some(KeyEvent::Right),
                0x47 => return Some(KeyEvent::Home),
                0x4F => return Some(KeyEvent::End),
                0x1D => { self.ctrl_pressed = true; return None; } // Right Ctrl
                0x38 => { self.alt_pressed = true; return None; } // Right Alt
                // TODO: Delete, PageUp, PageDown
                _ => return None,
            }
        }

        match scancode {
            // Shift pressed
            0x2A | 0x36 => {
                self.shift_pressed = true;
                return None;
            }
            // Shift released
            0xAA | 0xB6 => {
                self.shift_pressed = false;
                return None;
            }
            // Caps Lock
            0x3A => {
                self.caps_lock = !self.caps_lock;
                return None;
            }
            // Ctrl pressed
            0x1D => {
                self.ctrl_pressed = true;
                return None;
            }
            // Alt pressed
            0x38 => {
                self.alt_pressed = true;
                return None;
            }

            // Regular key press (ignore releases)
            sc if sc < 0x80 => {
                if self.alt_pressed {
                    if let Some(fn_key) = scancode_to_fn(sc) {
                        return Some(KeyEvent::AltFn(fn_key));
                    }
                }
                let base = SCANCODE_MAP[sc as usize];
                if base == '\0' {
                    // Helps us verify keyboard activity even if mapping is incomplete.
                    return Some(KeyEvent::Char('?'));
                }

                let mut out = if self.shift_pressed {
                    SCANCODE_MAP_SHIFT[sc as usize]
                } else if self.caps_lock && base.is_ascii_alphabetic() {
                    // Caps Lock logic: Invert case if Shift is pressed
                    if self.shift_pressed {
                        base.to_ascii_lowercase()
                    } else {
                        base.to_ascii_uppercase()
                    }
                } else {
                    base
                };
                if self.ctrl_pressed && out.is_ascii_alphabetic() {
                    out = out.to_ascii_lowercase();
                    return Some(KeyEvent::Ctrl(out));
                }
                if self.alt_pressed {
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

#[inline]
fn is_data_available() -> bool {
    unsafe { inb(STATUS_PORT) & 0x01 != 0 }
}

#[inline]
fn read_scancode() -> u8 {
    unsafe { inb(DATA_PORT) }
}

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
        if timeout == 0 { break; }
    }
}

#[inline]
fn wait_read() -> bool {
    let mut timeout = 100000;
    while unsafe { inb(STATUS_PORT) } & 0x01 == 0 {
        core::hint::spin_loop();
        timeout -= 1;
        if timeout == 0 { return false; }
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
            
            // Write Controller Configuration Byte
            wait_write();
            outb(STATUS_PORT, 0x60);
            wait_write();
            outb(DATA_PORT, config);
        }

        // Enable keyboard port
        wait_write();
        outb(STATUS_PORT, 0xAE);
    }
    crate::vga::print_str("[KEYBOARD] PS/2 Controller initialized (Translation enabled)\n");
}

/// Poll the PS/2 controller and return a character (Set 1 scancodes).
pub fn poll() -> Option<char> {
    // Only read from buffer, populated by ISR
    if let Some(byte) = KEY_BUFFER.lock().pop() {
        return Some(byte as char);
    }
    None
}

/// Poll the PS/2 controller and return a higher-level key event.
pub fn poll_event() -> Option<KeyEvent> {
    // Only read from buffer, populated by ISR
    if let Some(ev) = EVENT_BUFFER.lock().pop() {
        return Some(ev);
    }
    None
}

/// Handle keyboard IRQ (IRQ1)
pub fn handle_irq() {
    let status = unsafe { inb(STATUS_PORT) };

    // Check if data is actually available (Bit 0)
    if status & 0x01 == 0 {
        return; // Spurious interrupt
    }

    // Check for errors (Parity or Timeout)
    if status & 0xC0 != 0 {
        // Error detected, read data to discard it
        let _ = unsafe { inb(DATA_PORT) };
        return;
    }

    // 3. Valid Read
    let scancode = unsafe { inb(DATA_PORT) };
    
    // DEBUG: Uncomment to see raw scancodes
    /*
    unsafe {
        let vga_buffer = 0xB8000 as *mut u16;
        let hex = "0123456789ABCDEF";
        let h1 = hex.chars().nth((scancode >> 4) as usize).unwrap() as u16;
        let h2 = hex.chars().nth((scancode & 0x0F) as usize).unwrap() as u16;
        // Print at bottom right corner
        *vga_buffer.add(80*24 + 70) = (0x0F00 | h1);
        *vga_buffer.add(80*24 + 71) = (0x0F00 | h2);
    }
    */
    
    // Ignore invalid/phantom scancodes
    if scancode == 0 || scancode == 0xFF {
        return;
    }

    let ev = {
        let mut kbd = KEYBOARD.lock();
        kbd.handle_scancode(scancode)
    };

    if let Some(event) = ev {
        let _ = EVENT_BUFFER.lock().push(event);
        if let Some(c) = event_to_char(event) {
            let _ = KEY_BUFFER.lock().push(c as u8);
        }
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

// US QWERTY scancode set 1 maps.
const SCANCODE_MAP: [char; 128] = [
    '\0', '\x1B', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', '\0', 'a', 's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
    'b', 'n', 'm', ',', '.', '/', '\0', '*', '\0', ' ', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '7', '8', '9', '-', '4', '5', '6', '+', '1',
    '2', '3', '0', '.', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
];

const SCANCODE_MAP_SHIFT: [char; 128] = [
    '\0', '\x1B', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\x08', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', '\0', 'A', 'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', '\0', '|', 'Z', 'X', 'C', 'V',
    'B', 'N', 'M', '<', '>', '?', '\0', '*', '\0', ' ', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '7', '8', '9', '-', '4', '5', '6', '+', '1',
    '2', '3', '0', '.', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
    '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
];
