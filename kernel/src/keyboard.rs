use spin::Mutex;

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;

static KEYBOARD: Mutex<Keyboard> = Mutex::new(Keyboard::new());

pub struct Keyboard {
    shift_pressed: bool,
    caps_lock: bool,
}

impl Keyboard {
    const fn new() -> Self {
        Self {
            shift_pressed: false,
            caps_lock: false,
        }
    }

    fn handle_scancode(&mut self, scancode: u8) -> Option<char> {
        match scancode {
            // Shift pressed
            0x2A | 0x36 => {
                self.shift_pressed = true;
                None
            }
            // Shift released
            0xAA | 0xB6 => {
                self.shift_pressed = false;
                None
            }
            // Caps Lock
            0x3A => {
                self.caps_lock = !self.caps_lock;
                None
            }

            // Regular key press (ignore releases)
            sc if sc < 0x80 => {
                let base = SCANCODE_MAP[sc as usize];
                if base == '\0' {
                    // Helps us verify keyboard activity even if mapping is incomplete.
                    return Some('?');
                }

                let out = if self.shift_pressed {
                    SCANCODE_MAP_SHIFT[sc as usize]
                } else if self.caps_lock && base.is_ascii_alphabetic() {
                    base.to_ascii_uppercase()
                } else {
                    base
                };

                Some(out)
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

/// Poll the PS/2 controller and return a character (Set 1 scancodes).
pub fn poll() -> Option<char> {
    if !is_data_available() {
        return None;
    }

    let scancode = read_scancode();
    let mut kbd = KEYBOARD.lock();
    kbd.handle_scancode(scancode)
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
