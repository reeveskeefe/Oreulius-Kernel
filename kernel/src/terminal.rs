use crate::vga::{self, Color};
use alloc::vec::Vec;
use lazy_static::lazy_static;
use spin::Mutex;
// use x86_64::instructions::interrupts; // Removed unavailable crate

const TERM_COUNT: usize = 6;

// Helper to execute closure with interrupts disabled
fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let flags: usize;
    unsafe {
        // Save EFLAGS
        core::arch::asm!("pushfd; pop {}", out(reg) flags, options(nomem, preserves_flags));
        // Disable interrupts
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }

    let ret = f();

    unsafe {
        // Restore interrupts if they were enabled (IF bit 9 is set)
        if (flags & 0x200) != 0 {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
    ret
}
const SCROLLBACK_MAX: usize = 1000;
const WIDTH: usize = vga::SCREEN_WIDTH;
const HEIGHT: usize = vga::SCREEN_HEIGHT;

const DEFAULT_FG: Color = Color::White;
const DEFAULT_BG: Color = Color::Black;

#[derive(Clone, Copy)]
struct Cell {
    ch: u8,
    fg: Color,
    bg: Color,
}

impl Cell {
    const fn blank(fg: Color, bg: Color) -> Self {
        Cell { ch: b' ', fg, bg }
    }
}

#[derive(Clone, Copy)]
enum EscState {
    None,
    Esc,
    Csi {
        params: [u16; 6],
        len: usize,
        current: u16,
        has_current: bool,
    },
}

impl EscState {
    fn new_csi() -> Self {
        EscState::Csi {
            params: [0; 6],
            len: 0,
            current: 0,
            has_current: false,
        }
    }
}

struct Terminal {
    buffer: [[Cell; WIDTH]; HEIGHT],
    scrollback: Vec<[Cell; WIDTH]>,
    cursor_row: usize,
    cursor_col: usize,
    saved_row: usize,
    saved_col: usize,
    fg: Color,
    bg: Color,
    esc: EscState,
}

impl Terminal {
    fn new() -> Self {
        Terminal {
            buffer: [[Cell::blank(DEFAULT_FG, DEFAULT_BG); WIDTH]; HEIGHT],
            scrollback: Vec::new(),
            cursor_row: 0,
            cursor_col: 0,
            saved_row: 0,
            saved_col: 0,
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            esc: EscState::None,
        }
    }

    fn render_full(&self) {
        for row in 0..HEIGHT {
            for col in 0..WIDTH {
                let cell = self.buffer[row][col];
                vga::write_cell(row, col, cell.ch, cell.fg, cell.bg);
            }
        }
    }

    fn clear_screen(&mut self, render: bool) {
        for row in 0..HEIGHT {
            for col in 0..WIDTH {
                self.buffer[row][col] = Cell::blank(self.fg, self.bg);
                if render {
                    vga::write_cell(row, col, b' ', self.fg, self.bg);
                }
            }
        }
        self.cursor_row = 0;
        self.cursor_col = 0;
        if render {
             vga::update_cursor(0, 0);
        }
    }

    fn clear_line_range(&mut self, row: usize, start: usize, end: usize, render: bool) {
        if row >= HEIGHT {
            return;
        }
        let mut col = start;
        while col < end && col < WIDTH {
            self.buffer[row][col] = Cell::blank(self.fg, self.bg);
            if render {
                vga::write_cell(row, col, b' ', self.fg, self.bg);
            }
            col += 1;
        }
    }

    fn clear_to_end(&mut self, render: bool) {
        self.clear_line_range(self.cursor_row, self.cursor_col, WIDTH, render);
        for row in (self.cursor_row + 1)..HEIGHT {
            self.clear_line_range(row, 0, WIDTH, render);
        }
    }

    fn clear_to_start(&mut self, render: bool) {
        self.clear_line_range(self.cursor_row, 0, self.cursor_col + 1, render);
        for row in 0..self.cursor_row {
            self.clear_line_range(row, 0, WIDTH, render);
        }
    }

    fn clear_line(&mut self, mode: u16, render: bool) {
        match mode {
            0 => self.clear_line_range(self.cursor_row, self.cursor_col, WIDTH, render),
            1 => self.clear_line_range(self.cursor_row, 0, self.cursor_col + 1, render),
            2 => self.clear_line_range(self.cursor_row, 0, WIDTH, render),
            _ => {}
        }
    }

    fn set_cursor(&mut self, row: usize, col: usize) {
        self.cursor_row = row.min(HEIGHT - 1);
        self.cursor_col = col.min(WIDTH - 1);
        vga::update_cursor(self.cursor_row, self.cursor_col);
    }


    fn cursor(&self) -> (usize, usize) {
        (self.cursor_row, self.cursor_col)
    }

    fn backspace(&mut self, render: bool) {
        if self.cursor_col == 0 {
            return;
        }
        self.cursor_col -= 1;
        self.buffer[self.cursor_row][self.cursor_col] = Cell::blank(self.fg, self.bg);
        if render {
            vga::write_cell(self.cursor_row, self.cursor_col, b' ', self.fg, self.bg);
            vga::update_cursor(self.cursor_row, self.cursor_col);
        }
    }

    fn new_line(&mut self, render: bool) {
        self.cursor_col = 0;
        if self.cursor_row < HEIGHT - 1 {
            self.cursor_row += 1;
        } else {
            self.scroll_up(render);
        }
        if render {
            vga::update_cursor(self.cursor_row, self.cursor_col);
        }
    }

    fn push_scrollback(&mut self) {
        if self.scrollback.len() >= SCROLLBACK_MAX {
            self.scrollback.remove(0);
        }
        self.scrollback.push(self.buffer[0]);
    }

    fn put_char(&mut self, ch: u8, render: bool) {
        if self.cursor_col >= WIDTH {
            self.new_line(render);
        }

        self.buffer[self.cursor_row][self.cursor_col] = Cell {
            ch,
            fg: self.fg,
            bg: self.bg,
        };

        if render {
            vga::write_cell(self.cursor_row, self.cursor_col, ch, self.fg, self.bg);
        }

        self.cursor_col += 1;
        if render {
            vga::update_cursor(self.cursor_row, self.cursor_col);
        }
    }

    fn write_byte(&mut self, byte: u8, render: bool) {
        match self.esc {
            EscState::None => {
                match byte {
                    b'\n' => self.new_line(render),
                    b'\r' => self.cursor_col = 0,
                    0x08 => self.backspace(render),
                    0x1B => self.esc = EscState::Esc,
                    0x20..=0x7e => self.put_char(byte, render),
                    _ => {}
                }
            }
            EscState::Esc => {
                match byte {
                    b'[' => self.esc = EscState::new_csi(),
                    b'7' => {
                        self.saved_row = self.cursor_row;
                        self.saved_col = self.cursor_col;
                        self.esc = EscState::None;
                    }
                    b'8' => {
                        self.cursor_row = self.saved_row;
                        self.cursor_col = self.saved_col;
                        self.esc = EscState::None;
                    }
                    _ => {
                        self.esc = EscState::None;
                    }
                }
            }
            EscState::Csi {
                ref mut params,
                ref mut len,
                ref mut current,
                ref mut has_current,
            } => {
                match byte {
                    b'0'..=b'9' => {
                        *current = current.saturating_mul(10).saturating_add((byte - b'0') as u16);
                        *has_current = true;
                    }
                    b';' => {
                        if *len < params.len() {
                            params[*len] = if *has_current { *current } else { 0 };
                            *len += 1;
                        }
                        *current = 0;
                        *has_current = false;
                    }
                    b'A' | b'B' | b'C' | b'D' | b'H' | b'f' | b'J' | b'K' | b'm' | b's'
                    | b'u' => {
                        if *len < params.len() {
                            if *has_current || *len > 0 {
                                params[*len] = if *has_current { *current } else { 0 };
                                *len += 1;
                            }
                        }
                        let count = *len;
                        let params_copy = *params;
                        self.esc = EscState::None;
                        self.handle_csi(byte, &params_copy, count, render);
                    }
                    _ => {
                        self.esc = EscState::None;
                    }
                }
            }
        }
    }

    fn handle_csi(&mut self, cmd: u8, params: &[u16; 6], count: usize, render: bool) {
        let get = |idx: usize, default: u16| -> u16 {
            if idx < count {
                params[idx]
            } else {
                default
            }
        };
        match cmd {
            b'A' => {
                let n = get(0, 1) as usize;
                self.cursor_row = self.cursor_row.saturating_sub(n);
            }
            b'B' => {
                let n = get(0, 1) as usize;
                self.cursor_row = (self.cursor_row + n).min(HEIGHT - 1);
            }
            b'C' => {
                let n = get(0, 1) as usize;
                self.cursor_col = (self.cursor_col + n).min(WIDTH - 1);
            }
            b'D' => {
                let n = get(0, 1) as usize;
                self.cursor_col = self.cursor_col.saturating_sub(n);
            }
            b'H' | b'f' => {
                let row = get(0, 1).saturating_sub(1) as usize;
                let col = get(1, 1).saturating_sub(1) as usize;
                self.set_cursor(row, col);
            }
            b'J' => {
                let mode = get(0, 0);
                match mode {
                    0 => self.clear_to_end(render),
                    1 => self.clear_to_start(render),
                    2 => self.clear_screen(render),
                    _ => {}
                }
            }
            b'K' => {
                let mode = get(0, 0);
                self.clear_line(mode, render);
            }
            b's' => {
                self.saved_row = self.cursor_row;
                self.saved_col = self.cursor_col;
            }
            b'u' => {
                self.cursor_row = self.saved_row;
                self.cursor_col = self.saved_col;
            }
            b'm' => {
                self.apply_sgr(params, count);
            }
            _ => {}
        }
    }

    fn apply_sgr(&mut self, params: &[u16; 6], count: usize) {
        if count == 0 {
            self.fg = DEFAULT_FG;
            self.bg = DEFAULT_BG;
            return;
        }
        for idx in 0..count.min(6) {
            let val = params[idx];
            match val {
                0 => {
                    self.fg = DEFAULT_FG;
                    self.bg = DEFAULT_BG;
                }
                39 => self.fg = DEFAULT_FG,
                49 => self.bg = DEFAULT_BG,
                _ => {
                    if let Some(color) = sgr_to_color(val) {
                        self.fg = color;
                    } else if let Some(color) = sgr_to_bg(val) {
                        self.bg = color;
                    }
                }
            }
        }
    }

    fn scroll_up(&mut self, render: bool) {
        // Move lines up in buffer
        for row in 1..HEIGHT {
            for col in 0..WIDTH {
                self.buffer[row - 1][col] = self.buffer[row][col];
            }
        }
        
        // Clear last line
        for col in 0..WIDTH {
            self.buffer[HEIGHT - 1][col] = Cell::blank(self.fg, self.bg);
        }

        if render {
            // Repaint screen
            self.render_full();
        }
    }
}

fn sgr_to_color(code: u16) -> Option<Color> {
    match code {
        30 => Some(Color::Black),
        31 => Some(Color::Red),
        32 => Some(Color::Green),
        33 => Some(Color::Yellow),
        34 => Some(Color::Blue),
        35 => Some(Color::Magenta),
        36 => Some(Color::Cyan),
        37 => Some(Color::LightGray),
        90 => Some(Color::DarkGray),
        91 => Some(Color::LightRed),
        92 => Some(Color::LightGreen),
        93 => Some(Color::Yellow),
        94 => Some(Color::LightBlue),
        95 => Some(Color::Pink),
        96 => Some(Color::LightCyan),
        97 => Some(Color::White),
        _ => None,
    }
}

fn sgr_to_bg(code: u16) -> Option<Color> {
    match code {
        40 => Some(Color::Black),
        41 => Some(Color::Red),
        42 => Some(Color::Green),
        43 => Some(Color::Brown),
        44 => Some(Color::Blue),
        45 => Some(Color::Magenta),
        46 => Some(Color::Cyan),
        47 => Some(Color::LightGray),
        100 => Some(Color::DarkGray),
        101 => Some(Color::LightRed),
        102 => Some(Color::LightGreen),
        103 => Some(Color::Yellow),
        104 => Some(Color::LightBlue),
        105 => Some(Color::Pink),
        106 => Some(Color::LightCyan),
        107 => Some(Color::White),
        _ => None,
    }
}

struct TerminalManager {
    terminals: [Terminal; TERM_COUNT],
    active: usize,
}

impl TerminalManager {
    fn new() -> Self {
        TerminalManager {
            terminals: [
                Terminal::new(),
                Terminal::new(),
                Terminal::new(),
                Terminal::new(),
                Terminal::new(),
                Terminal::new(),
            ],
            active: 0,
        }
    }

    fn active_mut(&mut self) -> &mut Terminal {
        &mut self.terminals[self.active]
    }

    fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.active_mut().write_byte(byte, true);
        }
    }

    fn write_char(&mut self, c: char) {
        self.active_mut().write_byte(c as u8, true);
    }

    fn clear_screen(&mut self) {
        self.active_mut().clear_screen(true);
    }

    fn backspace(&mut self) {
        self.active_mut().backspace(true);
    }

    fn set_cursor(&mut self, row: usize, col: usize) {
        self.active_mut().set_cursor(row, col);
    }

    fn cursor(&self) -> (usize, usize) {
        self.terminals[self.active].cursor()
    }

    fn clear_line_from_cursor(&mut self) {
        let (row, col) = self.terminals[self.active].cursor();
        self.terminals[self.active].clear_line_range(row, col, WIDTH, true);
    }

    fn switch_to(&mut self, idx: usize) {
        if idx >= TERM_COUNT {
            return;
        }
        self.active = idx;
        self.terminals[self.active].render_full();
    }
}

lazy_static! {
    static ref TERMINAL: Mutex<TerminalManager> = Mutex::new(TerminalManager::new());
}

pub fn write_str(s: &str) {
    // Echo to serial for automated testing
    if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
        use core::fmt::Write;
        let _ = serial.write_str(s);
    }
    without_interrupts(|| {
        TERMINAL.lock().write_str(s);
    });
}

pub fn write_str_no_serial(s: &str) {
    without_interrupts(|| {
        TERMINAL.lock().write_str(s);
    });
}

pub fn write_char(c: char) {
    // Echo to serial for automated testing
    if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
        use core::fmt::Write;
        let _ = serial.write_char(c);
    }
    without_interrupts(|| {
        TERMINAL.lock().write_char(c);
    });
}

pub fn clear_screen() {
    without_interrupts(|| {
        TERMINAL.lock().clear_screen();
    });
}

pub fn backspace() {
    without_interrupts(|| {
        TERMINAL.lock().backspace();
    });
}

pub fn set_cursor(row: usize, col: usize) {
    without_interrupts(|| {
        TERMINAL.lock().set_cursor(row, col);
    });
}

pub fn cursor_position() -> (usize, usize) {
    without_interrupts(|| {
        TERMINAL.lock().cursor()
    })
}

pub fn clear_line_from_cursor() {
    without_interrupts(|| {
        TERMINAL.lock().clear_line_from_cursor();
    });
}

pub fn switch_terminal(index: usize) {
    without_interrupts(|| {
        TERMINAL.lock().switch_to(index);
    });
}
