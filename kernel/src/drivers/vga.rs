/*!
 * Oreulius Kernel Project
 *
 * License-Identifier: Oreulius Community License v1.0 (see LICENSE)
 * Commercial use requires a separate written agreement (see COMMERCIAL.md)
 *
 * Copyright (c) 2026 Keefe Reeves and Oreulius Contributors
 *
 * Contributing:
 * - By contributing to this file, you agree that accepted contributions may
 *   be distributed and relicensed as part of Oreulius.
 * - Please see docs/CONTRIBUTING.md for contribution terms and review
 *   guidelines.
 *
 * ---------------------------------------------------------------------------
 */

//! Name here
//!
//! fill out line by line features of the file here, and any important notes about the implementation
//!...

use crate::asm_bindings::{inb, outb};
use core::fmt;
use lazy_static::lazy_static;
use spin::Mutex;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ColorCode(u8);

impl ColorCode {
    const fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;
pub const SCREEN_HEIGHT: usize = BUFFER_HEIGHT;
pub const SCREEN_WIDTH: usize = BUFFER_WIDTH;

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

pub struct Writer {
    column_position: usize,
    row_position: usize,
    color_code: ColorCode,
    buffer: &'static mut Buffer,
}

impl Writer {
    pub fn new() -> Self {
        Writer {
            column_position: 0,
            row_position: 0,
            color_code: ColorCode::new(Color::White, Color::Black),
            buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
        }
    }

    pub fn set_color(&mut self, foreground: Color, background: Color) {
        self.color_code = ColorCode::new(foreground, background);
    }

    pub fn clear_screen(&mut self) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: ColorCode::new(Color::White, Color::Black),
        };
        for row in 0..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                self.buffer.chars[row][col] = blank;
            }
        }
        self.column_position = 0;
        self.row_position = 0;
    }

    pub fn write_at(&mut self, row: usize, col: usize, s: &str, fg: Color, bg: Color) {
        let color = ColorCode::new(fg, bg);
        for (i, byte) in s.bytes().enumerate() {
            if col + i >= BUFFER_WIDTH {
                break;
            }
            let ascii = match byte {
                0x20..=0x7e => byte,
                _ => 0xfe,
            };
            self.buffer.chars[row][col + i] = ScreenChar {
                ascii_character: ascii,
                color_code: color,
            };
        }
    }

    pub fn write_centered(&mut self, row: usize, s: &str, fg: Color, bg: Color) {
        let len = s.len();
        let col = if len < BUFFER_WIDTH {
            (BUFFER_WIDTH - len) / 2
        } else {
            0
        };
        self.write_at(row, col, s, fg, bg);
    }

    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }

                let row = self.row_position;
                let col = self.column_position;

                let color_code = self.color_code;
                self.buffer.chars[row][col] = ScreenChar {
                    ascii_character: byte,
                    color_code,
                };
                self.column_position += 1;
            }
        }
    }

    fn new_line(&mut self) {
        self.column_position = 0;
        if self.row_position < BUFFER_HEIGHT - 1 {
            self.row_position += 1;
        } else {
            for row in 1..BUFFER_HEIGHT {
                for col in 0..BUFFER_WIDTH {
                    let character = self.buffer.chars[row][col];
                    self.buffer.chars[row - 1][col] = character;
                }
            }
            self.clear_row(BUFFER_HEIGHT - 1);
        }
    }

    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            self.buffer.chars[row][col] = blank;
        }
    }

    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                _ => self.write_byte(0xfe),
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer::new());
}

// CRT Controller Ports
const CRTC_ADDR_PORT: u16 = 0x3D4;
const CRTC_DATA_PORT: u16 = 0x3D5;

#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => ($crate::vga::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! vga_println {
    () => ($crate::vga_print!("\n"));
    ($($arg:tt)*) => ($crate::vga_print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    // Write to serial for debugging
    if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
        let _ = serial.write_fmt(args);
    }

    struct TerminalAdapter;
    impl fmt::Write for TerminalAdapter {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            crate::terminal::write_str(s);
            Ok(())
        }
    }
    let mut terminal_writer = TerminalAdapter;
    let _ = terminal_writer.write_fmt(args);
}

pub fn print_str(s: &str) {
    crate::terminal::write_str(s);
}

pub fn print_char(c: char) {
    crate::terminal::write_char(c);
}

pub fn clear_screen() {
    crate::terminal::clear_screen();
}

pub fn backspace() {
    crate::terminal::backspace();
}

pub fn write_cell(row: usize, col: usize, byte: u8, fg: Color, bg: Color) {
    if row >= BUFFER_HEIGHT || col >= BUFFER_WIDTH {
        return;
    }
    let mut writer = WRITER.lock();
    writer.buffer.chars[row][col] = ScreenChar {
        ascii_character: byte,
        color_code: ColorCode::new(fg, bg),
    };
}

pub fn clear_screen_with(fg: Color, bg: Color) {
    let blank = ScreenChar {
        ascii_character: b' ',
        color_code: ColorCode::new(fg, bg),
    };
    let mut writer = WRITER.lock();

    // Enhanced buffer validation and integrity checking
    let buffer_addr = writer.buffer as *const _ as usize;

    // Verify VGA buffer is at expected address (0xB8000 for text mode)
    if buffer_addr != 0xB8000 {
        // Buffer might be remapped, but log for diagnostics
        crate::serial_println!("[VGA] Buffer at non-standard address: 0x{:X}", buffer_addr);
    }

    // Validate color codes are in valid range (0-15)
    if fg as u8 > 15 || bg as u8 > 15 {
        crate::serial_println!(
            "[VGA] WARNING: Invalid color codes - fg:{:?} bg:{:?}",
            fg,
            bg
        );
    }

    // Efficiently fill entire screen buffer with colored blank character
    // This provides explicit color control vs just setting default colors
    for row in 0..BUFFER_HEIGHT {
        for col in 0..BUFFER_WIDTH {
            writer.buffer.chars[row][col] = blank;
        }
    }

    // Memory fence to ensure all writes complete before proceeding
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);

    // Update writer's default color for future writes
    writer.set_color(fg, bg);
    // Reset cursor to origin
    writer.column_position = 0;
}

/// Initialize the VGA driver and enable the hardware cursor
pub fn init() {
    // Enable cursor (scanlines 14-15)
    enable_cursor(14, 15);
    // Reset cursor position to 0,0 locally and on hardware
    crate::terminal::clear_screen();
    update_cursor(0, 0);
}

pub fn update_cursor(row: usize, col: usize) {
    let pos = row * BUFFER_WIDTH + col;

    unsafe {
        outb(CRTC_ADDR_PORT, 0x0F);
        outb(CRTC_DATA_PORT, (pos & 0xFF) as u8);
        outb(CRTC_ADDR_PORT, 0x0E);
        outb(CRTC_DATA_PORT, ((pos >> 8) & 0xFF) as u8);
    }
}

pub fn enable_cursor(start: u8, end: u8) {
    unsafe {
        outb(CRTC_ADDR_PORT, 0x0A);
        let cursor_start = inb(CRTC_DATA_PORT) & 0xC0;
        outb(CRTC_DATA_PORT, cursor_start | start);

        outb(CRTC_ADDR_PORT, 0x0B);
        let cursor_end = inb(CRTC_DATA_PORT) & 0xE0;
        outb(CRTC_DATA_PORT, cursor_end | end);
    }
}
