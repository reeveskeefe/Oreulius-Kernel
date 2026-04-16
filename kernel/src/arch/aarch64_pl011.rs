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

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(crate) const QEMU_VIRT_PL011_BASE: usize = 0x0900_0000;

const DR: usize = 0x00;
const FR: usize = 0x18;
const CR: usize = 0x30;
const IMSC: usize = 0x38;
const RIS: usize = 0x3C;
const MIS: usize = 0x40;
const ICR: usize = 0x44;

const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const INT_RX: u32 = 1 << 4;
const INT_RT: u32 = 1 << 6;
const RX_BUF_CAPACITY: usize = 2048;

struct RxRingBuffer {
    buf: UnsafeCell<[u8; RX_BUF_CAPACITY]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicU64,
}

unsafe impl Sync for RxRingBuffer {}

impl RxRingBuffer {
    const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0; RX_BUF_CAPACITY]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    #[inline]
    fn push_irq(&self, byte: u8) {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let next = (head + 1) % RX_BUF_CAPACITY;
        if next == tail {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        unsafe {
            (*self.buf.get())[head] = byte;
        }
        self.head.store(next, Ordering::Release);
    }

    #[inline]
    fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        let byte = unsafe { (*self.buf.get())[tail] };
        let next = (tail + 1) % RX_BUF_CAPACITY;
        self.tail.store(next, Ordering::Release);
        Some(byte)
    }

    #[inline]
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            head - tail
        } else {
            RX_BUF_CAPACITY - tail + head
        }
    }

    #[inline]
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub(crate) struct Pl011 {
    base: AtomicUsize,
}

impl Pl011 {
    pub const fn new(base: usize) -> Self {
        Self {
            base: AtomicUsize::new(base),
        }
    }

    #[inline]
    fn reg(&self, off: usize) -> *mut u32 {
        (self.base.load(Ordering::Relaxed) + off) as *mut u32
    }

    #[inline]
    fn read(&self, off: usize) -> u32 {
        unsafe { read_volatile(self.reg(off)) }
    }

    #[inline]
    fn write(&self, off: usize, val: u32) {
        unsafe { write_volatile(self.reg(off), val) }
    }

    pub fn init_early(&self) {
        // Minimal bring-up: assume firmware/loader configured clocks/baud.
        // We only ensure the UART is enabled and interrupts are masked.
        self.write(CR, 0);
        self.write(ICR, 0x07FF);
        self.write(IMSC, 0);
        self.write(CR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    pub fn write_byte(&self, b: u8) {
        while (self.read(FR) & FR_TXFF) != 0 {
            core::hint::spin_loop();
        }
        self.write(DR, b as u32);
    }

    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    pub fn try_read_byte(&self) -> Option<u8> {
        if (self.read(FR) & FR_RXFE) != 0 {
            return None;
        }
        Some((self.read(DR) & 0xFF) as u8)
    }

    pub fn try_read_buffered_byte(&self) -> Option<u8> {
        RX_RING.pop()
    }

    pub fn irq_drain_rx_to_buffer(&self) -> usize {
        let mut drained = 0usize;
        while let Some(b) = self.try_read_byte() {
            RX_RING.push_irq(b);
            drained += 1;
        }
        drained
    }

    #[inline]
    pub fn enable_rx_interrupts(&self) {
        self.write(ICR, 0x07FF);
        self.write(IMSC, INT_RX | INT_RT);
    }

    #[inline]
    pub fn disable_interrupts(&self) {
        self.write(IMSC, 0);
        self.write(ICR, 0x07FF);
    }

    #[inline]
    pub fn ack_interrupts(&self) {
        self.write(ICR, 0x07FF);
    }

    #[inline]
    pub fn masked_interrupt_status(&self) -> u32 {
        self.read(MIS)
    }

    #[inline]
    pub fn raw_interrupt_status(&self) -> u32 {
        self.read(RIS)
    }

    #[inline]
    pub fn interrupt_mask(&self) -> u32 {
        self.read(IMSC)
    }

    #[inline]
    pub fn flags(&self) -> u32 {
        self.read(FR)
    }

    #[inline]
    pub fn rx_buffer_len(&self) -> usize {
        RX_RING.len()
    }

    #[inline]
    pub fn rx_buffer_dropped(&self) -> u64 {
        RX_RING.dropped()
    }

    #[inline]
    pub fn base(&self) -> usize {
        self.base.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn set_base(&self, base: usize) {
        if base != 0 {
            self.base.store(base, Ordering::Relaxed);
        }
    }
}

static EARLY_UART: Pl011 = Pl011::new(QEMU_VIRT_PL011_BASE);
static RX_RING: RxRingBuffer = RxRingBuffer::new();

#[inline]
pub(crate) fn early_uart() -> &'static Pl011 {
    &EARLY_UART
}

/// Returns `true` if at least one byte is waiting in the PL011 RX ring buffer.
#[inline]
pub(crate) fn has_input() -> bool {
    EARLY_UART.rx_buffer_len() > 0
}

/// Pop one byte from the PL011 RX ring buffer, or `None` if the buffer is empty.
#[inline]
pub(crate) fn read_byte() -> Option<u8> {
    EARLY_UART.try_read_buffered_byte()
}
