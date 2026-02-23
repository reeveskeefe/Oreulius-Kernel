/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 */

#![allow(dead_code)]

use core::fmt;
use core::sync::atomic::{fence, Ordering};

#[cfg(not(target_arch = "aarch64"))]
pub const MAX_TEMPORAL_VERSION_BYTES: usize = crate::temporal::MAX_TEMPORAL_VERSION_BYTES;
#[cfg(target_arch = "aarch64")]
pub const MAX_TEMPORAL_VERSION_BYTES: usize = 256 * 1024;

#[cfg(not(target_arch = "aarch64"))]
pub const TEMPORAL_OBJECT_ENCODING_V1: u8 = crate::temporal::TEMPORAL_OBJECT_ENCODING_V1;
#[cfg(target_arch = "aarch64")]
pub const TEMPORAL_OBJECT_ENCODING_V1: u8 = 1;

#[cfg(not(target_arch = "aarch64"))]
pub const TEMPORAL_SCHEDULER_OBJECT: u8 = crate::temporal::TEMPORAL_SCHEDULER_OBJECT;
#[cfg(target_arch = "aarch64")]
pub const TEMPORAL_SCHEDULER_OBJECT: u8 = 13;

#[cfg(not(target_arch = "aarch64"))]
pub const TEMPORAL_SCHEDULER_EVENT_STATE: u8 = crate::temporal::TEMPORAL_SCHEDULER_EVENT_STATE;
#[cfg(target_arch = "aarch64")]
pub const TEMPORAL_SCHEDULER_EVENT_STATE: u8 = 1;

#[inline]
pub fn vga_print_str(msg: &str) {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::vga::print_str(msg);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.init_early();
        uart.write_str(msg);
    }
}

pub fn logf(args: fmt::Arguments<'_>) {
    #[cfg(not(target_arch = "aarch64"))]
    {
        use core::fmt::Write;
        if let Some(mut serial) = crate::serial::SERIAL1.try_lock() {
            let _ = serial.write_fmt(args);
            let _ = serial.write_str("\n");
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        struct UartWriter;
        impl fmt::Write for UartWriter {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let uart = crate::arch::aarch64_pl011::early_uart();
                uart.init_early();
                uart.write_str(s);
                Ok(())
            }
        }
        let mut w = UartWriter;
        let _ = fmt::write(&mut w, args);
        let _ = fmt::Write::write_str(&mut w, "\n");
    }
}

#[inline]
pub fn memory_barrier() {
    fence(Ordering::SeqCst);
}

#[inline]
pub fn halt_cpu() -> ! {
    #[cfg(not(target_arch = "aarch64"))]
    unsafe {
        loop {
            core::arch::asm!("hlt");
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        loop {
            core::arch::asm!("wfe");
        }
    }
}

#[inline]
pub fn temporal_is_replay_active() -> bool {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::temporal::is_replay_active()
    }

    #[cfg(target_arch = "aarch64")]
    {
        false
    }
}

#[inline]
pub fn temporal_record_scheduler_state_event(payload: &[u8]) -> Result<(), &'static str> {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::temporal::record_scheduler_state_event(payload)
            .map(|_| ())
            .map_err(|_| "temporal scheduler record failed")
    }

    #[cfg(target_arch = "aarch64")]
    {
        let _ = payload;
        Ok(())
    }
}
