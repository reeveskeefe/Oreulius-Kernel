/*!
 * Oreulia Kernel Project
 *
 * SPDX-License-Identifier: MIT
 *
 * Thin AArch64 shell adapter that forwards into the shared command dispatcher
 * while keeping UART-backed output for the bring-up/runtime shell.
 */

use core::fmt::{self, Write};

struct UartWriter;

impl UartWriter {
    #[inline]
    fn new() -> Self {
        let uart = crate::arch::aarch64_pl011::early_uart();
        uart.init_early();
        Self
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::arch::aarch64_pl011::early_uart().write_str(s);
        Ok(())
    }
}

pub fn try_execute(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return true;
    }

    let mut out = UartWriter::new();
    crate::commands_shared::try_execute(&mut out, trimmed, "[A64-CMD]")
}

pub fn execute(input: &str) {
    let _ = try_execute(input);
}
