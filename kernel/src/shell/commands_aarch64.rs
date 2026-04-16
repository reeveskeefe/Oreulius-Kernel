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

//! Thin AArch64 shell adapter that forwards into the shared command dispatcher
//! while keeping UART-backed output for the bring-up/runtime shell.

use core::fmt::{self, Write};

struct UartWriter;

impl UartWriter {
    #[inline]
    fn new() -> Self {
        let uart = crate::arch::aarch64::aarch64_pl011::early_uart();
        uart.init_early();
        Self
    }
}

impl Write for UartWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::arch::aarch64::aarch64_pl011::early_uart().write_str(s);
        Ok(())
    }
}

pub fn try_execute(input: &str) -> bool {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return true;
    }

    let mut out = UartWriter::new();
    crate::shell::commands_shared::try_execute(&mut out, trimmed, "[A64-CMD]")
}

pub fn execute(input: &str) {
    let _ = try_execute(input);
}
