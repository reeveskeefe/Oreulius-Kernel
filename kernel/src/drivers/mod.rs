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

//! Driver facade for the kernel tree.
//!
//! The concrete hardware driver tree lives under `drivers::x86` for the current
//! x86-family backends. `drivers::aarch64` is intentionally minimal and exists
//! only as the explicit AArch64 root for future target-specific driver work.

#[cfg(not(target_arch = "aarch64"))]
pub mod x86;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
