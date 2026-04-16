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

pub mod pit;
pub mod process;
#[cfg(not(target_arch = "aarch64"))]
pub mod process_asm;
pub mod process_platform;
pub mod slice_scheduler;
#[cfg(not(target_arch = "aarch64"))]
pub mod scheduler;
pub mod scheduler_platform;
pub mod scheduler_runtime_platform;
#[cfg(not(target_arch = "aarch64"))]
pub mod tasks;

// Preserve the legacy `crate::scheduler::*` surface while grouping scheduler code.
#[cfg(not(target_arch = "aarch64"))]
pub use self::scheduler::*;
