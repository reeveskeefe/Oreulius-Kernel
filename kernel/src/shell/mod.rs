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

#[cfg(not(target_arch = "aarch64"))]
pub mod advanced_commands;
#[cfg(not(target_arch = "aarch64"))]
pub mod commands;
#[cfg(target_arch = "aarch64")]
pub mod commands_aarch64;
#[cfg(target_arch = "aarch64")]
pub use commands_aarch64 as commands;
pub mod commands_shared;
pub(crate) mod network_commands_shared;
#[cfg(not(target_arch = "aarch64"))]
pub mod console_service;
#[cfg(not(target_arch = "aarch64"))]
pub mod terminal;
