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
pub mod elf;
pub mod intent_wasm;
pub mod replay;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm;
pub mod wasm_jit;
#[cfg(not(target_arch = "aarch64"))]
pub mod wasm_thread;
