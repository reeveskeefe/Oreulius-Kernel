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

//! Facade for the CapNet subsystem.
//!
//! The implementation currently lives in a private legacy module so the split
//! can land without changing wire formats. The named submodules provide the
//! ownership boundaries and re-export grouped responsibilities.

#[path = "../capnet.rs"]
mod legacy;

pub mod encoding;
pub mod session;
pub mod persistence;
pub mod audit;
pub mod metrics;

pub use legacy::*;
