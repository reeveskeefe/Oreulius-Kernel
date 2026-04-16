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


/*!
 * Firmware validation hooks.
 */

use crate::drivers::x86::gpu_support::errors::GpuError;

/// Validate a raw firmware blob.
///
/// Checks that the blob is non-empty. Future work: add magic-header and
/// checksum verification once a canonical firmware format is defined.
pub fn verify_blob(bytes: &[u8]) -> Result<(), GpuError> {
    if bytes.is_empty() {
        return Err(GpuError::FirmwareInvalid);
    }
    Ok(())
}
