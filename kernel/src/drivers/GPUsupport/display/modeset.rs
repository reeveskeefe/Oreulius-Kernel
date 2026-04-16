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
 * Minimal display mode selection state.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeRequest {
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeSelection {
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
}

impl ModeSelection {
    pub const fn from_request(req: ModeRequest) -> Self {
        ModeSelection {
            width: req.width,
            height: req.height,
            bpp: req.bpp,
        }
    }
}
