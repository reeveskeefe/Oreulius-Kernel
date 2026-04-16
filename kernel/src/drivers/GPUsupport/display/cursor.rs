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
 * Hardware/software cursor state.
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorState {
    pub x: i32,
    pub y: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub visible: bool,
}

impl CursorState {
    pub const fn new() -> Self {
        CursorState {
            x: 0,
            y: 0,
            hot_x: 0,
            hot_y: 0,
            visible: true,
        }
    }
}
