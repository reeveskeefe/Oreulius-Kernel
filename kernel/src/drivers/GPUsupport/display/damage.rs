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
 * Display-side damage region tracking.
 */

pub const MAX_DAMAGE_RECTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DamageRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

pub struct DisplayDamage {
    rects: [Option<DamageRect>; MAX_DAMAGE_RECTS],
    len: usize,
}

impl DisplayDamage {
    pub const fn new() -> Self {
        DisplayDamage {
            rects: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            len: 0,
        }
    }

    pub fn push(&mut self, rect: DamageRect) {
        if self.len < MAX_DAMAGE_RECTS {
            self.rects[self.len] = Some(rect);
            self.len += 1;
        }
    }

    pub fn clear(&mut self) {
        self.rects = [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None,
        ];
        self.len = 0;
    }
}
