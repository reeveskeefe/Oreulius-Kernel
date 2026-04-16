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
 * GHASH over GF(2^128) for AES-GCM.
 */

fn gf_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *x;
    for byte in y {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 != 0 {
                for i in 0..16 {
                    z[i] ^= v[i];
                }
            }
            let lsb = v[15] & 1;
            for i in (0..15).rev() {
                v[i + 1] = (v[i + 1] >> 1) | ((v[i] & 1) << 7);
            }
            v[0] >>= 1;
            if lsb != 0 {
                v[0] ^= 0xE1;
            }
        }
    }
    z
}

pub fn ghash_block(y: &mut [u8; 16], h: &[u8; 16], block: &[u8]) {
    let mut padded = [0u8; 16];
    let l = block.len().min(16);
    padded[..l].copy_from_slice(&block[..l]);
    for i in 0..16 {
        y[i] ^= padded[i];
    }
    *y = gf_mul(y, h);
}

pub fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    let mut i = 0usize;
    while i + 16 <= aad.len() {
        ghash_block(&mut y, h, &aad[i..i + 16]);
        i += 16;
    }
    if i < aad.len() {
        ghash_block(&mut y, h, &aad[i..]);
    }
    i = 0;
    while i + 16 <= ct.len() {
        ghash_block(&mut y, h, &ct[i..i + 16]);
        i += 16;
    }
    if i < ct.len() {
        ghash_block(&mut y, h, &ct[i..]);
    }
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64 * 8).to_be_bytes()));
    len_block[8..].copy_from_slice(&((ct.len() as u64 * 8).to_be_bytes()));
    ghash_block(&mut y, h, &len_block);
    y
}
